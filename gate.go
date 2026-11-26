package registrationgate

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

const moduleName = "registration_gate"

var configName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.~-]{0,127}$`)

func init() {
	caddy.RegisterModule(&Gate{})
	caddy.RegisterModule(&Handler{})
}

// Gate holds administrator settings shared by the registration handlers.
type Gate struct {
	AdminSocket    string                `json:"admin_socket"`
	Database       string                `json:"database,omitempty"`
	ManagedAnchor  string                `json:"managed_anchor"`
	Namespace      string                `json:"namespace"`
	TrustDomains   map[string][]string   `json:"trust_domains"`
	UpstreamPolicy *UpstreamPolicyConfig `json:"upstream_policy,omitempty"`

	domainsByCA    map[[sha256.Size]byte]string
	store          *desiredStore
	upstreamPolicy upstreamPolicy
}

func (*Gate) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: moduleName, New: func() caddy.Module { return &Gate{} }}
}

func (g *Gate) Provision(_ caddy.Context) error {
	if g.Database == "" {
		g.Database = filepath.Join(caddy.AppDataDir(), "registration-gate", "registrations.db")
	}
	if !filepath.IsAbs(g.Database) || filepath.Clean(g.Database) != g.Database ||
		g.Database == "/" || strings.ContainsAny(g.Database, "\x00\r\n") {
		return fmt.Errorf("database must be an absolute SQLite file path")
	}
	if !filepath.IsAbs(g.AdminSocket) || filepath.Clean(g.AdminSocket) != g.AdminSocket ||
		g.AdminSocket == "/" || strings.ContainsAny(g.AdminSocket, "\x00\r\n") {
		return fmt.Errorf("admin_socket must be an absolute Unix socket path")
	}
	if !configName.MatchString(g.ManagedAnchor) || !configName.MatchString(g.Namespace) {
		return fmt.Errorf("managed_anchor and namespace must be valid configuration names")
	}
	if len(g.TrustDomains) == 0 {
		return fmt.Errorf("at least one trust domain is required")
	}
	policy, err := compileUpstreamPolicy(g.UpstreamPolicy)
	if err != nil {
		return fmt.Errorf("upstream_policy: %w", err)
	}

	domainsByCA := make(map[[sha256.Size]byte]string)
	for domain, files := range g.TrustDomains {
		if !configName.MatchString(domain) || len(files) == 0 {
			return fmt.Errorf("invalid trust domain %q or missing CA files", domain)
		}
		for _, file := range files {
			if err := loadDomainCAs(domainsByCA, domain, file); err != nil {
				return fmt.Errorf("trust domain %q CA file %q: %w", domain, file, err)
			}
		}
	}
	g.domainsByCA = domainsByCA
	g.upstreamPolicy = policy
	return nil
}

func loadDomainCAs(domains map[[sha256.Size]byte]string, domain, file string) error {
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return fmt.Errorf("empty CA file")
	}
	for len(data) > 0 {
		if !bytes.HasPrefix(data, []byte("-----BEGIN CERTIFICATE-----")) {
			return fmt.Errorf("expected a PEM CA certificate")
		}
		block, rest := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" {
			return fmt.Errorf("invalid PEM CA certificate")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return err
		}
		if !cert.IsCA || cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			return fmt.Errorf("certificate is not a signing CA")
		}
		fingerprint := sha256.Sum256(cert.Raw)
		if existing, ok := domains[fingerprint]; ok && existing != domain {
			return fmt.Errorf("CA already assigned to trust domain %q", existing)
		}
		domains[fingerprint] = domain
		data = bytes.TrimSpace(rest)
	}
	return nil
}

func (g *Gate) Start() error {
	path, err := prepareStorePath(g.Database)
	if err != nil {
		return fmt.Errorf("prepare registration database: %w", err)
	}
	scope := storeScope{anchor: g.ManagedAnchor, namespace: g.Namespace}
	value, _, err := desiredStores.LoadOrNew(scope.anchor, func() (caddy.Destructor, error) {
		return openDesiredStore(path, scope)
	})
	if err != nil {
		return fmt.Errorf("open registration database: %w", err)
	}
	store := value.(*desiredStore)
	if store.path != path || store.scope != scope {
		_, err := desiredStores.Delete(scope.anchor)
		return errors.Join(fmt.Errorf("stop Caddy before changing the database path or namespace for managed anchor %q", scope.anchor), err)
	}
	g.store = store
	return nil
}

func (g *Gate) Stop() error {
	if g.store == nil {
		return nil
	}
	anchor := g.store.scope.anchor
	g.store = nil
	_, err := desiredStores.Delete(anchor)
	return err
}

// Handler is a terminal handler for the registration API route.
type Handler struct {
	gate *Gate
}

func (*Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "http.handlers." + moduleName, New: func() caddy.Module { return &Handler{} }}
}

func (h *Handler) Provision(ctx caddy.Context) error {
	app, err := ctx.AppIfConfigured(moduleName)
	if err != nil {
		return err
	}
	h.gate = app.(*Gate)
	if h.gate.upstreamPolicy.allowDirectPeer {
		server, ok := ctx.Value(caddyhttp.ServerCtxKey).(*caddyhttp.Server)
		if !ok || server == nil {
			return fmt.Errorf("direct peer discovery requires a Caddy HTTP server context")
		}
		server.RegisterConnContext(captureDirectPeer)
	}
	return nil
}

// trustDomain matches configured CAs only within the verified peer chains.
func (g *Gate) trustDomain(state *tls.ConnectionState) string {
	if state == nil || !state.HandshakeComplete || len(state.PeerCertificates) == 0 {
		return ""
	}
	leaf := state.PeerCertificates[0]
	now := time.Now()
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return ""
	}

	var domain string
	for _, chain := range state.VerifiedChains {
		if len(chain) < 2 || !chain[0].Equal(leaf) {
			continue
		}
		for _, ca := range chain[1:] {
			assigned := g.domainsByCA[sha256.Sum256(ca.Raw)]
			if assigned == "" {
				continue
			}
			if domain != "" && assigned != domain {
				return ""
			}
			domain = assigned
		}
	}
	return domain
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, _ caddyhttp.Handler) error {
	if h.gate.trustDomain(r.TLS) == "" {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return nil
	}
	http.NotFound(w, r)
	return nil
}

var (
	_ caddy.App                   = (*Gate)(nil)
	_ caddy.Provisioner           = (*Gate)(nil)
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
)
