package registrationgate

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"
)

// UpstreamPolicyConfig defines the administrator's baseline HTTP destinations.
type UpstreamPolicyConfig struct {
	CIDRs           []string `json:"cidrs"`
	Ports           []string `json:"ports"`
	Hostnames       []string `json:"hostnames,omitempty"`
	Protocols       []string `json:"protocols,omitempty"`
	AllowDirectPeer bool     `json:"allow_direct_peer,omitempty"`
}

type portRange struct{ first, last uint16 }

type upstreamPolicy struct {
	cidrs           []netip.Prefix
	ports           []portRange
	hostnames       []string
	protocols       []string
	dnsNetwork      string
	allowDirectPeer bool
}

func compileUpstreamPolicy(config *UpstreamPolicyConfig) (upstreamPolicy, error) {
	if config == nil {
		return upstreamPolicy{}, nil
	}
	if len(config.CIDRs) == 0 || len(config.Ports) == 0 {
		return upstreamPolicy{}, fmt.Errorf("both cidrs and ports are required")
	}
	policy := upstreamPolicy{allowDirectPeer: config.AllowDirectPeer}
	var allowIPv4, allowIPv6 bool
	for _, value := range config.CIDRs {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix.Addr().Is4In6() {
			return upstreamPolicy{}, fmt.Errorf("invalid IPv4 or IPv6 CIDR %q", value)
		}
		policy.cidrs = append(policy.cidrs, prefix.Masked())
		allowIPv4 = allowIPv4 || prefix.Addr().Is4()
		allowIPv6 = allowIPv6 || prefix.Addr().Is6()
	}
	switch {
	case allowIPv4 && allowIPv6:
		policy.dnsNetwork = "ip"
	case allowIPv4:
		policy.dnsNetwork = "ip4"
	default:
		policy.dnsNetwork = "ip6"
	}
	for _, item := range config.Ports {
		first, last, ranged := strings.Cut(item, "-")
		if !ranged {
			last = first
		}
		lo, loErr := strconv.ParseUint(first, 10, 16)
		hi, hiErr := strconv.ParseUint(last, 10, 16)
		if loErr != nil || hiErr != nil || lo == 0 || hi < lo {
			return upstreamPolicy{}, fmt.Errorf("invalid port or port range %q", item)
		}
		policy.ports = append(policy.ports, portRange{uint16(lo), uint16(hi)})
	}
	for _, value := range config.Hostnames {
		base := canonicalHostname(strings.TrimPrefix(value, "*."))
		if base == "" {
			return upstreamPolicy{}, fmt.Errorf("invalid hostname or wildcard %q", value)
		}
		if strings.HasPrefix(value, "*.") {
			base = "*." + base
		}
		policy.hostnames = append(policy.hostnames, base)
	}
	policy.protocols = slices.Clone(config.Protocols)
	if len(policy.protocols) == 0 {
		policy.protocols = []string{"http"}
	}
	for _, protocol := range policy.protocols {
		if protocol != "http" && protocol != "https" {
			return upstreamPolicy{}, fmt.Errorf("unsupported upstream protocol %q", protocol)
		}
	}
	return policy, nil
}

func canonicalHostname(value string) string {
	value = strings.TrimSuffix(value, ".")
	if len(value) == 0 || len(value) > 253 {
		return ""
	}
	for label := range strings.SplitSeq(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return ""
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-') {
				return ""
			}
		}
	}
	return strings.ToLower(value)
}

func (p upstreamPolicy) allowsHostname(host string) bool {
	for _, rule := range p.hostnames {
		if host == rule || strings.HasPrefix(rule, "*.") && strings.HasSuffix(host, rule[1:]) {
			return true
		}
	}
	return false
}

type directPeerKey struct{}

// Capture the transport peer only when the TLS session sits directly on a TCP
// socket. A PROXY protocol or other connection wrapper cannot supply this value.
func captureDirectPeer(ctx context.Context, conn net.Conn) context.Context {
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return ctx
	}
	tcpConn, ok := tlsConn.NetConn().(*net.TCPConn)
	if !ok {
		return ctx
	}
	peer := tcpConn.RemoteAddr().(*net.TCPAddr).AddrPort().Addr()
	return context.WithValue(ctx, directPeerKey{}, peer)
}

type upstreamTarget struct {
	host     string // empty requests the authenticated direct TCP peer
	port     int
	protocol string // defaults to http
}

type resolvedUpstream struct {
	host     string
	protocol string
	dials    []netip.AddrPort
}

type upstreamResolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

var systemUpstreamResolver = &net.Resolver{PreferGo: true, StrictErrors: true}

// resolveHTTPUpstream is the entry point for building an authorized HTTP route.
// Call it again when generating a new revision from a hostname.
func (g *Gate) resolveHTTPUpstream(r *http.Request, target upstreamTarget) (resolvedUpstream, error) {
	if g.trustDomain(r.TLS) == "" {
		return resolvedUpstream{}, fmt.Errorf("upstream selection requires verified client authentication")
	}
	return g.upstreamPolicy.resolve(r.Context(), target, systemUpstreamResolver)
}

func (p upstreamPolicy) resolve(ctx context.Context, target upstreamTarget, resolver upstreamResolver) (resolvedUpstream, error) {
	protocol := target.protocol
	if protocol == "" {
		protocol = "http"
	}
	if !slices.Contains(p.protocols, protocol) {
		return resolvedUpstream{}, fmt.Errorf("upstream protocol is not permitted")
	}
	if target.port < 1 || target.port > 65535 {
		return resolvedUpstream{}, fmt.Errorf("upstream port must be between 1 and 65535")
	}
	port := uint16(target.port)
	if !slices.ContainsFunc(p.ports, func(r portRange) bool { return r.first <= port && port <= r.last }) {
		return resolvedUpstream{}, fmt.Errorf("upstream port is not permitted")
	}

	host := target.host
	var addresses []netip.Addr
	if host == "" {
		peer, ok := ctx.Value(directPeerKey{}).(netip.Addr)
		if !p.allowDirectPeer || !ok || !peer.IsValid() {
			return resolvedUpstream{}, fmt.Errorf("no permitted direct TCP peer address")
		}
		host = peer.Unmap().String()
		addresses = []netip.Addr{peer}
	} else if literal, err := netip.ParseAddr(host); err == nil {
		host = literal.Unmap().String()
		addresses = []netip.Addr{literal}
	} else {
		host = canonicalHostname(host)
		if host == "" || !p.allowsHostname(host) {
			return resolvedUpstream{}, fmt.Errorf("upstream hostname is invalid or not permitted")
		}
		lookupCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		answers, err := resolver.LookupNetIP(lookupCtx, p.dnsNetwork, host+".")
		if err != nil {
			return resolvedUpstream{}, fmt.Errorf("resolve upstream hostname: %w", err)
		}
		addresses = answers
	}

	dials := make([]netip.AddrPort, 0, len(addresses))
	for _, addr := range addresses {
		if !addr.IsValid() || addr.Zone() != "" {
			return resolvedUpstream{}, fmt.Errorf("upstream address is invalid")
		}
		addr = addr.Unmap()
		if addr.IsUnspecified() || addr.IsMulticast() || addr.Is6() && addr.IsLinkLocalUnicast() ||
			addr == netip.AddrFrom4([4]byte{255, 255, 255, 255}) ||
			!slices.ContainsFunc(p.cidrs, func(cidr netip.Prefix) bool { return cidr.Contains(addr) }) {
			return resolvedUpstream{}, fmt.Errorf("upstream address is not permitted")
		}
		dials = append(dials, netip.AddrPortFrom(addr, port))
	}
	if len(dials) == 0 {
		return resolvedUpstream{}, fmt.Errorf("upstream hostname has no usable addresses")
	}
	slices.SortFunc(dials, netip.AddrPort.Compare)
	return resolvedUpstream{host: host, protocol: protocol, dials: slices.Compact(dials)}, nil
}

// proxyHandler only emits checked numeric socket addresses. Preserve the TLS
// verification name separately and disable environment-based forward proxies.
func (u resolvedUpstream) proxyHandler() *reverseproxy.Handler {
	transport := reverseproxy.HTTPTransport{NetworkProxyRaw: json.RawMessage(`{"from":"none"}`)}
	if u.protocol == "https" {
		transport.TLS = &reverseproxy.TLSConfig{ServerName: u.host}
	}
	handler := &reverseproxy.Handler{
		TransportRaw: caddyconfig.JSONModuleObject(transport, "protocol", "http", nil),
		Upstreams:    make(reverseproxy.UpstreamPool, 0, len(u.dials)),
	}
	for _, address := range u.dials {
		handler.Upstreams = append(handler.Upstreams, &reverseproxy.Upstream{Dial: address.String()})
	}
	return handler
}
