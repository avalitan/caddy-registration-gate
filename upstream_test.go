package registrationgate

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"net/http/httptest"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"
)

type upstreamLookupFunc func(context.Context, string, string) ([]netip.Addr, error)

func (f upstreamLookupFunc) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return f(ctx, network, host)
}

func TestUpstreamDNSPinsCheckedIPs(t *testing.T) {
	policy, err := compileUpstreamPolicy(&UpstreamPolicyConfig{
		CIDRs:     []string{"192.0.2.0/24", "2001:db8::/32"},
		Ports:     []string{"443"},
		Hostnames: []string{"*.internal.example"},
		Protocols: []string{"https"},
	})
	if err != nil {
		t.Fatal(err)
	}
	v4 := netip.MustParseAddr("192.0.2.6")
	v6 := netip.MustParseAddr("2001:db8::6")
	answers := []netip.Addr{v6, v4, netip.MustParseAddr("::ffff:192.0.2.6")}
	resolver := upstreamLookupFunc(func(ctx context.Context, network, host string) ([]netip.Addr, error) {
		if network != "ip" || host != "web.internal.example." {
			t.Fatalf("unexpected DNS lookup %s %s", network, host)
		}
		if _, bounded := ctx.Deadline(); !bounded {
			t.Fatal("unbounded DNS lookup")
		}
		return answers, nil
	})
	target := upstreamTarget{host: "Web.Internal.Example.", port: 443, protocol: "https"}
	upstream, err := policy.resolve(t.Context(), target, resolver)
	if err != nil {
		t.Fatal(err)
	}

	answers = []netip.Addr{v4, netip.MustParseAddr("198.51.100.1")}
	if _, err := policy.resolve(t.Context(), target, resolver); err == nil {
		t.Fatal("accepted changed DNS answers outside the policy")
	}
	proxy := upstream.proxyHandler()
	dials := make([]string, 0, len(proxy.Upstreams))
	for _, item := range proxy.Upstreams {
		dials = append(dials, item.Dial)
	}
	if !slices.Equal(dials, []string{"192.0.2.6:443", "[2001:db8::6]:443"}) {
		t.Fatalf("unexpected pinned dial addresses %v", dials)
	}
	var transport reverseproxy.HTTPTransport
	if err := json.Unmarshal(proxy.TransportRaw, &transport); err != nil {
		t.Fatal(err)
	}
	if transport.TLS == nil || transport.TLS.ServerName != "web.internal.example" || transport.TLS.InsecureSkipVerify {
		t.Fatalf("unexpected TLS settings: %+v", transport.TLS)
	}
	if string(transport.NetworkProxyRaw) != `{"from":"none"}` {
		t.Fatalf("forward proxy was not disabled: %s", transport.NetworkProxyRaw)
	}
}

func TestUpstreamDestinationRestrictions(t *testing.T) {
	policy, err := compileUpstreamPolicy(&UpstreamPolicyConfig{
		CIDRs: []string{"192.0.2.0/24"}, Ports: []string{"8000-8002"}, Hostnames: []string{"*.internal.example"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resolver := upstreamLookupFunc(func(_ context.Context, network, host string) ([]netip.Addr, error) {
		if network != "ip4" || host != "valid.internal.example." {
			t.Fatalf("unexpected DNS lookup %s %s", network, host)
		}
		return nil, errors.New("DNS unavailable")
	})
	for _, target := range []upstreamTarget{
		{host: "198.51.100.2", port: 8001},
		{host: "2001:db8::2", port: 8001},
		{host: "192.0.2.2", port: 8003},
		{host: "192.0.2.2", port: 8001, protocol: "https"},
		{host: "unix//tmp/ignored.sock", port: 8001},
		{host: "fe80::1%eth0", port: 8001},
		{host: "internal.example", port: 8001},
		{host: "web.evilinternal.example", port: 8001},
		{host: "valid.internal.example", port: 8001},
		{port: 8001},
	} {
		if _, err := policy.resolve(t.Context(), target, resolver); err == nil {
			t.Errorf("unexpected permission for %+v", target)
		}
	}
	if _, err := (upstreamPolicy{}).resolve(t.Context(), upstreamTarget{host: "192.0.2.2", port: 8001}, resolver); err == nil {
		t.Fatal("permitted an upstream without an administrator policy")
	}
	upstream, err := policy.resolve(t.Context(), upstreamTarget{host: "::ffff:192.0.2.2", port: 8002}, resolver)
	if err != nil || !slices.Equal(upstream.dials, []netip.AddrPort{netip.MustParseAddrPort("192.0.2.2:8002")}) {
		t.Fatalf("mapped address: %v, %v", upstream.dials, err)
	}
}

func TestUpstreamPeerRequiresVerifiedDirectTCP(t *testing.T) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	accepted, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	defer accepted.Close()

	policy, err := compileUpstreamPolicy(&UpstreamPolicyConfig{
		CIDRs: []string{"127.0.0.0/8"}, Ports: []string{"8080"}, AllowDirectPeer: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	leaf := &x509.Certificate{Raw: []byte("test leaf"), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	ca := &x509.Certificate{Raw: []byte("test CA")}
	gate := Gate{upstreamPolicy: policy, domainsByCA: map[[sha256.Size]byte]string{sha256.Sum256(ca.Raw): "test"}}
	req := httptest.NewRequest("PUT", "https://gate.example/api/v1/services/site", nil)
	req.TLS = &tls.ConnectionState{HandshakeComplete: true, PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: [][]*x509.Certificate{{leaf, ca}}}
	req.RemoteAddr = "192.0.2.100:54321"
	req.Header.Set("Forwarded", "for=127.0.0.2")
	req.Header.Set("X-Forwarded-For", "127.0.0.2")
	target := upstreamTarget{port: 8080}

	wrapped := struct{ net.Conn }{accepted}
	wrappedCtx := captureDirectPeer(req.Context(), tls.Server(wrapped, &tls.Config{}))
	if _, err := gate.resolveHTTPUpstream(req.WithContext(wrappedCtx), target); err == nil {
		t.Fatal("accepted fallback from a wrapped connection or forwarded header")
	}
	ctx := captureDirectPeer(req.Context(), tls.Server(accepted, &tls.Config{}))
	upstream, err := gate.resolveHTTPUpstream(req.WithContext(ctx), target)
	if err != nil || !slices.Equal(upstream.dials, []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:8080")}) {
		t.Fatalf("direct peer: %v, %v", upstream.dials, err)
	}
	req.TLS = nil
	if _, err := gate.resolveHTTPUpstream(req.WithContext(ctx), target); err == nil {
		t.Fatal("accepted fallback without verified mTLS")
	}
}
