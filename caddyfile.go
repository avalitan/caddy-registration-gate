package registrationgate

import (
	"encoding/json"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	httpcaddyfile.RegisterGlobalOption(moduleName, parseGate)
	httpcaddyfile.RegisterHandlerDirective(moduleName, parseHandler)
}

func parseGate(d *caddyfile.Dispenser, existing any) (any, error) {
	if existing != nil {
		return nil, d.Errf("%s can only be configured once", moduleName)
	}
	d.Next()
	if d.NextArg() {
		return nil, d.ArgErr()
	}

	gate := Gate{TrustDomains: make(map[string][]string)}
	for d.NextBlock(0) {
		switch d.Val() {
		case "admin_socket":
			if gate.AdminSocket != "" || !d.AllArgs(&gate.AdminSocket) {
				return nil, d.ArgErr()
			}
		case "database":
			if gate.Database != "" || !d.AllArgs(&gate.Database) {
				return nil, d.ArgErr()
			}
		case "managed_anchor":
			if gate.ManagedAnchor != "" || !d.AllArgs(&gate.ManagedAnchor) {
				return nil, d.ArgErr()
			}
		case "namespace":
			if gate.Namespace != "" || !d.AllArgs(&gate.Namespace) {
				return nil, d.ArgErr()
			}
		case "upstream_policy":
			if gate.UpstreamPolicy != nil || d.NextArg() {
				return nil, d.ArgErr()
			}
			policy, err := parseUpstreamPolicy(d)
			if err != nil {
				return nil, err
			}
			gate.UpstreamPolicy = policy
		case "trust_domain":
			args := d.RemainingArgs()
			if len(args) < 2 {
				return nil, d.ArgErr()
			}
			gate.TrustDomains[args[0]] = append(gate.TrustDomains[args[0]], args[1:]...)
		default:
			return nil, d.Errf("unrecognized %s option %q", moduleName, d.Val())
		}
	}

	raw, err := json.Marshal(gate)
	if err != nil {
		return nil, err
	}
	return httpcaddyfile.App{Name: moduleName, Value: raw}, nil
}

func parseUpstreamPolicy(d *caddyfile.Dispenser) (*UpstreamPolicyConfig, error) {
	var policy UpstreamPolicyConfig
	for depth := d.Nesting(); d.NextBlock(depth); {
		option := d.Val()
		args := d.RemainingArgs()
		if option == "allow_direct_peer" {
			if len(args) != 0 {
				return nil, d.ArgErr()
			}
			policy.AllowDirectPeer = true
			continue
		}
		if len(args) == 0 {
			return nil, d.ArgErr()
		}
		switch option {
		case "cidrs":
			policy.CIDRs = append(policy.CIDRs, args...)
		case "ports":
			policy.Ports = append(policy.Ports, args...)
		case "hostnames":
			policy.Hostnames = append(policy.Hostnames, args...)
		case "protocols":
			policy.Protocols = append(policy.Protocols, args...)
		default:
			return nil, d.Errf("unrecognized upstream policy option %q", option)
		}
	}
	return &policy, nil
}

func parseHandler(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	h.Next()
	if h.NextArg() || h.NextBlock(0) {
		return nil, h.ArgErr()
	}
	return &Handler{}, nil
}
