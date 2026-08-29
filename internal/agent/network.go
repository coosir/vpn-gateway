package agent

import (
	"strconv"
	"strings"

	"github.com/vpn-gateway/vpn-gateway/pkg/contract"
)

// ApplyNetworkOverrides layers VG_EXTRA_JSON settings on top of whatever a
// provider auto-discovered.
//
// Auto-discovery is best-effort and varies by vendor, so an operator can
// always state the answer explicitly. Overrides win outright rather than
// merging, so a wrong guess by a provider can be corrected rather than only
// added to.
//
// Recognised keys: routes, dns, search_domains (comma-separated), mtu.
func ApplyNetworkOverrides(cfg Config, n contract.Network) contract.Network {
	if v := cfg.Str("routes", ""); v != "" {
		n.Routes = splitList(v)
	}
	if v := cfg.Str("dns", ""); v != "" {
		n.DNS = splitList(v)
	}
	if v := cfg.Str("search_domains", ""); v != "" {
		n.SearchDomains = splitList(v)
	}
	if v := cfg.Str("mtu", ""); v != "" {
		if mtu, err := strconv.Atoi(v); err == nil && mtu > 0 {
			n.MTU = mtu
		}
	}
	return n
}

func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if v := strings.TrimSpace(part); v != "" {
			out = append(out, v)
		}
	}
	return out
}
