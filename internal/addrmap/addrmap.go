// Package addrmap gives one tunnel's address ranges a second name, so that two
// tunnels leading to the same addresses can both be reached.
package addrmap

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// Map lets two tunnels that lead to the same addresses both be reached.
//
// Two corporate networks are free to use the same private range, and a client
// can send 10.11.12.2 to one tunnel or the other, never both. A map gives one
// of them a second name for its range: with "10.211.12.0/24=10.11.12.0/24"
// this tunnel is reached at 10.211.12.2, the agent dials 10.11.12.2 inside it,
// and the other tunnel keeps 10.11.12.2 to itself.
//
// It is configured as extra.map, a comma-separated list of virtual=real
// pairs of the same length. Rewriting happens where every connection into
// the tunnel is made, so it holds for any provider and any protocol; names
// are not rewritten, so a mapped host is reached by its address.
type Map struct {
	pairs []addrPair
}

type addrPair struct{ virtual, real netip.Prefix }

// Parse reads extra.map. An empty value is an empty map.
func Parse(s string) (Map, error) {
	var m Map
	for _, item := range strings.Split(s, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		v, r, ok := strings.Cut(item, "=")
		if !ok {
			return Map{}, fmt.Errorf("map entry %q is not virtual=real", item)
		}
		virtual, err := parsePrefix(v)
		if err != nil {
			return Map{}, fmt.Errorf("map entry %q: %w", item, err)
		}
		real, err := parsePrefix(r)
		if err != nil {
			return Map{}, fmt.Errorf("map entry %q: %w", item, err)
		}
		if virtual.Addr().Is4() != real.Addr().Is4() || virtual.Bits() != real.Bits() {
			return Map{}, fmt.Errorf("map entry %q: both sides must be the same size, so each address has exactly one counterpart", item)
		}
		for _, p := range m.pairs {
			if p.virtual.Overlaps(virtual) {
				return Map{}, fmt.Errorf("map entry %q overlaps %s=%s: an address would have two meanings", item, p.virtual, p.real)
			}
		}
		m.pairs = append(m.pairs, addrPair{virtual, real})
	}
	return m, nil
}

// Empty reports whether nothing is mapped.
func (m Map) Empty() bool { return len(m.pairs) == 0 }

func (m Map) String() string {
	parts := make([]string, len(m.pairs))
	for i, p := range m.pairs {
		parts[i] = p.virtual.String() + "=" + p.real.String()
	}
	return strings.Join(parts, ",")
}

// Dest rewrites a "host:port" a client asked for into the one to dial. Only an
// address inside a virtual range changes.
func (m Map) Dest(addr string) string {
	if m.Empty() {
		return addr
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return addr // a name: the tunnel resolves it as it is
	}
	ip = ip.Unmap()
	for _, p := range m.pairs {
		if p.virtual.Contains(ip) {
			return net.JoinHostPort(translate(ip, p.virtual, p.real).String(), port)
		}
	}
	return addr
}

// Routes turns what the tunnel leads to into what a client should send it.
//
// A real range is taken out of the routes, so that a client never hands this
// tunnel the addresses the other one owns: a route inside it moves to the
// virtual range, and a route around it -- 10.0.0.0/8 around 10.11.12.0/24 --
// keeps everything but it. Each virtual range is then routed here as well,
// whether or not the tunnel announced its real one.
func (m Map) Routes(routes []string) []string {
	if m.Empty() {
		return routes
	}
	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, r := range routes {
		pfx, err := parsePrefix(r)
		if err != nil {
			add(r) // not ours to judge; pass it on as given
			continue
		}
		rest := []netip.Prefix{pfx}
		for _, p := range m.pairs {
			var next []netip.Prefix
			for _, q := range rest {
				switch {
				case !q.Overlaps(p.real):
					next = append(next, q)
				case q.Bits() >= p.real.Bits():
					// Inside the real range: reached by its virtual name now.
					add(netip.PrefixFrom(translate(q.Addr(), p.real, p.virtual), q.Bits()).String())
				default:
					next = append(next, subtract(q, p.real)...)
				}
			}
			rest = next
		}
		for _, q := range rest {
			if q == pfx {
				add(r) // untouched: keep it exactly as the tunnel wrote it
			} else {
				add(q.String())
			}
		}
	}
	for _, p := range m.pairs {
		add(p.virtual.String())
	}
	return out
}

// parsePrefix accepts a prefix or a bare address, which means a single host.
func parsePrefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%q is not an address or a prefix", s)
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// translate moves ip from one range to the other, keeping its host part.
func translate(ip netip.Addr, from, to netip.Prefix) netip.Addr {
	src, dst := ip.AsSlice(), to.Addr().AsSlice()
	out := make([]byte, len(src))
	for i := range out {
		bits := from.Bits() - i*8
		var keep byte // bits of this byte that belong to the network part
		switch {
		case bits >= 8:
			keep = 0xff
		case bits > 0:
			keep = byte(0xff << (8 - bits))
		}
		out[i] = dst[i]&keep | src[i]&^keep
	}
	a, _ := netip.AddrFromSlice(out)
	return a
}

// subtract returns outer with inner taken out, as the fewest prefixes: at
// each step down from outer, the half not leading to inner is kept whole.
func subtract(outer, inner netip.Prefix) []netip.Prefix {
	var out []netip.Prefix
	for cur := outer; cur.Bits() < inner.Bits(); {
		lo, hi := halves(cur)
		if lo.Contains(inner.Addr()) {
			out = append(out, hi)
			cur = lo
		} else {
			out = append(out, lo)
			cur = hi
		}
	}
	return out
}

// halves splits p into its two prefixes one bit longer.
func halves(p netip.Prefix) (netip.Prefix, netip.Prefix) {
	bits := p.Bits() + 1
	lo := netip.PrefixFrom(p.Addr(), bits)
	b := p.Addr().AsSlice()
	b[(bits-1)/8] |= 0x80 >> ((bits - 1) % 8)
	a, _ := netip.AddrFromSlice(b)
	return lo, netip.PrefixFrom(a, bits)
}
