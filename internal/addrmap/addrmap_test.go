package addrmap

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func mustMap(t *testing.T, s string) Map {
	t.Helper()
	m, err := Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestAMappedAddressIsDialledAtItsRealOne(t *testing.T) {
	m := mustMap(t, "10.211.12.0/24=10.11.12.0/24, 172.30.0.0/20=192.168.16.0/20")
	for in, want := range map[string]string{
		"10.211.12.2:3389":        "10.11.12.2:3389",
		"10.211.12.255:22":        "10.11.12.255:22",
		"172.30.5.9:443":          "192.168.21.9:443", // the host part crosses a byte
		"10.11.12.2:3389":         "10.11.12.2:3389",  // the real one is left alone
		"10.212.0.1:80":           "10.212.0.1:80",
		"wiki.corp.example:443":   "wiki.corp.example:443",
		"[::ffff:10.211.12.7]:80": "10.11.12.7:80",
	} {
		if got := m.Dest(in); got != want {
			t.Errorf("Dest(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMappedRoutesNeverClaimTheRealRange(t *testing.T) {
	m := mustMap(t, "10.211.12.0/24=10.11.12.0/24")
	got := m.Routes([]string{
		"10.11.12.0/25",  // inside: moves to the virtual range
		"10.11.12.2",     // a bare host inside it
		"10.0.0.0/8",     // around it: keeps everything else
		"192.168.1.0/24", // elsewhere: untouched
		"not-a-route",
	})
	for _, want := range []string{"10.211.12.0/25", "10.211.12.2/32", "192.168.1.0/24", "not-a-route", "10.211.12.0/24"} {
		if !slices.Contains(got, want) {
			t.Errorf("routes %v are missing %s", got, want)
		}
	}
	for _, r := range got {
		if p, err := parsePrefix(r); err == nil && p.Overlaps(mustPrefix(t, "10.11.12.0/24")) {
			t.Errorf("route %s still sends the real range to this tunnel", r)
		}
	}
	// What is left of 10.0.0.0/8 must still cover the rest of it: 10.11.13.1
	// and 10.200.0.1 are this tunnel's as before.
	for _, addr := range []string{"10.11.13.1", "10.200.0.1", "10.11.11.255"} {
		if !covered(t, got, addr) {
			t.Errorf("%s is no longer routed here: %v", addr, got)
		}
	}
}

func TestNoMapLeavesRoutesAsTheyWere(t *testing.T) {
	in := []string{"10.0.0.0/8", "10.11.12.2"}
	if got := (Map{}).Routes(in); !slices.Equal(got, in) {
		t.Errorf("got %v", got)
	}
	if got := (Map{}).Dest("10.11.12.2:80"); got != "10.11.12.2:80" {
		t.Errorf("got %v", got)
	}
}

func TestAMapThatCannotWorkIsRefused(t *testing.T) {
	for _, bad := range []string{
		"10.211.12.0/24",                                            // no real side
		"10.211.12.0/24=10.11.12.0/16",                              // different sizes
		"10.211.12.0/24=fd00::/120",                                 // different families
		"nonsense=10.11.12.0/24",                                    // not an address
		"10.211.12.0/24=10.11.12.0/24,10.211.12.128/25=10.1.1.0/25", // overlapping virtual ranges
	} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("Parse(%q) was accepted", bad)
		}
	}
}

func TestAMapReadsBackAsWritten(t *testing.T) {
	m := mustMap(t, " 10.211.12.0/24 = 10.11.12.0/24 ")
	if got := m.String(); got != "10.211.12.0/24=10.11.12.0/24" {
		t.Errorf("got %q", got)
	}
	if !strings.Contains(mustMap(t, "10.211.12.9=10.11.12.9").String(), "/32") {
		t.Error("a bare address was not read as one host")
	}
}

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := parsePrefix(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func covered(t *testing.T, routes []string, addr string) bool {
	t.Helper()
	a := mustPrefix(t, addr).Addr()
	for _, r := range routes {
		if p, err := parsePrefix(r); err == nil && p.Contains(a) {
			return true
		}
	}
	return false
}
