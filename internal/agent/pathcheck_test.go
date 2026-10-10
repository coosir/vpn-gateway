package agent

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vpn-gateway/vpn-gateway/pkg/contract"
)

// sizedPath answers echoes no bigger than limit bytes and loses the rest,
// which is what a tunnel stuck on a small MTU looks like from inside it.
type sizedPath struct {
	limit   atomic.Int32
	largest atomic.Int32
	hosts   chan string
}

func newSizedPath(limit int) *sizedPath {
	p := &sizedPath{hosts: make(chan string, 64)}
	p.limit.Store(int32(limit))
	return p
}

func (p *sizedPath) echo(_ context.Context, host string, size int, _ time.Duration) error {
	if int32(size) > p.largest.Load() {
		p.largest.Store(int32(size))
	}
	select {
	case p.hosts <- host:
	default:
	}
	if size > int(p.limit.Load()) {
		return errors.New("i/o timeout")
	}
	return nil
}

// refreshCounter is a provider that counts the times it was asked to rebuild
// its data path.
type refreshCounter struct {
	scriptedProvider
	refreshes atomic.Int32
}

func (p *refreshCounter) Refresh() error { p.refreshes.Add(1); return nil }

func pathTestAgent(t *testing.T, prov Provider, path *sizedPath) *Agent {
	t.Helper()
	a := newTestAgent(t, prov)
	a.tunnelUp = func() bool { return true }
	a.echo = path.echo
	a.SetNetwork(contract.Network{DNS: []string{"10.195.86.54"}})
	a.SetState(contract.StateUp, nil)
	return a
}

func TestPathCheckRefreshesATunnelThatLosesLargePackets(t *testing.T) {
	// 576 is what got through the stuck tunnel.
	path := newSizedPath(576)
	p := &refreshCounter{}
	a := pathTestAgent(t, p, path)

	k := &keepaliveLoop{agent: a, interval: time.Hour, timeout: time.Second, pathSize: 1200}
	now := time.Now()
	k.round(context.Background(), now)
	if n := p.refreshes.Load(); n != 0 {
		t.Fatalf("refreshed %d times the moment the tunnel came up, want 0", n)
	}

	// Busy the whole time: the path is checked regardless.
	a.addRx(4096)
	k.round(context.Background(), now.Add(time.Hour))
	if got := path.largest.Load(); got != 1200 {
		t.Errorf("the large echo was %d bytes, want 1200", got)
	}
	if host := <-path.hosts; host != "10.195.86.54" {
		t.Errorf("pinged %q, want the resolver without its port", host)
	}
	if n := p.refreshes.Load(); n != 1 {
		t.Fatalf("refreshed %d times on a tunnel that lost large packets, want 1", n)
	}
	if !k.pathBroken {
		t.Error("the broken path was not recorded")
	}

	// Once the path carries full packets again, nothing more is asked of it.
	path.limit.Store(1500)
	k.round(context.Background(), now.Add(2*time.Hour))
	if n := p.refreshes.Load(); n != 1 {
		t.Fatalf("refreshed %d times after the path recovered, want 1", n)
	}
	if k.pathBroken {
		t.Error("the recovered path is still recorded as broken")
	}
}

func TestPathCheckLeavesAHostThatDoesNotAnswerPings(t *testing.T) {
	// A host that answers no echo at all says nothing about packet sizes,
	// and rebuilding the data path would not change what it does.
	path := newSizedPath(0)
	p := &refreshCounter{}
	a := pathTestAgent(t, p, path)

	k := &keepaliveLoop{agent: a, interval: time.Hour, timeout: time.Second, pathSize: 1200}
	now := time.Now()
	k.round(context.Background(), now)
	k.round(context.Background(), now.Add(time.Hour))
	if n := p.refreshes.Load(); n != 0 {
		t.Fatalf("refreshed %d times for a host that answers no pings, want 0", n)
	}
	if k.pathBroken {
		t.Error("a host that answers no pings was recorded as a broken path")
	}
}

func TestPathCheckIsQuietOnAHealthyTunnel(t *testing.T) {
	path := newSizedPath(1500)
	p := &refreshCounter{}
	a := pathTestAgent(t, p, path)

	k := &keepaliveLoop{agent: a, interval: time.Hour, timeout: time.Second, pathSize: 1200}
	now := time.Now()
	for i := 0; i < 4; i++ {
		k.round(context.Background(), now.Add(time.Duration(i)*time.Hour))
	}
	if n := p.refreshes.Load(); n != 0 {
		t.Fatalf("refreshed %d times on a healthy tunnel, want 0", n)
	}
}

func TestPathCheckSkipsAProxiedTunnel(t *testing.T) {
	// A tunnel reached through a client's own proxy has no packets of ours
	// to size.
	path := newSizedPath(576)
	p := &refreshCounter{}
	a := pathTestAgent(t, p, path)
	a.tunnelUp = func() bool { return false }

	k := &keepaliveLoop{agent: a, interval: time.Hour, timeout: time.Second, pathSize: 1200}
	now := time.Now()
	k.round(context.Background(), now)
	a.addRx(1) // busy, so the keepalive itself stays out of it
	k.round(context.Background(), now.Add(time.Hour))
	if n := path.largest.Load(); n != 0 {
		t.Fatalf("sent a %d-byte echo through a proxied tunnel", n)
	}
}
