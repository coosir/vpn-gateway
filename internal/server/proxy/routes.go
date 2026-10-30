package proxy

import (
	"context"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
)

// routeTable holds the outbound each tunnel's traffic leaves by.
//
// The outbounds live here rather than in sing-box's outbound manager. The
// manager is built for a set fixed at start: it cannot remove an outbound, or
// replace one under a tag it already has. Tunnels come and go while the
// listener runs, so each one's outbound is created from the registry, started
// under a scope of its own, and closed by closing that scope when it is
// replaced or removed -- without touching any other tunnel.
type routeTable struct {
	mu     sync.RWMutex
	routes map[string]*liveRoute
}

type liveRoute struct {
	outbound adapter.Outbound
	scope    *adapter.Scope
}

func newRouteTable() *routeTable {
	return &routeTable{routes: map[string]*liveRoute{}}
}

func (t *routeTable) lookup(name string) (adapter.Outbound, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	r, ok := t.routes[name]
	if !ok {
		return nil, false
	}
	return r.outbound, true
}

// start runs an outbound through every start stage under a scope of its own.
func startOutbound(ctx context.Context, logger log.ContextLogger, ob adapter.Outbound) (*adapter.Scope, error) {
	scope := adapter.NewScope(ctx, logger)
	if lifecycle, ok := ob.(adapter.Lifecycle); ok {
		name := "outbound/" + ob.Type() + "[" + ob.Tag() + "]"
		for _, stage := range adapter.ListStartStages {
			if err := scope.Start(name, lifecycle, stage); err != nil {
				scope.Close()
				return nil, err
			}
		}
	}
	return scope, nil
}

// set installs a tunnel's outbound, closing the one it replaces.
func (t *routeTable) set(name string, ob adapter.Outbound, scope *adapter.Scope) {
	t.mu.Lock()
	previous := t.routes[name]
	t.routes[name] = &liveRoute{outbound: ob, scope: scope}
	t.mu.Unlock()
	if previous != nil {
		previous.scope.Close()
	}
}

// remove takes a tunnel's outbound out and closes it. It reports whether
// there was one.
func (t *routeTable) remove(name string) bool {
	t.mu.Lock()
	previous, ok := t.routes[name]
	delete(t.routes, name)
	t.mu.Unlock()
	if ok {
		previous.scope.Close()
	}
	return ok
}

func (t *routeTable) closeAll() {
	t.mu.Lock()
	routes := t.routes
	t.routes = map[string]*liveRoute{}
	t.mu.Unlock()
	for _, r := range routes {
		r.scope.Close()
	}
}
