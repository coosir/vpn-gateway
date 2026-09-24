package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// probeTimeout bounds one probe end to end: reaching the node, the node
// reaching the target, and the answer coming back.
const probeTimeout = 15 * time.Second

// Probe asks for url through the named tunnel's outbound, the same one a
// client's traffic takes, and reports nil when an answer came back.
//
// Only a status below 400 counts. A trojan node that does not accept the
// password it is given does not say so: it hands the stream to the website it
// hides behind, and that site answers what it sees -- a trojan header where a
// request line should be -- with a 400. Taking any answer as proof would call
// a node that turns us away a node that works.
func (p *Proxy) Probe(ctx context.Context, tunnel, url string) error {
	if p == nil || p.instance == nil {
		return errors.New("the listener is not running")
	}
	ob, ok := p.instance.Outbound().Outbound(tunnelPrefix + tunnel)
	if !ok {
		return fmt.Errorf("no outbound for tunnel %q", tunnel)
	}
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return ob.DialContext(ctx, network, M.ParseSocksaddr(addr))
			},
			// A probe is one question; a connection kept for the next one
			// five minutes later would be a stale one by then.
			DisableKeepAlives: true,
		},
		// A redirect is an answer in itself, and following it could leave
		// the tunnel's network for somewhere it cannot vouch for.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "vpn-gateway-probe")
	resp, err := client.Do(req)
	if err != nil {
		return trimProbeError(err, url)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode >= 400 {
		return fmt.Errorf("%s answered %s", url, resp.Status)
	}
	return nil
}

// trimProbeError drops the method and URL net/http wraps every error in; the
// alert already names the tunnel and the reader knows what was asked.
func trimProbeError(err error, url string) error {
	return errors.New(strings.TrimPrefix(err.Error(), `Get "`+url+`": `))
}

// LastTraffic reports when the named tunnel last carried data back to a
// client: the time an answer from the far side was seen, zero if never.
func (p *Proxy) LastTraffic(tunnel string) time.Time {
	if p == nil || p.traffic == nil {
		return time.Time{}
	}
	return p.traffic.last(tunnel)
}

// trafficTracker notes, per tunnel, the last time the far side sent a client
// anything. That is proof the tunnel works that costs nothing, and while it
// keeps coming there is no need to probe.
//
// Only data coming back counts. A client sending into a tunnel whose far end
// is gone still writes happily; it is the answer that shows the path is whole.
type trafficTracker struct {
	seen map[string]*atomic.Int64
}

var _ adapter.ConnectionTracker = (*trafficTracker)(nil)

func newTrafficTracker(routes []Route) *trafficTracker {
	t := &trafficTracker{seen: make(map[string]*atomic.Int64, len(routes))}
	for _, r := range routes {
		t.seen[r.Name] = new(atomic.Int64)
	}
	return t
}

func (t *trafficTracker) last(tunnel string) time.Time {
	v, ok := t.seen[tunnel]
	if !ok || v.Load() == 0 {
		return time.Time{}
	}
	return time.Unix(0, v.Load())
}

func (t *trafficTracker) counter(ob adapter.Outbound) N.CountFunc {
	if ob == nil {
		return nil
	}
	name, ok := strings.CutPrefix(ob.Tag(), tunnelPrefix)
	if !ok {
		return nil
	}
	v, ok := t.seen[name]
	if !ok {
		return nil
	}
	return func(n int64) {
		if n > 0 {
			v.Store(time.Now().UnixNano())
		}
	}
}

// RoutedConnection wraps a client's connection so writes to it -- data from
// the far side -- are noticed. The counting wrapper keeps the extended
// interfaces sing-box copies through, so this costs a timestamp per write
// rather than the fast path.
func (t *trafficTracker) RoutedConnection(_ context.Context, conn net.Conn, _ adapter.InboundContext, _ adapter.Rule, ob adapter.Outbound) net.Conn {
	count := t.counter(ob)
	if count == nil {
		return conn
	}
	return bufio.NewCounterConn(conn, nil, []N.CountFunc{count})
}

// RoutedPacketConnection is RoutedConnection for UDP.
func (t *trafficTracker) RoutedPacketConnection(_ context.Context, conn N.PacketConn, _ adapter.InboundContext, _ adapter.Rule, ob adapter.Outbound) N.PacketConn {
	count := t.counter(ob)
	if count == nil {
		return conn
	}
	return bufio.NewCounterPacketConn(conn, nil, []N.CountFunc{count})
}
