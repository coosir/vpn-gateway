package agent

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/vpn-gateway/vpn-gateway/pkg/contract"
)

// Keepalive settings.
//
// A gateway that hangs up on an idle session is generous about it: the idle
// windows in the wild are hours, or most of an hour at the tightest. So the
// probe is rare by default. Probing more often than the gateway's patience
// requires buys nothing and puts a connection at a corporate network every
// time; a gateway that is stricter than this is told so with
// keepalive_interval.
//
// The timeout is the other kind of number: it bounds one probe, which either
// answers in a moment or is not going to.
const (
	defaultKeepaliveInterval = 30 * time.Minute
	defaultKeepaliveTimeout  = 10 * time.Second

	// minKeepaliveInterval is the floor under a configured interval. Below
	// this a keepalive stops being a reminder that somebody is there and
	// becomes a load generator against a corporate gateway.
	minKeepaliveInterval = 5 * time.Second

	// keepalivePort is where a target named without one is assumed to
	// listen, because the default targets are the resolvers the VPN pushed.
	keepalivePort = "53"
)

// keepalive sends a little traffic through the tunnel now and then, so a
// gateway that disconnects idle sessions sees a session that is not idle.
//
// It lives in the agent rather than in any provider because idling out is not
// a property of one protocol: every gateway here does it, and each client
// underneath is a different program with different flags, some of which have
// no keepalive at all. What every provider does have is Dial, so a probe
// through it is the one mechanism that reaches every tunnel, whether traffic
// leaves through a client's own SOCKS proxy or through routes it installed in
// this container's namespace.
//
// A client's own dead-peer detection is not this. Those packets keep the link
// from being declared dead by the protocol; the timer that drops a session
// for being idle counts what the user sent, and DPD is not that.
//
// It runs for the agent's whole life and probes only while the tunnel is up,
// so it costs nothing while a tunnel is down, parked, or waiting for someone
// to answer a gateway's question.
func (a *Agent) keepalive(ctx context.Context) {
	if !a.cfg.Bool("keepalive", true) {
		a.log.Info("keepalive is off; a gateway that drops idle sessions will drop this one")
		return
	}
	interval := cfgDuration(a.cfg, "keepalive_interval", defaultKeepaliveInterval)
	if interval < minKeepaliveInterval {
		interval = minKeepaliveInterval
	}
	timeout := cfgDuration(a.cfg, "keepalive_timeout", defaultKeepaliveTimeout)
	a.log.Info("keepalive running", "every", interval, "timeout", timeout)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var st keepaliveState
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		a.keepaliveRound(ctx, &st, timeout)
	}
}

// keepaliveState is what one round remembers from the last: whether it is in
// a spell of failure, whether the missing target has been mentioned, and how
// much traffic had crossed the tunnel by then.
type keepaliveState struct {
	failing   bool
	mentioned bool
	lastBytes uint64
}

// keepaliveRound is one tick: probe the tunnel unless something else already
// has.
func (a *Agent) keepaliveRound(ctx context.Context, st *keepaliveState, timeout time.Duration) {
	a.mu.RLock()
	state := a.state
	a.mu.RUnlock()
	if state != contract.StateUp {
		// Nothing to keep alive, and whatever the last probe found says
		// nothing about the session that comes back.
		st.failing = false
		return
	}

	// Real traffic is the best keepalive there is. If any crossed the tunnel
	// since the last tick, the gateway has already seen what this probe was
	// going to tell it.
	if bytes := a.tx.Load() + a.rx.Load(); bytes != st.lastBytes {
		st.lastBytes = bytes
		st.failing = false
		return
	}

	targets := a.keepaliveTargets()
	if len(targets) == 0 {
		if !st.mentioned {
			st.mentioned = true
			a.log.Warn("keepalive has nowhere to probe: this tunnel pushed no resolvers and installed none, so set extra.keepalive_target to an address inside the network")
		}
		return
	}
	st.mentioned = false

	err := a.probe(ctx, targets, timeout)
	switch {
	case err == nil && st.failing:
		st.failing = false
		a.Log("keepalive is reaching the network again")
	case err == nil:
		a.log.Debug("keepalive", "targets", targets)
	case ctx.Err() != nil:
		return
	case !st.failing:
		// Said once per spell of failure, not once per round. A refused
		// connection still crossed the tunnel and still kept the session
		// alive; this is reported so a target that will never answer can be
		// corrected, not because the tunnel is in trouble.
		st.failing = true
		a.log.Warn("keepalive could not reach anything through the tunnel",
			"targets", targets, "error", err)
	}
}

// probe opens and immediately closes a connection through the tunnel,
// stopping at the first target that answers.
func (a *Agent) probe(ctx context.Context, targets []string, timeout time.Duration) error {
	var first error
	for _, t := range targets {
		dialCtx, cancel := context.WithTimeout(ctx, timeout)
		conn, err := a.Dial(dialCtx, "tcp", t)
		cancel()
		if err == nil {
			conn.Close()
			return nil
		}
		if first == nil {
			first = fmt.Errorf("%s: %w", t, err)
		}
	}
	return first
}

// keepaliveTargets is what to connect to, as "host:port".
//
// The resolvers are the default because they are the one address a tunnel is
// certain to have: they were named by the gateway itself, they sit inside the
// network, and a corporate resolver answers TCP on 53. A tunnel whose useful
// addresses are elsewhere names them instead.
//
// They are looked for twice, because a provider reports them only when
// somebody configured them. A client that installs a tun interface also
// rewrites /etc/resolv.conf with what the gateway handed out, and that is
// worth reading: it is the difference between a tunnel that keeps itself
// alive out of the box and one that needs a line of configuration first.
func (a *Agent) keepaliveTargets() []string {
	if v := a.cfg.Str("keepalive_target", ""); v != "" {
		return withKeepalivePort(splitList(v))
	}
	if dns := a.Network().DNS; len(dns) > 0 {
		return withKeepalivePort(dns)
	}
	return withKeepalivePort(a.baseNet.PushedResolvers())
}

func withKeepalivePort(hosts []string) []string {
	out := make([]string, 0, len(hosts))
	for _, h := range hosts {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(h); err != nil {
			h = net.JoinHostPort(h, keepalivePort)
		}
		out = append(out, h)
	}
	return out
}

// cfgDuration reads a setting that is a length of time, written either as a
// duration ("90s", "5m") or as a bare number of seconds, which is how the
// server's own configuration spells its timeouts.
func cfgDuration(cfg Config, key string, def time.Duration) time.Duration {
	v := cfg.Str(key, "")
	if v == "" {
		return def
	}
	if d, err := time.ParseDuration(v); err == nil && d > 0 {
		return d
	}
	if n, err := strconv.Atoi(v); err == nil && n > 0 {
		return time.Duration(n) * time.Second
	}
	return def
}
