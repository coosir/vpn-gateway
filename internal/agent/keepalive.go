package agent

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
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

	k := &keepaliveLoop{agent: a, interval: interval, timeout: timeout}
	ticker := time.NewTicker(interval / keepaliveSamples)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			k.round(ctx, now)
		}
	}
}

// keepaliveSamples is how many times an interval the traffic counters are
// looked at.
//
// The question being asked is whether the tunnel has been idle for an
// interval, and answering it by comparing against the last look would mean
// something else: traffic arriving just after one look leaves the next one
// with nothing to report, and the tunnel then sits untouched for nearly two
// intervals before anybody asks after it. Looking more often than the
// interval is what makes "idle for an interval" mean what it says.
const keepaliveSamples = 4

// keepaliveLoop is one agent's keepalive: what it was configured with, and
// what it has seen.
type keepaliveLoop struct {
	agent    *Agent
	interval time.Duration
	timeout  time.Duration

	// lastActivity is when the tunnel last carried something -- real traffic,
	// or a probe of our own, which serves the same purpose. Zero means the
	// tunnel has only just come up and has not been watched yet.
	lastActivity time.Time
	lastBytes    uint64
	// failing records a spell of probes that went unanswered, so it is
	// reported when it starts and when it ends rather than every round.
	failing bool
	// mentioned records that a tunnel with nowhere to probe has been
	// reported once.
	mentioned bool
}

// round is one look at the tunnel: probe it if nothing else has.
func (k *keepaliveLoop) round(ctx context.Context, now time.Time) {
	a := k.agent

	a.mu.RLock()
	state := a.state
	a.mu.RUnlock()
	if state != contract.StateUp {
		// Nothing to keep alive, and whatever the last probe found says
		// nothing about the session that comes back. The clock starts again
		// with that session.
		k.failing = false
		k.lastActivity = time.Time{}
		return
	}

	bytes := a.tx.Load() + a.rx.Load()
	if k.lastActivity.IsZero() {
		k.lastBytes = bytes
		k.lastActivity = now
		return
	}
	if bytes != k.lastBytes {
		// Real traffic is the best keepalive there is: the gateway has just
		// seen everything a probe was going to tell it.
		k.lastBytes = bytes
		k.lastActivity = now
		k.failing = false
		return
	}
	if now.Sub(k.lastActivity) < k.interval {
		return
	}

	targets := a.keepaliveTargets()
	if len(targets) == 0 {
		if !k.mentioned {
			k.mentioned = true
			a.log.Warn("keepalive has nowhere to probe: this tunnel pushed no resolvers and installed none, so set extra.keepalive_target to an address inside the network")
		}
		k.lastActivity = now
		return
	}
	k.mentioned = false
	// Whatever the answer, the asking is what the gateway was waiting for, so
	// the next one is a full interval away.
	k.lastActivity = now

	err := a.probe(ctx, targets, k.timeout)
	switch {
	case err == nil && k.failing:
		k.failing = false
		a.Log("keepalive is reaching the network again")
	case err == nil:
		a.log.Debug("keepalive", "targets", targets)
	case ctx.Err() != nil:
		return
	case !k.failing:
		// Said once per spell of failure, not once per round. A refused
		// connection still crossed the tunnel and still kept the session
		// alive; this is reported so a target that will never answer can be
		// corrected, not because the tunnel is in trouble.
		k.failing = true
		a.log.Warn("keepalive could not reach anything through the tunnel",
			"targets", targets, "error", err)
	}
}

// probe sends something through the tunnel and reports whether anything came
// back, stopping at the first target that answers.
//
// There are two ways to ask, because there are two kinds of tunnel here. One
// installs an interface in this container and gets a resolver with it; the
// other hands us a proxy and installs nothing. The interface kind is asked a
// question its resolver will answer, because a corporate resolver that
// refuses TCP on 53 still answers a datagram -- one of the gateways here does
// exactly that, and a keepalive that only knew how to open a socket would
// send unanswered packets at it forever and call itself broken.
func (a *Agent) probe(ctx context.Context, targets []string, timeout time.Duration) error {
	viaInterface := a.onAnInterface()
	var first error
	note := func(t string, err error) {
		if first == nil {
			first = fmt.Errorf("%s: %w", t, err)
		}
	}
	for _, t := range targets {
		if viaInterface {
			if err := a.resolverProbe(ctx, t, timeout); err == nil {
				return nil
			} else {
				note(t, err)
			}
		}
		dialCtx, cancel := context.WithTimeout(ctx, timeout)
		conn, err := a.Dial(dialCtx, "tcp", t)
		cancel()
		if err == nil {
			conn.Close()
			return nil
		}
		note(t, err)
	}
	return first
}

// onAnInterface reports whether the tunnel is an interface in this container.
func (a *Agent) onAnInterface() bool {
	if a.tunnelUp != nil {
		return a.tunnelUp()
	}
	return TunnelInterfaceUp()
}

// resolverProbe asks the resolver at target to look up a name, over UDP,
// through whatever interface the routing table says reaches it.
//
// What the resolver says about the name does not matter: an answer of any
// kind is a round trip through the tunnel, which is both the traffic the
// gateway is waiting to see and proof that the session still carries it. So
// the question is written and read here rather than handed to a resolver
// library, which reports a nameserver that said nothing at all and one that
// said "no such name" as the same thing -- and those are opposite answers to
// the only question being asked.
func (a *Agent) resolverProbe(ctx context.Context, target string, timeout time.Duration) error {
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	var d net.Dialer
	conn, err := d.DialContext(dialCtx, "udp", target)
	cancel()
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	query, id := dnsQuery(a.keepaliveName())
	if _, err := conn.Write(query); err != nil {
		return err
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return err
	}
	if n < dnsHeaderLen || buf[0] != byte(id>>8) || buf[1] != byte(id) || buf[2]&0x80 == 0 {
		return errors.New("the resolver sent something that was not an answer")
	}
	return nil
}

// dnsHeaderLen is the fixed part of a DNS message.
const dnsHeaderLen = 12

// dnsQuery builds a question about name's address record, and returns it with
// the id that identifies the answer.
func dnsQuery(name string) ([]byte, uint16) {
	id := uint16(rand.Uint32())
	msg := make([]byte, 0, dnsHeaderLen+len(name)+6)
	msg = append(msg,
		byte(id>>8), byte(id),
		0x01, 0x00, // a recursive question
		0x00, 0x01, // one of them
		0, 0, 0, 0, 0, 0,
	)
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if label == "" || len(label) > 63 {
			continue
		}
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	msg = append(msg,
		0x00,       // the root label ends the name
		0x00, 0x01, // an address
		0x00, 0x01, // on the internet
	)
	return msg, id
}

// keepaliveName is the name the resolver probe asks about: the gateway's own
// hostname, which is the one name every tunnel here is certain to know.
func (a *Agent) keepaliveName() string {
	name := a.cfg.Server
	if host, _, err := net.SplitHostPort(name); err == nil {
		name = host
	}
	if name == "" {
		return "localhost"
	}
	return name
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
