package agent

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// defaultPathProbeSize is the size, in bytes of IP packet, of the echo the
// path check sends. It sits under every tunnel MTU here (1390-1400) with room
// for the encapsulation a client adds, and far above the 576 a client can
// fall back to.
const defaultPathProbeSize = 1200

// pathSmallSize is the echo that says the host answers at all: the size of a
// plain ping.
const pathSmallSize = 84

// pathProbeAttempts is how many times each echo is sent before it is called
// lost. One lost packet is weather; three in a row, with the small echo
// answered, is the path.
const pathProbeAttempts = 3

// checkPath asks whether the tunnel still carries full-sized packets, and not
// just the small ones a keepalive sends.
//
// A tunnel can go on answering a DNS query, a ping, a dead-peer probe --
// everything small -- while dropping every packet past some size without a
// word. openconnect does exactly that when it detects a DTLS MTU of 576 after
// a lossy minute: the interface stays at 1390, anything bigger than 576 goes
// into the tunnel and never comes out, and TCP sits on unacknowledged data.
// Every check that only sends small packets reports that tunnel up, which is
// how one stayed "up" here for two days with nothing behind it reachable.
//
// The question is an ICMP echo rather than a padded DNS query, because a
// corporate resolver may refuse a large query -- the one behind that very
// tunnel ignores anything past a plain question, while answering 1300-byte
// pings. And it is asked twice, small and large, of the same host: only a
// host that answers the small echo and loses the large one says anything
// about the path. One that answers neither does not answer pings, and is
// left alone.
//
// It runs whether or not the tunnel is busy, because a broken path is exactly
// a tunnel with traffic in it that is not getting through.
func (k *keepaliveLoop) checkPath(ctx context.Context, now time.Time) {
	a := k.agent
	if k.pathSize <= 0 || !a.onAnInterface() {
		// A tunnel reached through a client's proxy has no packets of ours
		// to size: the client carries streams, and its path is its own.
		return
	}
	if k.lastPath.IsZero() {
		k.lastPath = now
		return
	}
	if now.Sub(k.lastPath) < k.interval {
		return
	}
	k.lastPath = now

	var lost error
	for _, t := range a.keepaliveTargets() {
		host := t
		if h, _, err := net.SplitHostPort(t); err == nil {
			host = h
		}
		if a.echoAttempts(ctx, host, pathSmallSize, k.timeout) != nil {
			continue // does not answer pings, so it cannot tell us anything
		}
		err := a.echoAttempts(ctx, host, k.pathSize, k.timeout)
		if err == nil {
			if k.pathBroken {
				k.pathBroken = false
				a.Log("the tunnel carries %d-byte packets again", k.pathSize)
			}
			return
		}
		lost = fmt.Errorf("%s: %w", host, err)
	}
	if lost == nil || ctx.Err() != nil {
		return // nobody to ask, or nobody who answers pings
	}

	k.pathBroken = true
	a.Log("the tunnel answers small packets but loses %d-byte ones (%v); whatever is behind it is unreachable even though it looks up", k.pathSize, lost)
	r, ok := a.provider.(Refresher)
	if !ok {
		return
	}
	if err := r.Refresh(); err != nil {
		a.log.Warn("could not ask the client to rebuild its data path", "error", err)
		return
	}
	a.Log("asked the client to rebuild its data path on the session it holds")
}

// echoAttempts sends up to pathProbeAttempts echoes and reports whether any
// was answered.
func (a *Agent) echoAttempts(ctx context.Context, host string, size int, timeout time.Duration) error {
	echo := a.echo
	if echo == nil {
		echo = icmpEcho
	}
	var err error
	for i := 0; i < pathProbeAttempts; i++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err = echo(ctx, host, size, timeout); err == nil {
			return nil
		}
	}
	return err
}

// ipICMPHeaders is what IPv4 and ICMP add in front of an echo's data.
const ipICMPHeaders = 20 + 8

// icmpEcho pings host with an echo of size bytes of IP packet.
//
// Fragmentation is left allowed on purpose. A tunnel whose interface MTU is
// genuinely smaller than size splits the echo and delivers it, and that
// tunnel is fine; forbidding it would call every such tunnel broken. The
// failure this looks for drops the packet inside the client whatever its
// flags say.
func icmpEcho(ctx context.Context, host string, size int, timeout time.Duration) error {
	dst := net.ParseIP(host).To4()
	if dst == nil {
		return fmt.Errorf("%s is not an IPv4 address", host)
	}
	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return err
	}
	defer c.Close()
	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	c.SetDeadline(deadline)

	id, seq := os.Getpid()&0xffff, int(time.Now().UnixNano()&0xffff)
	data := make([]byte, max(size-ipICMPHeaders, 0))
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Body: &icmp.Echo{ID: id, Seq: seq, Data: data},
	}
	wire, err := msg.Marshal(nil)
	if err != nil {
		return err
	}
	if _, err := c.WriteTo(wire, &net.IPAddr{IP: dst}); err != nil {
		return err
	}
	buf := make([]byte, 2048)
	for {
		n, from, err := c.ReadFrom(buf)
		if err != nil {
			return err
		}
		if ip, ok := from.(*net.IPAddr); !ok || !ip.IP.Equal(dst) {
			continue
		}
		reply, err := icmp.ParseMessage(1, buf[:n])
		if err != nil || reply.Type != ipv4.ICMPTypeEchoReply {
			continue
		}
		// Every echo in the container arrives on a raw socket, ours and
		// anybody else's, so it is ours only if it says so.
		if e, ok := reply.Body.(*icmp.Echo); ok && e.ID == id && e.Seq == seq {
			return nil
		}
	}
}
