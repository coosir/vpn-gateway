# vpn-gateway design

## The problem

Several corporate and campus VPN clients — Fortinet, Sangfor aTrust, Sangfor
EasyConnect, H3C iNode — cannot run at the same time. Each one grabs the
default route, installs its own DNS, and creates its own tunnel interface.
Running two means one of them stops working.

What is actually wanted is several VPNs up at once, with traffic split
between them by domain or IP.

## The approach

One rule makes concurrency possible:

> Exactly one component on any machine owns the system routing table and DNS.
> Everything else lives in userspace.

Each VPN connection runs as a container on a server. The vendor or
reimplemented client inside can mangle routes all it likes — it is doing so
inside its own network namespace, invisible to the host. The container exposes
a SOCKS5 proxy and an HTTP control plane, and nothing else. On the client, a
single TUN interface owned by sing-box does all the routing.

```
 Client (Windows/macOS/Linux; mobile later)     Server (Linux, home NAS)
 +--------------------------------+            +------------------------------+
 |  [TUN]                         |            | sing-box trojan inbound :443 |
 |    |                           |            |   demux by auth_user         |
 |  sing-box routing engine       |            |  +------+------+------+      |
 |   |- direct  ------------------+--> internet|  v      v      v      v      |
 |   |- trojan(user=forti) -------+---TLS:443->| forti  ec   atrust inode     |
 |   |- trojan(user=ec)    -------+----------->| container   container        |
 |   '- trojan(user=atrust)-------+----------->|  :1080 SOCKS5, own netns     |
 |                                |            |                              |
 |  control API client <----------+--HTTPS---->| control API                  |
 +--------------------------------+            +---------+-------+------------+
                                                         v       v
                                                    corp A   campus B
```

## Key decisions

**The contract is the product.** [docs/CONTRACT.md](CONTRACT.md) is what makes
adding a VPN cheap. The server knows nothing about VPN protocols.

**One trojan port, one user per tunnel.** Only `:443` is exposed, and it looks
like HTTPS. sing-box maps `auth_user` to the matching container. This was the
design's main bet, because upstream had reported intermittent `auth_user`
matching; it is now covered by a concurrency test that runs hundreds of
interleaved requests across several users under the race detector, and it has
not misrouted once. The fallback, one port per tunnel, is no longer needed.

Traffic that matches no tunnel rule is blocked, never sent out the server's
own connection. Falling through to direct would look like a working tunnel
while quietly leaking intranet-bound traffic to the internet, which is far
harder to notice than a refused connection.

**Routing rules live on the client.** The server is dumb — user to container,
one to one, generated, never hand-edited. One source of truth, and each device
can have its own rules.

**The server discovers, the client generates.** Routes and DNS reported by a
container become implicit routing rules and a tunnel-scoped resolver on the
client. Users normally only add a few domain rules by hand.

**Authenticate once, share everywhere.** Interactive login (aTrust's SMS, a
vendor client's graphical first login) happens on the server and the session
persists. A phone gets the corporate VPN without installing anything.

**Both planes authenticate.** Container network isolation is not enough: some
engines let containers on separate bridge networks reach each other. Each
tunnel gets its own secret, enforced on the SOCKS5 data plane and the HTTP
control plane, so a compromised vendor client cannot pivot into another
tunnel.

## Deployment

Run the server on a home NAS or small always-on box, not a VPS.

A residential IP does not trip the impossible-travel and datacenter-IP alerts
that corporate VPNs raise, which at worst lock the account. A home server is
also network-close to domestic VPN gateways, which matters because every
intranet request is now `client -> server -> VPN gateway -> target`.

If trojan is also wanted for crossing a national firewall, that is a **second,
separate server** abroad and a sibling outbound in the client config. Merging
the two would send intranet traffic on a pointless intercontinental detour.

## Provider tiers

A VPN enters at whatever tier is available and graduates as reimplementations
appear.

- **Tier A — native reimplementation.** No vendor binary. `trojan` (built into
  sing-box), `easyconnect` and `atrust` (via zju-connect), `fortinet`
  (openfortivpn or a Go port).
- **Tier B — a reimplementation that installs its own interface.**
  OpenConnect covers Fortinet, GlobalProtect, Pulse, F5, Juniper, Array and
  AnyConnect from one image. It creates a tun interface inside the container,
  and because the agent shares that namespace an ordinary dial already goes
  through it. The userspace-stack approach this originally planned turned out
  to be unnecessary: the container is already the isolation.
- **Tier C — vendor client in a sandbox.** The vendor's own Linux client, with
  a VNC challenge for graphical first login. The honest fallback for anything
  not yet reimplemented, and the reason `vnc` exists in the contract.

Images needing a vendor binary ship as a Dockerfile only. The operator
supplies their own licensed installer; vendor binaries are never
redistributed.

## Fragile assumption

This design assumes corporate VPN gateways do not reject a login because the
source IP is a fixed server. Home deployment is the mitigation, and it is the
only reason a VPS is not recommended: the failure mode is not a rework, it is
a locked account.

## TLS for a home server

`selfsigned` is the default. It issues a long-lived certificate on first run
and the client trusts exactly that certificate, pinning its fingerprint.
Verification is never disabled: an unpinned or mismatched certificate is
refused rather than accepted. Renewal means re-pinning every client, which is
why the lifetime is ten years and why an existing certificate is reused even
close to expiry.

`files` takes a certificate you supply. Any ACME client with DNS-01 support
produces one, which is how to use Let's Encrypt from behind NAT without
exposing port 80.

## Status

Phases 0 and 1 are done and verified.

Phase 0: the contract, the agent with both planes, the provider framework,
the mock and Sangfor providers, container orchestration, tunnel supervision,
and the client-facing control API.

Phase 1: the trojan listener with per-tunnel users, TLS with pinned
self-signed certificates, the client bundle, and `vgctl verify`, which
connects through every tunnel the way a real client does.

Phase 2: the desktop client. A TUN interface or a local proxy port, rules by
domain and IP, DNS that follows routing, and per-tunnel failover.

Two things in the client are worth calling out.

**Rules target a selector, never a tunnel directly.** Each tunnel gets a
selector holding `[tunnel, fallback]`. When a tunnel goes down the client
switches that one selector in place. Rebuilding the configuration and
restarting instead would tear down every other tunnel's connections, which is
exactly the disruption tunnels are supposed to be isolated from.

**DNS follows routing.** An intranet name resolves only through the VPN's own
resolver, which is reachable only through that tunnel. Every rule that selects
by name gets a matching DNS rule, and each tunnel's resolver is reached
through its selector so it fails over with the tunnel. The query goes over TCP
unless the tunnel reports that its data plane carries datagrams. Routing the
traffic without also routing the lookup is the failure that looks correctly
configured and does not work.

Phase 4: interactive login. A gateway that wants an SMS code, a TOTP token, a
captcha or a single sign-on address raises a contract challenge; the server
relays it and the client asks whoever is there.

The supervised clients ask on standard input and block, so the agent had to
learn to write back to them. Two details decide whether this works at all. A
prompt carries no trailing newline, so a line-based reader never sees it and
the tunnel blocks forever showing nothing. And the readiness deadline has to
be suspended while a question is pending, or the client is killed while
someone is still looking for their phone.

Answering happens once, on the server, and the session persists. A phone using
the same tunnel never sees the prompt.

Phase 4 also adds the vendor tier: a provider that runs a vendor's own Linux
client in the container. It shares the network namespace with the agent, so
once the client connects an ordinary dial already goes through the tunnel and
no forwarder is needed. Where the client has no headless login at all, the
image serves a screen and the agent raises a vnc challenge. That is ugly, and
it is the honest price of a client never meant to run without a desktop.

Phase 3: the OpenConnect image, covering seven protocols. Two things came out
of running it rather than reasoning about it.

Readiness is the tun interface existing and holding an address, not a phrase
in the client's output. Seven protocols word their success differently and the
wording changes between versions; an interface either has an address or it
does not.

And the questions these gateways ask are worded by the gateway, so there is no
phrase to match. What is reliable is the shape: a log line is terminated,
while a question leaves the cursor after its colon. That alone is not enough,
because output such as an OpenSSL error is full of colons and a read boundary
can land after one, so a fragment must also stand unchanged for a moment
before it is treated as a question. A real prompt is followed by silence; half
a log line is not.

Phase 5: the interface. The client serves it on loopback behind a token.

It is a web page rather than a native window for a reason that is not
convenience: a native window cannot be checked here, and shipping an
interface nobody has looked at is the same mistake as shipping a privileged
helper nobody has run. This one was opened in a browser, screenshotted, and
driven through every path it offers.

The page is a single file with no build step and no external request. It is
most needed when the tunnels are down, which is exactly when there is no
network to fetch a webfont from, so every typeface is one the machine already
has and the whole thing is embedded in the binary.

Editing rules cannot be done in place the way a tunnel going down can: rules
are compiled into the routing engine, so applying them rebuilds it and
interrupts open connections. The new configuration is therefore built and
accepted before the running one is touched, and a rule with a typo in it
leaves the client running exactly as it was.

Client privilege separation is still open: creating a TUN interface needs
elevation, and splitting out a signed helper needs an Apple developer identity
on macOS.
