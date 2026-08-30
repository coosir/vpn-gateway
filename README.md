# vpn-gateway

Run several corporate VPNs at once and split traffic between them by domain or
IP, without installing any of their desktop clients.

Each VPN connection runs as a container on a server you control — a home NAS
works well. The container holds the VPN's mess inside its own network
namespace and exposes only a SOCKS5 proxy and a status API. The client is a
single binary with one TUN interface and a routing engine, so nothing on your
laptop or phone fights over the default route.

**Setting it up: [docs/DEPLOY.md](docs/DEPLOY.md)** walks the whole path, from
nothing installed to a laptop splitting its traffic.

See [docs/DESIGN.md](docs/DESIGN.md) for why it is built this way, and
[docs/CONTRACT.md](docs/CONTRACT.md) for the interface a VPN image implements.

## Status

Phases 0 to 2 are complete and verified end to end. What works today:

- image contract v1, with authentication on both the data and control planes
- `vg-agent`: the in-container supervisor, SOCKS5 data plane with traffic
  accounting, HTTP control plane with an event stream
- providers: `mock` (no VPN, for testing); `easyconnect` and `atrust` via
  zju-connect; `fortinet`, `globalprotect`, `pulse`, `f5`, `juniper`, `array`
  and `anyconnect` via OpenConnect; `inode` and a generic `vendor` tier for
  clients with no reimplementation
- `vpn-gateway-server`: container orchestration, per-tunnel supervision and
  restart backoff, the client-facing control API
- the trojan listener: one TLS port for every tunnel, selected by which
  password the client sends, with self-signed certificates clients pin or a
  certificate you supply
- `vgctl`: emits the client bundle and verifies every tunnel end to end
- `vpn-gateway`: the desktop client. One TUN interface or a local proxy port,
  rules by domain and IP, per-tunnel DNS, and failover that switches a tunnel
  out without disturbing the others
- interactive login: a gateway asking for an SMS code, a TOTP token, a
  captcha or a single sign-on address raises a challenge that reaches the
  client and is answered there
- a local interface in Chinese and English: live tunnel state, a rule editor
  that applies and saves without a restart, container logs, and login prompts
- a tray and window around it, for anyone who would rather not keep a browser
  tab open

Not built yet: privilege separation on the client (it currently needs
elevation itself, see below). The iNode image is written but cannot be built
or tested without H3C's installer.

## The interface

Set `ui.enabled` and the client prints a link when it starts:

```
$ sudo vpn-gateway -config client.yaml run
interface: http://127.0.0.1:8645/?token=…
```

It shows which tunnels are up and what each one claims, edits routing rules
and applies them without a restart, reads container logs from the server, and
asks for verification codes when a gateway wants one.

It listens on loopback and needs the token. Loopback alone is not enough:
this interface can reroute traffic and answer authentication prompts, so any
other process on the machine must not be able to drive it just by connecting.

It is in Chinese by default, with English a click away in the top bar. Text
that comes from a VPN gateway is passed through untouched: restating a
gateway's own message in another language would be guessing at what it said.

### Tray and window

```sh
make desktop      # the binary
make app          # and a macOS .app bundle around it

bin/vpn-gateway-desktop -config /etc/vpn-gateway/client.yaml
bin/vpn-gateway-desktop -url 'http://127.0.0.1:8645/?token=…'
```

It is built on Wails. On macOS and Linux that needs CGO and the platform's
webview libraries, so build it where it runs; on Windows the webview bindings
are pure Go, so `make desktop GOOS=windows` cross-compiles.

The tray attaches to a running client rather than starting one: creating a TUN
interface needs elevation, so the client runs as a service and a tray that
claimed to start it would be lying about what it can do. It shows which
tunnels are up, goes to a broken ring the moment one is not — including when
one is waiting for a verification code — and opens the console in a native
window.

On macOS it lives in the menu bar and takes no Dock slot.

Opening it from a launcher passes no arguments, so it has to be told where the
client is once. Either run it with `-url` a single time — the link is
remembered afterwards — or set `ui.link_file` in the client configuration to a
path your own user can read, and it will find it there:

```yaml
ui:
  enabled: true
  link_file: /Users/you/.config/vpn-gateway/link
```

That second option exists because the client usually runs elevated and keeps
its token in a directory a desktop session cannot read. Whoever can read that
file can drive the interface, so put it somewhere only you can.

It starts whether or not the client is running: a client that is down is the
case the tray exists to show. Only having no link at all stops it, and then it
says so in a dialog rather than exiting silently.

Pass `-url` when the client runs elevated and keeps its token somewhere your
desktop session cannot read.

The page is one file with no build step and reaches out to nothing. That is
deliberate: it is most needed when the tunnels are down, which is exactly when
there is no network to fetch a stylesheet or a font from.

## Which image for which VPN

| VPN | provider | image | needs |
|-----|----------|-------|-------|
| Sangfor EasyConnect | `easyconnect` | `sangfor` | nothing |
| Sangfor aTrust | `atrust` | `sangfor` | nothing |
| Fortinet | `fortinet` | `openconnect` | `NET_ADMIN`, `/dev/net/tun` |
| GlobalProtect | `globalprotect` | `openconnect` | same |
| Pulse / F5 / Juniper / Array / AnyConnect | `pulse` `f5` `juniper` `array` `anyconnect` | `openconnect` | same |
| H3C iNode | `inode` | `inode` | H3C's installer, `NET_ADMIN`, `/dev/net/tun` |

The `openconnect` image covers seven protocols because OpenConnect does. They
are all reimplementations, so none of them needs a vendor's own client.

The capability and device are for the tun interface the client creates. Both
stay inside that container's own network namespace, which is exactly what
lets several of these run at once.

## Logging in to a gateway that asks questions

Sangfor gateways commonly want a verification code. The container raises a
challenge, the server relays it, and the client asks:

```
$ vpn-gateway -config client.yaml auth
waiting for tunnels that need a verification code; press ctrl-c to stop

corp needs authentication: a code sent by SMS
  Enter the SMS verification code sent to your phone.
  Expires in 4m32s
  > 482915
tunnel corp: answer accepted
```

`run` does this too, so a tunnel that needs a code after reconnecting does not
need a second command. Answering happens on the server, so the session is
shared: every other device using that tunnel is unaffected.

Prompts are pushed over `GET /api/v1/events` rather than polled, because a
verification code is usually only valid for a minute or two.

## Running the client

```sh
# on the server
vgctl -config config.yaml client-config > client.json

# on the client, with client.json copied across
vpn-gateway -config client.yaml check     # validate
vpn-gateway -config client.yaml status    # what the server reports
vpn-gateway -config client.yaml config    # the generated sing-box config
sudo vpn-gateway -config client.yaml run  # bring up routing
```

Start with `proxy.enabled` and a local SOCKS5 port, which needs no
privileges, and switch to `tun` once the rules do what you expect.

Rules are matched in order and explicit rules come before anything derived
from what a tunnel reports, so a specific choice always beats an inferred
one:

```yaml
auto_routes: true      # a tunnel's reported CIDRs become ip_cidr rules
auto_domains: true     # its search domains become domain_suffix rules
on_failure: direct     # or block, for tunnels carrying anything sensitive

rules:
  - {domain_suffix: [corp.example.com], tunnel: office}
  - {ip_cidr: [10.20.5.0/24], tunnel: direct}   # carve one subnet back out
  - {domain_keyword: [gitlab], tunnel: lab}
```

DNS follows routing automatically: a name routed to a tunnel is also resolved
through that tunnel's own resolver, over TCP unless the tunnel reports that it
can carry datagrams. Without that, intranet names fail to resolve while
everything looks correctly configured.

### Privileges

Creating a TUN interface and installing routes needs elevation on every
platform. Today the client does that itself, so `run` needs `sudo` (or
Administrator on Windows). `packaging/` has a systemd unit that grants only
`CAP_NET_ADMIN` rather than running as root, and a launchd plist for macOS.

Splitting the client into a small privileged helper and an unprivileged main
process is the better shape and is not done yet: on macOS it needs a signed
application bundle and an Apple developer identity, which this project does
not have.

## Try it without any VPN credentials

The `mock` provider dials straight out and reports a synthetic network, so the
whole pipeline can be exercised on any machine with Docker.

```sh
make image-mock
cp config.example.yaml config.yaml     # the mock tunnel is enabled by default
./bin/vpn-gateway-server -config config.yaml -check
./bin/vpn-gateway-server -config config.yaml
```

In another shell:

```sh
TOKEN=$(cat /var/lib/vpn-gateway/api-token)
curl -sH "Authorization: Bearer $TOKEN" localhost:8642/api/v1/tunnels | jq
```

To send traffic through a tunnel directly, use its data port and secret:

```sh
SECRET=$(cat /var/lib/vpn-gateway/secrets/mock.secret)
curl --socks5-hostname "vpngw:$SECRET@127.0.0.1:21000" https://example.com/
```

## Connecting a client

The server carries every tunnel on one TLS port. A client picks a tunnel by
which trojan password it sends, so setting up a device means copying one
bundle:

```sh
vgctl -config config.yaml client-config > client.json   # for the desktop client
vgctl -config config.yaml outbounds                     # for a stock sing-box
vgctl -config config.yaml fingerprint                   # compare out of band
```

Check the whole path before configuring anything:

```sh
$ vgctl -config config.yaml verify
server vpn.example.dyndns.org:443 (sni vpn.example.dyndns.org)
  certificate is self-signed; clients pin 34:D8:53:...

  office     ok       tunnel=up   uptime=1m35s   egress=203.0.113.7
  lab        ok       tunnel=up   uptime=1m34s   egress=203.0.113.7

all 2 tunnels carried traffic
```

With `tls_mode: selfsigned` the client trusts exactly the server's
certificate. Verification is never disabled, so a certificate that does not
match is refused rather than silently accepted.

## Adding a real VPN

1. Check the server can run it: `./scripts/preflight.sh`
2. Build the image: `make image-sangfor`
3. Add a tunnel to `config.yaml`. Put the password in an environment variable
   or a `0600` file, never in the file itself.
4. `./bin/vpn-gateway-server -config config.yaml -check`, then start it.

Routes are the one thing worth stating by hand: `extra.routes` tells the
client which CIDRs belong to that tunnel, and `extra.dns` which resolver can
answer for its internal names.

## Adding a new VPN protocol

Implement `agent.Provider` under `internal/agent/providers/`, register it in
`init`, import it in `cmd/vg-agent/main.go`, and write a Dockerfile. If the
VPN client already serves a SOCKS5 proxy, `agent.Runner` does the process
supervision, readiness detection and dialing for you — see
`internal/agent/providers/sangfor`.

## Layout

```
pkg/contract/      the image contract: types and an HTTP client
internal/agent/    in-container agent, provider framework, both planes
internal/server/   config, container runtime driver, tunnel supervision, API
images/            one Dockerfile per VPN
cmd/               vg-agent, vpn-gateway-server
```

## Development

```sh
make test      # unit tests
make check     # build, vet and test
make images    # build every image
```
