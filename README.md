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
- providers: `direct` (direct server host network / LAN routing, no container);
  `trojan` (upstream Trojan proxy/VPN node forwarding, no container);
  `mock` (no VPN, for testing); `easyconnect` and `atrust` via
  zju-connect; `fortinet`, `globalprotect`, `pulse`, `f5`, `juniper`, `array`
  and `anyconnect` via OpenConnect; `inode` and a generic `vendor` tier for
  clients with no reimplementation
- `vpn-gateway-server`: container orchestration, per-tunnel supervision and
  restart backoff, the client-facing control API
- user authentication: optional server-side username & hashed password
  verification (`bcrypt`, `sha256`), password hashing tool (`vgctl hash-password`),
  and client credential enforcement
- the trojan listener: one TLS port for every tunnel, selected by which
  password the client sends, with self-signed certificates clients pin or a
  certificate you supply
- `vgctl`: emits the client bundle and verifies every tunnel end to end
- per-tunnel control: nothing dials by itself, and a tunnel that keeps
  failing stops rather than knocking
- `vpn-gateway`: the desktop client. TUN interface or local proxy port,
  custom and auto-derived routing rules by domain and IP with enable/disable
  toggles, per-tunnel DNS, and failover
- interactive login: a gateway asking for an SMS code, a TOTP token, a
  captcha or a single sign-on address raises a challenge that reaches the
  client and is answered there
- a local interface in Chinese and English: live tunnel state, rule editor
  with auto-rule visibility and toggles, container logs, and login prompts
- a tray and native window around it for macOS (with background launchd
  helper service for TUN mode), Windows, and Linux

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
```

Then open it. It takes no arguments: it runs the client itself, opens on a
setup screen, takes the bundle your server issued, and connects when told to.
Everything after that — rules, settings, logs — is in the same window.

It is built on Wails. On macOS and Linux that needs CGO and the platform's
webview libraries, so build it where it runs; on Windows the webview bindings
are pure Go, so `make desktop GOOS=windows` cross-compiles.

It starts as a local proxy, which needs no privileges at all, so the rules can
be proven before anything touches the routing table. Switching to a TUN
interface in the settings takes over the whole machine and needs to be run
with administrator rights.

The tray shows which tunnels are up and goes to a broken ring the moment one
is not. On macOS it lives in the menu bar and takes no Dock slot; closing the
window leaves it running.

Its configuration lives in your own directory, not `/etc`, because it is
opened by whoever is sitting at the machine and has to be able to write what
it is told without being elevated first.

`vpn-gateway run` is still there for a machine that should connect without
anyone logging in, and reads the same configuration.

Pass `-url` when the client runs elevated and keeps its token somewhere your
desktop session cannot read.

The page is one file with no build step and reaches out to nothing. That is
deliberate: it is most needed when the tunnels are down, which is exactly when
there is no network to fetch a stylesheet or a font from.

## Which image for which VPN

| VPN | provider | image | needs |
|-----|----------|-------|-------|
| Server Host / LAN | `direct` | *(none)* | direct host network routing |
| Upstream Trojan Node | `trojan` | *(none)* | upstream Trojan server forwarding |
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

### Dialling

Tunnels wait to be told. Each one is connected and disconnected on its own
from the client, and the decision survives a server restart.

That is not a convenience. Every attempt is a full authentication against a
corporate gateway, and enough failures in a row is what locks an account. A
tunnel that fails stops after a few tries and waits, rather than knocking at a
gateway that is refusing it:

```yaml
    autostart: true     # dial when the server starts, for a tunnel with
                        # nothing to lock out
    manual: true        # never dial except when a person asks
    max_attempts: 3     # tries before it stops and waits (the default)
```

`manual` is for a gateway that asks for an SMS code or a captcha. Those cannot
be answered by a server: dialling one while nobody is watching parks the
tunnel at auth_required with a question nobody was asked. A manual tunnel
starts down after a restart, and stands down again the moment it stops being
up, so every dial is somebody pressing connect with a phone in their hand. A
session still up is adopted rather than stopped, because a restart must not
spend a code again.

Keeping such a session alive is worth configuring. An openconnect tunnel
reconnects with the session cookie it already holds, which asks the gateway
for nothing; `extra: {reconnect_timeout: "1800"}` is how long it keeps trying
before giving up and needing a fresh login. The default is five minutes.

Restarting the server does not redial. The containers are left running and
the next start adopts the sessions already dialled, so an upgrade or a
configuration change costs the moment the listener is unbound rather than a
fresh login at every gateway.

Clients are a different matter: sessions live in memory, so a restart forgets
every token it issued and every trojan password derived from one. A connected
client finds itself refused, and logs in again on its own with a widening
backoff rather than sitting in failure until somebody notices. It gives up
only when the server refuses the credentials themselves, which no amount of
retrying would fix and which every attempt at counts against an account that
may lock. `stop_containers_on_exit: true` asks for the
opposite, for a server whose stopping should leave nothing connected.

Rejected credentials stop it immediately, without using up the attempts. In
every case a reconnect from the client starts it again, so a corrected
password does not mean recreating anything.

Pressing connect on something already connected does nothing, and a burst of
requests -- two clients, or one impatient person -- comes to a single dial.

### Two-factor

Gateways ask for a one-time code in one of two shapes, and nothing in the
protocol distinguishes them, so the configuration says which:

```yaml
# The gateway prompts for the code separately.
extra: {totp_secret: "BASE32SEED"}

# The gateway has no second prompt: it wants the code joined onto the end of
# the password, so the field carries "yourpassword123456".
extra: {totp_secret: "BASE32SEED", totp_append: "true"}
```

Either way the code is computed for each attempt, so a reconnect an hour later
sends a current one, and a code with only a moment of its life left is held
back for the next one rather than spent on a login that would be rejected.

The seed can be written the way an authenticator app shows it — spaced,
lowercase, unpadded. `totp_digits`, `totp_period` and `totp_algorithm` are
there for a gateway that departs from six digits over thirty seconds with
SHA-1.

One-time codes depend on the clock: a server whose time has drifted more than
about half a period will have every code rejected, with nothing to say why.

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
platform. From the command line the client does that itself, so `run` needs
`sudo` (or Administrator on Windows). `packaging/` has a systemd unit that
grants only `CAP_NET_ADMIN` rather than running as root.

An application opened from a launcher has no such option, so on macOS it
installs a background service instead: **Settings → Background service →
Install and hand over**. One authorisation prompt copies the client into
`/Library/PrivilegedHelperTools`, writes a launchd daemon that runs it as root
at boot, and starts it. Both then use the same configuration file, so nothing
has to be set up twice.

From that point the application is the service's front end rather than a
client of its own: the window shows the service's interface and the menu bar
reports its tunnels. Two engines would fight over one routing table, so the
one in this application stops when the service takes over and starts again
when the service is removed. Removing it is the same screen, and leaves the
configuration where it is.

The executable the service runs is copied somewhere only root can write. The
configuration is not: it stays in the home directory of whoever authorised the
install, because that is the person the service exists to serve and they can
already reroute this machine by definition.

Splitting the client into a small privileged helper and an unprivileged main
process is still the better shape, and this is not it: SMAppService wants a
signed bundle and an Apple developer identity this project does not have.

## Try it without any VPN credentials

The `mock` provider dials straight out and reports a synthetic network, so the
whole pipeline can be exercised on any machine with Docker.

```sh
make image-mock                        # builds coosir/vg-mock for this machine
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

make images    # build the images for this machine, to try them out
make push      # build for x86 and ARM and publish them
```

Images are built here and published; the server only pulls. That is what lets
it run somewhere with no route to where these are assembled from. The prefix
and tag are `REGISTRY` and `IMAGE_TAG`:

```sh
make push REGISTRY=registry.example.com/vpn-gateway/vg- IMAGE_TAG=2026-08-30
```
