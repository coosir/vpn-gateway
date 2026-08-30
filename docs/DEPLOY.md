# Deploying vpn-gateway

This walks the whole path: nothing installed, to a laptop routing some
traffic through a corporate VPN and the rest straight out.

Work through it in order. Steps 1 to 5 use a tunnel that needs no credentials,
so the plumbing is proven before a real gateway is involved. That matters:
when something does not work later, you will know it is the VPN and not the
setup.

## What goes where

| | Server (the NAS) | Client (laptop, desktop) |
|---|---|---|
| binaries | `vpn-gateway-server`, `vgctl` | `vpn-gateway` |
| needs | a container engine | nothing |
| runs | one container per tunnel, plus the TLS listener on 443 | one TUN interface and the routing engine |
| holds | every VPN credential | one password per tunnel, and nothing else |

The client never talks to a container. It reaches the server on one TLS port
and learns everything else from the control API.

## 0. Before anything

Run the preflight on the server. It checks the four things that are painful
to discover later.

```sh
sh scripts/preflight.sh
```

- **A container engine.** Docker or Podman.
- **CPU architecture.** `x86_64` runs everything. On `aarch64` the native
  providers are fine, but H3C's iNode client is x86-only and would need
  emulation.
- **Reachability.** If the check says your ISP uses CGNAT, port forwarding
  cannot work and you will need a reverse tunnel instead. Otherwise, forward
  TCP 443 to the server.
- **Upload bandwidth.** Every intranet request travels client → server → VPN
  gateway, so the server's upload speed is what a remote client feels.

You also want a name that follows the server's address: any dynamic DNS
service works. Everything below calls it `vpn.example.dyndns.org`.

> **Put this on a machine at home, not on a VPS.** A corporate VPN sees the
> login coming from wherever the server is. A datacenter address, and one that
> jumps countries from your usual one, is what triggers impossible-travel
> alerts and locked accounts. A residential connection raises none of that, and
> it is also closer to the gateways you are dialing.

## 1. Build and publish

Everything is built on your own machine and published to a registry. The
server only pulls: it never needs the sources, a Go toolchain, or a route to
wherever these are assembled from.

Images first. `make push` builds for both x86 and ARM and pushes one tag that
works on either, so it does not matter which the server is:

```sh
docker login                       # once, for wherever you publish

make push                          # coosir/vg-mock, -sangfor, -openconnect
make push IMAGE_TAG=2026-08-30     # or pin a tag you can roll back to
```

Publishing somewhere other than Docker Hub is a prefix:

```sh
make push REGISTRY=registry.example.com/vpn-gateway/vg-
```

Then the binaries, cross-compiled for whatever the server runs:

```sh
make dist                          # linux/amd64 by default
make dist DIST_ARCH=arm64          # for an ARM server

scp dist/linux-amd64/vpn-gateway-server \
    dist/linux-amd64/vgctl  server:/tmp/
```

On the server, that is the whole installation:

```sh
sudo install -m 0755 /tmp/vpn-gateway-server /tmp/vgctl /usr/local/bin/
```

The server fetches each image the first time it runs the tunnel that uses it,
so nothing has to be pulled by hand. `pull_policy: always` re-checks a tag
that moves; `never` refuses to reach out at all, for a machine with no route
to the registry, and then the images have to be loaded another way:

```sh
# on your machine
docker save coosir/vg-sangfor:latest | gzip > sangfor.tgz
# on the server
gunzip -c sangfor.tgz | docker load
```

## 2. Configure

```sh
sudo mkdir -p /etc/vpn-gateway
scp config.example.yaml server:/tmp/            # from your machine
sudo cp /tmp/config.example.yaml /etc/vpn-gateway/config.yaml
sudo chmod 0600 /etc/vpn-gateway/config.yaml
```

Start with only the credential-free tunnel enabled:

```yaml
api_listen: 127.0.0.1:8642
state_dir: /var/lib/vpn-gateway
runtime: auto
port_base: 21000

trojan:
  listen: ":443"
  server_name: vpn.example.dyndns.org
  tls_mode: selfsigned

pull_policy: missing

tunnels:
  - name: mock
    provider: mock
    image: coosir/vg-mock:latest
    server: mock.example
    username: tester
    extra:
      routes: "10.99.0.0/16"
      dns: "10.99.0.53"
```

`server_name` is baked into the certificate your clients will pin, so set it
now. Changing it later means re-pinning every device.

Check it before starting anything:

```sh
vpn-gateway-server -config /etc/vpn-gateway/config.yaml -check
```

`-check` also resolves every tunnel's credentials, so a `password_env` that
is not set is reported here rather than as a failed login against a real
account later.

## 3. Run it

```sh
scp packaging/systemd/vpn-gateway-server.service server:/tmp/   # from your machine
sudo cp /tmp/vpn-gateway-server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now vpn-gateway-server
journalctl -u vpn-gateway-server -f
```

No systemd? Anything that keeps a process alive will do:

```sh
sudo vpn-gateway-server -config /etc/vpn-gateway/config.yaml
```

The unit is hardened, and the hardening is the most likely reason it will not
start on an unusual distribution. If it fails immediately, comment out the
block at the bottom of the unit and add the lines back one at a time. None of
it is needed for the server to work.

## 4. Prove the plumbing

```sh
sudo vgctl -config /etc/vpn-gateway/config.yaml -host 127.0.0.1 verify
```

Expected:

```
server 127.0.0.1:443 (sni vpn.example.dyndns.org)
  certificate is self-signed; clients pin 34:D8:53:…

  mock    ok    tunnel=up   uptime=12s   egress=203.0.113.9

all 1 tunnels carried traffic
```

`-host 127.0.0.1` connects locally while still presenting the real name, which
is what you want here: many home routers cannot reach their own public address
from inside.

If this fails, stop and fix it. Everything after this point assumes it works.

- **`no container runtime found`** — the engine is not installed, or the
  service cannot reach its socket.
- **`fetch coosir/vg-…: …`** — the server cannot reach the registry. Either
  publish somewhere it can, or set `pull_policy: never` and load the images
  with `docker save` and `docker load` as above.
- **`tunnel=unreachable`** — the container is not answering. Look at it with
  `vgctl -config … tunnels` for the port, then `docker logs vpngw-mock`.
- **the listener will not bind 443** — something else has it, or the unit lost
  `CAP_NET_BIND_SERVICE`.

## 5. Connect a client

On the server:

```sh
sudo vgctl -config /etc/vpn-gateway/config.yaml client-config > client.json
sudo vgctl -config /etc/vpn-gateway/config.yaml fingerprint
```

`client.json` contains one password per tunnel and the certificate to trust.
Treat it like a key: copy it over `scp`, not a chat window. Compare the
fingerprint against what the client reports the first time, so you would
notice something sitting in the middle.

On the client, build and install:

```sh
make build
sudo install -m 0755 bin/vpn-gateway /usr/local/bin/
sudo mkdir -p /etc/vpn-gateway
sudo cp client.json /etc/vpn-gateway/
sudo cp client.example.yaml /etc/vpn-gateway/client.yaml
```

Start with the proxy rather than the interface — it needs no privileges, so
the rules can be proven before anything touches the routing table:

```yaml
bundle: /etc/vpn-gateway/client.json
tun: {enabled: false}
proxy: {enabled: true, listen: 127.0.0.1:1080}
ui: {enabled: true, listen: 127.0.0.1:8645, state_dir: /var/lib/vpn-gateway}
dns: {default: local}
on_failure: direct
auto_routes: true
auto_domains: true
rules: []
```

`dns.default: local` uses the system resolver, which always works. A public
resolver over HTTPS keeps names outside every tunnel off the local network,
which is worth having — but several are unreachable from some countries, and
one that times out looks like the whole client is broken rather than like a
DNS problem. Change it once the rest is working.

```sh
vpn-gateway -config /etc/vpn-gateway/client.yaml check
vpn-gateway -config /etc/vpn-gateway/client.yaml run
```

It prints a link with a token. Open it: the tunnel should be listed and up.
The interface is in Chinese by default; the top bar switches to English.

For a tray icon and a native window instead of a browser tab, build the
desktop shell on the client machine and point it at that link:

```sh
make desktop      # the binary
make app          # and a macOS .app bundle around it
```

Then open it and follow the setup screen: it asks for the bundle from step 5
and connects when told to. It takes no arguments and needs no configuration
file prepared for it — it writes its own, in your user directory.

On macOS and Linux it needs the platform's webview libraries to build
(`libgtk-3-dev` and `libwebkit2gtk-4.1-dev` on Debian); on Windows the
bindings are pure Go and it cross-compiles.

Then switch `tun.enabled` to true and run it with `sudo` (or install the
client unit from `packaging/systemd/`, which grants `CAP_NET_ADMIN` instead of
running as root). At that point all traffic goes through the routing engine.

## 6. Add a real VPN

Now that the path is proven, add the gateway. Passwords never go in the
configuration file:

```sh
sudo tee /etc/vpn-gateway/credentials.env >/dev/null <<'EOF'
CORP_PASSWORD=…
EOF
sudo chmod 0600 /etc/vpn-gateway/credentials.env
```

The unit already reads that file. Add the tunnel:

```yaml
  # Sangfor EasyConnect or aTrust. Change provider to atrust for the other.
  - name: corp
    provider: easyconnect
    image: coosir/vg-sangfor:latest
    server: vpn.corp.example
    username: alice
    password_env: CORP_PASSWORD
    extra:
      # State the intranet ranges: the client turns these into routing rules
      # by itself.
      routes: "10.20.0.0/16,172.16.0.0/12"
      dns: "10.20.0.53"
      search_domains: "corp.example"
```

For Fortinet and the rest of the OpenConnect family, the client creates a tun
interface inside its container, so that container needs two extra things:

```yaml
  - name: corp-forti
    provider: fortinet        # or globalprotect, pulse, f5, juniper, …
    image: coosir/vg-openconnect:latest
    server: vpn.corp.example
    username: alice
    password_env: CORP_PASSWORD
    cap_add: [NET_ADMIN]
    devices: ["/dev/net/tun"]
    extra:
      routes: "10.30.0.0/16"
      dns: "10.30.0.53"
      authgroup: "corp"       # the realm, if the login form has one
```

Tunnels do not dial by themselves. Connect this one from the client, or set
`autostart: true` on it. Either way it stops after `max_attempts` failures
rather than knocking at a gateway that is refusing it, because enough failed
authentications in a row is what locks a corporate account.

Then:

```sh
sudo vpn-gateway-server -config /etc/vpn-gateway/config.yaml -check
sudo systemctl restart vpn-gateway-server
sudo vgctl -config /etc/vpn-gateway/config.yaml -host 127.0.0.1 verify
```

**If the gateway wants a one-time code in the password field** rather than
asking for it separately — a common Fortinet arrangement, where you normally
type your password with the six digits on the end — set both:

```yaml
    extra:
      totp_secret: "BASE32SEED"
      totp_append: "true"
```

**If the gateway asks for a code** as a separate prompt, the tunnel sits in
`auth_required` until someone answers. Either the client interface will show a prompt, or:

```sh
vpn-gateway -config /etc/vpn-gateway/client.yaml auth
```

Answering happens on the server and the session persists, so your phone will
never see the prompt.

Re-issue `client.json` after adding a tunnel — it carries one password per
tunnel, and a new tunnel means a new password.

## 7. Route something through it

In the client interface, or in `client.yaml`:

```yaml
rules:
  - domain_suffix: [corp.example]
    tunnel: corp
  - ip_cidr: [10.20.0.0/16]
    tunnel: corp
```

With `auto_routes` on, the CIDRs a tunnel reports already route themselves, so
in practice you only add domain rules.

Check where something actually goes:

```sh
curl --socks5-hostname 127.0.0.1:1080 https://intranet.corp.example/
```

## When something does not work

**A tunnel never leaves `connecting`.** Read the container's own output:

```sh
vgctl -config /etc/vpn-gateway/config.yaml tunnels     # find it
docker logs --tail 50 vpngw-corp
```

**A tunnel keeps reconnecting.** It should not: after `max_attempts` failures
it stops and waits, and wrong credentials stop it at once. If you are watching
it retry, that is the few attempts it is allowed. Reconnect from the client
once whatever was wrong has been dealt with.

**A tunnel says stopped and will not come up on its own.** That is the
default. Connect it from the client, or set `autostart: true`.

**An intranet name does not resolve, but its address works.** The tunnel
reported no resolver. Set `extra.dns` to the VPN's own DNS server.

**Nothing resolves at all, through any tunnel or direct.** The client's own
resolver is unreachable. Set `dns.default: local` and try again.

**Everything works locally but not from outside.** Port 443 is not reaching
the server, or the dynamic DNS name is stale. `vgctl … -host <public name>
verify` from another network tells you which.

**A Fortinet gateway refuses the certificate.** Its certificate is not
publicly trusted. openconnect prints the fingerprint to use; put it in
`extra.servercert`.

**A Fortinet gateway rejects the client.** Some check the user agent. Try
`extra.useragent`, and `extra.authgroup` if the login page has a realm
dropdown.

**One-time codes are always rejected.** Either the wrong shape is configured —
`totp_append` for a gateway that prompts separately, or the reverse — or the
server's clock has drifted. A code is only valid for the period around the
time it was computed for, so more than about fifteen seconds of drift breaks
every one of them.

## What this does not do yet

- The client needs elevation itself to create a TUN interface. The systemd
  unit grants only `CAP_NET_ADMIN`; on macOS it runs as root.
- The iNode image is written but untested: H3C's installer is not
  redistributable, so it is supplied at build time and its start script will
  probably need adjusting for the version you have.
