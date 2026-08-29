# vpn-gateway

Run several corporate VPNs at once and split traffic between them by domain or
IP, without installing any of their desktop clients.

Each VPN connection runs as a container on a server you control — a home NAS
works well. The container holds the VPN's mess inside its own network
namespace and exposes only a SOCKS5 proxy and a status API. The client is a
single binary with one TUN interface and a routing engine, so nothing on your
laptop or phone fights over the default route.

See [docs/DESIGN.md](docs/DESIGN.md) for why it is built this way, and
[docs/CONTRACT.md](docs/CONTRACT.md) for the interface a VPN image implements.

## Status

Phase 0 is complete and verified end to end. What works today:

- image contract v1, with authentication on both the data and control planes
- `vg-agent`: the in-container supervisor, SOCKS5 data plane with traffic
  accounting, HTTP control plane with an event stream
- providers: `mock` (no VPN, for testing), `easyconnect` and `atrust` (via
  zju-connect)
- `vpn-gateway-server`: container orchestration, per-tunnel supervision and
  restart backoff, the client-facing control API

Not built yet: the trojan listener, the desktop client, the GUI, and the
Fortinet and iNode images.

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
