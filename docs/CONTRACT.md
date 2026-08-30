# Image contract v1

A vpn-gateway VPN image is any OCI image that speaks this contract. The
server knows nothing about VPN protocols; it only knows this document. Adding
a new VPN means shipping a conforming image, not changing the server or the
client.

## Ports

| Port | Plane | Protocol |
|------|-------|----------|
| 1080/tcp | data | SOCKS5, bound to `0.0.0.0` |
| 1081/tcp | control | HTTP/JSON, bound to `0.0.0.0` |

The server publishes both on `127.0.0.1` only. Nothing is ever bound to a
routable host address: an open SOCKS5 that tunnels into a corporate network
would be a serious hole.

## Authentication

Both planes require the per-tunnel secret passed in as `VG_AGENT_SECRET`:

- **data plane** — SOCKS5 username/password (RFC 1929), username `vpngw`,
  password the secret.
- **control plane** — `Authorization: Bearer <secret>`.

This is not redundant with container network isolation. Some engines let
containers on separate bridge networks reach each other, and a compromised
vendor client on one tunnel must not be able to pivot into another. The
protocol layer enforces the boundary the network layer may not.

## Environment

| Variable | Meaning |
|----------|---------|
| `VG_PROVIDER` | which provider the agent should run |
| `VG_SERVER` | gateway hostname |
| `VG_USERNAME` | account name |
| `VG_PASSWORD` | account password |
| `VG_AGENT_SECRET` | the shared secret above |
| `VG_EXTRA_JSON` | JSON object of string values, provider-specific |

The server passes these through a `0600` env-file consumed at container
create time, so credentials never appear on a command line or in the host
process list.

### Shared `VG_EXTRA_JSON` keys

Every provider honours these, and they override anything the provider
auto-discovered:

| Key | Meaning |
|-----|---------|
| `routes` | comma-separated CIDRs the tunnel claims |
| `dns` | comma-separated resolvers reachable only through the tunnel |
| `search_domains` | comma-separated domain suffixes |
| `mtu` | tunnel MTU |

Overrides replace rather than merge, so a wrong guess can be corrected.

## Control plane endpoints

### `GET /v1/status`

```json
{
  "contract": 1,
  "provider": "easyconnect",
  "state": "up",
  "since": "2026-08-30T00:54:01Z",
  "connected_at": "2026-08-30T00:54:01Z",
  "uptime_seconds": 3612,
  "capabilities": ["tcp", "routes", "dns"],
  "traffic": {"tx_bytes": 84213, "rx_bytes": 913220, "active_conns": 3, "total_conns": 41}
}
```

`state` is one of `connecting`, `auth_required`, `up`, `down`, `error`.
`uptime_seconds` is the current connection's duration and is `0` unless the
state is `up`. `connected_at` survives a disconnect so a UI can show when the
tunnel last worked. `error` is present when the state is `error`.

### `GET /v1/network`

```json
{
  "routes": ["10.20.0.0/16"],
  "dns": ["10.20.0.53"],
  "search_domains": ["corp.example.com"],
  "udp": false,
  "mtu": 1400,
  "assigned_ip": "10.20.7.31"
}
```

The client turns `routes` into implicit `ip_cidr` routing rules and `dns` into
a tunnel-scoped resolver. This is what makes split routing usable without
hand-written rules. Fields are empty until the state is `up`.

`udp` reports whether the data plane implements SOCKS5 UDP ASSOCIATE. When
false, the client must query that tunnel's DNS over TCP.

### `GET /v1/events`

A `text/event-stream` of the same data. The first events always describe the
current state, so a late subscriber does not also have to poll. Keepalive
comments are sent every 20 seconds.

```
data: {"type":"status","at":"...","status":{...}}
data: {"type":"network","at":"...","network":{...}}
data: {"type":"challenge","at":"...","challenge":{...}}
data: {"type":"log","at":"...","log":"..."}
```

### `GET /v1/auth/challenge`

Returns the pending interactive prompt, or an object with an empty `id` when
nothing is pending. An absent challenge is the normal case, not an error.

```json
{
  "id": "ec-1788022474",
  "type": "sms",
  "prompt": "Enter the code sent to ***1234",
  "expires_at": "2026-08-30T01:05:00Z"
}
```

`type` is one of `password`, `sms`, `totp`, `captcha`, `url`, `vnc`. A
`captcha` carries `image_b64`; a `url` carries the sign-on address to open and
expects whatever it redirects to; a `vnc` carries `vnc_port` and means the
vendor client has no headless login path, so the client shows a viewer for the
first login and the session is kept afterwards.

Most supervised clients ask these questions on standard input and block until
answered. The agent recognises the prompt, raises the challenge, and writes
the answer back. Two details are easy to get wrong and both are handled:

- A prompt usually has **no trailing newline**, because the cursor is meant to
  stay on the line. A reader that waits for `\n` never sees it and the tunnel
  blocks forever with nothing to show.
- The readiness deadline must be **suspended while a challenge is pending**.
  Someone fetching a code from their phone easily outlasts any timeout worth
  setting for a stuck process, and killing the client mid-login makes the
  tunnel impossible to bring up at all.

### `POST /v1/auth`

```json
{"id": "ec-1788022474", "value": "482915"}
```

`204` on success, `409` when the challenge is no longer pending. The id must
match: a stale answer must not satisfy a fresh prompt.

### `POST /v1/reconnect`

Tears down and redials. `202`.

## Labels

| Label | Value |
|-------|-------|
| `io.vpn-gateway.contract` | `1` |
| `io.vpn-gateway.provider` | provider name, or a comma-separated list |
| `io.vpn-gateway.capabilities` | comma-separated: `tcp`, `udp`, `routes`, `dns`, `sms`, `totp`, `vnc` |

`tcp` is mandatory. Never advertise a capability the image does not honour:
the client uses `udp` to decide whether DNS can use datagrams at all.

## Reconnection

Reconnection is two-level, and an image only implements the inner one.

The agent redials its provider in-process with exponential backoff, which is
cheap and can preserve an authenticated session. The server recreates the
container only when the control plane stops answering entirely, which means
the agent itself is gone.

A provider that has failed permanently — rejected credentials, most often —
must say so instead of retrying. A login loop against a corporate gateway is
how accounts get locked.
