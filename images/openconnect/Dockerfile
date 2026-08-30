# Fortinet, GlobalProtect, Pulse, F5, Juniper, Array and AnyConnect, through
# OpenConnect.
#
# One image serves all seven; the tunnel's VG_PROVIDER picks which. They are
# all reimplementations, so nothing here needs a vendor's own client or
# installer and the image can be published as it is.
#
# Build from the repository root:
#   make image-openconnect          # for this machine
#   make push-openconnect           # for every platform, published
#
# The client creates a tun interface and installs routes, so the container
# needs NET_ADMIN and /dev/net/tun. Both stay inside its own network
# namespace, which is what lets several of these run at once:
#
#   cap_add: [NET_ADMIN]
#   devices: ["/dev/net/tun"]

FROM golang:1.26-alpine AS agent
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY pkg ./pkg
COPY internal ./internal
COPY cmd ./cmd
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/vg-agent ./cmd/vg-agent

FROM alpine:3.22

# openconnect brings its own vpnc-script, which is what configures the
# interface, the routes and the resolver once the gateway answers.
# iptables is not installed: nothing here filters, and the routes the script
# writes are confined to this container's namespace anyway.
RUN apk add --no-cache openconnect ca-certificates iproute2 \
 && test -x /etc/vpnc/vpnc-script

COPY --from=agent /out/vg-agent /usr/local/bin/vg-agent

LABEL io.vpn-gateway.contract="1" \
      io.vpn-gateway.provider="fortinet,globalprotect,pulse,f5,juniper,array,anyconnect" \
      io.vpn-gateway.capabilities="tcp,routes,dns,password,totp"

# Runs as root: creating a tun interface and writing routes needs it, and the
# only thing reachable in here is one VPN client.
EXPOSE 1080 1081
ENTRYPOINT ["/usr/local/bin/vg-agent"]
