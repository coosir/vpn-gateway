# H3C iNode, by running the vendor's own Linux client inside the container.
#
# There is no public reimplementation of the iNode SSL VPN protocol, so the
# vendor's client does the work, in the container's own network namespace,
# where the routes and DNS it insists on rewriting are invisible to everything
# else.
#
# Only its service runs. The login and the tunnel live in AuthenMngService,
# which dials a saved connection by itself on start; the agent writes that
# connection, and the window -- and the desktop it would need -- never runs.
#
# The client comes from coosir/vg-inode-base (images/inode-base), which is
# built by hand from H3C's installer. This image only adds the agent, so it is
# built and published with the others. The base is x86_64 only, and so is
# this.

ARG BASE=coosir/vg-inode-base:latest

FROM golang:1.26-alpine AS agent
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY pkg ./pkg
COPY internal ./internal
COPY cmd ./cmd
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/vg-agent ./cmd/vg-agent

FROM ${BASE}

COPY --from=agent /out/vg-agent /usr/local/bin/vg-agent
COPY images/inode/start-inode.sh /opt/vpn-gateway/start-inode.sh
RUN chmod +x /opt/vpn-gateway/start-inode.sh

LABEL io.vpn-gateway.contract="1" \
      io.vpn-gateway.provider="inode" \
      io.vpn-gateway.capabilities="tcp,routes,dns"

# The service creates tun0, which needs NET_ADMIN and a tun device. Both stay
# inside this container's namespace.
EXPOSE 1080 1081
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/vg-agent"]
