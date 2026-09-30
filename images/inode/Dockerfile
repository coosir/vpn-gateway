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
# The vendor's installer is not in the repository. Supply your own licensed
# copy in images/inode/ and build or publish it like the others:
#
#   make image-inode        # to try it here
#   make push-inode         # to publish it for the server to pull
#
# The published image carries H3C's client, so its repository is kept
# private. The client is x86_64 only, and so is the image.

FROM golang:1.26-alpine AS agent
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY pkg ./pkg
COPY internal ./internal
COPY cmd ./cmd
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/vg-agent ./cmd/vg-agent

FROM ubuntu:22.04

ARG INODE_INSTALLER
ARG DEBIAN_FRONTEND=noninteractive

# netbase is not optional: without /etc/protocols the service's
# getprotobyname() returns NULL and it crashes the moment it opens tun0.
# procps is for the start script; net-tools and iptables are what the
# client's libraries shell out to for routes and its own firewall rules.
#
# tini, because the service forks itself into the background: every dial
# leaves processes whose parent is gone, and vg-agent, as the container's
# first process, would be their parent and never reap them.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates netbase procps psmisc iproute2 net-tools iptables tini \
 && rm -rf /var/lib/apt/lists/*

COPY --from=agent /out/vg-agent /usr/local/bin/vg-agent

# The installer is copied and installed only when one was supplied, so the
# image can still be built (and the failure explained clearly at runtime)
# without it.
COPY ${INODE_INSTALLER:-images/inode/Dockerfile} /tmp/inode-installer
COPY images/inode/install.sh /tmp/install.sh
RUN sh /tmp/install.sh && rm -f /tmp/install.sh /tmp/inode-installer

COPY images/inode/start-inode.sh /opt/vpn-gateway/start-inode.sh
RUN chmod +x /opt/vpn-gateway/start-inode.sh

LABEL io.vpn-gateway.contract="1" \
      io.vpn-gateway.provider="inode" \
      io.vpn-gateway.capabilities="tcp,routes,dns"

# The service creates tun0, which needs NET_ADMIN and a tun device. Both stay
# inside this container's namespace.
EXPOSE 1080 1081
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/vg-agent"]
