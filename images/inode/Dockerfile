# H3C iNode, by running the vendor's own Linux client inside the container.
#
# There is no public reimplementation of the iNode SSL VPN protocol, so this
# is the fallback tier: the vendor client runs in the container's own network
# namespace, where the routes and DNS it insists on rewriting are invisible to
# everything else.
#
# The vendor's installer is NOT redistributed. Supply your own licensed copy:
#
#   make image-inode INODE_INSTALLER=iNodeClient.tar.gz
#
# with the installer in the build context. It is not published alongside the
# others, so this one goes straight onto the machines that need it.
#
# The client has no headless login, so the image serves a VNC screen for the
# first sign-in and the agent raises a vnc challenge; the session persists
# afterwards.

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

# x11vnc and a minimal window manager exist only so the vendor client has a
# screen to draw its login dialog on.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates iproute2 iptables \
      xvfb x11vnc fluxbox \
      libgtk2.0-0 libxss1 libnss3 \
 && rm -rf /var/lib/apt/lists/*

COPY --from=agent /out/vg-agent /usr/local/bin/vg-agent

# The installer is copied and unpacked only when one was supplied, so the
# image can still be built (and the failure explained clearly at runtime)
# without it.
COPY ${INODE_INSTALLER:-images/inode/Dockerfile} /tmp/inode-installer
COPY images/inode/install.sh /tmp/install.sh
RUN sh /tmp/install.sh && rm -f /tmp/install.sh /tmp/inode-installer

COPY images/inode/start-inode.sh /opt/vpn-gateway/start-inode.sh
RUN chmod +x /opt/vpn-gateway/start-inode.sh

LABEL io.vpn-gateway.contract="1" \
      io.vpn-gateway.provider="inode" \
      io.vpn-gateway.capabilities="tcp,routes,dns,vnc"

# The vendor client creates its own interface, which needs NET_ADMIN and a tun
# device. Both stay inside this container's namespace.
EXPOSE 1080 1081 5901
ENTRYPOINT ["/usr/local/bin/vg-agent"]
