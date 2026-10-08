# The base of the iNode image: Ubuntu, what H3C's client needs from it, and
# the client itself, installed and pruned. No agent.
#
# It is built by hand, from your own licensed copy of H3C's installer, and
# only when the client or its system packages change:
#
#   make push-inode-base    # with the installer in images/inode-base/
#
# coosir/vg-inode is built on it like every other image, so a change to the
# agent never needs the installer. The client is x86_64 only, and so is this.

# The client is installed and pruned in a stage of its own. The image takes
# only /opt/inode and /etc/iNode from it, so neither the installer (26MB) nor
# what the vendor ships for its window reaches the image: a file removed in
# a later layer still costs what it cost in the layer that added it.
FROM ubuntu:22.04 AS inode

ARG INODE_INSTALLER
ARG DEBIAN_FRONTEND=noninteractive

# binutils for strip; procps for the pkill that makes sure the vendor's boot
# script left nothing running.
RUN apt-get update \
 && apt-get install -y --no-install-recommends binutils procps \
 && rm -rf /var/lib/apt/lists/*

# The build refuses to go on without an installer: a base without the client
# would make every image built on it useless.
COPY ${INODE_INSTALLER} /tmp/inode-installer
COPY images/inode-base/install.sh /tmp/install.sh
RUN sh /tmp/install.sh

FROM ubuntu:22.04

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
      ca-certificates netbase procps iproute2 net-tools iptables tini \
 && rm -rf /var/lib/apt/lists/*

COPY --from=inode /etc/iNode /etc/iNode
COPY --from=inode /opt/inode /opt/inode

LABEL io.vpn-gateway.inode-base="1"
