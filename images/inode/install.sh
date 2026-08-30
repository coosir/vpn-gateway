#!/bin/sh
# Unpack the vendor installer if one was supplied at build time.
#
# Building without it is allowed on purpose: the image is then a shell that
# explains what is missing, rather than a build that fails with a message
# about a COPY path.
set -e

if ! head -c 2 /tmp/inode-installer | grep -q "$(printf '\037\213')"; then
	echo "no iNode installer was supplied; build with --build-arg INODE_INSTALLER=<file>" >&2
	mkdir -p /opt/vpn-gateway
	exit 0
fi

mkdir -p /opt/inode
tar -xzf /tmp/inode-installer -C /opt/inode --strip-components=1
echo "iNode client unpacked into /opt/inode"
