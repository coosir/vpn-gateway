#!/bin/sh
# Install H3C's iNode client from the installer supplied at build time.
#
# Building without one is allowed on purpose: the image then starts, and the
# agent says what is missing, rather than the build failing with a message
# about a COPY path.
set -e

if ! head -c 2 /tmp/inode-installer | grep -q "$(printf '\037\213')"; then
	echo "no iNode installer was supplied; build with make image-inode INODE_INSTALLER=<file>" >&2
	exit 0
fi

# The tarball holds one directory, iNodeClient/, with the vendor's own
# install script inside.
mkdir -p /opt/inode
tar -xzf /tmp/inode-installer -C /opt/inode --strip-components=1

# The vendor script decides what to do from /etc/issue, and does the part
# that matters here: unpacking the bundled libraries, recording the install
# directory in /etc/iNode/inodesys.conf, and linking the system's libudev and
# libncurses in. What it does for a desktop -- the menu entry, the boot
# script -- is harmless and unused. It has to run from the install directory.
echo "Ubuntu 22.04 LTS" > /etc/issue
cd /opt/inode
sh ./install_64.sh

# The boot script it installed would start the service; here only the agent
# does. It fails harmlessly for want of sudo, but nothing should be left.
pkill -9 -f AuthenMngService 2>/dev/null || true
pkill -9 -f iNodeMon 2>/dev/null || true
rm -f /opt/inode/log/*.log /opt/inode/clientfiles/7000/*.icnf

test -x /opt/inode/AuthenMngService
echo "iNode client installed in /opt/inode"
