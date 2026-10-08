#!/bin/sh
# Install H3C's iNode client from the installer supplied at build time, and
# keep only what its service needs.
#
# This runs in a build stage of its own; the image takes /opt/inode and
# /etc/iNode from it and nothing else, so neither the installer nor anything
# removed here reaches the image.
set -e

mkdir -p /opt/inode /etc/iNode

if ! head -c 2 /tmp/inode-installer | grep -q "$(printf '\037\213')"; then
	echo "INODE_INSTALLER is not H3C's gzipped installer" >&2
	exit 1
fi

# The tarball holds one directory, iNodeClient/, with the vendor's own
# install script inside.
tar -xzf /tmp/inode-installer -C /opt/inode --strip-components=1

# The vendor script decides what to do from /etc/issue, and does the part
# that matters here: unpacking the bundled libraries, and recording the
# install directory in /etc/iNode/inodesys.conf, which the service reads. The
# rest -- a menu entry, a boot script -- is for a desktop and is left behind
# with this stage. It has to run from the install directory.
echo "Ubuntu 22.04 LTS" > /etc/issue
cd /opt/inode
sh ./install_64.sh

# Its boot script tries to start the service, and fails for want of sudo.
# Nothing should be running, but make sure.
pkill -9 -f AuthenMngService 2>/dev/null || true
pkill -9 -f iNodeMon 2>/dev/null || true

# What the service does not need. It loads its protocol plugins and security
# modules from libs/ -- some of them by name at run time, so libs/ is pruned
# by what is known to be unused rather than kept by what ldd finds.
#
#   the window, and the GUI toolkit and image libraries only it links
#   DamAgent, the device-control agent, and the USB libraries only it uses
#   iNodeMon, which restarts the service; here the agent does that
#   the installers for other distributions, both packed and unpacked
#   openssl, which the service only runs to read a client certificate
rm -rf .iNode iNodeClient.sh iNodeClient.desktop iNodeClient.png \
	DamAgent iNodeMon openssl install_64.sh uninstall.sh ubuntu18.sh \
	libs/libwx_* libs/libjpeg* libs/libpng12* libs/libpangox* libs/libtiff* \
	libs/libgmp* libs/libusb* libs/libudev* libs/libncurses* \
	libs/std libs/rocky libs/linux_release_packages \
	libs/linux64_std.tar.gz libs/linux_release_packages.tar.gz \
	libs/libstdc++.so.6.0.13 \
	log/*.log clientfiles/7000/*.icnf

# Every binary H3C ships still carries its debug information -- most of the
# thirteen megabytes of libACE alone. Only the debug sections go: the symbol
# tables that dynamic linking and dlsym rely on are kept.
find . -type f \( -name '*.so*' -o -name AuthenMngService \) \
	-exec strip --strip-debug {} +

test -x /opt/inode/AuthenMngService
echo "iNode client installed in /opt/inode ($(du -sh /opt/inode | cut -f1))"
