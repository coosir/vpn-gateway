#!/bin/sh
# Start the H3C iNode client and expose it through the agent contract.
#
# Called by vg-agent with the server and username as arguments; the password
# and the forwarder address arrive in the environment so they stay out of the
# container's process list.
set -e

server="${1:-$VG_SERVER}"
username="${2:-$VG_USERNAME}"

if [ ! -d /opt/inode ]; then
	echo "the iNode client is not installed in this image" >&2
	echo "rebuild with: docker build --build-arg INODE_INSTALLER=<installer> ..." >&2
	exit 1
fi

# A screen for the client to draw its login dialog on. It has no headless
# login, so this is not optional.
if [ -n "$VG_VNC_PORT" ]; then
	export DISPLAY=:1
	Xvfb :1 -screen 0 1024x768x16 >/dev/null 2>&1 &
	fluxbox >/dev/null 2>&1 &
	# Bound to every address inside the container; the server publishes it on
	# loopback only, and the control plane's secret guards the port mapping.
	x11vnc -display :1 -forever -shared -nopw -rfbport "$VG_VNC_PORT" >/dev/null 2>&1 &
	echo "VNC screen ready on port $VG_VNC_PORT"
fi

echo "starting iNode client for $username@$server"
/opt/inode/iNodeClient --server "$server" --username "$username" &
client_pid=$!

# Nothing else to start: the agent shares this network namespace, so the
# routes the client just installed already carry its traffic.
wait "$client_pid"
