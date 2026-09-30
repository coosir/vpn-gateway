#!/bin/sh
# Run H3C's iNode service for the agent, and relay its log.
#
# The agent has already written the saved connection the service dials on
# start (clientfiles/7000/vpn-gateway.icnf), so there is no window and no
# login to drive: this only starts the service, copies what it logs to
# standard output, where the agent reads it, and stays alive exactly as long
# as the service does.
#
# Called by vg-agent with the install directory as the only argument.
set -u

dir="${1:-/opt/inode}"
svc=AuthenMngService
# The kernel keeps only fifteen characters of a process name, and this one is
# sixteen, so it is found by its command line rather than by -x.
match="^\./$svc\$"

if [ ! -x "$dir/$svc" ]; then
	echo "the iNode client is not installed in this image" >&2
	echo "rebuild it with: make image-inode INODE_INSTALLER=<installer>" >&2
	exit 1
fi

# A service left over from an attempt that was ended outright is still logged
# in, and still holds tun0. It has to go before another one can dial.
pkill -9 -f "$match" 2>/dev/null
pkill -x tail 2>/dev/null

cd "$dir" || exit 1
rm -f log/*.log

# It forks into the background and the parent exits, so its pid is found
# rather than taken from $!.
#
# Its output goes nowhere, and has to: the agent reads this script's output
# until the last writer closes it, and a service holding it open would leave
# the agent waiting on this script long after it had exited. What it has to
# say is in its log, relayed below.
"./$svc" </dev/null >/dev/null 2>&1
pid=
for _ in 1 2 3 4 5 6 7 8 9 10; do
	pid=$(pgrep -o -f "$match") && break
	sleep 1
done
if [ -z "$pid" ]; then
	echo "$svc did not start" >&2
	exit 1
fi
echo "$svc running as pid $pid"

tailer=
stop() {
	# -k is the vendor's own way to stop it: it ends the session at the
	# gateway and takes tun0 down. The agent allows five seconds before it
	# kills this script, and the service must not outlive it.
	"./$svc" -k >/dev/null 2>&1
	for _ in 1 2 3 4 5 6; do
		kill -0 "$pid" 2>/dev/null || break
		sleep 0.5
	done
	kill -9 "$pid" 2>/dev/null
	[ -n "$tailer" ] && kill "$tailer" 2>/dev/null
	exit 0
}
trap stop TERM INT

# The service names its logs by date, so the tail is restarted when the date
# moves on. Starting from the first line loses nothing: each day's files are
# new.
while kill -0 "$pid" 2>/dev/null; do
	day=$(date +%Y%m%d)
	tail -q -n +1 -F "log/Sslvpn$day.log" "log/auth$day.log" 2>/dev/null &
	tailer=$!
	# Short, because a trap waits for the sleep in front of it.
	while kill -0 "$pid" 2>/dev/null && [ "$(date +%Y%m%d)" = "$day" ]; do
		sleep 1
	done
	kill "$tailer" 2>/dev/null
	tailer=
done

echo "$svc exited" >&2
exit 1
