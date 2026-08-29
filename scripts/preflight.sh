#!/bin/sh
# Check that a machine can host vpn-gateway before any tunnel is configured.
#
# These are the four preconditions that would otherwise be discovered late:
# a machine behind CGNAT cannot be reached, an ARM box cannot run x86-only
# vendor clients, a slow uplink caps every intranet request, and a missing
# container engine stops everything.
#
# Run it on the server:  sh scripts/preflight.sh

set -u
pass=0
fail=0
warn=0

ok()   { printf '  \033[32mOK\033[0m    %s\n' "$1"; pass=$((pass+1)); }
bad()  { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; fail=$((fail+1)); }
note() { printf '  \033[33mWARN\033[0m  %s\n' "$1"; warn=$((warn+1)); }
info() { printf '        %s\n' "$1"; }

echo
echo "1. Container engine"
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
	ok "docker is installed and the daemon is reachable"
elif command -v podman >/dev/null 2>&1 && podman info >/dev/null 2>&1; then
	ok "podman is installed and reachable"
else
	bad "no working container engine; install docker or podman"
fi

echo
echo "2. CPU architecture"
arch=$(uname -m)
case "$arch" in
	x86_64|amd64)
		ok "$arch runs vendor Linux clients natively"
		;;
	aarch64|arm64)
		note "$arch: aTrust and iNode ship x86_64-only Linux clients"
		info "native providers (easyconnect, atrust via zju-connect, trojan) are fine"
		info "for vendor images, register qemu-user-static and expect slow throughput"
		;;
	*)
		note "$arch is untested"
		;;
esac

echo
echo "3. Reachability from the internet"
pub=$(curl -s --max-time 8 https://api.ipify.org 2>/dev/null)
if [ -z "$pub" ]; then
	note "could not determine the public IP; check connectivity"
else
	info "public IP: $pub"
	local_ips=$(ip -4 addr show 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1)
	if echo "$local_ips" | grep -qx "$pub"; then
		ok "the public IP is configured locally; port forwarding is not needed"
	else
		case "$pub" in
			100.6[4-9].*|100.[7-9][0-9].*|100.1[0-1][0-9].*|100.12[0-7].*)
				bad "public IP is in 100.64.0.0/10: the ISP is using CGNAT"
				info "port forwarding cannot work; use a reverse tunnel or ask for a public IP"
				;;
			*)
				note "behind NAT: forward TCP 443 to this host, then re-check"
				;;
		esac
	fi
fi

echo
echo "4. Uplink bandwidth"
info "every intranet request travels client -> server -> VPN gateway,"
info "so the server's upload speed caps what a remote client sees."
if command -v speedtest-cli >/dev/null 2>&1; then
	up=$(speedtest-cli --simple 2>/dev/null | awk '/Upload/{print $2}')
	if [ -n "$up" ]; then
		info "measured upload: ${up} Mbit/s"
		awk -v u="$up" 'BEGIN{exit !(u < 10)}' && note "under 10 Mbit/s will feel slow for file transfers" || ok "upload bandwidth is adequate"
	else
		note "speedtest-cli did not return a result"
	fi
else
	note "speedtest-cli is not installed; measure the upload speed manually"
fi

echo
echo "5. Vendor installers (only for tier C images)"
info "aTrust and iNode images are built from your own licensed installer."
info "Nothing to do unless you plan to use them."

echo
printf '  %d passed, %d warnings, %d failed\n\n' "$pass" "$warn" "$fail"
[ "$fail" -eq 0 ]
