#!/bin/bash
# Two keepalived containers on a podman network of their own (rootless, nothing on the host):
# the address is on the first, moves to the second when the first stops, and comes back.
#   podman build -t localhost/kiwi-keepalived:test images/keepalived && bash images/keepalived/test-pair.sh
set -u
img=${IMG:-localhost/kiwi-keepalived:test}; net=kiwi-vip-test
podman network create --subnet 10.89.70.0/24 "$net" >/dev/null 2>&1 || true
trap 'podman rm -f vip-a vip-b >/dev/null 2>&1; podman network rm "$net" >/dev/null 2>&1' EXIT
run() { podman run -d --name "$1" --network "$net" --ip "$2" --cap-add NET_ADMIN --cap-add NET_RAW --cap-add NET_BROADCAST \
        -e VIP_ADDRESS=10.89.70.70/24 -e VIP_INTERFACE=eth0 -e VIP_PEERS="$3" -e VIP_PRIORITY="$4" -e VIP_ROUTER_ID=70 \
        -e VIP_PASSWORD=pairpass "$img" >/dev/null; }
has() { podman exec "$1" ip -4 addr show eth0 2>/dev/null | grep -q 10.89.70.70; }
who() { for c in vip-a vip-b; do has "$c" && printf '%s ' "$c"; done; echo; }
run vip-a 10.89.70.11 10.89.70.12 150; run vip-b 10.89.70.12 10.89.70.11 100
sleep 6; echo "start: $(who)"
podman stop -t 2 vip-a >/dev/null; t=$(date +%s)
for _ in $(seq 1 20); do sleep 0.5; has vip-b && break; done
echo "a stopped: $(who) after $(( $(date +%s) - t )) s"
podman start vip-a >/dev/null; sleep 6; echo "a back: $(who)"
podman logs vip-b 2>&1 | grep -i "entering\|vip:" | tail -4
