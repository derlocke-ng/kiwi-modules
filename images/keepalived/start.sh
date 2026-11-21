#!/bin/sh
# The moving address (VRRP) from the environment:
#   VIP_ADDRESS   the address, with its prefix (192.168.2.70/24); without one: /32 on the interface
#   VIP_INTERFACE the interface; empty: the one with the default route
#   VIP_PEERS     the other machines' addresses on that LAN, space separated (unicast, no multicast)
#   VIP_PRIORITY  higher holds the address (the first of a pair by name: 150, the others 100)
#   VIP_ROUTER_ID 1-255, the same on both machines of a pair
#   VIP_PASSWORD  the pair's password (VRRP keeps its first 8 characters)
#   VIP_CHECK_DNS 1: the address goes when the Pi-hole here does not answer a name
#   VIP_CHECK_PING an address that must answer through this machine (the master on the VPN): the
#                 gateway works; empty: no such check
set -eu
iface=${VIP_INTERFACE:-}
[ -n "$iface" ] || iface=$(ip -4 route show default | sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -n 1)
[ -n "$iface" ] || { echo "vip: no interface (no default route): set VIP_INTERFACE" >&2; exit 1; }
addr=$VIP_ADDRESS
case $addr in */*) ;; *) addr="$addr/32" ;; esac
peers=""
for p in ${VIP_PEERS:-}; do peers="$peers        $p
"; done
checks=""
track=""
if [ "${VIP_CHECK_DNS:-0}" = 1 ]; then
    checks="$checks
vrrp_script dns {
    script \"/usr/bin/dig +time=1 +tries=2 +short @127.0.0.1 localhost A\"
    interval 3
    fall 2
    rise 2
}"
    track="$track        dns
"
fi
if [ -n "${VIP_CHECK_PING:-}" ]; then
    checks="$checks
vrrp_script route {
    script \"/bin/ping -c 1 -W 2 ${VIP_CHECK_PING}\"
    interval 5
    fall 3
    rise 2
}"
    track="$track        route
"
fi
mkdir -p /etc/keepalived
{
    printf 'global_defs {\n    router_id %s\n    enable_script_security\n    script_user root\n}\n' "$(hostname)"
    printf '%s\n' "$checks"
    cat <<CONF
vrrp_instance kiwi {
    state BACKUP
    interface $iface
    virtual_router_id ${VIP_ROUTER_ID:-70}
    priority ${VIP_PRIORITY:-100}
    advert_int 1
    authentication {
        auth_type PASS
        auth_pass $(printf '%s' "${VIP_PASSWORD:-kiwi}" | cut -c1-8)
    }
    unicast_peer {
$peers    }
    virtual_ipaddress {
        $addr dev $iface
    }
CONF
    [ -n "$track" ] && printf '    track_script {\n%s    }\n' "$track"
    printf '}\n'
} > /etc/keepalived/keepalived.conf
echo "vip: $addr on $iface, priority ${VIP_PRIORITY:-100}, peers: ${VIP_PEERS:-none}"
exec /usr/sbin/keepalived --dont-fork --log-console --vrrp -f /etc/keepalived/keepalived.conf
