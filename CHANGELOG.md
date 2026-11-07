# Changelog

## 0.3.0 — the stack network and the tunnels get an MTU each

- **`bridge_mtu` and `wg_mtu`** replace the one stack setting `mtu`
  (kiwi-server problem 40). `bridge_mtu` (1500) is the stack's bridge,
  `wg_mtu` (1380) gluetun's `WIREGUARD_MTU`, wg-easy's `WG_MTU` and the
  server's own `wg0`. One 1412 for all three split every full-size tunnel
  packet in two on the bridge, which carries the encrypted packet, 60 bytes
  bigger over IPv4 (80 over IPv6): TLS stalls and stuttering streams through
  the VPN on the v1 fleet. 1380 fits a WireGuard packet into a 1460-byte path
  (DS-Lite, PPPoE). StackSpec refuses `wg_mtu` above `bridge_mtu - 80` or
  below 1280. A machine that still sets `mtu` gets it as `wg_mtu`, the bridge
  at 1500, and a warning; `mtu` and `wg_mtu` together are an error. The
  template context has `bridge_mtu` and `wg_mtu` instead of `mtu`.
- **vpn-server**: `start.sh` sets `wg0` to `wg_mtu` before the MSS clamp;
  wg-quick sized it from the bridge (1332 under a 1412 bridge) while the
  clients were told another MTU.
- **vpn-client**: `mss_clamp` defaults to true on a node with the gateway
  module, below the profile's and the machine's own setting: LAN clients
  routed through it advertise MSS 1460, more than the tunnel carries.
- tests/golden/sh3: the MTU lines.

## 0.2.3 — the gateway's masquerade leaves the mesh alone

- **gateway**: the `-o bridge MASQUERADE` for LAN clients excludes the stack
  network and the mesh; with bridged traffic tracked by the host (kiwi-stack
  0.2.2) it had caught the containers' and the mesh clients' traffic too, and
  nginx logged every mesh client as the host (kiwi-server 2.7.1, problem 57).

## 0.2.2 — Portainer reachable from the mesh

- **portainer**: `needs_vpn_dnat: true` — a node whose only web service is
  Portainer behind the reverse proxy had no mesh DNAT at all (kiwi-server
  2.7.1, problem 58, found with the first device).

## 0.2.1 — a group's clients get their answers

- **vpn-server**: inside the WireGuard server the whole mesh is routed into
  `wg0`; before, only the server's own /24 was, and wg-easy adds no route for
  the peers it creates — a device in the `devices` group received nothing
  back (kiwi-server 2.7.1, problem 56, found with the first device).

## 0.2.0 — what the first hardware round found

The modules and the renderer as kiwi-server 2.7.0 has them. Every fix below
was found on 30 October 2026 on the first master and the first gateway+cloud
node that ran a rendered stack, and changes what every preset renders
(tests/golden/sh3 updated with it):

- **NAT out of the VPN client, at last**: an inline `{% if %}` at the end of
  a comment line in `post-rules.txt.j2` had swallowed the newline before the
  masquerade rule, which was part of the comment in every rendered stack;
  gluetun's own traffic worked, nothing forwarded through it came back.
- **Containers without a fixed address draw from an `IPRange`** (the third
  quarter of the stack network, `ip_range` in the compose file) instead of
  taking the fixed ones; a fixed address inside the range is refused.
- **The master's WireGuard server comes up on an nf_tables host**: its
  `start.sh` uses `iptables-nft` where the image has it, `WG_POST_DOWN` is a
  no-op.
- **The gateway module's LAN-to-containers DROP** spares the replies to what
  the containers started and the LAN's connections to published ports
  (`--ctstate NEW ! --ctstatus DNAT`).
- **Pi-hole serves the fleet's records only**: no `AddHost=` into its
  container, `no-hosts` for its dnsmasq (podman copies the host's hosts
  file, where the node's own names are 127.0.0.1).

## 0.1.0 — the renderer carved out of kiwi-server

The modules, the profiles and the `kiwimodules` package as kiwi-server 2.6.0
has them, with `kiwi-modules render machine.yaml -o DIR` for one machine
without a fleet. A rendered sh3 matches kiwi-server's golden bundle byte for
byte (tests/test_render.py). Nothing here has run on hardware yet.
