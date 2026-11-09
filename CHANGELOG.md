# Changelog

## 0.4.2 — the package says the release

- `lib/kiwimodules/__init__.py` still said 0.3.0 in the 0.4.0 and 0.4.1
  releases, whose `kiwi.manifest` said otherwise, so the package reported the
  old number. Both say 0.4.2 now; there is no other change from 0.4.1.
- A test compares the manifest, the package and the changelog's top entry.
- The release workflow's check that a new tag's version agrees everywhere
  now reads `lib/*/__init__.py` and `VERSION` too; it only knew
  `src/*/__init__.py` and `__version__`, so it passed both releases above.

## 0.4.1 — account-only mounts and a space's relays

- **`hub`**: `account_mounts` (the mounts that ask for an account, a
  username and password for the key, not a key alone; anyone else is told
  why, registers or signs in, and comes back; no age is asked),
  `require_account` (every mount), and `space_relays` (`<space id>=<relays>`
  per line: a space's own relays, the network its mount reads and writes).
  They become `HUB_ACCOUNT_MOUNTS`, `HUB_REQUIRE_ACCOUNT` and
  `HUB_SPACE_RELAYS` for kiwi-framework 0.19's container.

## 0.4.0 — a hub and its relay

- **`nostr-relay`**: strfry behind the reverse proxy at `relay.<hostname>`,
  the relay a hub built on kiwi-framework keeps its events on. A mesh name
  (the fleet's DNS resolves it, the fleet CA signs it), so the relay is
  reachable through the VPN alone; a public relay is a public name in
  `relay_domain`, the host's 443 published and a certificate for the name
  under reverse-proxy. NIP-11 info and the limits are settings; the
  database lives in `<prefix>-nostr-relay/db`.
- **`hub`**: a distribution built with kiwi-framework's `container/Dockerfile`
  (Armory's image `ghcr.io/derlocke-ng/armory` by default, a fork's own
  otherwise) behind the proxy at `hub.<hostname>`. Its `HUB_*` environment
  comes from the module's settings and the container writes it to
  `hub.local.json`, which the page reads before it connects: `relays` (empty:
  this host's nostr-relay), `relays_locked`, `require_hub`, `public_relays`
  and `public_mounts` for a semi-public hub. The render refuses a hub with
  no relay to name, and public mounts without public relays.
- **The node profile's `hub` preset**: vpn-client, reverse-proxy,
  nostr-relay, hub — a private hub as it comes. `examples/hub.yaml` is a
  semi-public one (Armory's chat on public relays).

## 0.3.0 — the stack network and the tunnels get an MTU each

- **`bridge_mtu` and `wg_mtu`** replace the one stack setting `mtu`
  (kiwi-server problem 40). `bridge_mtu` (1500) is the stack's bridge,
  `wg_mtu` (1376) gluetun's `WIREGUARD_MTU`, wg-easy's `WG_MTU` and the
  server's own `wg0`. One 1412 for all three split every full-size tunnel
  packet in two on the bridge, which carries the encrypted packet, 60 bytes
  bigger over IPv4 (80 over IPv6): TLS stalls and stuttering streams through
  the VPN on the v1 fleet. The template context has `bridge_mtu` and
  `wg_mtu` instead of `mtu`.
- **WireGuard's padding counts**: a packet is padded to a multiple of 16 as
  far as the *sending* peer's MTU allows, so a peer with a bigger MTU (the
  commercial exit) grows a 1352-byte packet to 1360 — on the v1 master that
  made 1420-byte packets on a 1412 bridge, about 40 000 split per 50 MB.
  StackSpec refuses a `wg_mtu` whose padded packets plus 80 bytes do not fit
  `bridge_mtu` (at most 1408 under 1500), or below 1280. The default 1376 is
  a multiple of 16 and never grows: 1436 bytes over IPv4 fits a 1452-byte
  DS-Lite path, 1456 over IPv6 a 1460 one (1380 grew to 1392, exactly 1452).
- **The old `mtu`**: a machine that still sets it gets it as `wg_mtu`, the
  bridge at 1500, and a warning; `mtu` and `wg_mtu` together are an error,
  and so is the usual 1412, which no longer fits once padded (1424 + 80).
- **The MSS is set, not clamped to the path**: the vpn-server's `start.sh`
  and the vpn-client's post-rules (`mss_clamp`) set every forwarded SYN to
  `wg_mtu - 40` with `--set-mss`, which never raises a smaller one.
  `--clamp-mss-to-pmtu` reads only the interface a SYN leaves by: on the v1
  master the way back (wg0, 1352) was wider than the exit (1344), clients got
  MSS 1312, and every connection's first full-size upload segment bounced.
- **vpn-server**: `start.sh` sets `wg0` to `wg_mtu` before the MSS rule;
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
