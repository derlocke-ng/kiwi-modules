# Changelog

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
