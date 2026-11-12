# Changelog

## 0.28.0 — a cache for the LAN

- New module `cache` for a node: a pull-through mirror per registry (docker.io, ghcr.io,
  quay.io, lscr.io) at `cache.<hostname>/<registry>` behind the reverse proxy, and a caching
  proxy for Debian's package servers on port 3142 (only those; packages are signed).
- Stack settings `registry_mirrors` and `apt_proxy`: what a machine asks first. kiwi-server
  fills them in for the nodes on the cache's LAN.

## 0.27.1 — fail2ban for public sites

- On a master with public sites nginx writes its logs to files as well (kept a day, the journal
  keeps its copy), and fail2ban reads them: nginx-bad-request, nginx-http-auth and
  kiwi-nginx-probe (requests for wp-login.php, .env, cgi-bin and the like, three strikes), banned
  in FORWARD, where the host's port forwarding passes those packets.

## 0.27.0 — fail2ban

- New module `fail2ban` (in the master preset): linuxserver's fail2ban on the host's network,
  an sshd jail (5 failures in 10 minutes, a ban of an hour, all settings) over sshd's log,
  which the host unit `kn-sshd-log` copies out of the journal (the image cannot read it), and
  a rate limit of 20 new SSH connections a minute per address. The mesh is never banned.
- Its port follows `admin.ssh_port` unless set: the jail and the limit watch where sshd
  listens.

## 0.26.3 — a node is back sooner after its master restarts

- vpn-client `keepalive`: 10 seconds for a node joining the fleet's master (was 25), 25 for a
  provider. A restarted master learns where a node is only from the node's next packet: with
  users on the mesh, lychee's services were gone for 30 s after sorbet's WireGuard server
  restarted (tests/drills/users.py in kiwi-server).

## 0.26.2 — a master's own names inside its containers

- On a master the containers found the master's own names at the reverse proxy's own address,
  where nothing listens: the proxy lives in the WireGuard server's namespace. They point at
  that container now (found by kiwi-server check on sorbet).

## 0.26.1 — federation, tried

- A partner's connections into the mesh come from an address of this mesh (`as`, per
  partner): a node routes only its own mesh back through its VPN client, and the answers to a
  partner's own addresses left by the LAN.
- On a master with an exit, the link's packets carry WireGuard's own fwmark into the table
  that leaves by the real interface: through the exit, the partner learnt the exit's address
  and the link went one way.

## 0.26.0 — federation

- vpn-server `federation`: a WireGuard link (`wg-fed`, UDP `federation_port`, 51822) to each
  partner network's master. Their mesh is routed through it; they reach only what is shared
  (`share`: a node, `node:port`, or `service.node` on 443) from the addresses in `from`, and
  this master's DNS. The link's key derives from `federation_secret` (generated from the seed).
- dns: a master forwards each partner's domain to the partner's DNS over the link.
- reverse-proxy `federation` (generated): per name, which partner addresses may open it; the
  partner networks are shut out of every name not shared with them.

## 0.25.2 — multi-hop keeps the master's address

- A master whose VPN client holds another network's config (multi-hop, `vpn_provider:
  custom`) no longer takes that config's address as its own: its Pi-hole answered its own
  names with the other network's address, so its clients could not reach it by name.

## 0.25.1 — the night's backup runs

- The nightly run (its time and the hour after) backs up unless one ran within the hour; a
  backup by hand in the evening skipped the whole night before. Starts at other times (an
  apply, a boot) still wait 20 hours after the last backup.

## 0.25.0 — backups the app can read

- `kiwi-stack snapshots --json`: a line per backup server with restic's JSON.
- backup-server: `keep_daily`, `keep_weekly`, `keep_monthly`, what `kiwi-server prune` keeps.

## 0.24.2 — every setting says what it is for

- Help for the 94 settings that had none, which the app shows beside each field; a test keeps
  every new setting from coming without one.

## 0.24.1 — the automatic restore finishes

- A restore brings the stack up with its target (or `docker compose up`) instead of
  `kiwi-stack start`, which restarts the host units too: the automatic restore runs in
  kn-backup.service, killed itself half way and began again until the start limit stopped it.
- kn-backup.service has no start limit: every apply restarts it, and the limit of 0.24.0
  counted those and kept the night's run from starting. Its retries back off instead, from
  an hour to at most eight.

## 0.24.0 — two copies, and a rebuilt machine brings itself back

- `backup.servers`: a machine backs up to each server in the list, a full copy of its own on
  each, one after the other; a server that fails costs only its copy. `backup.server` stays
  for one. A restore takes the freshest copy, from whichever server has it.
- `backup.restore: auto` (the default): a machine that finds itself in the backups but has
  made none of them (a rebuild) restores every module by itself at its first run, then backs
  up as before. `hold` keeps the old behaviour of waiting for a person.
- `backup-server` keeps no copy of itself: two nodes back each other up.
- A commercial VPN exit (Mullvad through gluetun) that stays unhealthy for five minutes is
  started anew, and with it another server: gluetun restarts a failing tunnel to the same
  server, so a bad server kept a master's exit down for good. Under podman only.
- The settings schema has `required_unless: KEY`.

## 0.23.0 — a restore from before

- `kiwi-stack restore --at TIME MODULE...` puts back the newest snapshot of each module made at
  or before TIME, for a mistake found later than the last backup. Every snapshot is found
  before anything stops, so a time with nothing to restore changes nothing.
- `kiwi-stack snapshots MODULE...` lists only those modules' snapshots.

## 0.22.0 — what shares a network comes back with it

- A container in another's network (Pi-hole, Tor and nginx in the VPN server's or client's)
  is bound to it and wanted by it. With Requires it stayed stopped when the VPN came back after
  a stop, and after a crash it ran on in the old, dead namespace, cut off and looking healthy.
  The master's public sites were down until someone ran `kiwi-stack start`.

## 0.21.0 — a rebuilt machine does not back up its empty self

- A machine that has made no backup but finds snapshots of itself on the server holds its
  backups until `kiwi-stack restore` or `kiwi-stack backup --new`. A rebuilt master backed up its
  fresh, empty state during its first apply, so `restore` put that back instead of the data, and
  the next prune would have kept only it of that day. The timer skips while it is held.

## 0.20.0 — a full disk costs one module

- A repository that could not take a frozen database ends the run. A full disk still answers,
  so each module after it would have sat frozen in its turn, every night.
- Asking whether the repository exists no longer takes a lock. With a stale exclusive lock it
  failed, restic was asked to create the repository, and the run died on "config file already
  exists" before it reached the line that removes such locks.
- A database is frozen for at most 10 minutes (it was 30), and a failed run tries again three
  times, not five.
- A file that goes away while a backup reads it no longer fails the whole run. restic stored
  the rest, and says so with its exit code 3.

## 0.19.0 — a dying backup lets go

- `kn-backup.service` thaws what a run left frozen, after every run. A run killed outright
  thawed nothing, and left a database paused and looking like it was running.
- A database is frozen for at most 30 minutes. A backup server that hung rather than refused
  kept one frozen for as long as it hung, 40 minutes in the test and with no end in sight.
- With the backup server gone a run stops there, instead of freezing each module in its turn.
- A run removes the locks of dead restic processes first: one left by an interrupted prune
  would have stopped every backup after it.
- A run that failed tries again an hour later, up to six times: a backup server rebooting at
  three in the morning no longer costs the night.
- The certificate job names the ACME account to use. certbot refuses to choose when it finds
  several, which a restored machine can have, so no certificate would ever have been renewed
  there. A failed renewal no longer blames the name's DNS record.

## 0.18.0 — the certificates come back too

- The backup holds a public site's Let's Encrypt certificates and ACME account, so a
  rebuilt machine does not have to ask again, which is limited to a few a week.

## 0.17.0 — a restore that cannot saw off its own branch

- `kiwi-stack restore vpn-server` says why it will not: stopping WireGuard on a master
  takes away the mesh the restore comes over. kiwi-server keeps that state itself.
- A restore starts the whole stack again afterwards: a container in another's network
  namespace stops with it, and nothing else brought it back.

## 0.16.0 — the relay

- `vpn-server.unlock_relay` lets a machine that cannot reach its Tang ring at boot ask
  the master's public port instead. The packet goes on into the mesh in netfilter, with
  no process on the master that could learn anything. A gate lets through only the
  addresses enrolled machines last connected from, rate limited, so a box carried off
  elsewhere is dropped first; it is rebuilt from `wg show` every 30 seconds.
- The `tang` module's rings are reachable at the node's mesh address too.

## 0.15.0 — Tang

- The module `tang` serves rings: one Tang server each, with keys of its own, on a port
  of the host. kiwi-server's `unlock:` block binds a machine's disk to them. The rings'
  keys are in the backup, since the machines bound to them need them.
- `ghcr.io/derlocke-ng/tang:15-kiwi2`: a stopped ring is a clean exit, not a failed unit.
- A bind mount with `each:` and `host:` makes one directory per key of a map, and one
  `open_ports` entry can come out as several ports.

## 0.14.0 — backups of a machine's data

- The module `backup` keeps a machine's data with restic, encrypted, on a node running
  the new module `backup-server`: every night, and with `kiwi-stack backup`.
  `kiwi-stack restore MODULE...` puts the newest back, and only those modules stop.
  Passwords come from the seed, one set per machine.
- A module says what it wants kept in a `backup:` block: `frozen` (containers held still
  while their files are read, for databases) and `paths`, `volumes`, `exclude` (read with
  everything running). Vaultwarden, Portainer, Nextcloud, Immich, Paperless, OpenCloud,
  the WireGuard server, the relay, Tor and an sftp folder of its own have one.
- The server gives every machine its own repository and lets it add but not delete, so a
  machine that is taken over cannot destroy its own backups.
- A map setting can hold password hashes of what other machines derive for themselves
  (`generate_each`, `generate_hash_of`).

## 0.13.0 — folders the apps share

- Nextcloud can show folders every user sees and other apps on the host can use:
  `cloud.shared_folders` and, for what another app produces, `cloud.read_only_folders`.
  `kn-cloud-folders.service` hands the shared ones to Nextcloud's user, sets up the
  external storage after every start of the stack, and looks through the read-only ones
  every 15 minutes, so that sync clients get what another app added.
- Immich can read such a folder: `immich.external_dirs`, mounted read-only for an
  External Library.
- Paperless can run as another user (`paperless.user_id`, 33 to share a consume folder
  with Nextcloud) and name its files (`paperless.filename_format`).
- A map setting can check its values (`pattern`) and keys (`key_pattern`); a bind mount
  can stand for every value of a setting (`each`).

## 0.12.1 — Paperless takes a login

- Paperless's login page answered 403. The reverse proxy's `Referrer-Policy: no-referrer`
  makes a browser send `Origin: null` with a form, and Django's CSRF check refuses that.
  A site can now set `referrer_policy`; Paperless uses `same-origin`, every other site
  keeps `no-referrer`.

## 0.12.0 — OpenCloud, Immich and Paperless-ngx to try out

- **`opencloud`**, **`immich`** and **`paperless`**: new modules for a node, each at its
  own name behind the reverse proxy, with generated secrets and a setting for where the
  data lives. `immich.machine_learning` and `paperless.office_documents` turn their
  extra containers off. None is in a preset: add them to `modules:`.
- **Nextcloud installs end-to-end encryption by default** (`cloud.startup_apps`). It takes
  effect on a new install; encrypted folders are chosen per folder in the desktop and
  phone clients.
- The podman runtime translates a compose `entrypoint` of one word.

## 0.11.1 — the golden bundle again

- Tests only: the golden `stack.sh` carried a real version number and `meta.txt` lacked a
  directory, so kiwi-server's check that it carries this release failed. Nothing rendered
  changes.

## 0.11.0 — a calendar's way to Nextcloud

- **`hub.caldav`**: the hub forwards `/remote.php/dav/` to a Nextcloud, so its calendar
  needs no CORS. That path answers the mesh only, on a public hub too: it is the login
  of a private Nextcloud.
- **`cloud.cors_origins`**: hubs on other addresses (Armory on GitHub Pages) may use
  CalDAV from the browser. nginx answers only real CORS preflights itself; a DAV
  client's own `OPTIONS` still reaches Nextcloud, because DAVx5 and others read the
  `DAV:` header from it.
- A master's containers and host can reach the mesh: the masquerade was there, but the
  rule keeping mesh clients off the container network dropped the answers too.
- **Nextcloud sees who its clients are.** It recorded every client as `127.0.0.1`, so
  brute-force protection counted nothing and its logs named nobody. AIO's Caddy replaces
  `X-Forwarded-For` from a proxy outside private address space, which the stack network
  is, so Nextcloud now reads `X-Real-IP`. And the gateway's masquerade no longer hides LAN
  clients of published ports behind the bridge address.
- `pattern` on a list setting now checks every item.

## 0.10.0 — local traffic stays local

- A node's Pi-hole and hosts file answer with the LAN address of nodes on its own
  LAN (`lan_addresses`, mesh address to LAN address). A client at home opening
  `cloud.<node>.home` went through the tunnel to the master and back; now it goes
  across the switch. Mesh clients still ask the master's Pi-hole and get mesh addresses.

## 0.9.1 — a gateway that works, a health check without a shell

- **The `gateway` module works for LAN clients.** Two of its rules were invalid and
  refused at every start, so LAN clients were not masqueraded into the VPN client and
  the rule keeping them off the container network was missing. On a firewalld host
  forwarded LAN traffic was refused as well. A policy now lets it through, and the
  stack's network is trusted permanently, so the reload that needs cannot cut
  containers off from each other. Found with the first real LAN client.
- A LAN client's connection to the gateway node's own mesh address goes straight to
  its reverse proxy: that address lives inside the VPN client and only takes
  connections from the tunnel.
- An exec-style health check (`[CMD, ...]`) now runs directly. It was flattened into
  a string, which podman runs through `/bin/sh`; Collabora's image has no shell, so
  it reported unhealthy forever while working fine.

## 0.9.0 — a public relay knows its members

- **`nostr-relay` authenticates connections (NIP-42).** A key list cannot carry a
  hub: boards, groups and gift wraps are not signed by the person's own key. A
  connection that has proven a member's key may post everything it sends.
- **`members: approved | registered`**: the keys on the list an admin signs (kind
  30000, `d` members), or anyone with an account on this hub. `approved` is the
  default. `write_pubkeys` are the admins and always write; a ban list (`d`
  banned) beats membership.
- From anyone: a gift wrap to a member, and a sign-up (kind 30790) with
  `register_pow` bits of proof of work and at most `register_per_hour` per
  address. Refusals start with `auth-required:`, `restricted:`, `pow:` or
  `rate-limited:`, so a client can act on them.
- **Our own strfry image**, `ghcr.io/derlocke-ng/strfry:1.1.3-kiwi1` (`images/strfry`):
  release 1.1.3 with a patch of a few lines and Python for the write policy. Stock
  strfry tells the policy who a connection is only for a protected event by that
  same key, and sends a challenge only for one, so a member's boards and groups
  could not be accepted. With the patch a connection is challenged when it first
  writes, as NIP-42 clients expect, and the policy sees the key for every event.
- `hub` passes the relay's `register_pow` on as `HUB_REGISTER_POW`.

## 0.8.0 — a public relay is not an open one

- **`nostr-relay` now limits who may post.** Anyone may read; the mesh may post;
  from the internet only the keys in `write_pubkeys` may. `open_writes` is the
  old behaviour, by name.
- **The relay reads the client's address from `X-Real-IP`**, not
  `X-Forwarded-For`. nginx appends to the second, which a client can pre-fill,
  so a stranger could have claimed a mesh address.

## 0.7.1 — from a test certificate to a real one

- Turning `acme_staging` off now gets a real certificate at once. certbot keeps
  a certificate that is not due for renewal, test service or not, so `acme.sh`
  drops one that came from the test service first.

## 0.7.0 — a public hub, and nothing else public with it

- **`reverse-proxy.public`**, for a master: publishes 80 and 443 from the
  WireGuard server's namespace. A site whose name is outside the fleet's domain
  (`hub_domain`, `relay_domain`) is public; **every other site, the admin pages
  among them, answers the mesh only**, enforced in nginx per site. Without
  `public` nothing changes.
- **Let's Encrypt for the public names**: a host timer asks for a certificate
  when one is missing or within 30 days of expiring, over HTTP-01, and has nginx
  reload when one changed. nginx starts on the fleet's certificate until then.
  `acme_email` is optional; `acme_staging` uses the test service, and leaves
  HSTS off so a test certificate cannot stick in a browser.
- A public site's replies to the internet leave by the real interface on a
  double-hop master; its replies to the mesh stay on `wg0`.

## 0.6.0 — hubs live on masters

- **`hub` and `nostr-relay` are for masters now.** A hub may be public, and a
  master is the machine made to face the internet; a node publishes its
  services on its LAN. The node role's `hub` preset is gone: a master lists
  them in its `modules:`. `examples/hub.yaml` shows one.
- Run on a test master: a device on the mesh gets the hub's page and config, the
  relay's NIP-11 document and a websocket, with the fleet CA verifying.

## 0.5.0 — service passwords no longer have to be written down

- **`wg_password`, `pihole_password`, `transmission_password`, `sftp_password`,
  the cloud's and Portainer's `admin_password` are generated when left empty**,
  from the fleet's seed like the cloud's database secrets, the same at every
  render. A value that is set is used as before.
- Portainer left empty used to wait on its first-run page; it now starts with a
  generated password.
- Removing a value from a running machine's settings changes that password.
  Nextcloud's and Portainer's are only read at their first start, so on a
  machine already set up the password stays what it was.

## 0.4.3 — two things a boot got wrong

- **`vpn-client`** sets `net.ipv4.ip_forward=1` itself. A new network
  namespace copies the host's value when it is made, and at boot on podman the
  VPN client's is made before the host's forwarding is on. After every reboot
  nothing could leave through the client, so a master's mesh clients had no
  internet until the stack was restarted (kiwi-server problem 61).
- **`vpn-server`**: where Tor shares the WireGuard server's namespace, the
  namespace gets `net.ipv4.ip_nonlocal_bind=1`. Tor binds the mesh address,
  which exists only once `start.sh` has brought `wg0` up, so its first start
  could fail with `Address not available` at a boot or a re-apply (kiwi-server
  problem 59).

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
