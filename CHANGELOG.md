# Changelog

## 0.92.0 — the website's files from a CDN

- The control module's `website_cdn_hostname` (cdn.example.org): a name a content delivery network
  fetches the website's files from; only `/assets/` answers there. kiwi-server points the pages'
  images at it.

## 0.91.0 — a group and the linked networks

- A VPN group that may reach everything reaches what the linked networks open too; a group with
  a narrower reach only when its list names the linked network (`reach: [nodes, kiwi2]`).
  Before, guests and pentest reached what a partner opened, as the master forwarded everything
  not inside its own mesh.

## 0.90.1 — a linked network's names on a node's LAN

- A node's Pi-hole asks the master for the linked networks' domains (`dns.partner_domains`,
  filled in by kiwi-server), with a wildcard past Pi-hole 6's own `local=/internal/`. A computer
  at home that asks papaya got NXDOMAIN for damson.internal; one on the VPN got its address.

## 0.90.0 — a website for strangers

- The control module's `website_hostname`, `website_repo` and `website_commit`: the network's
  website at a public name and its `www.`, its pages from a repository pinned to a commit
  (kiwi-server renders them; docs/design/website.md there). Both names go to the control part.

## 0.89.2 — a partner's names under .internal

- A master forwards every name under a linked network's domain to its DNS with a wildcard too
  (`server=/*.internal/…`): Pi-hole 6 keeps `.internal` and `.home.arpa` to itself, and its own
  line won over the forward. kiwi2's names, and what it opens to kiwi, did not resolve on kiwi's
  side (found 18 Nov 2026; the federation drill only asked the other way).

## 0.89.1 — a linked network names its master

- A master with linked networks answers `_kiwi-master.<domain>` with its own name: the partner's
  picture names the master its traffic goes through.

## 0.89.0 — a linked network says what it opens

- A master's DNS answers each linked network what this one opens to it: a TXT record
  `<the partner's mesh>._kiwi-share.<domain>` with the names from `share` (`-` for nothing).
  The partner's master asks for it over the link, and its picture draws those machines.
- `kiwi/federation-ask` on a master: the linked networks to ask the same, for kiwi-server's
  status.

## 0.88.2 — the accounts page in a machine's logins

- A machine with accounts lists `Accounts (Kanidm)` among its logins, and says why there is no
  admin password: kiwi-server takes Kanidm's admin over for each change and keeps none. Accounts
  and admins are made under Accounts on the control page or in the app.

## 0.88.1 — a machine with no site of its own answers at the mesh too

- The VPN client lets 80 and 443 in from the mesh also when the machine's only site is its
  own page (`reverse-proxy.machine_page`): a minimal node at another site (kumquat, the
  offsite drill, 18 Nov 2026) answered SSH over the mesh but not its page or registry.

## 0.88.0 — the network's registry, for the apps

- **`control`** 1.2.0: the status page's names also answer `/api/registry` and
  `/.well-known/kiwi`: the same as the page, as data for an app (kiwi-app). At the public name
  only what is open to the Internet. `/api/ca` there too: the network's CA, for an app to trust
  the `.home` names' certificates.
- **`reverse-proxy`** 1.3.0: `https://<the machine's name>/.well-known/kiwi`, and the same at the
  machine's address on the LAN, lead to that registry (`machine_registry`, kiwi-server fills it):
  an app finds the network from a name typed in, or by asking the addresses of the LAN.

## 0.87.0 — a machine's own name leads to its page

- **`reverse-proxy`** 1.2.0: `https://<the machine's name>` (papaya.home) answers when kiwi-server
  names the machine's page on the network's status page (`machine_page`): it sends the visitor
  there. Without it the name still answers nothing.

## 0.86.1 — the admins' claims reach the clients made before

- **`accounts`** 1.2.1: the setup asked for the admins' claims before the script had defined
  how ("admins_claims: command not found"), so the setup failed on a machine whose Kanidm had
  clients already (quince, 18 Nov 2026). The test's stand-in Kanidm has such a client now.

## 0.86.0 — the network's admins

- **`accounts`** 1.2.0: a group `admins`. Each service that signs people in with the accounts
  is told who is in it, in its own words (claims `kiwi_roles` and `immich_role`); the clients made
  before get them at the next apply. `accounts.sh member admins NAME on|off`.
- **`git`** 1.1.0: Forgejo makes the group's members admins at their sign-in, and takes it back
  from those who left it (its admin group).
- **`cloud`** 2.1.0: Nextcloud puts them in its group `admin`; only that group follows the
  accounts, every other group stays Nextcloud's own.
- **`immich`** 1.2.0: Immich makes them admins at their sign-in (its role claim). Leaving the
  group does not take it back there: Immich only changes a role a sign-in names.

## 0.85.1 — Kanidm's pages really take the network's name

- **`accounts`** 1.1.1: the name and logo were asked of `idm_admin`, whose rights end at the
  accounts, and Kanidm kept "Kanidm id.quince.home". Its `admin` is taken over for those two,
  as `idm_admin` is for the rest (a new password each time, never kept).

## 0.85.0 — the account pages look like the network's

- **`accounts`** 1.1.0: Kanidm's own pages (signing in, setting a password) say the network's
  name and show the kiwi, set on every apply that changes them; they said "Kanidm id.quince.home".
  The sign-up page says Kiwi when `brand` is empty, not the fleet's domain ("home").
- **`control`** 1.1.1: `brand_name` is for the pages for the Internet; the pages on the VPN say
  Kiwi (kiwi-server 2.188.0, where status.<host> is one page).

## 0.84.1 — a hub on a node calls through the master's turn

- **`hub`** 1.2.1: `ice` empty means a turn module on this host, else the master's: kiwi-server
  (2.187.0) names it to a hub on a node, with its login.

## 0.84.0 — a hub's calls get through (a turn module, coturn)

- **`turn`** (master only: it relays traffic and keeps no data): coturn 4.18 on the master's public
  address, for the voice and video calls in a hub's chat where two networks allow no direct path
  (two phones on mobile data, a strict firewall). It passes the browsers' encrypted media on and
  cannot hear them. 3478 UDP/TCP plus `relay_ports` (49160-49200) opened; never relays into the
  machine's own networks (private ranges, the mesh, the stack's network). One login, its password
  from the seed. From the pull request of 10 November (0.24.0 then), brought onto today's modules.
- **`hub`** names a turn server on the same host to its pages by itself (`HUB_ICE`, its login in
  the env file); one elsewhere with `ice`, `ice_username`, `ice_credential`.

## 0.83.1 — a sleeping game server is not a failed one

- Zandronum ends with an error code of its own when it is stopped: its unit stayed failed while
  it slept, and the machine showed a failed service (medlar, 18 Nov 2026). The sleeper clears
  that after putting a server to sleep.

## 0.83.0 — each site says how it can be opened beyond the VPN

- `Module.sites()` (and `sites` in `as_dict`): each web site of a module with the first part of
  its default name, the setting that takes a public name for it, whether it works over Tor, and
  whether it is an admin page. Read from the module's nginx blocks; `pages: {key: {public: …}}`
  names the setting where it is another one (Jabber's `xmpp_domain`, the public status page).
  kiwi-server builds its "Open to" choice from it.

## 0.82.0 — a module names its pages and its sign-in

- `pages:` in a module.yaml: its sites as the start and status pages show them, by the first
  part of the name (`grow: {label: Grow lights, about: …}`), so a module from a source is named
  like a built-in one.
- `accounts:`: its sign-in with the network's accounts (OpenID Connect): `site` (its address, a
  template), `callbacks`, `pkce`, `group`; the settings `accounts_client`, `accounts_issuer` and
  `accounts_secret` take the client. kiwi-server connects any module that says so.

## 0.81.0 — the master routes, your data lives on the nodes

- `nostr-relay` and `hub` run on a node too (a master still can): a hub's data stays at home,
  and its public names come in through the master like any node's service.
  `examples/hub.yaml` is a node now.
- The module table says it first: the master only moves traffic by default; services that keep
  data run on nodes. `xmpp`, `tang`, `nostr-relay` and `hub` were listed as master only.
- Links to kiwi-server's pages on kiwi-network.eu that exist.

## 0.80.0 — modules from elsewhere

- **Module sources**: `ModuleSet` and `discover()` take more folders besides the built-in
  modules (`extra=[(name, folder)]`); `kiwi-modules render` and `modules` take
  `--source NAME=FOLDER`. A source's module never takes a built-in module's name, nor another
  source's; each module knows its source (`source`, also in `as_dict`).

## 0.79.1 — the onion self-check outlives an address that does not answer

- The self-check (0.76.0) ran under `set -e`, and `curl` fails when nothing answers: the first
  address that did not answer ended the check quietly, the very case it is for. It never started
  Tor anew and (0.79.0) wrote nothing down. Seen on papaya, 17 Nov 2026: a new hidden service
  its own Tor did not find yet. Now a failed ask is written down and the check goes on; a test
  runs the check itself against an address that does not answer.

## 0.79.0 — hidden services on the status page; each Jabber sign-up page says its own name

- **onion**: the self-check writes what it found to `kn-onion/var/kiwi-check` (service, address,
  the answer through Tor, when), for kiwi-server's status pages. Its first look is two minutes
  after a start, then every ten minutes as before.
- **xmpp**: with `separate: true` both sign-up pages were headed with the public name (xmpp.example.org),
  the internal one too, whose addresses end in jabber.<hostname>. Each page now names its own
  service (needs kiwi-server 2.179.0 for the page to read it).

## 0.78.0 — the game page's parts

- **control** (1.1.0): `play_page` serves a game page at `play.<hostname>` (VPN only unless it is
  a public name): whatever is asked for there goes to the control part's `/play/…`. `play_group`
  (default `games`) is the group of the network's accounts whose members get in; `play_extra`
  lists more containers than the game servers (`machine/container`). No admin page.
- **accounts**: `accounts.sh oauth … --group GROUP` lets only the group's members sign in at a
  service (the group is made when missing); `accounts.sh member GROUP NAME on|off` and
  `members GROUP`.

## 0.77.0 — game servers that sleep while nobody plays

- **`sleep: N` for a game server** (games module 1.1.0): after N minutes (5 or more) in which no
  player sent it anything, the server stops and frees the machine's memory; the first player who
  tries to join wakes it, and gets in a minute or two later. `kn-games-sleep.service` counts the
  packets for each server's ports in the mangle table (only connections that came from outside,
  so the server's own talk to a master server list does not keep it awake), every five seconds.
- A sleeping server has a file in `/run/kiwi-stack/sleeping/`: kiwi-stack 0.9.12 and kiwi-server
  count it as asleep, not as down. One stopped by hand has none and stays stopped.

## 0.76.1 — the onion help names `round`

- The onion module's help says what `round` in `services` does: a new address, and the old one
  stops working.
- A test of the git module no longer needs `cmp`, which the control image does not have.

## 0.76.0 — hidden services that stop being found start anew

- **The onion module checks its own addresses**: every ten minutes each hidden service open to
  anyone is asked through Tor itself (a SOCKS socket in its own folder, which no other container
  reaches); three rounds in a row with one that answers nothing, and Tor starts anew. On
  17 November 2026 two of medlar's three hidden services had answered nothing for hours while
  Tor ran on; a start anew brought them back.

## 0.75.1 — the small Tang image answers kiwi-server's questions

- The Tang image (15-kiwi6) has `curl` and `tang-show-keys` again: kiwi-server asks a ring for
  its key and its advertisement with them when it binds a machine (15-kiwi5 lacked both).

## 0.75.0 — a ring on the master, for the first machine at home

- **The tang module runs on a master too**: there the ring lives in the VPN server's namespace,
  and the VPN server publishes it (`vpn-server.local_rings`, filled in by kiwi-server) behind the
  gate the unlock relay already has: only the addresses enrolled machines last connected from
  get through. The first machine at home opens with it (`away`) after a power cut, and a box
  carried off elsewhere gets no answer.
- **The Tang image is built from Tang's source on Alpine** (15-kiwi5): 9 MB instead of about
  150, so it fits on a master that runs in memory. Same keys, same start.

## 0.74.0 — a ring's keys survive a power cut

- **The Tang image (15-kiwi4) makes a ring's keys beside, flushes them to the disk, then puts
  them in place**; a key file left empty by a power cut is put aside and never served. Before,
  a cut right after a ring's first start could leave it answering with nothing a machine can
  use. Tried in a container: new keys, the same keys after a restart, empty ones replaced.

## 0.73.0 — a container others live in always starts again

- **Before a container whose network namespace others share starts (the master's VPN server,
  a node's VPN client), whatever is still left in that namespace is removed**: a container
  started there by hand once kept the master's VPN server from being replaced, and its unit
  failed to start over and over (kiwi2, 17 Nov 2026). The stack's own containers come back
  with it as before.

## 0.72.0 — the switch to a standby does not flap

- **A return to the master that fails doubles the wait for the next one** (10, 20, 40 … minutes,
  up to eight hours; as new after an hour on the master): its machine answering is not yet its
  VPN answering. A test runs the switch through that story.

## 0.71.0 — a node follows its master to a standby

- **vpn-client: `standby_endpoints` and `standby_ping`** (kiwi-server fills them in for a node
  whose master has a standby): `kn-master-switch.service` moves the node's tunnel to the next
  address after three minutes without an answer from the master, and back to the master once
  its machine has answered for ten minutes. Without them nothing changes.

## 0.70.0 — Tor wakes at every start

- **tor:** `DormantCanceledByStartup 1`. Tor goes to sleep after a day without a client and stayed
  asleep across restarts until a client asked; its directory grew old meanwhile (found on the
  spare master crumble: no connection for 20 hours, "Dormant 1" in its state).

## 0.69.0 — the sign-up pins Kanidm's certificate; a provider's OpenVPN exit without a master

- **accounts:** the sign-up page talks to Kanidm with Kanidm's own certificate as the only one it
  trusts (`--kanidm-cert`, kiwi-server 2.160.0); before, it checked none.
- **vpn: false** allows a provider's OpenVPN file (`vpn_provider: custom`, `vpn_type: openvpn`) as
  a machine's exit; custom WireGuard stays the mesh's.
- **dns:** `upstream_dns` says what a network without a master asks (the fallback resolvers,
  unencrypted from the home line) and that you may set your own.

## 0.68.0 — the rest of the review of 15–16 November; a provider's OpenVPN file

- **`vpn: false` no longer drops the VPN client that the downloader, the gateway or BTCPay send
  their traffic through** (it would have left at home): it says to add a commercial VPN's
  `vpn-client`, or to leave the module out (`dependencies.exit`).
- **A commercial VPN as the exit of a machine off the VPN** opens none of the mesh's ways in on
  that tunnel (DNAT, the modules' inbound rules, mesh SSH).
- **Paperless:** a document without an owner was everyone's to change and delete. The admin owns
  what comes from the consume folder and from mail now (a workflow), and any left without.
- **Client secrets off command lines:** Immich's goes in on psql's input; Nextcloud's reaches the
  container in its environment.
- **games:** a second Bedrock server (another `port`) listens on that port inside too; it told
  clients the first server's port.
- **accounts:** `ldap` says what it does: Kanidm answers LDAP, nothing uses it yet; Jabber keeps
  its own accounts.
- **vpn-client: `openvpn_config`**, a provider's .ovpn with its certificates inside (Riseup and
  other OpenVPN-only providers), with `vpn_provider: custom` and `vpn_type: openvpn`.

## 0.67.0 — admin areas inside a site are for the admins only

- A site's location can be an admin area (`admin: true` in `extra_locations`): the VPN groups
  without the admin pages are refused there, whatever else of the site they reach. kiwi-server
  hands the ranges over as `reverse-proxy.access.admin`, on nodes and masters.
- ejabberd's `/admin` and Vaultwarden's `/admin` are such areas. Vaultwarden's answers the VPN
  only now, also when the vault has a public name.

## 0.66.0 — Jabber: one page for new accounts; its admin panel from the VPN only

- **One page, `/join`, whatever way is on.** Invite codes, requests and the open way (now with a
  picture test on that page, kiwi-server 2.158.0) are on the same page. ejabberd's own
  `/register` page is gone and sends people to `/join`.
- **By default only with an invite code or an accepted request** (`invites`, `requests` on,
  `registration` off), as the network's accounts. Open sign-up is a choice, in the apps too.
- **ejabberd's admin panel (`/admin`) answers the VPN only.** It showed its password prompt to the
  internet and over Tor.
- New settings: `file_days` (files people send are deleted after 30 days; 0 keeps them),
  `room_creators` (everyone or admins), `admins` (more admin accounts).
- The dates of the games catalog and two changelog lines: 16 November, not the 17th.

## 0.65.1 — the pages believe a forwarded address from their proxy only

- control and accounts (sign-up): `KIWI_PROXY` names the reverse proxy in front. kiwi-server 2.157.0
  believes X-Real-IP from it only, so nobody else picks the address that a limit per address counts.

## 0.65.0 — fixes from the review of 15–16 November

- **No account taken over by name.** Forgejo linked a sign-in to an existing user of the same name
  (`ACCOUNT_LINKING=auto`); it asks for that account's password now (`login`). Nextcloud's
  user_oidc joined a sign-in to a local user of the same name (soft auto-provisioning); that is off.
- **Tor never leaves on a home line unless chosen.** Stack setting `at_home` for a master at home
  (the first questions set it): there, and on a node without a VPN client, `tor` and `onion` get no
  network unless a VPN exit exists or `without_vpn` is chosen. A node's `tor` uses its VPN client.
- **fail2ban, corrected:** jails for Immich and Paperless (their wrong logins, from their logs;
  checked against real log lines); one ban list per jail behind the master, so one jail letting an
  address out does not lift another's ban, and recidive's week holds; a banned visitor's connection
  is closed (444), no 403 for another jail to count; private addresses are ignored only on machines
  at home, not on masters; the list's reload has no start limit; the bulk paths and page files have
  a limit of their own (ten times as high) instead of none.
- **A master that hands a node's names on keeps its own sites the mesh's.** With no public names of
  its own, its admin pages (wg-easy, Pi-hole) answered on 443 from the Internet.

## 0.64.0 — Tor without a VPN, when the owner chooses it

- onion: `without_vpn` (default off). Off, Tor runs only through a VPN, as before. On, a machine
  without a VPN client runs its hidden services through its own connection (its provider can see
  Tor traffic) instead of none at all. A machine with a VPN client still uses it.
- Fixed: a machine with the onion part and no VPN client did not render at all
  ("network_mode 'none' is not translated"); its Tor now gets no network, as meant.

## 0.63.0 — a commercial VPN as the exit of a machine off the mesh

- `vpn: false` (a network without a master) allows a VPN client when it is a commercial VPN's
  (`vpn_provider` mullvad, protonvpn, …), named in `modules:`: Tor, downloads and anything else that
  shares its network leave there, never on the home line. Nothing routes the home network into it,
  and the mesh's own VPN client (`custom`) is still refused there.

## 0.62.0 — fail2ban as others ship it: nobody banned for using a service

Compared with fail2ban's own defaults, Debian, YunoHost, mailcow, linuxserver's SWAG, Nextcloud's,
Vaultwarden's and Forgejo's guides. On the test network every wrong ban came from two of ours.
- No `nginx-bad-request` jail: a 400 never reaches an app, and real clients make them (a websocket's
  close frame, an empty connection a browser opens ahead). None of the others turn it on.
- sshd: `mode = normal` (failed logins), not aggressive (every connection closed before a login,
  six for one key scan). Logins are by key only.
- Private addresses are never banned (`ignore_home`, default on): who is inside a home is one of
  its people. mailcow, SWAG and YunoHost do the same.
- Bans start at 10 minutes and grow for an address that comes back (`bantime.increment`, up to
  `bantime_max`, 1 week). Was: 1 hour, fixed.
- recidive (out for a week on every port) after 5 bans in a day, fail2ban's own number; was 3.
- kiwi-nginx-refused leaves the apps' own doors to their jails (Nextcloud's WebDAV and OCS, `/api/`):
  a sync client keeps a stale password for a while. Forgejo's jail takes 10 tries (its guide).
- The rate limit leaves out what sync clients and photo apps fetch in bulk (WebDAV, previews, Immich
  thumbnails); its jail bans only after five minutes of refusals (600), not one (120).
- nginx's list of banned addresses starts empty with fail2ban, which puts back the bans it keeps:
  a jail taken away leaves nobody locked out.

## 0.61.3 — Nextcloud's push channel through the proxy

- cloud: the site passes websockets on (`websocket: true`). notify-push (`/push/ws`, the desktop and
  phone apps' channel) answered 400 every two minutes without the Upgrade header; the app's close
  frame then reached nginx as a bad request, and fail2ban banned the Nextcloud user. Seen on the
  test network on 16 November.

## 0.61.2 — a temporary file per writer

- `write_text` and `write_bytes` write through a temporary name of their own per process and
  thread: two writers of one file no longer share one `.tmp` (kiwi-server 2.152.1 found it).

## 0.61.1 — the home network stands in for the mesh

- `vpn: false`: the home subnet takes the mesh subnet's place too (unless `mesh_subnet` is set), so
  what is only for the network itself (the control page, fail2ban's own addresses) lets the home in.

## 0.61.0 — a machine off the VPN

- Stack setting `vpn` (default yes). `vpn: false` is for a network without a master (yet): the
  VPN client is left out of the presets and of what parts require, and the machine's fixed address
  at home stands in for its mesh address, so its sites and names answer on the home network. Named
  outright in `modules:`, the VPN client is refused; a machine without a fixed address is asked
  for one. The gateway and the downloader still need the VPN client.
- `ModuleSet.resolve(names, node_type, without=())` and `StackSpec(without=…)` carry it.

## 0.60.4 — every game of the catalog started

- games: the catalog's note says which games were started from it and listened: all ten, on
  16 November 2026. Steam games download the game at their first start; a failed download ends the
  container, which starts again by itself.

## 0.60.3 — Minecraft Bedrock as it runs now

- games: Bedrock (1.26.50 and later, NetherNet) shakes hands on TCP 19132 and plays on the UDP port
  it is told (`SERVER_UDP_PORTS`), not on UDP 19132 alone; both are handed on now. It no longer gets
  UID/GID: with them it could not write its own folder; it takes the folder's owner. Terraria,
  Factorio and Bedrock were started from the catalog and listen (kiwi-server's
  tests/drills/game-images.py).

## 0.60.2 — connecting a service works (really)

- accounts: `accounts.sh oauth` named its loop over the callbacks `url`, which is also Kanidm's own
  address in the script: every Kanidm call after the first callback went elsewhere and the script
  stopped. The test now checks that every call goes to Kanidm itself.

## 0.60.1 — connecting a service works again

- accounts: `accounts.sh oauth` (0.60.0) read its words one place off: Kanidm was asked to make the
  client with the wrong origin and refused, without a word. A refusal is said now, and a test runs the script against a
  stand-in for podman and checks the Kanidm commands it gives.

## 0.60.0 — Immich signs people in with the network's accounts

- **immich**: with `accounts_client`, `accounts_issuer` and `accounts_secret` (kiwi-server sets them:
  `kiwi-server accounts connect HOST immich`), `kn-immich-accounts.service` puts the sign-in into
  Immich's own settings in its database, keeping whatever else the admin set there; Immich's admin
  page stays editable (a config file would lock all of it). "Sign in with accounts" makes a person's
  Immich user at the first sign-in; the phone app is sent back through Immich's own redirect page.
  Immich trusts the fleet's CA (`NODE_EXTRA_CA_CERTS`).
- accounts: `accounts.sh oauth` takes several callbacks and `--pkce` for a service that sends a PKCE
  challenge (Immich); the others stay as they were.

## 0.59.1 — people from the network's accounts can use Paperless

- paperless: a person's first sign-in with the network's accounts made a Paperless user who could do
  nothing ("Error loading settings"). New users land in the group `accounts` now, which
  `kn-paperless-accounts.service` makes: documents, tags, saved views, notes, mail rules; not the
  workflows (they act on every document) and not the system's settings.

## 0.59.0 — Vaultwarden signs people in with the network's accounts

- **vault**: with `accounts_client`, `accounts_issuer` and `accounts_secret` (kiwi-server sets them:
  `kiwi-server accounts connect HOST vault`), Vaultwarden offers "Use single sign-on" with the
  network's accounts; it trusts the fleet's CA through a small start script. The person still keeps a
  master password: it unlocks the vault, the network never sees it. New setting `sso_only` (off).

## 0.58.1 — cookies hold over Tor

- reverse-proxy: at a hidden service, a cookie the service makes for its usual name is given the hidden
  address instead (`proxy_cookie_domain`). Kanidm's password page over Tor failed with 403: the
  browser had dropped its session cookie.

## 0.58.0 — Paperless signs people in with the network's accounts

- **paperless**: with `accounts_client`, `accounts_issuer` and `accounts_secret` (kiwi-server sets them:
  `kiwi-server accounts connect HOST paperless`), Paperless offers "Sign in with accounts" through
  allauth's OpenID Connect, makes the person's Paperless user on first sign-in and trusts the fleet's CA
  for the accounts server.

## 0.57.0 — signing up over Tor

- accounts: told its hidden service's address (`onion`, kiwi-server fills it in), the sign-up page gives
  someone who came over Tor links that stay on Tor: the password link, and the way to sign in.

## 0.56.1 — Nextcloud's sign-in starts on SELinux hosts

- cloud: the sign-in unit reads its secret in its script, not as systemd's EnvironmentFile, which
  SELinux keeps systemd from reading under the home folder (uCore).

## 0.56.0 — Nextcloud signs people in with the network's accounts

- **cloud**: with `accounts_client`, `accounts_issuer` and `accounts_secret` (kiwi-server sets them:
  `kiwi-server accounts <fleet> connect <host> cloud`), a host unit installs Nextcloud's OpenID
  Connect app and adds the accounts as "Log in with accounts"; a person's first sign-in makes
  their Nextcloud user. The admin and people made in Nextcloud keep their own passwords. The
  client's secret is in the unit's environment file, not on a command line.

## 0.55.2 — Jabber's sign-up page has the server's name

- xmpp: the sign-up page is called after the Jabber server (its public name, else its VPN
  name), not after the fleet's domain.

## 0.55.1 — a command word with spaces

- quadlet: each word of a container's command is quoted the way systemd reads it. A word with
  spaces or quotes (the JSON that tells Jabber's sign-up page where its servers are) fell apart
  and the container did not start.

## 0.55.0 — Jabber's sign-up page, chosen per network

- **xmpp**: besides the captcha (`registration`), a page at `https://<name>/join` takes invite codes
  (`invites`: the person chooses name and password, the address is made at once) and requests
  (`requests`: accepted on the control page, the person gets a password shown once with their
  request code). Any mix of the three, or none. The rules on the page: `terms`.
- ejabberd answers its HTTP API on port 5281 to the stack network only, and allows it two commands:
  make an account, and ask whether one exists.

## 0.54.1 — a sentence with a colon

- control: `about` (and the other words on the pages) may hold ": ": they are quoted now. A sentence
  like "Services for friends: chat, files" made the compose file invalid.

## 0.54.0 — start pages

- **control**: the status name (`status.<hostname>`) opens the network's start page now: every
  service people use, what it is for, its address and Tor address, whether it works. The status
  page is at `/status`. The public name opens a front page for strangers: the services open to the
  Internet, how to get an account, and `/status`.
- New settings: `brand_name`, `brand_accent`, `about`, `contact`: the network's name, colour, a few
  words and how to reach its people, on those pages.

## 0.53.1 — the module list in the docs

- `accounts` and `authenticator` in the docs' module table.

## 0.53.0 — Forgejo signs people in with the network's accounts

- **git**: with `accounts_client`, `accounts_issuer` and `accounts_secret` (kiwi-server sets them,
  `kiwi-server accounts <fleet> connect <host> git`), Forgejo shows "Sign in with accounts"; a
  person's first sign-in makes their Forgejo user. Forgejo trusts the fleet's CA for it.
- **accounts**: `accounts.sh oauth` registers a service that signs people in (OpenID Connect,
  without PKCE for a client with a secret, as Forgejo is); every account gets an address nobody
  reads (`name@<accounts' name>`), as Forgejo wants one and the network sends no mail.

## 0.52.0 — accounts, and one name per service

- **New module `accounts`**: Kanidm keeps the network's people, passwords and passkeys, at
  `id.<hostname>` or a public name. People get an account with an invite code or by asking
  (kiwi-server's sign-up page at `/join`, in its own container), and set their password with a
  link: no email. `kiwi/accounts.sh` makes accounts and links for kiwi-server. A password alone
  will do unless `second_factor` is on; Jabber can check passwords over LDAP (`ldap`), with the
  same password as the pages. 59 MB at rest.
- **A service with a public name keeps its VPN name**, which sends the browser on to the public
  name (301): Forgejo, Nextcloud, Vaultwarden, Immich, Paperless, OpenCloud, PrivateBin, BTCPay,
  Firefox Sync and the accounts. Both names are in the network's DNS and the machine's certificate.

## 0.51.0 — every WireGuard VPN provider as the exit

- **The VPN client takes every provider gluetun knows with WireGuard**: Mullvad, ProtonVPN,
  NordVPN, Surfshark, AirVPN, Windscribe, IVPN, FastestVPN, and any other provider's WireGuard
  config through `custom` (`wireguard_public_key`, `wireguard_endpoint_ip`, `vpn_endpoint_port`).
- ProtonVPN and NordVPN were refused: they give out no tunnel address, and one was demanded.
  Each provider is now checked for what it needs (AirVPN and Windscribe a preshared key:
  `wireguard_preshared_key`).
- `server_regions` and `server_hostnames` choose the exit's servers too.

## 0.50.0 — fail2ban done the way the apps document it

- **Wrong logins, per app**: a module says what a wrong login looks like in its log
  (module.yaml `fail2ban:`), and fail2ban bans who keeps on: Forgejo, Vaultwarden and Nextcloud
  to start with; Jabber has its own. A small host unit copies just those lines out of the
  app's log.
- **Never for loading a page**: a page's own files (scripts, styles, pictures, fonts) no longer
  count against the rate limit, and the rate limit's jail bans a flood only (120 refusals in a
  minute, not 10). The jail for refused requests is looser (40) and leaves WebDAV's PROPFIND out.
- **Bans that work behind the master**: a node's visitors come through the master, so a firewall
  rule on the node never matched them. There a ban is now a line in nginx's list of banned
  addresses, which nginx reads again when it changes.
- **The network's own addresses on nodes too**: the master tells its nodes, on port 80 to the
  mesh only, where the network's machines come from; their fail2ban never bans those either.
- **A node whose sites strangers reach gets fail2ban by itself.**
- fail2ban no longer stops on a new machine because its own log did not exist yet.
- Forgejo takes the visitor's address from nginx (`REVERSE_PROXY_TRUSTED_PROXIES`).
- A master's port 80 answered the mesh by its internet interface, so the answers never came
  back; they stay in the tunnel now.

## 0.49.1 — a master never bans its own network

- **fail2ban on a master leaves the network's own addresses alone**: every minute it reads
  where the machines' VPN tunnels come from (a home's public address) and tells every jail to
  ignore those addresses and let them out. Before, someone at home who loaded a public page
  too often locked the whole home out of the public names.

## 0.49.0 — plain names, fewer settings in view

- **The modules are called what they do**: *Files (Nextcloud)*, *Ad blocker (Pi-hole)*,
  *VPN connection*, *Web addresses (nginx)*, *Downloads*, *Home gateway*… instead of
  *Nextcloud*, *DNS (Pi-hole)*, *VPN client (gluetun)*, *Reverse proxy (nginx)*. The app,
  the control page and `kiwi-server modules` show these names.
- **Technical settings moved to Advanced** (25 of them): container images, ports that
  rarely move, sharing another container's network, certificate files, user ids. The app and
  the control page fold Advanced away.

## 0.48.1 — Jabber's accounts stay with their name

- When one Jabber service became two (`separate: true`), the public one started with no
  accounts: the accounts of the public name stayed in the first service's data. Each name
  now has a folder of its own (`hosts/<name>`), made once from the old layout's folder that
  holds that name's accounts. Switching between one service and two keeps every account.
- The public instance is stopped too while a backup saves Jabber's data.
- Tried on a test node: two services to one and back, the accounts with their names
  throughout; logins from the Internet and the VPN after.

## 0.48.0 — a game server open to the Internet, through the master

- **`games: servers: <name>: public: true`**: players outside the VPN join at the master's
  address, and the master hands the game's ports on to the machine, TCP and UDP, as they
  are. Nothing is opened at home.
  - A module's `expose: ports:` takes `25565/tcp` and `10666/udp` beside `5222:15222/proxy`;
    the master's proxy forwards UDP too, and its WireGuard server publishes the ports and
    answers by the real interface.
  - A node's ports are handed on whether or not it has a public web site.
- The notes on the sites usable over Tor say what was tried since (logins through Tor).
- Tried on a test node behind the master: Minecraft answers the server list's question at
  the master's address (TCP), Zandronum the launcher's (UDP).

## 0.47.1 — the master's door counts connections; a password with a dash

- What a master hands on to a node passes its limits on the node, which cannot keep an
  address out. The master's door (443 and the handed-on ports) now lets one address hold
  four times `rate_limit` connections at once (80 by default).
- Jabber's admin password may start with a dash: it was read as an option of `su`, and
  the account was not made.
- The pastebin's help says that a public name works on a node too.

## 0.47.0 — hidden services reworked, an authenticator, a public status page

- **Hidden services**
  - A redirect at a hidden service named the proxy's inner port (`http://….onion:8043/login`),
    which Tor does not carry: BTCPay's login was unreachable that way. Fixed.
  - A site with a `proxy_redirect` of its own (Nextcloud) made nginx refuse the whole
    config as a hidden service: every site of the machine was down. The site's own one
    is left out there.
  - **Sites usable over Tor are marked** (`onion: true` in a module's nginx block): Git,
    BTCPay, Jabber, the pastebin, the hub, the relay, Nextcloud, Immich, Paperless, the status
    page. Each
    was opened through Tor; the mark says what was tried. kiwi-server offers only those.
  - **Paperless** as a hidden service: it is told its `.onion` address (setting `onion`,
    filled in by kiwi-server), so a login sent from there is taken instead of refused.
  - **https at the address**: the onion module's `tls: true` hands port 443 over too, and
    the proxy answers it with one certificate for the machine's addresses
    (`reverse-proxy.onion_fullchain`, `onion_privkey`, from kiwi-server: the fleet CA's, or
    one of its own when the CA is limited to the fleet's names).
- **A new module, `authenticator`**: 2FAuth 9.0.1 at `auth.<hostname>`, the six-digit
  codes of two-factor logins in a page of one's own. For the VPN only (a public name is
  refused); its key comes from the fleet's seed; its database is in the backup.
- **A public status page**: the control module's `public_status_hostname` adds a site that
  asks the control part for `/status/public` only: the services open to the Internet.
- Tried on test machines: seventeen hidden services through Tor (pages, files, login
  forms, what a browser app is told about its address); https at four of them; the
  authenticator's pages over the VPN.

## 0.46.2 — a name that keeps its mesh address at home

- A module's site can say `mesh_only:` (in its nginx block): its service answers at the
  machine's mesh address only. On a LAN such a name is then not answered with the
  machine's address at home (`lan_addresses`), in Pi-hole's records and in the hosts
  file. `Renderer.mesh_only_names(spec)` lists them; a spec takes them as `mesh_only`.
- Jabber on a node marks its names so: its ports (5222, 5223) are in the VPN client's
  network, and a device at home was sent to the machine's home address, where they are
  closed.

## 0.46.1 — a node without a mesh address yet is told what it needs again

- 0.46.0 made every node with a reverse proxy and no mesh address yet (not enrolled) stop
  with "modules/reverse-proxy firewall: ${VPN_IP} is not set" instead of the sentence that
  says what to do. The new rules name the address the way the templates do.

## 0.46.0 — a node's service open to the Internet, through the master

- **`reverse-proxy: { public: true }` on a node.** A site whose name is outside the fleet's
  domain is then open to the Internet without opening anything at home: the master hands
  the name on to the node through the VPN, still encrypted, and the node holds the Let's
  Encrypt certificate (the master forwards Let's Encrypt's question too). Each connection
  comes with the visitor's address in front (PROXY protocol), so the node's rate limits
  count the real visitor. On the VPN the name is the node's own.
  - The master's own sites move behind that door (its proxy's `stream` block on 443) and
    still see who asks. A master that hands nothing on is as it was.
  - Generated settings: `reverse-proxy.exposed` (master: names and ports) and
    `reverse-proxy.via` (node: the master's mesh address). `Renderer.exposure(spec)` lists
    a node's public names and ports for kiwi-server.
  - A module names ports to hand on with `expose: ports:` ("5222:15222/proxy").
- **`xmpp` runs on a node** (and still on a master): in the network of the machine's door
  to the VPN. With a public name the master hands Jabber's ports 5222, 5223 and 5269 on.
  A hidden service on the node works as on a master. A new certificate is in use within a
  minute during the first hour.
- The master's Jabber and handed-on ports answer the Internet by the real interface when
  the master leaves through a VPN exit.
- Tried with a node behind a master: certificate fetched, logins from the Internet, the
  VPN and Tor, the page for new accounts with its captcha on all three.

## 0.45.0 — Firefox Sync

- **A new module, `firefox-sync`**: Mozilla's own sync server (syncstorage-rs) with a
  PostgreSQL database, wired as Mozilla's stand-alone set-up wires them, at
  `ffsync.<hostname>`. Bookmarks, tabs, passwords and history of your Firefox browsers
  are then kept on this machine, encrypted by the browser. In Firefox: `about:config`,
  `identity.sync.tokenserver.uri` = `https://ffsync.<hostname>/1.0/sync/1.5`, before
  signing in to sync.
  - The login still goes through a Mozilla account: the server asks Mozilla who someone
    is. Running Mozilla's accounts server too is not part of this.
  - Mozilla's image is for x86-64 only.
- Run by hand on a test machine with the module's settings: the server says that it and
  its database are fine, and its token door answers 401 without a login. Not tried: a
  browser syncing (it needs a Mozilla account).

## 0.44.0 — a pastebin, rate limits, and fail2ban that acts on them

- **A new module, `paste`**: PrivateBin, a page to put a text or a file on and pass its
  link along; it is encrypted in the browser. `paste.<hostname>` for the mesh; on a
  master a public name (`paste_domain`); for strangers elsewhere a hidden service
  (`onion: { services: { paste: {} } }`). Settings: title, how long a paste is kept,
  its largest size, files on or off. Its pastes are a volume, in the backup.
- **reverse-proxy: rate limits for sites strangers reach.** One address may send
  `rate_limit` (20) requests a second to a public site, four times that at once; more
  gets 429. A hidden service's visitors look like one address, so there the limit is the
  site's, three times as high. Sites of the VPN are not limited. Clients that send or
  read too slowly are let go.
- **fail2ban: three more jails.** `nginx-limit-req` bans who keeps hitting the rate
  limit, `kiwi-nginx-refused` who is refused twenty times (wrong passwords, closed
  pages), on a master with public sites; `recidive` puts who was banned three times in
  a day out for a week, on every machine.
- Tried on a test master: 500 fast requests from another server to a public site got
  some answers, some 429, and then a ban; the site did not answer that address until
  the ban was lifted. PrivateBin by hand with the module's settings: a paste was stored
  and read back.

## 0.43.0 — Jabber with a registration page, a captcha, and three doors

- **xmpp is ejabberd now** (it was Prosody for two releases): what was asked for is built
  into it. A server set up with 0.41 or 0.42 starts empty: its accounts were Prosody's.
  - **Accounts**: people make their own, in a Jabber app or on the page
    `https://<name>/register`, each after a captcha; one new account per address in ten
    minutes; an address that keeps typing wrong passwords is shut out for an hour.
    `registration: false` leaves it to the admin.
  - **One service, three doors.** The VPN: `jabber.<hostname>` (was `chat.`). The
    Internet: `xmpp_domain`, a public name; it then comes after the @, and apps on the VPN
    can still connect to the VPN's name. Tor: with the onion module and
    `onion: { services: { jabber: {} } }`, the page and Jabber's port 5222 answer at the
    hidden address, and people who cannot check a certificate can have accounts
    `@<address>.onion`.
  - **Or two apart**: `separate: true` with a public name keeps the VPN's service as it is
    and runs a second one for the public name, in a container of its own. Their accounts
    are apart and they do not exchange messages.
  - The image is the project's own, `ghcr.io/derlocke-ng/ejabberd`: ejabberd's plus
    ImageMagick and fonts, without which its captcha cannot draw and the server does not
    start.
- reverse-proxy: at a hidden service, what a page links to under its usual name leads
  back to the hidden address (captcha pictures, absolute links).
- onion: a hidden service of Jabber carries port 5222 beside the page.
- For modules: a template is told which output it makes (`output`), so one template can
  make several files.
- Tried on the test master: the admin logs in over the VPN, the page shows a captcha
  picture and refuses a wrong answer, the app's registration form carries a captcha, and
  through Tor the page opens and a Jabber server answers on 5222. Not tried: a public
  name (it needs a plain DNS record), two apart on a machine, a client app.

## 0.42.0 — BTCPay Server

- **A new module, `btcpay`**, for a node: BTCPay Server with its own Bitcoin node,
  NBXplorer and PostgreSQL, wired as the project's own set-up wires them and pinned to
  its versions. At `pay.<hostname>` behind the reverse proxy; with the `onion` module
  (`onion: { services: { pay: {} } }`) a hidden service for strangers.
  - The four containers share the VPN client's network: the Bitcoin node reaches the
    Bitcoin network through the VPN, never through the machine's own line, and listens
    for nobody. Database and node answer on 127.0.0.1 only.
  - The admin's account is made at the first start with the password of the settings,
    before the page is reachable: BTCPay gives the first account to whoever makes it.
  - `network`: mainnet, testnet, signet or regtest. `prune_mb` (5000) is how much of
    the chain is kept; the first sync of mainnet takes days.
  - The backup holds the database, BTCPay's and NBXplorer's folders: stores, invoices,
    wallet keys. Not the chain.
- Run by hand on a test machine in regtest, wired as the module does: the admin was
  made, a store, a wallet and an invoice came from the API with the admin's login, a
  payment from the test node settled the invoice, a point-of-sale page opened without
  a login. Not tried: mainnet (the sync), the hidden service, Lightning (not part of it).

## 0.41.1 — Jabber answers on the VPN

- xmpp: the server shares the WireGuard server's network, as the master's reverse proxy
  does. In 0.41.0 it stood beside it, and a device on the VPN was refused at the
  master's address (found by the first login through a fleet). For a public name the
  WireGuard server's container publishes 5222 and 5269.

## 0.41.0 — Jabber

- **A new module, `xmpp`**, for a master: Prosody, a Jabber (XMPP) server. Chats, group
  rooms (`rooms.<name>`), files, and message history that a new device shows.
  - By default at `chat.<hostname>`, a mesh name: for people on the VPN, with the fleet
    CA's certificate, no other server reached.
  - With `xmpp_domain: chat.example.org` (a public name that points at the master): open
    to the Internet on 5222 and 5269, Let's Encrypt's certificate from the reverse
    proxy, and people on other servers can be written to.
  - The admin's account is made at the first start with the password of the settings.
    Nobody else can register: the admin invites people from a Jabber app, and each
    makes an account with a password of their own.
  - A renewed certificate is loaded within the hour.
- Run by hand on a test machine with the module's files: it starts, its own check
  passes, the admin logs in with the right password and not with a wrong one. Not
  tried: a public name (it needs one in DNS), a client app, rooms and files.

## 0.40.0 — game servers

- **A new module, `games`**: game servers for the people on a network. `servers` lists
  them by name, each with its game:

  ```yaml
  games:
    eula: true                      # Minecraft's licence
    servers:
      survival: { game: minecraft, memory: 4G, name: Our world }
      doom: { game: zandronum }
      lab: { game: abiotic-factor, port: 7800, password: "..." }
  ```

  Every server is one container with one folder (`kn-games/<server>`, backed up; what
  a game downloads goes to `kn-games-files/<server>`, which is not). Its ports open on
  the machine's address at home and, for the VPN, at its mesh address. `port` moves a
  server whose usual port is taken; its other ports move with it.
- The catalog knows Minecraft (Java and Bedrock), Enshrouded, Abiotic Factor, Zandronum,
  Valheim, Factorio, Satisfactory, Palworld and Terraria, each with the image, the ports
  and the settings its image documents. `catalog` takes more. Run and seen working on a
  test machine: Minecraft (a status query answered) and Zandronum (with Freedoom, which
  is put into the server's folder by hand). The others are not tried here.
- For modules: a `firewall` rule and a `bind_mounts` path with `each` may come out as
  several; `x is match(pattern)` in `validate`.

## 0.39.0 — Nextcloud survives a power cut, and a status page

- **cloud: the database's settings come back after a power cut.** Nextcloud's database
  image rewrites `postgresql.conf` at every start without syncing it. A power cut in
  the seconds after leaves the file empty; the database then listens on 127.0.0.1
  only, Nextcloud waits for it for ever, and every container says it is healthy. Seen
  on a test machine after power-cut drills. The database container now starts through
  `kiwi-start.sh`, which puts the image's own sample back when the file has lost its
  settings, and then runs the image's start script as before.
- **control: `status.<hostname>`**, a site of the control part that is no admin page:
  whatever is asked for there, the control part is asked for `/status` and nothing
  else. For kiwi-server's status page, which needs no login. `status_page: false`
  switches it off, `status_hostname` names it.
- A module's `urls:` entry that renders empty is left out.

## 0.38.0 — admin pages, and every app

- A module's site can be an admin page (`admin: true` in its `nginx:` block): the
  control page, Portainer, Pi-hole, the WireGuard page, the backup server and the cache
  are. `Renderer.admin_names` lists them for a machine; kiwi-server refuses them to VPN
  groups and linked networks that were not given the admin pages.
- vpn-server: `reach: [apps]` gives a group the web pages of every node and nothing else
  of them: no SSH, no other port. A new default group `family` has it.
- The `admin` switch of a group now reads: the admin pages of the master and of every
  node.

## 0.37.0 — git hosting

- New module `git`: Forgejo for a node, at `git.<hostname>` behind the reverse proxy,
  with SQLite and no second container. Its admin (`admin_user`, `admin_password`) exists
  after the first start without a person; a password changed in the settings reaches
  Forgejo at the next start. Sign-up is off and a sign-in is needed to see anything
  (`registration`, `private`); no calls to Gravatar or a CDN.
- Git over SSH on a port of its own (`ssh_port`, 2223; `0` switches it off and leaves
  HTTPS). A VPN group reaches it with `<node>:2223` in `kiwi-server access`.
- The image is `codeberg.org/forgejo/forgejo:15-rootless`: the long-term release, run as
  the stack's user.
- A firewall rule of a module that comes out empty is left out (a port that is switched
  off).

## 0.36.1 — the proxy starts with a hidden service

- reverse-proxy: with a hidden service, nginx did not start
  (`could not build server_names_hash`): a `.onion` name is 62 characters, more than its
  table of names takes by default. The table is made bigger when a machine has hidden
  services. Found on the first real machine.

## 0.36.0 — hidden services

- New module `onion`: sites of a machine as Tor hidden services, for people who are not
  on the VPN. `services` names them (`git: {}` for anyone with the address,
  `cloud: { clients: [anna] }` for named keys only); kiwi-server fills in the keys and
  addresses, which derive from the fleet's seed.
- Tor shares the VPN client's network: what it sends goes through the mesh and leaves at
  the master, through its VPN exit or from its own address. It never leaves through a
  home connection. Without a VPN client on a node it gets no network at all.
- reverse-proxy: `onion`, site name -> address. Each such site gets one more server on
  port 8043, which is not published. The service hears its usual name and https, so it
  does not send a stranger to a name only the VPN knows; the allow lists and shut-out
  rules for the mesh do not apply there.

## 0.35.1 — the control page stays shut for who was not given it

- reverse-proxy: a site with allow and deny lines of its own (the control page: the mesh,
  `allow_from`) ignored the lines that shut out a federation partner or a limited VPN
  group. nginx takes such lines from one level only. A partner or a group that was given
  another service of the same node could open the control page's login. The shut-out
  lines are now repeated where the site has its own, before them. Found by kiwi-server's
  access drill, with real VPN clients.

## 0.35.0 — a VPN group reaches one service or one port of a node

- vpn-server: a group's `reach` takes what a federation partner's `share` takes. Beside
  `all`, `nodes`, a node's name and an address: `cloud.papaya` (that service's web
  address only) and `papaya:22` (that port only). A name that is not in the fleet is
  left out and said in the script, not handed to iptables.
- reverse-proxy: `access`, filled in by kiwi-server. A group that reaches a node for
  some services only is refused at the node's other names: all of a node's services
  share one address and port, so the master's firewall alone cannot tell them apart.

## 0.34.0 — a network leaves to the internet through its partner, over the link

- vpn-server: two keys in a federation partner's entry. `exit: true` makes that partner
  this network's way to the internet: what the clients send there goes over the
  federation link (`wg-fed`) and comes out at the partner's master. `internet: true` on
  the other side lets the partner out, to the internet only, never to a private
  address. The partner sees the entry master, not its clients. With the link down the
  clients have no internet: they do not fall back to the master's own connection.
- This is multi-hop between two networks without the entry master being a client of the
  exit master's VPN server: no VPN client container, no second tunnel, no login there.

## 0.33.2 — an empty blocklist database is made anew

- dns: a first start without names can leave Pi-hole a database file with nothing in
  it, and its own fetch cannot build on that (seen on an Odroid). The hourly look
  removes an empty file before it fetches.

## 0.33.1 — the ad blocker blocks

- dns: Pi-hole fetches its blocklist when its container starts, before it can resolve a
  name itself. On every machine whose own lookups go through that Pi-hole the fetch
  failed and the list stayed empty: three test machines answered names for two weeks
  and blocked nothing. A timer now looks at the list soon after every start and once an
  hour, and fetches an empty one again (`kn-pihole-blocklist.timer`).

## 0.33.0 — a module says how to log in to it

- `logins:` in `module.yaml`: what a person types to get into a module's service. Each
  entry has a `label`, and as needed a `site` or an `address`, a `path`, a `user` (a
  literal or Jinja over the settings), the `password` (the key of the secret setting
  that holds it), a `note` and a `when`. Published with the schema, so kiwi-server can
  list every login of a machine. docs/development.md.
- Declared for cloud, opencloud, paperless, portainer, dns (Pi-hole), downloader
  (Transmission, JDownloader), sftp, vault, vpn-server (wg-easy), immich and control.
- An nginx server of a module may carry a `site:` name, for a module with several.

## 0.32.3 — the gateway keeps its clients inside the VPN, whatever happens to its rules

- gateway: a kill switch. What a LAN client sends is never forwarded back out of the
  card it came in on. Before, when the routing rule (table 128) was lost, the gateway
  became a plain router and its clients' traffic left by the home's own connection.
  Seen on an Odroid: systemd-networkd drops rules it did not make when it sets the
  card up anew.
- gateway: `kn-gateway.service` now stays running and looks at the rule, the routes
  and the kill switch twice a minute, and puts back what is gone. A v1 gateway needed
  its services restarted by hand for this.

## 0.32.2 — a file behind a link is written where the link points

- `util.write_bytes` (and `write_text`) follow a link: a control node's fleet file is a
  link into memory, and writing it used to put a plain copy on the disk beside it.
- control: `ram_mb` is 2048 by default (was 256), so install media made on the page fit
  in memory until they are fetched. It is a limit, not a reservation.

## 0.32.1 — a docs/ folder, and a short README

- `docs/`: install, the commands, the machine file, modules and presets, the bundle,
  development. kiwi-network.eu shows these pages from the next release on.
- The README is the short front page now. Its section on hubs said a node hosts a hub
  through a `hub` preset; there is no such preset, and the `hub` and `nostr-relay`
  modules run on a master.

## 0.32.0 — Nextcloud's database password can be changed where it lives

- `rotate:` takes a list of steps, run in order, and `name:` for a container with a name of
  its own (`in:` stays the name after the prefix).
- cloud: `database_password` has two steps: Nextcloud's `config.php` through occ (skipped
  when it already holds the new value), then the roles `oc_nextcloud` and `nextcloud` in
  its Postgres.

## 0.31.1 — the backup server password follows a new seed

- backup: `server_password` is `rotate: restart`. The machine reads it from its restic
  environment at every backup, and its backup servers keep only a hash that derives from
  the same value: both sides follow a new seed at their next apply. Between the two
  applies that machine's backups to that server are refused.

## 0.31.0 — a generated secret can say how it is changed where it lives

- `rotate: { in: <container>, run: <command with $NEW> }` on a generated secret: the
  command runs in that container of the module and sets the new value there, before the
  containers restart with it. kiwi-server `rotate seed` uses it.
- First: the database passwords of Immich and Paperless (`ALTER USER` in their Postgres).

## 0.30.1 — the bundle names the seed it follows

- The bundle's manifest carries `KS_SEED_FROM` (the id of the seed this one replaced) when
  the secrets provider knows one: kiwi-stack 0.8.0 takes a changed seed from that one only.

## 0.30.0 — which generated secrets may change with a restart

- A generated secret can say `rotate: restart`: its containers read it at every start and
  keep it nowhere else, so kiwi-server can replace it when the fleet's seed is replaced
  (kiwi-server `rotate seed`). Marked, after reading what each image does with it: cloud
  (redis_password, onlyoffice_secret, imaginary_secret, whiteboard_secret,
  talk_internal_secret), dns (pihole_password), paperless (secret_key), sftp
  (sftp_password), downloader (transmission_password), vpn-server (wg_password).
- Not marked, so kept as they are: database and admin passwords, the backup passwords,
  Talk's TURN and signaling secrets (Nextcloud adds them once and keeps them), the
  federation secret.

## 0.29.1 — the control node keeps its secrets in RAM

- control: the opened store, job logs and renders live in a tmpfs (`ram_mb`); the disk holds
  the fleet file and the encrypted store only. It waits for the first `control push` instead
  of restarting in a loop.

## 0.29.0 — the control node, SSH over the mesh

- New module `control`: kiwi-server with web pages at `control.<hostname>`, open to the mesh
  only (`allow_from` adds one more network). Its data directory is the fleet directory, and it
  is in the node's backup.
- vpn-client `mesh_ssh` (on by default, nodes only): port 22 of a node's mesh address goes to
  the machine's sshd (`ssh_port` follows `admin.ssh_port`), so the control node and admin
  devices reach every node from anywhere in the VPN.

## 0.28.1 — our own images for arm64 too

- The tang and strfry images are built for linux/amd64 and linux/arm64 (tang 15-kiwi3,
  strfry 1.1.3-kiwi2): a Tang ring or a relay on an Odroid or another arm64 board. Every other
  image the modules use already comes for both.

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
