# Modules and profiles

A *module* is one service, or a small group of containers that belong
together, such as Nextcloud with its database. A *profile* says what a
machine is: a master or a node, with a list of modules to start from. A
*preset* is one of several named module lists inside a profile. This page
lists all of them as of v0.28.1. `kiwi-modules modules -v` shows every
setting with its default, and each setting has a help text in its module's
`module.yaml`.

Two words come up throughout. The *master* is the one machine of the network
that is reachable from the Internet; it runs the WireGuard server that every
device connects to. The *nodes* are the machines at home or in the office
that run your services; each one connects to the master through its own VPN
client. Together they form the *mesh*, the private WireGuard network.

## The modules

| Module | What it is | Runs on | Requires |
|---|---|---|---|
| `vpn-server` | wg-easy, the WireGuard server every device and node connects to. Its traffic to the Internet goes on through the master's VPN client. | master | none |
| `vpn-client` | gluetun, the VPN tunnel. On a node it leads to the master; on the master it leads to a commercial VPN provider. | both | none |
| `dns` | Pi-hole 6, a DNS server that blocks ads for the mesh or the LAN and answers for the network's own names. | both | none |
| `tor` | A Tor SOCKS5 proxy for devices in the mesh, limited to the countries you set. | both | none |
| `reverse-proxy` | nginx with TLS. It serves every service the other modules announce under its own name. | both | none |
| `fail2ban` | Bans addresses that keep failing to log in over SSH and limits how fast one address may open SSH connections. | both | none |
| `gateway` | Policy routing on the host: LAN devices that use this node as their gateway reach the Internet through the VPN client. | node | `vpn-client` |
| `dhcp-relay` | Passes the LAN's DHCP requests to Pi-hole, so Pi-hole can be the LAN's DHCP server. | node | `dns` |
| `cache` | A pull-through mirror for container images and a caching proxy for Debian packages, for the other machines on the same LAN. | node | `reverse-proxy` |
| `cloud` | Nextcloud from the AIO project's containers, without the AIO master container, so it needs no docker socket. | node | `vpn-client`, `reverse-proxy` |
| `vault` | Vaultwarden, a password manager that works with the Bitwarden apps. | node | `vpn-client`, `reverse-proxy` |
| `downloader` | Transmission and JDownloader inside the VPN client's network namespace, so they transfer nothing while the tunnel is down. | node | `vpn-client` |
| `sftp` | An SFTP server on its own port (`2224` by default), for fetching downloads. | node | none |
| `portainer` | Portainer CE, a web interface for the machine's containers. | both | none |
| `opencloud` | OpenCloud, for files and sharing (to try out). | node | `vpn-client`, `reverse-proxy` |
| `immich` | Immich, for photos and videos (to try out). | node | `vpn-client`, `reverse-proxy` |
| `paperless` | Paperless-ngx, for scanned documents with OCR (to try out). | node | `vpn-client`, `reverse-proxy` |
| `nostr-relay` | strfry, the nostr relay a hub keeps its events on. | master | `reverse-proxy` |
| `hub` | A hub built with kiwi-framework, Armory by default, as a container. | master | `reverse-proxy` |
| `backup` | Backs up the machine's data with restic, encrypted, to one or more nodes that run `backup-server`, every night and on demand. | both | none |
| `backup-server` | restic's REST server. Each machine reaches only its own repository and can add to it but not delete from it. | node | `vpn-client`, `reverse-proxy` |
| `tang` | Tang servers, which let machines with encrypted disks unlock them at boot without a person typing a key. | node | none |

A *network namespace* is a container's own set of network interfaces and
ports. When one container shares another's namespace, it uses that
container's network and has none of its own.

## Names

Every module behind the reverse proxy announces a name for its service, made
from a short word and the machine's hostname. On papaya.home these are, for
example, `cloud.papaya.home`, `vault.papaya.home`, `portainer.papaya.home`,
`pihole.papaya.home`, `dl.papaya.home` and `jd.papaya.home` (Transmission
and JDownloader), `backup.papaya.home` and `cache.papaya.home`. On a master
they include `wg.<hostname>` (wg-easy), `relay.<hostname>` and
`hub.<hostname>`. Most modules have a setting to choose another name.

## Profiles

| Profile | What it is |
|---|---|
| `master` | The master: `vpn-client`, `vpn-server`, `dns`, `tor`, `reverse-proxy` and `fail2ban`. The VPN client leads to Mullvad by default. Pi-hole, Tor and nginx share the WireGuard server's network namespace, so devices in the mesh reach them at the master's mesh address. |
| `node` | A node, with a preset or a module list of your own. |
| `node-gw` | The same as `node` with the `gateway` preset. It is kept for older files. |
| `node-cloud` | The same as `node` with the `cloud` preset. It is kept for older files. |
| `bare` | A machine without a stack. kiwi-server uses it; `render` refuses it because there is nothing to render. |

The profiles are in
[profiles/](https://github.com/derlocke-ng/kiwi-modules/tree/main/profiles).
Their format is the one kiwi-server uses for its roles.

## Presets of the node profile

| Preset | Modules |
|---|---|
| `gateway` (the default) | `vpn-client`, `dns`, `dhcp-relay`, `reverse-proxy`, `downloader`, `gateway`, `portainer`, `sftp`. The node is the LAN's DNS server, and with the `gateway` module its router into the VPN. |
| `cloud` | `vpn-client`, `reverse-proxy`, `cloud`, `vault`, `portainer` |
| `minimal` | `vpn-client`, `reverse-proxy`, for a module list you build yourself |

To run modules that are in no preset, such as `backup`, `cache`, `opencloud`,
`immich` or `paperless`, list the whole set in `modules:`:

```yaml
role: node
node:
  modules: [vpn-client, reverse-proxy, cloud, vault, portainer, backup]
  backup: { servers: [https://backup.lychee.home] }
```

## A hub on a master

A *hub* is a community's own site in the browser, built with
[kiwi-framework](https://kiwi-network.eu/docs/people/apps/). The `hub` and
`nostr-relay` modules run one on a master. Add both to the master's
`modules:`, as
[examples/hub.yaml](https://github.com/derlocke-ng/kiwi-modules/blob/main/examples/hub.yaml)
does.

As it comes, the hub is private. It is reachable at `hub.<hostname>` from
inside the mesh only, and it uses the relay at `relay.<hostname>` on the same
master. Two settings of the `hub` module open a public area:
`public_relays` names relays on the Internet, and `public_mounts` names the
parts of the hub that use them, so people inside can talk to people outside.
`examples/hub.yaml` is such a semi-public hub. A fully public hub names
public relays in `relays`, sets `relays_locked: false` and
`require_hub: false`, and uses
`reverse-proxy.public` with a public name in `hub_domain`.
[Running your own hub](https://kiwi-network.eu/docs/people/hubs/) explains
the three kinds.

## The three apps to try out

`opencloud`, `immich` and `paperless` are marked "to try out": they work, but
they are not proven yet. Each runs at its own name behind the
reverse proxy and has a setting for where its data lives, so you can put it
on a big disk. `immich.machine_learning: false` leaves out the container that
needs the most memory, and `paperless.office_documents: false` leaves out
Tika and Gotenberg.
