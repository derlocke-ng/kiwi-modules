# Modules and presets

A *module* is one service with everything it needs: its containers, its
configuration files, the ports and names it uses, and its settings. A
*profile* is the shape of a whole machine. A *preset* is a ready-made list of
modules inside the `node` profile.

`kiwi-modules modules -v` prints the settings of every module with their
defaults. That output is the reference; this page says what each module is
for.

## Profiles

| Profile | What it is |
|---|---|
| `master` | The entry point of the network: the WireGuard server, a second VPN hop through a commercial provider, Pi-hole as DNS and a Tor proxy for the mesh. |
| `node` | A machine behind the VPN client. It takes a preset or any list of modules. |
| `bare` | Only the admin user, SSH and automatic updates. No stack. |

The profiles `node-gw` and `node-cloud` are the presets `gateway` and `cloud`
as profiles of their own. They are kept for files that already use them.

## Presets of the node profile

| Preset | Modules |
|---|---|
| `gateway` | `vpn-client`, `dns`, `dhcp-relay`, `reverse-proxy`, `downloader`, `gateway`, `portainer`, `sftp` |
| `cloud` | `vpn-client`, `reverse-proxy`, `cloud`, `vault`, `portainer` |
| `minimal` | `vpn-client`, `reverse-proxy` |

## Modules

"Runs on" says which profile may use the module.

| Module | Runs on | What it does |
|---|---|---|
| `vpn-server` | master | wg-easy, the WireGuard server that every client and node connects to. |
| `vpn-client` | master, node | gluetun, the tunnel of the machine: to the master on a node, to a commercial VPN on the master. |
| `dns` | master, node | Pi-hole, a resolver that blocks advertising, for the mesh or the LAN. |
| `reverse-proxy` | master, node | nginx with TLS, with one address per service that the other modules announce. |
| `tor` | master, node | A Tor SOCKS5 proxy for the clients in the mesh. |
| `fail2ban` | master, node | Blocks addresses that keep failing to log in over SSH. |
| `portainer` | master, node | Portainer CE, a web page for the containers on the machine. |
| `backup` | master, node | Saves the machine's data with restic, encrypted, to a node that runs `backup-server`, every night. |
| `backup-server` | node | Stores the backups of other machines: restic's REST server behind the reverse proxy. |
| `cache` | node | Keeps container images and Debian packages that the machines on the LAN would each fetch from the Internet. |
| `cloud` | node | Nextcloud, from the containers of the AIO project without its master container. |
| `vault` | node | Vaultwarden, a password manager that works with the Bitwarden apps. |
| `opencloud` | node | OpenCloud, files and sharing. |
| `immich` | node | Immich, photos and videos from your phone. |
| `paperless` | node | Paperless-ngx, scanned documents with text recognition and search. |
| `downloader` | node | Transmission and JDownloader. They share the VPN client's network, so they have no connection without the tunnel. |
| `sftp` | node | An SFTP server on its own port, to fetch downloads from the LAN or the mesh. |
| `gateway` | node | Routes LAN clients that use this machine as their gateway through the VPN client. |
| `dhcp-relay` | node | Passes the LAN's DHCP requests on to Pi-hole, so that Pi-hole can be the LAN's DHCP server. |
| `tang` | node | Tang servers, which let the encrypted machines of the network unlock their disks at boot without anyone typing a key. |
| `control` | node | The control node: kiwi-server with web pages, reachable from the mesh. |
| `nostr-relay` | master | strfry, a nostr relay, behind the reverse proxy. A hub keeps its data on it. |
| `hub` | master | A hub built on kiwi-framework (Armory or your own fork) as a container behind the reverse proxy. |

## A hub

A master can run a hub: add `nostr-relay` and `hub` to its modules.
`examples/hub.yaml` in the repository shows it. As it comes, the hub is
private: its relay is reachable through the mesh only. The settings
`public_relays` and `public_mounts` of the `hub` module open a public area,
for example a chat on public relays.

## Write your own module

A module is a directory `modules/<name>/` with a `module.yaml` and its
templates. The format is the same as in kiwi-server and is described there:
[Modules](https://kiwi-network.eu/docs/server/kiwi-server/modules/).
