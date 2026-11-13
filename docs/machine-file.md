# The machine file

The machine file describes one machine in YAML: its name, which *profile* it
follows (a master or a node), which modules it runs and how they are set. It
is the only input of `kiwi-modules render`. kiwi-server keeps the same
information for many machines in its fleet file; a machine file is the same
thing for a single machine.

## An example

This is a cloud node called papaya. It uses the node profile's `cloud`
preset, which brings the VPN client, the reverse proxy, Nextcloud, Vaultwarden
and Portainer.

```yaml
name: papaya                    # the machine's short name
domain: home                    # the full hostname is papaya.home
target: ucore                   # coreos, ucore or debian: what the stack runs on
timezone: Europe/Berlin
admin: { user: core }           # owns the stack's data unless service_user is set
role: node                      # the profile
node:                           # the role block: named after the role
  preset: cloud
  cloud: { collabora: true }    # settings of one module
  reverse-proxy:
    tls_fullchain: secrets/papaya-fullchain.pem
    tls_privkey: secrets/papaya-privkey.pem
dns_records:                    # the network's names (optional)
  - [10.8.0.1, sorbet.home]
  - [10.8.0.25, papaya.home]
  - [10.8.0.25, cloud.papaya.home]
master_ip: 10.8.0.1             # the master's address in the mesh (optional)
ca_cert: ca.pem                 # your network's CA certificate (optional)
seed: secrets/seed              # 32 random bytes for the generated passwords
```

[examples/](https://github.com/derlocke-ng/kiwi-modules/tree/main/examples)
holds three complete machine files: `sh3.yaml` (a cloud node), `master.yaml`
(a master) and `hub.yaml` (a master with a hub).

All paths in the file are relative to the folder the file is in. A path may
also be absolute or start with `~`.

## Top-level keys

| Key | Default | What it is |
|---|---|---|
| `name` | required | The machine's short name. |
| `role` | required | The profile: `master`, `node`, or the older `node-gw` and `node-cloud`. See [profiles](modules.md#profiles). |
| `domain` | `home` | The network's domain. Names under it are the network's own names. |
| `hostname` | `<name>.<domain>` | The full hostname. Service names are built from it, for example `cloud.papaya.home`. |
| `target` | `ucore` | What the stack runs on: `coreos`, `ucore` or `debian`. Settings that only apply to some targets use it. |
| `timezone` | `UTC` | The time zone the containers get. |
| `admin` | `{ user: core }` | The admin user. `admin.user` owns the stack's data unless `service_user` is set. `admin.ssh_port` (default `22`) is the port the fail2ban module watches. |
| `<role>` | `{}` | The role block: the stack settings, the module list and every module's settings. See below. |
| `dns_records` | none | The network's names as `[address, name]` pairs. See [Names and addresses](#names-and-addresses). |
| `lan_addresses` | none | For nodes on this machine's own LAN: mesh address to LAN address. |
| `master_ip` | none | The master's address in the mesh. A node's Pi-hole forwards to it, and the host routes the mesh through the VPN client. |
| `ca_cert` | none | A PEM file with your network's CA certificate. The containers that call other services over TLS trust it. The file must exist. |
| `seed` | none | A file with random bytes. Every generated secret is derived from it. See [Secrets and the seed](#secrets-and-the-seed). |

## The role block

The role block is a mapping named after the role, so `node:` for a node and
`master:` for a master. It holds three kinds of keys.

**Stack settings** apply to the whole stack. The most common ones:

| Setting | Default | What it does |
|---|---|---|
| `preset` | `gateway` | Node only. The module list to start from: `gateway`, `cloud` or `minimal`. |
| `modules` | the preset's or the profile's list | Replaces the module list. Required dependencies are added by themselves. |
| `vpn_ip` | from the WireGuard config | This machine's address in the mesh. |
| `docker_dir` | `/home/user/docker` | The stack directory on the machine. |
| `service_user` | the admin user | Owns the data directories the containers write to. |
| `runtime` | `podman` | `podman` renders quadlets, `docker` runs the compose file with docker compose. |
| `docker_subnet` | `172.64.0.0/24` on a master, `172.128.0.0/24` on a node | The stack's bridge network. |
| `wg_mtu` | `1376` | The MTU of the WireGuard tunnels. |
| `bridge_mtu` | `1500` | The MTU of the stack's bridge network. |
| `auto_update` | `registry` | `registry` lets the weekly update pull newer images of the same tag; `off` changes images only with an apply. |
| `variables` | `{}` | Extra values for your own templates, as `KEY: value`. |

`kiwi-modules profiles` lists the presets, and `kiwi-modules modules -v`
lists every module setting. The stack settings are defined in
[profiles/common/stack.yaml](https://github.com/derlocke-ng/kiwi-modules/blob/main/profiles/common/stack.yaml),
each with a help text that says what it is for.

**Module blocks** are mappings named after a module, such as `cloud:` or
`reverse-proxy:`. They hold that module's settings. Each module block may also
set `container_ip`, which gives the module a fixed address of your choice on
the stack network.

A module's settings are filled in from four places, each overriding the one
before:

1. the setting's default in the module's `module.yaml`,
2. a default the profile sets for that module (`module_defaults`),
3. a default the chosen preset sets for that module,
4. your module block.

**Anything else** in the role block is an error. If you name a module that is
not in the module list, the error says so and tells you to add it to
`modules:`. An unknown setting inside a module block is an error too, and the
message lists the settings the module knows.

## Secrets and the seed

Many settings are passwords or keys, for example `cloud.admin_password` or
`dns.pihole_password`. If you leave such a setting empty, kiwi-modules
derives its value from the seed, the machine's hostname, the module and the
setting's name. The same seed and machine file therefore always give the same
passwords, and a backup of the seed is a backup of every generated password.

Create a seed once and keep it safe:

```bash
mkdir -p secrets && head -c 32 /dev/urandom > secrets/seed
```

A seed shorter than 16 bytes is refused. Without a seed, every generated
setting must be given in the machine file, or the render stops and says which
one is missing.

The derivation is frozen: a test pins one derived value, because a change
would change every generated password of every machine. kiwi-server derives
the same values from the same seed. A machine first set up from a kiwi-server
fleet therefore keeps its passwords when you render it from a machine file,
and the other way round.

The bundle records which seed it came from as `KS_SEED_ID`, twelve hex digits
that name the seed without revealing it. kiwi-stack uses this to refuse a
bundle from another seed on a machine whose databases know the old passwords.

## Files the render reads

Settings of the type `file` name a file next to the machine file. The render
reads the file and writes its content into the bundle, where the module puts
it. Three of them matter for almost every machine:

- **The WireGuard config.** A node's VPN client needs the client config that
  the master's WireGuard server issued for it (`vpn-client.wireguard_config`).
  If you leave the setting empty, kiwi-modules uses
  `secrets/<hostname>.conf` when that file exists, for example
  `secrets/papaya.home.conf`. On a node, an empty `vpn_ip` is taken from the
  config's `Address` line. If both are set and disagree, the render prints a
  warning.
- **The TLS certificate and key** of the reverse proxy
  (`reverse-proxy.tls_fullchain` and `reverse-proxy.tls_privkey`), for
  `<hostname>` and `*.<hostname>`. kiwi-server issues these from its own
  certificate authority; kiwi-modules has none, so you provide both files.
  The render does not stop when they are missing, but nginx then has no
  certificate to start with.
- **The CA certificate** (`ca_cert`), if your network has a CA. It is written
  to `kiwi/ca/kiwiCA.crt` in the bundle.

## Names and addresses

`dns_records` lists the network's names, each as an address and a name. They
are used in three places:

- The dns module's Pi-hole answers for them (setting `dns.fleet_records`, on
  by default).
- They are written to the machine's `/etc/hosts`. The machine's own names
  point at `127.0.0.1` there.
- Inside the containers, the machine's own names point at the reverse proxy
  on the stack network, so a service can reach another service on the same
  machine by its name.

`lan_addresses` maps the mesh address of a node on the same LAN to its LAN
address, for example `{ 10.8.0.26: 192.168.1.26 }`. For those nodes the
machine's Pi-hole and `/etc/hosts` answer with the LAN address, so traffic
between two machines at home stays on the LAN instead of going through the
master.
