# The machine file

The machine file is a YAML file that describes one machine: its name, the
system it runs, and the modules it gets with their settings. `kiwi-modules
render` reads it and writes the bundle. This page lists every key.

```yaml
name: sh3
domain: home
target: ucore
timezone: Europe/Berlin
admin: { user: core }
role: node
node:
  preset: cloud
  vpn_ip: 10.8.0.25
  cloud: { collabora: true }
  reverse-proxy: { tls_fullchain: secrets/sh3-fullchain.pem, tls_privkey: secrets/sh3-privkey.pem }
dns_records: [[10.8.0.1, gate.home], [10.8.0.25, sh3.home]]
master_ip: 10.8.0.1
ca_cert: ca.pem
seed: secrets/seed
```

## The keys

| Key | Default | What it means |
|---|---|---|
| `name` | required | The machine's short name. |
| `hostname` | `name.domain` | The machine's full name. |
| `domain` | `home` | The domain of the network's names. |
| `target` | `ucore` | The system the stack runs on: `coreos`, `ucore` or `debian`. |
| `timezone` | `UTC` | The time zone for the containers. |
| `admin` | `{ user: core }` | The user the services run as, unless the profile sets another. |
| `role` | required | The profile: `master`, `node` or `bare`. |
| `dns_records` | none | The network's names as pairs of address and name, for the DNS module. |
| `lan_addresses` | none | For nodes on this machine's own LAN: the mesh address and the LAN address of each, so that traffic between them stays on the LAN. |
| `master_ip` | none | The master's address in the mesh. Nodes use it as the upstream for DNS and as the route into the mesh. |
| `ca_cert` | none | The certificate of the network's own certificate authority. The containers trust it. |
| `seed` | none | A file with 32 random bytes. Passwords you leave out are derived from it. |

A *mesh* is the private WireGuard network that connects the machines. The
*master* is the one machine that is reachable from the Internet; a *node* is a
machine at home or in the office that runs your services.

## The settings of the role

Everything else goes into a block named after the role, here `node:`.

- `preset:` picks one of the node's module lists, or `modules: [...]` names
  the modules one by one. [Modules and presets](modules.md) lists both.
- The profile's own settings stand next to it, for example `vpn_ip`,
  `docker_dir`, `service_user`, `runtime` (`podman` or `docker`) and
  `auto_update`.
- Each module's settings go into a block named after the module, for example
  `cloud:` or `reverse-proxy:`.

`kiwi-modules modules -v` prints every setting of every module with its
default. `kiwi-modules profiles` prints the profiles and presets.

## Paths

Paths in the machine file are relative to the file. The VPN client looks for
the WireGuard configuration of the machine at `secrets/<hostname>.conf` when
`vpn-client.wireguard_config` is not set. On a network managed with wg-easy,
the master exports one such file per client.

## Generated secrets and the seed

A setting of the type *secret* (a password, a signing key) that you leave
empty is generated. kiwi-modules derives it from the seed, the hostname, the
module and the setting's name. This has three consequences.

- A render is repeatable: the same machine file and the same seed give the
  same passwords every time.
- A backup of the seed is a backup of every generated password.
- Without a seed you have to give every secret yourself.

kiwi-server derives the same values from the same seed. A machine that was
first set up from a fleet keeps its passwords when you later render it from a
machine file, and the other way round.

The bundle carries a short name of the seed (`KS_SEED_ID`). kiwi-stack refuses
a bundle from another seed, because the running databases know the passwords
of the old one.
