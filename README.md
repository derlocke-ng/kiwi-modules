# kiwi-modules

The kiwi-network's modules and their renderer: one machine file in, a stack
bundle out. The bundle is what [kiwi-stack](https://github.com/derlocke-ng/kiwi-stack)
installs on the machine (`sudo kiwi-stack apply DIR`): podman quadlets (or a
compose file on docker), the configs, the host units, and `stack.sh`, the
manifest that names them all.

[kiwi-server](https://github.com/derlocke-ng/kiwi-server) uses the same
package for a whole fleet (ISOs, enrolment, the CA, apply over SSH). This
repository is for a stack on one machine without any of that: a node you set
up by hand, a module you develop, a machine that renders its own stack.

```sh
git clone https://github.com/derlocke-ng/kiwi-modules
cd kiwi-modules
./install.sh install                       # ~/.local/bin/kiwi-modules (KIWI_SCOPE=system: /usr/local)
mkdir -p sh3/secrets && head -c 32 /dev/urandom > sh3/secrets/seed
cp examples/sh3.yaml sh3/                  # edit: passwords, TLS files, the WireGuard config
kiwi-modules render sh3/sh3.yaml -o sh3/sh3.bundle
scp -r sh3/sh3.bundle sh3:/tmp/ && ssh sh3 sudo kiwi-stack apply /tmp/sh3.bundle
```

It needs python3 with PyYAML and Jinja2 (`python3-yaml python3-jinja2` on
Debian, `python3-pyyaml python3-jinja2` on Fedora). kiwi-updater installs it
from `kiwi.manifest`. `python3 -m kiwimodules` from a checkout works too
(`PYTHONPATH=lib`).

## The machine file

```yaml
name: sh3                       # hostname: name.domain unless given
domain: home
target: ucore                   # coreos | ucore | debian — what the stack runs on
timezone: Europe/Berlin
admin: { user: core }           # the service user default
role: node                      # the profile: master, or node with a preset
node:
  preset: cloud                 # gateway | cloud | minimal; or modules: [...] outright
  vpn_ip: 10.8.0.25             # or taken from the WireGuard config's Address
  cloud: { admin_password: ... }
  reverse-proxy: { tls_fullchain: secrets/sh3-fullchain.pem, tls_privkey: secrets/sh3-privkey.pem }
dns_records: [[10.8.0.1, gate.home], [10.8.0.25, sh3.home]]   # optional: the network's names
master_ip: 10.8.0.1             # optional: the DNS upstream and the mesh route
ca_cert: ca.pem                 # optional: the network's CA, trusted inside the containers
seed: secrets/seed              # 32 random bytes — generated secrets derive from it
```

Paths are relative to the file. `secrets/<hostname>.conf` is the WireGuard
client config the vpn-client takes when `vpn-client.wireguard_config` is not
set (the master's wg-easy exports one per client). The profile's settings
(`docker_dir`, `service_user`, `runtime: podman|docker`, `auto_update`, …)
and every module's settings go under the `role:` name; `kiwi-modules
modules -v` lists them all with their defaults, `kiwi-modules profiles` the
profiles and presets.

**Secrets.** A secret-typed setting left empty is derived from the seed, the
hostname, the module and the key, so a render is repeatable and a backup of
the seed is a backup of every generated password. The derivation is frozen
(tests/test_render.py pins a value); kiwi-server derives the same values
from the same seed, so a machine first set up from a fleet keeps its
secrets when rendered from a machine file, and the other way round. Without
a seed every secret must be given. The bundle carries `KS_SEED_ID`;
kiwi-stack refuses to apply a bundle from another seed onto a machine whose
databases know the old passwords.

## What a bundle is

```
sh3.bundle/
  stack.sh                 # bash manifest: KS_HOST…, KS_STACK_MODULES, _QUADLETS, _IMAGES, _PORTS, _FILES …
  docker-compose.yml       # the stack (used as is on docker; the source of the quadlets on podman)
  quadlets/*.container|*.network|kiwi-stack.target   # podman: one unit per service, '# kiwi-server stack' marker
  host-units/*.service|*.timer                       # units a module wants on the host (gateway routing, …)
  kiwi/env/<service>.env   # the secrets, root-only, EnvironmentFile= of the units
  kiwi/ca/kiwiCA.crt       # the network's CA when given
  <prefix>-<module>/…      # each module's config files (nginx.conf, wg0.conf, torrc …)
```

`stack.sh` is the contract between the two repositories: kiwi-stack sources
it and reads only `KS_*` variables. Every file's mode is in `KS_STACK_FILES`
(`path:0600` for the secrets); directories, ports, sysctls, kernel modules,
images and the URLs to print after the start are lists of their own.

## Modules and profiles

`modules/<name>/module.yaml` declares a module's settings, its compose
fragment and templates, the ports and names it announces, its dependencies;
`profiles/<name>/role.yaml` is a stack shape (module list or presets, module
defaults). The formats are kiwi-server's, documented in its
[docs/modules.md](https://github.com/derlocke-ng/kiwi-server/blob/main/docs/modules.md)
(the context a template sees, every key, how to add a module); the directory
layout here (`lib/kiwimodules`, `modules/`, `profiles/`) is what the package
expects around itself. `KIWI_MODULES_HOME` points it at another modules
directory, `KIWI_MODULES_PROFILES` at other profiles.

## Status

0.2.0: the renderer as kiwi-server 2.7.0 has it, with the fixes of the first
hardware round (CHANGELOG.md); the stacks it renders run on a master and two
nodes. tests/golden/sh3 is kiwi-server's golden bundle, matched byte for
byte. kiwi-server is still the place the modules and the renderer are
developed; its `tools/split-sync.sh` copies them here and checks for drift,
until this repository is vendored back.

## License

GPL-3.0-or-later.
