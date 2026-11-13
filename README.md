# kiwi-modules

kiwi-modules holds the modules of Kiwi Network and the renderer that turns
them into a running configuration. A *module* is one service a machine runs,
for example the WireGuard server, Pi-hole, the reverse proxy or Nextcloud. You
describe one machine in a short YAML file, the *machine file*, and
`kiwi-modules render` writes a *stack bundle*: a directory with podman quadlets
(one systemd unit per container), a compose file, the configuration files, the
systemd units for the host and `stack.sh`, a manifest that lists all of them.
[kiwi-stack](https://kiwi-network.eu/docs/server/single/) then installs the
bundle on the machine.

kiwi-modules is part of the network side of Kiwi Network.
[kiwi-server](https://kiwi-network.eu/docs/server/) uses the same modules and
renderer for a whole fleet and adds install images, enrolment and a
certificate authority. You use kiwi-modules on its own when you want a stack
on one machine without all of that: a node you set up by hand, a module you
are developing, or a machine that renders its own stack. If you write modules,
this is the repository they live in.

- Latest release: **v0.28.1**
- Runs on: any Linux machine with Python 3, PyYAML and Jinja2; CI runs it on
  Ubuntu. The stacks it renders are for Fedora CoreOS, uCore and Debian.
- License: GPL-3.0-or-later

## Install

kiwi-modules needs Python 3 with PyYAML and Jinja2: `python3-yaml
python3-jinja2` on Debian and Ubuntu, `python3-pyyaml python3-jinja2` on
Fedora.

```bash
git clone https://github.com/derlocke-ng/kiwi-modules
cd kiwi-modules
./install.sh install
```

The installer copies the package, the modules and the profiles to
`~/.local/lib/kiwi-modules` and the `kiwi-modules` command to `~/.local/bin`.
It needs no root. You can also run `bin/kiwi-modules` straight from the
checkout. [Install](docs/install.md) has the other options.

## Quick start

These commands render the example cloud node `sh3`, which runs Nextcloud,
Vaultwarden and Portainer behind the VPN client and the reverse proxy:

```bash
mkdir -p sh3/secrets && head -c 32 /dev/urandom > sh3/secrets/seed
cp examples/sh3.yaml sh3/
# put next to it: secrets/sh3.home.conf (the node's WireGuard config),
# secrets/sh3-fullchain.pem and secrets/sh3-privkey.pem (TLS), ca.pem (your CA)
kiwi-modules render sh3/sh3.yaml -o sh3/sh3.bundle
scp -r sh3/sh3.bundle sh3:/tmp/ && ssh sh3 sudo kiwi-stack apply /tmp/sh3.bundle
```

The seed is 32 random bytes. Every password you leave out of the machine file
is derived from it, so the same file and seed always give the same bundle.
`kiwi-modules modules -v` lists every module and setting with its default.

## Documentation

| Page | What it covers |
|---|---|
| [Install](docs/install.md) | requirements, install, update and uninstall |
| [The machine file](docs/machine-file.md) | every key, the role block, secrets and the seed |
| [Render a machine](docs/render.md) | the commands, what the render checks, what the bundle contains |
| [Modules and profiles](docs/modules.md) | every module, the profiles and their presets |
| [Writing a module](docs/writing-a-module.md) | a new module from start to finish |
| [module.yaml reference](docs/module-yaml.md) | every key of `module.yaml` and the settings schema |
| [Templates](docs/templates.md) | what a template sees and what the renderer adds |
| [Development](docs/development.md) | tests, CI, releases and how kiwi-server carries this repository |

The same pages are on
[kiwi-network.eu](https://kiwi-network.eu/docs/server/modules/).

## License

GPL-3.0-or-later; see [LICENSE](LICENSE).
