# kiwi-modules

kiwi-modules turns the description of one machine into the files that run its
services. You write a machine file that names the modules the machine gets (a
VPN client, a reverse proxy, Nextcloud and so on). kiwi-modules renders it
into a bundle: container units, configuration files and a list of them all.
[kiwi-stack](https://github.com/derlocke-ng/kiwi-stack) installs the bundle on
the machine.

It is part of the network side of Kiwi Network. Use it for a single machine
that you set up by hand, or to develop a module.
[kiwi-server](https://github.com/derlocke-ng/kiwi-server) uses the same
package to manage a whole fleet of machines.

- Runs on: Linux with Python 3; CI tests it on Ubuntu
- Needs: PyYAML and Jinja2
- License: GPL-3.0-or-later

## Install

```bash
git clone https://github.com/derlocke-ng/kiwi-modules
cd kiwi-modules
./install.sh install
```

The installer copies the tool to `~/.local` and does not need root. kiwi-updater
installs it the same way, from the `kiwi.manifest` file.

## Quick start

```bash
mkdir -p sh3/secrets && head -c 32 /dev/urandom > sh3/secrets/seed
cp examples/sh3.yaml sh3/          # then edit it: TLS files, the WireGuard configuration
kiwi-modules render sh3/sh3.yaml -o sh3/sh3.bundle
scp -r sh3/sh3.bundle sh3:/tmp/ && ssh sh3 sudo kiwi-stack apply /tmp/sh3.bundle
```

This renders the stack of a node called `sh3` and installs it there.
`kiwi-modules modules -v` lists every module and setting you can use.

## Documentation

| Page | What it covers |
|---|---|
| [Install](docs/install.md) | what it needs, install, update, uninstall |
| [Using kiwi-modules](docs/usage.md) | the commands, from a machine file to a running stack |
| [The machine file](docs/machine-file.md) | every key, paths, generated secrets and the seed |
| [Modules and presets](docs/modules.md) | what each module does and where it can run |
| [The bundle](docs/bundle.md) | the files a render writes |
| [Development](docs/development.md) | tests, CI, releases |

The same pages are on [kiwi-network.eu](https://kiwi-network.eu/docs/server/modules/).

## License

GPL-3.0-or-later; see [LICENSE](LICENSE).
