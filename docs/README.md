# kiwi-modules documentation

kiwi-modules turns the description of one machine into the files that run its
services. You write a *machine file* that says which *modules* the machine
gets (a VPN client, a reverse proxy, Nextcloud and so on). kiwi-modules
renders it into a *bundle*, a directory of container units and configuration
files, and kiwi-stack installs that bundle on the machine. It is for a single
machine that you set up by hand. kiwi-server uses the same package for a
whole fleet.

| Page | For | What it covers |
|---|---|---|
| [Install](install.md) | everyone | what it needs, install, update, uninstall |
| [Using kiwi-modules](usage.md) | everyone | the three commands, from a machine file to a running stack |
| [The machine file](machine-file.md) | everyone | every key, the paths, generated secrets and the seed |
| [Modules and presets](modules.md) | everyone | what each module does and where it can run |
| [The bundle](bundle.md) | people who look inside | the files a render writes and what `stack.sh` is |
| [Development](development.md) | contributors | tests, CI, releases, how kiwi-server takes a release |

These pages are also on [kiwi-network.eu](https://kiwi-network.eu/docs/),
where they are pulled from this folder at every release.
