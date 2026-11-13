# kiwi-modules documentation

kiwi-modules holds the modules of Kiwi Network and the renderer that turns
them into a stack for one machine. A *module* is one service, such as the
WireGuard server, Pi-hole or Nextcloud. A *profile* says whether a machine is
a master or a node and which modules it starts with. The *machine file*
describes one machine, and `kiwi-modules render` turns it into a *stack
bundle*, which [kiwi-stack](https://kiwi-network.eu/docs/server/single/)
installs on the machine.

| Page | For | What it covers |
|---|---|---|
| [Install](install.md) | everyone | requirements, install, update and uninstall |
| [The machine file](machine-file.md) | everyone | every key, the role block, secrets and the seed |
| [Render a machine](render.md) | everyone | the commands, what the render checks, what the bundle contains |
| [Modules and profiles](modules.md) | everyone | every module, the profiles and their presets, hubs |
| [Writing a module](writing-a-module.md) | module authors | a new module from start to finish |
| [module.yaml reference](module-yaml.md) | module authors | every key of `module.yaml` and the settings schema |
| [Templates](templates.md) | module authors | what a template sees, how a stack is put together, what the renderer adds |
| [Development](development.md) | contributors | tests, CI, releases and how kiwi-server carries this repository |

The history of every release is in
[CHANGELOG.md](https://github.com/derlocke-ng/kiwi-modules/blob/main/CHANGELOG.md).
These pages are also on
[kiwi-network.eu](https://kiwi-network.eu/docs/server/modules/), where they
are pulled from this folder at every release.
