# Render a machine

Rendering turns a [machine file](machine-file.md) into a *stack bundle*, a
directory that holds everything the machine needs to run its services. All
templates are filled in at this point, on the computer that renders. The
machine itself only needs [kiwi-stack](https://kiwi-network.eu/docs/server/single/)
and a container runtime; it never sees Python or Jinja.

## Commands

kiwi-modules has three commands. `kiwi-modules --version` prints the version.

| Command | What it does |
|---|---|
| `kiwi-modules render MACHINE.yaml -o DIR` | Renders the machine's stack into `DIR`. |
| `kiwi-modules modules` | Lists every module with the node types it runs on and a description. |
| `kiwi-modules modules -v` | Also lists every setting of every module with its type and default, and marks the required ones. |
| `kiwi-modules profiles` | Lists the profiles and the presets of each. |

`python3 -m kiwimodules` takes the same commands when `lib/` is on
`PYTHONPATH`.

## Render and apply

```bash
kiwi-modules render papaya/papaya.yaml -o papaya/papaya.bundle
scp -r papaya/papaya.bundle papaya:/tmp/
ssh papaya sudo kiwi-stack apply /tmp/papaya.bundle
```

`render` refuses an output directory that exists and is not empty, so an old
bundle is never mixed with a new one. It creates the directory readable only
by you, because the bundle contains passwords. When it has finished it prints
the modules it rendered, any warnings, the addresses of the services (for
example `Nextcloud: https://cloud.papaya.home`) and the `kiwi-stack apply`
line to run on the machine.

Rendering is repeatable. The same machine file, seed and kiwi-modules version
give the same bundle, byte for byte.

## What the render checks

A mistake stops the render with a message that starts with `error:` and
usually names the machine, the module and the setting. Nothing is written in that
case. These are the checks:

- **The machine file.** `name` and `role` are present, the role is a profile
  with a stack (the `bare` profile has none), and every key in the role block
  is a stack setting, `modules`, or an enabled module.
- **The modules.** Every module exists and may run on this machine's node
  type (master or node). Required dependencies are added and put first; a
  dependency cycle is an error.
- **The settings.** Every value has the setting's type and matches its
  pattern. Required settings are set. Unknown settings are refused. Files
  named in `file` settings exist.
- **The modules' own rules.** A module can refuse combinations of settings
  that do not work (its `validate:` rules), for example a commercial VPN
  provider without a private key.
- **The stack as a whole.** No two modules define the same container, write
  the same file or install the same host unit. No two containers publish the
  same host port. No two modules that share one network namespace listen on
  the same port in it. Every fixed container address lies inside the stack
  network.
- **The mesh address.** When a service must be reachable at the machine's
  mesh address, `vpn_ip` must be known.
- **The MTUs.** `wg_mtu` must fit into `bridge_mtu` once WireGuard has added
  its headers and padding, and must be at least 1280.
- **podman.** With `runtime: podman` every container must use only the
  compose keys that can be translated into a quadlet.

## The bundle

```
papaya.bundle/
  stack.sh               the manifest that kiwi-stack reads
  docker-compose.yml     every container of the stack (readable by root only)
  quadlets/              podman only: one .container per container, the .network,
                         and kiwi-stack.target, which starts them all
  host-units/            systemd units a module wants on the host itself
  kiwi/env/<name>.env    podman only: the secrets of one container (root only)
  kiwi/ca/kiwiCA.crt     your CA certificate, when the machine file names one
  kiwi/…                 host scripts some modules install (backup, certificates)
  kn-nginx/, kn-vpn-client/ …
                         each module's configuration files (km-… on a master)
```

The compose file is the source in both runtimes. With `runtime: docker`,
kiwi-stack runs it with docker compose. With `runtime: podman`, the renderer
has already translated it into quadlets, which systemd runs, and the compose
file is still in the bundle.

Under podman, a password never appears in a unit file, because anyone on the
machine can read unit files through `systemctl show`. Every environment
value that contains a secret setting goes into `kiwi/env/<container>.env`,
which only root can read, and the unit loads it with `EnvironmentFile=`.

### stack.sh

`stack.sh` is the contract between kiwi-modules and kiwi-stack. It is a bash
file that kiwi-stack sources, and kiwi-stack reads only the `KS_*` variables
in it. They describe the machine (`KS_HOSTNAME`, `KS_TARGET`,
`KS_ADMIN_USER`, `KS_TIMEZONE` …) and everything kiwi-stack has to set up:

| Variable | What it lists |
|---|---|
| `KS_STACK_DIR`, `KS_STACK_USER` | the stack directory and the user who owns its data |
| `KS_STACK_MODULES`, `KS_STACK_SERVICES` | the modules and their containers |
| `KS_STACK_FILES` | every file of the bundle with its mode, for example `kiwi/env/kn-vault.env:0600` |
| `KS_STACK_DIRS` | the directories to create |
| `KS_STACK_PORTS` | the ports to open in the host firewall |
| `KS_STACK_UNITS`, `KS_STACK_QUADLETS` | the host units and the quadlets |
| `KS_STACK_SYSCTL`, `KS_STACK_KMODS` | kernel settings and kernel modules the stack needs |
| `KS_STACK_IMAGES` | every image, pulled before the first start |
| `KS_STACK_HOSTS` | the lines for `/etc/hosts` |
| `KS_STACK_URLS` | the addresses printed after the start |
| `KS_SEED_ID` | which seed the secrets came from |

What kiwi-stack does with them is described on
[kiwi-network.eu](https://kiwi-network.eu/docs/server/single/).
