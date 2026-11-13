# Install

kiwi-modules runs on the computer where you render a stack, not on the machine
that runs it. That can be your workstation, the machine itself, or any other
Linux computer. The machine that runs the stack needs
[kiwi-stack](https://kiwi-network.eu/docs/server/single/) instead.

## Requirements

- **Python 3** with **PyYAML** and **Jinja2**. On Debian and Ubuntu the
  packages are `python3-yaml` and `python3-jinja2`. On Fedora they are
  `python3-pyyaml` and `python3-jinja2`. Elsewhere,
  `pip install --user pyyaml jinja2` works too.
- **bash**, for the launcher `bin/kiwi-modules` and the installer.

CI installs kiwi-modules and renders the examples on Ubuntu (GitHub's
`ubuntu-latest`) with the distribution's Python packages. Other systems are
not tested yet.

## Install from a checkout

```bash
git clone https://github.com/derlocke-ng/kiwi-modules
cd kiwi-modules
./install.sh install
```

The installer checks that `python3` exists and warns if it cannot import
`yaml` or `jinja2`. It then copies `lib/`, `modules/`, `profiles/` and
`examples/` to `<prefix>/lib/kiwi-modules` and the launcher to
`<prefix>/bin/kiwi-modules`. The prefix is chosen like this:

| Setting | Prefix | Needs root |
|---|---|---|
| nothing (the default) | `~/.local` | no |
| `KIWI_SCOPE=system` | `/usr/local` | yes |
| `KIWI_PREFIX=/some/path` | that path | only if you cannot write there |

For example, `sudo KIWI_SCOPE=system ./install.sh install` installs for every
user. Make sure the prefix's `bin` folder is on your `PATH`.

The repository also has a `kiwi.manifest`, the file
[kiwi-updater](https://kiwi-network.eu/docs/desktop/kiwi-updater/) reads to
install an app. `install.sh` follows kiwi-updater's installer contract.

## Run without installing

You do not have to install anything to use a checkout. Either of these works
from the repository root:

```bash
bin/kiwi-modules --version
PYTHONPATH=lib python3 -m kiwimodules --version
```

The launcher finds the package next to itself, both in a checkout and in an
installed copy.

## Update

Pull the checkout and run the installer again:

```bash
git pull
./install.sh update
```

`update` does the same as `install`: it removes the installed copy and copies
the current one.

## Uninstall

```bash
./install.sh uninstall
```

This removes `<prefix>/bin/kiwi-modules` and `<prefix>/lib/kiwi-modules`. Use
the same `KIWI_SCOPE` or `KIWI_PREFIX` you installed with. The usage line also
names `--purge`, but it has no effect: kiwi-modules keeps no data of its own.
Your machine files, seeds and bundles stay where you put them.

## Use other modules or profiles

kiwi-modules reads the modules and profiles that sit next to its package. Two
environment variables point it somewhere else:

| Variable | What it changes |
|---|---|
| `KIWI_MODULES_HOME` | the modules folder, for example a checkout where you develop a module |
| `KIWI_MODULES_PROFILES` | the profiles folder |

kiwi-server's names for the same settings, `KIWI_SERVER_MODULES`,
`KIWI_SERVER_ROLES` and `KIWI_SERVER_HOME`, are read too.
