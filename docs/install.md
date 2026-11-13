# Install

kiwi-modules is a command-line tool written in Python. It runs on the computer
where you write the machine file. That can be your desktop or the machine
itself.

## What it needs

- `python3` with the packages PyYAML and Jinja2. On Debian they are called
  `python3-yaml` and `python3-jinja2`, on Fedora `python3-pyyaml` and
  `python3-jinja2`. The installer warns when one of them is missing.
- [kiwi-stack](https://kiwi-network.eu/docs/server/single/) on the machine
  that will run the services. kiwi-modules only writes the files; kiwi-stack
  installs them.

The continuous integration runs the tests and renders the examples on Ubuntu.
Other systems are not tested yet.

## Install from a checkout

```bash
git clone https://github.com/derlocke-ng/kiwi-modules
cd kiwi-modules
./install.sh install
```

This copies the library, the modules, the profiles and the examples to
`~/.local/lib/kiwi-modules` and the command to `~/.local/bin/kiwi-modules`.
Nothing runs as root.

| Setting | What it does |
|---|---|
| `KIWI_SCOPE=system` | Installs under `/usr/local` instead of `~/.local`. Run the installer as root for this. |
| `KIWI_PREFIX=/some/path` | Installs under that path. It takes precedence over `KIWI_SCOPE`. |

kiwi-updater installs kiwi-modules the same way, from the `kiwi.manifest`
file in the repository.

## Run it without installing

From a checkout, the package runs in place:

```bash
PYTHONPATH=lib python3 -m kiwimodules --help
```

## Update

```bash
git pull
./install.sh update
```

`update` does the same as `install`: it replaces the installed copy.

## Uninstall

```bash
./install.sh uninstall
```

This removes the command and the library directory. Your machine files and
bundles are not touched.
