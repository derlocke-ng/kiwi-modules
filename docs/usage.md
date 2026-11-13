# Using kiwi-modules

kiwi-modules has three commands. `render` does the work. `modules` and
`profiles` show what you can put into a machine file.

| Command | What it does |
|---|---|
| `kiwi-modules render machine.yaml -o DIR` | Renders the machine file into the bundle directory `DIR`. |
| `kiwi-modules modules` | Lists the modules with a one-line description. With `-v` it also lists every setting of every module and its default. |
| `kiwi-modules profiles` | Lists the profiles and the presets of the `node` profile. |
| `kiwi-modules --version` | Prints the version. |

## From a machine file to a running stack

A *stack* is the set of containers one machine runs. These steps set up a node
called `sh3` with the `cloud` preset, which is Nextcloud and Vaultwarden
behind a reverse proxy.

1. Make a directory for the machine and a *seed*. The seed is a file with 32
   random bytes. Passwords that you leave out of the machine file are derived
   from it, so keep it and back it up.

   ```bash
   mkdir -p sh3/secrets
   head -c 32 /dev/urandom > sh3/secrets/seed
   ```

2. Copy the example and edit it. The example names the TLS certificate files
   and expects the WireGuard client configuration of this machine as
   `secrets/sh3.home.conf`. [The machine file](machine-file.md) explains every
   key.

   ```bash
   cp examples/sh3.yaml sh3/
   ```

3. Render the bundle.

   ```bash
   kiwi-modules render sh3/sh3.yaml -o sh3/sh3.bundle
   ```

4. Copy the bundle to the machine and install it there with kiwi-stack.
   kiwi-stack needs root, because it writes systemd units and starts
   containers.

   ```bash
   scp -r sh3/sh3.bundle sh3:/tmp/
   ssh sh3 sudo kiwi-stack apply /tmp/sh3.bundle
   ```

When you change the machine file, render again and apply the new bundle.
kiwi-stack restarts only the containers whose files changed.

## The examples

The `examples/` directory of the repository has three machine files.

| File | What it describes |
|---|---|
| `sh3.yaml` | A node with the `cloud` preset. |
| `master.yaml` | A master with the modules of the `master` profile. |
| `hub.yaml` | A master that also runs a nostr relay and a hub built on kiwi-framework. |

## Other module and profile directories

Two environment variables point kiwi-modules at other directories. They are
meant for developing modules.

| Variable | What it does |
|---|---|
| `KIWI_MODULES_HOME` | The directory that holds the modules, instead of the installed one. |
| `KIWI_MODULES_PROFILES` | The directory that holds the profiles, instead of the installed one. |
