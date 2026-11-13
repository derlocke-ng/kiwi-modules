# Development

This page is for people who change kiwi-modules itself: the renderer in
`lib/kiwimodules`, the modules or the profiles. It covers the tests, CI,
releases, and how kiwi-server takes in each release.

## Repository layout

| Path | What it holds |
|---|---|
| `lib/kiwimodules/` | The renderer, a Python package. `cli.py` has the commands, `machine.py` the machine file and the secret derivation, `resolver.py` the settings, `modules.py` the rendering, `quadlet.py` the translation for podman, `manifest.py` `stack.sh`. |
| `modules/` | One folder per module, and `networks.yml.j2`, the stack network. |
| `profiles/` | One folder per profile with a `role.yaml`, and `common/stack.yaml`, the stack settings every profile includes. |
| `examples/` | Machine files that CI renders. |
| `images/` | The container images this repository builds itself: strfry with a patch for the nostr-relay module, and Tang for the tang module. |
| `tests/` | The unit tests and the golden bundle. |
| `bin/kiwi-modules`, `install.sh`, `kiwi.manifest` | The launcher, the installer and the manifest for kiwi-updater. |

## Tests

The tests need Python 3 with PyYAML and Jinja2, and nothing else: no root, no
network, no container runtime. Run them from the repository root:

```bash
python3 -m unittest discover -s tests -v
```

They render machines into temporary folders and check the bundles. A few of
them guard rules that are easy to break by accident:

- **The golden bundle.** `tests/golden/sh3` is kiwi-server's golden bundle
  of the node sh3. kiwi-modules must render the same machine to the same
  bytes and the same file modes. When you change the output on purpose,
  update the golden files in the same commit and explain why in the
  changelog.
- **Every preset renders.** A master, each node preset and a hub on a master
  render into a bundle with the files kiwi-stack needs, and `stack.sh` passes
  `bash -n` (and `shellcheck` when it is installed).
- **The secret derivation is frozen.** One derived value is pinned. If this
  test fails, every generated password of every machine would change.
- **Every setting has help.** A module setting without a help text fails.
- **Errors are messages.** Mistakes in a machine file give `error: …`, not a
  Python traceback.
- **The version agrees.** `VERSION` in `kiwi.manifest`, `VERSION` in
  `lib/kiwimodules/__init__.py` and the first `## ` heading of
  `CHANGELOG.md` must be the same.

## CI

[.github/workflows/ci.yml](https://github.com/derlocke-ng/kiwi-modules/blob/main/.github/workflows/ci.yml)
runs on every push and pull request, on Ubuntu (`ubuntu-latest`):

1. `shellcheck -S warning bin/kiwi-modules install.sh`
2. `python3 -m py_compile` on the package and the tests
3. the unit tests
4. `install.sh install` into a temporary prefix, then a render of
   `examples/sh3.yaml` and `examples/master.yaml` with stand-in key and
   certificate files

You can run the same steps locally; none of them needs root.

## Releases

A release is a version tag `vX.Y.Z`. To make one:

1. Set the new version in `kiwi.manifest` (`VERSION=`) and in
   `lib/kiwimodules/__init__.py` (`VERSION = "…"`).
2. Add a section at the top of `CHANGELOG.md` headed `## X.Y.Z — what it
   brings`.
3. Merge to `main`.

[.github/workflows/release.yml](https://github.com/derlocke-ng/kiwi-modules/blob/main/.github/workflows/release.yml)
then creates the tag `vX.Y.Z` and a GitHub release whose notes are that
changelog section. It refuses a version that is not higher than the newest
tag, or one that `lib/kiwimodules/__init__.py` does not repeat. A push that
leaves `VERSION` alone creates nothing.

kiwi-network.eu shows the `docs/` folder of the latest release tag, so a
change to these pages reaches the site with the next release. Run the docs
checker before you tag:

```bash
python3 .claude/skills/kiwi-docs/scripts/check-docs.py .
```

## The container images

The nostr-relay and tang modules use images built here:
`ghcr.io/derlocke-ng/strfry` (strfry 1.1.3 with `images/strfry/auth.patch`)
and `ghcr.io/derlocke-ng/tang`, each for `linux/amd64` and `linux/arm64`.
Their workflows build the image on a pull
request that changes `images/strfry/` or `images/tang/`, and push it to GHCR
when such a change reaches `main`. The tag is set in the workflow file
(`TAG:`); raise it with every change, and point the module's `image` default
at the new tag.

## How kiwi-server uses this repository

[kiwi-server](https://kiwi-network.eu/docs/server/) carries a copy of
kiwi-modules, pinned to a release tag in its `VENDORED` file, and brings a
new release in with its `tools/vendor.sh`. Modules and the renderer are
therefore developed and released here, and reach kiwi-server's fleets when
kiwi-server takes the release. Machine-side code lives in
[kiwi-stack](https://kiwi-network.eu/docs/server/single/), which kiwi-server
carries the same way.

Some names in the bundle still say `kiwi-server`, for example the marker
`# kiwi-server stack` at the top of every quadlet. kiwi-stack relies on them,
so they are not renamed.
