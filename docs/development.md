# Development

This page is for people who change kiwi-modules: the renderer in
`lib/kiwimodules`, a module in `modules/` or a profile in `profiles/`.

## Layout

| Path | What it holds |
|---|---|
| `lib/kiwimodules/` | The Python package: the renderer, the settings resolver, the quadlet writer, the command line. |
| `modules/<name>/` | One module: `module.yaml`, its compose fragment and its templates. |
| `profiles/<name>/role.yaml` | One profile: its module list or presets, and defaults for the modules. |
| `examples/` | Machine files that CI renders. |
| `tests/` | The unit tests and the golden bundle. |

The format of `module.yaml` and `role.yaml` is described with kiwi-server:
[Modules](https://kiwi-network.eu/docs/server/kiwi-server/modules/).

## Run the tests

```bash
python3 -m unittest discover -s tests
```

The tests need PyYAML and Jinja2. They render every preset, compare one
machine with a stored result, and check that a generated secret has the value
it always had.

`tests/golden/sh3` is that stored result, called the *golden bundle*. It is
the same machine that kiwi-server renders in its own tests, and both must
match it byte for byte. When a change to a module is meant to change the
rendered files, the golden bundle has to be updated in both repositories.

## What CI checks

On every push and pull request, on Ubuntu:

1. `shellcheck` on `bin/kiwi-modules` and `install.sh`,
2. that every Python file compiles,
3. the unit tests,
4. an install into a temporary prefix and a render of `examples/sh3.yaml` and
   `examples/master.yaml`.

## Release

The version is the `VERSION` line in `kiwi.manifest` and `VERSION` in
`lib/kiwimodules/__init__.py`. They must be the same, and `CHANGELOG.md` gets
an entry.

When a change with a new version reaches the `main` branch, a workflow makes
the tag `vX.Y.Z` and the release. Nothing is tagged by hand.

## How kiwi-server takes a release

kiwi-server carries a copy of this repository's `lib/kiwimodules`, `modules/`
and `profiles/`. Its script `tools/vendor.sh` copies a release in by tag, and
its file `VENDORED` names the tag. A change here reaches a fleet when
kiwi-server has taken the release and has been released itself.

## Secrets that follow a new seed

A generated secret can say how it takes a new value when a fleet replaces its
seed. kiwi-server's command `rotate seed` uses it.

| In `module.yaml` | Meaning |
|---|---|
| `rotate: restart` | The containers read the secret at every start and keep it nowhere else. New files and a restart are enough. |
| `rotate: { in: <container>, run: <command> }` | The secret lives in a database or an account. The command runs in that container of the module before the restart, with the new value in `$NEW`, and sets it there. `name:` in place of `in:` names a container whose name does not start with the prefix. |
| a list of such mappings | The steps run in order. All of them must work. |
| nothing | The secret keeps its value when the seed is replaced. |

A command must work whatever the value is at that moment, and it must be safe
to run twice.
