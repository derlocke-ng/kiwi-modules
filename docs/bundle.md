# The bundle

A *bundle* is the directory that `kiwi-modules render` writes. It holds every
file the machine needs to run its stack. kiwi-stack installs it with
`sudo kiwi-stack apply DIR`. You only need this page when you want to look
inside a bundle or when you work on kiwi-modules or kiwi-stack.

```
sh3.bundle/
  stack.sh                 the list of everything in the bundle
  docker-compose.yml       the stack as a compose file
  quadlets/                one unit file per container, for podman
  host-units/              systemd units a module wants on the host
  kiwi/env/<service>.env   the secrets of each container
  kiwi/ca/kiwiCA.crt       the network's CA certificate, when one is given
  <prefix>-<module>/       the configuration files of each module
```

| Part | What it is |
|---|---|
| `stack.sh` | A bash file that only sets variables whose names start with `KS_`. kiwi-stack reads it and nothing else to learn what the bundle holds: the modules, the unit files, the images, the ports, the directories, the kernel settings and the addresses to print after the start. |
| `docker-compose.yml` | The whole stack. On docker, kiwi-stack uses it as it is. On podman, the unit files in `quadlets/` are made from it. |
| `quadlets/` | A *quadlet* is a unit file from which podman and systemd start one container. There is one per container, one for the network, and `kiwi-stack.target`, which starts them together. |
| `host-units/` | Units that run on the host and not in a container, for example the routing of the `gateway` module. |
| `kiwi/env/` | The passwords and keys, one file per container. The unit files name them as their environment file, so no secret stands in a unit file that every user can read. |
| `<prefix>-<module>/` | The module's own files, for example `nginx.conf` or `wg0.conf`. The prefix is `kn` on a node and `km` on a master. |

The mode of every file is listed in `stack.sh` (`KS_STACK_FILES`). The files
with secrets have the mode `0600`, so only root reads them on the machine.

`stack.sh` is the agreement between kiwi-modules and kiwi-stack. kiwi-stack
does not know any module. It installs what `stack.sh` names.
