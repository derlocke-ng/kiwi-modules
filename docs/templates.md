# Templates

A module's templates are Jinja2 files that the renderer fills in for one
machine: the compose template with the module's containers, and any
configuration file or host unit the module ships. This page lists what a
template can use, how the parts are put together, and what the renderer adds
to every stack by itself.

## How a stack is rendered

For one machine, `kiwi-modules render` does this, in this order:

1. It reads the machine file and resolves the settings of the profile and of
   every module (see [The machine file](machine-file.md#the-role-block)).
2. It orders the modules, required dependencies first.
3. It builds the context and gives each module a fixed address on the stack
   network.
4. It collects the `nginx` blocks of all modules and the firewall rules for
   the VPN client.
5. It renders each module's compose template, reads the result as YAML and
   merges the `services`, `volumes` and `networks` of all modules into one
   compose file, plus the stack network from `modules/networks.yml.j2`. It
   then checks the ports and adds the names and resolvers described below.
6. Under podman, it translates the compose file into quadlets and moves the
   secrets into `kiwi/env/` files.
7. For each module, it checks the `validate` rules, renders the other
   templates to their outputs, writes the `file` settings, and collects
   directories, ports, kernel settings and URLs.
8. It writes the bundle and `stack.sh`.

The Jinja environment uses `trim_blocks` and `lstrip_blocks`, so a line with
only a `{% … %}` tag leaves no empty line behind, and it keeps the final
newline of a template.

## The context

Every template of a module sees the values below, the module's own settings
under their keys, its `derived` values and the lower-case names of its
`env.optional` defaults.

| Value | Meaning |
|---|---|
| `hostname`, `node_name` | The machine's full hostname, for example `papaya.home`. |
| `node_type` | `master` or `node`. |
| `domain` | The network's domain, for example `home`. |
| `module` | This module's name. |
| `modules` | The names of all modules on the machine, in render order. |
| `has_<module>` | True for every module on the machine, with `-` as `_`: `has_reverse_proxy`, `has_nostr_relay`. `has_nextcloud` means `has_cloud`. |
| `module_config` | Every module's resolved settings, by module name. Read another module's setting with `module_config.get('reverse-proxy', {}).get('network_mode')`. |
| `container_prefix` | `kn` on a node, `km` on a master. |
| `network_name` | The stack network: `knet-node` or `knet-master`. |
| `container_ip` | This module's fixed address on the stack network. |
| `container_ips` | Every module's address, by module name. |
| `docker_subnet`, `docker_gateway`, `docker_subnet_base`, `docker_ip_range` | The stack network, its gateway, its first three numbers (`172.128.0`) and the range for containers without a fixed address. |
| `bridge_mtu`, `wg_mtu` | The MTU of the stack network and of the WireGuard tunnels. |
| `docker_dir` | The stack directory on the machine. |
| `service_user` | The user who owns the stack's data. |
| `timezone` | The machine's time zone. |
| `runtime` | `podman` or `docker`. The compose template is the source in both cases. |
| `vpn_ip` | The machine's address in the mesh. |
| `pub_iface` | The LAN interface, or empty when it is detected on the machine. |
| `master_ip`, `mesh_subnet` | The master's mesh address and the whole mesh (`10.8.0.0/16` by default). |
| `mesh_via` | The address of the container the host routes the mesh through: the WireGuard server on a master, the VPN client on a node. |
| `proxy_ip`, `vpn_client_ip`, `dns_ip` | The addresses of the reverse proxy, the VPN client and Pi-hole, or empty when the module is not there. |
| `proxy_netns_ip`, `dns_container_ip` | Where the reverse proxy and Pi-hole answer on the stack network: their own address, or that of the container whose namespace they share. |
| `dns_records`, `mesh_ips` | The machine file's `(address, name)` records, and the mesh addresses in them. |
| `lan_addresses` | Mesh address to LAN address, for nodes on the same LAN. |
| `ca_cert_dir` | The folder of the CA certificate on the machine, or empty without one. |
| `<key>_present` | For each `file` setting that was given, for example `wireguard_config_present`. |
| the keys of `variables` | The stack setting `variables`, with lower-case keys. |

These values are added once the `nginx` blocks are collected. They are there
for the compose template and the other templates, but not for the `nginx`
block of `module.yaml` itself:

| Value | Meaning |
|---|---|
| `upstreams`, `servers` | The reverse proxy's collected upstreams and server blocks. |
| `public_names` | The names of the public sites, with `reverse-proxy.public`. |
| `module_rules` | The firewall rules other modules add to the VPN client. |
| `enable_vpn_dnat` | Whether mesh traffic on 80 and 443 is forwarded to the reverse proxy. |

The backup module also gets `backup_sources`, the `backup:` blocks of every
module.

One filter is added to Jinja's own: `wg_key` turns a generated secret into a
WireGuard private key.

## Writing the compose template

The compose template renders to a compose file with one top-level
`services:` mapping, and optionally `volumes:` and `networks:`. Two modules
that define the same service stop the render. The stack network comes from
`modules/networks.yml.j2`, so a module only joins it:

```yaml
    networks:
      {{ network_name }}:
        ipv4_address: {{ container_ip }}
```

In the compose template, and only there, every `$` in a value becomes `$$`,
because docker compose would otherwise read `$NAME` in a password as a
variable. Write the template as usual; the escaping is done for you.

Mount files from the stack directory with `{{ docker_dir }}/…`, and add `:z`
to every bind mount (`:ro,z` when it is read-only) for SELinux on Fedora
CoreOS and uCore. Do not label mounts of the container socket or of
`/lib/modules`.

## Container addresses

Each module gets one fixed address on the stack network, its
`container_ip`. The first modules keep the addresses of the first version of
Kiwi Network, so a machine set up then keeps them:

| Module | Address |
|---|---|
| `vpn-client`, `vpn-server`, `dns`, `reverse-proxy`, `cloud` | `.2`, `.3`, `.4`, `.5`, `.6` |
| `vault`, `tor`, `downloader`, `gateway` | `.7`, `.8`, `.9`, `.10` |
| `portainer`, `sftp` | `.250`, `.251` |
| every other module | `.100` plus its position in the render order, counted from 0 |

Containers without a fixed address, such as a module's database, get one from
the third quarter of the network (`.128/26` of a `/24`). A fixed address may
not lie there. A machine file can give a module another address with
`container_ip` in its block.

## What the renderer adds to every stack

- **Secrets stay out of the unit files.** Under podman, an environment value
  that contains a `secret` setting goes into `kiwi/env/<container>.env`,
  which only root can read, and not into the `.container` file. The compose
  file keeps the value and has mode `0600`.
- **The machine's own names inside the containers.** Each container on the
  stack network gets `extra_hosts` entries that point the machine's own
  names, from `dns_records`, at the reverse proxy. Without them a container
  would reach its own host's loopback or go through the VPN client and back.
  Pi-hole does not get them, so it does not hand those addresses to its
  clients.
- **The containers' resolver.** When the machine runs the dns module, every
  container on the stack network except Pi-hole and the VPN client asks
  Pi-hole first and Quad9 (`9.9.9.9`) second. A module that sets `dns` or
  `extra_hosts` itself keeps its own.
- **The CA certificate** from the machine file is written to
  `kiwi/ca/kiwiCA.crt`. A module mounts it where its software looks for CA
  certificates, using `ca_cert_dir`.
- **Every image** is listed in `stack.sh`, so kiwi-stack can pull them before
  the first start.
- **Two MTUs.** `wg_mtu` (default 1376) is the tunnels' MTU; `bridge_mtu`
  (default 1500) is the stack network's, which carries the tunnels' encrypted
  packets. WireGuard adds up to 80 bytes and pads packets to a multiple of 16,
  so the render refuses a `wg_mtu` that does not fit: at most 1408 under a
  1500 bridge. The old single setting `mtu` is read as `wg_mtu`, with a
  warning.
- **Port ranges** such as `27000-27100/udp` are understood in `open_ports`,
  in `ports:` and in `vpn-client.extra_dnat_rules`, including the check for
  ports that two containers publish.
