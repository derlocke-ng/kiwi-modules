# module.yaml reference

Every module has a `module.yaml` that tells the renderer what the module is,
what it needs, which templates it has and which settings a machine may give
it. This page lists every key the renderer reads at v0.28.0. For a guided
first module, see [Writing a module](writing-a-module.md).

Every key is optional. The smallest useful `module.yaml` names the module
and its compose template. Look at the modules in
[modules/](https://github.com/derlocke-ng/kiwi-modules/tree/main/modules)
for complete examples: `vault` and `sftp` are short, `cloud` and `dns` use
almost everything.

## Expressions in module.yaml

Many values in `module.yaml` are templates themselves. They are rendered with
Jinja against the module's context (see [Templates](templates.md#the-context)),
so `"{{ container_prefix }}-vault"` becomes `kn-vault` on a node.

Before Jinja runs, `${NAME}` placeholders are replaced, an older convention
that the modules still use. `${NAME}` stands for the context value `name` in
lower case, with three special names:

| Placeholder | Becomes |
|---|---|
| `${DOCKERDIR}` | `docker_dir`, the stack directory |
| `${DOCKER_SUBNET2}` | `docker_subnet_base`, the first three numbers of the stack network |
| `${LAN_IFACE}` | `pub_iface`, the LAN interface |

A `${NAME}` that is not set, or empty, stops the render with an error;
`${VPN_IP}` says that the stack setting `vpn_ip` is needed. Placeholders and
Jinja both work in: `nginx`, `outputs` paths and unit names,
`storage.bind_mounts` hosts, `network.open_ports`, `network.listen_ports`,
`firewall.rules`, `urls` and `backup`. `derived` and `validate` use Jinja
only.

## module

```yaml
schema_version: "1.0"
module:
  name: vault
  title: Vaultwarden
  version: 1.1.0
  description: "Vaultwarden — the Bitwarden-compatible password manager, behind the reverse proxy"
  category: security
  node_types: [node]
```

| Key | Default | Meaning |
|---|---|---|
| `name` | the folder name | Must equal the folder name if it is given. |
| `title` | the name | A short title. kiwi-server's app shows it. |
| `description` | empty | One or two sentences. `kiwi-modules modules` prints it. |
| `category` | empty | A group for the app: the modules use `core`, `network`, `productivity`, `security`, `storage` and `system`. |
| `version` | empty | The module's own version. The renderer does not use it. |
| `node_types` | `[master, node]` | Where the module may run. A machine of another type is refused. The old form `master_only: true` means `[master]`. |

`schema_version` is written at the top of every module; the renderer does
not read it.

## dependencies

```yaml
dependencies:
  required: [vpn-client, reverse-proxy]
  optional: [dns]
```

`required` modules are added to a machine that lists this module, and are
rendered before it. A cycle is an error. `optional` modules are only
information for the app; nothing is added for them. A module that works with
another one when it is present checks for it in its templates with
`has_<module>` (see [Templates](templates.md#the-context)).

## network

```yaml
network:
  needs_vpn_dnat: true
  open_ports: ["{{ sftp_port }}/tcp"]
  listen_ports: ["53/tcp", "53/udp"]
```

| Key | Meaning |
|---|---|
| `needs_vpn_dnat` | The module's service is reachable from the mesh through the reverse proxy. When any module of a stack with a reverse proxy sets it, the VPN client forwards mesh traffic for the machine's `vpn_ip` on ports 80 and 443 to the reverse proxy, and the host opens 80 and 443. The stack then needs `vpn_ip`. |
| `open_ports` | Ports the host firewall must open, as `port/proto` or `low-high/proto`. One entry may render to several ports separated by spaces, or to nothing. |
| `listen_ports` | Ports the module's containers bind inside their network namespace. When two modules share one namespace (`network_mode: service:…`) and list the same port, the render stops. |

## firewall

```yaml
firewall:
  scope: vpn-client
  rules:
    - "-t nat -A PREROUTING -d ${VPN_IP} -p tcp --dport {{ sftp_port }} -j DNAT --to-destination {{ container_ip }}:22"
```

With `scope: vpn-client` (the default), each rule that starts with `-` is
rendered and added to the VPN client's iptables rules, which the vpn-client
module applies inside its container. The rules of all modules are collected
there, without duplicates. With any other scope, such as `self` or `host`,
the renderer ignores `rules`; such a module applies its own rules from its
templates.

## templates and outputs

```yaml
templates:
  compose: docker-compose.yml.j2
  users: users.conf.j2
  timer: refresh.timer.j2

outputs:
  users: { path: "{{ container_prefix }}-sftp/users.conf", mode: 0600 }
  timer: { kind: host_unit, name: "{{ container_prefix }}-refresh.timer", when: refresh_enabled }
  wireguard_config: { path: "{{ container_prefix }}-vpn-client/wg0.conf", mode: 0600 }
```

`templates` names the module's template files under keys of your choice. The
key `compose` is the module's part of the compose file. Every other key is
rendered and written where `outputs.<key>` says:

| Output key | Default | Meaning |
|---|---|---|
| `path` | `<module>/<template file without .j2>` | Where the file goes, relative to the stack directory. A plain string instead of a mapping is the path. |
| `mode` | `0644` for a template, `0600` for a file setting | The file's mode on the machine. Write it as an octal number (`0600`). |
| `when` | none | The name of a context value. The output is left out while that value is empty or false. |
| `kind: host_unit` | not set | The output is a systemd unit on the host, installed by kiwi-stack, instead of a file in the stack directory. |
| `name` | the template file without `.j2` | With `kind: host_unit`: the unit's file name. |

`outputs` also says where a setting of type `file` goes: the key is the
setting's key. A file setting without an `outputs` entry is an error. Two
modules that write the same path, or install the same host unit, stop the
render.

## storage

```yaml
storage:
  volumes: [portainer_data]
  bind_mounts:
    - { host: "${DOCKERDIR}/{{ container_prefix }}-vault", type: dir, required: true }
    - { host: "{{ media_dir }}", type: dir, required: false }
    - { host: "${DOCKERDIR}/{{ container_prefix }}-x/extra", type: dir, when: extra_enabled }
    - { each: shared_folders, type: dir }
    - { each: rings, host: "${DOCKERDIR}/{{ container_prefix }}-tang/{{ item }}" }
```

`volumes` are named volumes added to the compose file. `bind_mounts` are the
host directories kiwi-stack creates before the start:

| Key | Meaning |
|---|---|
| `host` | The directory on the host. A path inside the stack directory is kept relative to it. |
| `type` | Only `dir` (the default) creates a directory; other types are skipped. |
| `required` | Default `true`. With `false`, a mount whose `${NAME}` is not set is skipped instead of stopping the render. |
| `when` | The name of a context value; the mount is skipped while it is empty or false. |
| `each` | The name of a list or map setting: one directory per value. With `host`, one directory per item of the list or key of the map instead, with the item as `{{ item }}` in the path. |

The parent directory of every file in the bundle is created as well.

## backup

```yaml
backup:
  frozen:
    containers: ["{{ container_prefix }}-db"]
    volumes: [app_db]
    paths: []
  paths:
    - "{{ data_path }}"
    - { each: shared_folders }
  volumes: []
  exclude: ["{{ data_path }}/thumbs", "appdata_*/preview"]
  no_restore: "it carries the mesh this restore would come over"
```

The backup module reads these blocks of all modules on the machine. A module
without a `backup:` block has nothing worth keeping.

| Key | Meaning |
|---|---|
| `frozen.containers` | Containers paused while their data is copied, so a database is copied in a consistent state. |
| `frozen.paths`, `frozen.volumes` | Host paths and named volumes copied while those containers are paused. |
| `paths`, `volumes` | Host paths and named volumes copied while everything runs. |
| `exclude` | What to leave out. An absolute path is a path on the host; anything else is a restic pattern. |
| `no_restore` | A reason why `kiwi-stack restore` must not restore this module. The reason is shown to whoever tries. |

An item of a list may be `{ each: <setting> }`, which stands for every value
of a list or map setting. An item that renders to an empty string is left
out, so a path that depends on an unset setting can stay in the list.

## host_integration

```yaml
host_integration:
  sysctl: { net.ipv4.ip_forward: 1 }
  kernel_modules: [wireguard]
```

`sysctl` values and `kernel_modules` are collected from all modules into
`stack.sh`, and kiwi-stack sets them on the host. The dns module also has
`disable_resolved_stub: true`, but the renderer does not read that key at
v0.28.0.

## urls

```yaml
urls:
  - "Vaultwarden: {{ vault_domain or 'https://vault.' ~ hostname }}"
```

Lines printed after the render and after the stack has started.

## nginx

A module that is served by the reverse proxy announces its server blocks
here. The reverse-proxy module itself has `nginx: { aggregator: true }`; it
collects the blocks of all modules into one `nginx.conf`.

```yaml
nginx:
  upstream: { name: vaultwarden, server: "{{ container_prefix }}-vault:80" }
  server_name: "vault.{{ hostname }}"        # one block …
  proxy_pass: "http://vaultwarden"
  websocket: true
  servers:                                   # … and/or several
    - server_name: "{{ nc_hostname or 'cloud.' ~ hostname }}"
      proxy_pass: "http://nextcloud-aio-apache:11000"
      hsts: true
      client_max_body_size: "0"
      proxy_read_timeout: 86400s
      when: has_reverse_proxy
      extra_directives: ["proxy_redirect off;"]
      extra_locations: [{ path: /api/, config: "proxy_pass http://x/api/;" }]
```

A block given directly under `nginx:` comes first, then the ones in
`servers:`. Each block takes these keys:

| Key | Meaning |
|---|---|
| `server_name` | Required. The name the site answers for. |
| `proxy_pass` | Required. Where nginx sends the requests. |
| `websocket` | `true` passes WebSocket connections on. |
| `hsts` | `true` or `false` decides HSTS for this site. Not set: the reverse proxy's `hsts` setting decides. |
| `proxy_ssl` | The upstream speaks HTTPS. Default: `true` when `proxy_pass` starts with `https://`. The upstream's certificate is not verified. |
| `client_max_body_size`, `proxy_read_timeout`, `referrer_policy` | Passed to nginx for this site. |
| `extra_directives` | A list of nginx lines added to the server block. |
| `extra_locations` | A list of `{ path, config }` location blocks. `proxy: true` adds the site's own `proxy_pass` and proxy headers to the block, and `when` works as below. |
| `cors` | `{ path, origins, methods, allow_headers, expose_headers }`: answers browsers from other origins on that path. `origins` names a list setting; while it is empty, nothing is added. |
| `comment` | The comment above the block in `nginx.conf`. |
| `when` | The name of a context value; the block is left out while it is empty or false. |

`upstream` gives the upstream server a short name. nginx would resolve an
upstream block once at its start and refuse to start while a container does
not exist yet, so the renderer puts `upstream.server` straight into
`proxy_pass` instead, and nginx resolves the name for each request.

With `reverse-proxy.public` on a master, a site whose name is outside the
network's domain is public and gets a Let's Encrypt certificate; every other
site answers the mesh only.

## derived

```yaml
derived:
  hub_host: "{{ hub_domain or 'hub.' ~ hostname }}"
```

Named Jinja expressions. Each is rendered after the module's settings are
known, in the order given, and is then a context value for the module's
templates and the rest of `module.yaml`. A later entry may use an earlier
one. Use it for a value that several places need.

## env

```yaml
env:
  optional:
    DOT_PROVIDERS: "quad9"
```

Default values that the module's templates see in lower case
(`{{ dot_providers }}`). A setting of the same name takes their place.

## validate

```yaml
validate:
  - { when: "public_mounts and not public_relays", error: "public_mounts need public_relays" }
```

Each rule is a Jinja expression over the module's context. When it is true,
the render stops with the error text, which is itself rendered with Jinja.
Use rules for combinations of settings that cannot work, so the mistake shows
up at the render and not on the machine.

## settings

The settings are what a machine file may set in the module's block. The same
list builds the settings form in kiwi-server's app, so a new module needs no
code there. Profiles use the same format for the stack settings.

```yaml
settings:
  - key: vault_domain
    type: string
    label: URL
    help: "The full URL clients use. Empty: https://vault.<hostname>."
    default: ""
```

| Key | Meaning |
|---|---|
| `key` | Required. Lower case with underscores (`snake_case`). The template sees the value under this name. Two settings with one key are an error. |
| `type` | One of the types below. Default `string`. |
| `label` | A short label for the form. Default: the key with spaces. |
| `help` | What the setting is for, shown beside the field. A test requires at least a short sentence for every module setting. |
| `default` | The value when the machine file gives none. Without it: `0`, `false`, `[]` or `{}` by type, else an empty string. |
| `required` | `true`: the render stops while the value is empty. |
| `required_unless` | The key of another setting: one of the two must be set. |
| `options` | The allowed values of an `enum`. Required for `enum`. |
| `pattern` | A regular expression the value must match in full. An empty string passes. For a `list` each item is checked, for a `map` each value. |
| `key_pattern` | For a `map`: the expression its keys must match. |
| `targets` | The targets (`coreos`, `ucore`, `debian`) where the setting applies. On other targets it keeps its default, whatever the machine file says. |
| `group` | The section of the form. Default `Settings`. |
| `placeholder` | An example shown in an empty field, and in the error when `pattern` does not match. |
| `generate` | `secret` only: derive the value from the seed when it is empty. |
| `generate_each`, `generate_hash_of` | `map` only: one password hash per value of the list setting `generate_each`, of the secret that each of those machines derives for itself as `generate_hash_of` (`<module>/<key>`). The backup server uses this to know its clients' passwords. |
| `fallback_file` | `file` only: a path used when the setting is empty and the file exists. `{hostname}` and `{name}` are filled in. |

The types:

| Type | Value |
|---|---|
| `string` | One line of text. |
| `text` | Several lines of text. |
| `int` | A whole number. |
| `bool` | `true` or `false`; `yes`, `no`, `on`, `off`, `1` and `0` are accepted. |
| `enum` | One of `options`. |
| `list` | A YAML list, or a string whose words are the items. |
| `map` | A YAML mapping; keys and values become strings. |
| `object` | Any YAML mapping or list, passed to the template as it is. The template checks its shape. |
| `secret` | Like `string`, but never printed in an error, and kept out of the unit files under podman. |
| `file` | A path relative to the machine file. The render reads the file and writes it to `outputs.<key>`. In templates the setting holds the file's name, and `<key>_present` is true. |

## Compose keys under podman

With `runtime: podman` the merged compose file is translated into quadlets.
The translation knows these service keys, and any other key stops the
render, so a module keeps working with both runtimes:

`image`, `container_name`, `environment`, `volumes`, `networks`,
`network_mode`, `ports`, `cap_add`, `cap_drop`, `sysctls`, `devices`,
`restart`, `security_opt`, `init`, `read_only`, `tmpfs`, `user`, `shm_size`,
`stop_grace_period`, `hostname`, `command`, `entrypoint`, `depends_on`,
`healthcheck`, `extra_hosts`, `dns`, and `x-kiwi-health-on-failure`.
`expose`, `logging`, `profiles` and `labels` are accepted and have no effect
under podman.

Some keys are translated only in part:

- `network_mode` may be `host`, `service:<name>` or `container:<name>`.
  With `service:<name>` the container is bound to that service, so systemd
  stops and starts it together with it.
- `networks` may give each network an `ipv4_address`.
- `volumes` must use the short form (`host:container:options`).
- `entrypoint` may be one word only; put the arguments in `command`.
- `security_opt: [label:disable]` turns SELinux labelling off for the
  container; other options are passed to podman as they are.
- `restart: always` and `unless-stopped` become `Restart=always`,
  `on-failure` becomes `Restart=on-failure`.
- A `healthcheck` test written as `[CMD, …]` runs without a shell, which
  images without `/bin/sh` need.
- `x-kiwi-health-on-failure` (`kill`, `restart`, `stop` or `none`) tells
  podman what to do with a container that stays unhealthy. docker ignores it.
