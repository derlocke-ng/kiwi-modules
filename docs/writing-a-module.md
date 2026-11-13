# Writing a module

This page walks you through a new module, from an empty folder to a rendered
bundle. The example is `uptime`, which runs Uptime Kuma, a status page,
behind the reverse proxy of a node. The [module.yaml reference](module-yaml.md)
lists every key, and [Templates](templates.md) lists every value a template
can use.

A module is a folder under `modules/` with two files at least:

```
modules/uptime/
├── module.yaml              what the module is, what it needs, its settings
└── docker-compose.yml.j2    its containers, as a Jinja template of a compose file
```

Add any configuration file the service needs as another `.j2` template next
to them. kiwi-server uses the same modules, so a module you add here works in
a kiwi-server fleet too once kiwi-server carries the release.

## 1. Describe the module

`modules/uptime/module.yaml`:

```yaml
schema_version: "1.0"

module:
  name: uptime                     # the same as the folder name
  title: Uptime Kuma
  description: "Uptime Kuma, a status page that watches your services, behind the reverse proxy at uptime.<hostname>"
  category: system
  node_types: [node]               # where it may run: master, node, or both

dependencies:
  required: [vpn-client, reverse-proxy]

network:
  needs_vpn_dnat: true             # reachable from the mesh through the reverse proxy

templates:
  compose: docker-compose.yml.j2

storage:
  bind_mounts:
    - { host: "${DOCKERDIR}/{{ container_prefix }}-uptime", type: dir, required: true }

nginx:
  server_name: "{{ uptime_hostname or 'uptime.' ~ hostname }}"
  proxy_pass: "http://{{ container_prefix }}-uptime:3001"
  websocket: true

backup:
  frozen:
    containers: ["{{ container_prefix }}-uptime"]
    paths: ["${DOCKERDIR}/{{ container_prefix }}-uptime"]

urls:
  - "Uptime Kuma: https://{{ uptime_hostname or 'uptime.' ~ hostname }}"

settings:
  - key: uptime_hostname
    label: Name
    help: "The name the status page is served under. Empty: uptime.<hostname>."
    default: ""
  - key: image
    group: Advanced
    help: "The container image this module runs, pinned by tag."
    default: docker.io/louislam/uptime-kuma:1
```

What each part does:

- **`dependencies.required`**: the render adds these modules when a machine
  lists `uptime`, and renders them first.
- **`network.needs_vpn_dnat`**: mesh traffic to the node's mesh address on
  ports 80 and 443 is forwarded to the reverse proxy, so the status page is
  reachable from the mesh.
- **`storage.bind_mounts`**: kiwi-stack creates this directory on the machine
  before the container starts. `${DOCKERDIR}` is the stack directory.
- **`nginx`**: the reverse proxy gets a server block for this name.
  kiwi-server also adds the name to the network's DNS records.
- **`backup`**: the backup module pauses the container while it copies the
  directory, so the copy of the database is consistent.
- **`urls`**: printed after the render and after `kiwi-stack apply`.
- **`settings`**: what the machine file may set in an `uptime:` block. Each
  setting becomes a variable of the same name in the templates. Every setting
  needs a `help` text; a test fails without one.

## 2. Write the compose template

`modules/uptime/docker-compose.yml.j2`:

```yaml
# uptime (Uptime Kuma)
services:
  {{ container_prefix }}-uptime:
    image: {{ image }}
    container_name: {{ container_prefix }}-uptime
    environment:
      - TZ={{ timezone }}
    networks:
      {{ network_name }}:
        ipv4_address: {{ container_ip }}
    restart: unless-stopped
    volumes:
      - {{ docker_dir }}/{{ container_prefix }}-uptime:/app/data:z
```

Follow the existing modules here:

- Name containers `{{ container_prefix }}-<something>`. The prefix is `kn`
  on a node and `km` on a master.
- Join `{{ network_name }}` with the fixed address `{{ container_ip }}`.
  The renderer gives each module its own address on the stack network.
- Use a fully qualified image name (`docker.io/…`, `ghcr.io/…`). podman does
  not guess a registry.
- Label bind mounts with `:z` (`:ro,z` for read-only ones). Fedora CoreOS and
  uCore run with SELinux, which otherwise keeps the container from reading
  the files. Debian ignores the label. Never label a mount of the container
  socket or of `/lib/modules`.
- Use only the compose keys that the podman runtime translates; the
  [reference](module-yaml.md#compose-keys-under-podman) lists them.

## 3. Render a machine with it

Write a machine file that uses the module. The module list only needs
`uptime`, because its dependencies are added by themselves:

```yaml
name: papaya
role: node
node:
  modules: [uptime]
  reverse-proxy:
    tls_fullchain: secrets/papaya-fullchain.pem
    tls_privkey: secrets/papaya-privkey.pem
seed: secrets/seed
```

Put the seed, the two TLS files and the WireGuard config
`secrets/papaya.home.conf` next to it, as described in
[The machine file](machine-file.md#files-the-render-reads), and render:

```bash
kiwi-modules modules | grep uptime
kiwi-modules render papaya/papaya.yaml -o papaya/papaya.bundle
```

The render prints `papaya: vpn-client, reverse-proxy, uptime` and the URL
`https://uptime.papaya.home`. Read the result:

- `quadlets/kn-uptime.container` is the systemd unit podman will run.
- `kn-nginx/nginx.conf` has a server block for `uptime.papaya.home`.
- `stack.sh` lists `kn-uptime` in `KS_STACK_DIRS`.

If you develop the module outside this checkout, point kiwi-modules at your
copy of the modules folder with `KIWI_MODULES_HOME=/path/to/modules`.

## 4. Add a test and a changelog entry

[tests/test_render.py](https://github.com/derlocke-ng/kiwi-modules/blob/main/tests/test_render.py)
renders machines and checks what lands in the bundle. Add a test that renders
a machine with your module and checks the parts that matter: the container,
its secrets kept out of the unit, the nginx block. Run the tests as
described in [Development](development.md#tests), and add a section to
`CHANGELOG.md` for the release that brings the module.

## Going further

- **A configuration file.** Add a template, for example `config.toml.j2`,
  under `templates:` with a key of your choice, and say under `outputs:` where
  it goes and with which mode. Mount it into the container from there.
- **Passwords.** A setting of type `secret` with `generate: true` is derived
  from the seed when the machine file leaves it empty. Under podman it never
  appears in a unit file.
- **A unit on the host.** An output with `kind: host_unit` becomes a systemd
  unit on the machine itself, for timers and scripts that must run outside a
  container.
- **Rules that refuse bad settings.** `validate:` stops the render with your
  message when a combination of settings cannot work.

Every key is in the [module.yaml reference](module-yaml.md).
