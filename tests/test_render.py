"""kiwi-modules renders a bundle from a one-machine file. The golden sh3
under tests/golden/sh3 is kiwi-server's: the same machine, rendered from a
fleet there and from a machine file here, must give the same bytes (the
secrets derive from the same seed). Run: python3 -m unittest discover -s tests
"""
import base64
import contextlib
import difflib
import hashlib
import io
import json
import os
import shlex
import re
import shutil
import subprocess
import time
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "lib"))

import yaml  # noqa: E402

from kiwimodules import VERSION, cli, machine, modules, quadlet, resolver  # noqa: E402
from kiwimodules.util import KiwiError  # noqa: E402

GOLDEN = os.path.join(HERE, "golden")
SEED = b"kiwi-golden-seed-0123456789abcdef"      # 32 bytes, never used for a real machine
CA_PEM = "-----BEGIN CERTIFICATE-----\nR09MREVOLUNBLU5PVC1BLVJFQUwtQ0VSVA==\n-----END CERTIFICATE-----\n"
KEY_PEM = "-----BEGIN PRIVATE KEY-----\nR09MREVOLUtFWS1OT1QtUkVBTA==\n-----END PRIVATE KEY-----\n"
WG = "[Interface]\nPrivateKey = Z29sZGVuLXByaXZhdGUta2V5LW5vdC1yZWFsLTAwMDAwMDAwMDA=\nAddress = %s/24\nDNS = 10.8.0.1\n\n[Peer]\nPublicKey = Z29sZGVuLXNlcnZlci1wdWJsaWMta2V5LW5vdC1yZWFsLTAwMDA=\nAllowedIPs = 0.0.0.0/0\nEndpoint = vpn.example.org:51820\n"
TLS = {"tls_fullchain": "secrets/golden-fullchain.pem", "tls_privkey": "secrets/golden-privkey.pem"}
RECORDS = [["10.8.0.1", "gate.home"], ["10.8.0.1", "wg.gate.home"], ["10.8.0.1", "pihole.gate.home"],
           ["10.8.0.6", "m1.home"], ["10.8.0.6", "pihole.m1.home"], ["10.8.0.6", "dl.m1.home"],
           ["10.8.0.6", "jd.m1.home"], ["10.8.0.6", "portainer.m1.home"],
           ["10.8.0.25", "sh3.home"], ["10.8.0.25", "cloud.sh3.home"], ["10.8.0.25", "vault.sh3.home"],
           ["10.8.0.25", "portainer.sh3.home"], ["10.8.0.9", "min.home"]]
SH3 = {"name": "sh3", "domain": "home", "target": "ucore", "timezone": "Europe/Berlin", "admin": {"user": "core"},
       "role": "node", "node": {"preset": "cloud", "cloud": {"admin_password": "golden-nc-admin", "collabora": True,
                                                            "talk": True}, "reverse-proxy": dict(TLS)},
       "dns_records": RECORDS, "master_ip": "10.8.0.1", "ca_cert": "ca.pem", "seed": "secrets/seed"}
MACHINES = {
    "gate": {"name": "gate", "domain": "home", "target": "debian", "timezone": "Europe/Berlin", "admin": {"user": "admin"},
             "role": "master", "master": {
                 "vpn-client": {"vpn_provider": "mullvad", "wireguard_private_key": "golden-mullvad-key",
                                "wireguard_addresses": "10.66.1.2/32", "server_countries": "Germany"},
                 "vpn-server": {"wg_host": "vpn.example.org", "wg_password": "golden-wg-password"},
                 "dns": {"pihole_password": "golden-pihole-master"}, "reverse-proxy": dict(TLS)},
             "seed": "secrets/seed"},
    "m1": {"name": "m1", "domain": "home", "role": "node", "node": {
               "preset": "gateway", "pub_iface": "eth0", "dns": {"pihole_password": "golden-pihole-m1"},
               "modules": ["vpn-client", "dns", "dhcp-relay", "reverse-proxy", "downloader", "gateway", "portainer", "sftp"],
               "downloader": {"download_dir": "/mnt/dl", "transmission_password": "golden-transmission"},
               "sftp": {"sftp_password": "golden-sftp"}, "reverse-proxy": dict(TLS)},
           "master_ip": "10.8.0.1", "seed": "secrets/seed"},
    "min": {"name": "min", "domain": "home", "target": "coreos", "role": "node",
            "node": {"preset": "minimal", "reverse-proxy": dict(TLS)}, "seed": "secrets/seed"},
    # a semi-public hub on a master: its own relay for the hub, Armory's chat on public relays
    "hub1": {"name": "hub1", "domain": "home", "target": "debian", "role": "master", "master": {
                 "modules": ["vpn-client", "vpn-server", "dns", "tor", "reverse-proxy", "nostr-relay", "hub"],
                 "vpn-client": {"vpn_provider": "mullvad", "wireguard_private_key": "golden-mullvad-key",
                                "wireguard_addresses": "10.66.1.2/32", "server_countries": "Germany"},
                 "vpn-server": {"wg_host": "vpn.example.org"}, "reverse-proxy": dict(TLS),
                 "nostr-relay": {"relay_name": "Golden relay"},
                 "hub": {"public_relays": ["wss://nos.lol"], "public_mounts": ["uplink"], "account_mounts": ["tradingpost"],
                         "space_relays": ["outpost=wss://relay.hub1.home"]}},
             "seed": "secrets/seed"},
}
ADDRESSES = {"m1": "10.8.0.6", "sh3": "10.8.0.25", "min": "10.8.0.9"}


def as_text(data):
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        import base64
        return "base64:" + base64.b64encode(data).decode()


def read(out, rel):
    with open(os.path.join(out, rel)) as f:
        return f.read()


class TestRender(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="kiwi-modules-")
        os.makedirs(os.path.join(self.tmp, "secrets"), mode=0o700)
        with open(os.path.join(self.tmp, "secrets", "seed"), "wb") as f:
            f.write(SEED)
        with open(os.path.join(self.tmp, "secrets", "golden-fullchain.pem"), "w") as f:
            f.write(CA_PEM)
        with open(os.path.join(self.tmp, "secrets", "golden-privkey.pem"), "w") as f:
            f.write(KEY_PEM)
        with open(os.path.join(self.tmp, "ca.pem"), "w") as f:
            f.write(CA_PEM)
        for name, addr in ADDRESSES.items():
            with open(os.path.join(self.tmp, "secrets", "%s.home.conf" % name), "w") as f:
                f.write(WG % addr)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write(self, name, data):
        p = os.path.join(self.tmp, name + ".yaml")
        with open(p, "w") as f:
            yaml.safe_dump(data, f, sort_keys=False)
        return p

    def render(self, name, data):
        out = os.path.join(self.tmp, name + ".bundle")
        self.assertEqual(cli.main(["render", self.write(name, data), "-o", out]), 0)
        return out

    def stack_of(self, data, ready=None, runtime="podman", moving=None, leased=None):
        """(spec, bundle) of a machine file's data, with parts kept ready ({part: (settings, files)})."""
        from kiwimodules import machine as machinemod, profiles as profmod
        data = dict(data)
        data[data["role"]] = dict(data[data["role"]], runtime=runtime)
        m = machinemod.load(self.write(data["name"], data))
        profile = profmod.discover()[m.role]
        ms = modules.discover()
        resolver.resolve_settings(profile, m, ms)
        spec = resolver.stack_spec(m, profile, m.dns_records, master_ip=m.master_ip, ca_cert=m.ca_cert, ready=ready,
                                   moving=moving, leased=leased)
        return m, modules.Renderer(ms).render(spec)

    def test_a_part_with_a_standby_runs_by_its_permission(self):
        """kiwi-server's permissions (docs/design/authority.md, step 2): a part of this machine that
        has a standby is everything it was (site, backup, units), but nothing starts it except its
        permission: no `up`, no boot. A part named that the machine does not run is left out."""
        src = dict(MACHINES["min"], name="quince")
        src["node"] = dict(src["node"], modules=["vpn-client", "reverse-proxy", "firefox-sync"])
        with open(os.path.join(self.tmp, "secrets", "quince.home.conf"), "w") as f:
            f.write(WG % "10.8.0.30")
        from kiwimodules import manifest
        for runtime in ("podman", "docker"):
            _m, plain = self.stack_of(src, runtime=runtime)
            m, b = self.stack_of(src, runtime=runtime, leased=["firefox-sync", "gitea"])
            self.assertEqual(b.leased_parts, {"firefox-sync": ["kn-ffsync", "kn-ffsync-db"]})
            self.assertEqual(b.services, plain.services)                                  # still its own
            self.assertEqual(b.compose["services"]["kn-ffsync"]["profiles"], [modules.LEASED])
            self.assertEqual(b.compose["services"]["kn-ffsync"]["restart"], "on-failure")      # no daemon start starts it
            self.assertEqual(plain.compose["services"]["kn-ffsync"]["restart"], "unless-stopped")
            self.assertNotIn("profiles", b.compose["services"]["kn-nginx"])
            self.assertEqual(b.files.get("kn-nginx/nginx.conf"), plain.files.get("kn-nginx/nginx.conf"))   # its site stays
            self.assertEqual(plain.leased_parts, {})
            if runtime == "podman":
                self.assertNotIn("[Install]", b.quadlets["kn-ffsync.container"])         # no boot starts it
                self.assertIn("[Install]", plain.quadlets["kn-ffsync.container"])
            self.assertIn("KS_STACK_LEASED=", "\n".join(manifest.stack_vars(m, b)))
            self.assertIn("kn-ffsync-db", [x for x in manifest.stack_vars(m, b) if x.startswith("KS_STACK_LEASED=")][0])
            self.assertFalse([x for x in manifest.stack_vars(m, plain) if x.startswith("KS_STACK_LEASED=")])

    def test_a_part_kept_ready_is_made_and_not_started(self):
        """A standby keeps a part ready (kiwi-server keep_ready): its containers are made from the
        settings and secrets of the machine it runs on, in a profile no apply starts; it gets no
        site, unit, port or backup there, and moves no other container's address."""
        src = dict(MACHINES["min"], name="quince")
        src["node"] = dict(src["node"], modules=["vpn-client", "reverse-proxy", "firefox-sync"])
        with open(os.path.join(self.tmp, "secrets", "quince.home.conf"), "w") as f:
            f.write(WG % "10.8.0.30")
        there, there_bundle = self.stack_of(src)
        part = (there.module_settings["firefox-sync"], {k: v for k, v in there.module_files.items() if k.startswith("firefox-sync/")})
        sync_name = "ffsync.quince.home"
        part[0]["sync_hostname"] = sync_name             # (kiwi-server keeps the name the part has where it runs)
        for runtime in ("podman", "docker"):
            plain_m, plain = self.stack_of(MACHINES["min"], runtime=runtime)
            m, b = self.stack_of(MACHINES["min"], {"firefox-sync": part}, runtime=runtime)
            self.assertEqual(b.modules, plain.modules)                                    # its own parts as before
            self.assertEqual(b.ready, ["firefox-sync"])
            self.assertEqual(b.services, plain.services)
            self.assertEqual(b.ready_services, ["kn-ffsync", "kn-ffsync-db"])
            self.assertEqual({k: v for k, v in b.container_ips.items() if k != "firefox-sync"}, plain.container_ips)
            svc = b.compose["services"]["kn-ffsync"]
            self.assertEqual(svc["profiles"], [modules.READY])
            # the secrets of the machine it runs on, not this one's
            token = lambda env: [e for e in env if str(e).startswith("SYNC_MASTER_SECRET=")]    # noqa: E731
            mine = token(there_bundle.compose["services"]["kn-ffsync"]["environment"])
            self.assertTrue(mine)
            self.assertEqual(token(svc["environment"]), mine)
            nginx = b.files["kn-nginx/nginx.conf"][0] if "kn-nginx/nginx.conf" in b.files else ""
            self.assertNotIn("ffsync", nginx)                                             # no site of its own here
            # the proxy as it is once the part runs here: its site, at its address here
            later = b.files["kn-nginx/nginx-ready.conf"][0]
            self.assertIn("server_name %s;" % sync_name, later)
            self.assertIn("http://kn-ffsync:8000", later)                                 # by its container's name
            self.assertNotIn("kn-nginx/nginx-ready.conf", plain.files)
            self.assertEqual((b.units, b.ports, b.urls), (plain.units, plain.ports, plain.urls))
            self.assertIn(svc["image"], b.images)                                        # its image is pulled
            self.assertEqual(b.vpn_dependents, plain.vpn_dependents)                     # a VPN restart starts none of it
            if runtime == "podman":
                q = b.quadlets["kn-ffsync.container"]
                self.assertNotIn("[Install]", q)                                         # nothing starts it
                self.assertIn("[Install]", b.quadlets["kn-nginx.container"])
        with self.assertRaisesRegex(KiwiError, "keeps firefox-sync ready, but has no reverse-proxy"):
            bare = dict(MACHINES["min"], name="bare")
            bare["node"] = {"preset": "minimal", "modules": []}
            self.stack_of(bare, {"firefox-sync": part})

    def test_the_names_of_parts_that_can_move_are_in_a_file_of_their_own(self):
        """A part kept ready on another machine may be switched there: Pi-hole serves its name from a
        hosts file of its own, which the switch rewrites in a moment (dnsmasq reloads it by itself)."""
        m1 = dict(MACHINES["m1"], dns_records=RECORDS)
        _m, plain = self.stack_of(m1)
        _m, b = self.stack_of(m1, moving=["vault.sh3.home"])
        env = lambda bundle: next(e for e in bundle.compose["services"]["kn-pihole"]["environment"]    # noqa: E731
                                  if str(e).startswith("FTLCONF_dns_hosts="))
        self.assertIn("vault.sh3.home", env(plain))
        self.assertNotIn("vault.sh3.home", env(b))
        self.assertIn("cloud.sh3.home", env(b))                                 # the others as before
        hosts = b.files["kn-pihole/moving/kiwi.hosts"][0]
        self.assertIn("\n10.8.0.25 vault.sh3.home\n", hosts)
        self.assertNotIn("cloud.sh3.home", hosts)
        lines = next(e for e in b.compose["services"]["kn-pihole"]["environment"] if str(e).startswith("FTLCONF_misc_dnsmasq_lines="))
        self.assertIn("hostsdir=/etc/kiwi-moving", lines)
        self.assertIn("/etc/kiwi-moving:ro", " ".join(b.compose["services"]["kn-pihole"]["volumes"]))
        self.assertIn("kn-pihole/moving", b.dirs)
        self.assertNotIn("kn-pihole/moving/kiwi.hosts", plain.files)

    def test_a_part_says_how_it_is_named(self):
        """named_by: the setting that holds a part's name and its own word (kiwi-server names a part
        by service and keeps the name when it moves)."""
        ms = modules.discover()
        named = {name: m.named_by for name, m in ms.modules.items() if m.named_by}
        self.assertEqual(named["paste"], {"setting": "paste_domain", "word": "paste", "url": False})
        self.assertEqual(named["vault"], {"setting": "vault_domain", "word": "vault", "url": True})
        self.assertEqual(named["cloud"]["setting"], "nc_hostname")
        for name, nb in named.items():                    # the setting exists, and the word is the default name's
            keys = {x.key for x in ms.modules[name].settings}
            self.assertIn(nb["setting"], keys, name)
            self.assertIn("'%s.' ~ hostname" % nb["word"], open(os.path.join(ms.modules[name].dir, "module.yaml")).read(), name)
        # every part with a page of its own under a name setting says so
        self.assertGreaterEqual(len(named), 14)

    def test_tor_never_leaves_on_a_home_line_unless_chosen(self):
        """A master at home without a VPN exit, and a node without a VPN client: their Tor gets no
        network. A master at a hoster, a node behind its VPN client, or the owner's choice: it runs."""
        def tor(name, machine):
            out = self.render(name, machine)
            with open(os.path.join(out, "docker-compose.yml")) as f:
                return yaml.safe_load(f)["services"]
        home = json.loads(json.dumps(MACHINES["hub1"]))
        home["master"]["at_home"] = True
        home["master"]["modules"] = [m for m in home["master"]["modules"] if m != "vpn-client"]
        home["master"].pop("vpn-client", None)
        self.assertEqual(tor("hub-home", home)["km-tor"]["network_mode"], "none")
        home["master"]["tor"] = dict(home["master"].get("tor") or {}, without_vpn=True)
        self.assertEqual(tor("hub-home-chosen", home)["km-tor"]["network_mode"], "service:km-vpn-server")
        away = json.loads(json.dumps(MACHINES["hub1"]))
        away["master"]["modules"] = [m for m in away["master"]["modules"] if m != "vpn-client"]
        away["master"].pop("vpn-client", None)
        self.assertEqual(tor("hub-away", away)["km-tor"]["network_mode"], "service:km-vpn-server")   # a hoster's line
        node = json.loads(json.dumps(MACHINES["min"]))
        node["node"]["modules"] = ["vpn-client", "reverse-proxy", "tor"]
        node["node"]["vpn-client"] = {"vpn_provider": "mullvad", "wireguard_private_key": "k", "wireguard_addresses": "10.66.1.2/32"}
        node["vpn_ip"] = "10.8.0.9"
        self.assertEqual(tor("min-tor", node)["kn-tor"]["network_mode"], "service:kn-vpn-client")    # behind its VPN

    def test_a_ring_on_the_master_answers_the_homes_addresses_only(self):
        hub = json.loads(json.dumps(MACHINES["hub1"]))
        hub["master"]["modules"] = hub["master"]["modules"] + ["tang"]
        hub["master"]["tang"] = {"rings": {"away": "7501"}}
        hub["master"]["vpn-server"] = dict(hub["master"]["vpn-server"], local_rings={"away": "7501"})
        out = self.render("hub-away", hub)
        with open(os.path.join(out, "docker-compose.yml")) as f:
            services = yaml.safe_load(f)["services"]
        tang = services["km-tang-away"]
        self.assertEqual(tang["network_mode"], "service:km-vpn-server")          # in the VPN server's namespace
        self.assertNotIn("ports", tang)
        self.assertIn("TANG_PORT=7501", tang["environment"])
        self.assertIn("7501:7501/tcp", " ".join(services["km-vpn-server"]["ports"]))
        start = [os.path.join(d, f) for d, _ds, fs in os.walk(out) for f in fs if f == "start.sh" and "vpn-server" in d][0]
        with open(start) as f:
            script = f.read()
        self.assertIn("-A INPUT -i eth0 -p tcp --dport 7501 -m conntrack --ctstate NEW -j KIWI_RELAY", script)
        self.assertIn("-A INPUT -i eth0 -p tcp --dport 7501 -m conntrack --ctstate NEW -j DROP", script)
        self.assertIn("relay_gate()", script)                                     # the gate of enrolled machines' addresses
        self.assertEqual(subprocess.run(["bash", "-n", start]).returncode, 0)

    def test_a_node_whose_master_has_a_standby_switches_its_tunnel(self):
        def files(out):
            return {os.path.relpath(os.path.join(d, f), out) for d, _ds, fs in os.walk(out) for f in fs}
        node = json.loads(json.dumps(MACHINES["min"]))
        plain = files(self.render("min-plain", node))
        self.assertFalse([f for f in plain if "master-switch" in f])            # no standby: nothing of it
        node["node"]["vpn-client"] = dict(node["node"].get("vpn-client") or {},
                                          standby_endpoints=["198.51.100.9:51820:41022", "192.168.2.70:51820:41022"],
                                          standby_ping="10.8.0.1")
        out = self.render("min-standby", node)
        found = files(out)
        script = [f for f in found if f.endswith("kn-vpn-client/master-switch.sh")]
        self.assertTrue(script, sorted(found))
        self.assertTrue([f for f in found if f.endswith("kn-master-switch.service")], sorted(found))
        path = os.path.join(out, script[0])
        self.assertEqual(subprocess.run(["bash", "-n", path]).returncode, 0)
        with open(path) as f:
            text = f.read()
        self.assertIn("endpoints=(198.51.100.9:51820:41022 192.168.2.70:51820:41022 )", text)
        self.assertIn("ping_to=10.8.0.1", text)
        self.assertIn("systemctl restart kn-vpn-client.service", text)
        # run: the master's VPN goes, its machine stays; the return fails and the next waits longer
        t = os.path.join(self.tmp, "switch")
        os.makedirs(os.path.join(t, "bin"))
        conf = os.path.join(t, "wg0.conf")
        with open(conf, "w") as f:
            f.write("[Peer]\nEndpoint = 198.51.100.9:51820\n")
        stubs = {
            # the tunnel answers when the address it goes to is in `alive`
            "podman": 'e=$(sed -n "s/^Endpoint *= *//p" "$KIWI_SWITCH_CONF"); grep -qx "${e%%:*}" "$T/alive"',
            "systemctl": 'echo "restart $(sed -n "s/^Endpoint *= *//p" "$KIWI_SWITCH_CONF")" >> "$T/log"',
            "timeout": 'grep -qx "$5" "$T/ssh" && echo SSH-2.0',
            "logger": 'shift 2; echo "$*" >> "$T/log"',
            # each check: a step of the story, and the end of it
            "sleep": 'n=$(( $(cat "$T/n" 2>/dev/null || echo 0) + 1 )); echo $n > "$T/n"\n'
                     'case $n in 2) echo 192.168.2.70 > "$T/alive";; 70) echo 198.51.100.9 > "$T/alive";; 150) exit 99;; esac\n'
                     '[ $n -ge 150 ] && kill $PPID',
        }
        for name, body in stubs.items():
            with open(os.path.join(t, "bin", name), "w") as f:
                f.write("#!/bin/bash\n" + body + "\n")
            os.chmod(os.path.join(t, "bin", name), 0o755)
        with open(os.path.join(t, "alive"), "w") as f:
            f.write("198.51.100.9\n")
        with open(os.path.join(t, "ssh"), "w") as f:
            f.write("198.51.100.9\n")
        subprocess.run(["bash", path, "watch"], env=dict(os.environ, PATH=os.path.join(t, "bin") + ":" + os.environ["PATH"],
                       T=t, KIWI_SWITCH_CONF=conf, KIWI_SWITCH_STATE=os.path.join(t, "state"), KIWI_SWITCH_EVERY="0"),
                       capture_output=True, timeout=60)
        with open(os.path.join(t, "log")) as f:
            log = f.read()
        moves = re.findall(r"^restart (\S+)$", log, re.M)
        # down: to the standby; its machine answers 20 checks: back; down again: away; back after 40: and it works
        self.assertEqual(moves, ["192.168.2.70:51820", "198.51.100.9:51820", "192.168.2.70:51820", "198.51.100.9:51820"], log)
        self.assertIn("the next return to the master waits 0 minutes", log)       # doubled (0 s checks here)
        with open(conf) as f:
            self.assertIn("Endpoint = 198.51.100.9:51820", f.read())

    def test_vpn_false_never_drops_the_vpn_client_a_module_sends_its_traffic_through(self):
        """The downloader, the gateway and BTCPay leave through the VPN client: on a machine with no
        VPN they need a commercial one listed, not a silent drop (their traffic would leave at home)."""
        from kiwimodules import modules
        from kiwimodules.util import KiwiError
        ms = modules.discover()
        self.assertEqual(ms.resolve(["cloud"], without=("vpn-client",))[-1], "cloud")      # the mesh only: fine          # the mesh only: fine
        for m in ("downloader", "gateway", "btcpay"):
            with self.assertRaisesRegex(KiwiError, "%s sends its traffic out through vpn-client.*vpn_provider" % m):
                ms.resolve([m], without=("vpn-client",))
        # listed, as a commercial VPN's exit: it stays
        self.assertIn("vpn-client", ms.resolve(["vpn-client", "downloader"], without=("vpn-client",)))

    def test_a_machine_off_the_vpn_answers_at_its_home_address(self):
        """vpn: false (a network without a master): no VPN client, the home address stands in for
        the mesh address, and the names point there."""
        solo = {"name": "solo", "domain": "home", "target": "ucore", "role": "node",
                "network": {"dhcp": False, "address": "192.168.1.30/24"},
                "node": {"preset": "cloud", "vpn": False, "modules": ["dns", "reverse-proxy", "cloud", "vault"],
                         "reverse-proxy": dict(TLS)},
                "dns_records": [["192.168.1.30", "solo.home"], ["192.168.1.30", "cloud.solo.home"]],
                "seed": "secrets/seed"}
        out = self.render("solo", solo)
        with open(os.path.join(out, "docker-compose.yml")) as f:
            svcs = yaml.safe_load(f)["services"]
        self.assertNotIn("kn-vpn-client", svcs)
        self.assertIn("80:80", svcs["kn-nginx"]["ports"])                       # the sites answer at home
        hosts = next(e for e in svcs["kn-pihole"]["environment"] if e.startswith("FTLCONF_dns_hosts="))
        self.assertIn("192.168.1.30 cloud.solo.home", hosts)
        # the home network stands in for the mesh: what is only for "us" lets the home in
        from kiwimodules import machine as machmod, profiles
        mm = machmod.load(self.write("solo2", solo))
        resolver.resolve_settings(profiles.discover()[mm.role], mm, None)
        self.assertEqual((mm.role_settings["vpn_ip"], mm.role_settings["mesh_subnet"]), ("192.168.1.30", "192.168.1.0/24"))
        # also when the fleet has a mesh of its own in mind for later (a new network gets one): this
        # machine is on none, and its admin pages let the home in, not a mesh that does not exist
        # (found by the starter drill, 20 Nov 2026: the control page of "No master yet" said 403 at home)
        planned = dict(solo, node=dict(solo["node"], mesh_subnet="10.105.0.0/16", master_ip="10.105.0.1",
                                       modules=["dns", "reverse-proxy", "control"]))
        mm = machmod.load(self.write("solo3", planned))
        resolver.resolve_settings(profiles.discover()[mm.role], mm, None)
        self.assertEqual(mm.role_settings["mesh_subnet"], "192.168.1.0/24")
        with open(os.path.join(self.render("solo3r", planned), "kn-nginx", "nginx.conf")) as f:
            conf = f.read()
        control = conf[conf.index("server_name control.solo.home;"):]
        control = control[:control.index("\n    }\n")]
        self.assertIn("allow 192.168.1.0/24;", control)
        self.assertNotIn("10.105.", control)
        # the preset's VPN client is left out; named outright, it is refused
        bad = dict(solo, node=dict(solo["node"], modules=["vpn-client", "reverse-proxy", "cloud"]))
        ms = None
        with self.assertRaisesRegex(Exception, "vpn is false"):
            mm = machmod.load(self.write("bad", bad))
            resolver.resolve_settings(profiles.discover()[mm.role], mm, ms)
        # with no fixed address there is nothing to stand in
        moving = dict(solo, network={"dhcp": True})
        with self.assertRaisesRegex(Exception, "give it a fixed one"):
            mm = machmod.load(self.write("moving", moving))
            resolver.resolve_settings(profiles.discover()[mm.role], mm, ms)
        # off the mesh, a commercial VPN may still be its exit (Tor never leaves on the home line):
        # its VPN client is allowed then, and nothing routes the "mesh" (the home network) into it
        exit_ = dict(solo, node=dict(solo["node"], modules=["dns", "reverse-proxy", "vpn-client", "downloader"],
                                     **{"vpn-client": {"vpn_provider": "mullvad", "wireguard_private_key": "golden-mullvad-key",
                                                       "wireguard_addresses": "10.66.1.2/32"},
                                        "downloader": {"download_dir": "/srv/dl", "transmission_password": "golden-t"}}))
        out = self.render("solo-exit", exit_)
        with open(os.path.join(out, "docker-compose.yml")) as f:
            svcs = yaml.safe_load(f)["services"]
        self.assertIn("kn-vpn-client", svcs)
        self.assertEqual(svcs["kn-transmission"]["network_mode"], "service:kn-vpn-client")    # downloads leave there
        with open(os.path.join(out, "stack.sh")) as f:
            stack = f.read()
        self.assertIn("KS_STACK_MESH_SUBNET=''\nKS_STACK_MESH_VIA=''", stack)          # the home is not routed into it
        # and its tunnel is the provider's: none of the mesh's ways in are opened there
        with open(os.path.join(out, "kn-vpn-client", "post-rules.txt")) as f:
            rules = f.read()
        self.assertNotIn("PREROUTING", rules)
        self.assertNotRegex(rules, r"-A INPUT -i tun0 (?!-m state)")
        self.assertIn("-o tun0 -j MASQUERADE", rules)                                   # what leaves still does
        # Tor without any VPN: only when the owner chooses it; else its Tor gets no network at all
        tor = dict(solo, node=dict(solo["node"], modules=["dns", "reverse-proxy", "onion"]))
        out = self.render("solo-tor", tor)
        with open(os.path.join(out, "docker-compose.yml")) as f:
            self.assertEqual(yaml.safe_load(f)["services"]["kn-onion"]["network_mode"], "none")
        tor["node"] = dict(tor["node"], onion={"without_vpn": True})
        out = self.render("solo-tor-direct", tor)
        with open(os.path.join(out, "docker-compose.yml")) as f:
            onion = yaml.safe_load(f)["services"]["kn-onion"]
        self.assertNotIn("network_mode", onion)
        self.assertIn("networks", onion)                                       # its own connection, chosen
        mesh = dict(exit_, node=dict(exit_["node"], **{"vpn-client": {"wireguard_config": "x.conf"}}))
        with self.assertRaisesRegex(Exception, "only be a commercial VPN"):
            mm = machmod.load(self.write("mesh", mesh))
            resolver.resolve_settings(profiles.discover()[mm.role], mm, None)
        from kiwimodules import modules as modmod
        ms = modmod.discover()
        self.assertIn("vpn-client", ms.resolve(["cloud"], "node"))
        self.assertNotIn("vpn-client", ms.resolve(["cloud"], "node", ("vpn-client",)))

    def test_sh3_matches_kiwi_servers_golden_bundle(self):
        out = self.render("sh3", SH3)
        gdir = os.path.join(GOLDEN, "sh3")
        problems, modes = [], []
        for dp, _dn, fns in os.walk(gdir):
            for fn in fns:
                rel = os.path.relpath(os.path.join(dp, fn), gdir)
                if rel == "meta.txt":
                    continue
                p = os.path.join(out, rel)
                if not os.path.isfile(p):
                    problems.append("%s: not rendered" % rel)
                    continue
                with open(os.path.join(gdir, rel)) as f:
                    expected = f.read()
                with open(p, "rb") as f:
                    got = as_text(f.read())
                if rel == "stack.sh":
                    expected = expected.replace("KS_VERSION='VERSION'", "KS_VERSION='kiwi-modules %s'" % VERSION)
                if expected != got:
                    diff = difflib.unified_diff(expected.splitlines(), got.splitlines(), "golden/sh3/" + rel,
                                                "rendered", lineterm="", n=2)
                    problems.append("\n".join(list(diff)[:40]))
        self.assertEqual(problems, [], "\n\n".join(problems))
        for dp, _dn, fns in os.walk(out):
            for fn in fns:
                p = os.path.join(dp, fn)
                rel = os.path.relpath(p, out)
                self.assertTrue(os.path.isfile(os.path.join(gdir, rel)), "%s: rendered but not golden" % rel)
                if not rel.startswith(("host-units/", "quadlets/")) and rel != "stack.sh":
                    modes.append("%s:%04o" % (rel, os.stat(p).st_mode & 0o777))
        with open(os.path.join(gdir, "meta.txt")) as f:
            self.assertEqual("modes: " + " ".join(sorted(modes)), f.readline().strip())

    def test_the_manifest_names_the_seed_this_one_replaced(self):
        from unittest import mock
        name, data = next(iter(MACHINES.items()))
        with open(os.path.join(self.render(name, data), "stack.sh")) as f:
            sh = f.read()
        self.assertRegex(sh, r"KS_SEED_ID='[0-9a-f]{12}'")
        self.assertNotIn("KS_SEED_FROM", sh)                     # a machine file knows no older seed
        with mock.patch.object(machine.Secrets, "seed_from", lambda _s: "0123456789ab", create=True):
            with open(os.path.join(self.render(name + "-again", data), "stack.sh")) as f:
                self.assertIn("KS_SEED_FROM='0123456789ab'", f.read())

    def test_every_preset_renders_a_bundle_kiwi_stack_takes(self):
        for name, data in MACHINES.items():
            out = self.render(name, data)
            self.assertTrue(os.path.isfile(os.path.join(out, "stack.sh")), name)
            self.assertTrue(os.path.isfile(os.path.join(out, "quadlets", "kiwi-stack.target")), name)
            self.assertTrue(os.path.isfile(os.path.join(out, "docker-compose.yml")), name)
            with open(os.path.join(out, "stack.sh")) as f:
                sh = f.read()
            for var in ("KS_STACK_DIR=", "KS_STACK_MODULES=(", "KS_STACK_QUADLETS=(", "KS_STACK_IMAGES=(",
                        "KS_SEED_ID='", "KS_STACK=1"):
                self.assertIn(var, sh, name)
            self.assertEqual(subprocess.run(["bash", "-n", os.path.join(out, "stack.sh")]).returncode, 0, name)
            if shutil.which("shellcheck"):
                r = subprocess.run(["shellcheck", "-S", "warning", "-s", "bash", os.path.join(out, "stack.sh")],
                                   capture_output=True, text=True)
                self.assertEqual(r.returncode, 0, r.stdout)
            for dp, _dn, fns in os.walk(os.path.join(out, "quadlets")):
                for fn in fns:
                    with open(os.path.join(dp, fn)) as f:
                        self.assertTrue(f.readline().startswith("# kiwi-server stack"), "%s/%s: no marker" % (name, fn))

    def test_a_hub_on_a_master_uses_its_own_relay(self):
        out = self.render("hub1", MACHINES["hub1"])
        with open(os.path.join(out, "docker-compose.yml")) as f:
            compose = f.read()
        self.assertIn("HUB_RELAYS=wss://relay.hub1.home", compose)
        self.assertIn("HUB_ACCOUNT_MOUNTS=tradingpost", compose)
        self.assertNotIn("HUB_REQUIRE_ACCOUNT", compose, "not said: the distribution's own policy stands")
        self.assertIn("HUB_SPACE_RELAYS=outpost=wss://relay.hub1.home", compose)
        self.assertIn("HUB_PUBLIC_RELAYS=wss://nos.lol", compose)
        self.assertIn("HUB_PUBLIC_MOUNTS=uplink", compose)
        self.assertIn("HUB_RELAYS_LOCKED=true", compose)
        self.assertIn("HUB_REQUIRE_HUB=true", compose)
        with open(os.path.join(out, "km-nginx", "nginx.conf")) as f:
            nginx = f.read()
        self.assertIn("server_name relay.hub1.home;", nginx)
        self.assertIn("server_name hub.hub1.home;", nginx)
        with open(os.path.join(out, "km-nostr-relay", "strfry.conf")) as f:
            strfry = f.read()
        self.assertIn('name = "Golden relay"', strfry)
        self.assertIn("maxEventSize = 262144", strfry)
        # keep_days 0 is "no limit": strfry reads 0 as "nothing older than now", and refused a note dated
        # five seconds back, so a phone's slow clock or a sealed message dated back on purpose never got in
        self.assertIn("rejectEventsOlderThanSeconds = 3153600000", strfry)
        import copy
        kept = copy.deepcopy(MACHINES["hub1"])
        kept["master"]["nostr-relay"] = dict(kept["master"].get("nostr-relay") or {}, keep_days=30)
        with open(os.path.join(self.render("hub1-kept", kept), "km-nostr-relay", "strfry.conf")) as f:
            self.assertIn("rejectEventsOlderThanSeconds = 2592000\n", f.read())
        # a hub with nothing to name as its relay, and public mounts without public relays, are refused
        master = MACHINES["hub1"]["master"]
        norelay = {k: v for k, v in master.items() if k != "nostr-relay"}
        norelay["modules"] = [m for m in master["modules"] if m != "nostr-relay"]
        self.assertNotEqual(cli.main(["render", self.write("hub1-norelay", dict(MACHINES["hub1"], master=norelay)),
                                      "-o", os.path.join(self.tmp, "norelay.bundle")]), 0)
        # and so is a space's relays line without the space's id
        odd = dict(MACHINES["hub1"], master=dict(master, hub={"space_relays": ["wss://relay.hub1.home"]}))
        self.assertNotEqual(cli.main(["render", self.write("hub1-oddspace", odd), "-o", os.path.join(self.tmp, "oddspace.bundle")]), 0)

    def test_the_machines_own_name_leads_to_its_status_page(self):
        node = json.loads(json.dumps(SH3))
        node["node"].pop("cloud", None)                 # a machine with no site of its own: only its page
        node["node"]["preset"] = "minimal"
        node["vpn_ip"] = "10.8.0.31"
        out = self.render("sh3-own", node)
        with open(os.path.join(out, "kn-nginx", "nginx.conf")) as f:
            self.assertNotIn("return 302", f.read())                 # no status page in the network: nothing there
        node["node"]["reverse-proxy"] = dict(node["node"].get("reverse-proxy") or {},
                                             machine_page="https://status.papaya.home/?machine=sh3")
        out = self.render("sh3-own-page", node)
        with open(os.path.join(out, "kn-nginx", "nginx.conf")) as f:
            nginx = f.read()
        block = nginx.split("server_name sh3.home;", 1)[1].split("}", 2)
        self.assertIn("return 302 https://status.papaya.home/?machine=sh3;", block[0] + block[1])
        self.assertNotIn("/.well-known/kiwi", nginx)                  # no registry named: none
        with open(os.path.join(out, "docker-compose.yml")) as f:          # the page answers at the mesh address too
            ports = next(l for l in f.read().splitlines() if "FIREWALL_VPN_INPUT_PORTS=" in l)
        self.assertIn("443", ports.split("=", 1)[1].split(","))
        # the registry: at the machine's name and at its address on the LAN, for an app that scans
        node["node"]["reverse-proxy"]["machine_registry"] = "https://status.papaya.home/api/registry?machine=sh3"
        out = self.render("sh3-own-registry", node)
        with open(os.path.join(out, "kn-nginx", "nginx.conf")) as f:
            nginx = f.read()
        self.assertEqual(nginx.count("location = /.well-known/kiwi {\n            return 302 https://status.papaya.home/api/registry?machine=sh3;"), 2)
        default = nginx.split("server_name _;", 2)[2].split("\n    }", 1)[0]          # the TLS default server
        self.assertIn("return 444;", default)
        self.assertIn("/.well-known/kiwi", default)

    def test_a_hub_on_a_node_keeps_its_data_at_home(self):
        """The master routes; the hub and its relay can live on a node like any service with data."""
        from kiwimodules import modules as modmod, profiles
        node = json.loads(json.dumps(SH3))
        node["node"].pop("preset", None)
        node["node"].pop("cloud", None)
        node["node"]["modules"] = ["vpn-client", "reverse-proxy", "nostr-relay", "hub"]
        node["node"]["nostr-relay"] = {"relay_name": "Home relay"}
        out = self.render("sh3-hub", node)
        with open(os.path.join(out, "docker-compose.yml")) as f:
            compose = f.read()
        self.assertIn("HUB_RELAYS=wss://relay.sh3.home", compose)
        self.assertIn("kn-nostr-relay", compose)
        with open(os.path.join(out, "kn-nginx", "nginx.conf")) as f:
            nginx = f.read()
        self.assertIn("server_name relay.sh3.home;", nginx)
        self.assertIn("server_name hub.sh3.home;", nginx)
        # public names: handed on by the master, the certificate and the data stay on the node
        node["node"]["reverse-proxy"] = dict(TLS, public=True, via="10.8.0.1")
        node["node"]["hub"] = {"hub_domain": "hub.example.org"}
        node["node"]["nostr-relay"] = {"relay_name": "Home relay", "relay_domain": "relay.example.org"}
        node["vpn_ip"] = "10.8.0.25"
        mm = machine.load(self.write("sh3-hub-public", node))
        profile = profiles.discover()[mm.role]
        ms = modmod.discover()
        resolver.resolve_settings(profile, mm, ms)
        spec = resolver.stack_spec(mm, profile, mm.dns_records, master_ip=mm.master_ip, ca_cert=mm.ca_cert, lan_addresses=mm.lan_addresses)
        names, _ports = modmod.Renderer(ms).exposure(spec)
        self.assertEqual(sorted(names), ["hub.example.org", "relay.example.org"])

    def public_hub(self, **proxy):
        master = dict(MACHINES["hub1"]["master"], **{"reverse-proxy": dict(TLS, public=True, **proxy)})
        master["hub"] = dict(master["hub"], hub_domain="hub.example.org")
        master["nostr-relay"] = dict(master["nostr-relay"], relay_domain="relay.example.org")
        return dict(MACHINES["hub1"], master=master)

    def test_the_proxy_is_asked_before_its_files_are_written(self):
        """module.yaml `preflight`: kiwi-stack asks nginx about its new config in a throwaway
        container before the stack is written (KS_STACK_CHECKS). With public names its own start
        script answers, after the stand-in certificates it also makes at a real start."""
        out = self.render("sh3-ask", json.loads(json.dumps(SH3)))
        with open(os.path.join(out, "stack.sh")) as f:
            self.assertIn("KS_STACK_CHECKS=('kn-nginx|nginx -t')", f.read())
        out = self.render("hub-ask", self.public_hub())
        with open(os.path.join(out, "stack.sh")) as f:
            self.assertIn("KS_STACK_CHECKS=('km-nginx|/bin/sh /etc/nginx/start.sh')", f.read())
        with open(os.path.join(out, "km-nginx", "start.sh")) as f:
            start = f.read()
        self.assertLess(start.index("cp /etc/nginx/fullchain.pem"), start.index('[ -z "${KIWI_CHECK:-}" ] || exec nginx -t'))
        self.assertLess(start.index("exec nginx -t"), start.index("exec nginx -g"))
        # the accounts: Kanidm's own config test, the program itself (its image has no shell)
        self.assertIn(("kn-accounts", "exec /sbin/kanidmd configtest -c /config/server.toml"),
                      [(a["service"].replace("{{ container_prefix }}", "kn"), a["run"]) for a in modules.discover().get("accounts").preflight])
        # what a module may write there
        self.assertEqual(modules.load_preflight("modules/x", [{"service": "a", "run": "b -t"}]), [{"service": "a", "run": "b -t"}])
        for bad, word in (([{"service": "a"}], "run is required"), ([{"service": "a", "run": "b", "when": "x"}], "unknown key(s): when"),
                          (["a|b"], "each entry is a mapping")):
            with self.assertRaises(KiwiError) as cm:
                modules.load_preflight("modules/x", bad)
            self.assertIn(word, str(cm.exception))

    def test_a_public_hub_opens_only_its_own_sites(self):
        out = self.render("hub2", self.public_hub())
        with open(os.path.join(out, "km-nginx", "nginx.conf")) as f:
            nginx = f.read()
        blocks = {b.split("server_name ", 1)[1].split(";", 1)[0]: b for b in nginx.split("    server {") if "server_name " in b}
        for name in ("hub.example.org", "relay.example.org"):
            self.assertIn("/etc/nginx/acme/%s/fullchain.pem" % name, blocks[name])
            self.assertNotIn("deny all", blocks[name])
        self.assertIn("location /.well-known/acme-challenge/", nginx)
        mesh_only = [n for n in blocks if n.endswith(".home")]
        self.assertTrue(any(n.startswith("wg.") for n in mesh_only), mesh_only)
        for name in mesh_only:
            self.assertIn("allow 10.8.0.0/16;", blocks[name], name)
            self.assertIn("deny all;", blocks[name], name)
        with open(os.path.join(out, "docker-compose.yml")) as f:
            compose = yaml.safe_load(f)["services"]
        self.assertIn("443:443/tcp", compose["km-vpn-server"]["ports"])
        self.assertIn("80:80/tcp", compose["km-vpn-server"]["ports"])
        self.assertEqual(compose["km-nginx"]["command"], "/bin/sh /etc/nginx/start.sh")
        with open(os.path.join(out, "km-vpn-server", "start.sh")) as f:
            self.assertIn("--sport 443 ! -d 10.8.0.0/16 -j MARK", f.read())
        with open(os.path.join(out, "kiwi", "acme.sh")) as f:
            acme = f.read()
        self.assertRegex(acme, r"for name in (hub|relay)\.example\.org (hub|relay)\.example\.org; do")
        self.assertNotIn("--staging", acme)
        self.assertIn("acme-staging", acme)                  # a test certificate does not survive leaving the test service
        self.assertIn("--register-unsafely-without-email", acme)
        self.assertIn('${account:+--account "$account"}', acme)   # certbot refuses to choose among several
        self.assertTrue(os.path.isfile(os.path.join(out, "host-units", "km-acme.timer")))
        with open(os.path.join(out, "stack.sh")) as f:
            self.assertRegex(f.read(), r"KS_STACK_PORTS=\([^)]*443/tcp")
        # a name without a certificate is asked for again soon, three times, not a day later
        work = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, work, True)
        os.makedirs(os.path.join(work, "bin"))
        os.makedirs(os.path.join(work, "nginx", "acme"))
        stub = os.path.join(work, "bin", "rt")
        with open(stub, "w") as f:          # the container runtime: nginx answers, certbot does as $CERTBOT says
            f.write('#!/bin/bash\n[ "$1" = run ] || exit 0\n[ "$CERTBOT" = ok ] || exit 1\n'
                    'for n in hub relay; do mkdir -p %s/nginx/letsencrypt/live/$n.example.org; '
                    'echo cert > %s/nginx/letsencrypt/live/$n.example.org/fullchain.pem; '
                    'echo key > %s/nginx/letsencrypt/live/$n.example.org/privkey.pem; done\n' % (work, work, work))
        with open(os.path.join(work, "bin", "systemd-run"), "w") as f:
            f.write('#!/bin/bash\necho "$@" >> %s/asked\n' % work)
        for x in ("rt", "systemd-run"):
            os.chmod(os.path.join(work, "bin", x), 0o755)
        script = os.path.join(work, "acme.sh")
        with open(script, "w") as f:
            f.write(re.sub(r"(?m)^rt=.*$", "rt=" + stub, re.sub(r"(?m)^dir=.*$", "dir=%s/nginx" % work, acme)))
        env = dict(os.environ, PATH=os.path.join(work, "bin") + os.pathsep + os.environ["PATH"])
        for _ in range(5):
            r = subprocess.run(["bash", script], env=env, capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
        with open(os.path.join(work, "asked")) as f:
            asked = f.read().splitlines()
        self.assertEqual(asked, ["--quiet --on-active=10min systemctl start km-acme.service"] * 3)
        self.assertNotIn("asking again", r.stdout)                               # the fourth and fifth: the daily run goes on
        r = subprocess.run(["bash", script], env=dict(env, CERTBOT="ok"), capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(os.path.exists(os.path.join(work, "nginx", "acme", ".tries")))      # it has them: the count starts anew
        self.assertTrue(os.path.isfile(os.path.join(work, "nginx", "acme", "hub.example.org", "fullchain.pem")))
        if shutil.which("shellcheck"):
            r = subprocess.run(["shellcheck", "-S", "warning", os.path.join(out, "kiwi", "acme.sh"),
                                os.path.join(out, "km-nginx", "start.sh")], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stdout)

    def test_a_private_hub_publishes_nothing(self):
        out = self.render("hub3", MACHINES["hub1"])
        with open(os.path.join(out, "km-nginx", "nginx.conf")) as f:
            nginx = f.read()
        self.assertNotIn("deny all", nginx)
        self.assertNotIn("acme", nginx)
        with open(os.path.join(out, "docker-compose.yml")) as f:
            compose = yaml.safe_load(f)["services"]
        self.assertFalse([p for p in compose["km-vpn-server"]["ports"] if p.split("/")[0].endswith((":80", ":443"))])
        self.assertFalse(os.path.exists(os.path.join(out, "kiwi", "acme.sh")))

    def test_staging_certificates_get_no_hsts(self):
        out = self.render("hub4", self.public_hub(acme_staging=True, acme_email="a@example.org"))
        with open(os.path.join(out, "km-nginx", "nginx.conf")) as f:
            nginx = f.read()
        block = next(b for b in nginx.split("    server {") if "server_name hub.example.org;" in b)
        self.assertNotIn("Strict-Transport-Security", block)
        with open(os.path.join(out, "kiwi", "acme.sh")) as f:
            acme = f.read()
        self.assertIn("--staging", acme)
        self.assertNotIn("grep -qs 'acme-staging'", acme)
        self.assertIn("--email a@example.org", acme)

    def test_public_needs_a_master_and_a_public_name(self):
        nameless = dict(MACHINES["hub1"], master=dict(MACHINES["hub1"]["master"], **{"reverse-proxy": dict(TLS, public=True)}))
        self.assertNotEqual(cli.main(["render", self.write("nameless", nameless), "-o", os.path.join(self.tmp, "nl.bundle")]), 0)
        node = {"name": "n2", "domain": "home", "role": "node", "seed": "secrets/seed", "master_ip": "10.8.0.1",
                "node": {"preset": "minimal", "vpn_ip": "10.8.0.31", "reverse-proxy": dict(TLS, public=True)}}
        self.assertNotEqual(cli.main(["render", self.write("n2", node), "-o", os.path.join(self.tmp, "n2.bundle")]), 0)

    def relay_files(self, name, **relay):
        master = dict(MACHINES["hub1"]["master"])
        master["nostr-relay"] = dict(master["nostr-relay"], **relay)
        out = self.render(name, dict(MACHINES["hub1"], master=master))
        with open(os.path.join(out, "km-nostr-relay", "strfry.conf")) as f:
            conf = f.read()
        return out, conf

    def ask_policy(self, out, requests):
        """The rendered write policy, run the way strfry runs it."""
        r = subprocess.run([sys.executable, os.path.join(out, "km-nostr-relay", "write-policy.py")],
                           input="\n".join(requests) + "\n", capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        return [json.loads(line) for line in r.stdout.splitlines()]

    @staticmethod
    def post(pubkey, source, content="hello", kind="new", source_type="IP4", authed=None, event_kind=1, tags=(),
             event_id="e" * 64, created_at=100):
        request = {"type": kind, "sourceType": source_type, "sourceInfo": source, "receivedAt": 1,
                   "event": {"id": event_id, "pubkey": pubkey, "kind": event_kind, "tags": list(tags), "content": content,
                             "created_at": created_at}}
        if authed:
            request["authed"] = authed
        return json.dumps(request)

    OUTSIDE, MESH_ADDRESS = "203.0.113.9", "10.8.3.5"
    ADMIN, PERSON, OTHER, BOARD = "a" * 64, "b" * 64, "c" * 64, "d" * 64
    WORKED = "00" + "f" * 62       # 8 bits of proof of work

    def signup(self, key=None, event_id=None, source=None):
        return self.post(key or self.PERSON, source or self.OUTSIDE, content="sealed", event_kind=30790, tags=[["v", "2"]],
                         event_id=event_id or self.WORKED)

    def admin_list(self, name, *keys, key=None, created_at=200):
        return self.post(key or self.ADMIN, self.OUTSIDE, event_kind=30000, created_at=created_at,
                         tags=[["d", name]] + [["p", k] for k in keys])

    def verdicts(self, answers):
        return [a["action"] for a in answers]

    def test_the_relay_takes_posts_from_the_mesh_and_admins(self):
        out, conf = self.relay_files("hub5", write_pubkeys=[self.ADMIN])
        self.assertIn('plugin = "/app/kiwi-write-policy.py"', conf)
        self.assertIn('realIpHeader = "x-real-ip"', conf)     # nginx overwrites this one; a client can pre-fill the other
        answers = self.ask_policy(out, [
            self.post(self.PERSON, self.MESH_ADDRESS),        # the mesh
            self.post(self.ADMIN, self.OUTSIDE),              # an admin, from anywhere
            self.post(self.PERSON, self.OUTSIDE),             # a stranger
            # a stranger hiding an admin's key in the content: only a parser tells them apart
            self.post(self.PERSON, self.OUTSIDE, content='"pubkey":"%s"' % self.ADMIN),
            self.post(self.PERSON, "wss://other.example", source_type="Stream"),
            "this is not json",
            '{"type":"new"}'])
        self.assertEqual(self.verdicts(answers), ["accept", "accept", "reject", "reject", "reject", "reject", "reject"])
        self.assertIn("auth-required:", answers[2]["msg"])
        self.assertEqual(answers[2]["id"], "e" * 64)

    def test_a_connection_can_prove_its_key(self):
        _out, conf = self.relay_files("hub7", relay_domain="relay.example.org")
        self.assertIn('serviceUrl = "wss://relay.example.org"', conf)
        self.assertRegex(conf, r"auth \{\s+enabled = true")

    def test_a_registered_member_writes_what_others_signed(self):
        out, _conf = self.relay_files("hub8", members="registered", register_pow=8)
        answers = self.ask_policy(out, [
            self.signup(event_id="f" * 64),                                                  # no work done
            self.signup(),
            self.post(self.BOARD, self.OUTSIDE, authed=self.PERSON, event_kind=30700),       # a board's own key
            self.post(self.BOARD, self.OUTSIDE, event_kind=30700),                           # the same, not signed in
            self.post(self.BOARD, self.OUTSIDE, authed=self.OTHER, event_kind=30700),        # signed in, no account
            self.post(self.BOARD, self.OUTSIDE, event_kind=1059, tags=[["p", self.PERSON]]), # sealed note to a member
            self.post(self.BOARD, self.OUTSIDE, event_kind=1059, tags=[["p", self.OTHER]])])  # and to nobody here
        self.assertEqual(self.verdicts(answers), ["reject", "accept", "accept", "reject", "reject", "accept", "reject"])
        self.assertIn("pow:", answers[0]["msg"])
        self.assertIn("auth-required:", answers[3]["msg"])
        self.assertIn("restricted:", answers[4]["msg"])

    def test_an_approved_relay_reads_only_until_an_admin_says_so(self):
        out, _conf = self.relay_files("hub9", members="approved", register_pow=8, write_pubkeys=[self.ADMIN])
        answers = self.ask_policy(out, [
            self.signup(),                                                                   # still stored: it asks to join
            self.post(self.PERSON, self.OUTSIDE, authed=self.PERSON),
            self.admin_list("members", self.PERSON, key=self.OTHER),                         # not an admin: refused and ignored
            self.post(self.PERSON, self.OUTSIDE, authed=self.PERSON),
            self.admin_list("members", self.PERSON),
            self.post(self.PERSON, self.OUTSIDE, authed=self.PERSON),
            self.admin_list("members", self.OTHER, created_at=150),                          # older than the one that counts
            self.post(self.PERSON, self.OUTSIDE, authed=self.PERSON),
            self.admin_list("members", self.OTHER, created_at=300),
            self.post(self.PERSON, self.OUTSIDE, authed=self.PERSON)])
        self.assertEqual(self.verdicts(answers),
                         ["accept", "reject", "reject", "reject", "accept", "accept", "accept", "accept", "accept", "reject"])
        self.assertIn("restricted:", answers[1]["msg"])

    def test_a_ban_beats_membership(self):
        out, _conf = self.relay_files("hub10", members="registered", register_pow=8, write_pubkeys=[self.ADMIN])
        answers = self.ask_policy(out, [
            self.signup(),
            self.admin_list("banned", self.PERSON),
            self.post(self.BOARD, self.OUTSIDE, authed=self.PERSON, event_kind=30700),
            self.post(self.BOARD, self.OUTSIDE, event_kind=1059, tags=[["p", self.PERSON]]),
            self.signup(),
            self.post(self.ADMIN, self.OUTSIDE, authed=self.ADMIN)])
        self.assertEqual(self.verdicts(answers), ["accept", "accept", "reject", "reject", "reject", "accept"])
        self.assertIn("banned", answers[2]["msg"])

    def test_a_retired_account_is_no_member(self):
        out, _conf = self.relay_files("hub11", members="registered", register_pow=8)
        retired = self.post(self.PERSON, self.OUTSIDE, content="", event_kind=30790, created_at=500, authed=self.PERSON,
                            tags=[["v", "2"], ["retired", "1"]])
        answers = self.ask_policy(out, [self.signup(), retired, self.post(self.PERSON, self.OUTSIDE, authed=self.PERSON)])
        self.assertEqual(self.verdicts(answers), ["accept", "accept", "reject"])

    def test_new_accounts_are_limited_per_address(self):
        out, _conf = self.relay_files("hub12", members="registered", register_pow=8, register_per_hour=2)
        answers = self.ask_policy(out, [self.signup(key=k * 64) for k in "123"] + [self.signup(key="4" * 64, source="203.0.113.77")])
        self.assertEqual(self.verdicts(answers), ["accept", "accept", "reject", "accept"])
        self.assertIn("rate-limited:", answers[2]["msg"])

    def test_the_hub_is_told_the_work_a_sign_up_costs(self):
        out, _conf = self.relay_files("hub13", register_pow=17)
        with open(os.path.join(out, "docker-compose.yml")) as f:
            self.assertIn("HUB_REGISTER_POW=17", f.read())

    def test_too_much_work_is_refused(self):
        master = dict(MACHINES["hub1"]["master"])
        master["nostr-relay"] = dict(master["nostr-relay"], register_pow=64)
        self.assertNotEqual(cli.main(["render", self.write("badpow", dict(MACHINES["hub1"], master=master)),
                                      "-o", os.path.join(self.tmp, "bp.bundle")]), 0)

    def test_open_writes_is_asked_for_by_name(self):
        out, conf = self.relay_files("hub6", open_writes=True)
        self.assertIn('plugin = ""', conf)
        self.assertRegex(conf, r"auth \{\s+enabled = false")
        self.assertFalse(os.path.exists(os.path.join(out, "km-nostr-relay", "write-policy.py")))
        with open(os.path.join(out, "docker-compose.yml")) as f:
            self.assertNotIn("kiwi-write-policy", f.read())

    def test_a_key_in_the_wrong_form_is_refused(self):
        master = dict(MACHINES["hub1"]["master"])
        master["nostr-relay"] = dict(master["nostr-relay"], write_pubkeys=["npub1abc"])
        self.assertNotEqual(cli.main(["render", self.write("badkey", dict(MACHINES["hub1"], master=master)),
                                      "-o", os.path.join(self.tmp, "bk.bundle")]), 0)

    def hub_with(self, name, **hub):
        master = dict(MACHINES["hub1"]["master"])
        master["hub"] = dict(master["hub"], **hub)
        return dict(MACHINES["hub1"], master=master)

    def cloud_with(self, name, **cloud):
        node = dict(SH3["node"])
        node["cloud"] = dict(node["cloud"], **cloud)
        return dict(SH3, node=node)

    def turn_hub(self, hub=None, **turn):
        """hub1 with the turn module, its settings `turn`, and the hub's own settings changed by `hub`."""
        master = dict(MACHINES["hub1"]["master"])
        master["modules"] = master["modules"] + ["turn"]
        if turn:
            master["turn"] = turn
        if hub:
            master["hub"] = dict(master["hub"], **hub)
        return dict(MACHINES["hub1"], master=master)

    def test_a_turn_server_relays_the_hubs_calls_from_the_hosts_own_address(self):
        out = self.render("turn1", self.turn_hub())
        with open(os.path.join(out, "docker-compose.yml")) as f:
            services = yaml.safe_load(f)["services"]
        self.assertEqual(services["km-turn"]["network_mode"], "host", "the host's address and ports, past the mesh's double hop")
        self.assertTrue(services["km-turn"]["image"].startswith("docker.io/coturn/coturn:"))
        conf = read(out, "km-turn/turnserver.conf")
        password = re.search(r"^user=kiwi:(\S+)$", conf, re.M).group(1)
        self.assertEqual(len(password), 32, "generated from the seed")
        self.assertIn("realm=vpn.example.org", conf, "the WireGuard server's public endpoint names it")
        self.assertIn("listening-port=3478", conf)
        self.assertIn("min-port=49160", conf)
        self.assertIn("max-port=49200", conf)
        self.assertNotIn("external-ip", conf)
        # never a way into the machine's own networks: the private ranges, the mesh, and the stack's own network
        for r in ("10.0.0.0-10.255.255.255", "127.0.0.0-127.255.255.255", "172.16.0.0-172.31.255.255",
                  "192.168.0.0-192.168.255.255", "100.64.0.0-100.127.255.255", "172.64.0.0-172.64.0.255"):
            self.assertIn("denied-peer-ip=%s\n" % r, conf)
        self.assertEqual(oct(os.stat(os.path.join(out, "km-turn", "turnserver.conf")).st_mode & 0o777), "0o644")
        stack = read(out, "stack.sh")
        for port in ("3478/udp", "3478/tcp", "49160-49200/udp"):
            self.assertIn("'%s'" % port, stack)
        # the hub on the same host names it to its pages, the password kept out of the unit
        env = services["km-hub"]["environment"]
        self.assertIn("HUB_ICE=stun:vpn.example.org:3478 turn:vpn.example.org:3478?transport=udp turn:vpn.example.org:3478?transport=tcp", env)
        self.assertIn("HUB_ICE_USERNAME=kiwi", env)
        self.assertIn("HUB_ICE_CREDENTIAL=" + password, env)
        self.assertNotIn(password, read(out, "quadlets/km-hub.container"))
        self.assertIn("HUB_ICE_CREDENTIAL=" + password, read(out, "kiwi/env/km-hub.env"))
        # a name of its own, behind a router, other ports
        out = self.render("turn2", self.turn_hub(turn_domain="turn.example.org", external_ip="203.0.113.7", port=3479,
                                                 relay_ports="50000-50100", username="calls"))
        conf = read(out, "km-turn/turnserver.conf")
        self.assertIn("external-ip=203.0.113.7", conf)
        self.assertIn("realm=turn.example.org", conf)
        self.assertIn("listening-port=3479", conf)
        self.assertIn("min-port=50000", conf)
        self.assertRegex(conf, r"(?m)^user=calls:\S+$")
        with open(os.path.join(out, "docker-compose.yml")) as f:
            env = yaml.safe_load(f)["services"]["km-hub"]["environment"]
        self.assertIn("HUB_ICE=stun:turn.example.org:3479 turn:turn.example.org:3479?transport=udp turn:turn.example.org:3479?transport=tcp", env)
        self.assertIn("HUB_ICE_USERNAME=calls", env)

    def test_a_turn_server_takes_a_port_range_it_can_use(self):
        for turn in ({"relay_ports": "100-200"}, {"relay_ports": "50000-49000"}, {"relay_ports": "40000-50000"},
                     {"port": 49170}, {"relay_ports": "49160"}, {"external_ip": "turn.example.org"}):
            name = "turnbad-%d" % len(os.listdir(self.tmp))
            self.assertNotEqual(cli.main(["render", self.write(name, self.turn_hub(**turn)), "-o", os.path.join(self.tmp, name + ".bundle")]),
                                0, turn)

    def test_a_turn_server_runs_on_a_master_only(self):
        node = dict(MACHINES["min"], node=dict(MACHINES["min"]["node"], modules=["vpn-client", "reverse-proxy", "turn"]))
        self.assertNotEqual(cli.main(["render", self.write("turnnode", node), "-o", os.path.join(self.tmp, "turnnode.bundle")]), 0)

    def test_a_hub_names_servers_for_calls_elsewhere_or_none(self):
        master = dict(MACHINES["hub1"]["master"], hub=dict(MACHINES["hub1"]["master"]["hub"], ice=["turn:turn.example.org:3478?transport=udp"],
                                                            ice_username="hub1", ice_credential="a-turn-login-for-hub1"))
        out = self.render("ice1", dict(MACHINES["hub1"], master=master))
        with open(os.path.join(out, "docker-compose.yml")) as f:
            env = yaml.safe_load(f)["services"]["km-hub"]["environment"]
        self.assertIn("HUB_ICE=turn:turn.example.org:3478?transport=udp", env)
        self.assertIn("HUB_ICE_USERNAME=hub1", env)
        self.assertNotIn("a-turn-login-for-hub1", read(out, "quadlets/km-hub.container"))
        # nothing named and no turn module: nothing passed, the distribution's public STUN stands
        out = self.render("ice2", MACHINES["hub1"])
        with open(os.path.join(out, "docker-compose.yml")) as f:
            env = yaml.safe_load(f)["services"]["km-hub"]["environment"]
        self.assertFalse([e for e in env if e.startswith("HUB_ICE")])
        # what is no STUN or TURN address is refused
        bad = dict(MACHINES["hub1"], master=dict(master, hub=dict(master["hub"], ice=["https://turn.example.org"])))
        self.assertNotEqual(cli.main(["render", self.write("ice3", bad), "-o", os.path.join(self.tmp, "ice3.bundle")]), 0)

    def test_the_hub_forwards_the_calendar_to_the_mesh_only(self):
        out = self.render("cal1", self.hub_with("cal1", caldav="https://cloud.sh3.home"))
        self.assertIn("HUB_CALDAV=https://cloud.sh3.home", read(out, "docker-compose.yml"))
        conf = read(out, "km-nginx/nginx.conf")
        block = conf[conf.index("location ^~ /remote.php/dav/"):]
        self.assertRegex(block[:400], r"allow 10\.\d+\.0\.0/16; deny all;")
        self.assertIn("proxy_pass $backend;", block)
        out = self.render("cal2", self.hub_with("cal2"))
        self.assertNotIn("HUB_CALDAV", read(out, "docker-compose.yml"))
        self.assertNotIn("/remote.php/dav/", read(out, "km-nginx/nginx.conf"))

    def test_a_calendar_server_with_a_path_is_refused(self):
        for bad in ("https://cloud.sh3.home/nextcloud", "cloud.sh3.home", "https://a b"):
            self.assertNotEqual(cli.main(["render", self.write("cal3", self.hub_with("cal3", caldav=bad)),
                                          "-o", os.path.join(self.tmp, "c3.bundle")]), 0, bad)

    def test_nextcloud_answers_browsers_only_on_the_listed_origins(self):
        out = self.render("cors1", self.cloud_with("cors1", cors_origins=["https://derlocke-ng.github.io", "https://hub.example.org:8443"]))
        conf = read(out, "kn-nginx/nginx.conf")
        self.assertIn('"https://derlocke-ng.github.io" $http_origin;', conf)
        self.assertIn('"https://hub.example.org:8443" $http_origin;', conf)
        block = conf[conf.index("location ^~ /remote.php/dav/"):]
        self.assertIn("return 204;", block)
        self.assertIn("always;", block[:200])
        self.assertIn('add_header X-Frame-Options "SAMEORIGIN" always;', block)      # add_header here drops the server's
        self.assertIn("proxy_set_header Host $host;", block)
        # only a browser's preflight: a DAV client's OPTIONS has to reach Nextcloud
        self.assertIn('"~^OPTIONS:.+" 1;', conf)
        self.assertNotIn("$request_method = OPTIONS", conf)
        self.assertNotIn("/remote.php/dav/ {", read(self.render("cors2", SH3), "kn-nginx/nginx.conf"))

    def test_nextcloud_reads_the_address_nginx_saw(self):
        out = self.render("addr1", SH3)
        self.assertIn("'forwarded_for_headers' => ['HTTP_X_REAL_IP']", read(out, "nextcloud-aio-nextcloud/kiwi.config.php"))
        self.assertIn("/var/www/html/config/kiwi.config.php:ro", read(out, "docker-compose.yml"))
        self.assertIn("proxy_set_header X-Real-IP $remote_addr;", read(out, "kn-nginx/nginx.conf"))

    def test_a_cors_origin_must_be_only_an_origin(self):
        for bad in ("https://x.example/path", "http://x.example", 'https://x.example" $http_origin; #'):
            self.assertNotEqual(cli.main(["render", self.write("cors3", self.cloud_with("cors3", cors_origins=[bad])),
                                          "-o", os.path.join(self.tmp, "c.bundle")]), 0, bad)

    def apps_node(self, name, **settings):
        node = {k: v for k, v in SH3["node"].items() if k in ("vpn_ip", "vpn-client", "reverse-proxy", "pub_iface")}
        node["modules"] = ["vpn-client", "reverse-proxy", "opencloud", "immich", "paperless"]
        node.update(settings)
        return self.render(name, dict(SH3, node=node))

    def test_the_three_apps_render_as_units_with_their_secrets_kept_out(self):
        out = self.apps_node("apps1")
        conf = read(out, "kn-nginx/nginx.conf")
        for name in ("opencloud", "immich", "paperless"):
            self.assertIn("server_name %s.sh3.home;" % name, conf)
        compose = read(out, "docker-compose.yml")
        self.assertIn("OC_URL=https://opencloud.sh3.home", compose)
        self.assertIn("IMMICH_MACHINE_LEARNING_URL=http://kn-immich-ml:3003", compose)
        self.assertIn("PAPERLESS_URL=https://paperless.sh3.home", compose)
        # an entrypoint of one word becomes the unit's; the script is mounted, with its own line
        unit = read(out, "quadlets/kn-opencloud.container")
        self.assertIn("PodmanArgs=--entrypoint=/bin/sh", unit)
        self.assertIn("Exec=/kiwi-start.sh", unit)
        self.assertIn("exec opencloud server", read(out, "kn-opencloud/start.sh"))
        # generated secrets go to the root-only env file, not the unit anyone can read
        for name in ("kn-opencloud", "kn-immich", "kn-immich-db", "kn-paperless", "kn-paperless-db"):
            self.assertIn("EnvironmentFile=", read(out, "quadlets/%s.container" % name), name)
        for line in unit.splitlines():
            self.assertFalse(line.startswith("Environment=") and "IDM_ADMIN_PASSWORD" in line, line)

    def test_paperless_can_take_a_login_form(self):
        conf = read(self.apps_node("apps4"), "kn-nginx/nginx.conf")
        site = conf[conf.index("server_name paperless.sh3.home;"):]
        self.assertIn('add_header Referrer-Policy "same-origin" always;', site[:900])
        other = conf[conf.index("server_name immich.sh3.home;"):]
        self.assertIn('add_header Referrer-Policy "no-referrer" always;', other[:900])

    def test_the_big_data_can_live_on_another_disk(self):
        out = self.apps_node("apps2", opencloud={"data_dir": "/mnt/data/oc"}, immich={"library_dir": "/mnt/data/im"},
                             paperless={"store_dir": "/mnt/data/pl", "consume_dir": "/mnt/scans"})
        compose = read(out, "docker-compose.yml")
        for path in ("/mnt/data/oc:/var/lib/opencloud", "/mnt/data/im:/data", "/mnt/data/pl/media:/usr/src/paperless/media",
                     "/mnt/scans:/usr/src/paperless/consume"):
            self.assertIn(path, compose)

    def folders_data(self, **cloud):
        return dict(SH3, node=dict(SH3["node"], cloud=dict(SH3["node"]["cloud"], **cloud)))

    def folders_refusal(self, **cloud):
        """What the renderer says about these settings; they must not render."""
        out, err = os.path.join(self.tmp, "refused.bundle"), io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(cli.main(["render", self.write("refused", self.folders_data(**cloud)), "-o", out]), 1)
        return err.getvalue()

    def test_nextcloud_shows_folders_other_apps_can_use(self):
        out = self.render("folders1", self.folders_data(shared_folders={"Photos": "/mnt/data/shared/Photos"},
                                                        read_only_folders={"Archive": "/mnt/data/pl/archive"}))
        compose = read(out, "docker-compose.yml")
        self.assertIn("/mnt/data/shared/Photos:/mnt/data/shared/Photos:rw,z", compose)
        self.assertIn("/mnt/data/pl/archive:/mnt/data/pl/archive:ro,z", compose)
        script = read(out, "kiwi/cloud-folders.sh")
        self.assertIn("folder Photos /mnt/data/shared/Photos false", script)
        self.assertIn("folder Archive /mnt/data/pl/archive true", script)
        self.assertIn("find /mnt/data/shared/Photos ", script)
        self.assertNotIn("find /mnt/data/pl/archive", script)   # what another app owns stays its own
        self.assertIn('files:scan --path="admin/files/Archive"', script)
        self.assertNotIn('files:scan --path="admin/files/Photos"', script)
        self.assertIn("kiwi/cloud-folders.sh", read(out, "host-units/kn-cloud-folders.service"))
        for path in ("/mnt/data/shared/Photos", "/mnt/data/pl/archive"):
            self.assertIn(path, read(out, "stack.sh"))      # made before a container mounts them

    def test_talk_drops_the_servers_under_a_name_the_nextcloud_no_longer_has(self):
        """After a change of its name (cloud.nc_hostname, or data taken over from an installation
        under another name) Talk keeps the old signalling, STUN and TURN servers beside the new
        ones, the old ones first (rehearsed 27 Nov 2026). A unit takes them out after every start."""
        data = self.folders_data()
        data["node"]["cloud"] = dict(data["node"].get("cloud") or {}, talk=True, nc_hostname="cloud.new.home")
        out = self.render("talk1", data)
        self.assertIn("kiwi/cloud-talk.sh", read(out, "host-units/kn-cloud-talk.service"))
        script = os.path.join(out, "kiwi", "cloud-talk.sh")
        # a stand-in for the container runtime: occ's answers as Talk gives them, and what is deleted
        bin_dir, log = os.path.join(self.tmp, "talk-bin"), os.path.join(self.tmp, "talk-deleted")
        os.makedirs(bin_dir)
        rt = "podman" if "podman exec" in read(out, "kiwi/cloud-talk.sh") else "docker"
        with open(os.path.join(bin_dir, rt), "w") as f:
            f.write("""#!/bin/bash
shift 6                                   # exec --user 33 nextcloud-aio-nextcloud php /var/www/html/occ
case "$1" in
  status) echo '{"installed":true,"version":"35.0.3.2","maintenance":false,"needsDbUpgrade":false}' ;;
  talk:stun:list) printf '  - cloud.old.kiwi:3478\n  - cloud.new.home:3478\n' ;;
  talk:turn:list) printf '0:\n  schemes: turn\n  server: cloud.old.kiwi:3478\n  secret: s3cret\n  protocols: udp,tcp\n1:\n  schemes: turn\n  server: cloud.new.home:3478\n  secret: s3cret\n  protocols: udp,tcp\n' ;;
  talk:signaling:list) printf 'servers:\n  0:\n    server: https://cloud.old.kiwi/standalone-signaling/\n    verify: true\n  1:\n    server: https://cloud.new.home/standalone-signaling/\n    verify: true\nsecret: s3cret\n' ;;
  talk:*:delete) echo "$*" >> %s ;;
esac
""" % shlex.quote(log))
        os.chmod(os.path.join(bin_dir, rt), 0o755)
        r = subprocess.run(["bash", script], env=dict(os.environ, PATH=bin_dir + ":" + os.environ["PATH"]),
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(log) as f:
            self.assertEqual(f.read().splitlines(), ["talk:stun:delete cloud.old.kiwi:3478",
                                                     "talk:turn:delete turn cloud.old.kiwi:3478 udp,tcp",
                                                     "talk:signaling:delete https://cloud.old.kiwi/standalone-signaling/"])
        self.assertIn("3 server(s)", r.stdout)
        self.assertNotIn("s3cret", r.stdout + r.stderr)
        # without Talk there is no such unit
        out = self.render("talk2", self.folders_data(talk=False))
        self.assertFalse(os.path.exists(os.path.join(out, "host-units", "kn-cloud-talk.service")))
        self.assertFalse(os.path.exists(os.path.join(out, "kiwi", "cloud-talk.sh")))

    def test_without_shared_folders_there_is_no_unit(self):
        out = self.render("folders2", SH3)
        self.assertFalse(os.path.exists(os.path.join(out, "host-units", "kn-cloud-folders.service")))
        self.assertFalse(os.path.exists(os.path.join(out, "kiwi", "cloud-folders.sh")))

    def test_a_shared_folder_must_be_a_plain_name_and_path(self):
        for bad in ({"shared_folders": {"a b": "/mnt/x"}}, {"shared_folders": {"Photos": "mnt/x"}},
                    {"shared_folders": {"Photos": "/mnt/x;reboot"}}, {"read_only_folders": {"$(id)": "/mnt/x"}}):
            self.assertIn("is not a valid", self.folders_refusal(**bad))

    def test_a_name_cannot_be_two_shared_folders(self):
        self.assertIn("read_only_folders too", self.folders_refusal(shared_folders={"A": "/mnt/a"},
                                                                    read_only_folders={"A": "/mnt/b"}))

    def test_the_data_directory_is_not_a_shared_folder(self):
        self.assertIn("must not hold the data directory",
                      self.folders_refusal(nextcloud_datadir="/mnt/nc", shared_folders={"A": "/mnt/nc"}))

    def test_immich_only_reads_a_folder_another_app_holds(self):
        out = self.apps_node("apps5", immich={"external_dirs": ["/mnt/data/shared/Photos"]})
        self.assertIn("/mnt/data/shared/Photos:/mnt/data/shared/Photos:ro,z", read(out, "docker-compose.yml"))
        self.assertIn("/mnt/data/shared/Photos", read(out, "stack.sh"))

    def test_paperless_can_share_an_owner_and_name_its_files(self):
        compose = read(self.apps_node("apps6"), "docker-compose.yml")
        self.assertIn("USERMAP_UID=1000", compose)
        self.assertNotIn("PAPERLESS_FILENAME_FORMAT", compose)
        out = self.apps_node("apps7", paperless={"user_id": 33, "filename_format": "{{created_year}}/{{title}}"})
        compose = read(out, "docker-compose.yml")
        self.assertIn("USERMAP_UID=33", compose)
        self.assertIn("USERMAP_GID=33", compose)
        self.assertIn("PAPERLESS_FILENAME_FORMAT={{created_year}}/{{title}}", compose)
        self.assertIn("{{created_year}}/{{title}}", read(out, "quadlets/kn-paperless.container"))

    def backup_node(self, name, modules=("vault", "paperless"), **settings):
        node = {k: v for k, v in SH3["node"].items() if k in ("vpn_ip", "vpn-client", "reverse-proxy", "pub_iface")}
        node["modules"] = ["vpn-client", "reverse-proxy", *modules, "backup"]
        node["backup"] = {"server": "https://backup.lychee.home"}
        node.update(settings)
        return self.render(name, dict(SH3, node=node))

    def test_restore_at_a_time_picks_the_newest_snapshot_from_then(self):
        script = read(self.backup_node("backup7"), "kiwi/backup.sh")
        func = re.search(r"^snapshot_at\(\) \{.*?^\}$", script, re.S | re.M).group(0)
        listing = json.dumps([      # restic's own order and fields, as `snapshots --json` gives them
            {"time": "2026-11-09T22:05:00.123456789+01:00", "tree": "t", "paths": ["/x"], "hostname": "h",
             "summary": {"backup_start": "2026-11-09T21:05:00Z", "backup_end": "2026-11-09T21:05:01Z"}, "id": "a" * 64, "short_id": "aaaaaaaa"},
            {"time": "2026-11-10T08:44:17.5Z", "tree": "t", "paths": ["/x"], "hostname": "h", "id": "b" * 64, "short_id": "bbbbbbbb"},
            {"time": "2026-11-10T10:06:12+01:00", "tree": "t", "paths": ["/x"], "hostname": "h", "parent": "c" * 64, "id": "c" * 64, "short_id": "cccccccc"}])

        def pick(when):
            prog = "set -uo pipefail\nHOST=h\nREPO_HOST=h\nASK_LIMIT=3m\nrestic() { cat <<'J'\n%s\nJ\n}\n%s\nsnapshot_at vault frozen $(date -d '%s' +%%s%%N)" % (listing, func, when)
            r = subprocess.run(["bash", "-c", prog], capture_output=True, text=True)
            return (r.stdout.split() or [""])[-1], r.returncode       # "NANOSECONDS SHORT-ID"
        self.assertEqual(pick("2026-11-10T09:10:00Z"), ("cccccccc", 0))   # 10:06+01:00 is 09:06Z
        self.assertEqual(pick("2026-11-10T09:00:00Z"), ("bbbbbbbb", 0))
        self.assertEqual(pick("2026-11-10T08:44:17Z"), ("aaaaaaaa", 0))   # not the one half a second later
        self.assertEqual(pick("2026-11-09T21:05:00.123456789Z"), ("aaaaaaaa", 0))   # at the moment itself
        self.assertEqual(pick("2026-11-09T21:05:00Z"), ("", 1))          # nothing that old
        self.assertIn('restore "$5" --target /restore --delete', script)
        self.assertIn('"${tags[@]}"', script)                             # snapshots MODULE...

    def test_a_machine_backs_up_to_each_of_its_servers(self):
        out = self.backup_node("backup6", backup={"servers": ["https://backup.lychee.home", "https://backup.papaya.home"],
                                                  "server": "https://backup.lychee.home"})
        script = read(out, "kiwi/backup.sh")
        self.assertIn("TARGETS=(https://backup.lychee.home https://backup.papaya.home)", script)   # once each
        self.assertIn("AUTO_RESTORE=yes", script)
        self.assertIn('-r "rest:$TARGET/$REPO_HOST/"', script)
        self.assertIn("REPO_HOST=$HOST", script)                     # its own copies, unless a module moved here
        # a module that moved here: the other machine's copies, its way in read from standard input for one run
        self.assertIn("restore_from() { # MACHINE [--at TIME] MODULE...", script)
        self.assertIn('if [[ ${1:-} == --from ]]; then shift; restore_from "$@"; else restore "$@"; fi', script)
        self.assertIn('--env-file "$ENV_FILE"', script)
        self.assertNotIn('--env-file "$DIR/restic.env"', script)
        self.assertIn("backup.lychee.home, https://backup.papaya.home", read(out, "host-units/kn-backup.service"))
        env = read(out, "kiwi/backup/restic.env")
        self.assertTrue(env.startswith("RESTIC_REPOSITORY=rest:https://backup.lychee.home/"), env[:60])
        held = self.backup_node("backup5", backup={"server": "https://backup.lychee.home", "restore": "hold"})
        self.assertIn("AUTO_RESTORE=no", read(held, "kiwi/backup.sh"))
        node = {k: v for k, v in SH3["node"].items() if k in ("vpn_ip", "vpn-client", "reverse-proxy", "pub_iface")}
        node.update(modules=["vpn-client", "reverse-proxy", "vault", "backup"], backup={})
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = cli.main(["render", self.write("backup4", dict(SH3, node=node)), "-o", os.path.join(self.tmp, "b4")])
        self.assertNotEqual(rc, 0)
        self.assertRegex(err.getvalue(), "servers or .*server is required")

    def test_a_module_that_moved_here_is_restored_from_the_other_machines_copies(self):
        """restore --from MACHINE: that machine's copies, its servers and its way in (read from
        standard input, kept in RAM for the run and removed), and nothing of it stays."""
        out = self.backup_node("backup7", backup={"server": "https://backup.lychee.home"})
        script = read(out, "kiwi/backup.sh")
        func = script[script.index("restore_from() {"):script.index("restore_all() {")]
        prog = ("set -uo pipefail\nHOST=here.home\nREPO_HOST=$HOST\nENV_FILE=/own/restic.env\nTARGETS=(https://own.home)\nTARGET=${TARGETS[0]}\n"
                "restore() { echo \"repo=$REPO_HOST target=$TARGET targets=${TARGETS[*]} args=$*\"; grep -c . \"$ENV_FILE\"; "
                "grep -q KIWI_TARGETS \"$ENV_FILE\" && echo leaked; echo \"file=$ENV_FILE\"; }\n"
                "mktemp() { command mktemp \"${TMPDIR:-/tmp}/kiwi-backup-from.XXXXXX\"; }\n" + func +
                "\nrestore_from \"$@\"; echo \"rc=$? after: repo=$REPO_HOST env=$ENV_FILE\"\n")
        env = "RESTIC_PASSWORD=repo-secret\nRESTIC_REST_USERNAME=there.home\nRESTIC_REST_PASSWORD=server-secret\nKIWI_TARGETS=https://a.home https://b.home\n"
        r = subprocess.run(["bash", "-c", prog, "x", "there.home", "--at", "yesterday", "vault"], input=env, capture_output=True, text=True)
        lines = r.stdout.splitlines()
        self.assertIn("repo=there.home target=https://a.home targets=https://a.home https://b.home args=--at yesterday vault", lines)
        self.assertIn("3", lines)                                             # its three lines; KIWI_TARGETS is ours, not restic's
        self.assertNotIn("leaked", lines)
        self.assertIn("rc=0 after: repo=here.home env=/own/restic.env", lines)    # this machine's own again
        kept = next(x for x in lines if x.startswith("file=")).split("=", 1)[1]
        self.assertFalse(os.path.exists(kept))                                 # the way in is gone after the run
        self.assertNotIn("secret", r.stdout + r.stderr)
        # nothing on standard input: refused, and nothing is restored
        r = subprocess.run(["bash", "-c", prog, "x", "there.home", "vault"], input="", capture_output=True, text=True)
        self.assertIn("wants there.home's way into its backups on standard input", r.stderr)
        self.assertIn("rc=1", r.stdout)
        self.assertNotIn("repo=there.home", r.stdout)

    def test_a_restore_takes_the_freshest_copy_of_any_server(self):
        script = read(self.backup_node("backup3", backup={"servers": ["https://a.home", "https://b.home"]}), "kiwi/backup.sh")
        funcs = "\n".join(re.search(r"^%s\(\) \{.*?^\}$" % f, script, re.S | re.M).group(0) for f in ("snapshot_at", "freshest"))

        def listing(*snaps):
            return json.dumps([{"time": t, "hostname": "h", "id": i * 8, "short_id": i * 8} for t, i in snaps])
        a = listing(("2026-11-10T08:00:00Z", "a"), ("2026-11-10T09:00:00Z", "b"))
        b = listing(("2026-11-10T08:30:00Z", "c"))           # b missed the night's second run
        prog = ("set -uo pipefail\nHOST=h\nREPO_HOST=h\nASK_LIMIT=3m\nTARGETS=(https://a.home https://b.home)\n"
                "restic() { if [[ $TARGET == https://a.home ]]; then echo '%s'; else echo '%s'; fi; }\n%s\n"
                "freshest m frozen $(date -d \"$1\" +%%s%%N)" % (a, b, funcs))

        def pick(when):
            return subprocess.run(["bash", "-c", prog, "x", when], capture_output=True, text=True).stdout.strip()
        self.assertEqual(pick("2026-11-10T10:00:00Z"), "https://a.home bbbbbbbb")
        self.assertEqual(pick("2026-11-10T08:45:00Z"), "https://b.home cccccccc")
        self.assertEqual(pick("2026-11-10T07:00:00Z"), "")

    def test_a_commercial_exit_that_stays_unhealthy_is_started_anew(self):
        text, _ = quadlet.container_unit("km-vpn-client", {
            "image": "gluetun:3", "restart": "unless-stopped", "x-kiwi-health-on-failure": "kill",
            "healthcheck": {"test": ["CMD", "/gluetun-entrypoint", "healthcheck"], "interval": "60s", "retries": 5}},
            {}, {"km-vpn-client": {}})
        self.assertIn('HealthCmd=["/gluetun-entrypoint","healthcheck"]', text)
        self.assertIn("HealthOnFailure=kill", text)
        self.assertIn("Restart=always", text)
        with self.assertRaisesRegex(Exception, "not one of"):
            quadlet.container_unit("x", {"image": "i", "x-kiwi-health-on-failure": "reboot",
                                         "healthcheck": {"test": ["CMD", "true"]}}, {}, {"x": {}})

    def test_a_container_in_anothers_network_lives_and_dies_with_it(self):
        from kiwimodules import quadlet
        text, _ = quadlet.container_unit("km-nginx", {"image": "nginx:1", "network_mode": "service:km-vpn-server", "restart": "always"},
                                         {}, {"km-nginx": {}, "km-vpn-server": {}})
        self.assertIn("BindsTo=km-vpn-server.service", text)
        self.assertNotIn("Requires=km-vpn-server.service", text)
        install = text.split("[Install]", 1)[1]
        self.assertIn("WantedBy=kiwi-stack.target", install)
        self.assertIn("WantedBy=km-vpn-server.service", install)       # its start brings this one back
        host, _ = quadlet.container_unit("km-vpn-server", {"image": "wg:1", "restart": "always"}, {},
                                         {"km-nginx": {"network_mode": "service:km-vpn-server"}, "km-vpn-server": {}})
        self.assertIn("ExecStartPre=-/usr/bin/podman rm -f -i --depend km-vpn-server", host)   # nothing left there blocks it
        self.assertNotIn("--depend", text)

    def test_a_backup_holds_what_the_modules_declare(self):
        script = read(self.backup_node("backup1"), "kiwi/backup.sh")
        self.assertIn('FREEZE[vault]="kn-vault"', script)
        self.assertIn('FROZEN[vault]="/home/user/docker/kn-vault:/source/home/user/docker/kn-vault"', script)
        self.assertIn('FREEZE[paperless]="kn-paperless-db"', script)
        self.assertIn('FROZEN[paperless]="paperless_db:/volume/paperless_db"', script)
        self.assertIn('EXCLUDE[paperless]="/source/home/user/docker/kn-paperless/data/log"', script)
        self.assertIn('SERVICES[vault]="kn-vault"', script)

    def test_a_backup_keeps_the_certificates_of_a_public_site(self):
        host = self.public_hub()
        host["master"]["modules"] = [*host["master"]["modules"], "backup"]
        host["master"]["backup"] = {"server": "https://backup.lychee.home"}
        script = read(self.render("backup9", host), "kiwi/backup.sh")
        self.assertIn("/home/user/docker/km-nginx/letsencrypt:/source/home/user/docker/km-nginx/letsencrypt", script)
        self.assertIn('SERVICES[reverse-proxy]="km-nginx"', script)
        # a machine without public names has none to keep, and the backup would say so every night
        self.assertNotIn("letsencrypt", read(self.backup_node("backup8"), "kiwi/backup.sh"))

    def test_a_backup_leaves_out_what_is_not_set_here(self):
        out = self.backup_node("backup2", modules=("sftp",), sftp={"sftp_password": "x"})
        self.assertIn('BULK[sftp]=""', read(out, "kiwi/backup.sh"))

    def test_a_restore_can_only_empty_the_folders_it_puts_back(self):
        script = read(self.backup_node("backup3"), "kiwi/backup.sh")
        self.assertIn("--target /restore --delete", script)
        self.assertNotIn("--target / ", script)

    def test_a_backup_keeps_its_passwords_in_a_file_only_root_reads(self):
        out = self.backup_node("backup4")
        env = read(out, "kiwi/backup/restic.env")
        self.assertIn("RESTIC_REPOSITORY=rest:https://backup.lychee.home/sh3.home/", env)
        self.assertEqual(os.stat(os.path.join(out, "kiwi/backup/restic.env")).st_mode & 0o777, 0o600)
        secret = dict(line.split("=", 1) for line in env.splitlines())["RESTIC_PASSWORD"]
        self.assertNotIn(secret, read(out, "kiwi/backup.sh"))

    def test_a_backup_runs_at_night_and_not_at_every_apply(self):
        out = self.backup_node("backup5", backup={"server": "https://backup.lychee.home", "at": "04:30"})
        self.assertIn("OnCalendar=*-*-* 04:30:00", read(out, "host-units/kn-backup.timer"))
        self.assertIn("backup.sh due", read(out, "host-units/kn-backup.service"))
        self.assertIn("backup.sh thaw", read(out, "host-units/kn-backup.service"))
        script = read(out, "kiwi/backup.sh")
        self.assertIn('touch "$DIR/restored"', script)         # a restore lets a rebuilt machine back up again
        self.assertIn("kiwi-stack backup --new", script)
        unit = read(out, "host-units/kn-backup.service")
        self.assertIn("Restart=on-failure", unit)
        self.assertIn("StartLimitIntervalSec=0", unit)          # applies restart it; a limit kept the night out
        self.assertNotIn("kiwi-stack start", read(out, "kiwi/backup.sh"))   # it would restart this very unit

    def test_a_backup_needs_a_server_it_can_name(self):
        data = dict(SH3, node=dict(SH3["node"], modules=["vpn-client", "reverse-proxy", "backup"],
                                   backup={"server": "http://nope"}))
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(cli.main(["render", self.write("b6", data), "-o", os.path.join(self.tmp, "b6.bundle")]), 1)
        self.assertIn("is not a valid value", err.getvalue())

    def test_a_backup_server_knows_each_client_by_the_password_it_derives(self):
        client = dict(line.split("=", 1) for line in read(self.backup_node("backup7"), "kiwi/backup/restic.env").splitlines())
        node = {k: v for k, v in SH3["node"].items() if k in ("vpn_ip", "vpn-client", "reverse-proxy", "pub_iface")}
        node["modules"] = ["vpn-client", "reverse-proxy", "backup-server"]
        node["backup-server"] = {"clients": ["sh3.home", "other.home"]}
        out = self.render("backup8", dict(SH3, node=node))
        lines = dict(line.split(":", 1) for line in read(out, "kn-backup-server/htpasswd").splitlines())
        want = "{SHA}" + base64.b64encode(hashlib.sha1(client["RESTIC_REST_PASSWORD"].encode()).digest()).decode()
        self.assertEqual(lines["sh3.home"], want)
        self.assertNotEqual(lines["other.home"], want)
        self.assertNotIn(client["RESTIC_REST_PASSWORD"], read(out, "kn-backup-server/htpasswd"))
        self.assertIn("--private-repos --append-only", read(out, "docker-compose.yml"))

    def test_a_backup_store_keeps_an_encrypted_copy_at_another_place(self):
        """backup-server.offsite_url: every night rclone brings a copy of the store up to date in a
        WebDAV folder, encrypted once more (names too) with a key from the seed."""
        node = {k: v for k, v in SH3["node"].items() if k in ("vpn_ip", "vpn-client", "reverse-proxy", "pub_iface")}
        node["modules"] = ["vpn-client", "reverse-proxy", "backup-server"]
        node["backup-server"] = {"clients": ["sh3.home"]}
        out = self.render("offsite-none", dict(SH3, node=node))
        self.assertFalse(os.path.exists(os.path.join(out, "kiwi", "backup-offsite.sh")))       # none unless asked for
        node["backup-server"] = dict(node["backup-server"], offsite_url="https://dav.example.org/kiwi",
                                     offsite_user="me", offsite_password="golden-dav-password", offsite_bwlimit="5M")
        out = self.render("offsite", dict(SH3, node=node))
        env = dict(line.split("=", 1) for line in read(out, "kn-backup-server/offsite.env").splitlines() if "=" in line and not line.startswith("#"))
        self.assertEqual((env["OFFSITE_URL"], env["OFFSITE_USER"], env["OFFSITE_PASS"]), ("https://dav.example.org/kiwi", "me", "golden-dav-password"))
        self.assertGreaterEqual(len(env["OFFSITE_KEY"]), 20)                                   # from the seed
        self.assertEqual(oct(os.stat(os.path.join(out, "kn-backup-server", "offsite.env")).st_mode & 0o777), "0o600")
        script = read(out, "kiwi/backup-offsite.sh")
        self.assertNotIn("golden-dav-password", script)                                        # the password stays in the env file
        self.assertIn("RCLONE_CONFIG_KIWI_TYPE=crypt", script)
        self.assertIn("RCLONE_CONFIG_KIWI_DIRECTORY_NAME_ENCRYPTION=true", script)
        self.assertIn('-v "$data:/data:ro,z"', script)                                           # the store is only read
        self.assertIn('--bwlimit "5M"', script)
        self.assertIn('--exclude "/*/locks/**"', script)
        # a store installed anew: what the copy holds and the store has not comes back; what it has stays
        fake = os.path.join(self.tmp, "fakert")
        here = os.path.join(self.tmp, "store")
        os.makedirs(os.path.join(here, "data", "lime.home"))
        with open(os.path.join(here, "data", "lime.home", "config"), "w") as f:
            f.write("x")
        with open(os.path.join(here, "offsite.env"), "w") as f:
            f.write("OFFSITE_URL=https://dav.example.org/kiwi\nOFFSITE_USER=me\nOFFSITE_PASS=p\nOFFSITE_KEY=k\n")
        with open(fake, "w") as f:
            f.write('#!/bin/bash\necho "$*" >> "%s/calls"\ncase "$*" in *lsf*) printf "lime.home/\\nquince.home/\\n" ;; '
                    '*obscure*) echo obscured ;; esac\nexit 0\n' % here)
        os.chmod(fake, 0o755)
        test = script
        for line in test.splitlines():
            if line.startswith(("dir=", "data=", "rt=")):
                test = test.replace(line, {"dir": "dir=" + here, "data": "data=" + os.path.join(here, "data"),
                                           "rt": "rt=" + fake}[line.split("=", 1)[0]], 1)
        path = os.path.join(self.tmp, "offsite-test.sh")
        with open(path, "w") as f:
            f.write(test.replace("/run/kiwi-offsite.XXXXXX", os.path.join(self.tmp, "run.XXXXXX")))
        r = subprocess.run(["bash", path, "bring-back"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("lime.home: here already, left as it is", r.stdout)
        self.assertIn("quince.home: from the copy", r.stdout)
        with open(os.path.join(here, "calls")) as f:
            calls = f.read()
        self.assertIn("copy kiwi:quince.home /back", calls)
        self.assertNotIn("copy kiwi:lime.home", calls)
        timer = read(out, "host-units/kn-backup-offsite.timer")
        self.assertIn("OnCalendar=*-*-* 05:30:00", timer)
        self.assertTrue(os.path.isfile(os.path.join(out, "host-units", "kn-backup-offsite.service")))
        if shutil.which("shellcheck"):
            r = subprocess.run(["shellcheck", "-S", "warning", os.path.join(out, "kiwi", "backup-offsite.sh")], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stdout)
        # an address without the account: refused
        node["backup-server"] = {"clients": ["sh3.home"], "offsite_url": "https://dav.example.org/kiwi"}
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertNotEqual(cli.main(["render", self.write("offsite-bad", dict(SH3, node=node)), "-o", os.path.join(self.tmp, "ob.bundle")]), 0)
        self.assertIn("needs offsite_user and offsite_password", err.getvalue())

    def tang_node(self, name, **settings):
        node = {k: v for k, v in SH3["node"].items() if k in ("vpn_ip", "vpn-client", "reverse-proxy", "pub_iface")}
        node["modules"] = ["vpn-client", "reverse-proxy", "tang"]
        node.update(settings)
        return self.render(name, dict(SH3, node=node))

    def test_a_ring_is_a_server_with_a_port_and_keys_of_its_own(self):
        out = self.tang_node("tang1", tang={"rings": {"infra": "7500", "emergency": "7501"}})
        compose = read(out, "docker-compose.yml")
        self.assertIn("kn-tang-infra:", compose)
        self.assertIn("kn-tang-emergency:", compose)
        self.assertIn("7501:7500", compose)
        self.assertIn("/home/user/docker/kn-tang/emergency:/db:z", compose)
        stack = read(out, "stack.sh")
        self.assertIn("kn-tang/infra", stack)
        self.assertIn("kn-tang/emergency", stack)
        self.assertIn("7500/tcp", stack)
        self.assertIn("7501/tcp", stack)

    def test_the_mesh_reaches_a_ring_through_the_hosts_port(self):
        rules = read(self.tang_node("tang4", tang={"rings": {"infra": "7500", "b": "7501"}}), "kn-vpn-client/post-rules.txt")
        self.assertIn("-d 10.8.0.25 -p tcp -m multiport --dports 7500,7501 -j DNAT --to-destination 172.128.0.1", rules)
        self.assertIn("-i tun0 -m conntrack --ctstate DNAT -j ACCEPT", rules)

    def relay_master(self, name, **vpn):
        data = json.loads(json.dumps(MACHINES["gate"]))
        data["master"]["vpn-server"].update(vpn)
        return self.render(name, data)

    def test_a_master_relays_a_ring_only_past_its_gate(self):
        out = self.relay_master("relay1", unlock_relay={"7500": "10.8.0.25:7500"})
        script = read(out, "km-vpn-server/start.sh")
        self.assertIn("-t nat -A PREROUTING -i eth0 -p tcp --dport 7500 -j DNAT --to-destination 10.8.0.25:7500", script)
        self.assertIn("wg show wg0 endpoints", script)
        # the gate and its DROP come before wg-easy's accept of everything towards wg0
        self.assertLess(script.index("-j KIWI_RELAY"), script.index("iptables -A FORWARD -o wg0 -j ACCEPT"))
        self.assertLess(script.index("--ctstate NEW -j DROP"), script.index("iptables -A FORWARD -o wg0 -j ACCEPT"))
        self.assertIn("7500:7500/tcp", read(out, "docker-compose.yml"))
        self.assertIn("7500/tcp", read(out, "stack.sh"))

    def test_a_master_without_a_relay_stays_as_it_was(self):
        out = self.relay_master("relay2")
        self.assertNotIn("KIWI_RELAY", read(out, "km-vpn-server/start.sh"))

    def test_the_wireguard_server_is_not_restored_from_over_its_own_mesh(self):
        data = json.loads(json.dumps(MACHINES["gate"]))
        data["master"]["modules"] = ["vpn-client", "vpn-server", "dns", "reverse-proxy", "backup"]
        data["master"]["backup"] = {"server": "https://backup.lychee.home"}
        script = read(self.render("norestore1", data), "kiwi/backup.sh")
        self.assertIn('NO_RESTORE[vpn-server]="it carries the mesh', script)
        self.assertIn("is not restored from here", script)
        self.assertLess(script.index("is not restored from here"), script.index("service stop"))

    def test_a_restore_brings_back_what_shares_a_network(self):
        script = read(self.backup_node("norestore2"), "kiwi/backup.sh")
        self.assertIn("systemctl start kiwi-stack.target", script)    # not kiwi-stack start: it restarts this unit

    def test_a_relay_needs_a_mesh_address_and_port(self):
        data = json.loads(json.dumps(MACHINES["gate"]))
        data["master"]["vpn-server"]["unlock_relay"] = {"7500": "papaya:7500"}
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(cli.main(["render", self.write("relay3", data), "-o", os.path.join(self.tmp, "relay3.bundle")]), 1)
        self.assertIn("is not a valid value", err.getvalue())

    def test_the_infra_ring_is_the_default(self):
        self.assertIn("kn-tang-infra:", read(self.tang_node("tang2"), "docker-compose.yml"))

    def test_a_backup_keeps_the_rings_keys(self):
        out = self.backup_node("tang3", modules=("tang",))
        self.assertIn('BULK[tang]="/home/user/docker/kn-tang:/source/home/user/docker/kn-tang"', read(out, "kiwi/backup.sh"))

    def test_the_extra_containers_can_be_left_out(self):
        compose = read(self.apps_node("apps3", immich={"machine_learning": False}, paperless={"office_documents": False}),
                       "docker-compose.yml")
        self.assertIn("IMMICH_MACHINE_LEARNING_ENABLED=false", compose)
        for name in ("kn-immich-ml:", "kn-paperless-tika:", "kn-paperless-gotenberg:", "PAPERLESS_TIKA_ENABLED"):
            self.assertNotIn(name, compose)

    def test_a_new_nextcloud_gets_end_to_end_encryption(self):
        self.assertIn("end_to_end_encryption", read(self.render("e2e1", SH3), "docker-compose.yml"))

    def test_a_node_on_this_lan_answers_with_its_lan_address(self):
        data = dict(MACHINES["m1"], dns_records=[["10.8.0.1", "gate.home"], ["10.8.0.25", "sh3.home"], ["10.8.0.25", "cloud.sh3.home"]],
                    lan_addresses={"10.8.0.25": "192.168.1.25"})
        out = self.render("lan1", data)
        with open(os.path.join(out, "docker-compose.yml")) as f:
            compose = f.read()
        self.assertIn("192.168.1.25 sh3.home", compose)
        self.assertIn("192.168.1.25 cloud.sh3.home", compose)
        self.assertIn("10.8.0.1 gate.home", compose)          # not on this LAN: still the mesh
        self.assertNotIn("10.8.0.25 sh3.home", compose)
        with open(os.path.join(out, "stack.sh")) as f:
            stack = f.read()
        self.assertIn("192.168.1.25 sh3.home", stack)         # the host's own /etc/hosts
        self.assertIn("10.8.0.1 gate.home", stack)
        # a name whose service answers at the mesh address only keeps it, also on this LAN
        data = dict(data, dns_records=data["dns_records"] + [["10.8.0.25", "jabber.sh3.home"]], mesh_only=["jabber.sh3.home"])
        out = self.render("lan2", data)
        with open(os.path.join(out, "docker-compose.yml")) as f:
            compose = f.read()
        self.assertIn("10.8.0.25 jabber.sh3.home", compose)
        self.assertIn("192.168.1.25 cloud.sh3.home", compose)
        with open(os.path.join(out, "stack.sh")) as f:
            self.assertIn("10.8.0.25 jabber.sh3.home", f.read())

    def test_an_empty_blocklist_is_fetched_again(self):
        """Pi-hole's own fetch at its start fails where the machine resolves through it: a timer
        looks at the list and fetches an empty one."""
        out = self.render("gw1", MACHINES["m1"])
        found = {f: os.path.join(d, f) for d, _s, files in os.walk(out) for f in files}
        script = found["pihole-blocklist.sh"]
        self.assertEqual(subprocess.run(["bash", "-n", script]).returncode, 0)
        with open(script) as f:
            text = f.read()
        self.assertIn('C="kn-pihole"', text)
        self.assertIn("select count(*) from gravity", text)
        self.assertIn("pihole -g", text)
        self.assertLess(text.index("rm -f /etc/pihole/gravity.db"), text.index("pihole -g"))    # an empty file first
        with open(found["kn-pihole-blocklist.timer"]) as f:
            timer = f.read()
        self.assertIn("OnUnitActiveSec=1h", timer)
        self.assertIn("Unit=kn-pihole-blocklist.service", timer)
        with open(found["kn-pihole-blocklist.service"]) as f:
            self.assertIn("kiwi/pihole-blocklist.sh", f.read())

    def test_a_gateway_lets_its_lan_clients_through(self):
        out = self.render("gw1", MACHINES["m1"])
        path = next(os.path.join(d, "gw.sh") for d, _s, files in os.walk(out) if "gw.sh" in files)
        with open(path) as f:
            text = f.read()
        self.assertEqual(subprocess.run(["bash", "-n", path]).returncode, 0)
        # both of these were refused by iptables at every start, and nobody saw
        self.assertNotIn("--ctstatus", text)
        self.assertNotRegex(text, r"! -s \S+ ! -s")
        self.assertIn("-j KIWI_GW_NAT", text)
        self.assertLess(text.index("--ctstate DNAT -j RETURN"), text.index("-A KIWI_GW_NAT -j MASQUERADE"))    # nginx sees who the LAN client is
        # firewalld refuses forwarded LAN traffic without a policy, and a reload must not untrust the stack
        self.assertIn("--policy=kiwi-lan-gateway --set-target=ACCEPT", text)
        self.assertLess(text.index('--permanent --zone=trusted --add-source="$DOCKER_SUBNET"'), text.index("firewall-cmd -q --reload"))
        # the node's own mesh address goes straight to its proxy for a LAN client
        self.assertRegex(text, r'-d "\$OWN_MESH_IP" -p tcp -m multiport --dports 80,443 -j DNAT --to-destination "\$PROXY_IP"')
        # the kill switch: a LAN client's traffic never leaves by the card it came in on. It is the
        # last rule inserted, so the first one checked, and stop takes it away again
        kill = 'iptables -I FORWARD -i "$PUB_IFACE" -o "$PUB_IFACE" -j DROP'
        self.assertIn(kill, text)
        self.assertGreater(text.rindex(kill), text.index('iptables -I FORWARD -i "$PUB_IFACE" -o "$BRIDGE" -j ACCEPT'))
        self.assertIn('iptables -D FORWARD -i "$PUB_IFACE" -o "$PUB_IFACE" -j DROP', text)
        # and the unit stays to watch what a network manager may take away
        unit = next(os.path.join(d, "kn-gateway.service") for d, _s, files in os.walk(out) if "kn-gateway.service" in files)
        with open(unit) as f:
            u = f.read()
        self.assertIn("gw.sh watch", u)
        self.assertNotIn("oneshot", u)
        self.assertIn("ExecStopPost=", u)

    def test_an_exec_health_check_needs_no_shell(self):
        def health(test):
            unit, _env = quadlet.container_unit("s", {"image": "x", "healthcheck": {"test": test}}, {}, {"s": {}})
            return [line for line in unit.splitlines() if line.startswith("HealthCmd=")]
        # quadlet passes the value on as it stands, so the quotes must not be escaped
        self.assertEqual(health(["CMD", "/usr/bin/coolwsd", "--probe"]), ['HealthCmd=["/usr/bin/coolwsd","--probe"]'])
        self.assertEqual(health(["CMD-SHELL", "/healthcheck.sh"]), ["HealthCmd=/healthcheck.sh"])
        self.assertEqual(health("/healthcheck.sh"), ["HealthCmd=/healthcheck.sh"])

    def test_a_node_cannot_carry_a_hub(self):
        for modules in (["vpn-client", "reverse-proxy", "hub"], ["vpn-client", "reverse-proxy", "nostr-relay"]):
            node = {"name": "n1", "domain": "home", "role": "node", "seed": "secrets/seed",
                    "node": {"modules": modules, "reverse-proxy": dict(TLS)}}
            self.assertNotEqual(cli.main(["render", self.write("n1", node), "-o", os.path.join(self.tmp, "n1.bundle")]), 0)

    def test_errors_are_messages_not_tracebacks(self):
        out = os.path.join(self.tmp, "x.bundle")
        noseed = dict(SH3)
        del noseed["seed"]
        self.assertEqual(cli.main(["render", self.write("noseed", noseed), "-o", out]), 1)
        self.assertEqual(cli.main(["render", self.write("norole", {"name": "x"}), "-o", out]), 1)
        self.assertEqual(cli.main(["render", self.write("badrole", {"name": "x", "role": "nope"}), "-o", out]), 1)
        bare = {"name": "x", "role": "bare"}
        self.assertEqual(cli.main(["render", self.write("bare", bare), "-o", out]), 1)
        self.render("sh3", SH3)
        self.assertEqual(cli.main(["render", self.write("sh3", SH3), "-o", os.path.join(self.tmp, "sh3.bundle")]), 1)

    def test_the_bridge_and_the_tunnels_have_an_mtu_each(self):
        def read(out, rel):
            with open(os.path.join(out, rel)) as f:
                return f.read()
        # defaults: the bridge at 1500 carries the 1376 tunnels with their headers; wg0 set before the
        # MSS rule, which is the tunnels' MTU less 40 both ways, not the interface a SYN leaves by
        out = self.render("gate", MACHINES["gate"])
        self.assertIn("Options=mtu=1500", read(out, "quadlets/knet-master.network"))
        self.assertIn("Environment=WG_MTU=1376", read(out, "quadlets/km-vpn-server.container"))
        start = read(out, "km-vpn-server/start.sh")
        self.assertLess(start.index("ip link set dev wg0 mtu 1376"), start.index("TCPMSS --set-mss 1336"))
        self.assertNotIn("-j TCPMSS --clamp-mss-to-pmtu", start)
        self.assertIn("TCPMSS --set-mss 1336", read(out, "km-vpn-client/post-rules.txt"))
        # a gateway node sets the MSS in its VPN client: LAN clients advertise 1460
        out = self.render("m1", MACHINES["m1"])
        self.assertIn("TCPMSS --set-mss 1336", read(out, "kn-vpn-client/post-rules.txt"))
        # the old single `mtu` is the tunnels' MTU, with a warning; the bridge keeps 1500
        old = dict(SH3, node=dict(SH3["node"], mtu=1360))
        from io import StringIO
        import contextlib
        err = StringIO()
        with contextlib.redirect_stderr(err):
            out = self.render("old", old)
        self.assertIn("node.mtu is the old name of wg_mtu", err.getvalue())
        self.assertIn("Options=mtu=1500", read(out, "quadlets/knet-node.network"))
        self.assertIn("Environment=WIREGUARD_MTU=1360", read(out, "quadlets/kn-vpn-client.container"))
        # the 1412 fleets set does not fit as the tunnels' MTU: padded to 1424, plus 80, over 1500
        err = StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(cli.main(["render", self.write("old1412", dict(SH3, node=dict(SH3["node"], mtu=1412))),
                                       "-o", os.path.join(self.tmp, "old1412.bundle")]), 1)
        self.assertIn("mtu 1412 is the old name of wg_mtu", err.getvalue())
        # a tunnel whose padded packets do not fit the bridge with their headers is refused
        for wg, ok in ((1408, True), (1409, False)):
            data = dict(SH3, node=dict(SH3["node"], wg_mtu=wg))
            with contextlib.redirect_stderr(StringIO()), contextlib.redirect_stdout(StringIO()):
                code = cli.main(["render", self.write("w%d" % wg, data), "-o", os.path.join(self.tmp, "w%d.bundle" % wg)])
            self.assertEqual(code, 0 if ok else 1, wg)

    def test_a_kept_password_comes_from_the_secret_store(self):
        """A secret nothing can generate (a provider's key) may live in the secret store instead of the
        fleet file (kiwi-server secrets keep): the same value as when it was written there."""
        from kiwimodules import modules as modmod, profiles
        data = dict(MACHINES["hub1"], master=dict(MACHINES["hub1"]["master"], **{"vpn-client": {
            k: v for k, v in MACHINES["hub1"]["master"]["vpn-client"].items() if k != "wireguard_private_key"}}))
        mm = machine.load(self.write("hub1-kept", data))
        mm.secrets.pins = lambda: {"hub1.home/vpn-client/wireguard_private_key": "kept-mullvad-key"}
        profile = profiles.discover()[mm.role]
        ms = modmod.discover()
        resolver.resolve_settings(profile, mm, ms)
        self.assertEqual(mm.module_settings["vpn-client"]["wireguard_private_key"], "kept-mullvad-key")
        mm = machine.load(self.write("hub1-written", MACHINES["hub1"]))
        mm.secrets.pins = lambda: {"hub1.home/vpn-client/wireguard_private_key": "kept-mullvad-key"}
        resolver.resolve_settings(profile, mm, ms)
        self.assertEqual(mm.module_settings["vpn-client"]["wireguard_private_key"], "golden-mullvad-key")   # written wins

    def test_secret_derivation_is_frozen(self):
        # kiwi-server derives the same values: a change here rotates every generated secret
        self.assertEqual(machine.derive_secret(SEED, "sh3.home", "cloud", "redis_password"),
                         "ErXoT6obmcMFnpKb3N73gQp1R0fAUOzt")
        self.assertEqual(machine.seed_id(SEED), "956141ccd4bc")

    def test_lists(self):
        self.assertEqual(cli.main(["modules", "-v"]), 0)
        self.assertEqual(cli.main(["profiles"]), 0)


class TestFederation(unittest.TestCase):
    setUp, tearDown, render, write = TestRender.setUp, TestRender.tearDown, TestRender.render, TestRender.write
    PARTNER = {"endpoint": "198.51.100.9", "public_key": "cGFydG5lci1wdWJsaWMta2V5LW5vdC1yZWFsLTAwMDA9",
               "mesh": "10.10.0.0/16", "domain": "internal", "dns": "10.10.0.1",
               "share": ["cloud.sh3", "m1:22", "min", "nowhere"], "from": ["10.10.3.0/24"], "as": "10.8.255.1"}

    def test_pihole_serves_the_time_and_never_sets_the_clock(self):
        """dns.ntp: Pi-hole answers time questions on port 123 (published, open, handed out by DHCP);
        it never sets the clock itself, which is the machine's own time service's to do."""
        m = json.loads(json.dumps(MACHINES["m1"]))
        out = self.render("m1-ntp", m)
        with open(os.path.join(out, "docker-compose.yml")) as f:
            pihole = yaml.safe_load(f)["services"]["kn-pihole"]
        self.assertIn("FTLCONF_ntp_sync_active=false", pihole["environment"])
        self.assertNotIn("FTLCONF_ntp_ipv4_active=false", pihole["environment"])
        self.assertIn("123:123/udp", pihole["ports"])
        self.assertNotIn("SYS_TIME", pihole["cap_add"])
        with open(os.path.join(out, "stack.sh")) as f:
            stack = f.read()
        self.assertRegex(stack, r"KS_STACK_PORTS=\([^)]*123/udp")
        # the devices that get their address from it get the time from it too
        dhcp = json.loads(json.dumps(m))
        dhcp["node"]["dns"] = dict(dhcp["node"]["dns"], dhcp_enabled=True, dhcp_start="192.168.1.100",
                                   dhcp_end="192.168.1.200", dhcp_router="192.168.1.1")
        with open(os.path.join(self.render("m1-ntp-dhcp", dhcp), "docker-compose.yml")) as f:
            env = yaml.safe_load(f)["services"]["kn-pihole"]["environment"]
        self.assertIn("dhcp-option=option:ntp-server,0.0.0.0", next(e for e in env if e.startswith("FTLCONF_misc_dnsmasq_lines=")))
        # switched off: it answers no time questions, and nothing is published for it
        off = json.loads(json.dumps(m))
        off["node"]["dns"] = dict(off["node"]["dns"], ntp=False)
        out = self.render("m1-ntp-off", off)
        with open(os.path.join(out, "docker-compose.yml")) as f:
            pihole = yaml.safe_load(f)["services"]["kn-pihole"]
        self.assertIn("FTLCONF_ntp_ipv4_active=false", pihole["environment"])
        self.assertIn("FTLCONF_ntp_sync_active=false", pihole["environment"])
        self.assertNotIn("123:123/udp", pihole["ports"])
        # the machine's own time servers (kiwi-server fills them in) reach the role library
        from kiwimodules import machine as machmod, manifest, modules as modmod, profiles
        mm = machmod.load(self.write("m1-ntp-servers", m))
        profile = profiles.discover()[mm.role]
        ms = modmod.discover()
        resolver.resolve_settings(profile, mm, ms)
        mm.role_settings["ntp_servers"] = ["192.168.1.5", "10.8.0.1"]
        b = modmod.Renderer(ms).render(resolver.stack_spec(mm, profile, mm.dns_records, master_ip=mm.master_ip))
        self.assertIn("KS_STACK_NTP=('192.168.1.5' '10.8.0.1')", manifest.stack_vars(mm, b))

    def test_a_nodes_pihole_goes_on_while_the_master_is_away(self):
        """A node's Pi-hole asks a small resolver in front of it, which asks the master while it
        answers and the fallbacks, over TLS, while it does not. Pi-hole's own order switched only
        when a client asked again: lookups took seconds or got nothing (the master-down drill)."""
        m = json.loads(json.dumps(MACHINES["m1"]))
        out = self.render("m1-up", m)
        with open(os.path.join(out, "docker-compose.yml")) as f:
            svcs = yaml.safe_load(f)["services"]
        self.assertIn("FTLCONF_dns_upstreams=127.0.0.1#5335", svcs["kn-pihole"]["environment"])
        up = svcs["kn-dns-up"]
        self.assertEqual((up["network_mode"], up["command"]), ("service:kn-pihole", ["-conf", "/Corefile"]))
        self.assertTrue(up["image"].startswith("docker.io/coredns/coredns:"))
        with open(os.path.join(out, "kn-pihole", "Corefile")) as f:
            core = f.read()
        master = MACHINES["m1"]["node"].get("master_ip") or "10.8.0.1"
        self.assertIn("forward . %s tls://1.1.1.1 tls://1.0.0.1 {" % master, core)
        self.assertIn("tls_servername cloudflare-dns.com", core)
        self.assertIn("policy sequential", core)
        self.assertIn("bind 127.0.0.1", core)
        self.assertTrue(os.path.isfile(os.path.join(out, "quadlets", "kn-dns-up.container")))
        with open(os.path.join(out, "quadlets", "kn-dns-up.container")) as f:
            self.assertIn("Network=container:kn-pihole", f.read())
        # the fallbacks in plain text when asked so; none without fallbacks, nor with upstreams of one's own
        plain = json.loads(json.dumps(m))
        plain["node"]["dns"] = dict(plain["node"]["dns"], fallback_tls_name="")
        with open(os.path.join(self.render("m1-plain", plain), "kn-pihole", "Corefile")) as f:
            self.assertIn("forward . %s 1.1.1.1 1.0.0.1 {" % master, f.read())
        for name, dns in (("m1-nofb", {"fallback_dns": ""}), ("m1-own", {"upstream_dns": "9.9.9.10"})):
            other = json.loads(json.dumps(m))
            other["node"]["dns"] = dict(other["node"]["dns"], **dns)
            out2 = self.render(name, other)
            with open(os.path.join(out2, "docker-compose.yml")) as f:
                svcs2 = yaml.safe_load(f)["services"]
            self.assertNotIn("kn-dns-up", svcs2, name)
            self.assertFalse(os.path.exists(os.path.join(out2, "kn-pihole", "Corefile")), name)
            self.assertNotIn("FTLCONF_dns_upstreams=127.0.0.1#5335", svcs2["kn-pihole"]["environment"])
        # a master asks its VPN client, which sits next to it: as before
        with open(os.path.join(self.render("gate-up", MACHINES["gate"]), "docker-compose.yml")) as f:
            gate = yaml.safe_load(f)["services"]
        self.assertNotIn("km-dns-up", gate)

    def test_a_nodes_pihole_asks_the_master_for_a_partners_names(self):
        m = json.loads(json.dumps(MACHINES["m1"]))
        m["node"]["dns"] = dict(m["node"]["dns"], partner_domains=["internal", m["domain"], ""])
        out = self.render("m1-fed", m)
        with open(os.path.join(out, "docker-compose.yml")) as f:
            compose = f.read()
        self.assertRegex(compose, r"server=/internal/[0-9.]+;server=/\*\.internal/[0-9.]+")    # past Pi-hole's local=/internal/
        self.assertEqual(compose.count("server=/%s/" % m["domain"]), 1)                       # its own domain once, as before

    def test_a_master_links_to_a_partner_and_lets_in_only_what_is_shared(self):
        m = json.loads(json.dumps(MACHINES["gate"]))
        m["master"].setdefault("vpn-server", {})["federation"] = {"kiwi2": self.PARTNER}
        m["dns_records"] = RECORDS
        out = self.render("gate-fed", m)
        with open(os.path.join(out, "km-vpn-server", "start.sh")) as f:
            start = f.read()
        self.assertIn("ip link add wg-fed type wireguard", start)
        self.assertIn("listen-port 51822 fwmark 65", start)      # gate exits through Mullvad: the link must not
        self.assertIn("endpoint 198.51.100.9:51822 allowed-ips 10.10.0.0/16 persistent-keepalive 25", start)
        self.assertRegex(start, r"-A KIWI_FED -s 10\.10\.3\.0/24 -d [0-9.]+ -p tcp --dport 443 -j ACCEPT")   # a service
        self.assertRegex(start, r"-A KIWI_FED -s 10\.10\.3\.0/24 -d [0-9.]+ -p tcp --dport 22 -j ACCEPT")    # a port
        self.assertRegex(start, r"-A KIWI_FED -s 10\.10\.3\.0/24 -d [0-9.]+ -j ACCEPT")                      # a node
        self.assertIn("# share nowhere: no such name in this fleet, left out", start)
        self.assertIn("-t nat -A POSTROUTING -s 10.10.0.0/16 -o wg0 -j SNAT --to-source 10.8.255.1", start)
        self.assertLess(start.index("-A KIWI_FED -s"), start.index("-A KIWI_FED -j DROP"))
        with open(os.path.join(out, "docker-compose.yml")) as f:
            compose = f.read()
        self.assertIn("server=/internal/10.10.0.1", compose)
        self.assertIn("server=/*.internal/10.10.0.1", compose)     # past Pi-hole's own local=/internal/
        self.assertIn("51822:51822/udp", compose)
        # what it opens to the partner, for the partner's picture; and whom to ask the same
        self.assertIn("txt-record=10-10-0-0-16._kiwi-share.%s,cloud.sh3,m1:22,min,nowhere" % m["domain"], compose)
        self.assertIn("txt-record=_kiwi-master.%s,gate.%s" % (m["domain"], m["domain"]), compose)
        with open(os.path.join(out, "kiwi", "federation-ask")) as f:
            self.assertEqual(f.read().split(), ["kiwi2", "internal", "10-8-0-0-16"])        # its own mesh, as the partner names it

    def test_a_partner_with_this_networks_mesh_and_domain_is_translated_at_the_link(self):
        """docs/design/federation.md in kiwi-server: seen here under another /16 and domain; the link's
        DNS translates its names, NETMAP its addresses, its answers go back over the link."""
        m = json.loads(json.dumps(MACHINES["gate"]))
        same = dict(self.PARTNER, mesh="10.8.0.0/16", domain=m["domain"], dns="10.8.0.1", **{"from": []},
                    seen_as={"mesh": "10.208.0.0/16", "domain": "kiwi2." + m["domain"], "dns": "10.208.0.1", "link": "10.8.255.254"})
        m["master"].setdefault("vpn-server", {})["federation"] = {"kiwi2": same}
        m["dns_records"] = RECORDS
        out = self.render("gate-same", m)
        path = os.path.join(out, "km-vpn-server", "start.sh")
        self.assertEqual(subprocess.run(["sh", "-n", path]).returncode, 0)
        with open(path) as f:
            start = f.read()
        self.assertNotIn("ip route replace 10.8.0.0/16 dev wg-fed", start)          # never over this network's own mesh
        self.assertIn("iptables -t nat -A $hook -d 10.208.0.0/16 -j NETMAP --to 10.8.0.0/16", start)
        self.assertIn("ip rule add pref 90 fwmark 301 table 301", start)
        self.assertIn("ip route replace 10.208.0.0/16 dev wg-fed", start)            # its own lookups find a way
        self.assertIn("echo 1 > /proc/sys/net/ipv4/conf/wg-fed/accept_local", start)  # the partner answers from our address
        self.assertIn("-o wg-fed -m mark --mark 301 -s 10.8.0.1 -j SNAT --to-source 10.8.255.254", start)
        self.assertIn("-o wg0 -m connmark --mark 301 -j SNAT --to-source 10.8.255.1", start)
        self.assertNotIn("-s 10.8.0.0/16 -o wg0 -j SNAT", start)                      # that would catch its own clients
        self.assertIn("--dport 5353 -j DROP", start)
        with open(os.path.join(out, "docker-compose.yml")) as f:
            compose = f.read()
        self.assertIn("km-fed-dns:", compose)
        self.assertIn("km-fed-dns:\n    image: docker.io/library/python:3.13-alpine\n    container_name: km-fed-dns\n    network_mode: service:km-vpn-server", compose)
        self.assertIn("server=/kiwi2.%s/127.0.0.1#5353" % m["domain"], compose)
        self.assertIn("server=/*.kiwi2.%s/127.0.0.1#5353" % m["domain"], compose)
        with open(os.path.join(out, "km-vpn-server", "fed-dns", "fed-dns.json")) as f:
            self.assertEqual(json.load(f), [{"name": "kiwi2", "alias": "kiwi2." + m["domain"], "real": m["domain"],
                                             "upstream": "10.208.0.1", "mesh": "10.8.0.0/16", "seen_as": "10.208.0.0/16"}])
        self.assertTrue(os.path.isfile(os.path.join(out, "km-vpn-server", "fed-dns", "fed-dns.py")))
        with open(os.path.join(out, "kiwi", "federation-ask")) as f:
            self.assertEqual(f.read().split()[:2], ["kiwi2", "kiwi2." + m["domain"]])     # asked under its alias
        # a partner of another mesh and domain: no translation, no proxy
        out = self.render("gate-other", dict(m, master=dict(m["master"], **{"vpn-server": dict(m["master"]["vpn-server"], federation={"kiwi2": self.PARTNER})})))
        with open(os.path.join(out, "docker-compose.yml")) as f:
            self.assertNotIn("fed-dns", f.read())

    def test_a_shared_node_answers_the_name_a_partner_of_the_same_domain_gives_it(self):
        m = json.loads(json.dumps(SH3))
        m["node"]["reverse-proxy"] = dict(m["node"].get("reverse-proxy") or {}, federation={
            "names": {"cloud.sh3.home": {"allow": ["10.8.255.1"], "deny": []}}, "deny": [],
            "alias": {"domain": "home", "as": "kiwi.home"}})
        out = self.render("sh3-alias", m)
        with open(os.path.join(out, "kn-nginx", "nginx.conf")) as f:
            nginx = f.read()
        self.assertIn("server_name cloud.sh3.home cloud.sh3.kiwi.home;", nginx)
        # with a certificate the partner's CA signed: the alias in a server of its own, with that certificate
        m["node"]["reverse-proxy"]["alias_fullchain"] = TLS["tls_fullchain"]
        out = self.render("sh3-alias-cert", m)
        with open(os.path.join(out, "kn-nginx", "nginx.conf")) as f:
            nginx = f.read()
        self.assertIn("server_name cloud.sh3.home;", nginx)
        alias = nginx.split("server_name cloud.sh3.kiwi.home;", 1)[1].split("\n    }\n", 1)[0]
        self.assertIn("ssl_certificate     /etc/nginx/alias-fullchain.pem;", alias)
        self.assertIn("allow 10.8.255.1;", alias)                     # the partner's rules hold there too
        self.assertIn("location / {", alias)
        self.assertTrue(os.path.isfile(os.path.join(out, "kn-nginx", "alias-fullchain.pem")))
        with open(os.path.join(out, "docker-compose.yml")) as f:
            self.assertIn("alias-fullchain.pem:/etc/nginx/alias-fullchain.pem:ro", f.read())

    def start_of(self, name, **partner):
        m = json.loads(json.dumps(MACHINES["gate"]))
        m["master"].setdefault("vpn-server", {})["federation"] = {"kiwi2": dict(self.PARTNER, **partner)}
        m["dns_records"] = RECORDS
        out = self.render(name, m)
        path = os.path.join(out, "km-vpn-server", "start.sh")
        self.assertEqual(subprocess.run(["sh", "-n", path]).returncode, 0)
        with open(path) as f:
            return f.read()

    def test_a_network_leaves_through_its_partner_over_the_link(self):
        """The exit rides the link that is there: no VPN client that logs in to the partner's
        VPN server, no second tunnel."""
        plain = self.start_of("gate-fed-plain")
        self.assertNotIn("table 202", plain)
        self.assertNotIn("0.0.0.0/0", plain)
        start = self.start_of("gate-fed-exit", exit=True)
        self.assertIn("allowed-ips 10.10.0.0/16,0.0.0.0/0 persistent-keepalive 25", start)
        self.assertIn("ip rule add iif wg0 table 202", start)                 # what the clients send
        self.assertIn("ip route add default dev wg-fed table 202", start)     # the internet: over the link
        for mesh in ("10.8.0.0/16", "10.10.0.0/16"):                          # the meshes: as before
            self.assertIn("ip route add throw %s table 202" % mesh, start)
        # the partner sees this master, not its clients; what goes to the partner's mesh keeps its address
        self.assertLess(start.index("-A KIWI_FED_SNAT -d 10.10.0.0/16 -j RETURN"),
                        start.index("-A KIWI_FED_SNAT -j SNAT --to-source 10.8.0.1"))
        self.assertIn("-t nat -A POSTROUTING -o wg-fed -j KIWI_FED_SNAT", start)
        # the kill switch: with the link down, not out by this master's own connection
        self.assertRegex(start, r"iptables -I FORWARD 1 -i wg0 -o eth0 ! -d [0-9./]+ -j DROP")

    def test_only_some_groups_leave_through_the_partner(self):
        """exit: [groups]: those groups' clients leave over the link, with their own kill switch;
        the others leave by this master's own way. A group the VPN does not have is refused."""
        start = self.start_of("gate-fed-groups", exit=["family", "devices"])
        self.assertIn("allowed-ips 10.10.0.0/16,0.0.0.0/0 persistent-keepalive 25", start)
        self.assertNotIn("ip rule add iif wg0 table 202", start)
        self.assertIn("ip rule add iif wg0 from 10.8.5.0/24 table 202", start)
        self.assertIn("ip rule add iif wg0 from 10.8.3.0/24 table 202", start)
        self.assertNotIn("from 10.8.1.0/24 table 202", start)
        self.assertRegex(start, r"iptables -I FORWARD 1 -i wg0 -s 10.8.5.0/24 -o eth0 ! -d [0-9./]+ -j DROP")
        self.assertNotRegex(start, r"iptables -I FORWARD 1 -i wg0 -o eth0 ")
        m = json.loads(json.dumps(MACHINES["gate"]))
        m["master"].setdefault("vpn-server", {})["federation"] = {"kiwi2": dict(self.PARTNER, exit=["family", "nobody"])}
        m["dns_records"] = RECORDS
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertNotEqual(cli.main(["render", self.write("gate-fed-bad", m), "-o", os.path.join(self.tmp, "bad")]), 0)
        self.assertIn("exit names groups this VPN does not have: nobody", err.getvalue())

    def test_a_partner_may_leave_through_this_master_and_only_to_the_internet(self):
        plain = self.start_of("gate-fed-plain2")
        self.assertNotIn("KIWI_FED_OUT", plain)
        start = self.start_of("gate-fed-out", internet=True)
        for net in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"):
            self.assertIn("-A KIWI_FED_OUT -d %s -j RETURN" % net, start)     # never a private network, this mesh included
        self.assertLess(start.index("-A KIWI_FED_OUT -d 10.0.0.0/8 -j RETURN"), start.index("-A KIWI_FED_OUT -j ACCEPT"))
        self.assertIn("-A KIWI_FED -s 10.10.0.1 -j KIWI_FED_OUT", start)      # the partner's master, as it arrives
        self.assertLess(start.index("-j KIWI_FED_OUT"), start.index("-A KIWI_FED -j DROP"))
        self.assertIn("-t nat -A POSTROUTING -s 10.10.0.0/16 -o eth0 -j MASQUERADE", start)
        self.assertNotIn("table 202", start)                                  # letting out is not leaving

    def test_a_masters_containers_reach_its_own_names_where_the_proxy_is(self):
        m = json.loads(json.dumps(MACHINES["gate"]))
        m["dns_records"] = RECORDS
        out = self.render("gate-names", m)
        with open(os.path.join(out, "docker-compose.yml")) as f:
            compose = yaml.safe_load(f)
        server = compose["services"]["km-vpn-server"]
        ip = server["networks"]["knet-master"]["ipv4_address"]
        self.assertIn("wg.gate.home:%s" % ip, server["extra_hosts"])     # nginx lives in this namespace

    def test_a_moving_address_on_the_hosts_network(self):
        """vip (basics-twice.md): keepalived on the host's network, configured from its environment."""
        name = "m1"
        m = json.loads(json.dumps(MACHINES[name]))
        m["node"]["modules"] = ["vpn-client", "dns", "dhcp-relay", "reverse-proxy", "downloader", "gateway", "portainer",
                                "sftp", "vip"]      # its preset's, and the moving address
        m["node"]["vip"] = {"address": "192.168.2.70/16", "peers": ["192.168.2.30"], "priority": 150, "password": "pairpass"}
        out = self.render(name + "-vip", m)
        with open(os.path.join(out, "docker-compose.yml")) as f:
            svc = [v for k, v in yaml.safe_load(f)["services"].items() if k.endswith("-vip")][0]
        self.assertEqual(svc["network_mode"], "host")
        self.assertIn("NET_ADMIN", svc["cap_add"])
        env = svc["environment"]
        self.assertEqual((env["VIP_ADDRESS"], env["VIP_PEERS"], env["VIP_PRIORITY"], env["VIP_ROUTER_ID"], env["VIP_CHECK_DNS"]),
                         ("192.168.2.70/16", "192.168.2.30", "150", "70", "1"))

    def test_dhcp_follows_the_moving_address(self):
        """dhcp-relay with `follow` (filled in by kiwi-server beside vip): only the holder of the moving
        address relays, so one Pi-hole at a time hands out leases (tests/drills/dhcp-pair.sh in
        kiwi-server: halves on both gave devices new addresses). Without it, it relays as before."""
        name = "m1"
        m = json.loads(json.dumps(MACHINES[name]))
        m["node"]["modules"] = ["vpn-client", "dns", "dhcp-relay", "reverse-proxy", "downloader", "gateway", "portainer",
                                "sftp", "vip"]
        m["node"]["vip"] = {"address": "192.168.2.70/16", "peers": ["192.168.2.30"], "priority": 150, "password": "pairpass"}
        m["node"]["dhcp-relay"] = {"follow": "192.168.2.70"}
        out = self.render(name + "-follow", m)
        with open(os.path.join(out, "docker-compose.yml")) as f:
            svc = [v for k, v in yaml.safe_load(f)["services"].items() if k.endswith("-dhcphelper")][0]
        self.assertEqual((svc["entrypoint"], svc["command"]), (["/bin/sh"], ["/kiwi/follow.sh"]))
        script = [os.path.join(r, f) for r, _d, fs in os.walk(out) for f in fs if f == "follow.sh"]
        self.assertEqual(len(script), 1)
        with open(script[0]) as f:
            text = f.read()
        self.assertIn('VIP="192.168.2.70"', text)
        self.assertIn("dhcp-helper -n -s", text)
        del m["node"]["dhcp-relay"]
        out = self.render(name + "-always", m)
        with open(os.path.join(out, "docker-compose.yml")) as f:
            svc = [v for k, v in yaml.safe_load(f)["services"].items() if k.endswith("-dhcphelper")][0]
        self.assertNotIn("entrypoint", svc)
        self.assertFalse([f for _r, _d, fs in os.walk(out) for f in fs if f == "follow.sh"])

    def test_the_vpn_client_connects_anew_every_day(self):
        """vpn-client reconnect: a daily timer runs kiwi-stack vpn-restart; with server cities a
        provider gives another random server each time (v1's master: docker restart at 07:00)."""
        m = json.loads(json.dumps(MACHINES["gate"]))
        m["master"]["vpn-client"] = dict(m["master"].get("vpn-client") or {}, reconnect="07:00")
        out = self.render("gate-reconnect", m)
        units = [os.path.join(r, f) for r, _d, fs in os.walk(out) for f in fs if "vpn-reconnect" in f]
        timer = [u for u in units if u.endswith(".timer")]
        self.assertEqual(len(timer), 1, units)
        with open(timer[0]) as f:
            self.assertIn("OnCalendar=*-*-* 07:00:00", f.read())
        with open([u for u in units if u.endswith(".service")][0]) as f:
            self.assertIn("ExecStart=/usr/local/bin/kiwi-stack vpn-restart", f.read())
        m["master"]["vpn-client"]["reconnect"] = "7 Uhr"
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertNotEqual(cli.main(["render", self.write("gate-reconnect-bad", m), "-o", os.path.join(self.tmp, "rb")]), 0)
        self.assertIn("vpn-client.reconnect is a time of day like 07:00", err.getvalue())
        del m["master"]["vpn-client"]["reconnect"]
        out = self.render("gate-reconnect-none", m)
        self.assertFalse([f for _r, _d, fs in os.walk(out) for f in fs if "vpn-reconnect" in f])

    def test_a_local_ai_on_the_lan_and_the_vpn_only(self):
        """ai (Unsloth Studio): the GPU into the container, the page and the API only for the
        addresses kiwi-server fills in, ipc and ulimits as Unsloth asks, for docker and podman."""
        m = json.loads(json.dumps(MACHINES["m1"]))
        m["node"]["modules"] = ["vpn-client", "dns", "dhcp-relay", "reverse-proxy", "downloader", "gateway", "portainer",
                                "sftp", "ai"]
        m["node"]["ai"] = {"gpu": "amd", "allow": ["192.168.2.0/24", "10.9.0.0/16"]}
        out = self.render("m1-ai", m)
        with open(os.path.join(out, "docker-compose.yml")) as f:
            svc = yaml.safe_load(f)["services"]["kn-ai"]
        self.assertEqual(svc["image"], "docker.io/unsloth/unsloth-rocm:studio")
        self.assertEqual(svc["devices"], ["/dev/kfd", "/dev/dri"])
        self.assertEqual((svc["ipc"], svc["ulimits"]), ("host", {"memlock": -1, "stack": 67108864}))
        self.assertIn("UNSLOTH_STUDIO_PORT=8000", svc["environment"])
        self.assertFalse([e for e in svc["environment"] if e.startswith("UNSLOTH_SAMPLING_")])   # nothing fixed unless asked
        cmd = svc["command"][-1]
        self.assertIn("--no-cloudflare --disable-tools", cmd)            # no tunnel, no tools; no JupyterLab
        self.assertIn("unsloth-studio-run --stored", cmd)                # the initial password only once
        meta = yaml.safe_load(open(os.path.join(ROOT, "modules", "ai", "module.yaml")))
        self.assertEqual([(x.get("user", ""), x["password"], x["when"]) for x in meta["logins"]],
                         [("unsloth", "studio_password", "studio"), ("", "api_key", "lean")])
        nginx = "".join(open(os.path.join(r, f)).read() for r, _d, fs in os.walk(out) for f in fs if f == "nginx.conf")
        self.assertIn("allow 192.168.2.0/24; allow 10.9.0.0/16; deny all;", nginx)
        m["node"]["runtime"] = "podman"
        out = self.render("m1-ai-podman", m)
        quad = [os.path.join(r, f) for r, _d, fs in os.walk(out) for f in fs if f == "kn-ai.container"]
        self.assertTrue(quad, out)
        with open(quad[0]) as f:
            text = f.read()
        for want in ("AddDevice=/dev/kfd", "PodmanArgs=--ipc=host", "Ulimit=memlock=-1:-1", "Ulimit=stack=67108864:67108864",
                     "--disable-tools"):
            self.assertIn(want, text)
        self.assertNotIn("UNSLOTH_SAMPLING_TOP_K", text)
        m["node"]["ai"] = {"gpu": "amd", "allow": ["192.168.2.0/24"], "top_k": 20}       # Top-K fixed for every request
        out = self.render("m1-ai-topk", m)
        quad = [os.path.join(r, f) for r, _d, fs in os.walk(out) for f in fs if f == "kn-ai.container"]
        with open(quad[0]) as f:
            self.assertIn("UNSLOTH_SAMPLING_TOP_K=20", f.read())
        m["node"]["ai"] = {"gpu": "amd", "allow": ["192.168.2.0/24"], "top_k": 500}
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertNotEqual(cli.main(["render", self.write("m1-ai-topk-bad", m), "-o", os.path.join(self.tmp, "topk-bad")]), 0)
        self.assertIn("ai.top_k: 0 (not fixed) to 100", err.getvalue())
        m["node"]["ai"] = {"gpu": "amd", "allow": []}
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertNotEqual(cli.main(["render", self.write("m1-ai-closed", m), "-o", os.path.join(self.tmp, "closed")]), 0)
        self.assertIn("ai.allow: nobody may reach it", err.getvalue())

    def test_a_lean_local_ai_is_llama_cpp_alone(self):
        """ai with engine: llama: llama.cpp's server in place of Studio, for a small graphics chip
        (Vulkan, /dev/dri) or the processor alone; its models in a file, one in memory at a time,
        asleep when idle; a key from the seed; no Studio volume, nothing of Studio's to back up."""
        m = json.loads(json.dumps(MACHINES["m1"]))
        m["node"]["modules"] = ["vpn-client", "dns", "dhcp-relay", "reverse-proxy", "downloader", "gateway", "portainer",
                                "sftp", "backup", "ai"]
        m["node"]["ai"] = {"engine": "llama", "gpu": "vulkan", "allow": ["192.168.2.0/24"],
                           "models": ["ggml-org/gemma-3-4b-it-GGUF:Q4_K_M", "unsloth/Qwen3-8B-GGUF"]}
        m["node"]["backup"] = {"server": "https://backup.lychee.home"}
        out = self.render("m1-lean", m)
        with open(os.path.join(out, "docker-compose.yml")) as f:
            compose = yaml.safe_load(f)
        svc = compose["services"]["kn-ai"]
        self.assertEqual(svc["image"], "ghcr.io/ggml-org/llama.cpp:server-vulkan")
        self.assertEqual(svc["devices"], ["/dev/dri"])
        self.assertEqual(svc["command"], ["--host", "0.0.0.0", "--port", "8000", "--models-preset", "/etc/llama/models.ini",
                                          "--models-max", "1", "--sleep-idle-seconds", "600"])
        for off in ("--tools", "--agent", "--connect", "--ui-mcp-proxy", "--allow-unauthenticated-tools"):
            self.assertNotIn(off, svc["command"])
        env = dict(e.split("=", 1) for e in svc["environment"])
        self.assertEqual(env["LLAMA_CACHE"], "/models/hub")                 # where Studio keeps its models too
        self.assertRegex(env["LLAMA_API_KEY"], r"^[A-Za-z0-9]{16,}$")       # from the seed
        self.assertNotIn("ipc", svc)
        self.assertNotIn("unsloth_studio", compose.get("volumes") or {})
        self.assertIn("/kn-ai/models.ini:/etc/llama/models.ini:ro,z", " ".join(svc["volumes"]))
        ini = [read(r, f) for r, _d, fs in os.walk(out) for f in fs if f == "models.ini"]
        self.assertEqual(len(ini), 1, out)
        self.assertIn("[*]\nctx-size = 8192\n", ini[0])
        self.assertIn("[ggml-org/gemma-3-4b-it-GGUF:Q4_K_M]\nhf-repo = ggml-org/gemma-3-4b-it-GGUF:Q4_K_M\nload-on-startup = true\n",
                      ini[0])
        self.assertIn("[unsloth/Qwen3-8B-GGUF]\nhf-repo = unsloth/Qwen3-8B-GGUF\n", ini[0])
        self.assertEqual(ini[0].count("load-on-startup"), 1)                # the first one only
        self.assertNotIn("threads", ini[0])
        everything = "".join(open(os.path.join(r, f), errors="replace").read() for r, _d, fs in os.walk(out) for f in fs)
        self.assertNotIn("unsloth_studio", everything)                      # no volume, no backup of one
        self.assertIn("allow 192.168.2.0/24; deny all;", everything)
        # the processor alone, always loaded, with fewer threads; NVIDIA takes the CUDA image
        m["node"]["ai"].update(gpu="none", idle_minutes=0, threads=4, context=0)
        m["node"]["runtime"] = "podman"
        out = self.render("m1-lean-cpu", m)
        quad = [os.path.join(r, f) for r, _d, fs in os.walk(out) for f in fs if f == "kn-ai.container"]
        text = read(os.path.dirname(quad[0]), "kn-ai.container")
        self.assertIn("Image=ghcr.io/ggml-org/llama.cpp:server\n", text)
        self.assertNotIn("AddDevice", text)
        self.assertNotIn("sleep-idle", text)
        ini = [read(r, f) for r, _d, fs in os.walk(out) for f in fs if f == "models.ini"][0]
        self.assertIn("threads = 4", ini)
        self.assertNotIn("ctx-size", ini)
        self.assertFalse([f for _r, _d, fs in os.walk(out) for f in fs if f == "unsloth_studio.volume"])
        m["node"]["ai"].update(gpu="nvidia")
        out = self.render("m1-lean-nvidia", m)
        text = "".join(read(r, f) for r, _d, fs in os.walk(out) for f in fs if f == "kn-ai.container")
        self.assertIn("Image=ghcr.io/ggml-org/llama.cpp:server-cuda\n", text)
        self.assertIn("nvidia.com/gpu=all", text)
        # what is refused: Studio without a graphics card, no model, a name that is not one
        for ai, want in (({"engine": "studio", "gpu": "vulkan"}, "Unsloth Studio needs a graphics card"),
                         ({"engine": "llama", "gpu": "none", "models": []}, "llama.cpp needs at least one model"),
                         ({"engine": "llama", "gpu": "none", "models": ["gemma]\nagent = true"]}, "named as on Hugging Face"),
                         ({"engine": "llama", "gpu": "none", "models": ["../x/y"]}, "named as on Hugging Face"),
                         ({"engine": "ollama", "gpu": "none"}, "ai.engine must be one of studio, llama")):
            m["node"]["ai"] = dict(ai, allow=["192.168.2.0/24"])
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                self.assertNotEqual(cli.main(["render", self.write("m1-lean-bad", m), "-o", os.path.join(self.tmp, "bad")]), 0)
            self.assertIn(want, err.getvalue())

    def test_fail2ban_watches_the_ssh_port_and_limits_new_connections(self):
        m = json.loads(json.dumps(MACHINES["gate"]))
        m["master"]["modules"] = ["vpn-client", "vpn-server", "dns", "tor", "reverse-proxy", "fail2ban"]
        m["admin"] = dict(m["admin"], ssh_port=2222)          # fail2ban follows it
        m["master"]["fail2ban"] = {"ignore": ["198.51.100.7"]}
        out = self.render("gate-f2b", m)
        with open(os.path.join(out, "km-fail2ban", "config", "fail2ban", "jail.d", "kiwi.local")) as f:
            jail = f.read()
        self.assertIn("port     = 2222", jail)
        self.assertIn("198.51.100.7", jail)
        self.assertIn("10.8.0.0/16", jail)          # the mesh is never banned
        with open(os.path.join(out, "km-fail2ban", "init", "50-kiwi-ratelimit")) as f:
            self.assertIn("--dport 2222", f.read())
        with open(os.path.join(out, "docker-compose.yml")) as f:
            svc = yaml.safe_load(f)["services"]["km-fail2ban"]
        self.assertEqual(svc["network_mode"], "host")
        self.assertIn("/var/log/kiwi:/var/log/kiwi:ro,z", svc["volumes"])
        self.assertTrue(os.path.isfile(os.path.join(out, "host-units", "kn-sshd-log.service")))

    def test_fail2ban_watches_a_public_masters_sites_in_forward(self):
        m = TestRender.public_hub(self)
        m["master"] = dict(m["master"], modules=list(m["master"].get("modules") or
                           ["vpn-client", "vpn-server", "dns", "tor", "reverse-proxy", "nostr-relay", "hub"]) + ["fail2ban"])
        out = self.render("hub-f2b", m)
        with open(os.path.join(out, "km-fail2ban", "config", "fail2ban", "jail.d", "kiwi.local")) as f:
            jail = f.read()
        self.assertIn("[kiwi-nginx-probe]", jail)
        self.assertIn("chain    = FORWARD", jail)
        self.assertTrue(os.path.isfile(os.path.join(out, "km-fail2ban", "config", "fail2ban", "filter.d", "kiwi-nginx-probe.conf")))
        with open(os.path.join(out, "docker-compose.yml")) as f:
            svcs = yaml.safe_load(f)["services"]
        self.assertIn("/home/user/docker/km-nginx/log:/var/log/nginx:ro,z", svcs["km-fail2ban"]["volumes"])
        self.assertIn("/home/user/docker/km-nginx/log:/var/log/nginx:z", svcs["km-nginx"]["volumes"])
        self.assertTrue(os.path.isfile(os.path.join(out, "host-units", "km-nginx-logs.timer")))

    def test_every_wireguard_provider_of_gluetun_is_an_exit(self):
        def env(name, vc):
            m = json.loads(json.dumps(MACHINES["gate"]))
            m["master"]["vpn-client"] = vc
            out = self.render(name, m)
            with open(os.path.join(out, "docker-compose.yml")) as f:
                return "\n".join(yaml.safe_load(f)["services"]["km-vpn-client"]["environment"])
        e = env("exit-proton", {"vpn_provider": "protonvpn", "wireguard_private_key": "golden-proton-key", "server_countries": "Switzerland"})
        self.assertIn("VPN_SERVICE_PROVIDER=protonvpn", e)
        self.assertNotIn("WIREGUARD_ADDRESSES", e)                      # Proton and Nord give out no address
        self.assertIn("SERVER_COUNTRIES=Switzerland", e)
        e = env("exit-air", {"vpn_provider": "airvpn", "wireguard_private_key": "k", "wireguard_addresses": "10.128.0.2/32",
                             "wireguard_preshared_key": "golden-psk", "server_regions": "Europe"})
        self.assertIn("SERVER_REGIONS=Europe", e)
        self.assertIn("WIREGUARD_ADDRESSES=10.128.0.2/32", e)
        e = env("exit-other", {"vpn_provider": "custom", "wireguard_private_key": "k", "wireguard_addresses": "10.2.0.2/32",
                               "wireguard_public_key": "golden-server-pub", "wireguard_endpoint_ip": "203.0.113.9", "vpn_endpoint_port": 51820})
        for want in ("WIREGUARD_PUBLIC_KEY=golden-server-pub", "WIREGUARD_ENDPOINT_IP=203.0.113.9", "WIREGUARD_ENDPOINT_PORT=51820"):
            self.assertIn(want, e)
        # what each one needs, said before anything is sent
        m = json.loads(json.dumps(MACHINES["gate"]))
        for vc, words in (({"vpn_provider": "airvpn", "wireguard_private_key": "k", "wireguard_addresses": "10.1.0.2/32"}, "preshared"),
                          ({"vpn_provider": "surfshark", "wireguard_private_key": "k"}, "wireguard_addresses"),
                          ({"vpn_provider": "nordvpn"}, "wireguard_private_key")):
            m["master"]["vpn-client"] = vc
            buf = io.StringIO()
            with contextlib.redirect_stderr(buf):
                self.assertNotEqual(cli.main(["render", self.write("exit-bad", m), "-o", os.path.join(self.tmp, "bad.bundle")]), 0)
            self.assertIn(words, buf.getvalue())

    def test_accounts_is_kanidm_behind_the_proxy_with_the_machines_certificate(self):
        n = json.loads(json.dumps(SH3))
        n["node"]["modules"] = ["vpn-client", "reverse-proxy", "accounts"]
        n["node"].pop("preset", None); n["node"].pop("cloud", None)
        n["node"]["accounts"] = {"ldap": True}
        out = self.render("accounts", n)
        with open(os.path.join(out, "kn-accounts", "server.toml")) as f:
            conf = f.read()
        self.assertIn('domain = "id.sh3.home"', conf)
        self.assertIn('origin = "https://id.sh3.home"', conf)
        self.assertIn('ldapbindaddress = "0.0.0.0:3636"', conf)
        self.assertIn('tls_chain = "/certs/fullchain.pem"', conf)
        with open(os.path.join(out, "docker-compose.yml")) as f:
            svc = yaml.safe_load(f)["services"]["kn-accounts"]
        self.assertIn("/home/user/docker/kn-nginx/fullchain.pem:/certs/fullchain.pem:ro,z", svc["volumes"])
        self.assertEqual(svc["command"], ["/sbin/kanidmd", "server", "-c", "/config/server.toml"])
        with open(os.path.join(out, "kn-nginx", "nginx.conf")) as f:
            nginx = f.read()
        block = nginx[nginx.index("server_name id.sh3.home;"):]
        self.assertIn("proxy_pass $backend;", block[:1500])
        self.assertIn("https://kn-accounts:8443", block[:1500])
        self.assertIn("proxy_ssl_verify off;", block[:1500])
        # the sign-up page in front, in its own container, with its rules
        self.assertIn("location = / {\n            return 302 /join;", block[:3000])
        self.assertIn("location /join {", block[:3000])
        self.assertIn("set $signup http://kn-signup:8080;", block[:3000])
        with open(os.path.join(out, "docker-compose.yml")) as f:
            su = yaml.safe_load(f)["services"]["kn-signup"]
        self.assertEqual(su["command"][:2], ["signup", "serve"])
        self.assertIn("/home/user/docker/kn-accounts/signup:/state:z", su["volumes"])
        self.assertTrue(os.path.isfile(os.path.join(out, "kn-accounts", "signup", "terms.txt")))
        self.assertTrue(os.path.isfile(os.path.join(out, "host-units", "kn-accounts-setup.service")))
        # it waits for Kanidm's own page, not for a command Kanidm 1.12 no longer has (the wait never
        # ended early and every apply of the machine took two minutes more, quince, 27 Nov 2026)
        unit = read(out, "host-units/kn-accounts-setup.service")
        self.assertRegex(unit, r"curl -fsk -m 3 -o /dev/null https://172\.\d+\.\d+\.\d+:8443/status && exit 0")
        self.assertNotIn("kanidmd healthcheck", unit.split("ExecStartPre=", 1)[1])
        with open(os.path.join(out, "kiwi", "accounts.sh")) as f:
            sh = f.read()
        self.assertIn("allow-primary-cred-fallback jabber true", sh)               # Jabber takes the same password
        self.assertIn("credential-type-minimum idm_all_persons any", sh)
        r = subprocess.run(["sh", "-n", os.path.join(out, "kiwi", "accounts.sh")], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        n["node"]["accounts"] = {"signup": False, "second_factor": True}
        out = self.render("accounts-noldap", n)
        with open(os.path.join(out, "kn-accounts", "server.toml")) as f:
            self.assertNotIn("ldapbindaddress", f.read())
        with open(os.path.join(out, "docker-compose.yml")) as f:
            self.assertNotIn("kn-signup", yaml.safe_load(f)["services"])
        with open(os.path.join(out, "kiwi", "accounts.sh")) as f:
            self.assertIn("credential-type-minimum idm_all_persons mfa", f.read())

    def test_accounts_oauth_makes_the_client_with_its_callbacks(self):
        """accounts.sh oauth, run for real against a stand-in for podman that writes down the
        kanidm commands it is given."""
        n = json.loads(json.dumps(SH3))
        n["node"]["modules"] = ["vpn-client", "reverse-proxy", "accounts"]
        n["node"].pop("preset", None); n["node"].pop("cloud", None)
        out = self.render("accounts-oauth", n)
        with open(os.path.join(out, "kiwi", "accounts.sh")) as f:
            sh = f.read()
        base = tempfile.mkdtemp()
        os.makedirs(os.path.join(base, "kn-accounts", "data"))
        log = os.path.join(base, "log")
        fake = os.path.join(base, "podman")
        with open(fake, "w") as f:
            f.write('#!/bin/sh\ncase "$*" in\n'
                    '  *recover-account*) echo \'{"new_password": "x"}\' ;;\n'
                    '  *show-basic-secret*) echo sekret ;;\n'
                    '  *"oauth2 list"*) echo "name: old-sh3" ;;\n'
                    '  *" kanidm "*) echo "$*" | sed "s/.* kanidm //" >> ' + log + '; echo "$*" | grep -o "KANIDM_URL=[^ ]*" >> ' + log + '.url ;;\n'
                    'esac\n')
        os.chmod(fake, 0o755)
        script = os.path.join(base, "accounts.sh")
        with open(script, "w") as f:
            f.write(re.sub(r"(?m)^rt=.*$", "rt=" + fake, sh).replace("/home/user/docker", base))

        def oauth(*words):
            open(log, "w").close()
            r = subprocess.run(["sh", script, "oauth"] + list(words), capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            with open(log) as f:
                return json.loads(r.stdout), f.read().splitlines()
        answer, cmds = oauth("immich-sh3", "Immich on sh3", "https://immich.sh3.home", "https://immich.sh3.home/auth/login",
                             "https://immich.sh3.home/api/oauth/mobile-redirect", "--pkce")
        self.assertEqual((answer["client"], answer["secret"]), ("immich-sh3", "sekret"))
        # the network's admins, told to every client in its own words: this one and the one made before
        for c in ("immich-sh3", "old-sh3"):
            self.assertIn("system oauth2 update-claim-map %s kiwi_roles admins admin" % c, cmds)
            self.assertIn("system oauth2 update-claim-map-join %s kiwi_roles array" % c, cmds)
            self.assertIn("system oauth2 update-claim-map %s immich_role admins admin" % c, cmds)
            self.assertIn("system oauth2 update-claim-map-join %s immich_role ssv" % c, cmds)
        self.assertIn("system oauth2 create immich-sh3 Immich on sh3 https://immich.sh3.home", cmds)
        self.assertIn("system oauth2 add-redirect-url immich-sh3 https://immich.sh3.home/auth/login", cmds)
        self.assertIn("system oauth2 add-redirect-url immich-sh3 https://immich.sh3.home/api/oauth/mobile-redirect", cmds)
        self.assertFalse(any("disable-pkce" in c or "--pkce" in c for c in cmds))
        with open(log + ".url") as f:                              # every call goes to Kanidm itself
            self.assertEqual(set(f.read().split()), {"KANIDM_URL=https://172.128.0.%s:8443" % re.search(r"rt=.*\nurl=https://172\.128\.0\.(\d+)", sh).group(1)})
        _answer, cmds = oauth("git-sh3", "Forgejo on sh3", "https://git.sh3.home", "https://git.sh3.home/user/oauth2/accounts/callback")
        self.assertIn("system oauth2 create git-sh3 Forgejo on sh3 https://git.sh3.home", cmds)
        self.assertIn("system oauth2 warning-insecure-client-disable-pkce git-sh3", cmds)
        self.assertIn("system oauth2 update-scope-map git-sh3 idm_all_persons openid email profile groups", cmds)
        # only a group's members (the game page): the group is made, everyone else is no longer mapped
        _answer, cmds = oauth("control-sh3", "Game page on sh3", "https://play.sh3.home", "https://play.sh3.home/back", "--group", "games")
        self.assertIn("system oauth2 add-redirect-url control-sh3 https://play.sh3.home/back", cmds)
        self.assertFalse(any("add-redirect-url control-sh3 games" in c for c in cmds))
        self.assertIn("group create games", cmds)
        self.assertIn("system oauth2 delete-scope-map control-sh3 idm_all_persons", cmds)
        self.assertIn("system oauth2 update-scope-map control-sh3 games openid email profile groups", cmds)
        r = subprocess.run(["sh", script, "oauth", "c-sh3", "C", "https://c.sh3.home", "https://c.sh3.home/b", "--group", "Bad Group"],
                           capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)
        # who is in a group, and in or out
        open(log, "w").close()
        r = subprocess.run(["sh", script, "member", "games", "alice", "on"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout), {"name": "alice", "group": "games", "member": "off"})   # (the stand-in keeps nobody)
        with open(log) as f:
            self.assertIn("group add-members games alice", f.read().splitlines())
        r = subprocess.run(["sh", script, "members", "games"], capture_output=True, text=True)
        self.assertEqual(json.loads(r.stdout), {"group": "games", "members": []})
        # Kanidm refuses: said, not swallowed
        with open(fake) as f:
            body = f.read().replace("#!/bin/sh\n", "#!/bin/sh\n" + 'case "$*" in *"oauth2 create"*) echo "invalid origin" >&2; exit 1 ;; esac\n', 1)
        with open(fake, "w") as f:
            f.write(body)
        r = subprocess.run(["sh", script, "oauth", "x-sh3", "X", "https://x.sh3.home", "https://x.sh3.home/cb"], capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("did not make the client x-sh3: invalid origin", r.stderr)

    def test_a_service_with_a_public_name_keeps_its_vpn_name_as_a_way_there(self):
        n = json.loads(json.dumps(SH3))
        n["node"]["modules"] = ["vpn-client", "reverse-proxy", "git"]
        n["node"].pop("preset", None); n["node"].pop("cloud", None)
        n["node"]["git"] = {"git_hostname": "git.example.org", "admin_password": "golden-git-pass"}
        n["node"]["vpn-client"] = {"vpn_provider": "mullvad", "wireguard_private_key": "golden-mullvad-key",
                                   "wireguard_addresses": "10.66.1.2/32"}
        n["vpn_ip"] = "10.8.0.25"
        n["node"].setdefault("reverse-proxy", {}).update(public=True, via="10.8.0.1")
        out = self.render("alias", n)
        with open(os.path.join(out, "kn-nginx", "nginx.conf")) as f:
            nginx = f.read()
        block = nginx[nginx.index("server_name git.sh3.home;") - 200:nginx.index("server_name git.sh3.home;") + 200]
        self.assertIn("return 301 https://git.example.org$request_uri;", block)
        self.assertIn("listen 443 ssl;", block)                         # the VPN's door, never the master's
        self.assertNotIn("8443", block)
        # without a public name there is nothing to send on
        n["node"]["git"] = {"admin_password": "golden-git-pass"}
        n["node"]["reverse-proxy"] = {}
        with open(os.path.join(self.render("alias-none", n), "kn-nginx", "nginx.conf")) as f:
            self.assertNotIn("return 301 https://git.", f.read())

    def test_the_bundle_says_which_module_each_container_is_of(self):
        from kiwimodules import machine as machmod, modules as modmod, profiles
        mm = machmod.load(self.write("owner", SH3))
        ms = modmod.discover()
        profile = profiles.discover()[mm.role]
        resolver.resolve_settings(profile, mm, ms)
        b = modmod.Renderer(ms).render(resolver.stack_spec(mm, profile, mm.dns_records))
        self.assertEqual(sorted(b.service_modules), sorted(b.services))       # every container, by its name
        self.assertEqual(b.service_modules[next(s for s in b.services if s.endswith("-nginx"))], "reverse-proxy")
        self.assertEqual(b.service_modules[next(s for s in b.services if s.endswith("-vpn-client"))], "vpn-client")

    def test_a_command_word_with_spaces_or_quotes_stays_one_word_in_the_quadlet(self):
        from kiwimodules import quadlet
        units, _env = quadlet.from_compose_with_env({"services": {"x": {"image": "img", "container_name": "x",
            "command": ["serve", "--map", '{"a b": {"c": "d"}}', "--name", "50% off"]}}}, "net")
        execline = [l for l in units["x.container"].splitlines() if l.startswith("Exec=")][0]
        self.assertEqual(execline, 'Exec=serve --map "{\\"a b\\": {\\"c\\": \\"d\\"}}" --name "50%% off"')
        self.assertEqual(shlex.split(execline[5:].replace("%%", "%")), ["serve", "--map", '{"a b": {"c": "d"}}', "--name", "50% off"])
        # an empty word stays one word (an empty --id-onion vanished and the sign-up stopped, 19 Nov 2026)
        units, _env = quadlet.from_compose_with_env({"services": {"x": {"image": "img", "container_name": "x",
            "command": ["serve", "--id-onion", "", "--listen", "0.0.0.0:8080"]}}}, "net")
        execline = [l for l in units["x.container"].splitlines() if l.startswith("Exec=")][0]
        self.assertEqual(shlex.split(execline[5:]), ["serve", "--id-onion", "", "--listen", "0.0.0.0:8080"])

    def test_nextcloud_signs_people_in_with_the_networks_accounts(self):
        n = json.loads(json.dumps(SH3))
        n["node"]["cloud"] = dict(n["node"].get("cloud") or {}, accounts_client="cloud-sh3", accounts_secret="golden-oidc-secret",
                                  accounts_issuer="https://id.example.org/oauth2/openid/cloud-sh3")
        out = self.render("cloud-accounts", n)
        with open(os.path.join(out, "kiwi", "cloud-accounts.sh")) as f:
            sh = f.read()
        self.assertIn("occ_secret user_oidc:provider accounts --clientid=cloud-sh3", sh)
        self.assertIn("exec -e KIWI_SECRET", sh)                                     # the secret: not on a command line here
        self.assertNotIn('--clientsecret="$KIWI_SECRET" \\', sh)
        # nobody becomes a local user of Nextcloud by having the same name
        self.assertIn("occ config:system:set user_oidc soft_auto_provision --type=boolean --value=false", sh)
        self.assertIn("https://id.example.org/oauth2/openid/cloud-sh3/.well-known/openid-configuration", sh)
        self.assertNotIn("golden-oidc-secret", sh)                                 # in the unit's environment file only
        with open(os.path.join(out, "kiwi", "cloud-accounts.env")) as f:
            self.assertEqual(f.read().strip(), "KIWI_SECRET=golden-oidc-secret")
        self.assertTrue(os.path.isfile(os.path.join(out, "host-units", "kn-cloud-accounts.service")))
        with open(os.path.join(out, "host-units", "kn-cloud-accounts.service")) as f:
            self.assertNotIn("EnvironmentFile", f.read())                         # systemd may not read the home folder
        self.assertIn("/home/user/docker/kiwi/cloud-accounts.env", sh)
        r = subprocess.run(["bash", "-n", os.path.join(out, "kiwi", "cloud-accounts.sh")], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(os.path.join(self.render("cloud-plain", SH3), "docker-compose.yml")) as f:
            pass
        self.assertFalse(os.path.isfile(os.path.join(self.render("cloud-plain2", SH3), "kiwi", "cloud-accounts.sh")))

    def test_paperless_signs_people_in_with_the_networks_accounts(self):
        n = json.loads(json.dumps(SH3))
        n["node"]["modules"] = ["vpn-client", "reverse-proxy", "paperless"]
        n["node"].pop("preset", None); n["node"].pop("cloud", None)
        n["node"]["paperless"] = {"admin_password": "golden-paperless", "accounts_client": "paperless-sh3",
                                  "accounts_secret": "golden-oidc", "accounts_issuer": "https://id.example.org/oauth2/openid/paperless-sh3"}
        out = self.render("paperless-accounts", n)
        with open(os.path.join(out, "docker-compose.yml")) as f:
            env = yaml.safe_load(f)["services"]["kn-paperless"]["environment"]
        prov = json.loads(next(e for e in env if e.startswith("PAPERLESS_SOCIALACCOUNT_PROVIDERS=")).split("=", 1)[1])
        app = prov["openid_connect"]["APPS"][0]
        self.assertEqual((app["provider_id"], app["client_id"], app["settings"]["server_url"]),
                         ("accounts", "paperless-sh3", "https://id.example.org/oauth2/openid/paperless-sh3"))
        self.assertIn("PAPERLESS_APPS=allauth.socialaccount.providers.openid_connect", env)
        self.assertIn("REQUESTS_CA_BUNDLE=/usr/src/paperless/kiwi-ca-bundle.pem", env)
        self.assertTrue(os.path.isfile(os.path.join(out, "kn-paperless", "init", "10-kiwi-ca.sh")))
        # a new person lands in the group "accounts", which the host unit makes: not the workflows
        self.assertIn("PAPERLESS_SOCIAL_ACCOUNT_DEFAULT_GROUPS=accounts", env)
        with open(os.path.join(out, "kiwi", "paperless-accounts.sh")) as f:
            script = f.read()
        self.assertIn('get_or_create(name="accounts")', script)
        self.assertIn('exclude(content_type__model__startswith="workflow")', script)
        self.assertTrue(os.path.isfile(os.path.join(out, "host-units", "kn-paperless-accounts.service")))

    def test_immich_signs_people_in_with_the_networks_accounts(self):
        n = json.loads(json.dumps(SH3))
        n["node"]["modules"] = ["vpn-client", "reverse-proxy", "immich"]
        n["node"].pop("preset", None); n["node"].pop("cloud", None)
        n["node"]["immich"] = {"db_password": "golden-immich", "accounts_client": "immich-sh3", "accounts_secret": "golden-oidc",
                               "accounts_issuer": "https://id.example.org/oauth2/openid/immich-sh3"}
        out = self.render("immich-accounts", n)
        with open(os.path.join(out, "docker-compose.yml")) as f:
            immich = yaml.safe_load(f)["services"]["kn-immich"]
        self.assertIn("NODE_EXTRA_CA_CERTS=/kiwi-ca/kiwiCA.crt", immich["environment"])
        self.assertTrue(os.path.isfile(os.path.join(out, "host-units", "kn-immich-accounts.service")))
        with open(os.path.join(out, "kiwi", "immich-accounts.sh")) as f:
            script = f.read()
        self.assertIn("-v client=immich-sh3", script)
        self.assertIn("mobile=https://immich.sh3.home/api/oauth/mobile-redirect", script)
        self.assertNotIn("golden-oidc", script)                   # the secret is in the root-only env file
        with open(os.path.join(out, "kiwi", "immich-accounts.env")) as f:
            self.assertIn("KIWI_SECRET=golden-oidc", f.read())

    def test_vaultwarden_signs_people_in_with_the_networks_accounts(self):
        n = json.loads(json.dumps(SH3))
        n["node"]["modules"] = ["vpn-client", "reverse-proxy", "vault"]
        n["node"].pop("preset", None); n["node"].pop("cloud", None)
        out = self.render("vault-plain", n)
        with open(os.path.join(out, "docker-compose.yml")) as f:
            plain = yaml.safe_load(f)["services"]["kn-vault"]
        self.assertFalse(any(e.startswith("SSO_") for e in plain["environment"]))
        self.assertNotIn("entrypoint", plain)
        n["node"]["vault"] = {"accounts_client": "vault-sh3", "accounts_secret": "golden-oidc",
                              "accounts_issuer": "https://id.example.org/oauth2/openid/vault-sh3"}
        out = self.render("vault-accounts", n)
        with open(os.path.join(out, "docker-compose.yml")) as f:
            vault = yaml.safe_load(f)["services"]["kn-vault"]
        env = vault["environment"]
        for e in ("SSO_ENABLED=true", "SSO_ONLY=false", "SSO_CLIENT_ID=vault-sh3", "SSO_PKCE=false", "SSO_SIGNUPS_MATCH_EMAIL=false",
                  "SSO_AUTHORITY=https://id.example.org/oauth2/openid/vault-sh3"):
            self.assertIn(e, env)
        self.assertEqual(vault["entrypoint"], ["/kiwi-start.sh"])
        start = os.path.join(out, "kn-vault-kiwi", "kiwi-start.sh")
        self.assertTrue(os.path.isfile(start))
        with open(start) as f:
            self.assertIn("exec /start.sh", f.read())
        self.assertTrue(any(v.endswith(":/kiwi-start.sh:ro,z") for v in vault["volumes"]))

    def test_jabber_has_a_sign_up_page_with_the_ways_chosen(self):
        n = json.loads(json.dumps(SH3))
        n["node"]["modules"] = ["vpn-client", "reverse-proxy", "xmpp"]
        n["node"].pop("preset", None); n["node"].pop("cloud", None)
        n["node"]["xmpp"] = {"xmpp_domain": "chat.example.org", "separate": True, "admin_password": "golden-xmpp",
                             "invites": True, "requests": True, "registration": True}
        n["node"]["vpn-client"] = {"vpn_provider": "mullvad", "wireguard_private_key": "golden-mullvad-key",
                                   "wireguard_addresses": "10.66.1.2/32"}
        n["vpn_ip"] = "10.8.0.25"
        n["node"].setdefault("reverse-proxy", {}).update(public=True, via="10.8.0.1",
                                                         access={"admin": ["10.9.5.0/24"]})    # a group without the admin pages
        out = self.render("xmpp-join", n)
        with open(os.path.join(out, "docker-compose.yml")) as f:
            join = yaml.safe_load(f)["services"]["kn-xmpp-join"]
        pages = json.loads(join["command"][join["command"].index("--ejabberd") + 1])
        self.assertEqual(pages["jabber.sh3.home"]["api"], "http://kn-vpn-client:5281/api")      # the internal instance
        self.assertEqual(pages["chat.example.org"]["api"], "http://kn-xmpp-public:5281/api")    # the public one
        self.assertEqual(pages["chat.example.org"]["host"], "chat.example.org")
        # each page is called after its own service: the internal one never after the public name
        self.assertEqual((pages["jabber.sh3.home"]["brand"], pages["chat.example.org"]["brand"]), ("jabber.sh3.home", "chat.example.org"))
        self.assertEqual(join["command"][join["command"].index("--ways") + 1], "invites,requests,captcha")
        for conf in ("ejabberd.yml", "ejabberd-public.yml"):
            with open(os.path.join(out, "kn-xmpp", conf)) as f:
                e = yaml.safe_load(f)
            api = [x for x in e["listen"] if x["port"] == 5281][0]
            self.assertEqual(api["request_handlers"], {"/api": "mod_http_api"})
            self.assertEqual(e["api_permissions"]["kiwi sign-up page"]["what"], ["register", "check_account"])
        with open(os.path.join(out, "kn-nginx", "nginx.conf")) as f:
            nginx = f.read()
        self.assertEqual(nginx.count("set $join http://kn-xmpp-join:8080;"), 2)    # the VPN's name and the public one
        self.assertIn("return 302 /join;", nginx)
        self.assertTrue(os.path.isfile(os.path.join(out, "kn-xmpp", "join", "terms.txt")))
        # ejabberd's own sign-up page leads to the one page; its admin panel answers the VPN only
        for site in nginx.split("server_name ")[1:]:
            if site.startswith(("jabber.sh3.home;", "chat.example.org;")):
                self.assertIn("location ^~ /register {\n            return 302 /join;", site)
                # ejabberd's admin panel: the group without the admin pages first refused, then the VPN only
                self.assertRegex(site, r"location \^~ /admin \{\n\s+#[^\n]*\n\s+deny 10\.9\.5\.0/24;\n\s+allow 10\.[0-9./]+; deny all;"
                                       r"\n\s+set \$backend \S+;\n\s+proxy_pass")
                self.assertNotIn("deny 10.9.5.0/24", site.split("location ^~ /admin", 1)[0])    # the rest of the site is theirs
        # only the open way: the same one page, with the picture test only
        n["node"]["xmpp"].update(invites=False, requests=False)
        out = self.render("xmpp-open", n)
        with open(os.path.join(out, "docker-compose.yml")) as f:
            join = yaml.safe_load(f)["services"]["kn-xmpp-join"]
        self.assertEqual(join["command"][join["command"].index("--ways") + 1], "captcha")
        with open(os.path.join(out, "kn-nginx", "nginx.conf")) as f:
            self.assertNotIn("/register/", f.read())

    def test_fail2ban_on_a_master_never_bans_the_networks_own_addresses(self):
        m = TestRender.public_hub(self)
        m["master"] = dict(m["master"], modules=list(m["master"].get("modules") or
                           ["vpn-client", "vpn-server", "dns", "tor", "reverse-proxy", "nostr-relay", "hub"]) + ["fail2ban"])
        out = self.render("hub-f2b-own", m)
        units = os.path.join(out, "host-units")
        self.assertTrue(os.path.isfile(os.path.join(units, "kn-fail2ban-own.timer")))
        with open(os.path.join(units, "kn-fail2ban-own.service")) as f:
            self.assertIn("/bin/sh /home/user/docker/kiwi/fail2ban-own.sh", f.read())
        with open(os.path.join(out, "kiwi", "fail2ban-own.sh")) as f:
            sh = f.read()
        self.assertIn("km-vpn-server wg show wg0 dump", sh)
        self.assertIn("addignoreip", sh)
        self.assertIn("{{.State.StartedAt}}", sh)
        r = subprocess.run(["sh", "-n", os.path.join(out, "kiwi", "fail2ban-own.sh")], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_a_public_node_bans_wrong_logins_in_nginx(self):
        n = json.loads(json.dumps(SH3))
        n["node"]["modules"] = ["vpn-client", "reverse-proxy", "git", "vault", "fail2ban"]
        n["node"].pop("preset", None); n["node"].pop("cloud", None)
        n["node"]["git"] = {"git_hostname": "git.example.org", "admin_password": "golden-git-pass"}
        n["node"]["vpn-client"] = {"vpn_provider": "mullvad", "wireguard_private_key": "golden-mullvad-key",
                                   "wireguard_addresses": "10.66.1.2/32"}
        n["vpn_ip"] = "10.8.0.25"
        n["node"].setdefault("reverse-proxy", {}).update(public=True, via="10.8.0.1")
        out = self.render("f2b-node", n)
        f2b = os.path.join(out, "kn-fail2ban", "config", "fail2ban")
        with open(os.path.join(f2b, "jail.d", "kiwi.local")) as f:
            jail = f.read()
        # behind the master a ban is nginx's, never a firewall rule that would only ever see the master
        self.assertNotIn("chain    = FORWARD", jail)
        self.assertIn("[kiwi-git]", jail)
        self.assertIn("[kiwi-vault]", jail)
        self.assertNotIn("[kiwi-cloud]", jail)                                   # not on this machine
        git = jail[jail.index("[kiwi-git]"):]
        self.assertIn("action   = kiwi-nginx-deny", git[:400])
        self.assertIn("logpath  = /kiwi-apps/git.log", git[:400])
        self.assertIn("from <HOST>", git[:400])
        limit = jail[jail.index("[nginx-limit-req]"):jail.index("[kiwi-nginx-refused]")]
        self.assertIn("findtime = 5m\nmaxretry = 600", limit)                   # floods, not page loads
        # the master's door: an address that keeps on opening more connections than it lets through
        door = jail[jail.index("[kiwi-nginx-door]"):]
        self.assertIn('limiting connections by zone "kiwi_door", client: <HOST>,', door[:700])
        self.assertIn("maxretry = 300", door[:700])
        # gentle, as others ship it (fail2ban, Debian, YunoHost, mailcow): no ban for a 400, sshd's
        # failed logins only, never a home address, short bans that grow, Forgejo's own count
        self.assertNotIn("[nginx-bad-request]", jail)
        self.assertIn("mode     = normal", jail)
        self.assertIn("192.168.0.0/16 fc00::/7", jail)
        self.assertIn("bantime  = 10m\nbantime.increment = true\nbantime.maxtime = 1w", jail)
        self.assertIn("maxretry = 10", git[:500])
        self.assertIn("maxretry = 5", jail[jail.index("[recidive]"):])
        with open(os.path.join(f2b, "filter.d", "kiwi-nginx-refused.conf")) as f:
            refused = f.read()
        self.assertIn("ignoreregex = ^<HOST> -[^\"]*\"[A-Z]+ /(?:remote\\.php|ocs", refused)
        with open(os.path.join(out, "kn-nginx", "nginx.conf")) as f:
            self.assertIn('~^/remote\\.php/(?:dav|webdav)/ "";', f.read())          # sync clients are not limited
        self.assertTrue(os.path.isfile(os.path.join(f2b, "action.d", "kiwi-nginx-deny.conf")))
        self.assertTrue(os.path.isfile(os.path.join(f2b, "filter.d", "kiwi-app.conf")))
        units = os.path.join(out, "host-units")
        for u in ("kn-f2b-tap.service", "kn-nginx-banned.path", "kn-nginx-banned.service"):
            self.assertTrue(os.path.isfile(os.path.join(units, u)), u)
        # the network's own addresses: asked of the master, which sees the tunnels
        self.assertTrue(os.path.isfile(os.path.join(units, "kn-fail2ban-own.timer")))
        with open(os.path.join(out, "kiwi", "fail2ban-own.sh")) as f:
            own = f.read()
        self.assertIn("kn-vpn-client wget -q -T 10 -O - http://10.8.0.1/.well-known/kiwi-own", own)
        self.assertNotIn("wg show", own)
        with open(os.path.join(f2b, "..", "..", "init", "51-kiwi-files")) as f:
            init = f.read()
        self.assertIn("touch /config/log/fail2ban/fail2ban.log", init)       # recidive's file, or fail2ban stops
        self.assertIn("rm -f /kiwi-banned/*.map", init)                      # nobody stays locked out by a jail gone
        with open(os.path.join(f2b, "action.d", "kiwi-nginx-deny.conf")) as f:
            self.assertIn("/kiwi-banned/<name>.map", f.read())                # one list per jail: one unban lifts one ban
        with open(os.path.join(units, "kn-nginx-banned.service")) as f:
            self.assertIn("StartLimitIntervalSec=0", f.read())
        self.assertIn("touch /kiwi-apps/git.log", init)
        with open(os.path.join(out, "kiwi", "f2b-tap.sh")) as f:
            tap = f.read()
        self.assertIn("tap git kn-git '' 'Failed authentication attempt|", tap)
        r = subprocess.run(["sh", "-n", os.path.join(out, "kiwi", "f2b-tap.sh")], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(os.path.join(out, "kn-nginx", "nginx.conf")) as f:
            nginx = f.read()
        self.assertIn("include /etc/nginx/banned/*.map;", nginx)
        block = nginx[nginx.index("server_name git.example.org;") - 400:nginx.index("server_name git.example.org;")]
        self.assertIn("if ($kiwi_banned) {", block)
        self.assertIn("map $uri $kiwi_limit_key", nginx)
        with open(os.path.join(out, "docker-compose.yml")) as f:
            svcs = yaml.safe_load(f)["services"]
        self.assertIn("/home/user/docker/kn-nginx/banned:/etc/nginx/banned:ro,z", svcs["kn-nginx"]["volumes"])
        self.assertIn("/home/user/docker/kn-nginx/banned:/kiwi-banned:z", svcs["kn-fail2ban"]["volumes"])
        self.assertIn("/home/user/docker/kn-fail2ban/apps:/kiwi-apps:z", svcs["kn-fail2ban"]["volumes"])
        env = "\n".join(svcs["kn-git"]["environment"])
        self.assertIn("FORGEJO__security__REVERSE_PROXY_TRUSTED_PROXIES=", env)
        # not asked for: a node whose sites strangers reach gets it anyway
        n["node"]["modules"] = ["vpn-client", "reverse-proxy", "git"]
        n["node"].pop("vault", None)
        out = self.render("f2b-node-implied", n)
        with open(os.path.join(out, "docker-compose.yml")) as f:
            self.assertIn("kn-fail2ban", yaml.safe_load(f)["services"])

    def test_control_is_for_the_mesh_and_a_node_takes_ssh_from_it(self):
        m = json.loads(json.dumps(SH3))
        m["node"]["modules"] = ["vpn-client", "reverse-proxy", "control"]
        m["node"].pop("preset", None)
        for k in ("cloud", "vault"):
            m["node"].pop(k, None)
        m["node"]["control"] = {"allow_from": "192.168.0.0/16"}
        m["admin"] = dict(m.get("admin") or {}, ssh_port=41022)
        out = self.render("sh3-control", m)
        with open(os.path.join(out, "kn-nginx", "nginx.conf")) as f:
            conf = f.read()
        site = conf[conf.index("server_name control.sh3.home"):]
        self.assertIn("allow 10.8.0.0/16;", site)
        self.assertIn("allow 192.168.0.0/16;", site)
        self.assertIn("deny all;", site)
        # the agents' reports are signed and need no address rule: the control node's own machine reports
        # from the stack's network, which the rule above does not know
        report = site[site.index("location = /api/report"):]
        report = report[:report.index("}")]
        self.assertIn("allow all;", report)
        self.assertIn("proxy_pass", report)
        with open(os.path.join(out, "docker-compose.yml")) as f:
            svcs = yaml.safe_load(f)["services"]
        self.assertIn("/home/user/docker/kn-control:/fleet:Z", svcs["kn-control"]["volumes"])
        self.assertIn("KIWI_CONTROL_HOST=sh3", svcs["kn-control"]["environment"])
        self.assertEqual(svcs["kn-control"]["tmpfs"], ["/run/kiwi:size=2048m,mode=0700"])    # the open store lives in RAM
        self.assertIn("--wait", svcs["kn-control"]["command"])
        with open(os.path.join(out, "kn-vpn-client", "post-rules.txt")) as f:
            rules = f.read()
        self.assertIn("--dport 22 -j DNAT --to-destination 172.128.0.1:41022", rules)   # follows admin.ssh_port
        m["node"]["vpn-client"] = dict(m["node"].get("vpn-client") or {}, mesh_ssh=False)
        with open(os.path.join(self.render("sh3-nossh", m), "kn-vpn-client", "post-rules.txt")) as f:
            self.assertNotIn("--dport 22 ", f.read())

    def test_the_status_page_is_one_path_without_a_login(self):
        m = json.loads(json.dumps(SH3))
        m["node"]["modules"] = ["vpn-client", "reverse-proxy", "control"]
        m["node"].pop("preset", None)
        for k in ("cloud", "vault"):
            m["node"].pop(k, None)
        out = self.render("sh3-status", m)
        with open(os.path.join(out, "kn-nginx", "nginx.conf")) as f:
            conf = f.read()
        site = conf.split("server_name status.sh3.home;", 1)[1].split("\n    server {", 1)[0]
        self.assertIn("set $backend http://kn-control:8740/start;", site)        # whatever is asked for: the start page
        self.assertIn("location = /status {", site)                                # and the status page, nothing else
        self.assertIn("set $page http://kn-control:8740/status;", site)
        for path in ("/api/registry", "/.well-known/kiwi"):                       # the same as data, for the apps
            part = site.split("location = %s {" % path, 1)[1].split("}", 1)[0]
            self.assertIn("set $page http://kn-control:8740/api/registry$is_args$args;", part)
        self.assertIn("set $page http://kn-control:8740/api/ca;", site.split("location = /api/ca {", 1)[1].split("}", 1)[0])
        m["node"]["control"] = {"about": "Ours: chat, files. # and more", "brand_name": "dlhost", "contact": "a@b.org"}
        with open(os.path.join(self.render("sh3-brand", m), "docker-compose.yml")) as f:
            env = yaml.safe_load(f)["services"]["kn-control"]["environment"]
        self.assertIn("KIWI_ABOUT=Ours: chat, files. # and more", env)        # a sentence with ": " stays a string
        self.assertIn("KIWI_BRAND=dlhost", env)
        m["node"]["control"] = {}
        self.assertNotIn("deny all;", site)                                       # no admin page: the access rules decide
        from kiwimodules import modules
        nx = modules.discover().get("control").nginx
        self.assertEqual([bool(e.get("admin")) for e in nx["servers"]], [False] * 6)  # status, the Internet's, games, the website twice, its files
        # the website: its name and www. to the control part, which knows them from its environment
        m["node"]["control"] = {"website_hostname": "example.org", "website_repo": "https://example.org/site.git",
                                "website_commit": "a" * 40, "website_cdn_hostname": "cdn.example.org"}
        out = self.render("sh3-site", m)
        with open(os.path.join(out, "kn-nginx", "nginx.conf")) as f:
            conf = f.read()
        for name in ("example.org", "www.example.org", "cdn.example.org"):
            self.assertIn("server_name %s;" % name, conf)
        with open(os.path.join(out, "docker-compose.yml")) as f:
            env = yaml.safe_load(f)["services"]["kn-control"]["environment"]
        self.assertIn("KIWI_SITE_HOST=example.org", env)
        self.assertIn("KIWI_SITE_COMMIT=" + "a" * 40, env)
        self.assertIn("KIWI_SITE_CDN=cdn.example.org", env)
        # the public pages in their own container: no fleet, read-only, the public data only
        with open(os.path.join(out, "docker-compose.yml")) as f:
            services = yaml.safe_load(f)["services"]
        pub = services["kn-control-public"]
        self.assertEqual(pub["command"][:2], ["serve-public", "/public"])
        self.assertTrue(pub["read_only"])
        self.assertTrue(all(":ro" in v and "/fleet" not in v for v in pub["volumes"]))
        self.assertIn("KIWI_PUBLIC_DIR=/public", services["kn-control"]["environment"])
        site = conf.split("server_name example.org;", 1)[1].split("\n    server {", 1)[0]
        self.assertIn("kn-control-public:8741", site)
        self.assertNotIn("kn-control:8740", site)
        err = io.StringIO()
        m["node"]["control"] = {"website_hostname": "example.org"}
        with contextlib.redirect_stderr(err):                                     # no repository, no pin: refused
            self.assertEqual(cli.main(["render", self.write("sh3-site-bad", m), "-o", self.tmp + "/sb"]), 1)
        self.assertIn("website_repo", err.getvalue())
        m["node"]["control"] = {"status_page": False}
        with open(os.path.join(self.render("sh3-nostatus", m), "kn-nginx", "nginx.conf")) as f:
            conf = f.read()
        self.assertNotIn("status.sh3.home", conf)
        self.assertNotIn("play.sh3.home", conf)                                    # the game page: only when asked for
        # the game page: everything at its name is the control part's /play/, nothing else
        m["node"]["control"] = {"play_page": True}
        with open(os.path.join(self.render("sh3-play", m), "kn-nginx", "nginx.conf")) as f:
            site = f.read().split("server_name play.sh3.home;", 1)[1].split("\n    server {", 1)[0]
        self.assertIn("set $backend http://kn-control:8740/play$request_uri;", site)    # its path and question kept
        m["node"]["control"] = {"play_page": True, "play_extra": ["papaya/kn-jellyfin"]}
        with open(os.path.join(self.render("sh3-play2", m), "docker-compose.yml")) as f:
            env = yaml.safe_load(f)["services"]["kn-control"]["environment"]
        self.assertIn("KIWI_PLAY_HOST=play.sh3.home", env)
        self.assertIn("KIWI_PLAY_GROUP=games", env)
        self.assertIn("KIWI_PLAY_EXTRA=papaya/kn-jellyfin", env)
        self.assertNotIn("deny all;", site)
        err = io.StringIO()
        m["node"]["control"] = {"play_page": True, "play_group": "Not A Group"}
        with contextlib.redirect_stderr(err):
            self.assertEqual(cli.main(["render", self.write("sh3-play-bad", m), "-o", self.tmp + "/pb"]), 1)

    def test_a_nodes_service_is_open_to_the_internet_through_the_master(self):
        """The service and its certificate on the node; the master hands on names (still
        encrypted) and ports, each connection with the address it came from in front."""
        # the master: what kiwi-server gives it from the nodes
        m = json.loads(json.dumps(MACHINES["hub1"]))
        m["master"].setdefault("reverse-proxy", {})["exposed"] = {
            "names": {"chat.example.org": "10.8.0.25"},
            "ports": [{"port": 5222, "to": "10.8.0.25:15222", "proxy_protocol": True},
                      {"port": 10666, "to": "10.8.0.25:10666", "proxy_protocol": False, "proto": "udp"}]}
        out = self.render("exp-master", m)
        with open(os.path.join(out, "km-nginx", "nginx.conf")) as f:
            nginx = f.read()
        self.assertIn("stream {", nginx)
        self.assertIn("chat.example.org 10.8.0.25:8443;", nginx)
        self.assertIn("default 127.0.0.1:8443;", nginx)
        self.assertIn("ssl_preread on;", nginx)
        self.assertEqual(nginx.count("limit_conn kiwi_door 80;"), 3)       # one address, so many connections at once: the door and the port
        self.assertIn("listen 5222;\n        proxy_pass 10.8.0.25:15222;\n        proxy_protocol on;", nginx)
        self.assertIn("listen 10666 udp;\n        proxy_pass 10.8.0.25:10666;", nginx)     # a game's port, as it is
        self.assertNotIn("listen 443 ssl", nginx)                      # its own sites moved behind the stream block
        self.assertIn("listen 127.0.0.1:8443 ssl proxy_protocol;", nginx)
        self.assertIn("real_ip_header proxy_protocol;", nginx)        # and still see who asks
        self.assertIn("port_in_redirect off;", nginx)                 # a redirect names no inner port
        self.assertIn("proxy_pass http://10.8.0.25:80;", nginx)       # Let's Encrypt's question goes to the node
        # with only a node's names handed on, the master's own sites (wg-easy, Pi-hole) stay the mesh's
        own = nginx[nginx.index("server_name wg.hub1.home;"):]
        own = own[:own.index("}")]
        self.assertIn("allow 10.8.0.0/16;", own)
        self.assertIn("deny all;", own)
        with open(os.path.join(out, "docker-compose.yml")) as f:
            ports = yaml.safe_load(f)["services"]["km-vpn-server"]["ports"]
        for want in ("80:80/tcp", "443:443/tcp", "5222:5222/tcp", "10666:10666/udp"):
            self.assertTrue(any(p.endswith(want) for p in ports), (want, ports))
        with open(os.path.join(out, "km-vpn-server", "start.sh")) as f:
            start = f.read()
        self.assertIn("--sport 5222 ! -d", start)                      # the answers leave by the real interface
        self.assertIn("-p udp --sport 10666 ! -d", start)
        self.assertIn("--sport 443 ! -d", start)
        # the node may ask port 80 for the network's own addresses, which fail2ban here writes down
        self.assertIn("-A INPUT -i wg0 -s 10.8.0.25 -p tcp --dport 80 -j ACCEPT", start)
        self.assertNotIn("--sport 80 -j MARK", start)                     # port 80's answers to the mesh stay in the tunnel
        self.assertIn("location = /.well-known/kiwi-own {", nginx)
        # a master that hands nothing on is as it was
        with open(os.path.join(self.render("exp-plain", MACHINES["hub1"]), "km-nginx", "nginx.conf")) as f:
            plain = f.read()
        self.assertNotIn("stream {", plain)
        self.assertNotIn("8443", plain)

        # the new rules ask for no mesh address where they do not apply (a node not enrolled yet)
        from kiwimodules import modules as mods
        self.assertNotIn("${VPN_IP}", " ".join(mods.discover().get("reverse-proxy").firewall_rules))
        # the node: Jabber with a public name, in the VPN client's network
        n = json.loads(json.dumps(SH3))
        n["node"]["modules"] = ["vpn-client", "reverse-proxy", "xmpp"]
        n["node"].pop("preset", None); n["node"].pop("cloud", None)
        n["node"]["xmpp"] = {"xmpp_domain": "chat.example.org", "admin_password": "golden-xmpp"}
        n["node"]["vpn-client"] = {"vpn_provider": "mullvad", "wireguard_private_key": "golden-mullvad-key",
                                   "wireguard_addresses": "10.66.1.2/32"}
        n["vpn_ip"] = "10.8.0.25"
        rp = n["node"].setdefault("reverse-proxy", {})
        rp.update(public=True)
        # nobody hands on to it: said, not rendered
        self.assertNotEqual(cli.main(["render", self.write("exp-alone", n), "-o", os.path.join(self.tmp, "exp-alone.bundle")]), 0)
        rp["via"] = "10.8.0.1"
        out = self.render("exp-node", n)
        with open(os.path.join(out, "kn-nginx", "nginx.conf")) as f:
            nginx = f.read()
        block = nginx[nginx.index("server_name chat.example.org;") - 400:nginx.index("server_name chat.example.org;") + 400]
        self.assertIn("listen 8443 ssl proxy_protocol;", block)
        self.assertIn("listen 443 ssl;", block)                        # and from the VPN, directly
        self.assertIn("port_in_redirect off;", nginx)
        self.assertIn("set_real_ip_from 10.8.0.1;", block)
        self.assertIn("/etc/nginx/acme/chat.example.org/fullchain.pem", block)
        internal = nginx[nginx.index("server_name jabber.sh3.home;") - 200:nginx.index("server_name jabber.sh3.home;") + 300]
        self.assertIn("listen 443 ssl;", internal)                     # the VPN's site stays as it is
        self.assertNotIn("deny all;", internal)
        self.assertNotIn("stream {", nginx)
        with open(os.path.join(out, "kn-vpn-client", "post-rules.txt")) as f:
            rules = f.read()
        self.assertIn("-s 10.8.0.1 -d 10.8.0.25 -p tcp --dport 8443 -j DNAT", rules.replace("${VPN_IP}", "10.8.0.25"))
        self.assertIn("-A INPUT -i tun0 -p tcp -m multiport --dports 5222,5223 -j ACCEPT", rules)
        self.assertIn("-A INPUT -i tun0 -s 10.8.0.1 -p tcp -m multiport --dports 15222,15223,15269 -j ACCEPT", rules)
        with open(os.path.join(out, "docker-compose.yml")) as f:
            svcs = yaml.safe_load(f)["services"]
        self.assertEqual(svcs["kn-xmpp"]["network_mode"], "service:kn-vpn-client")
        self.assertNotIn("ports", svcs["kn-xmpp"])                     # nothing opened at home
        with open(os.path.join(out, "kn-xmpp", "ejabberd.yml")) as f:
            conf = yaml.safe_load(f)
        handed = {x["port"]: x for x in conf["listen"] if x.get("use_proxy_protocol")}
        self.assertEqual(sorted(handed), [15222, 15223, 15269])
        self.assertEqual(conf["hosts"], ["chat.example.org"])
        self.assertTrue(os.path.isfile(os.path.join(out, "kiwi", "acme.sh")))     # the node fetches the certificate
        # and what kiwi-server asks the library, to tell the master
        from kiwimodules import modules as modmod, profiles
        mm = machine.load(self.write("exp-node2", n))
        profile = profiles.discover()[mm.role]
        ms = modmod.discover()
        resolver.resolve_settings(profile, mm, ms)
        spec = resolver.stack_spec(mm, profile, mm.dns_records, master_ip=mm.master_ip, ca_cert=mm.ca_cert,
                                   lan_addresses=mm.lan_addresses)
        names, ports = modmod.Renderer(ms).exposure(spec)
        self.assertEqual(names, ["chat.example.org"])
        # Jabber's ports on a node are at its mesh address only: its names say so
        self.assertEqual(sorted(modmod.Renderer(ms).mesh_only_names(spec)), ["chat.example.org", "jabber.sh3.home"])
        self.assertEqual(ports, [{"port": 5222, "to": 15222, "proxy_protocol": True, "proto": "tcp"},
                                 {"port": 5223, "to": 15223, "proxy_protocol": True, "proto": "tcp"},
                                 {"port": 5269, "to": 15269, "proxy_protocol": True, "proto": "tcp"}])

    def xmpp_master(self, **xmpp):
        m = json.loads(json.dumps(MACHINES["hub1"]))
        m["master"]["modules"] = list(m["master"]["modules"]) + ["xmpp"]
        if xmpp:
            m["master"]["xmpp"] = xmpp
        return m

    def test_jabber_is_one_service_with_three_doors_or_two_apart(self):
        def rendered(name, **xmpp):
            m = self.xmpp_master(**xmpp)
            if xmpp.get("xmpp_domain"):
                m["master"].setdefault("reverse-proxy", {}).update(public=True, acme_email="me@example.org")
            out = self.render(name, m)
            with open(os.path.join(out, "docker-compose.yml")) as f:
                svcs = yaml.safe_load(f)["services"]
            conf = {}
            for fn in ("ejabberd.yml", "ejabberd-public.yml"):
                path = os.path.join(out, "km-xmpp", fn)
                if os.path.isfile(path):
                    with open(path) as f:
                        conf[fn] = yaml.safe_load(f)
            with open(os.path.join(out, "km-nginx", "nginx.conf")) as f:
                nginx = f.read()
            return out, svcs, conf, nginx
        # for the VPN only: one service in the WireGuard server's network, no other server reached
        out, svcs, conf, nginx = rendered("x1", upload_mb=50)
        x, c = svcs["km-xmpp"], conf["ejabberd.yml"]
        self.assertEqual(x["network_mode"], "service:km-vpn-server")
        self.assertNotIn("km-xmpp-public", svcs)
        self.assertNotIn("5222", str(svcs["km-vpn-server"]["ports"]))
        self.assertIn("/home/user/docker/km-nginx:/kiwi-certs:ro,z", x["volumes"])           # the fleet CA's certificate
        self.assertEqual((x["user"], x["entrypoint"], x["command"]), ("0:0", ["/bin/sh"], ["/kiwi-start.sh"]))
        self.assertIn("ERLANG_NODE_ARG=ejabberd@localhost", x["environment"])
        self.assertEqual((c["hosts"], c["s2s_access"]), (["jabber.hub1.home"], "none"))
        self.assertEqual([l["port"] for l in c["listen"]], [5222, 5223, 5280, 5281])        # 5281: the sign-up page's API
        web = [l for l in c["listen"] if l["port"] == 5280][0]
        self.assertEqual(web["ip"], "127.0.0.1")                                             # the proxy shares the network
        self.assertNotIn("/register", web["request_handlers"])                               # the one page is /join
        self.assertNotIn("mod_register_web", c["modules"])
        self.assertEqual((c["captcha_cmd"], c["captcha_url"]), ("/usr/local/bin/captcha.sh", "https://jabber.hub1.home/captcha"))
        self.assertTrue(c["modules"]["mod_register"]["captcha_protected"])
        # by default only with an invite code or an accepted request: no open sign-up, in the apps either
        self.assertEqual(c["access_rules"]["register"], {"deny": "all"})
        self.assertEqual(c["modules"]["mod_http_upload"]["max_size"], 50 * 1024 * 1024)
        self.assertEqual(c["modules"]["mod_http_upload_quota"], {"max_days": 30})        # files go after 30 days
        self.assertEqual(c["access_rules"]["muc_create"], {"allow": "local"})
        self.assertEqual(c["acl"]["admin"]["user"], ["admin@jabber.hub1.home"])
        self.assertIn("mod_fail2ban", c["modules"])
        self.assertNotIn("mod_s2s_dialback", c["modules"])
        site = nginx.split("server_name jabber.hub1.home;", 1)[1].split("\n    server {", 1)[0]
        self.assertIn("client_max_body_size 50m;", site)
        self.assertIn("http://127.0.0.1:5280", site)
        script = os.path.join(out, "km-xmpp", "start.sh")
        self.assertEqual(subprocess.run(["sh", "-n", script]).returncode, 0)
        with open(script) as f:
            text = f.read()
        self.assertIn("unset KIWI_ADMIN_PASSWORD", text)
        self.assertIn("exec su ejabberd", text)
        # open sign-up when chosen; rooms by the admins only; more admins; files kept
        c = rendered("x1b", registration=True, room_creators="admins", admins=["anna", "ben"], file_days=0)[2]["ejabberd.yml"]
        self.assertEqual(c["access_rules"]["register"], {"allow": "all"})
        self.assertEqual(c["access_rules"]["muc_create"], {"allow": "admin"})
        self.assertEqual(c["acl"]["admin"]["user"], ["admin@jabber.hub1.home", "anna@jabber.hub1.home", "ben@jabber.hub1.home"])
        self.assertNotIn("mod_http_upload_quota", c["modules"])
        # a public name, one service: the name after the @ is the public one, the WireGuard server
        # publishes the ports, the VPN's name stays a door, Tor is a third (its own name too)
        out, svcs, conf, nginx = rendered("x2", xmpp_domain="chat.example.org", onion={"jabber": "abcdef.onion"})
        c = conf["ejabberd.yml"]
        self.assertEqual(c["hosts"], ["chat.example.org", "abcdef.onion"])
        self.assertNotIn("s2s_access", c)
        self.assertIn(5269, [l["port"] for l in c["listen"]])
        self.assertIn("mod_s2s_dialback", c["modules"])
        for port in ("5222:5222/tcp", "5223:5223/tcp", "5269:5269/tcp"):
            self.assertIn(port, svcs["km-vpn-server"]["ports"])
        self.assertIn("/home/user/docker/km-nginx/acme/chat.example.org:/kiwi-certs:ro,z", svcs["km-xmpp"]["volumes"])
        self.assertIn("KIWI_ONION=abcdef.onion", svcs["km-xmpp"]["environment"])
        self.assertIn("server_name jabber.hub1.home;", nginx)
        self.assertIn("server_name chat.example.org;", nginx)
        # two apart: the VPN's stays as it was, the public one has a container and ports of its own
        out, svcs, conf, nginx = rendered("x3", xmpp_domain="chat.example.org", separate=True, onion={"xmpp": "abcdef.onion"})
        inner, outer = conf["ejabberd.yml"], conf["ejabberd-public.yml"]
        self.assertEqual((inner["hosts"], inner["s2s_access"]), (["jabber.hub1.home"], "none"))
        self.assertEqual(outer["hosts"], ["chat.example.org", "abcdef.onion"])
        self.assertIn(5269, [l["port"] for l in outer["listen"]])
        self.assertEqual(outer["listen"][-1]["ip"], "::")
        pub = svcs["km-xmpp-public"]
        self.assertEqual(pub["ports"], ["5222:5222", "5223:5223", "5269:5269"])
        self.assertNotIn("network_mode", pub)
        self.assertIn("/home/user/docker/km-xmpp:/kiwi-xmpp:z", pub["volumes"])           # each name's folder under hosts/
        env = dict(e.split("=", 1) for e in pub["environment"])
        self.assertEqual((env["KIWI_HOST"], env["KIWI_OLD"], env["KIWI_OTHER"]), ("chat.example.org", "public", "data"))
        with open(os.path.join(out, "km-xmpp", "start.sh")) as f:
            start = f.read()
        self.assertIn('d=$X/hosts/$host', start)
        self.assertIn('for o in "$KIWI_OLD" "$KIWI_OTHER"', start)          # the old folder that holds the name's accounts
        self.assertEqual(subprocess.run(["sh", "-n", os.path.join(out, "km-xmpp", "start.sh")]).returncode, 0)
        self.assertNotIn("5222", str(svcs["km-vpn-server"]["ports"]))
        self.assertIn("http://km-xmpp-public:5280", nginx.split("server_name chat.example.org;", 1)[1].split("\n    server {", 1)[0])
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = cli.main(["render", self.write("x4", self.xmpp_master(separate=True)), "-o", self.tmp + "/x4"])
        self.assertEqual(rc, 1)
        self.assertIn("two instances need a public name", err.getvalue())

    def test_btcpay_runs_behind_the_vpn_client_and_makes_its_admin_first(self):
        m = json.loads(json.dumps(SH3))
        m["node"]["modules"] = ["vpn-client", "reverse-proxy", "btcpay"]
        m["node"].pop("preset", None)
        for k in ("cloud", "vault", "portainer"):
            m["node"].pop(k, None)
        out = self.render("sh3-pay", m)
        with open(os.path.join(out, "docker-compose.yml")) as f:
            svcs = yaml.safe_load(f)["services"]
        four = ["kn-btcpay-db", "kn-btcpay-bitcoind", "kn-btcpay-nbxplorer", "kn-btcpay"]
        for name in four:                                   # the node's traffic leaves through the VPN, not the home's line
            self.assertEqual(svcs[name]["network_mode"], "service:kn-vpn-client", name)
            self.assertNotIn("ports", svcs[name])
        btc = svcs["kn-btcpay-bitcoind"]
        self.assertIn("-rpcbind=127.0.0.1:43782", btc["command"])
        self.assertIn("-bind=127.0.0.1", btc["command"])
        self.assertIn("-prune=5000", btc["command"])
        self.assertIn("BITCOIN_NETWORK=mainnet", btc["environment"])
        self.assertIn("CREATE_WALLET=false", btc["environment"])
        self.assertIn("listen_addresses=127.0.0.1", svcs["kn-btcpay-db"]["command"])
        self.assertTrue(all("\n" not in str(e) for name in four for e in svcs[name].get("environment") or []))   # a unit file holds no line breaks
        pay = svcs["kn-btcpay"]
        self.assertEqual((pay["entrypoint"], pay["command"]), (["/bin/bash"], ["/kiwi-start.sh"]))
        self.assertIn("KIWI_ADMIN=admin@sh3.home", pay["environment"])
        self.assertIn("BTCPAY_BTCEXPLORERURL=http://127.0.0.1:32838/", pay["environment"])
        script = os.path.join(out, "kn-btcpay", "start.sh")
        self.assertEqual(subprocess.run(["bash", "-n", script]).returncode, 0)
        with open(script) as f:
            text = f.read()
        self.assertIn("unset KIWI_ADMIN_PASSWORD", text)
        self.assertIn("POST /api/v1/users", text)
        with open(os.path.join(out, "kn-nginx", "nginx.conf")) as f:
            site = f.read().split("server_name pay.sh3.home;", 1)[1].split("\n    server {", 1)[0]
        self.assertIn("http://kn-vpn-client:49392", site)
        # a chain of one's own for trying it: the node gets a wallet, nothing is pruned when 0
        m["node"]["btcpay"] = {"network": "regtest", "prune_mb": 0}
        with open(os.path.join(self.render("sh3-pay2", m), "docker-compose.yml")) as f:
            btc = yaml.safe_load(f)["services"]["kn-btcpay-bitcoind"]
        self.assertIn("CREATE_WALLET=true", btc["environment"])
        self.assertFalse([a for a in btc["command"] if a.startswith("-prune")])

    def test_the_pastebin_is_one_container_with_its_settings(self):
        m = json.loads(json.dumps(SH3))
        m["node"]["modules"] = ["vpn-client", "reverse-proxy", "paste"]
        m["node"].pop("preset", None)
        for k in ("cloud", "vault", "portainer"):
            m["node"].pop(k, None)
        m["node"]["paste"] = {"title": "Our \"paste\"", "size_mb": 20, "default_expire": "1day", "file_upload": False}
        out = self.render("sh3-paste", m)
        with open(os.path.join(out, "docker-compose.yml")) as f:
            d = yaml.safe_load(f)
        self.assertEqual(d["services"]["kn-paste"]["volumes"],
                         ["privatebin_data:/srv/data", "/home/user/docker/kn-paste/conf.php:/srv/cfg/conf.php:ro,z"])
        self.assertIn("privatebin_data", d["volumes"])                         # it owns its pastes: a volume, in the backup
        with open(os.path.join(out, "kn-paste", "conf.php")) as f:
            conf = f.read()
        self.assertTrue(conf.startswith(";<?php http_response_code(403); /*"))  # asked for as a page, it gives nothing away
        for line in ('name = "Our paste"', "sizelimit = 20971520", 'default = "1day"', "fileupload = false",
                     'header = "X_FORWARDED_FOR"'):
            self.assertIn(line, conf)
        with open(os.path.join(out, "kn-nginx", "nginx.conf")) as f:
            site = f.read().split("server_name paste.sh3.home;", 1)[1].split("\n    server {", 1)[0]
        self.assertIn("client_max_body_size 25m;", site)
        self.assertIn("http://kn-paste:8080", site)

    def test_sites_strangers_reach_are_rate_limited_and_fail2ban_reads_it(self):
        pub = self.xmpp_master(xmpp_domain="chat.example.org")
        pub["master"]["modules"] = list(pub["master"]["modules"]) + ["fail2ban"]
        pub["master"].setdefault("reverse-proxy", {}).update(public=True, acme_email="me@example.org")
        out = self.render("lim1", pub)
        with open(os.path.join(out, "km-nginx", "nginx.conf")) as f:
            nginx = f.read()
        self.assertIn("limit_req_zone $kiwi_limit_key zone=kiwi_public:10m rate=20r/s;", nginx)
        public = nginx.split("server_name chat.example.org;", 1)[1].split("\n    server {", 1)[0]
        self.assertIn("limit_req zone=kiwi_public burst=80 nodelay;", public)
        self.assertIn("limit_conn kiwi_conn 60;", public)
        mesh = nginx.split("server_name jabber.hub1.home;", 1)[1].split("\n    server {", 1)[0]
        self.assertNotIn("limit_req", mesh)                                    # the VPN's own sites are not limited
        with open(os.path.join(out, "km-fail2ban", "config", "fail2ban", "jail.d", "kiwi.local")) as f:
            jail = f.read()
        for name in ("[sshd]", "[nginx-limit-req]", "[kiwi-nginx-refused]", "[kiwi-nginx-probe]", "[recidive]"):
            self.assertIn(name, jail)
        self.assertIn("recidive-forward, chain=FORWARD", jail)
        with open(os.path.join(out, "km-fail2ban", "config", "fail2ban", "filter.d", "kiwi-nginx-refused.conf")) as f:
            rule = re.search(r"failregex = (.*)", f.read()).group(1).replace("<HOST>", r"(?P<host>\S+)")
        hit = '203.0.113.9 - - [15/Nov/2026:12:00:00 +0100] "POST /login HTTP/2.0" 401 12 "-" "curl" "-"'
        fine = '203.0.113.9 - - [15/Nov/2026:12:00:00 +0100] "GET / HTTP/2.0" 200 12 "-" "curl" "-"'
        self.assertEqual(re.match(rule, hit).group("host"), "203.0.113.9")
        self.assertIsNone(re.match(rule, fine))
        # rate_limit: 0 takes the limits out; a machine without public or hidden sites has none to begin with
        pub["master"]["reverse-proxy"]["rate_limit"] = 0
        with open(os.path.join(self.render("lim2", pub), "km-nginx", "nginx.conf")) as f:
            self.assertNotIn("limit_req", f.read())
        with open(os.path.join(self.render("lim3", json.loads(json.dumps(SH3))), "kn-nginx", "nginx.conf")) as f:
            self.assertNotIn("limit_req", f.read())

    def test_firefox_sync_is_mozillas_server_with_its_database(self):
        m = json.loads(json.dumps(SH3))
        m["node"]["modules"] = ["vpn-client", "reverse-proxy", "firefox-sync"]
        m["node"].pop("preset", None)
        for k in ("cloud", "vault", "portainer"):
            m["node"].pop(k, None)
        out = self.render("sh3-ffsync", m)
        with open(os.path.join(out, "docker-compose.yml")) as f:
            svcs = yaml.safe_load(f)["services"]
        env = dict(e.split("=", 1) for e in svcs["kn-ffsync"]["environment"])
        dbenv = dict(e.split("=", 1) for e in svcs["kn-ffsync-db"]["environment"])
        self.assertEqual(env["SYNC_TOKENSERVER__INIT_NODE_URL"], "https://ffsync.sh3.home")      # where browsers find their data
        self.assertEqual(env["SYNC_SYNCSTORAGE__DATABASE_URL"], "postgres://sync:%s@kn-ffsync-db:5432/syncserver" % dbenv["POSTGRES_PASSWORD"])
        self.assertEqual(env["SYNC_TOKENSERVER__DATABASE_URL"], env["SYNC_SYNCSTORAGE__DATABASE_URL"])
        self.assertTrue(len(env["SYNC_MASTER_SECRET"]) >= 20 and len(dbenv["POSTGRES_PASSWORD"]) >= 20)       # from the seed
        self.assertEqual(env["SYNC_TOKENSERVER__NODE_TYPE"], "postgres")
        self.assertEqual(svcs["kn-ffsync-db"]["volumes"], ["/home/user/docker/kn-ffsync/db:/var/lib/postgresql:z"])
        self.assertNotIn("ports", svcs["kn-ffsync"])
        with open(os.path.join(out, "kn-nginx", "nginx.conf")) as f:
            self.assertIn("http://kn-ffsync:8000", f.read().split("server_name ffsync.sh3.home;", 1)[1].split("\n    server {", 1)[0])

    def games_machine(self, **games):
        m = json.loads(json.dumps(SH3))
        m["node"]["modules"] = ["vpn-client", "games"]
        m["node"].pop("preset", None)
        for k in ("cloud", "vault", "reverse-proxy", "portainer"):
            m["node"].pop(k, None)
        m["node"]["games"] = games
        return m

    def source(self, name="hello", folder="src"):
        """A module source: a folder with one module, as a community repository has them."""
        d = os.path.join(self.tmp, folder, name)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "module.yaml"), "w") as f:
            f.write("schema_version: \"1.0\"\nmodule:\n  name: %s\n  title: Hello\n  version: 0.1.0\n"
                    "  description: a module from a source\n  category: productivity\n  node_types: [node]\n"
                    "dependencies: {required: [], optional: []}\nnetwork: {needs_vpn_dnat: false, open_ports: []}\n"
                    "firewall: {scope: self, rules: []}\ntemplates: {compose: docker-compose.yml.j2}\n"
                    "settings:\n  - key: greeting\n    default: hi\n" % name)
        with open(os.path.join(d, "docker-compose.yml.j2"), "w") as f:
            f.write("services:\n  {{ container_prefix }}-%s:\n    image: docker.io/library/busybox:1\n"
                    "    container_name: {{ container_prefix }}-%s\n    command: [\"echo\", {{ greeting | tojson }}]\n"
                    "    networks:\n      {{ network_name }}: {}\n" % (name, name))
        return os.path.join(self.tmp, folder)

    def test_a_module_of_a_source_renders_like_a_built_in_one(self):
        from kiwimodules import modules
        from kiwimodules.util import KiwiError
        src = self.source()
        ms = modules.discover(extra=[("community", src)])
        self.assertEqual((ms.get("hello").source, ms.get("cloud").source), ("community", None))
        self.assertEqual(ms.get("hello").as_dict()["source"], "community")
        m = self.games_machine()
        m["node"]["modules"] = ["vpn-client", "hello"]
        m["node"].pop("games")
        m["node"]["hello"] = {"greeting": "from the community"}
        path = self.write("sh3-hello", m)
        out = os.path.join(self.tmp, "sh3-hello.bundle")
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(cli.main(["render", path, "-o", out]), 1)            # without the source: unknown
        self.assertIn("unknown module 'hello'", err.getvalue())
        self.assertEqual(cli.main(["render", path, "-o", out, "--source", "community=" + src]), 0)
        with open(os.path.join(out, "docker-compose.yml")) as f:
            self.assertEqual(yaml.safe_load(f)["services"]["kn-hello"]["command"], ["echo", "from the community"])
        # a source never takes a built-in module's name, nor another source's
        self.source("cloud", "bad")
        with self.assertRaisesRegex(KiwiError, "module source bad: its module cloud has the name of a built-in module"):
            modules.discover(extra=[("bad", os.path.join(self.tmp, "bad"))])
        with self.assertRaisesRegex(KiwiError, "its module hello has the name of a module of the source community"):
            modules.discover(extra=[("community", src), ("personal", src)])
        os.makedirs(os.path.join(self.tmp, "empty"))
        with self.assertRaisesRegex(KiwiError, "module source e: no modules in"):
            modules.discover(extra=[("e", os.path.join(self.tmp, "empty"))])

    def test_a_module_names_its_pages_and_its_sign_in(self):
        from kiwimodules import modules
        from kiwimodules.util import KiwiError
        src = self.source("grow")
        mod = os.path.join(src, "grow", "module.yaml")
        with open(mod, "a") as f:
            f.write("pages:\n  grow: {label: Grow lights, about: Light schedules for the plugs}\n"
                    "accounts:\n  site: \"{{ 'grow.' ~ hostname }}\"\n  callbacks: [/oauth/back]\n  pkce: true\n"
                    "  - key: accounts_client\n")
        # (the settings it takes the client in are missing: said)
        with open(mod) as f:
            text = f.read().replace("  - key: accounts_client\n", "")
        with open(mod, "w") as f:
            f.write(text)
        with self.assertRaisesRegex(KiwiError, "the settings accounts_client, accounts_issuer, accounts_secret take the client"):
            modules.discover(extra=[("c", src)])
        with open(mod, "w") as f:
            f.write(text.replace("settings:\n", "settings:\n  - key: accounts_client\n    default: \"\"\n"
                                 "  - key: accounts_issuer\n    default: \"\"\n  - key: accounts_secret\n    type: secret\n    default: \"\"\n"))
        m = modules.discover(extra=[("c", src)]).get("grow")
        self.assertEqual(m.pages, {"grow": {"label": "Grow lights", "about": "Light schedules for the plugs", "public": ""}})
        self.assertEqual((m.accounts["callbacks"], m.accounts["pkce"], m.accounts["label"]), (["/oauth/back"], True, "Hello"))      # (its title)
        self.assertEqual(m.as_dict()["pages"]["grow"]["label"], "Grow lights")

    def test_each_site_says_how_it_can_be_opened_beyond_the_vpn(self):
        """The app's and the page's "Open to": the name setting for the Internet, Tor, admin pages never."""
        from kiwimodules import modules
        ms = modules.discover()
        by = {(m, x["key"]): x for m in ("git", "vault", "xmpp", "control", "games") for x in ms.get(m).sites()}
        self.assertEqual((by["git", "git"]["setting"], by["git", "git"]["tor"]), ("git_hostname", True))
        self.assertTrue(by["vault", "vault"]["url"])                         # vault_domain is https://<name>
        self.assertEqual(by["xmpp", "jabber"]["setting"], "xmpp_domain")     # its own door, from pages:
        self.assertTrue(by["control", "control"]["admin"])                   # never offered beyond the VPN
        self.assertEqual(by["control", "status"]["setting"], "public_status_hostname")
        self.assertFalse([k for k in by if k[0] == "games"])                 # no web site

    def test_a_public_game_server_is_handed_on_by_the_master(self):
        from kiwimodules import modules as modmod, profiles
        m = self.games_machine(eula=True, servers={
            "survival": {"game": "minecraft", "public": True},
            "doom": {"game": "zandronum", "public": True, "port": 10700},
            "private": {"game": "terraria"}})
        mm = machine.load(self.write("sh3-games-public", m))
        profile = profiles.discover()[mm.role]
        ms = modmod.discover()
        resolver.resolve_settings(profile, mm, ms)
        spec = resolver.stack_spec(mm, profile, mm.dns_records, master_ip=mm.master_ip, ca_cert=mm.ca_cert, lan_addresses=mm.lan_addresses)
        names, ports = modmod.Renderer(ms).exposure(spec)
        self.assertEqual(names, [])                                    # no web site: a game needs no public proxy
        self.assertEqual(sorted((p["port"], p["to"], p["proto"], p["proxy_protocol"]) for p in ports),
                         [(10700, 10700, "udp", False), (25565, 25565, "tcp", False)])        # the private one stays at home

    def test_game_servers_each_get_a_container_a_folder_and_their_ports(self):
        out = self.render("sh3-games", self.games_machine(eula=True, servers={
            "survival": {"game": "minecraft", "memory": "4G", "name": "Our world"},
            "doom": {"game": "zandronum"},
            "lab": {"game": "abiotic-factor", "port": 7800, "password": "join-me", "env": {"MaxServerPlayers": "4"}}}))
        with open(os.path.join(out, "docker-compose.yml")) as f:
            svcs = yaml.safe_load(f)["services"]
        mc, doom, lab = svcs["kn-game-survival"], svcs["kn-game-doom"], svcs["kn-game-lab"]
        self.assertEqual(mc["image"], "docker.io/itzg/minecraft-server:latest")
        self.assertEqual(mc["ports"], ["25565:25565/tcp"])
        for e in ("EULA=TRUE", "MEMORY=4G", "MOTD=Our world", "UID=1000"):
            self.assertIn(e, mc["environment"])
        # the world, backed up; and a folder for a server pack's archive (a modded server), not backed up
        self.assertEqual(mc["volumes"], ["/home/user/docker/kn-games-files/survival/modpacks:/modpacks:z",
                                         "/home/user/docker/kn-games/survival/data:/data:z"])
        # the image's own word that it takes players (the catalog's `health`); a game without one has no check
        self.assertEqual(mc["healthcheck"]["test"], ["CMD", "mc-health"])
        self.assertEqual(mc["healthcheck"]["start_period"], "900s")
        self.assertNotIn("healthcheck", doom)
        # Satisfactory: the game apart from the folder that is backed up, and the server's own answer as its check
        factory = self.render("sh3-factory", self.games_machine(servers={"factory": {"game": "satisfactory"}}))
        with open(os.path.join(factory, "docker-compose.yml")) as f:
            sat = yaml.safe_load(f)["services"]["kn-game-factory"]
        self.assertEqual(sat["volumes"], ["/home/user/docker/kn-games-files/factory/gamefiles:/config/gamefiles:z",
                                          "/home/user/docker/kn-games/factory/config:/config:z"])
        self.assertEqual(sat["healthcheck"]["test"][:3], ["CMD", "sh", "-c"])
        self.assertIn('"function":"HealthCheck"', sat["healthcheck"]["test"][3])
        self.assertEqual(doom["command"], "zandronum-server -port 10666 -iwad /data/freedoom2.wad +sv_hostname doom +deathmatch 1 +map MAP01")
        self.assertEqual(doom["ports"], ["10666:10666/udp"])
        # another first port: every port of the server moves with it, inside it stays the game's own
        self.assertEqual(lab["ports"], ["7800:7777/udp", "27038:27015/udp"])
        self.assertIn("ServerPassword=join-me", lab["environment"])
        self.assertIn("MaxServerPlayers=4", lab["environment"])             # the server's own setting over the catalog's
        self.assertNotIn("MaxServerPlayers=6", lab["environment"])
        # what it keeps is backed up, the game it downloads is not
        self.assertEqual(sorted(lab["volumes"]), ["/home/user/docker/kn-games-files/lab/game:/server:z",
                                                  "/home/user/docker/kn-games/lab/saves:/server/AbioticFactor/Saved:z"])
        with open(os.path.join(out, "stack.sh")) as f:
            sh = f.read()
        dirs = re.search(r"KS_STACK_DIRS=\(([^)]*)\)", sh).group(1)
        for d in ("'kn-games/survival/data'", "'kn-games/doom/data'", "'kn-games/lab/saves'", "'kn-games-files/lab/game'"):
            self.assertIn(d, dirs)
        self.assertIn("KS_STACK_PORTS=('25565/tcp' '10666/udp' '7800/udp' '27038/udp')", sh)
        with open(os.path.join(out, "kn-vpn-client", "post-rules.txt")) as f:
            rules = f.read()
        for proto, port in (("tcp", 25565), ("udp", 10666), ("udp", 7800), ("udp", 27038)):      # from the VPN, at the mesh address
            self.assertIn("-d 10.8.0.25 -p %s --dport %d -j DNAT --to-destination 172.128.0.1:%d" % (proto, port, port), rules)
        with open(os.path.join(out, "quadlets", "kn-game-survival.container")) as f:
            unit = f.read()
        self.assertIn("PublishPort=25565:25565/tcp", unit)
        self.assertIn("StopTimeout=90", unit)

    def test_a_game_server_sleeps_while_nobody_plays_and_wakes_for_the_first_who_does(self):
        out = self.render("sh3-games-sleep", self.games_machine(eula=True, servers={
            "survival": {"game": "minecraft", "sleep": 5},
            "lab": {"game": "abiotic-factor", "port": 7800, "sleep": 5},
            "doom": {"game": "zandronum"}}))
        script = read(out, "kiwi/games-sleep.sh")
        self.assertIn("kiwi/games-sleep.sh watch", read(out, "host-units/kn-games-sleep.service"))
        self.assertIn('"kn-game-survival 5 25565/tcp"', script)
        self.assertIn('"kn-game-lab 5 7800/udp 27038/udp"', script)         # its ports where they moved to
        self.assertNotIn("kn-game-doom", script)                             # no sleep: always on
        path = os.path.join(out, "kiwi", "games-sleep.sh")
        self.assertEqual(subprocess.run(["bash", "-n", path]).returncode, 0)
        # without a sleeper there is nothing to install
        plain = self.render("sh3-games-awake", self.games_machine(servers={"doom": {"game": "zandronum"}}))
        self.assertFalse(os.path.exists(os.path.join(plain, "kiwi", "games-sleep.sh")))
        self.assertFalse(os.path.exists(os.path.join(plain, "host-units", "kn-games-sleep.service")))
        for bad in (2, "soon"):
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                rc = cli.main(["render", self.write("gs", self.games_machine(servers={"d": {"game": "zandronum", "sleep": bad}})),
                               "-o", self.tmp + "/gs"])
            self.assertEqual(rc, 1)
            self.assertIn("5 or more", err.getvalue())
        # run for real against stand-ins: the counters of iptables, and systemd's units as files
        bin_, state, sleeping = (os.path.join(self.tmp, d) for d in ("sleep-bin", "sleep-state", "sleeping"))
        for d in (bin_, state, sleeping):
            os.makedirs(d)
        counts, said = os.path.join(self.tmp, "counts"), os.path.join(self.tmp, "said")
        stubs = {
            "iptables": 'case "$*" in *" -L "*) cat %s ;; esac\nexit 0\n' % counts,
            "ip6tables": "exit 1\n",
            "systemctl": 'u=""; for a; do u=${a%%.service}; done\n[ "$1" = -q ] && shift\ncase "$1" in\n'
                         '  is-active) [ -e %s/$u ] ;;\n  stop) rm -f %s/$u; echo "stop $u" >> %s ;;\n'
                         '  start) touch %s/$u; echo "start $u" >> %s ;;\n  *) exit 0 ;;\nesac\n' % (state, state, said, state, said),
        }
        for name, body in stubs.items():
            with open(os.path.join(bin_, name), "w") as f:
                f.write("#!/bin/sh\n" + body)
            os.chmod(os.path.join(bin_, name), 0o755)

        def knock(survival, lab):
            with open(counts + ".new", "w") as f:
                f.write("Chain KN-GAMES-SLEEP (1 references)\n    pkts      bytes target     prot opt in     out     source               destination\n"
                        "%8d 0  tcp -- * * 0.0.0.0/0 0.0.0.0/0 tcp dpt:25565 ctdir ORIGINAL /* kn-game-survival */\n"
                        "%8d 0  udp -- * * 0.0.0.0/0 0.0.0.0/0 udp dpt:7800 ctdir ORIGINAL /* kn-game-lab */\n"
                        "       1 0  udp -- * * 0.0.0.0/0 0.0.0.0/0 udp dpt:27038 ctdir ORIGINAL /* kn-game-lab */\n" % (survival, lab))
            os.replace(counts + ".new", counts)

        def until(what, seconds=8):
            end = time.time() + seconds
            while time.time() < end:
                if what():
                    return True
                time.sleep(0.1)
            return False
        knock(0, 0)
        open(os.path.join(state, "kn-game-survival"), "w").close()          # it runs; lab was stopped by hand
        env = dict(os.environ, PATH=bin_ + ":" + os.environ["PATH"], KS_SLEEPING=sleeping, KIWI_SLEEP_STEP="0.2",
                   KIWI_SLEEP_MINUTE="1")
        proc = subprocess.Popen(["bash", path, "watch"], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        try:
            time.sleep(3)
            knock(7, 0)                                                     # someone plays: its time begins again
            time.sleep(3)
            self.assertTrue(os.path.exists(os.path.join(state, "kn-game-survival")))
            self.assertTrue(until(lambda: not os.path.exists(os.path.join(state, "kn-game-survival"))))      # five quiet "minutes"
            self.assertTrue(os.path.exists(os.path.join(sleeping, "kn-game-survival")))                     # asleep, not down
            knock(8, 5)                                                     # a player knocks on both
            self.assertTrue(until(lambda: os.path.exists(os.path.join(state, "kn-game-survival"))))
            self.assertTrue(until(lambda: not os.path.exists(os.path.join(sleeping, "kn-game-survival"))))   # (just after the start)
            time.sleep(1)
            self.assertFalse(os.path.exists(os.path.join(state, "kn-game-lab")))    # stopped by hand: stays stopped
        finally:
            proc.kill()
            log = proc.communicate()[0]
        self.assertIn("kn-game-survival: nobody played for 5 minutes, it sleeps", log)
        self.assertIn("kn-game-survival: a player knocked, it wakes up", log)
        with open(said) as f:
            self.assertEqual(f.read().split(), ["stop", "kn-game-survival", "start", "kn-game-survival"])
        self.assertIn('systemctl reset-failed "$1.service"', script)          # a game that ends with an error code: not failed

    def test_bedrock_has_its_handshake_on_tcp_and_its_game_on_udp_at_one_port(self):
        from kiwimodules import modules as modmod, profiles
        m = self.games_machine(eula=True, servers={"pocket": {"game": "minecraft-bedrock", "public": True, "port": 19200}})
        out = self.render("sh3-bedrock", m)
        with open(os.path.join(out, "docker-compose.yml")) as f:
            be = yaml.safe_load(f)["services"]["kn-game-pocket"]
        # it listens on its own port inside too: the server tells clients that port, and a second one
        # on 19132 inside would send them to the first server
        self.assertEqual(be["ports"], ["19200:19200/tcp", "19200:19200/udp"])
        self.assertIn("SERVER_UDP_PORTS=19200", be["environment"])
        self.assertIn("SERVER_PORT=19200", be["environment"])
        self.assertFalse(any(e.startswith("UID=") for e in be["environment"]))   # it takes the folder's owner
        mm = machine.load(self.write("sh3-bedrock-public", m))
        profile = profiles.discover()[mm.role]
        ms = modmod.discover()
        resolver.resolve_settings(profile, mm, ms)
        spec = resolver.stack_spec(mm, profile, mm.dns_records, master_ip=mm.master_ip, ca_cert=mm.ca_cert, lan_addresses=mm.lan_addresses)
        _names, ports = modmod.Renderer(ms).exposure(spec)
        self.assertEqual(sorted((p["port"], p["proto"]) for p in ports), [(19200, "tcp"), (19200, "udp")])

    def test_game_servers_say_what_is_missing(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = cli.main(["render", self.write("g1", self.games_machine(servers={"a": {"game": "minecraft"}})), "-o", self.tmp + "/g1"])
        self.assertEqual(rc, 1)
        self.assertIn("needs its licence accepted", err.getvalue())
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = cli.main(["render", self.write("g2", self.games_machine(servers={"a": {"game": "pong"}, "B b": {"game": "terraria"}})),
                           "-o", self.tmp + "/g2"])
        self.assertEqual(rc, 1)
        self.assertIn("no such game: pong", err.getvalue())
        # a game of one's own: one more entry of the catalog
        from kiwimodules import modules
        catalog = dict(next(s.default for s in modules.discover().get("games").settings if s.key == "catalog"))
        catalog["pong"] = {"title": "Pong", "image": "example.org/pong:1", "ports": ["4000/udp"], "data": {"scores": "/scores"}}
        out = self.render("g3", self.games_machine(servers={"p": {"game": "pong"}}, catalog=catalog))
        with open(os.path.join(out, "docker-compose.yml")) as f:
            pong = yaml.safe_load(f)["services"]["kn-game-p"]
        self.assertEqual((pong["image"], pong["ports"], pong["volumes"]),
                         ("example.org/pong:1", ["4000:4000/udp"], ["/home/user/docker/kn-games/p/scores:/scores:z"]))
        # no server at all: the module is there and starts nothing
        out = self.render("g4", self.games_machine())
        with open(os.path.join(out, "docker-compose.yml")) as f:
            self.assertFalse([n for n in yaml.safe_load(f)["services"] if "game" in n])

    def test_nextclouds_database_gets_its_settings_back_after_a_power_cut(self):
        out = self.render("sh3-dbguard", json.loads(json.dumps(SH3)))
        with open(os.path.join(out, "docker-compose.yml")) as f:
            db = yaml.safe_load(f)["services"]["nextcloud-aio-database"]
        self.assertEqual((db["entrypoint"], db["command"]), (["/bin/sh"], ["/kiwi-start.sh"]))
        self.assertIn("/home/user/docker/nextcloud-aio-database/kiwi-start.sh:/kiwi-start.sh:ro,z", db["volumes"])
        script = os.path.join(out, "nextcloud-aio-database", "kiwi-start.sh")
        self.assertEqual(subprocess.run(["sh", "-n", script]).returncode, 0)
        # run for real against a folder that looks like the database's: an emptied file is put back, a good one kept
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        data, sample, started = os.path.join(tmp, "data"), os.path.join(tmp, "sample"), os.path.join(tmp, "started")
        os.makedirs(data)
        with open(sample, "w") as f:
            f.write("listen_addresses = '*'\nmax_connections = 100\n")
        with open(os.path.join(tmp, "start.sh"), "w") as f:
            f.write("#!/bin/sh\ntouch %s\n" % started)
        os.chmod(os.path.join(tmp, "start.sh"), 0o755)
        with open(script) as f:
            text = f.read().replace("/var/lib/postgresql/data", data).replace(
                "/usr/local/share/postgresql/postgresql.conf.sample", sample).replace("exec /start.sh", "exec %s/start.sh" % tmp)
        guard = os.path.join(tmp, "guard.sh")
        with open(guard, "w") as f:
            f.write(text)
        conf = os.path.join(data, "postgresql.conf")

        def run(before):
            if before is not None:
                with open(conf, "w") as f:
                    f.write(before)
            r = subprocess.run(["sh", guard], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertTrue(os.path.exists(started))
            os.remove(started)
            return (open(conf).read() if os.path.exists(conf) else None), r.stdout
        self.assertEqual(run("log_min_messages = warning\n")[0], "log_min_messages = warning\n")     # no database yet: left alone
        open(os.path.join(data, "PG_VERSION"), "w").write("18\n")
        after, said = run("log_min_messages = warning\n")                         # what a power cut left
        self.assertEqual(after, "listen_addresses = '*'\nmax_connections = 100\n")
        self.assertIn("putting the image's own back", said)
        self.assertEqual(oct(os.stat(conf).st_mode & 0o777), "0o600")
        kept = "listen_addresses = '*'\nmax_connections = 5000\n"
        self.assertEqual(run(kept), (kept, ""))                                   # a good file is not touched

    def test_the_cache_mirrors_registries_behind_the_proxy_and_proxies_apt(self):
        m = json.loads(json.dumps(SH3))
        m["node"]["modules"] = ["vpn-client", "reverse-proxy", "cache"]
        m["node"].pop("preset", None)
        for k in ("cloud", "vault"):
            m["node"].pop(k, None)
        m["node"]["cache"] = {"registries": ["docker.io", "ghcr.io"]}
        out = self.render("sh3-cache", m)
        with open(os.path.join(out, "docker-compose.yml")) as f:
            svcs = yaml.safe_load(f)["services"]
        self.assertIn("REGISTRY_PROXY_REMOTEURL=https://registry-1.docker.io", svcs["kn-cache-docker"]["environment"])
        self.assertIn("REGISTRY_PROXY_REMOTEURL=https://ghcr.io", svcs["kn-cache-ghcr"]["environment"])
        # a layer whose data expired is fetched again, not served empty (no in-memory descriptor cache)
        self.assertIn("REGISTRY_STORAGE_CACHE_BLOBDESCRIPTOR=off", svcs["kn-cache-docker"]["environment"])
        self.assertNotIn("kn-cache-quay", svcs)
        self.assertEqual(svcs["kn-cache-apt"]["ports"], ["3142:3142"])
        nginx = open(os.path.join(out, "kn-nginx", "nginx.conf")).read()
        site = nginx.split("server_name cache.sh3.home;", 1)[1]
        self.assertIn("set $mirror http://kn-cache-ghcr:5000; rewrite ^/v2/ghcr\\.io/(.*)$ /v2/$1 break;", site)   # set first: break ends them
        apt = open(os.path.join(out, "kn-cache", "apt-nginx.conf")).read()
        self.assertIn("deb.debian.org 1;", apt)
        self.assertIn("max_size=10g", apt)
        # install images: kept for the LAN at cache.<hostname>/files/<server>/<path>, from a few servers only
        self.assertIn("kn-cache-files", svcs)
        self.assertIn("set $files http://kn-cache-files:8080; proxy_pass $files;", site)
        files = open(os.path.join(out, "kn-cache", "files-nginx.conf")).read()
        for server in ("builds.coreos.fedoraproject.org 1;", "cdimage.debian.org 1;"):
            self.assertIn(server, files)
        self.assertIn("proxy_ssl_verify on;", files)
        self.assertIn("max_size=20g", files)
        m["node"]["cache"]["files"] = False
        out = self.render("sh3-cache-nofiles", m)
        with open(os.path.join(out, "docker-compose.yml")) as f:
            self.assertNotIn("kn-cache-files", yaml.safe_load(f)["services"])
        self.assertNotIn("kn-cache-files", open(os.path.join(out, "kn-nginx", "nginx.conf")).read())

    def test_a_node_lets_partners_open_only_the_shared_names(self):
        m = json.loads(json.dumps(SH3))
        m["node"].setdefault("reverse-proxy", {})["federation"] = {
            "names": {"cloud.sh3.home": {"allow": ["10.10.3.0/24"], "deny": ["10.10.0.0/16"]}},
            "deny": ["10.10.0.0/16"]}
        out = self.render("sh3-fed", m)
        nginx = open(os.path.join(out, "kn-nginx", "nginx.conf")).read()
        cloud = nginx.split("server_name cloud.sh3.home;", 1)[1].split("server {", 1)[0]
        vault = nginx.split("server_name vault.sh3.home;", 1)[1].split("server {", 1)[0]
        self.assertLess(cloud.index("allow 10.10.3.0/24;"), cloud.index("deny 10.10.0.0/16;"))
        self.assertIn("deny 10.10.0.0/16;", vault)
        self.assertNotIn("allow 10.10.3.0/24;", vault)


class TestAccess(unittest.TestCase):
    """Who on the VPN may reach what: a group's reach names nodes, one service or one port."""
    setUp, tearDown, render, write = TestRender.setUp, TestRender.tearDown, TestRender.render, TestRender.write

    def start_of(self, name, groups):
        m = json.loads(json.dumps(MACHINES["gate"]))
        m["master"]["vpn-server"]["groups"] = groups
        m["dns_records"] = RECORDS
        out = self.render(name, m)
        path = os.path.join(out, "km-vpn-server", "start.sh")
        self.assertEqual(subprocess.run(["sh", "-n", path]).returncode, 0)
        with open(path) as f:
            return f.read()

    def test_a_narrow_group_reaches_a_linked_network_only_when_named(self):
        m = json.loads(json.dumps(MACHINES["gate"]))
        m["master"]["vpn-server"]["groups"] = {
            "guests": {"subnet": "10.8.1.0/24", "reach": ["nodes"]},
            "friends": {"subnet": "10.8.2.0/24", "reach": ["nodes", "kiwi2"]},
            "devices": {"subnet": "10.8.3.0/24", "reach": ["all"]}}
        m["master"]["vpn-server"]["federation"] = {"kiwi2": {
            "endpoint": "198.51.100.9", "public_key": "cGFydG5lci1wdWJsaWMta2V5LW5vdC1yZWFsLTAwMDA9", "mesh": "10.10.0.0/16",
            "domain": "internal", "dns": "10.10.0.1", "share": [], "from": [], "as": "10.8.255.1"}}
        m["dns_records"] = RECORDS
        with open(os.path.join(self.render("gate-groups-fed", m), "km-vpn-server", "start.sh")) as f:
            start = f.read()
        self.assertIn("-A FORWARD -s 10.8.1.0/24 -d 10.10.0.0/16 -j DROP", start)       # not named: what kiwi2 opens is not theirs
        self.assertIn("-A FORWARD -s 10.8.2.0/24 -d 10.10.0.0/16 -j ACCEPT", start)     # named
        self.assertNotIn("-s 10.8.3.0/24 -d 10.10.0.0/16", start)                      # everything: as before
        self.assertNotIn("reach kiwi2: no such name", start)

    def test_a_group_reaches_one_service_or_one_port_of_a_node(self):
        start = self.start_of("gate-access", {
            "guests": {"subnet": "10.8.1.0/24", "reach": ["cloud.sh3", "m1:22", "min", "vault.sh3.home", "nowhere"], "peers": False},
            "family": {"subnet": "10.8.5.0/24", "reach": ["sh3", "cloud.sh3", "10.8.0.99"]}})
        g = [x for x in start.splitlines() if "-s 10.8.1.0/24" in x]
        for want in ("-d 10.8.0.25 -p tcp --dport 443 -j ACCEPT", "-d 10.8.0.25 -p tcp --dport 80 -j ACCEPT",   # a service: its web address
                     "-d 10.8.0.6 -p tcp --dport 22 -j ACCEPT",                                                 # a port
                     "-d 10.8.0.9 -j ACCEPT"):                                                                  # a whole node
            self.assertTrue(any(x.endswith(want) for x in g), want)
        self.assertFalse(any(x.endswith("-d 10.8.0.25 -j ACCEPT") or x.endswith("-d 10.8.0.6 -j ACCEPT") for x in g))
        self.assertEqual(len([x for x in g if "--dport 443" in x and "FORWARD" in x]), 1)      # two services of sh3: one rule
        self.assertEqual(g[-2:], ["iptables -A FORWARD -s 10.8.1.0/24 -d 10.8.0.0/16 -j DROP",
                                  "iptables -t nat -A POSTROUTING -s 10.8.1.0/24 -o eth0 -j MASQUERADE"])
        self.assertIn("# reach nowhere: no such name in this fleet, left out", start)
        self.assertNotIn("-d nowhere", start)
        f = [x for x in start.splitlines() if "-s 10.8.5.0/24" in x]
        self.assertIn("iptables -A FORWARD -s 10.8.5.0/24 -d 10.8.0.25 -j ACCEPT", f)          # the whole node: no port rules beside it
        self.assertFalse(any("--dport" in x and "FORWARD" in x for x in f))
        self.assertIn("iptables -A FORWARD -s 10.8.5.0/24 -d 10.8.0.99 -j ACCEPT", f)          # an address as written
        self.assertIn("iptables -A FORWARD -s 10.8.5.0/24 -d 10.8.0.6 -j DROP", f)             # the other nodes, one by one

    def test_apps_are_the_web_pages_of_every_node_and_nothing_else(self):
        start = self.start_of("gate-apps", {"family": {"subnet": "10.8.5.0/24", "reach": ["apps"]}})
        f = [x for x in start.splitlines() if "-s 10.8.5.0/24" in x and "FORWARD" in x]
        for ip in ("10.8.0.6", "10.8.0.25", "10.8.0.9"):
            self.assertIn("iptables -A FORWARD -s 10.8.5.0/24 -d %s -p tcp --dport 443 -j ACCEPT" % ip, f)
            self.assertIn("iptables -A FORWARD -s 10.8.5.0/24 -d %s -j DROP" % ip, f)          # no SSH, nothing else
            self.assertNotIn("iptables -A FORWARD -s 10.8.5.0/24 -d %s -j ACCEPT" % ip, f)

    def test_the_admin_pages_are_marked(self):
        from kiwimodules import modules
        ms = modules.discover()

        def admin(name):
            nx = ms.get(name).nginx
            return [bool(e.get("admin")) for e in ([nx] if nx.get("server_name") else []) + list(nx.get("servers") or [])]
        for name in ("portainer", "dns", "vpn-server", "backup-server", "cache"):
            self.assertEqual(admin(name), [True], name)
        self.assertEqual(admin("control"), [True] + [False] * 6)    # the control page is one; status, games and the website are not
        for name in ("cloud", "vault", "paperless", "git"):
            self.assertFalse(any(admin(name)), name)

    def test_a_node_refuses_a_group_the_names_it_was_not_given(self):
        m = json.loads(json.dumps(SH3))
        m["node"].setdefault("reverse-proxy", {})["access"] = {
            "names": {"cloud.sh3.home": []}, "others": ["10.8.1.0/24"]}
        out = self.render("sh3-access", m)
        with open(os.path.join(out, "kn-nginx", "nginx.conf")) as f:
            nginx = f.read()
        cloud = nginx.split("server_name cloud.sh3.home;", 1)[1].split("server {", 1)[0]
        vault = nginx.split("server_name vault.sh3.home;", 1)[1].split("server {", 1)[0]
        self.assertNotIn("deny 10.8.1.0/24;", cloud)
        self.assertIn("deny 10.8.1.0/24;", vault)

    def test_a_site_with_its_own_allow_list_still_shuts_out_who_was_not_given_it(self):
        """The control page allows the mesh in its location. nginx then ignores the server
        block's deny lines: a group or a partner that was given another service of the node
        opened the control page too (found by kiwi-server's access drill)."""
        m = json.loads(json.dumps(SH3))
        m["node"]["modules"] = ["vpn-client", "reverse-proxy", "cloud", "control"]
        m["node"].pop("preset", None)
        m["node"]["reverse-proxy"]["access"] = {"names": {"cloud.sh3.home": []}, "others": ["10.8.1.0/24"]}
        m["node"]["reverse-proxy"]["federation"] = {
            "names": {"cloud.sh3.home": {"allow": ["10.8.255.1"], "deny": ["10.8.255.1"]}}, "deny": ["10.8.255.1"]}
        out = self.render("sh3-control", m)
        with open(os.path.join(out, "kn-nginx", "nginx.conf")) as f:
            nginx = f.read()
        site = nginx.split("server_name control.sh3.home;", 1)[1].split("\n    server {", 1)[0]
        where = site.split("location / {", 1)[1]
        for shut in ("deny 10.8.1.0/24;", "deny 10.8.255.1;"):
            self.assertIn(shut, where)
            self.assertLess(where.index(shut), where.index("allow 10.8.0.0/16;"))      # the first match counts
        cloud = nginx.split("server_name cloud.sh3.home;", 1)[1].split("\n    server {", 1)[0]
        self.assertNotIn("deny 10.8.1.0/24;", cloud.split("location / {", 1)[1])        # no rules of its own there


class TestOnion(unittest.TestCase):
    """Hidden services: Tor in the VPN client's network, the proxy's .onion sites."""
    setUp, tearDown, render, write = TestRender.setUp, TestRender.tearDown, TestRender.render, TestRender.write
    KEYS = {"vault": {"address": "a" * 56 + ".onion", "secret": "c2VjcmV0", "public": "cHVibGlj", "clients": {}},
            "cloud": {"address": "b" * 56 + ".onion", "secret": "c2VjcmV0Mg==", "public": "cHVibGljMg==", "clients": {"anna": "ANNAKEY"}}}

    def node(self, name, **change):
        m = json.loads(json.dumps(SH3))
        m["node"]["modules"] = ["vpn-client", "reverse-proxy", "cloud", "vault", "onion"]
        m["node"].pop("preset", None)
        m["node"]["onion"] = {"services": {"vault": {}, "cloud": {"clients": ["anna"]}}, "keys": self.KEYS}
        m["node"]["reverse-proxy"]["onion"] = {"vault.sh3.home": self.KEYS["vault"]["address"], "cloud.sh3.home": self.KEYS["cloud"]["address"]}
        m["node"].update(change)
        out = self.render(name, m)
        with open(os.path.join(out, "docker-compose.yml")) as f:
            compose = yaml.safe_load(f)
        return out, compose

    def test_a_hidden_service_answers_https_when_asked_to_and_names_no_inner_port(self):
        out, _compose = self.node("sh3-onion-plain")
        with open(os.path.join(out, "kn-nginx", "nginx.conf")) as f:
            nginx = f.read()
        self.assertIn("port_in_redirect off;", nginx)             # a redirect at a hidden service names no port 8043
        # Nextcloud's site has a proxy_redirect of its own: at its hidden service only one is left (nginx refuses two)
        at = nginx.index("server_name %s;" % self.KEYS["cloud"]["address"])
        end = nginx.index("\n    }\n", at)
        self.assertEqual(nginx[at:end].split("location / {")[1].split("}")[0].count("proxy_redirect "), 1)
        self.assertNotIn("8044", nginx)
        with open(os.path.join(out, "kn-onion", "etc", "torrc")) as f:
            self.assertNotIn("HiddenServicePort 443", f.read())
        # tls: Tor hands 443 over too, and the proxy answers it with a certificate for the addresses
        m = json.loads(json.dumps(SH3))
        m["node"]["modules"] = ["vpn-client", "reverse-proxy", "vault", "onion"]
        m["node"].pop("preset", None); m["node"].pop("cloud", None)
        m["node"]["onion"] = {"services": {"vault": {}}, "keys": {"vault": self.KEYS["vault"]}, "tls": True}
        m["node"]["reverse-proxy"]["onion"] = {"vault.sh3.home": self.KEYS["vault"]["address"]}
        self.assertNotEqual(cli.main(["render", self.write("sh3-onion-nocert", m), "-o", os.path.join(self.tmp, "nocert.bundle")]), 0)
        m["node"]["reverse-proxy"].update(onion_fullchain=TLS["tls_fullchain"], onion_privkey=TLS["tls_privkey"])
        out = self.render("sh3-onion-tls", m)
        with open(os.path.join(out, "kn-nginx", "nginx.conf")) as f:
            nginx = f.read()
        at = nginx.index("server_name %s;" % self.KEYS["vault"]["address"])
        block = nginx[at - 400:at]
        self.assertIn("listen 8043;", block)
        self.assertIn("listen 8044 ssl;", block)
        self.assertIn("ssl_certificate     /etc/nginx/onion-fullchain.pem;", block)
        self.assertIn("listen 8044 ssl default_server;", nginx)
        # the service's cookies, made for its usual name, hold for the hidden address
        self.assertIn("proxy_cookie_domain vault.sh3.home $host;", nginx[at:at + 2500])
        with open(os.path.join(out, "kn-onion", "etc", "torrc")) as f:
            self.assertRegex(f.read(), r"HiddenServicePort 443 [0-9.]+:8044")
        self.assertTrue(os.path.isfile(os.path.join(out, "kn-nginx", "onion-privkey.pem")))
        with open(os.path.join(out, "docker-compose.yml")) as f:
            vols = yaml.safe_load(f)["services"]["kn-nginx"]["volumes"]
        self.assertTrue(any(v.endswith("/etc/nginx/onion-fullchain.pem:ro,z") for v in vols))

    def test_the_authenticator_is_for_the_vpn_and_keeps_its_key(self):
        m = json.loads(json.dumps(SH3))
        m["node"]["modules"] = ["vpn-client", "reverse-proxy", "authenticator"]
        m["node"].pop("preset", None); m["node"].pop("cloud", None)
        out = self.render("sh3-auth", m)
        with open(os.path.join(out, "docker-compose.yml")) as f:
            svc = yaml.safe_load(f)["services"]["kn-auth"]
        env = dict(e.split("=", 1) for e in svc["environment"])
        self.assertEqual(len(env["APP_KEY"]), 32)                     # from the seed: the same at every render
        self.assertEqual(env["APP_URL"], "https://auth.sh3.home")
        self.assertEqual(env["WEBAUTHN_ID"], "auth.sh3.home")
        self.assertNotIn("ports", svc)
        self.assertTrue(any(v.endswith("/kn-auth/data:/2fauth:z") for v in svc["volumes"]))
        with open(os.path.join(self.render("sh3-auth2", m), "docker-compose.yml")) as f:
            again = dict(e.split("=", 1) for e in yaml.safe_load(f)["services"]["kn-auth"]["environment"])
        self.assertEqual(again["APP_KEY"], env["APP_KEY"])
        with open(os.path.join(out, "kn-nginx", "nginx.conf")) as f:
            self.assertIn("server_name auth.sh3.home;", f.read())
        # the secrets of one's logins are not for a public name
        m["node"]["authenticator"] = {"auth_hostname": "auth.example.org"}
        self.assertNotEqual(cli.main(["render", self.write("sh3-auth3", m), "-o", os.path.join(self.tmp, "auth3.bundle")]), 0)

    def test_tor_shares_the_vpn_clients_network_and_only_serves(self):
        out, compose = self.node("sh3-onion")
        svc = compose["services"]["kn-onion"]
        self.assertEqual(svc["network_mode"], "service:kn-vpn-client")      # leaves at the master, never from home
        self.assertNotIn("ports", svc)
        self.assertEqual((svc["entrypoint"], svc["command"]), ("/bin/sh", ["/etc/tor/start.sh"]))
        with open(os.path.join(out, "kn-onion", "etc", "torrc")) as f:
            torrc = f.read()
        self.assertIn("SocksPort unix:/var/lib/tor/self-check.sock", torrc)       # its own self-check only
        self.assertNotRegex(torrc, r"SocksPort [0-9]")
        self.assertEqual(torrc.count("HiddenServiceDir /var/lib/tor/onion/"), 2)
        self.assertRegex(torrc, r"HiddenServicePort 80 [0-9.]+:8043")
        start = os.path.join(out, "kn-onion", "etc", "start.sh")
        self.assertEqual(subprocess.run(["sh", "-n", start]).returncode, 0)
        with open(start) as f:
            script = f.read()
        self.assertIn("printf '%s\\n' 'descriptor:x25519:ANNAKEY' > \"$D/cloud/authorized_clients/anna.auth\"", script)
        self.assertNotIn("vault/authorized_clients/anna", script)             # open to anyone with the address
        self.assertIn("su-exec tor tor -f /etc/tor/torrc &", script)
        addresses = re.search(r'^ADDRESSES="([^"]*)"', script, re.M).group(1).split()
        self.assertEqual(addresses, ["vault=" + self.KEYS["vault"]["address"]])    # cloud is for anna only: not asked
        # what it found, for the status pages: name, address, answer, when; replaced whole each round
        self.assertIn('printf \'%s %s %s %s\\n\' "${na%%=*}" "$a" "${code:-000}" "$(date +%s)" >> "$CHECK.new"', script)
        self.assertIn('mv -f "$CHECK.new" "$CHECK"', script)
        self.assertIn("CHECK=${KIWI_CHECK:-/var/lib/tor/kiwi-check}", script)
        self.assertIn('-x "socks5h://localhost/var/lib/tor/self-check.sock"', script)
        self.assertIn('if [ "$misses" -ge 3 ]; then', script)
        self.assertEqual(os.stat(start).st_mode & 0o077, 0)                   # it carries the services' keys
        # the check run for real (its part of the script, under set -eu as there): an address that
        # does not answer is written down and the check goes on; three rounds of it and Tor ends.
        # Until 0.79.1 the first curl that failed ended the check itself, quietly
        part = script[script.index("ADDRESSES="):script.index(") &") + 1]
        part = re.sub(r'^ADDRESSES=.*$', 'ADDRESSES="vault=live.onion cloud=dead.onion"', part, flags=re.M)
        base = tempfile.mkdtemp()
        for name, body in (("su-exec", 'shift; exec "$@"'),
                           ("curl", 'for a; do u=$a; done\ncase "$u" in *dead*) printf 000; exit 7 ;; esac\nprintf 200')):
            with open(os.path.join(base, name), "w") as f:
                f.write("#!/bin/sh\n" + body + "\n")
            os.chmod(os.path.join(base, name), 0o755)
        tor = subprocess.Popen(["sleep", "60"])
        self.addCleanup(tor.kill)
        r = subprocess.run(["sh", "-euc", "tor=%d\n%s\nwait" % (tor.pid, part)], capture_output=True, text=True, timeout=30,
                           env=dict(os.environ, PATH=base + ":" + os.environ["PATH"], KIWI_FIRST="0", KIWI_EVERY="0",
                                    KIWI_CHECK=os.path.join(base, "check")))
        self.assertIn("not found through Tor three times in a row: dead.onion; Tor starts anew", r.stdout, r.stderr)
        self.assertIsNotNone(tor.wait(timeout=5))                             # Tor was ended: the container starts anew
        with open(os.path.join(base, "check")) as f:
            self.assertEqual([l.split()[:3] for l in f.read().splitlines()],
                             [["vault", "live.onion", "200"], ["cloud", "dead.onion", "000"]])

    def test_the_proxy_answers_a_hidden_service_as_that_one_site(self):
        out, _compose = self.node("sh3-onion-nginx")
        with open(os.path.join(out, "kn-nginx", "nginx.conf")) as f:
            nginx = f.read()
        site = nginx.split("server_name %s;" % self.KEYS["vault"]["address"], 1)[1].split("\n    server {", 1)[0]
        before = nginx.split("server_name %s;" % self.KEYS["vault"]["address"], 1)[0].rsplit("server {", 1)[1]
        self.assertIn("listen 8043;", before)
        self.assertNotIn("ssl", before)
        self.assertIn("proxy_set_header Host vault.sh3.home;", site)          # its usual name, and https
        self.assertIn("proxy_set_header X-Forwarded-Proto https;", site)
        self.assertIn("proxy_redirect https://vault.sh3.home/ /;", site)
        self.assertNotIn("$remote_addr", site)                               # a stranger's circuit is nobody's address
        self.assertIn("listen 8043 default_server;", nginx)                  # another name on that port: nothing
        self.assertIn("server_names_hash_bucket_size 128;", nginx)           # or nginx does not start: the name is 62 long
        self.check_with_nginx(os.path.join(out, "kn-nginx", "nginx.conf"))
        self.assertNotIn("8043", yaml.safe_dump(_compose["services"]["kn-nginx"].get("ports", [])))   # not published
        plain = self.render("sh3-no-onion", json.loads(json.dumps(SH3)))
        with open(os.path.join(plain, "kn-nginx", "nginx.conf")) as f:
            self.assertNotIn("8043", f.read())


    def check_with_nginx(self, conf):
        """nginx itself reads the file, where podman and its image are here (not in CI): a
        hidden service's name once kept the proxy of a real machine from starting."""
        import shutil
        if not shutil.which("podman") or subprocess.run(["podman", "image", "exists", "docker.io/library/nginx:1-alpine"]).returncode:
            return
        with open(conf) as f:
            text = f.read()
        # nothing to proxy to and no certificates here: only the names and the syntax are asked
        import re
        text = re.sub(r"ssl_certificate(_key)?\s+[^;]+;", "", text)
        text = re.sub(r"listen 443 ssl( default_server)?;", lambda m: "listen 8443%s;" % (m.group(1) or ""), text).replace("http2 on;", "")
        tmp = conf + ".check"
        with open(tmp, "w") as f:
            f.write(text)
        r = subprocess.run(["podman", "run", "--rm", "--network", "none", "-v", "%s:/etc/nginx/nginx.conf:ro,z" % tmp,
                            "docker.io/library/nginx:1-alpine", "nginx", "-t"], capture_output=True, text=True)
        self.assertNotIn("server_names_hash", r.stderr)



class TestGit(unittest.TestCase):
    """Forgejo on a node: behind the reverse proxy, git over SSH on a port of its own,
    the admin made by the start script."""
    setUp, tearDown, render, write = TestRender.setUp, TestRender.tearDown, TestRender.render, TestRender.write

    def node(self, modules=("vpn-client", "reverse-proxy", "git"), **git):
        node = {"modules": list(modules), "reverse-proxy": dict(TLS)}
        if git:
            node["git"] = git
        return dict(SH3, node=node)

    def services(self, out):
        with open(os.path.join(out, "docker-compose.yml")) as f:
            return yaml.safe_load(f)["services"]

    def test_a_sign_in_never_takes_over_an_account_of_the_same_name(self):
        """Linked by name (ACCOUNT_LINKING=auto), a person called like an existing user of Forgejo
        became that user. Linking asks for the existing account's password now."""
        out = self.render("git-sso", self.node(accounts_client="git-sh3", accounts_secret="golden-oidc",
                                               accounts_issuer="https://id.example.org/oauth2/openid/git-sh3"))
        env = dict(e.split("=", 1) for e in self.services(out)["kn-git"]["environment"])
        self.assertEqual(env["FORGEJO__oauth2_client__ACCOUNT_LINKING"], "login")

    def test_forgejo_runs_behind_the_proxy_with_ssh_on_its_own_port(self):
        out = self.render("git1", self.node())
        svc = self.services(out)["kn-git"]
        self.assertEqual(svc["image"], "codeberg.org/forgejo/forgejo:15-rootless")
        self.assertEqual(svc["user"], "1000:1000")
        self.assertEqual((svc["entrypoint"], svc["command"]), (["/bin/sh"], ["/kiwi-start.sh"]))
        self.assertEqual(svc["volumes"], ["/home/user/docker/kn-git/start.sh:/kiwi-start.sh:ro,z",
                                          "/home/user/docker/kn-git/data:/var/lib/gitea:z"])
        env = dict(e.split("=", 1) for e in svc["environment"])
        for k, v in (("FORGEJO__server__ROOT_URL", "https://git.sh3.home/"), ("FORGEJO__server__DOMAIN", "git.sh3.home"),
                     ("FORGEJO__security__INSTALL_LOCK", "true"), ("FORGEJO__service__DISABLE_REGISTRATION", "true"),
                     ("FORGEJO__service__REQUIRE_SIGNIN_VIEW", "true"), ("FORGEJO__openid__ENABLE_OPENID_SIGNIN", "false"),
                     ("FORGEJO__server__OFFLINE_MODE", "true"), ("FORGEJO__mailer__ENABLED", "false"),
                     ("FORGEJO__database__DB_TYPE", "sqlite3"), ("FORGEJO__server__DISABLE_SSH", "false"),
                     ("FORGEJO__server__SSH_DOMAIN", "git.sh3.home"), ("FORGEJO__server__SSH_PORT", "2223"),
                     ("FORGEJO__server__SSH_LISTEN_PORT", "2222"), ("KIWI_ADMIN_USER", "kiwi"),
                     ("KIWI_ADMIN_EMAIL", "admin@sh3.home")):
            self.assertEqual(env.get(k), v, k)
        password = machine.derive_secret(SEED, "sh3.home", "git", "admin_password")
        self.assertEqual(env["KIWI_ADMIN_PASSWORD"], password)
        self.assertEqual(svc["ports"], ["2223:2222"])
        # the secrets are in the root-only env file, not in the unit
        unit = read(out, "quadlets/kn-git.container")
        self.assertIn("PublishPort=2223:2222", unit)
        self.assertNotIn(password, unit)
        self.assertIn("KIWI_ADMIN_PASSWORD=%s" % password, read(out, "kiwi/env/kn-git.env"))
        self.assertIn("FORGEJO__security__SECRET_KEY=", read(out, "kiwi/env/kn-git.env"))
        # the site: big pushes go through as they come
        conf = read(out, "kn-nginx/nginx.conf")
        site = conf.split("server_name git.sh3.home;", 1)[1].split("\n    server {", 1)[0]
        for line in ("client_max_body_size 0;", "proxy_request_buffering off;", "set $backend http://kn-git:3000;"):
            self.assertIn(line, site)
        # SSH from the LAN on the host's port, from the mesh through the VPN client
        self.assertIn("'2223/tcp'", read(out, "stack.sh"))
        self.assertIn("iptables -t nat -A PREROUTING -d 10.8.0.25 -p tcp --dport 2223 -j DNAT --to-destination "
                      "%s:2222" % svc["networks"]["knet-node"]["ipv4_address"], read(out, "kn-vpn-client/post-rules.txt"))

    def test_registration_and_a_public_view_can_be_switched_on(self):
        env = self.services(self.render("git2", self.node(registration=True, private=False, git_hostname="code.example.org")))["kn-git"]["environment"]
        for line in ("FORGEJO__service__DISABLE_REGISTRATION=false", "FORGEJO__service__REQUIRE_SIGNIN_VIEW=false",
                     "FORGEJO__server__ROOT_URL=https://code.example.org/"):
            self.assertIn(line, env)

    def test_ssh_port_0_publishes_nothing_and_switches_ssh_off(self):
        out = self.render("git3", self.node(ssh_port=0))
        svc = self.services(out)["kn-git"]
        self.assertNotIn("ports", svc)
        self.assertIn("FORGEJO__server__DISABLE_SSH=true", svc["environment"])
        self.assertIn("FORGEJO__server__START_SSH_SERVER=false", svc["environment"])
        self.assertFalse([e for e in svc["environment"] if e.startswith("FORGEJO__server__SSH_PORT=")])
        self.assertNotIn("PublishPort", read(out, "quadlets/kn-git.container"))
        self.assertIn("\nKS_STACK_PORTS=('80/tcp' '443/tcp')\n", read(out, "stack.sh"))
        rules = read(out, "kn-vpn-client/post-rules.txt")
        self.assertNotIn("2222", rules)
        self.assertNotIn("iptables \n", rules)

    def test_a_port_another_module_publishes_is_an_error(self):
        data = self.node(("vpn-client", "reverse-proxy", "sftp", "git"), ssh_port=2224)
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(cli.main(["render", self.write("git4", data), "-o", os.path.join(self.tmp, "git4.bundle")]), 1)
        self.assertIn("host port 2224/tcp is published by both", err.getvalue())
        # the defaults of the two do not collide
        self.render("git5", self.node(("vpn-client", "reverse-proxy", "sftp", "git")))

    def test_a_name_forgejo_keeps_for_itself_is_refused(self):
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(cli.main(["render", self.write("git6", self.node(admin_user="admin")),
                                       "-o", os.path.join(self.tmp, "git6.bundle")]), 1)
        self.assertIn("keeps the name admin", err.getvalue())

    def run_start(self, out, users, right_password):
        """start.sh with forgejo, curl, sleep and the image's entrypoint replaced by stubs that
        write down what they were given: (output, calls)."""
        stubs = os.path.join(self.tmp, "stubs")
        os.makedirs(stubs, exist_ok=True)
        calls = os.path.join(self.tmp, "calls")
        stub = {"forgejo": 'echo "forgejo $*" >> %s\nif [ "$3" = list ]; then printf "ID Username Email\\n%s"; fi\n'
                           % (calls, "".join("%d %s x@y\\n" % (i + 1, u) for i, u in enumerate(users))),
                # the API answers 200 only to the right password, which curl reads from its standard
                # input as a line of its configuration, with " and \\ escaped
                "curl": 'case "$*" in *healthz*) exit 0;; esac\ncat > %s.stdin\necho "curl $*" >> %s\n'
                        '[ "$(cat %s.stdin)" = "$(cat %s.right)" ]\n' % (calls, calls, calls, calls),     # (no cmp everywhere)
                "sleep": "exit 0\n"}
        with open(calls + ".right", "w") as f:
            f.write('user = "kiwi:%s"\n' % right_password.replace("\\", "\\\\").replace('"', '\\"'))
        for name, body in stub.items():
            with open(os.path.join(stubs, name), "w") as f:
                f.write("#!/bin/sh\n" + body)
            os.chmod(os.path.join(stubs, name), 0o755)
        with open(os.path.join(out, "kn-git", "start.sh")) as f:
            script = f.read()
        self.assertIn("\nexec /usr/bin/dumb-init -- /usr/local/bin/docker-entrypoint.sh\n", script)
        script = script.replace("\nexec /usr/bin/dumb-init -- /usr/local/bin/docker-entrypoint.sh\n", "\nwait\n")
        env = dict(os.environ, PATH=stubs + ":" + os.environ["PATH"], KIWI_ADMIN_USER="kiwi",
                   KIWI_ADMIN_EMAIL="admin@sh3.home", KIWI_ADMIN_PASSWORD='Pa"ss\\word-1')
        r = subprocess.run(["sh", "-c", script], env=env, capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(calls) as f:
            made = f.read()
        os.unlink(calls)
        return r.stdout + r.stderr, made

    def test_the_start_script_makes_the_admin_once_and_never_prints_the_password(self):
        out = self.render("git7", self.node())
        path = os.path.join(out, "kn-git", "start.sh")
        self.assertEqual(subprocess.run(["sh", "-n", path]).returncode, 0)
        self.assertNotIn(machine.derive_secret(SEED, "sh3.home", "git", "admin_password"), read(out, "kn-git/start.sh"))
        pw = 'Pa"ss\\word-1'
        # first start: no such user yet
        said, calls = self.run_start(out, [], pw)
        self.assertIn("made the admin user kiwi", said)
        self.assertIn('user create --admin --username kiwi --email admin@sh3.home --password %s --must-change-password=false' % pw, calls)
        self.assertNotIn(pw, said)
        # the next start: there, with the right password: nothing changes, nothing is said
        said, calls = self.run_start(out, ["kiwi"], pw)
        self.assertNotIn("create", calls)
        self.assertNotIn("change-password", calls)
        self.assertEqual(said.strip(), "")
        with open(os.path.join(self.tmp, "calls.stdin")) as f:
            self.assertEqual(f.read(), 'user = "kiwi:Pa\\"ss\\\\word-1"\n')    # escaped for curl's configuration
        self.assertNotIn(pw, calls.split("\n", 1)[1])                         # not on curl's command line
        # the settings say another password: it is set, and the container goes on
        said, calls = self.run_start(out, ["other", "kiwi"], "not this one")
        self.assertIn("user change-password --username kiwi --password %s --must-change-password=false" % pw, calls)
        self.assertIn("set the password of kiwi from the settings", said)
        self.assertNotIn(pw, said)
        # nothing in the script echoes the password
        for line in read(out, "kn-git/start.sh").splitlines():
            if "echo" in line or "say " in line:
                self.assertNotIn("$pw", line)


class TestOpenVPNFile(unittest.TestCase):
    setUp = TestRender.setUp
    render = TestRender.render
    write = TestRender.write
    tearDown = TestRender.tearDown

    def test_a_providers_openvpn_file_is_the_exit(self):
        """Riseup and other OpenVPN-only providers: their .ovpn (certificates inside) as the master's exit."""
        m = json.loads(json.dumps(MACHINES["hub1"]))
        with open(os.path.join(self.tmp, "riseup.ovpn"), "w") as f:
            f.write("client\ndev tun\nproto tcp\nremote 203.0.113.5 443\n<key>\nnot a real key\n</key>\n")
        m["master"]["vpn-client"] = {"vpn_provider": "custom", "vpn_type": "openvpn",
                                     "openvpn_config": os.path.join(self.tmp, "riseup.ovpn")}
        out = self.render("ovpn", m)
        with open(os.path.join(out, "docker-compose.yml")) as f:
            vc = yaml.safe_load(f)["services"]["km-vpn-client"]
        self.assertIn("OPENVPN_CUSTOM_CONFIG=/gluetun/custom.ovpn", vc["environment"])
        self.assertIn("VPN_TYPE=openvpn", vc["environment"])
        self.assertFalse([e for e in vc["environment"] if e.startswith(("WIREGUARD_PRIVATE_KEY", "WIREGUARD_ADDRESSES"))])
        self.assertTrue(any(v.endswith("/km-vpn-client/custom.ovpn:/gluetun/custom.ovpn:ro,z") for v in vc["volumes"]))
        with open(os.path.join(out, "km-vpn-client", "custom.ovpn")) as f:
            self.assertIn("remote 203.0.113.5 443", f.read())
        self.assertEqual(oct(os.stat(os.path.join(out, "km-vpn-client", "custom.ovpn")).st_mode & 0o777), "0o600")
        # custom OpenVPN without its file: said, not a container that never connects
        del m["master"]["vpn-client"]["openvpn_config"]
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertNotEqual(cli.main(["render", self.write("ovpn2", m), "-o", os.path.join(self.tmp, "x.bundle")]), 0)
        self.assertIn("needs openvpn_config", err.getvalue())


class TestMeshAddress(unittest.TestCase):
    def test_a_master_exiting_through_another_network_keeps_its_own_address(self):
        conf = {"vpn-client/wireguard_config": b"[Interface]\nAddress = 10.10.5.2/32\n"}

        class Host:
            def __init__(self, modules):
                self.modules, self.role_settings, self.warnings = modules, {}, []
        node, master = Host(["vpn-client"]), Host(["vpn-client", "vpn-server"])
        resolver._mesh_address_from_wireguard(node, conf, "node")
        resolver._mesh_address_from_wireguard(master, conf, "master")
        self.assertEqual(node.role_settings.get("vpn_ip"), "10.10.5.2")
        self.assertNotIn("vpn_ip", master.role_settings)     # its records keep server_ip, not the other network's


class TestHelp(unittest.TestCase):
    def test_every_setting_says_what_it_is_for(self):
        """The app shows a setting's help beside it: a setting without one is a field nobody can
        fill in with confidence."""
        from kiwimodules import modules
        missing = ["%s.%s" % (name, s.key) for name, m in modules.discover().modules.items()
                   for s in m.settings if len(s.help.strip()) < 12]
        self.assertEqual(missing, [], "settings without help in module.yaml")


class TestVersion(unittest.TestCase):
    def test_manifest_package_and_changelog_agree(self):
        with open(os.path.join(ROOT, "kiwi.manifest")) as f:
            manifest = next(line.split("=", 1)[1].strip() for line in f if line.startswith("VERSION="))
        with open(os.path.join(ROOT, "CHANGELOG.md")) as f:
            changelog = next(line.split()[1] for line in f if line.startswith("## "))
        self.assertEqual(VERSION, manifest)
        self.assertEqual(VERSION, changelog)


class TestRotateAttribute(unittest.TestCase):
    """Which generated secrets a new seed may replace by a restart alone."""
    def test_only_generated_secrets_take_it_and_only_restart(self):
        from kiwimodules.schema import Setting
        from kiwimodules.util import KiwiError
        s = Setting("t", {"key": "a_secret", "type": "secret", "generate": True, "rotate": "restart"})
        self.assertEqual((s.rotate, s.as_dict()["rotate"]), ("restart", "restart"))
        self.assertEqual(Setting("t", {"key": "a_secret", "type": "secret", "rotate": "restart"}).rotate, "")
        with self.assertRaisesRegex(KiwiError, "rotate"):
            Setting("t", {"key": "a_secret", "type": "secret", "generate": True, "rotate": "magic"})
        s = Setting("t", {"key": "a_secret", "type": "secret", "generate": True,
                          "rotate": {"in": "x-db", "run": "set-password $NEW"}})
        self.assertEqual((s.rotate, s.rotate_in, s.rotate_run), ("exec", "x-db", "set-password $NEW"))
        s = Setting("t", {"key": "a_secret", "type": "secret", "generate": True, "rotate": [
            {"name": "app", "run": "app set $NEW"}, {"in": "db", "run": "db set $NEW"}]})
        self.assertEqual(s.rotate_steps, [{"in": "", "name": "app", "run": "app set $NEW"},
                                          {"in": "db", "name": "", "run": "db set $NEW"}])
        for bad in ({"in": "x-db"}, {"in": "x-db", "run": "no value here"}, {"in": "x", "run": "$NEW", "more": 1},
                    {"in": "x", "name": "y", "run": "$NEW"}, [{"run": "$NEW"}], ["x"]):
            with self.assertRaisesRegex(KiwiError, "rotate needs"):
                Setting("t", {"key": "a_secret", "type": "secret", "generate": True, "rotate": bad})

    def test_the_marked_ones(self):
        from kiwimodules import modules as modmod
        ms = modmod.discover()
        marked = sorted("%s.%s" % (m.name, s.key) for m in ms.modules.values() for s in m.settings if s.rotate == "restart")
        changed_in_place = sorted("%s.%s" % (m.name, s.key) for m in ms.modules.values() for s in m.settings if s.rotate == "exec")
        self.assertEqual(changed_in_place, ["cloud.database_password", "immich.db_password", "paperless.db_password"])
        self.assertEqual(marked, [
            "ai.api_key", "backup.server_password", "cloud.imaginary_secret", "cloud.onlyoffice_secret", "cloud.redis_password", "cloud.talk_internal_secret",
            "cloud.whiteboard_secret", "dns.pihole_password", "downloader.transmission_password", "git.admin_password",
            "paperless.secret_key", "sftp.sftp_password", "vpn-server.wg_password", "xmpp.admin_password"])



class TestLogins(unittest.TestCase):
    """What a person signs in to: a module says it in `logins:`, a machine lists it with its own values."""
    setUp, tearDown, render, write = TestRender.setUp, TestRender.tearDown, TestRender.render, TestRender.write

    def logins(self, name, data):
        from kiwimodules import modules as modmod, profiles as profmod
        m = machine.load(self.write(name, data))
        profile = profmod.discover()[m.role]
        ms = modmod.discover()
        resolver.resolve_settings(profile, m, ms)
        spec = resolver.stack_spec(m, profile, m.dns_records, master_ip=m.master_ip, ca_cert=m.ca_cert,
                                   lan_addresses=m.lan_addresses)
        return modmod.Renderer(ms).logins(spec)

    @staticmethod
    def rows(logins):
        return [(x["module"], x["label"], x["address"], x["user"], x["password"]) for x in logins]

    def test_a_gateway_lists_its_pages_with_user_names_and_passwords(self):
        generated = machine.derive_secret(SEED, "m1.home", "portainer", "admin_password")
        self.assertEqual(self.rows(self.logins("m1", MACHINES["m1"])), [
            ("dns", "Ad blocker (Pi-hole)", "https://pihole.m1.home/admin", "", "golden-pihole-m1"),
            ("downloader", "Downloads (Transmission)", "https://dl.m1.home", "user", "golden-transmission"),
            # JDownloader without a login of its own takes Transmission's, as its container does
            ("downloader", "Downloads (JDownloader)", "https://jd.m1.home", "user", "golden-transmission"),
            ("portainer", "Containers (Portainer)", "https://portainer.m1.home", "admin", generated),
            ("sftp", "File transfer (SFTP)", "sftp://m1.home:2224", "user", "golden-sftp")])
        own = json.loads(json.dumps(MACHINES["m1"]))
        own["node"]["downloader"].update(transmission_user="anna", jd_web_user="ben", jd_web_password="golden-jd",
                                         jd_hostname="load.example.org")
        own["node"]["sftp"].update(sftp_user="carl", sftp_port=2022)
        rows = self.rows(self.logins("m1-own", own))
        self.assertIn(("downloader", "Downloads (Transmission)", "https://dl.m1.home", "anna", "golden-transmission"), rows)
        self.assertIn(("downloader", "Downloads (JDownloader)", "https://load.example.org", "ben", "golden-jd"), rows)
        self.assertIn(("sftp", "File transfer (SFTP)", "sftp://m1.home:2022", "carl", "golden-sftp"), rows)
        # what the compose file gives the containers is what the list says
        with open(os.path.join(self.render("m1-own", own), "docker-compose.yml")) as f:
            compose = f.read()
        for line in ("USER=anna", "PASS=golden-transmission", "WEB_AUTHENTICATION_USERNAME=ben",
                     "WEB_AUTHENTICATION_PASSWORD=golden-jd"):
            self.assertIn(line, compose)
        off = json.loads(json.dumps(MACHINES["m1"]))
        off["node"]["downloader"]["jdownloader"] = False
        self.assertNotIn("Downloads (JDownloader)", [r[1] for r in self.rows(self.logins("m1-off", off))])

    def test_a_cloud_node_and_a_master(self):
        logins = self.logins("sh3", SH3)
        self.assertEqual(self.rows(logins)[:2], [
            ("cloud", "Files (Nextcloud)", "https://cloud.sh3.home", "admin", "golden-nc-admin"),
            ("vault", "Passwords (Vaultwarden)", "https://vault.sh3.home", "", "")])       # everyone has an account of their own
        self.assertIn("own account", logins[1]["note"])
        self.assertEqual([r[1] for r in self.rows(logins)], ["Files (Nextcloud)", "Passwords (Vaultwarden)", "Containers (Portainer)"])
        self.assertEqual(self.rows(self.logins("gate", MACHINES["gate"])), [
            ("vpn-server", "VPN devices (wg-easy)", "https://wg.gate.home", "", "golden-wg-password"),
            ("dns", "Ad blocker (Pi-hole)", "https://pihole.gate.home/admin", "", "golden-pihole-master")])

    def test_vaultwardens_admin_page_says_what_to_type(self):
        def admin(token):
            data = json.loads(json.dumps(SH3))
            data["node"]["vault"] = {"admin_token": token}
            return [x for x in self.logins("sh3-" + str(len(token)), data) if x["label"] == "Vaultwarden admin page"]
        self.assertEqual(admin(""), [])                                  # no token: the page is off
        plain, = admin("golden-admin-token")
        self.assertEqual((plain["address"], plain["user"], plain["password"]),
                         ("https://vault.sh3.home/admin", "", "golden-admin-token"))
        hashed, = admin("$argon2id$v=19$m=65540,t=3,p=4$Z29sZGVu$Z29sZGVuLWhhc2g")
        self.assertEqual((hashed["address"], hashed["password"]), ("https://vault.sh3.home/admin", ""))   # a hash is not what is typed
        self.assertIn("hash", hashed["note"])

    def test_without_a_reverse_proxy_a_page_has_no_address(self):
        data = {"name": "bare1", "domain": "home", "role": "node", "seed": "secrets/seed",
                "node": {"modules": ["portainer"]}}
        row, = self.logins("bare1", data)
        self.assertEqual((row["label"], row["address"], row["user"]), ("Containers (Portainer)", "", "admin"))
        self.assertEqual(row["password"], machine.derive_secret(SEED, "bare1.home", "portainer", "admin_password"))

    def test_a_login_is_checked_when_the_module_is_read(self):
        from kiwimodules.schema import Login, Setting, load_logins
        from kiwimodules.util import KiwiError
        settings = [Setting("t", {"key": "admin_password", "type": "secret", "generate": True}),
                    Setting("t", {"key": "other_password", "type": "secret"}),
                    Setting("t", {"key": "admin_user", "default": "admin"}), Setting("t", {"key": "extra", "type": "bool"})]
        full = Login("t", {"label": "Files", "site": "cloud", "path": "/login", "user": "{{ admin_user }}",
                           "password": "admin_password", "note": "A note.", "when": "extra"}, settings, ["cloud"])
        self.assertEqual(full.as_dict(), {"label": "Files", "site": "cloud", "path": "/login", "address": "",
                                          "user": "{{ admin_user }}", "password": ["admin_password"], "note": "A note.",
                                          "when": "extra"})
        self.assertEqual(Login("t", {"label": "Files"}).as_dict()["password"], [])           # a note-only login
        self.assertEqual(Login("t", {"label": "Files", "password": ["other_password", "admin_password"]}, settings).password,
                         ["other_password", "admin_password"])
        self.assertEqual(Login("t", {"label": "Files", "address": "sftp://x:22", "when": "has_dns"}, settings).address, "sftp://x:22")
        self.assertEqual(Login("t", {"label": "Files", "when": "ready"}, settings, derived=["ready"]).when, "ready")
        self.assertEqual(load_logins("t", None), [])
        for bad, said in (({"user": "admin"}, "needs a label"),
                          ({"label": "Files", "pasword": "admin_password"}, "unknown key.*pasword"),
                          ({"label": "Files", "password": "no_such"}, "not a secret setting"),
                          ({"label": "Files", "password": "admin_user"}, "not a secret setting"),
                          ({"label": "Files", "password": {"key": "admin_password"}}, "key of a setting"),
                          ({"label": "Files", "site": "other"}, "site 'other' is not a site"),
                          ({"label": "Files", "site": "cloud", "address": "sftp://x"}, "in place of site and path"),
                          ({"label": "Files", "path": "admin"}, "path starts with a /"),
                          ({"label": "Files", "when": "nothing"}, "when names 'nothing'"),
                          ("Files", "is a mapping")):
            with self.assertRaisesRegex(KiwiError, said):
                Login("t", bad, settings, ["cloud"])
        with self.assertRaisesRegex(KiwiError, "is a list"):
            load_logins("t", {"label": "Files"}, settings)

    def test_the_modules_that_have_one_and_every_password_is_a_setting(self):
        from kiwimodules import modules as modmod
        ms = modmod.discover()
        self.assertEqual(sorted(m.name for m in ms.modules.values() if m.logins),
                         ["accounts", "ai", "btcpay", "cloud", "control", "dns", "downloader", "git", "immich", "opencloud", "paperless", "portainer",
                          "sftp", "vault", "vpn-server", "xmpp"])
        for mod in ms.modules.values():
            secrets = {s.key for s in mod.settings if s.type == "secret"}
            names = {s.key for s in mod.settings} | set(mod.derived)
            sites = [str(e.get("site") or "") for e in [mod.nginx or {}] + list((mod.nginx or {}).get("servers") or [])]
            published = mod.as_dict()["logins"]
            self.assertEqual(published, [x.as_dict() for x in mod.logins])
            for login in published:
                where = "%s: %s" % (mod.name, login["label"])
                for key in login["password"]:
                    self.assertIn(key, secrets, where)
                if login["site"]:
                    self.assertIn(login["site"], sites, where)
                if login["when"]:
                    self.assertIn(login["when"], names, where)
                self.assertTrue(login["password"] or login["note"], "%s: neither a password nor a word about it" % where)
                for text in (login["label"], login["note"]):
                    self.assertNotRegex(text.lower(), r"\b(hub|dashboard|cluster|credentials?)\b", where)


class TestWriteThroughLinks(unittest.TestCase):
    def test_a_link_is_written_where_it_points(self):
        import tempfile
        from kiwimodules import util
        with tempfile.TemporaryDirectory() as tmp:
            ram, disk = os.path.join(tmp, "ram"), os.path.join(tmp, "disk")
            os.makedirs(ram)
            os.makedirs(disk)
            util.write_text(os.path.join(ram, "fleet.yaml"), "old\n", 0o600)
            os.symlink(os.path.join(ram, "fleet.yaml"), os.path.join(disk, "fleet.yaml"))
            util.write_text(os.path.join(disk, "fleet.yaml"), "new\n", 0o600)
            self.assertTrue(os.path.islink(os.path.join(disk, "fleet.yaml")))
            self.assertEqual(os.listdir(disk), ["fleet.yaml"])           # no copy, no .tmp beside the link
            self.assertEqual(util.read_text(os.path.join(ram, "fleet.yaml")), "new\n")


if __name__ == "__main__":
    unittest.main()


class TestLanGroups(unittest.TestCase):
    setUp, tearDown, render, write = TestRender.setUp, TestRender.tearDown, TestRender.render, TestRender.write

    def test_the_gateway_keeps_a_group_of_the_home_network_to_what_it_was_given(self):
        m = json.loads(json.dumps(MACHINES["m1"]))
        m["node"]["gateway"] = dict(m["node"].get("gateway") or {}, lan_groups=[
            "192.168.20.0/24 to 10.8.0.25 tcp:443,tcp:80", "192.168.20.0/24 drop", "192.168.30.0/24 all", "bogus"])
        out = self.render("m1-langw", m)
        path = os.path.join(out, "kiwi", "gw.sh")
        if not os.path.isfile(path):
            path = next(os.path.join(d, f) for d, _s, fs in os.walk(out) for f in fs if f == "gw.sh")
        self.assertEqual(subprocess.run(["bash", "-n", path]).returncode, 0)
        with open(path) as f:
            gw = f.read()
        self.assertIn("iptables -A KIWI_GW_LAN -s 192.168.20.0/24 -d 10.8.0.25 -p tcp --dport 443 -j RETURN", gw)
        self.assertIn("iptables -A KIWI_GW_LAN -s 192.168.20.0/24 -j DROP", gw)
        self.assertIn("iptables -A KIWI_GW_LAN -s 192.168.30.0/24 -j RETURN", gw)
        self.assertIn("# lan group rule bogus: not understood, left out", gw)
        self.assertLess(gw.index('-d "$VPN_SUBNET" -j ACCEPT'), gw.index('-d "$VPN_SUBNET" -j KIWI_GW_LAN'))   # inserted later: checked first
        self.assertNotIn("KIWI_GW_LAN -s", self._gw_without_groups())

    def _gw_without_groups(self):
        out = self.render("m1-nolangw", json.loads(json.dumps(MACHINES["m1"])))
        path = next(os.path.join(d, f) for d, _s, fs in os.walk(out) for f in fs if f == "gw.sh")
        with open(path) as f:
            return f.read()

    def test_a_nodes_rules_for_the_groups_of_the_home_network_reach_kiwi_stack(self):
        m = json.loads(json.dumps(SH3))
        m["node"]["lan_rules"] = ["192.168.20.0/24 tcp:443,tcp:80", "192.168.30.0/24 none"]
        out = self.render("sh3-lan", m)
        with open(os.path.join(out, "stack.sh")) as f:
            stack = f.read()
        self.assertIn("KS_STACK_LAN_RULES=('192.168.20.0/24 tcp:443,tcp:80' '192.168.30.0/24 none')", stack)
        out = self.render("sh3-nolan", json.loads(json.dumps(SH3)))
        with open(os.path.join(out, "stack.sh")) as f:
            self.assertIn("KS_STACK_LAN_RULES=()", f.read())

    def test_a_module_answers_at_one_address_only(self):
        """listen (every module that publishes ports): its ports bound to one address, a VLAN's say."""
        m = json.loads(json.dumps(SH3))
        m["node"]["reverse-proxy"] = dict(m["node"]["reverse-proxy"], listen="192.168.20.5")
        out = self.render("sh3-listen", m)
        with open(os.path.join(out, "docker-compose.yml")) as f:
            compose = yaml.safe_load(f)
        nginx = next(b for n, b in compose["services"].items() if n.endswith("-nginx"))
        self.assertTrue(nginx["ports"] and all(str(p).startswith("192.168.20.5:") for p in nginx["ports"]))
        others = [p for n, b in compose["services"].items() if not n.endswith("-nginx") for p in (b or {}).get("ports") or []]
        self.assertFalse(any(str(p).startswith("192.168.20.5:") for p in others))     # its own setting only
        doc = {"services": {"x": {"network_mode": "host"}}}
        with self.assertRaises(KiwiError):
            modules.Renderer.bind_ports("dhcp-relay", "192.168.20.5", doc)
        doc = {"services": {"x": {"ports": ["127.0.0.1:8080:80", {"target": 80, "published": 8081}]}}}
        modules.Renderer.bind_ports("x", "192.168.20.5", doc)
        self.assertEqual(doc["services"]["x"]["ports"], ["127.0.0.1:8080:80", {"target": 80, "published": 8081, "host_ip": "192.168.20.5"}])

    def test_a_machines_vlans_reach_kiwi_stack(self):
        m = json.loads(json.dumps(SH3))
        m["node"]["vlans"] = ["20 192.168.20.5/24 eth0", "30 192.168.30.5/24"]
        out = self.render("sh3-vlan", m)
        with open(os.path.join(out, "stack.sh")) as f:
            self.assertIn("KS_STACK_VLANS=('20 192.168.20.5/24 eth0' '30 192.168.30.5/24')", f.read())

class TestFedDns(unittest.TestCase):
    """The link's DNS for a partner seen under another domain or mesh (vpn-server/fed-dns.py.j2)."""

    @classmethod
    def setUpClass(cls):
        import importlib.util
        import jinja2
        path = os.path.join(os.path.dirname(__file__), "..", "modules", "vpn-server", "fed-dns.py.j2")
        code = jinja2.Environment().from_string(open(path).read()).render()
        spec = importlib.util.spec_from_loader("feddns", loader=None)
        cls.m = importlib.util.module_from_spec(spec)
        exec(compile(code, path, "exec"), cls.m.__dict__)

    def query(self, name, qtype=1):
        import struct
        return struct.pack("!6H", 0x1234, 0x0100, 1, 0, 0, 0) + self.m.write_name([x.encode() for x in name.split(".")]) + \
            struct.pack("!2H", qtype, 1)

    def answer_for(self, q, records):
        """The partner's answer, with name compression as real servers send it."""
        import struct
        head = struct.pack("!6H", 0x1234, 0x8180, 1, len(records), 0, 0)
        body = q[12:]
        out = head + body
        for rtype, rdata in records:
            out += b"\xc0\x0c" + struct.pack("!2HIH", rtype, 1, 60, len(rdata)) + rdata
        return out

    def test_names_and_addresses_go_through_under_the_alias(self):
        import socket
        link = self.m.Link({"alias": "kiwi2.home", "real": "home", "upstream": "10.209.0.1",
                            "mesh": "10.9.0.0/16", "seen_as": "10.209.0.0/16"})
        asked = []

        def ask(upstream, data):
            asked.append((upstream, data))
            q = self.m.parse(data)
            self.assertEqual(b".".join(q["qs"][0][0]), b"cloud.papaya.home")          # the real name, to the partner
            return self.answer_for(data, [(5, b"\x06papaya\xc0\x19"), (1, socket.inet_aton("10.9.0.5"))])
        out = self.m.parse(self.m.handle([link], self.query("cloud.papaya.kiwi2.home"), ask))
        self.assertEqual(asked[0][0], "10.209.0.1")
        self.assertEqual(out["id"], 0x1234)
        self.assertEqual(b".".join(out["qs"][0][0]), b"cloud.papaya.kiwi2.home")
        cname, a = out["rrs"]
        self.assertEqual(b".".join(cname[5][1]), b"papaya.kiwi2.home")                 # a name inside: moved too
        self.assertEqual(socket.inet_ntoa(a[5][1]), "10.209.0.5")                       # the address: into the alias mesh

    def test_a_name_that_is_no_partners_is_refused_and_a_silent_partner_fails(self):
        link = self.m.Link({"alias": "kiwi2.home", "real": "home", "upstream": "10.209.0.1", "mesh": "10.9.0.0/16",
                            "seen_as": "10.209.0.0/16"})
        out = self.m.parse(self.m.handle([link], self.query("papaya.home"), lambda u, d: self.fail("asked")))
        self.assertEqual((out["flags"] & 0xF, out["rrs"]), (5, []))                    # REFUSED: not this link's
        out = self.m.parse(self.m.handle([link], self.query("papaya.kiwi2.home"), lambda u, d: (_ for _ in ()).throw(OSError())))
        self.assertEqual(out["flags"] & 0xF, 2)                                         # SERVFAIL
        self.assertIsNone(self.m.handle([link], b"\x00\x01", lambda u, d: b""))        # not a message: no answer

    def test_only_the_name_when_the_meshes_differ(self):
        import socket
        link = self.m.Link({"alias": "kiwi2.home", "real": "home", "upstream": "10.10.0.1", "mesh": "10.10.0.0/16"})
        out = self.m.parse(self.m.handle([link], self.query("papaya.kiwi2.home"),
                                         lambda u, d: self.answer_for(d, [(1, socket.inet_aton("10.10.0.5")), (16, b"\x03a,b")])))
        self.assertEqual(socket.inet_ntoa(out["rrs"][0][5][1]), "10.10.0.5")            # its own address, as it is
        self.assertEqual(out["rrs"][1][5][1], b"\x03a,b")                               # a TXT record untouched
