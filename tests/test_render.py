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
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "lib"))

import yaml  # noqa: E402

from kiwimodules import VERSION, cli, machine, quadlet  # noqa: E402

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
        # a hub with nothing to name as its relay, and public mounts without public relays, are refused
        master = MACHINES["hub1"]["master"]
        norelay = {k: v for k, v in master.items() if k != "nostr-relay"}
        norelay["modules"] = [m for m in master["modules"] if m != "nostr-relay"]
        self.assertNotEqual(cli.main(["render", self.write("hub1-norelay", dict(MACHINES["hub1"], master=norelay)),
                                      "-o", os.path.join(self.tmp, "norelay.bundle")]), 0)
        # and so is a space's relays line without the space's id
        odd = dict(MACHINES["hub1"], master=dict(master, hub={"space_relays": ["wss://relay.hub1.home"]}))
        self.assertNotEqual(cli.main(["render", self.write("hub1-oddspace", odd), "-o", os.path.join(self.tmp, "oddspace.bundle")]), 0)

    def public_hub(self, **proxy):
        master = dict(MACHINES["hub1"]["master"], **{"reverse-proxy": dict(TLS, public=True, **proxy)})
        master["hub"] = dict(master["hub"], hub_domain="hub.example.org")
        master["nostr-relay"] = dict(master["nostr-relay"], relay_domain="relay.example.org")
        return dict(MACHINES["hub1"], master=master)

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
        self.assertIn("Restart=on-failure", read(out, "host-units/kn-backup.service"))

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
        self.assertIn("/usr/local/bin/kiwi-stack start", script)

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

    def test_secret_derivation_is_frozen(self):
        # kiwi-server derives the same values: a change here rotates every generated secret
        self.assertEqual(machine.derive_secret(SEED, "sh3.home", "cloud", "redis_password"),
                         "ErXoT6obmcMFnpKb3N73gQp1R0fAUOzt")
        self.assertEqual(machine.seed_id(SEED), "956141ccd4bc")

    def test_lists(self):
        self.assertEqual(cli.main(["modules", "-v"]), 0)
        self.assertEqual(cli.main(["profiles"]), 0)


class TestVersion(unittest.TestCase):
    def test_manifest_package_and_changelog_agree(self):
        with open(os.path.join(ROOT, "kiwi.manifest")) as f:
            manifest = next(line.split("=", 1)[1].strip() for line in f if line.startswith("VERSION="))
        with open(os.path.join(ROOT, "CHANGELOG.md")) as f:
            changelog = next(line.split()[1] for line in f if line.startswith("## "))
        self.assertEqual(VERSION, manifest)
        self.assertEqual(VERSION, changelog)


if __name__ == "__main__":
    unittest.main()
