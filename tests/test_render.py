"""kiwi-modules renders a bundle from a one-machine file. The golden sh3
under tests/golden/sh3 is kiwi-server's: the same machine, rendered from a
fleet there and from a machine file here, must give the same bytes (the
secrets derive from the same seed). Run: python3 -m unittest discover -s tests
"""
import difflib
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

from kiwimodules import VERSION, cli, machine  # noqa: E402

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
        self.assertNotIn("acme-staging", acme)
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
