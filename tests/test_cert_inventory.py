"""Tests for deploy/cert_inventory.py against a mock Kubernetes API.

Run from the repo root:  python -m unittest discover -s tests -v
Fixtures are public test certificates only (no private keys).
"""

import base64
import importlib.util
import json
import os
import re
import tempfile
import threading
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
FIX = os.path.join(HERE, "fixtures")
SCRIPT = os.path.join(HERE, "..", "deploy", "cert_inventory.py")

spec = importlib.util.spec_from_file_location("cert_inventory", SCRIPT)
ci = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ci)


def fixture(name):
    with open(os.path.join(FIX, name), "rb") as f:
        return f.read()


def b64(data):
    return base64.b64encode(data).decode("ascii")


PRIVATE_KEY_PEM = b"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg\n-----END PRIVATE KEY-----\n"

OBJECTS = {
    "/api/v1/namespaces/app/secrets/api-tls": {
        "data": {"tls.crt": b64(fixture("bundle.pem")), "tls.key": b64(PRIVATE_KEY_PEM),
                 "ca.crt": b64(fixture("ca.pem"))}},
    "/api/v1/namespaces/app/secrets/old-tls": {"data": {"tls.crt": b64(fixture("expired.pem"))}},
    "/api/v1/namespaces/app/secrets/der-secret": {"data": {"ca.der": b64(fixture("ca.der"))}},
    "/api/v1/namespaces/app/secrets/junk": {"data": {"tls.crt": b64(b"not a certificate")}},
    "/api/v1/namespaces/infra/configmaps/trust-bundle": {
        "data": {"ca.crt": fixture("ca.pem").decode("ascii"), "readme": "hello"}},
}
FORBIDDEN = {"/api/v1/namespaces/locked/secrets/nope"}


class MockAPI(BaseHTTPRequestHandler):
    seen_auth = []

    def do_GET(self):  # noqa: N802
        MockAPI.seen_auth.append(self.headers.get("Authorization"))
        if self.path in FORBIDDEN:
            self.send_response(403)
            self.end_headers()
            return
        obj = OBJECTS.get(self.path)
        if obj is None:
            self.send_response(404)
            self.end_headers()
            return
        body = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


TARGETS = """
# namespace  kind       name          key
app          secret     api-tls       tls.crt
app          secret     api-tls       *          # wildcard: tls.crt + ca.crt, ignores tls.key
app          secret     old-tls       tls.crt
app          Secret     der-secret    ca.der
app          secret     junk          tls.crt
app          secret     missing       tls.crt
app          secret     api-tls       nokey
locked       secret     nope          tls.crt
infra        configmap  trust-bundle  ca.crt
"""


def parse_metrics(text):
    """Return list of (name, {labels}, value) from Prometheus text format."""
    out = []
    line_re = re.compile(r'^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{(.*)\})? (\S+)$')
    label_re = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"')
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        m = line_re.match(line)
        assert m, "bad metric line: %r" % line
        lbls = {k: v for k, v in label_re.findall(m.group(3) or "")}
        out.append((m.group(1), lbls, float(m.group(4))))
    return out


class CertInventoryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), MockAPI)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.tmp = tempfile.mkdtemp()
        cls.targets_path = os.path.join(cls.tmp, "targets.txt")
        with open(cls.targets_path, "w") as f:
            f.write(TARGETS)
        token = os.path.join(cls.tmp, "token")
        with open(token, "w") as f:
            f.write("test-token\n")
        ci.API_URL = "http://127.0.0.1:%d" % cls.server.server_address[1]
        ci.TOKEN_FILE = token
        ci.TARGETS_FILE = cls.targets_path
        cls.metrics_text = ci.run_scan()
        cls.metrics = parse_metrics(cls.metrics_text)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def series(self, name, **match):
        return [(l, v) for n, l, v in self.metrics
                if n == name and all(l.get(k) == want for k, want in match.items())]

    def test_bundle_yields_leaf_and_ca(self):
        rows = self.series("certinv_cert_not_after_seconds", cert_resource="Secret/api-tls", cert_key="tls.crt")
        self.assertEqual(sorted(l["subject_CN"] for l, _ in rows), ["Example Test Root CA", "api.example.test"])

    def test_leaf_fields(self):
        (lbls, _), = self.series("certinv_cert_info", cert_key="tls.crt", cert_name="api-tls",
                                 subject="O=Example Corp, OU=Platform, CN=api.example.test")
        self.assertEqual(lbls["sans"], "DNS:api.example.test, DNS:*.api.example.test, IP:10.0.0.5")
        self.assertEqual(lbls["issuer"], "C=US, O=Example Corp, CN=Example Test Root CA")
        self.assertRegex(lbls["sha256_fingerprint"], r"^[0-9A-F]{64}$")
        self.assertRegex(lbls["not_after"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        sans = sorted(l["san"] for l, _ in self.series("certinv_cert_san_info", cert_key="tls.crt",
                                                       serial_number=lbls["serial_number"]))
        self.assertEqual(sans, ["DNS:*.api.example.test", "DNS:api.example.test", "IP:10.0.0.5"])

    def test_wildcard_reads_cert_keys_and_skips_private_key(self):
        keys = {l["cert_key"] for l, _ in self.series("certinv_cert_info", cert_name="api-tls")}
        self.assertEqual(keys, {"tls.crt", "ca.crt"})
        self.assertNotIn("PRIVATE KEY", self.metrics_text)

    def test_wildcard_target_duplicates_are_not_double_counted(self):
        rows = self.series("certinv_cert_not_after_seconds", cert_name="api-tls", cert_key="tls.crt")
        self.assertEqual(len(rows), 2)

    def test_expired_cert_dates(self):
        (lbls, value), = self.series("certinv_cert_not_after_seconds", cert_name="old-tls")
        self.assertEqual(value, 1609459200.0)  # 2021-01-01T00:00:00Z
        (nb, value), = self.series("certinv_cert_not_before_seconds", cert_name="old-tls")
        self.assertEqual(value, 1577836800.0)  # 2020-01-01T00:00:00Z

    def test_der_and_configmap(self):
        self.assertEqual(len(self.series("certinv_cert_info", cert_name="der-secret")), 1)
        (lbls, _), = self.series("certinv_cert_info", cert_resource="ConfigMap/trust-bundle")
        self.assertEqual(lbls["cert_namespace"], "infra")

    def test_target_status_reasons(self):
        reasons = {(l["cert_name"], l["cert_key"]): (l["reason"], v)
                   for l, v in self.series("certinv_target_up")}
        self.assertEqual(reasons[("api-tls", "tls.crt")], ("", 1.0))
        self.assertEqual(reasons[("api-tls", "*")], ("", 1.0))
        self.assertEqual(reasons[("junk", "tls.crt")], ("no_certificates", 0.0))
        self.assertEqual(reasons[("missing", "tls.crt")], ("not_found", 0.0))
        self.assertEqual(reasons[("api-tls", "nokey")], ("key_not_found", 0.0))
        self.assertEqual(reasons[("nope", "tls.crt")], ("forbidden", 0.0))
        self.assertEqual(len(reasons), 9)

    def test_bearer_token_sent(self):
        self.assertIn("Bearer test-token", MockAPI.seen_auth)

    def test_object_fetched_once_per_scan(self):
        # api-tls appears in three target lines but should be fetched once
        count_before = len(MockAPI.seen_auth)
        ci.run_scan()
        self.assertEqual(len(MockAPI.seen_auth) - count_before, 7)  # 7 distinct objects

    def test_bad_targets_file_is_reported(self):
        bad = os.path.join(self.tmp, "bad.txt")
        with open(bad, "w") as f:
            f.write("app secret only-three-fields\n")
        old = ci.TARGETS_FILE
        ci.TARGETS_FILE = bad
        try:
            metrics = parse_metrics(ci.run_scan())
        finally:
            ci.TARGETS_FILE = old
        (_, lbls, v), = [m for m in metrics if m[0] == "certinv_targets_file_ok"]
        self.assertEqual(v, 0.0)
        self.assertIn("expected 'namespace kind name key'", lbls["error"])

    def test_http_endpoints(self):
        ci.State.metrics, ci.State.last_scan = self.metrics_text, __import__("time").time()
        srv = ThreadingHTTPServer(("127.0.0.1", 0), ci.Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        base = "http://127.0.0.1:%d" % srv.server_address[1]
        try:
            with urllib.request.urlopen(base + "/metrics") as r:
                self.assertIn("text/plain; version=0.0.4", r.headers["Content-Type"])
                self.assertEqual(r.read().decode(), self.metrics_text)
            with urllib.request.urlopen(base + "/healthz") as r:
                self.assertEqual(r.status, 200)
        finally:
            srv.shutdown()

    def test_rbac_lists_exact_names(self):
        rbac = ci.render_rbac(ci.load_targets(self.targets_path), "cert-inventory")
        self.assertIn('resourceNames: ["api-tls", "old-tls", "der-secret", "junk", "missing"]', rbac)
        self.assertIn('namespace: "infra"', rbac)
        self.assertIn('resources: ["configmaps"]', rbac)
        self.assertEqual(rbac.count("\nkind: Role\n"), 3)
        self.assertEqual(rbac.count("\nkind: RoleBinding\n"), 3)
        verbs = set(re.findall(r'verbs: \[(.*)\]', rbac))
        self.assertEqual(verbs, {'"get"'})  # never list/watch


if __name__ == "__main__":
    unittest.main()
