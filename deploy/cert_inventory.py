#!/usr/bin/env python3
"""cert-inventory: a Prometheus exporter for X.509 certificates stored in a
fixed list of Kubernetes Secrets and ConfigMaps.

Uses only the Python standard library (3.9+), so it runs on any approved
Python base image without installing packages.

Modes:
  cert_inventory.py                     run the exporter (in-cluster)
  cert_inventory.py --once              scan once, print metrics, exit
  cert_inventory.py --print-rbac FILE   print Roles/RoleBindings for a targets file

Environment variables (all optional):
  CERTINV_TARGETS                 targets file             (/config/targets.txt)
  CERTINV_PORT                    HTTP listen port         (9793)
  CERTINV_SCAN_INTERVAL_SECONDS   seconds between scans    (300)
  CERTINV_API_URL                 Kubernetes API base URL  (in-cluster service)
  CERTINV_TOKEN_FILE / CERTINV_CA_FILE   service account token / CA bundle
"""

import base64
import binascii
import hashlib
import json
import logging
import os
import re
import ssl
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from collections import OrderedDict, namedtuple
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SA_DIR = "/var/run/secrets/kubernetes.io/serviceaccount"
TARGETS_FILE = os.environ.get("CERTINV_TARGETS", "/config/targets.txt")
PORT = int(os.environ.get("CERTINV_PORT", "9793"))
SCAN_INTERVAL = int(os.environ.get("CERTINV_SCAN_INTERVAL_SECONDS", "300"))
TOKEN_FILE = os.environ.get("CERTINV_TOKEN_FILE", SA_DIR + "/token")
CA_FILE = os.environ.get("CERTINV_CA_FILE", SA_DIR + "/ca.crt")


def default_api_url():
    host = os.environ.get("KUBERNETES_SERVICE_HOST")
    port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
    if not host:
        return ""
    if ":" in host:  # IPv6 literal
        host = "[" + host + "]"
    return "https://%s:%s" % (host, port)


API_URL = os.environ.get("CERTINV_API_URL") or default_api_url()

log = logging.getLogger("cert-inventory")

KINDS = {"secret": ("Secret", "secrets"), "configmap": ("ConfigMap", "configmaps")}
PEM_RE = re.compile(rb"-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+?-----END CERTIFICATE-----")
DN_SHORT = {
    "commonName": "CN",
    "organizationName": "O",
    "organizationalUnitName": "OU",
    "countryName": "C",
    "stateOrProvinceName": "ST",
    "localityName": "L",
    "domainComponent": "DC",
    "emailAddress": "emailAddress",
}
SAN_SHORT = {"IP Address": "IP", "Registered ID": "RID"}

Target = namedtuple("Target", "namespace kind name key")


class TargetError(Exception):
    """A target could not be read. `reason` becomes a metric label value."""

    def __init__(self, reason, detail=""):
        Exception.__init__(self, "%s: %s" % (reason, detail) if detail else reason)
        self.reason = reason


# --------------------------------------------------------------------------
# Targets file
# --------------------------------------------------------------------------

def load_targets(path):
    """Parse `namespace kind name key` lines. `#` starts a comment.
    key may be `*` to read every key that holds a PEM certificate."""
    targets = []
    with open(path, encoding="utf-8") as f:
        for lineno, raw in enumerate(f, 1):
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) != 4:
                raise ValueError("%s:%d: expected 'namespace kind name key', got %r"
                                 % (path, lineno, line))
            ns, kind, name, key = parts
            kind = kind.lower()
            if kind not in KINDS:
                raise ValueError("%s:%d: kind must be 'secret' or 'configmap', got %r"
                                 % (path, lineno, parts[1]))
            target = Target(ns, kind, name, key)
            if target not in targets:
                targets.append(target)
    return targets


# --------------------------------------------------------------------------
# Kubernetes API (read-only GETs of named objects)
# --------------------------------------------------------------------------

def api_get(path):
    if not API_URL:
        raise TargetError("api_unavailable", "KUBERNETES_SERVICE_HOST not set and CERTINV_API_URL empty")
    req = urllib.request.Request(API_URL + path, headers={"Accept": "application/json"})
    if os.path.exists(TOKEN_FILE):  # re-read every call: projected tokens rotate
        with open(TOKEN_FILE, encoding="utf-8") as f:
            req.add_header("Authorization", "Bearer " + f.read().strip())
    context = None
    if API_URL.startswith("https://"):
        context = ssl.create_default_context(cafile=CA_FILE if os.path.exists(CA_FILE) else None)
    try:
        with urllib.request.urlopen(req, timeout=15, context=context) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        reason = {401: "unauthorized", 403: "forbidden", 404: "not_found"}.get(e.code, "api_error")
        raise TargetError(reason, "HTTP %d for %s" % (e.code, path))
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise TargetError("api_error", "%s: %s" % (path, e))


def fetch_object(namespace, kind):
    def fetch(name):
        return api_get("/api/v1/namespaces/%s/%s/%s" % (namespace, KINDS[kind][1], name))
    return fetch


def object_data(obj, kind):
    """Return {key: bytes} for a Secret or ConfigMap object."""
    data = OrderedDict()
    try:
        if kind == "secret":
            for k, v in sorted((obj.get("data") or {}).items()):
                data[k] = base64.b64decode(v)
        else:
            for k, v in sorted((obj.get("data") or {}).items()):
                data[k] = v.encode("utf-8")
            for k, v in sorted((obj.get("binaryData") or {}).items()):
                data[k] = base64.b64decode(v)
    except (binascii.Error, ValueError) as e:
        raise TargetError("decode_error", str(e))
    return data


# --------------------------------------------------------------------------
# Certificate decoding (stdlib only)
# --------------------------------------------------------------------------

def decode_pem_cert(pem_text):
    """Decode one PEM certificate into the dict format of SSLSocket.getpeercert().

    The stdlib has no public API for decoding a certificate file. This uses
    ssl._ssl._test_decode_cert, which CPython has shipped since 2.7/3.2 and
    still ships in 3.14. It needs a file path, so the PEM (public data) is
    written to a short-lived temp file.
    """
    fd, path = tempfile.mkstemp(suffix=".pem")
    try:
        with os.fdopen(fd, "w", encoding="ascii") as f:
            f.write(pem_text)
        return ssl._ssl._test_decode_cert(path)  # pylint: disable=protected-access
    finally:
        os.unlink(path)


def format_dn(rdns):
    parts = []
    for rdn in rdns:
        for attr, value in rdn:
            parts.append("%s=%s" % (DN_SHORT.get(attr, attr), value))
    return ", ".join(parts)


def dn_attr(rdns, attr):
    values = [value for rdn in rdns for a, value in rdn if a == attr]
    return ", ".join(values)


def iso(ts):
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_certificates(blob, allow_der):
    """Return decoded certificate dicts found in blob (PEM, PEM bundle, or DER)."""
    pems = [m.decode("ascii") for m in PEM_RE.findall(blob)]
    if not pems and allow_der and blob[:1] == b"\x30":  # DER SEQUENCE
        pems = [ssl.DER_cert_to_PEM_cert(blob)]
    certs = []
    for pem in pems:
        try:
            der = ssl.PEM_cert_to_DER_cert(pem)
            info = decode_pem_cert(pem)
        except (ssl.SSLError, ValueError, binascii.Error) as e:
            raise TargetError("parse_error", str(e))
        not_before = ssl.cert_time_to_seconds(info["notBefore"])
        not_after = ssl.cert_time_to_seconds(info["notAfter"])
        subject = info.get("subject", ())
        issuer = info.get("issuer", ())
        sans = ["%s:%s" % (SAN_SHORT.get(t, t), v) for t, v in info.get("subjectAltName", ())]
        certs.append({
            "serial_number": info.get("serialNumber", ""),
            "subject": format_dn(subject),
            "subject_CN": dn_attr(subject, "commonName"),
            "subject_O": dn_attr(subject, "organizationName"),
            "issuer": format_dn(issuer),
            "issuer_CN": dn_attr(issuer, "commonName"),
            "sans": sans,
            "sha256_fingerprint": hashlib.sha256(der).hexdigest().upper(),
            "not_before": not_before,
            "not_after": not_after,
        })
    return certs


# --------------------------------------------------------------------------
# Scanning
# --------------------------------------------------------------------------

def scan(targets, fetcher=fetch_object):
    """Read every target. Returns (certs, statuses).

    certs:    list of dicts, one per certificate found
    statuses: list of (target, reason, cert_count); reason is "" when OK
    """
    objects = {}
    certs, statuses, seen = [], [], set()
    for t in targets:
        found = 0
        try:
            obj_key = (t.namespace, t.kind, t.name)
            if obj_key not in objects:
                try:
                    objects[obj_key] = fetcher(t.namespace, t.kind)(t.name)
                except TargetError as e:
                    objects[obj_key] = e
            obj = objects[obj_key]
            if isinstance(obj, TargetError):
                raise obj
            data = object_data(obj, t.kind)
            if t.key == "*":
                items = list(data.items())
            elif t.key in data:
                items = [(t.key, data[t.key])]
            else:
                raise TargetError("key_not_found", "%s/%s has no key %r" % (t.namespace, t.name, t.key))
            for key, blob in items:
                try:
                    parsed = parse_certificates(blob, allow_der=(t.key != "*"))
                except TargetError:
                    if t.key == "*":
                        log.warning("skipping unparseable key %s in %s/%s", key, t.namespace, t.name)
                        continue
                    raise
                for cert in parsed:
                    ident = (t.namespace, t.kind, t.name, key, cert["serial_number"], cert["sha256_fingerprint"])
                    found += 1
                    if ident in seen:
                        continue
                    seen.add(ident)
                    cert.update({
                        "cert_namespace": t.namespace,
                        "cert_kind": KINDS[t.kind][0],
                        "cert_name": t.name,
                        "cert_resource": "%s/%s" % (KINDS[t.kind][0], t.name),
                        "cert_key": key,
                    })
                    certs.append(cert)
            if found == 0:
                raise TargetError("no_certificates", "%s/%s key %s" % (t.namespace, t.name, t.key))
            statuses.append((t, "", found))
        except TargetError as e:
            log.warning("target %s %s/%s key=%s: %s", t.kind, t.namespace, t.name, t.key, e)
            statuses.append((t, e.reason, found))
        except Exception:  # never let one bad target stop the scan
            log.exception("target %s %s/%s key=%s: unexpected error", t.kind, t.namespace, t.name, t.key)
            statuses.append((t, "internal_error", found))
    return certs, statuses


# --------------------------------------------------------------------------
# Prometheus text format
# --------------------------------------------------------------------------

def esc(value):
    return str(value).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def labels(pairs):
    if not pairs:
        return ""
    return "{" + ",".join('%s="%s"' % (k, esc(v)) for k, v in pairs) + "}"


def render_metrics(certs, statuses, scan_started, scan_duration, targets_error=""):
    out = []

    def family(name, help_text, samples):
        out.append("# HELP %s %s" % (name, help_text))
        out.append("# TYPE %s gauge" % name)
        for lbls, value in samples:
            out.append("%s%s %s" % (name, labels(lbls), repr(float(value))))

    def ident(c):
        return [("cert_namespace", c["cert_namespace"]), ("cert_kind", c["cert_kind"]),
                ("cert_name", c["cert_name"]), ("cert_resource", c["cert_resource"]),
                ("cert_key", c["cert_key"]), ("serial_number", c["serial_number"])]

    family("certinv_cert_not_after_seconds",
           "Certificate notAfter as a Unix timestamp.",
           [(ident(c) + [("subject_CN", c["subject_CN"]), ("subject_O", c["subject_O"]),
                         ("issuer_CN", c["issuer_CN"]), ("sans", ", ".join(c["sans"]))],
             c["not_after"]) for c in certs])
    family("certinv_cert_not_before_seconds",
           "Certificate notBefore as a Unix timestamp.",
           [(ident(c), c["not_before"]) for c in certs])
    family("certinv_cert_info",
           "Decoded certificate details, value is always 1.",
           [(ident(c) + [("subject", c["subject"]), ("issuer", c["issuer"]),
                         ("sans", ", ".join(c["sans"])),
                         ("sha256_fingerprint", c["sha256_fingerprint"]),
                         ("not_before", iso(c["not_before"])), ("not_after", iso(c["not_after"]))], 1)
            for c in certs])
    family("certinv_cert_san_info",
           "One series per subject alternative name, value is always 1.",
           [(ident(c) + [("san", san)], 1) for c in certs for san in c["sans"]])

    def target_labels(t):
        return [("cert_namespace", t.namespace), ("cert_kind", KINDS[t.kind][0]),
                ("cert_name", t.name), ("cert_resource", "%s/%s" % (KINDS[t.kind][0], t.name)),
                ("cert_key", t.key)]

    family("certinv_target_up",
           "1 if the target was read and contained at least one certificate.",
           [(target_labels(t) + [("reason", reason)], 0 if reason else 1) for t, reason, _ in statuses])
    family("certinv_target_certificates",
           "Number of certificates found in the target.",
           [(target_labels(t), n) for t, _, n in statuses])
    family("certinv_targets_file_ok",
           "1 if the targets file was parsed successfully on the last scan.",
           [([("error", targets_error)], 0 if targets_error else 1)])
    family("certinv_last_scan_timestamp_seconds",
           "Unix time the last scan finished.", [([], scan_started + scan_duration)])
    family("certinv_scan_duration_seconds",
           "Duration of the last scan.", [([], scan_duration)])
    return "\n".join(out) + "\n"


def run_scan():
    started = time.time()
    targets_error = ""
    try:
        targets = load_targets(TARGETS_FILE)
    except (OSError, ValueError) as e:
        log.error("cannot load targets: %s", e)
        targets, targets_error = [], str(e).splitlines()[0][:200]
    certs, statuses = scan(targets)
    duration = time.time() - started
    failed = sum(1 for _, reason, _ in statuses if reason)
    log.info("scan done: %d targets (%d failing), %d certificates, %.2fs",
             len(statuses), failed, len(certs), duration)
    return render_metrics(certs, statuses, started, duration, targets_error)


# --------------------------------------------------------------------------
# HTTP server
# --------------------------------------------------------------------------

class State(object):
    lock = threading.Lock()
    metrics = ""
    last_scan = 0.0


class Handler(BaseHTTPRequestHandler):
    server_version = "cert-inventory"

    def _send(self, code, body, ctype="text/plain; charset=utf-8"):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):  # noqa: N802 (stdlib naming)
        path = self.path.split("?", 1)[0]
        with State.lock:
            metrics, last_scan = State.metrics, State.last_scan
        if path == "/metrics":
            if not metrics:
                self._send(503, "first scan not finished\n")
            else:
                self._send(200, metrics, "text/plain; version=0.0.4; charset=utf-8")
        elif path == "/healthz":
            # Healthy once a scan has completed and scans are not stuck.
            if last_scan and time.time() - last_scan < 3 * SCAN_INTERVAL + 60:
                self._send(200, "ok\n")
            else:
                self._send(503, "no recent scan\n")
        elif path == "/":
            self._send(200, '<html><body><a href="/metrics">metrics</a></body></html>\n',
                       "text/html; charset=utf-8")
        else:
            self._send(404, "not found\n")

    def log_message(self, fmt, *args):  # keep scrape requests out of the logs
        pass


def scan_loop():
    while True:
        try:
            metrics = run_scan()
            with State.lock:
                State.metrics, State.last_scan = metrics, time.time()
        except Exception:
            log.exception("scan failed")
        time.sleep(SCAN_INTERVAL)


# --------------------------------------------------------------------------
# RBAC generation
# --------------------------------------------------------------------------

def render_rbac(targets, sa_namespace, sa_name="cert-inventory"):
    by_ns = OrderedDict()
    for t in targets:
        by_ns.setdefault(t.namespace, OrderedDict()).setdefault(KINDS[t.kind][1], [])
        names = by_ns[t.namespace][KINDS[t.kind][1]]
        if t.name not in names:
            names.append(t.name)
    q = json.dumps  # JSON strings are valid YAML scalars
    docs = []
    for ns, resources in by_ns.items():
        rules = []
        for resource, names in resources.items():
            rules.append("  - apiGroups: [\"\"]\n    resources: [%s]\n    verbs: [\"get\"]\n"
                         "    resourceNames: [%s]" % (q(resource), ", ".join(q(n) for n in names)))
        docs.append(
            "apiVersion: rbac.authorization.k8s.io/v1\nkind: Role\nmetadata:\n"
            "  name: cert-inventory-reader\n  namespace: %s\n"
            "  labels:\n    app.kubernetes.io/name: cert-inventory\nrules:\n%s"
            % (q(ns), "\n".join(rules)))
        docs.append(
            "apiVersion: rbac.authorization.k8s.io/v1\nkind: RoleBinding\nmetadata:\n"
            "  name: cert-inventory-reader\n  namespace: %s\n"
            "  labels:\n    app.kubernetes.io/name: cert-inventory\n"
            "roleRef:\n  apiGroup: rbac.authorization.k8s.io\n  kind: Role\n  name: cert-inventory-reader\n"
            "subjects:\n  - kind: ServiceAccount\n    name: %s\n    namespace: %s"
            % (q(ns), q(sa_name), q(sa_namespace)))
    header = ("# GENERATED by: python cert_inventory.py --print-rbac targets.txt\n"
              "# Read-only access to exactly the objects listed in targets.txt.\n")
    return header + "---\n" + "\n---\n".join(docs) + "\n"


def main(argv):
    logging.basicConfig(level=logging.INFO, stream=sys.stderr,
                        format="%(asctime)s %(levelname)s %(message)s")
    if len(argv) >= 2 and argv[1] == "--print-rbac":
        path = argv[2] if len(argv) > 2 else TARGETS_FILE
        sa_ns = argv[3] if len(argv) > 3 else "cert-inventory"
        sys.stdout.write(render_rbac(load_targets(path), sa_ns))
        return 0
    if len(argv) >= 2 and argv[1] == "--once":
        sys.stdout.write(run_scan())
        return 0
    if len(argv) > 1:
        sys.stderr.write(__doc__)
        return 2
    log.info("starting: targets=%s port=%d interval=%ds api=%s",
             TARGETS_FILE, PORT, SCAN_INTERVAL, API_URL or "(none)")
    threading.Thread(target=scan_loop, name="scanner", daemon=True).start()
    server = ThreadingHTTPServer(("", PORT), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
