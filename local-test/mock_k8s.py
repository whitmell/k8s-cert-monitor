"""Minimal mock of the Kubernetes API for local testing of cert-inventory.

Serves GET /api/v1/namespaces/<ns>/{secrets,configmaps}/<name> from the test
certificates in ./certs. Requires the bearer token "local-test" (to exercise
auth) and returns 403 for objects under namespace "locked".
"""
import base64
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CERTS = os.environ.get("CERT_DIR", "/certs")
FAKE_KEY = b"-----BEGIN PRIVATE KEY-----\nTUlTU0lORy1OT1QtQS1SRUFMLUtFWQ==\n-----END PRIVATE KEY-----\n"


def read(name):
    with open(os.path.join(CERTS, name), "rb") as f:
        return f.read()


def secret(**keys):
    return {"kind": "Secret", "type": "kubernetes.io/tls",
            "data": {k: base64.b64encode(v).decode() for k, v in keys.items()}}


def configmap(**keys):
    return {"kind": "ConfigMap", "data": {k: v.decode() for k, v in keys.items()}}


OBJECTS = {
    ("payments", "secrets", "payments-tls"): secret(**{"tls.crt": read("payments.pem"), "tls.key": FAKE_KEY,
                                                       "ca.crt": read("root-ca.pem")}),
    ("edge", "secrets", "gateway-tls"): secret(**{"tls.crt": read("gateway-bundle.pem"), "tls.key": FAKE_KEY}),
    ("web", "secrets", "portal-tls"): secret(**{"tls.crt": read("portal.pem"), "tls.key": FAKE_KEY}),
    ("web", "secrets", "legacy-tls"): secret(**{"tls.crt": read("legacy.pem"), "tls.key": FAKE_KEY}),
    ("reports", "secrets", "reporting-tls"): secret(**{"tls.crt": read("reporting.pem"), "tls.key": FAKE_KEY}),
    ("reports", "secrets", "truststore"): secret(**{"root.der": read("root-ca.der")}),
    ("kube-system", "configmaps", "kube-root-ca.crt"): configmap(**{"ca.crt": read("root-ca.pem")}),
}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        if self.headers.get("Authorization") != "Bearer local-test":
            return self.reply(401, {"reason": "Unauthorized"})
        parts = self.path.strip("/").split("/")
        if len(parts) != 6 or parts[:3] != ["api", "v1", "namespaces"]:
            return self.reply(404, {"reason": "NotFound"})
        ns, resource, name = parts[3], parts[4], parts[5]
        if ns == "locked":
            return self.reply(403, {"reason": "Forbidden"})
        obj = OBJECTS.get((ns, resource, name))
        return self.reply(200, obj) if obj else self.reply(404, {"reason": "NotFound"})

    def reply(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(data)


if __name__ == "__main__":
    ThreadingHTTPServer(("", 8080), Handler).serve_forever()
