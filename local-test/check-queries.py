"""Runs every dashboard panel and variable query against the local Prometheus
with variables substituted, and every alert expression, and reports results.

  python check-queries.py [http://127.0.0.1:9090]
"""
import json
import os
import re
import sys
import urllib.parse
import urllib.request

PROM = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:9090"
HERE = os.path.dirname(os.path.abspath(__file__))
failures = 0


def api(path, **params):
    url = PROM + path + "?" + urllib.parse.urlencode(params, doseq=True)
    try:
        with urllib.request.urlopen(url, timeout=10) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        return json.load(e)


def query(expr):
    return api("/api/v1/query", query=expr)


def check(label, expr, expect_rows=True):
    global failures
    res = query(expr)
    if res.get("status") != "success":
        failures += 1
        print("FAIL  %-45s %s\n      %s" % (label, res.get("error"), expr))
        return []
    rows = res["data"]["result"]
    ok = bool(rows) or not expect_rows
    if not ok:
        failures += 1
    print("%s  %-45s %d result(s)" % ("ok  " if ok else "EMPTY", label, len(rows)))
    return rows


def subst(expr, values):
    for name, value in sorted(values.items(), key=lambda kv: -len(kv[0])):
        expr = expr.replace("$" + name, value)
    return expr


def check_dashboard(filename, values):
    d = json.load(open(os.path.join(HERE, "..", "dashboards", filename), encoding="utf-8"))
    print("\n== %s  %s" % (d["title"], values))
    for v in d["templating"]["list"]:
        if v["type"] != "query":
            continue
        m = re.match(r"label_values\((.*),\s*(\w+)\)$", v["definition"])
        selector, label = subst(m.group(1), values), m.group(2)
        res = api("/api/v1/label/%s/values" % label, **{"match[]": selector})
        vals = res.get("data", [])
        global failures
        if res.get("status") != "success" or not vals:
            failures += 1
        print("%s  var %-41s %s" % ("ok  " if vals else "FAIL", v["name"], vals[:6]))
    for p in d["panels"]:
        for t in p.get("targets", []):
            check("panel %d %s [%s]" % (p["id"], p["title"], t["refId"]), subst(t["expr"], values))


# Pick a real certificate for the detail dashboard: the leaf in the gateway bundle.
rows = check("pick detail cert", 'certinv_cert_info{cert_resource="Secret/gateway-tls",cert_key="tls.crt"}')
leaf = next(r["metric"] for r in rows if "gateway.apps.test" in r["metric"]["subject"])

check_dashboard("certificate-inventory.json", {"namespace": ".+"})
check_dashboard("certificate-inventory.json", {"namespace": "(web|edge)"})
check_dashboard("certificate-detail.json", {
    "namespace": leaf["cert_namespace"], "resource": leaf["cert_resource"],
    "key": leaf["cert_key"], "serial": leaf["serial_number"]})

print("\n== Alert rules")
rules = api("/api/v1/rules")["data"]["groups"]
for g in rules:
    for r in g["rules"]:
        bad = r.get("health") != "ok"
        failures += bad
        print("%s  %-45s health=%s state=%s firing/pending=%d" % (
            "FAIL" if bad else "ok  ", r["name"], r.get("health"), r.get("state"), len(r.get("alerts", []))))

print("\n%d problem(s)" % failures)
sys.exit(1 if failures else 0)
