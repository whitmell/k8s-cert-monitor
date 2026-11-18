"""Generates the cert-inventory Grafana dashboards (Grafana 10+).

  python dashboards/generate.py

writes certificate-inventory.json and certificate-detail.json next to this
file. Edit this script rather than the JSON so PromQL quoting stays correct.
"""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
DS = {"type": "prometheus", "uid": "${datasource}"}
INVENTORY_UID = "certinv-inventory"
DETAIL_UID = "certinv-detail"

DAYS_LEFT_THRESHOLDS = {"mode": "absolute", "steps": [
    {"color": "dark-red", "value": None},
    {"color": "red", "value": 0},
    {"color": "orange", "value": 14},
    {"color": "yellow", "value": 30},
    {"color": "green", "value": 90},
]}


def target(expr, ref="A", fmt="table", legend=None):
    t = {"refId": ref, "datasource": DS, "expr": expr, "instant": True, "range": False, "format": fmt}
    if legend:
        t["legendFormat"] = legend
    return t


def datasource_var():
    return {"name": "datasource", "label": "Data source", "type": "datasource", "query": "prometheus",
            "current": {}, "hide": 0, "refresh": 1, "regex": ""}


def query_var(name, label, query, multi=False, hide=0):
    v = {"name": name, "label": label, "type": "query", "datasource": DS,
         "query": {"query": query, "refId": name, "qryType": 1},
         "definition": query, "current": {}, "refresh": 2, "sort": 1, "hide": hide,
         "multi": multi, "includeAll": multi, "regex": ""}
    if multi:
        v["allValue"] = ".+"
    return v


def stat(pid, title, expr, grid, steps, description="", unit="none", decimals=0, color_mode="background"):
    return {
        "id": pid, "type": "stat", "title": title, "description": description, "datasource": DS,
        "gridPos": grid, "targets": [target(expr, fmt="time_series")],
        "options": {"colorMode": color_mode, "graphMode": "none", "justifyMode": "center",
                    "textMode": "value", "wideLayout": True,
                    "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False}},
        "fieldConfig": {"defaults": {"unit": unit, "decimals": decimals, "color": {"mode": "thresholds"},
                                     "thresholds": {"mode": "absolute", "steps": steps},
                                     "noValue": "-"},
                        "overrides": []},
    }


def by_name(name, props):
    return {"matcher": {"id": "byName", "options": name},
            "properties": [{"id": k, "value": v} for k, v in props]}


def organize(fields):
    """filter + order + rename table columns; fields is an ordered {source: display}."""
    return [
        {"id": "filterFieldsByName", "options": {"include": {"names": list(fields)}}},
        {"id": "organize", "options": {"excludeByName": {},
                                       "indexByName": {n: i for i, n in enumerate(fields)},
                                       "renameByName": fields}},
    ]


def table_defaults():
    return {"custom": {"align": "auto", "filterable": True, "inspect": False,
                       "cellOptions": {"type": "auto", "wrapText": False}},
            "color": {"mode": "thresholds"},
            "thresholds": {"mode": "absolute", "steps": [{"color": "green", "value": None}]}}


def alert_steps(color):
    return [{"color": "green", "value": None}, {"color": color, "value": 1}]


def dashboard(uid, title, description, variables, panels, links):
    return {
        "uid": uid, "title": title, "description": description,
        "tags": ["certificates", "x509", "tls", "cert-inventory"],
        "editable": True, "graphTooltip": 0, "refresh": "5m",
        "time": {"from": "now-6h", "to": "now"}, "timezone": "browser",
        "schemaVersion": 39, "version": 1, "links": links,
        "annotations": {"list": []},
        "templating": {"list": variables},
        "panels": panels,
    }


# --------------------------------------------------------------------------
# Certificate inventory
# --------------------------------------------------------------------------

def inventory():
    sel = '{cert_namespace=~"$namespace"}'
    na = "certinv_cert_not_after_seconds" + sel

    def within(days):
        return "count(%s - time() < %d * 86400) or vector(0)" % (na, days)

    panels = [
        stat(1, "Certificates", "count(%s) or vector(0)" % na, {"h": 4, "w": 4, "x": 0, "y": 0},
             [{"color": "blue", "value": None}], "All certificates in the selected namespaces."),
        stat(2, "Expired", "count(%s - time() < 0) or vector(0)" % na, {"h": 4, "w": 4, "x": 4, "y": 0},
             alert_steps("dark-red"), "Certificates whose notAfter date has passed."),
        stat(3, "Expiring < 14 days", within(14), {"h": 4, "w": 4, "x": 8, "y": 0},
             alert_steps("red"), "Includes expired certificates."),
        stat(4, "Expiring < 30 days", within(30), {"h": 4, "w": 4, "x": 12, "y": 0},
             alert_steps("orange"), "Includes expired certificates."),
        stat(5, "Expiring < 90 days", within(90), {"h": 4, "w": 4, "x": 16, "y": 0},
             alert_steps("yellow"), "Includes expired certificates."),
        stat(6, "Targets failing", "count(certinv_target_up%s == 0) or vector(0)" % sel,
             {"h": 4, "w": 4, "x": 20, "y": 0}, alert_steps("red"),
             "Entries in targets.txt that could not be read. Their certificates are missing from "
             "this dashboard. See the 'Monitored targets' table at the bottom."),
    ]

    fields = {
        "cert_namespace": "Namespace",
        "cert_resource": "Resource",
        "cert_key": "Key",
        "subject_CN": "Subject CN",
        "issuer_CN": "Issuer CN",
        "sans": "SANs",
        "serial_number": "Serial",
        "Value #A": "Expires",
        "Value #B": "Days left",
    }
    detail_link = (
        "/d/%s/certificate-detail?${datasource:queryparam}"
        "&var-namespace=${__data.fields[\"Namespace\"]}"
        "&var-resource=${__data.fields[\"Resource\"]}"
        "&var-key=${__data.fields[\"Key\"]}"
        "&var-serial=${__data.fields[\"Serial\"]}" % DETAIL_UID)
    panels.append({
        "id": 7, "type": "table", "title": "Certificates",
        "description": "Every certificate in the selected namespaces, soonest expiry first. "
                       "Click a Subject CN to open the full certificate details.",
        "datasource": DS, "gridPos": {"h": 20, "w": 24, "x": 0, "y": 4},
        "targets": [target(na + " * 1000", "A"), target("(%s - time()) / 86400" % na, "B")],
        "transformations": [{"id": "merge", "options": {}}] + organize(fields),
        "options": {"showHeader": True, "cellHeight": "sm",
                    "footer": {"show": False, "reducer": ["sum"], "fields": ""},
                    "sortBy": [{"displayName": "Days left", "desc": False}]},
        "fieldConfig": {"defaults": table_defaults(), "overrides": [
            by_name("Subject CN", [("links", [{"title": "Show certificate details",
                                               "url": detail_link}])]),
            by_name("Resource", [("custom.width", 220)]),
            by_name("Key", [("custom.width", 90)]),
            by_name("Issuer CN", [("custom.width", 200)]),
            by_name("Serial", [("custom.width", 330)]),
            by_name("Expires", [("unit", "dateTimeAsIso"), ("custom.width", 170)]),
            by_name("Days left", [("unit", "none"), ("decimals", 0), ("custom.width", 95),
                                  ("custom.cellOptions", {"type": "color-background", "mode": "basic"}),
                                  ("thresholds", DAYS_LEFT_THRESHOLDS)]),
        ]},
    })

    target_fields = {"cert_namespace": "Namespace", "cert_resource": "Resource", "cert_key": "Key",
                     "Value": "Status", "reason": "Reason"}
    panels.append({
        "id": 8, "type": "table", "title": "Monitored targets",
        "description": "Each line of targets.txt and whether cert-inventory could read it. "
                       "'forbidden' means the Helm-generated RBAC is missing or outdated; 'not_found' means "
                       "the Secret/ConfigMap does not exist; 'key_not_found' means the key name is wrong.",
        "datasource": DS, "gridPos": {"h": 12, "w": 24, "x": 0, "y": 24},
        "targets": [target("certinv_target_up" + sel)],
        "transformations": organize(target_fields),
        "options": {"showHeader": True, "cellHeight": "sm",
                    "footer": {"show": False, "reducer": ["sum"], "fields": ""},
                    "sortBy": [{"displayName": "Status", "desc": False}]},
        "fieldConfig": {"defaults": table_defaults(), "overrides": [
            by_name("Status", [
                ("mappings", [{"type": "value", "options": {
                    "1": {"text": "OK", "color": "green", "index": 0},
                    "0": {"text": "FAILING", "color": "red", "index": 1}}}]),
                ("custom.cellOptions", {"type": "color-text"}),
                ("custom.width", 110)]),
        ]},
    })

    variables = [
        datasource_var(),
        query_var("namespace", "Namespace",
                  "label_values(certinv_cert_not_after_seconds, cert_namespace)", multi=True),
    ]
    links = [{"type": "link", "title": "Certificate detail", "icon": "doc",
              "url": "/d/%s/certificate-detail" % DETAIL_UID, "includeVars": False,
              "keepTime": False, "targetBlank": False, "tooltip": "", "asDropdown": False, "tags": []}]
    return dashboard(INVENTORY_UID, "Certificate Inventory",
                     "All monitored certificates, per namespace, from cert-inventory.",
                     variables, panels, links)


# --------------------------------------------------------------------------
# Certificate detail
# --------------------------------------------------------------------------

def detail():
    sel = ('{cert_namespace="$namespace",cert_resource="$resource",'
           'cert_key="$key",serial_number="$serial"}')
    key_sel = '{cert_namespace="$namespace",cert_resource="$resource",cert_key="$key"}'
    green = [{"color": "text", "value": None}]

    panels = [
        stat(1, "Days left", "(certinv_cert_not_after_seconds%s - time()) / 86400" % sel,
             {"h": 4, "w": 6, "x": 0, "y": 0}, DAYS_LEFT_THRESHOLDS["steps"]),
        stat(2, "Valid until", "certinv_cert_not_after_seconds%s * 1000" % sel,
             {"h": 4, "w": 6, "x": 6, "y": 0}, green, unit="dateTimeAsIso", color_mode="none"),
        stat(3, "Valid from", "certinv_cert_not_before_seconds%s * 1000" % sel,
             {"h": 4, "w": 6, "x": 12, "y": 0}, green, unit="dateTimeAsIso", color_mode="none"),
        # max() drops labels so the two series (different label sets) can be subtracted.
        stat(4, "Validity period (days)",
             "(max(certinv_cert_not_after_seconds%s) - max(certinv_cert_not_before_seconds%s)) / 86400"
             % (sel, sel), {"h": 4, "w": 6, "x": 18, "y": 0}, green, color_mode="none"),
    ]

    friendly = dict([
        ("subject", "Subject"),
        ("issuer", "Issuer"),
        ("sans", "Subject alternative names"),
        ("serial_number", "Serial number (hex)"),
        ("sha256_fingerprint", "SHA-256 fingerprint"),
        ("not_before", "Valid from (UTC)"),
        ("not_after", "Valid until (UTC)"),
        ("cert_namespace", "Namespace"),
        ("cert_resource", "Stored in"),
        ("cert_key", "Key"),
    ])
    panels.append({
        "id": 5, "type": "table", "title": "Certificate",
        "datasource": DS, "gridPos": {"h": 12, "w": 15, "x": 0, "y": 4},
        "targets": [target("certinv_cert_info" + sel, fmt="time_series")],
        "transformations": [
            {"id": "labelsToFields", "options": {"mode": "rows", "keepLabels": list(friendly)}},
            {"id": "organize", "options": {"excludeByName": {}, "indexByName": {},
                                           "renameByName": {"label": "Field", "value": "Value"}}},
        ],
        "options": {"showHeader": False, "cellHeight": "sm",
                    "footer": {"show": False, "reducer": ["sum"], "fields": ""}},
        "fieldConfig": {"defaults": table_defaults(), "overrides": [
            by_name("Field", [("custom.width", 210),
                              ("mappings", [{"type": "value", "options": {
                                  k: {"text": v, "index": i}
                                  for i, (k, v) in enumerate(friendly.items())}}])]),
            by_name("Value", [("custom.inspect", True)]),
        ]},
    })
    panels.append({
        "id": 6, "type": "table", "title": "Subject alternative names",
        "datasource": DS, "gridPos": {"h": 12, "w": 9, "x": 15, "y": 4},
        "targets": [target("certinv_cert_san_info" + sel)],
        "transformations": organize({"san": "Name"}),
        "options": {"showHeader": True, "cellHeight": "sm",
                    "footer": {"show": False, "reducer": ["sum"], "fields": ""},
                    "sortBy": [{"displayName": "Name", "desc": False}]},
        "fieldConfig": {"defaults": dict(table_defaults(), noValue="No SANs"), "overrides": []},
    })
    chain_link = ("/d/%s/certificate-detail?${datasource:queryparam}&${namespace:queryparam}"
                  "&${resource:queryparam}&${key:queryparam}&var-serial=${__value.raw}" % DETAIL_UID)
    panels.append({
        "id": 7, "type": "table", "title": "All certificates in this key",
        "description": "A key holding a bundle (leaf + intermediates/CA) lists each certificate. "
                       "Click a serial to view that certificate.",
        "datasource": DS, "gridPos": {"h": 7, "w": 24, "x": 0, "y": 16},
        "targets": [target("certinv_cert_info" + key_sel)],
        "transformations": organize({"subject": "Subject", "issuer": "Issuer",
                                     "serial_number": "Serial", "not_after": "Valid until (UTC)"}),
        "options": {"showHeader": True, "cellHeight": "sm",
                    "footer": {"show": False, "reducer": ["sum"], "fields": ""}},
        "fieldConfig": {"defaults": table_defaults(), "overrides": [
            by_name("Serial", [("links", [{"title": "View this certificate", "url": chain_link}])]),
        ]},
    })

    variables = [
        datasource_var(),
        query_var("namespace", "Namespace", "label_values(certinv_cert_info, cert_namespace)"),
        query_var("resource", "Resource",
                  'label_values(certinv_cert_info{cert_namespace="$namespace"}, cert_resource)'),
        query_var("key", "Key",
                  'label_values(certinv_cert_info{cert_namespace="$namespace",'
                  'cert_resource="$resource"}, cert_key)'),
        query_var("serial", "Serial",
                  'label_values(certinv_cert_info{cert_namespace="$namespace",'
                  'cert_resource="$resource",cert_key="$key"}, serial_number)'),
    ]
    links = [{"type": "link", "title": "Certificate inventory", "icon": "arrow-left",
              "url": "/d/%s/certificate-inventory" % INVENTORY_UID, "includeVars": False,
              "keepTime": False, "targetBlank": False, "tooltip": "", "asDropdown": False, "tags": []}]
    return dashboard(DETAIL_UID, "Certificate Detail",
                     "Decoded details of one certificate monitored by cert-inventory.",
                     variables, panels, links)


if __name__ == "__main__":
    for name, build in (("certificate-inventory.json", inventory), ("certificate-detail.json", detail)):
        path = os.path.join(HERE, name)
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            json.dump(build(), f, indent=2)
            f.write("\n")
        print("wrote", path)
