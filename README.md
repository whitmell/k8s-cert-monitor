# cert-inventory

Monitors X.509 certificates stored in a fixed list of Kubernetes Secrets and
ConfigMaps, and shows every one of them in Grafana with its full details:
subject, issuer, SANs, serial, fingerprint, and validity dates. Certificates
appear whatever their expiry date.

It needs **no new container images**. The exporter is a single Python script
that uses only the standard library. It runs on the approved
`base-images-docker/python-ubi-min` image, mounted from a ConfigMap.

```
targets.txt ──► cert_inventory.py ──/metrics──► Prometheus ──► Grafana
 (ConfigMap)     (python-ubi-min)    ServiceMonitor  + alert rules   Inventory + Detail dashboards
                  │
                  └─ GET only the listed Secrets/ConfigMaps (Role with resourceNames)
```

## Layout

| Path | What |
|---|---|
| `deploy/Chart.yaml` and `deploy/templates/` | Helm chart for the exporter |
| `deploy/values.yaml` | Image, targets, service, and monitoring defaults |
| `deploy/cert_inventory.py` | The exporter (Python 3.9+, stdlib only) |
| `deploy/dashboards/` | Grafana dashboards (Inventory and Detail), generated; installed by the chart |
| `dashboards/generate.py` | Generates the dashboard JSON. Edit this, not the JSON |
| `tests/` | Unit tests against a mock Kubernetes API |

## Setup

### Install with Helm

The chart is in `deploy/`. By default it monitors the Kubernetes-published
cluster CA certificate. Install it with:

```bash
helm upgrade --install cert-inventory deploy \
  --namespace cert-inventory --create-namespace
```

Set `image.repository` and `image.tag` to your approved Python image as needed.
To change the monitored objects, pass a values file containing a `targets`
list; each entry has `namespace`, `kind` (`secret` or `configmap`), `name`, and
`key` (use `*` to scan all certificate-bearing keys). The chart generates
read-only, resource-name-scoped Roles and RoleBindings for those targets, so
RBAC stays in sync with the list. For example:

```yaml
targets:
  - namespace: my-app
    kind: secret
    name: my-app-tls
    key: tls.crt
```

Enable the Prometheus Operator ServiceMonitor and alert rules with
`--set monitoring.enabled=true` if its CRDs are installed.

### Dashboards

The chart also installs both Grafana dashboards (Grafana 10 or later) as a
ConfigMap for the Grafana dashboard sidecar. The defaults suit Rancher
Monitoring:

| Value | Default | Meaning |
|---|---|---|
| `dashboards.enabled` | `true` | Set `false` to skip them |
| `dashboards.namespace` | `cattle-dashboards` | Namespace the sidecar watches (empty: the release namespace) |
| `dashboards.label` / `labelValue` | `grafana_dashboard` / `"1"` | Must match the sidecar's label setting |
| `dashboards.annotations` | `{}` | For example `grafana_folder: Certificates` if the sidecar uses a folder annotation |

The ConfigMap lives outside the release namespace, so whoever runs `helm` needs
permission to create ConfigMaps in `dashboards.namespace`. Without the sidecar,
set `dashboards.enabled=false` and import `deploy/dashboards/*.json` through the
Grafana UI.

### Check that it works

```bash
kubectl -n cert-inventory logs deploy/cert-inventory
kubectl -n cert-inventory port-forward svc/cert-inventory 9793 &
curl -s localhost:9793/metrics | grep certinv_target_up
```

Every target should show `certinv_target_up{...,reason=""} 1`. The
**Monitored targets** table at the bottom of the inventory dashboard shows the
same information.

| reason | Fix |
|---|---|
| `forbidden` | Upgrade the Helm release after changing `targets`; verify the generated Role and RoleBinding |
| `not_found` | Wrong namespace or name in the Helm `targets` values |
| `key_not_found` | Wrong key; check with `kubectl get secret NAME -o jsonpath='{.data}'` |
| `no_certificates` / `parse_error` | The key isn't a PEM or DER certificate (for example PKCS#12/JKS, which aren't supported) |

## Dashboards

- **Certificate Inventory:** counts by expiry window, then a table of every
  certificate in the selected namespaces (Namespace, Resource, Key, Subject,
  Issuer, SANs, Serial, Expires, Days left), soonest expiry first.
  Click a **Subject CN** to open its details.
- **Certificate Detail:** one certificate decoded: subject and issuer DNs,
  SANs, serial, SHA-256 fingerprint, validity dates, and where it's stored.
  It also lists every certificate in the same key (for chains and bundles).

## Metrics

| Metric | Labels (besides `cert_namespace`, `cert_kind`, `cert_name`, `cert_resource`, `cert_key`, `serial_number`) |
|---|---|
| `certinv_cert_not_after_seconds` | `subject_CN`, `subject_O`, `issuer_CN`, `sans` |
| `certinv_cert_not_before_seconds` | none |
| `certinv_cert_info` (always 1) | `subject`, `issuer`, `sans`, `sha256_fingerprint`, `not_before`, `not_after` |
| `certinv_cert_san_info` (always 1) | `san` (one series per SAN) |
| `certinv_target_up` | `reason` (labels identify the targets.txt line) |
| `certinv_target_certificates`, `certinv_targets_file_ok`, `certinv_last_scan_timestamp_seconds`, `certinv_scan_duration_seconds` | exporter health |

Alerts (from `deploy/templates/monitoring.yaml`): expiring within 30 days (warning), within 14
days (critical), expired (critical), target unreadable, targets file invalid,
and the exporter not scanning.

## Design notes and limits

- **Least privilege:** the ServiceAccount can only `get` the named objects. It
  has no `list` or `watch`, and no access to anything else. The exporter never
  exports private keys: it extracts only `CERTIFICATE` PEM blocks, and a test
  checks this. Note that reading a TLS Secret through the API does return the
  whole Secret, including `tls.key`, to the pod's memory.
- **Certificate decoding** uses `ssl._ssl._test_decode_cert`. It's an
  undocumented CPython function, but it has existed since Python 2.7/3.2 and
  still exists in 3.14. If a future base image removes it, every target reports
  `parse_error` and the `CertInventoryTargetFailing` alert fires. That is a
  loud failure, not a silent one.
- **Supported formats:** PEM, PEM bundles, and single DER certificates.
  PKCS#12 and JKS keystores are not supported.
- Scans run every 5 minutes (`CERTINV_SCAN_INTERVAL_SECONDS`). Editing the Helm
  `targets` values rolls the pod automatically through the ConfigMap name hash.

## Development

```bash
python -m unittest discover -s tests -v      # exporter tests (mock Kubernetes API)
python dashboards/generate.py                # regenerate dashboard JSON after editing generate.py
```

### Local end-to-end demo (Docker)

`local-test/` runs the whole pipeline on a workstation: a mock Kubernetes API
serving generated test certificates (expiring in 9, 25, 75 and 400 days, one
expired, plus a CA bundle and a DER file), the exporter, Prometheus with the
alert rules, and Grafana with both dashboards. It also includes three targets
that are meant to fail.

```bash
cd local-test
bash make-certs.sh          # needs openssl (Git Bash has it)
python extract-rules.py     # PrometheusRule -> plain rules.yml
docker compose up -d        # Grafana: http://127.0.0.1:3000  Prometheus: http://127.0.0.1:9090
python check-queries.py     # runs every dashboard/alert query and reports problems
docker compose down
```

The local stack uses public images (`ubi9/python-312`, `prom/prometheus`,
`grafana/grafana`) because it's only for testing. The cluster deployment uses
only your approved image.
