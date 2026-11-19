# Securitas

CVE reports for Kubernetes ([Trivy Operator](https://aquasecurity.github.io/trivy-operator/)), Linux (SSH) and
Windows (WinRM), ranked with the CISA Known Exploited Vulnerabilities (KEV) catalog and EPSS scores.
A summary landing page with per-platform status and counts (each platform links to its section of the report),
failed or partial scans flagged with their error, scheduled and on-demand scans with history, sign-in with local
accounts, LDAP or OpenID Connect, Viewer / Operator / Admin roles, light and dark mode, and **Export to PDF**
(WeasyPrint, no browser in the image).

- Source, documentation and Helm chart: https://github.com/uhlix-net/securitas
- License: Apache-2.0
- Platforms: linux/amd64, linux/arm64
- Runs as UID 10001, read-only root filesystem; writes only to `/data` (feed cache) and `/tmp`
- Stores users, schedules and scan history in PostgreSQL (bundled with the Helm chart, or external)

## Install with Helm

```bash
helm repo add securitas https://uhlix-net.github.io/securitas
helm install securitas securitas/securitas -n securitas --create-namespace
kubectl -n securitas get secret securitas-admin -o jsonpath='{.data.password}' | base64 -d; echo
```
