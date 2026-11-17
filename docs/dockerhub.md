# Securitas

A read-only CVE report for Kubernetes clusters scanned by [Trivy Operator](https://aquasecurity.github.io/trivy-operator/).
Findings are ranked with the CISA Known Exploited Vulnerabilities (KEV) catalog and EPSS scores and served
as one web page, with an **Export to PDF** button (made with WeasyPrint, no browser in the image).

- Source, documentation and Helm chart: https://github.com/uhlix-net/securitas
- License: Apache-2.0
- Platforms: linux/amd64, linux/arm64
- Runs as UID 10001, read-only root filesystem; writes only to `/data` (feed cache) and `/tmp`

## Install with Helm

```bash
helm repo add securitas https://uhlix-net.github.io/securitas
helm install securitas securitas/securitas -n securitas --create-namespace
```

The report lists unpatched software and has no login of its own: expose it only on a trusted network
or behind an authenticating proxy.
