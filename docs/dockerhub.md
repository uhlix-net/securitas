# Securitas

CVE reports for Kubernetes, Linux and Windows. Securitas scans on a schedule or on demand, ranks the findings
with the [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
(KEV) catalog and [EPSS](https://www.first.org/epss/) scores, keeps every scan in its history, and serves the
results as web pages behind a sign-in, with an **Export to PDF** button.

> **0.2.0** adds Linux and Windows scans, schedules, history, a summary page, sign-in and roles. 0.1.0 was a
> single-page Kubernetes-only report. See the [changelog](https://github.com/uhlix-net/securitas/blob/main/CHANGELOG.md)
> and the upgrade notes there.

## Features

- **Three platforms**
  - **Kubernetes:** reads the vulnerability reports that [Trivy Operator](https://aquasecurity.github.io/trivy-operator/) keeps in the cluster.
  - **Linux (RHEL family):** connects over SSH and lists pending security advisories with `dnf updateinfo`.
  - **Windows:** connects over WinRM, reads the OS build and compares it with Microsoft's monthly security release data.
- **Run scans whenever you want**
  - Operators and admins can start a scan of any platform from the Scans page.
  - Each platform also has its own cron schedule, which admins and operators can change in the browser.
- **Scan history:** every scheduled and manual scan is kept, with its log, and can be opened and exported as it was at the time. Filter it by platform to see that platform's status and counts.
- **Summary page:** after sign-in, one row per platform shows its scan status, when it was last scanned, and its counts (systems, priority CVEs, known exploited, critical, high). Each platform name links to its section of the full report.
- **Failed scans are flagged, not hidden:** if a platform's latest scan failed or was only partly successful, the summary, the report and the PDF say so and show the error.
- **Ranked, not just counted**
  - A CVE is a *priority* when it is in the KEV catalog or its EPSS score is at or above a threshold (default 0.10).
  - Known-exploited CVEs come first.
  - The current report is re-ranked when the KEV catalog or EPSS scores change, without a rescan.
- **Sign-in**
  - Local accounts.
  - LDAP / Active Directory, including nested groups.
  - OpenID Connect single sign-on (for example Authentik, Keycloak, Entra ID).
  - Local sign-in can be turned off once SSO works; a break-glass local admin is created at install.
- **Roles:** Viewer (view and export), Operator (also runs scans and edits schedules) and Admin (also manages targets, users, authentication settings and group-to-role mappings). LDAP and SSO users get their role from their groups.
- **Audit log** of every sign-in, scan and change.
- **Light and dark mode**, chosen per user.
- **PDF export** with WeasyPrint (no browser in the image).

## Security

- **Scans don't change the systems they scan.** Nothing is installed on the targets, and the scan accounts need no root, sudo or admin rights.
- **No scripts in the pages.** A strict Content Security Policy blocks all scripts, every form carries a CSRF token, and sessions use secure, HTTP-only cookies.
- **Locked-down container.** It runs as UID 10001 with a read-only root filesystem and writes only to `/data` (feed cache) and `/tmp`.

## Image

- Source, full documentation and Helm chart: https://github.com/uhlix-net/securitas
- Platforms: linux/amd64, linux/arm64
- Tags: `X.Y.Z` for releases, `X.Y.Z-rc.N` for pre-releases, and `latest` for the newest release
- Stores users, schedules and scan history in PostgreSQL (bundled with the Helm chart, or external); SQLite for local testing
- License: Apache-2.0

## Install with Helm

```bash
helm repo add securitas https://uhlix-net.github.io/securitas
helm install securitas securitas/securitas -n securitas --create-namespace
kubectl -n securitas get secret securitas-admin -o jsonpath='{.data.password}' | base64 -d; echo
```

LDAP, SSO, Linux SSH keys, Windows WinRM credentials, ingress and the database are all set through chart
values. See the [README](https://github.com/uhlix-net/securitas#readme) for configuration.
