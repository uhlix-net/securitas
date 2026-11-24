# Securitas

Vulnerabilities and compliance for Kubernetes, Linux and Windows. Securitas scans on a schedule or on demand,
ranks CVEs with the [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
(KEV) catalog and [EPSS](https://www.first.org/epss/) scores, checks hosts against CIS benchmarks, keeps every
scan in its history, and serves the results as web pages behind a sign-in, with an **Export to PDF** button.

> **0.6.0** adds compliance exceptions (baseline or per server, shown as *Accepted* in yellow), the **Securitas
> agent** for Linux (one-line install; Securitas copies the audit checks at scan time so every host runs the same
> content), [benchmark packages built from the official CIS documents](https://github.com/uhlix-net/securitas-benchmarks),
> a compliance report by test, a Certificates page and a friendlier schedule picker. See the
> [changelog](https://github.com/uhlix-net/securitas/blob/main/CHANGELOG.md).

## Features

- **Three platforms**
  - **Kubernetes:** reads the vulnerability reports that [Trivy Operator](https://aquasecurity.github.io/trivy-operator/) keeps in the cluster.
  - **Linux (RHEL family):** connects over SSH and lists pending security advisories with `dnf updateinfo`.
  - **Windows:** connects over WinRM, reads the OS build and compares it with Microsoft's monthly security release data.
- **CIS compliance checks** for Linux (with the Securitas agent) and Windows Server, against
  [benchmark packages built from the official CIS documents](https://github.com/uhlix-net/securitas-benchmarks):
  per-host and per-test results, scores, score history, and exceptions (baseline or per server) with reasons.
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
- **Settings in the browser:** LDAP, single sign-on, the SSH key and WinRM account for scans (with a connection
  test), targets, schedules, users and sources. Secrets are encrypted in the database and never shown again;
  anything not set there comes from the Helm values.
- **Transparent sources:** a Sources page describes CISA KEV, EPSS, Trivy, dnf advisories and Microsoft's release
  data, when each was last fetched, and what turning it off changes; KEV, EPSS and each platform can be turned
  off. It also shows the exact script each scanner runs on a host.
- **Sign-in**
  - Local accounts.
  - LDAP / Active Directory, including nested groups.
  - OpenID Connect single sign-on (for example Authentik, Keycloak, Entra ID).
  - Local sign-in can be turned off once SSO works; a break-glass local admin is created at install.
- **Roles:** Viewer (view and export), Operator (also runs scans and edits schedules) and Admin (also manages targets, users, authentication settings and group-to-role mappings). LDAP and SSO users get their role from their groups.
- **Audit log** of every sign-in, scan and change.
- **Light and dark mode**, chosen per user.
- **PDF export** with WeasyPrint (no browser in the image).

## Installing the agent on Linux targets

Linux compliance checks need the **Securitas agent** on each host: a small RPM (`securitas-agent`, Rocky Linux /
RHEL / AlmaLinux 8 and 9, x86_64) with the compliance wrapper, a checksum-pinned Goss and a setup command. It
creates the scan account (password locked), authorizes Securitas's SSH key and adds **one** sudo rule: the
account may run only `/usr/local/sbin/securitas-cis-audit` as root. Nothing runs on the host between scans.

**One line, on each host as root** (Securitas serves the script and the RPM; set the scan account and key in
*Settings → Scan credentials* first, and the allowed source addresses in *Settings → Agent*):

```bash
curl -fsS https://securitas.example.com/agent/install.sh | sudo bash
# private CA the host does not trust yet:
curl -fsS --cacert /path/ca.pem https://securitas.example.com/agent/install.sh | sudo SECURITAS_CA=/path/ca.pem bash
```

**Or by hand / with Ansible**, using the RPM from Securitas or from the [GitHub release](https://github.com/uhlix-net/securitas/releases):

```bash
dnf install https://github.com/uhlix-net/securitas/releases/download/v0.6.0/securitas-agent-0.6.0-1.x86_64.rpm
securitas-agent-setup --user svc-securitas --key 'ssh-ed25519 AAAA... securitas' --from 10.0.0.11,10.0.0.12
```

Then add the host under **Targets**, run a vulnerability scan once (so its OS is known) and a compliance scan.
`securitas-agent-setup --remove` removes the sudo rule and the key; `dnf remove securitas-agent` removes the agent
(the account is kept).

At scan time Securitas copies the benchmark's audit content (uploaded once per benchmark on its page) to a random
hidden file in `/tmp`; the wrapper, as root, unpacks it into a new root-only directory, runs Goss read-only and
deletes both. Every host runs exactly the same content, so there is no drift between hosts. Trust: whoever
controls Securitas decides what the checks run as root on these hosts, as with Semaphore or a credentialed
Tenable scan; protect Securitas's admin accounts and SSH key accordingly.

## Security

- **Scans don't change the systems they scan.** Vulnerability scans install nothing and need no root, sudo or admin rights. Linux compliance checks use the Securitas agent, whose scan account may run only the read-only compliance wrapper as root.
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
