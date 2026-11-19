# Changelog

## 0.4.0 (2026-11-19)

The report shows every CVE, not only priority ones, and the Summary page shows how the counts change.

### New

- **CVEs over time.** The Summary page has a graph of distinct CVEs per platform, one shaded line each, under
  the summary table. Choose daily (last 7 days), weekly (last 3 months, the default) or monthly (last year).
  Each point is the newest successful scan at the end of that day, week or month. Hover a point for its
  value; *Show as a table* lists the numbers.
- **CVEs by severity.** Under the graph, a pie chart per platform of its CVEs at every severity level, with
  counts and percentages.
- **Severity filter on the report.** Tick one or more levels (Critical, High / Important, Medium / Moderate,
  Low, Unknown) and optionally *Priority CVEs only*. Works on the current report, past scans and Export to PDF.
  Long CVE tables are split into pages of 200 on the web page. The PDF lists the first 500 matching CVEs per
  platform in ranking order and says how many it left out (a PDF of every CVE would not fit the pod's memory).

### Changed

- **Every CVE is listed.** The report used to list only priority CVEs (CISA KEV or EPSS at or above the
  threshold). It now lists all of them, priority CVEs first and tagged *priority*. *Priority CVEs only* brings
  back the old view. The summary table's counts are still priority CVEs.
- The page needs no script: charts are drawn on the server as SVG, so the Content-Security-Policy is unchanged.

### Upgrading from 0.3.0

- A new table, `result_stats`, is created at startup and filled from the scans already stored, so the graph
  has history straight away (up to the retention period). This runs once and takes a moment per stored scan.
- Scans saved from 0.4.0 on store every CVE in their report, so the database grows faster than before.
  Past scans saved by earlier versions still show only their priority CVEs.
- PDFs are now made one at a time, since each can use a few hundred MB. Keep the memory limit at 1 GiB or more.

## 0.3.0 (2026-11-19)

Administration moves into the browser, and Securitas explains where its data comes from.

### New

- **Settings menu.** One place for everything administrative: Users, Authentication, Scan credentials,
  Targets, Schedules, Sources and the Audit log. Each user sees the pages their role allows (viewers see
  Sources). The old addresses (`/admin/...`, `/schedules`) redirect.
- **LDAP and single sign-on configured in the browser.** Server, bind account and password, search bases,
  nested groups and StartTLS for LDAP; issuer, client ID and secret, scopes, claims and button label for
  OpenID Connect; an on/off switch for each, and a *Test the provider* button for SSO. Changes apply to the
  next sign-in, without a restart.
- **Scan credentials in the browser.** The Linux SSH user, port and private key, and the Windows WinRM
  account, password, port, HTTPS and authentication method, with a *Test a connection* button that signs in
  to a chosen target and reports who it signed in as (recorded in the audit log).
- **Secrets are encrypted and write-only.** Passwords, the SSH key and the OIDC client secret saved in the
  browser are encrypted in the database with a key the chart generates (`settings.secretKey`). They are never
  shown again; they can only be replaced or put back to the deployment's value. Every change is in the audit
  log, without secret values.
- **Sources page.** Describes each data source (CISA KEV, FIRST EPSS, Trivy Operator, dnf security advisories,
  Microsoft MSRC release data): what it is, how Securitas uses it, how often it updates, where it comes from,
  when it was last fetched or scanned, and what turning it off changes. It also explains how each platform is
  scanned and shows the exact shell and PowerShell scripts the scanners run on a host.
- **Sources can be turned off.** KEV and EPSS each have a switch (with both off, every CVE is listed
  unranked), and the EPSS threshold can be changed. Turning off Trivy, dnf or MSRC turns off scanning of that
  platform: scheduled and manual scans skip it, and its last results stay in the report marked as no longer updated.
- **Summary at the top of the report.** The Summary page's table (status, last scan, systems, priority CVEs,
  known exploited, critical, high, totals) now opens the report, past scans and the PDF.

### Changed

- **Settings and Helm values.** A value saved on a Settings page overrides the Helm value; anything not saved
  there still comes from Helm. Every field shows which applies.
- **Top menu.** Now Summary, Report, Scans and Settings.

### Upgrading from 0.2.0

- `helm upgrade` adds the Secret `<release>-key` (the encryption key). Back it up with the database: without
  it, secrets saved in the browser cannot be read (Securitas then falls back to the Helm values and says so on
  the Settings page). To bring your own key, set `settings.secretKey.existingSecret`.
- Nothing else changes until you save something on a Settings page.

## 0.2.0 (2026-11-19)

Securitas grows from a single Kubernetes report page into a scanner for Kubernetes, Linux and Windows,
with scheduled and on-demand scans, history, sign-in and roles.

### New

- **Linux scans (RHEL family).** Connects over SSH with a key and lists pending security advisories
  with `dnf updateinfo`. It can compare against upstream repositories instead of the host's own
  (for hosts on Foreman/Katello or Satellite content that lags). The SSH host key is recorded on the
  first scan and checked on later scans.
- **Windows scans.** Connects over WinRM (HTTPS by default) and compares the OS build and update revision
  with the fixed build of every CVE in Microsoft's monthly security release data. Needs no admin
  rights: Remote Management Users plus WMI *Enable Account* and *Remote Enable* on `root\cimv2`.
- **Scheduled and on-demand scans.** Each platform has its own cron schedule, editable on the Schedules
  page. Operators and admins can start a scan at any time.
- **Scan history.** Every scan is kept with its log, and can be opened and exported to PDF as it was at the time.
  You can filter the history by platform: the status and counts shown are that platform's, and scan
  links open its section.
- **Summary page.** The page you land on after sign-in. It lists each platform with its scan status, last scan,
  systems, priority CVEs, known exploited, critical and high counts. Each platform name links to its
  section of the full report, which moved to `/report`.
- **Failed scans are flagged, not hidden.** A failed or partial platform scan is shown, with its error, in the
  summary, the report and the PDF. If the newest scan failed, older results stay visible but are marked as older.
- **Sign-in.** Local accounts, LDAP / Active Directory (with nested groups) and OpenID Connect
  single sign-on (authorization code flow with PKCE). Local sign-in can be turned off; a break-glass
  admin is created at install.
- **Roles.** Viewer, Operator and Admin, with group-to-role mappings for LDAP and SSO users.
- **Admin pages.** Scan targets, users, authentication settings and group mappings, and an audit log of every
  sign-in, scan and change.
- **Light and dark mode**, chosen per user.
- **PostgreSQL** for users, schedules and history. The chart bundles a PostgreSQL StatefulSet, or it can use
  an external server.

### Changed

- Every page now requires sign-in.
- The report moved from `/` to `/report`; `/` is the summary.
- Kubernetes reports are no longer refreshed on a timer. They are scanned on the `kubernetes` schedule
  (default hourly at :05) or on demand.
- The web UI uses 85% of the window width.

### Upgrading from 0.1.0

- `helm upgrade` works. The chart now also creates a PostgreSQL StatefulSet with a 2 Gi volume, so the cluster
  needs a default StorageClass, or set `database.bundled.storage.storageClass`, or point
  `database.external.*` at your own server.
- `config.refreshSeconds` and `replicaCount` were removed: use `scanning.schedules.kubernetes`. The chart
  always runs one replica, because the scheduler and scan worker run in the web process.
- After the upgrade, sign in as `admin` with the password from the `securitas-admin` Secret.
- `extraPlatforms` still works as before.

## 0.1.0 (2026-11-17)

First release: a read-only CVE report for Kubernetes clusters scanned by Trivy Operator. Findings are ranked
with the CISA KEV catalog and EPSS scores and shown on one web page, with PDF export.
