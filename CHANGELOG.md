# Changelog

## 0.6.0 (beta)

Compliance exceptions: accept a failed rule, for every host or for one.

### New

- **Exceptions on failed rules.** On a host's compliance result, each failed rule has a drop-down
  (*BASELINE EXCEPTION* or *SERVER EXCEPTION*) and a reason (required). A **baseline exception** applies to every
  host checked against that benchmark (matched by benchmark name, e.g. `RHEL9-CIS`, so it carries over to a newer
  version of the same role); a **server exception** applies only to that host and wins over a baseline one.
  Choosing *No exception* removes the exception that applies. Admins only; viewers and operators can read them.
- **Accepted results.** Compliance scans after an exception is saved report the rule as **Accepted** (yellow),
  with the exception type and reason next to it. Until the next scan, the rule stays Failed and shows
  *Exception saved*. Removing an exception makes the rule Failed again from the next scan.
- **Score.** Accepted rules count as met: score = (passed + accepted) / (passed + accepted + failed).
- **Compliance → Exceptions**: every exception with its benchmark, rule, scope, host, reason, who saved it and
  when; admins can remove them there. Every change is in the audit log.
- **Compliance over time** graph on Home and Compliance → Summary: the average compliance score per platform
  (each host's newest check at the end of each day, week or month), daily, weekly or monthly like the CVE graph.
- The *over time* graphs (CVEs and compliance) now open on the **daily** view (was weekly).
- **Charts and tables** have an Accepted colour and column: the per-host score bars, the rule-result pies, Home,
  Compliance summary, report, scan list and scan pages.

## 0.5.0 (2026-11-21)

Compliance: a library of CIS benchmarks, and Linux and Windows hosts checked against them.

### New

- **Compliance → Benchmarks.** Upload an [Ansible-Lockdown](https://github.com/ansible-lockdown) CIS role as the
  zip GitHub offers on its release page (for example `RHEL9-CIS-2.4.2.zip`, one folder `<role>-<version>`).
  Securitas reads it without running anything and stores:
  - the benchmark under its role name and version (`RHEL9-CIS-2.4.2`), shown as
    `RHEL9-CIS 2.4.2 · uploaded 2026-11-20`, with who uploaded it, the file name, size and SHA-256;
  - the CIS document version (`v2.0.0`), the operating system it is for (RHEL 9 family) and the role's metadata;
  - every rule: ID, title, automated (PATCH) or manual (AUDIT), profile level tags, NIST 800-53 mappings, the
    role's on/off variable and its default;
  - the original zip, which admins can download again.
- **Several versions side by side.** Loading the same role/version twice is refused; a different version is
  added next to the old one. One benchmark per operating system is *active* (the first one loaded becomes it);
  admins can switch.
- **Which rules are checked.** Each benchmark has a profile: Level 1 or Level 2, Server or Workstation (Level 1
  Server by default; Level 2 includes Level 1). Single rules can be switched on or off; those choices are marked
  *Set here* and can be cleared. The rule list can be searched and filtered by section, level, type and state.
- **Remove a benchmark** from the benchmark list (tick *Confirm*, then *Remove*, as on the Targets page) or from
  its own page: its rules, choices and stored zip go with it.
- Viewers and operators can browse benchmarks and rules; only admins change them. Every upload, change,
  download and removal is in the audit log.
- Linux and Windows CIS roles are read (Windows roles such as `Windows-2022-CIS`, with member-server and
  domain-controller levels); STIG roles are refused for now. Kubernetes compliance will come from Trivy Operator's CIS report, so it needs no upload.

- Chart text is a little smaller, and the compliance score bars are thinner (charts are drawn at the page width).
- **Home page** (`/`): vulnerabilities and compliance at a glance: headline numbers (priority CVEs, known
  exploited, critical, systems, compliance score, systems checked, rules failed), both platform tables, the CVE
  history graph and severity pies, a compliance score bar per host (passed and failed rules, lowest score
  first) and a pie of rule results per platform.
- **About page** (top menu): version, what is scanned and how, data sources, database, time zone, your
  account, source code and licence.
- **Scan only some hosts.** On *Compliance → Scans*, tick one or more hosts to check just those; leave them all
  unticked to check every matched host of the platforms ticked. The scan history and the scan page show the
  selection.
- **Linux compliance checks.** *Compliance → Scans → Run compliance scan* checks each enabled Linux target
  against the active benchmark for its OS (matched by the OS its latest vulnerability scan saw) with
  [Goss](https://github.com/goss-org/goss) and the benchmark's Ansible-Lockdown audit content (for
  `RHEL9-CIS-2.4.2`: `RHEL9-CIS-Audit`, branch `benchmark_v2.0.0`). Over SSH, as the scan account, Securitas runs
  `sudo -n /usr/local/sbin/securitas-cis-audit <benchmark> server|workstation`. Ansible installs that wrapper,
  Goss and the audit content root-owned on each host, with a sudo rule for the wrapper only, so the scan account
  cannot change what runs as root. Goss changes nothing on the host.
  - Every rule the benchmark checks (its profile and the rules switched on or off) gets a result: *Passed*,
    *Failed*, *Not applicable* (all its tests skipped) or *No automated check* (manual review). A rule fails when
    any of its tests fails; the audit content's "Manual Check Required" placeholders do not count.
  - The score is passed / (passed + failed).
  - Each scan has a page with every host's counts and score, its log, and per host every rule with its tests
    (failed first, with Goss's message), filterable by result.
  - Results keep the benchmark's name, version, profile and rule titles, so they stay readable after the
    benchmark is removed.
  - Compliance schedules now start Linux compliance scans. Compliance scans have their own worker, so they
    run alongside vulnerability scans.
- **Windows compliance checks.** Windows Server hosts are checked against the active Windows benchmark for
  their OS (for example `Windows-2022-CIS-4.2.0`, `Windows-2025-CIS-1.2.2`) with
  [syver](https://github.com/krameff/syver), the Goss fork the Ansible-Lockdown Windows audits are written for, and
  the benchmark's audit content (`Windows-2022-CIS-Audit` branch `benchmark_v4.0.0`, `Windows-2025-CIS-Audit`
  branch `benchmark_v1.0.0`). Over WinRM, as the scan account, Securitas starts the scheduled task
  `\Securitas\CIS Audit <benchmark>`, which runs the audit as SYSTEM, waits for it and reads its JSON result from
  `C:\ProgramData\Securitas\CIS`. Ansible installs syver (pinned, checksum- and signature-checked), the content,
  the wrapper and the task. The scan account may only start the task and read its output, so it cannot change
  what runs as SYSTEM.
  - Windows benchmarks tag rules for **member servers** or **domain controllers**. The default Windows profile
    is *Level 1, by each host's role*: a domain controller gets the domain controller rules, a member server
    the member server rules (the role is read from the host when it is checked). Fixed member-server and
    domain-controller profiles, and Level 2, can be chosen per benchmark.
  - The CIS *Next Generation Windows Security* rules (tagged `ngws-*`) are in neither Level 1 nor Level 2.
    They can be switched on one by one.
  - Each result records the role the host was checked as.
  - The task is started and watched through the Task Scheduler COM API, which honours the task's own permissions.
    `Get-ScheduledTask` reads a WMI namespace that a non-admin scan account cannot read.
- **Compliance summary.** *Compliance → Summary* (`/compliance`) has one row per platform: systems, how many
  are matched to an active benchmark, which benchmark, the check results (empty until a checker exists) and the
  schedule, plus the active benchmarks.
- **Compliance schedules.** *Compliance → Schedules* sets a cron schedule per platform for compliance scans,
  stored apart from the vulnerability scan schedules. They are saved but start nothing until a checker exists.
- **Compliance report.** *Compliance → Report* (`/compliance/report`) lists the active benchmark per operating
  system and every enabled target with its OS, its benchmark and its newest check (passed, failed, score).
  Kubernetes has no checker yet.

### Changed

- **New menus.** The top menu is *Home*, *Vulnerabilities*, *Compliance*, *Targets*, *Audit log*, *Settings* and
  *About*. The vulnerability summary moved from `/` to `/vulnerabilities`; `/` is now the Home page.
  - *Vulnerabilities*: Summary, Report, Scans, **Schedules** (moved from Settings to `/vulnerabilities/schedules`;
    they are vulnerability scan schedules) and **Sources** (moved to `/vulnerabilities/sources`).
  - *Compliance*: Summary, Report, Scans, Schedules and Benchmarks.
  - **Targets** (`/targets`) and **Audit log** (`/audit`) moved out of Settings to the top menu (admins only).
  - The menu bar's subtitle reads *Vulnerabilities and Compliance*; the cluster name moved to the About page.
  - Settings keeps Users, Authentication and Scan credentials. Users whose role has no settings pages
    (viewers, operators) no longer see the Settings menu.
  - The vulnerability Report and Scans addresses (`/report`, `/scans`) are unchanged. The old addresses
    (`/settings/sources`, `/settings/schedules`, `/settings/targets`, `/settings/audit`, `/settings/compliance`)
    redirect to the new ones.

- **Target setup guide.** [docs/target-setup.md](docs/target-setup.md) explains how to prepare Linux and Windows
  hosts for vulnerability scans and compliance checks. [`contrib/`](contrib) has the wrapper scripts, the sudo rule,
  the scheduled-task installer and example Ansible playbooks.

### Upgrading from 0.4.0

- Six new tables (`benchmarks`, `benchmark_rules`, `benchmark_files`, `compliance_schedules`, `compliance_scans`,
  `compliance_results`) are created at startup.
- A column is added to `compliance_scans` (`hosts`) at startup if a 0.5.0 release candidate created the table
  without it.
- Windows compliance checks need syver, the audit content, the wrapper and the scheduled task on each host:
  uhlix-net/ansible `Windows_Securitas_CIS_Audit.yml`; the interface is described in `securitas/scan_compliance.py`.
- Linux compliance checks need Goss, the audit content, the wrapper and its sudo rule on each host. uhlix-net/ansible
  `Linux_Securitas_CIS_Audit.yml` installs them; the wrapper's interface is described in `securitas/scan_compliance.py`. No change to
  existing data.
- New dependency: PyYAML.
- Uploads are up to 25 MB; if an ingress in front of Securitas limits request bodies, allow at least that.

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
