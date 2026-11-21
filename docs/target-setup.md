# Preparing Linux and Windows targets

Securitas scans hosts over SSH (Linux) and WinRM (Windows) with a dedicated **scan account**. What a host needs
depends on what you want from it:

| | Vulnerability scans | Compliance checks (CIS) |
|---|---|---|
| **Linux** (RHEL family) | A scan account that can log in with an SSH key. No sudo. | Goss, the benchmark's audit content and a wrapper, all owned by root, plus **one** sudo rule for the wrapper. |
| **Windows Server** | A domain account in *Remote Management Users* with WMI access to `root\cimv2`; WinRM over HTTPS. No admin rights. | syver, the benchmark's audit content and a wrapper, writable by administrators only, plus a scheduled task that runs as SYSTEM and that the scan account may **only start**. |

In both cases the scan account cannot change anything that runs with elevated rights: it can only start a fixed,
read-only check that an administrator installed. Nothing on a host is changed by a scan.

The files referred to below are in [`contrib/`](../contrib). The [example Ansible playbooks](../contrib/ansible)
do the compliance setup for you; the manual steps show what they do.

---

## Linux

### 1. Scan account (vulnerability scans)

On each host, as root (the account name `securitas` is an example):

```bash
useradd --system --create-home --shell /bin/bash securitas
passwd -l securitas                      # key login only
install -d -m 700 -o securitas -g securitas ~securitas/.ssh
# Paste the public key. "restrict" turns off forwarding, PTYs and agents; "from=" limits where it may log in from
# (use the addresses your Securitas pod's traffic leaves from, e.g. your Kubernetes nodes).
echo 'restrict,from="10.0.0.11,10.0.0.12" ssh-ed25519 AAAA... securitas' > ~securitas/.ssh/authorized_keys
chown securitas:securitas ~securitas/.ssh/authorized_keys && chmod 600 ~securitas/.ssh/authorized_keys
```

In Securitas: paste the private key in **Settings → Scan credentials** (or use `scanning.linux.*` in the Helm
values), add the host on **Targets**, and use **Test a connection**. The host's SSH key is recorded on the first
scan; a changed key fails the scan until an admin resets it on the Targets page.

### 2. Compliance checks

You need the benchmark loaded in Securitas (**Compliance → Benchmarks**, upload the Ansible-Lockdown role zip) and
active for the host's OS. Its **key**, for example `RHEL9-CIS-2.4.2`, names the folder the audit content goes in.

1. **Goss**, the official release, checked against its published checksum:

   ```bash
   v=0.4.10
   curl -fsSLO https://github.com/goss-org/goss/releases/download/v$v/goss_${v}_linux_x86_64.tar.gz
   curl -fsSLO https://github.com/goss-org/goss/releases/download/v$v/goss_${v}_SHA256SUMS
   grep linux_x86_64.tar.gz goss_${v}_SHA256SUMS | sha256sum -c -
   tar xzf goss_${v}_linux_x86_64.tar.gz goss && install -o root -g root -m 0755 goss /usr/local/bin/goss
   ```

2. **Audit content**: the Ansible-Lockdown `<OS>-CIS-Audit` repository at the branch for the role's CIS version
   (the role's `benchmark_version`, shown on the benchmark's page). Pin a commit so it cannot change underneath you:

   ```bash
   install -d -o root -g root -m 0755 /opt/securitas-cis
   git clone https://github.com/ansible-lockdown/RHEL9-CIS-Audit.git /opt/securitas-cis/RHEL9-CIS-2.4.2
   git -C /opt/securitas-cis/RHEL9-CIS-2.4.2 checkout d9c0f2ce3be692d27d21f613030311ad7309fa9f   # benchmark_v2.0.0
   chown -R root:root /opt/securitas-cis && chmod -R go-w /opt/securitas-cis
   ```

3. **Wrapper and sudo rule**:

   ```bash
   install -o root -g root -m 0755 contrib/linux/securitas-cis-audit /usr/local/sbin/securitas-cis-audit
   # edit the account name in the file first, then:
   install -o root -g root -m 0440 contrib/linux/sudoers.securitas-cis /etc/sudoers.d/securitas-cis
   visudo -cf /etc/sudoers.d/securitas-cis
   ```

4. **Check** that the scan account may run the wrapper and nothing else, and that it works (about a minute):

   ```bash
   sudo -l -U securitas                         # (root) NOPASSWD: /usr/local/sbin/securitas-cis-audit
   sudo -u securitas sudo -n /usr/local/sbin/securitas-cis-audit RHEL9-CIS-2.4.2 server | head -c 300
   ```

**With Ansible:** [`contrib/ansible/linux-cis-audit.yml`](../contrib/ansible/linux-cis-audit.yml) does steps 1-3
(set `scan_user`; add a `securitas_cis_benchmarks` entry per benchmark).

---

## Windows

### 1. Scan account (vulnerability scans)

1. Create a domain user for Securitas (for example `CONTOSO\securitas`) with a strong password. It needs no admin
   rights.
2. On each host (or for domain controllers, in the domain's *Builtin* container), add it to
   **Remote Management Users**.
3. Give it **Enable Account** and **Remote Enable** on the WMI namespace `root\cimv2` (WMI Control → Properties →
   Security), or as an administrator:

   ```powershell
   $sid = (New-Object Security.Principal.NTAccount('CONTOSO\securitas')).Translate([Security.Principal.SecurityIdentifier]).Value
   $sec = Get-WmiObject -Namespace root\cimv2 -Class __SystemSecurity
   $helper = [wmiclass]'Win32_SecurityDescriptorHelper'
   $sddl = $helper.BinarySDToSDDL($sec.GetSD().SD).SDDL
   $ace = "(A;CI;CCWP;;;$sid)"                          # CC + WP = 0x21: Enable Account + Remote Enable
   $sddl = if ($sddl -match 'S:') { $sddl -replace 'S:', "${ace}S:" } else { $sddl + $ace }
   $null = $sec.SetSD($helper.SDDLToBinarySD($sddl).BinarySD)
   ```

4. Enable **WinRM over HTTPS** (port 5986) with a certificate your Securitas deployment trusts (`caBundle.*` in the
   Helm values), and allow 5986 from the addresses Securitas connects from.

In Securitas: enter the account (`DOMAIN\user` or `user@domain`) and password in **Settings → Scan credentials**,
add the host on **Targets**, and use **Test a connection**.

### 2. Compliance checks

Upload the Windows benchmark (for example `Windows-2025-CIS-1.2.2`) in **Compliance → Benchmarks**. Windows
benchmarks tag rules for member servers or domain controllers; the default profile checks each host with the rules
for its role, which Securitas reads from the host.

The Ansible-Lockdown Windows audits run with [syver](https://github.com/krameff/syver), a Goss fork that adds
Windows support. It is maintained by one person and released often, so pin a version and verify it:

1. **syver**, checked against the release's signed checksum file (do this on a workstation with GnuPG):

   ```bash
   v=0.20.0; u=https://github.com/krameff/syver/releases/download/v$v
   curl -fsSLO $u/syver-windows-amd64.exe -O $u/syver_${v}_SHA256SUMS -O $u/syver_${v}_SHA256SUMS.sig -O $u/krameff-syver-key.asc
   gpg --import krameff-syver-key.asc
   gpg --verify syver_${v}_SHA256SUMS.sig syver_${v}_SHA256SUMS      # Good signature, key CD21 8D52 ... CABE 5092
   grep windows-amd64.exe syver_${v}_SHA256SUMS | sha256sum -c -
   ```

   Copy it to `C:\Program Files\Securitas\CIS\syver\syver.exe`. `C:\Program Files` is writable by administrators
   only, which is what you want.

2. **Audit content**: the `<OS>-CIS-Audit` repository at the commit for the role's CIS version, extracted into
   `C:\Program Files\Securitas\CIS\<benchmark key>\<OS>-CIS-Audit`. Start from an empty folder each time; the
   content's README warns that files left over from an older version abort the whole run.

   | Benchmark key | Audit repository | Branch | Commit |
   |---|---|---|---|
   | `Windows-2022-CIS-4.2.0` | `ansible-lockdown/Windows-2022-CIS-Audit` | `benchmark_v4.0.0` | `fed5857c5d0a9cfa93451937e7236678b46681d4` |
   | `Windows-2025-CIS-1.2.2` | `ansible-lockdown/Windows-2025-CIS-Audit` | `benchmark_v1.0.0` | `59620023f3ef6459ff0bca2bfa53b77488db4251` |

   For example: `C:\Program Files\Securitas\CIS\Windows-2025-CIS-1.2.2\Windows-2025-CIS-Audit\goss.yml`.

3. **Wrapper and scheduled task**, as an administrator on the host:

   ```powershell
   Copy-Item contrib\windows\securitas-cis-audit.ps1 'C:\Program Files\Securitas\CIS\'
   .\contrib\windows\Install-SecuritasCisTask.ps1 -Key Windows-2025-CIS-1.2.2 -ScanAccount 'CONTOSO\securitas'
   ```

   This creates `C:\ProgramData\Securitas\CIS` (SYSTEM and Administrators write, the scan account reads) and the
   task `\Securitas\CIS Audit Windows-2025-CIS-1.2.2`, which runs the wrapper as SYSTEM with that fixed key. The scan
   account gets read + execute on the task: it may start it, not change it. Securitas starts and watches the task
   through the Task Scheduler COM API; `Get-ScheduledTask` would need WMI rights a non-admin account does not have.

4. **Check**: run the task once as an administrator (`Start-ScheduledTask -TaskPath \Securitas\ -TaskName 'CIS Audit
   Windows-2025-CIS-1.2.2'`). A few minutes later `C:\ProgramData\Securitas\CIS\Windows-2025-CIS-1.2.2.json`
   exists; if not, read the `.log` next to it.

**With Ansible:** [`contrib/ansible/windows-cis-audit.yml`](../contrib/ansible/windows-cis-audit.yml) does steps
1-3. Downloads happen on the controller and are checked against pinned checksums, so the hosts need no internet
access. Set `scan_account` and the WinRM connection settings.

---

## Running a check

**Compliance → Scans → Run compliance scan**, for a whole platform or ticked hosts only. A host is matched to a
benchmark by the OS its latest vulnerability scan saw, so run a vulnerability scan of a new host first.

| Message on a host | What to do |
|---|---|
| `the OS is not known yet: run a vulnerability scan of this host first` | Run a vulnerability scan of the host. |
| `no active benchmark for <OS>` | Upload a benchmark for that OS, or make one active, in Compliance → Benchmarks. |
| `sudo refused: the host has no sudo rule …` | Linux: install the sudo rule (step 3). |
| `… securitas-cis-audit is not installed …` / `benchmark <key> is not installed on this host` | Linux: install the wrapper or the audit content under `/opt/securitas-cis/<key>`. |
| `the scheduled task \Securitas\CIS Audit <key> is not installed …` | Windows: run step 3 for that key. |
| `this account may not start the scheduled task` | Windows: re-run `Install-SecuritasCisTask.ps1` with the scan account. |
| `the audit wrote no new result …` | Windows: read `C:\ProgramData\Securitas\CIS\<key>.log` on the host. |
