# Preparing Linux and Windows targets

Securitas scans hosts over SSH (Linux) and WinRM (Windows) with a dedicated **scan account**. What a host needs
depends on what you want from it:

| | Vulnerability scans | Compliance checks (CIS) |
|---|---|---|
| **Linux** (RHEL family) | A scan account that can log in with an SSH key. No sudo. | The **Securitas agent** RPM: Goss and a wrapper owned by root, the scan account and **one** sudo rule for the wrapper. Securitas copies the audit content at each scan. |
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

### 2. Compliance checks: the Securitas agent

You need the benchmark loaded in Securitas (**Compliance → Benchmarks**: upload the Ansible-Lockdown role zip,
make it active for the host's OS, and upload the matching audit zip on the benchmark's page, e.g.
`RHEL9-CIS-Audit` at the branch for the role's CIS version).

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
dnf install https://github.com/uhlix-net/securitas/releases/download/vX.Y.Z/securitas-agent-X.Y.Z-1.x86_64.rpm
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

**Without the RPM:** install Goss (checksum-checked) at `/usr/local/bin/goss`, copy
[`contrib/linux/securitas-cis-audit`](../contrib/linux/securitas-cis-audit) to `/usr/local/sbin/` (root, 0755) and
[`contrib/linux/sudoers.securitas-cis`](../contrib/linux/sudoers.securitas-cis) to `/etc/sudoers.d/` (0440, edit
the account name, `visudo -cf`). [`contrib/ansible/linux-cis-audit.yml`](../contrib/ansible/linux-cis-audit.yml)
is an older example that also installs a fixed copy of the audit content on the host (used only when Securitas has
no audit zip for the benchmark).

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
