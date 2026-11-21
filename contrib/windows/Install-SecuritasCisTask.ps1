<#
.SYNOPSIS
    Creates the Securitas output folder and the scheduled task that runs one benchmark's audit as SYSTEM.
.DESCRIPTION
    Run as an administrator on the Windows host, after syver, the audit content and securitas-cis-audit.ps1 are in
    place (see docs/target-setup.md). The scan account gets read + execute on the task (it may start it, not change
    it) and read access to C:\ProgramData\Securitas\CIS. Safe to run again.
.EXAMPLE
    .\Install-SecuritasCisTask.ps1 -Key Windows-2025-CIS-1.2.2 -ScanAccount 'CONTOSO\securitas'
#>
param(
    [Parameter(Mandatory = $true)][ValidatePattern('^[A-Za-z0-9][A-Za-z0-9.-]*$')][string]$Key,
    [Parameter(Mandatory = $true)][string]$ScanAccount
)
$ErrorActionPreference = 'Stop'
$root = 'C:\Program Files\Securitas\CIS'
$outDir = 'C:\ProgramData\Securitas\CIS'
$sid = (New-Object System.Security.Principal.NTAccount($ScanAccount)).Translate([System.Security.Principal.SecurityIdentifier]).Value

# Output folder: SYSTEM and Administrators write, the scan account reads, nobody else (ProgramData lets Users create files).
New-Item -ItemType Directory -Path $outDir -Force | Out-Null
& icacls.exe $outDir /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'BUILTIN\Administrators:(OI)(CI)F' "*${sid}:(OI)(CI)RX" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "icacls failed ($LASTEXITCODE)" }

# Task folder and task. The Task Scheduler COM API is used because it sets the task's security descriptor;
# Securitas also uses it to start the task (Get-ScheduledTask needs WMI rights a non-admin account lacks).
$svc = New-Object -ComObject Schedule.Service
$svc.Connect()
try { $folder = $svc.GetFolder('\Securitas') } catch {
    $folder = $svc.GetFolder([string][char]92).CreateFolder('Securitas', "D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;GR;;;$sid)")
}
$def = $svc.NewTask(0)
$def.RegistrationInfo.Description = "Securitas compliance check $Key (read-only)"
$def.Settings.Enabled = $true
$def.Settings.AllowDemandStart = $true
$def.Settings.MultipleInstances = 2          # ignore a start while it runs
$def.Settings.ExecutionTimeLimit = 'PT1H'
$def.Settings.DisallowStartIfOnBatteries = $false
$def.Principal.RunLevel = 1
$a = $def.Actions.Create(0)
$a.Path = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
$a.Arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$root\securitas-cis-audit.ps1`" -Key $Key"
$sddl = "D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;GRGX;;;$sid)"   # SYSTEM, Administrators: full; scan account: read + execute
$null = $folder.RegisterTaskDefinition("CIS Audit $Key", $def, 6, 'SYSTEM', $null, 5, $sddl)
$t = $folder.GetTask("CIS Audit $Key")
'{0} runs as {1}; security: {2}' -f $t.Path, $t.Definition.Principal.UserId, $t.GetSecurityDescriptor(4)
