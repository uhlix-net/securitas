# Securitas compliance check for Windows. Install as C:\Program Files\Securitas\CIS\securitas-cis-audit.ps1
# (writable by Administrators only). Run as SYSTEM by the scheduled task "\Securitas\CIS Audit <key>" that
# Install-SecuritasCisTask.ps1 creates. Runs the benchmark's run_audit.ps1 (syver, read-only) and writes
# <key>.json and <key>.log to C:\ProgramData\Securitas\CIS.
param([Parameter(Mandatory = $true)][ValidatePattern('^[A-Za-z0-9][A-Za-z0-9.-]*$')][string]$Key)
$ErrorActionPreference = 'Stop'
$root = 'C:\Program Files\Securitas\CIS'
$outDir = 'C:\ProgramData\Securitas\CIS'
$log = Join-Path $outDir ($Key + '.log')
$tmp = Join-Path $outDir ($Key + '.json.tmp')
$out = Join-Path $outDir ($Key + '.json')
$dir = Join-Path $root $Key
$content = Get-ChildItem -LiteralPath $dir -Directory -Filter '*-CIS-Audit' -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $content) { "benchmark $Key is not installed on this host" | Set-Content -LiteralPath $log; exit 3 }
$env:AUDIT_CONTENT_LOCATION = $dir
$env:AUDIT_BIN = Join-Path $root 'syver\syver.exe'
Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
try {
  & (Join-Path $content.FullName 'run_audit.ps1') -Format json -SystemType Server -OutFile $tmp *> $log
  Move-Item -LiteralPath $tmp -Destination $out -Force
} catch {
  $_ | Out-String | Add-Content -LiteralPath $log
  exit 1
}
