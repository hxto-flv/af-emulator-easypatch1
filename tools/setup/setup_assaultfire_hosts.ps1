# Assault Fire PH local-host mappings
# Run PowerShell as Administrator.
#
# This script:
#   - backs up the current Windows hosts file
#   - removes old/conflicting entries for the three AF PH hostnames
#   - adds the localhost mappings once
#   - flushes the Windows DNS cache
#
# It does not modify Assault Fire binaries or game assets.

$ErrorActionPreference = "Stop"

$HostsPath = Join-Path $env:SystemRoot "System32\drivers\etc\hosts"
$Stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$BackupPath = "$HostsPath.assaultfire_$Stamp.bak"

$Mappings = [ordered]@{
    "tversion.levelupgames.ph"   = "127.0.0.1"
    "tauthproxy.levelupgames.ph" = "127.0.0.1"
    "tdir.levelupgames.ph"       = "127.0.0.1"
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)

if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Please run PowerShell as Administrator."
}

Write-Host "[AF] Hosts file: $HostsPath"

Copy-Item -LiteralPath $HostsPath -Destination $BackupPath -Force
Write-Host "[AF] Backup:     $BackupPath"

$lines = Get-Content -LiteralPath $HostsPath -ErrorAction Stop

$filtered = foreach ($line in $lines) {
    $trimmed = $line.Trim()

    if ($trimmed.Length -eq 0 -or $trimmed.StartsWith("#")) {
        $line
        continue
    }

    $content = ($line -split "#", 2)[0].Trim()
    if ($content.Length -eq 0) {
        $line
        continue
    }

    $parts = $content -split "\s+"
    if ($parts.Count -lt 2) {
        $line
        continue
    }

    $names = @(
        $parts[1..($parts.Count - 1)] |
        ForEach-Object { $_.ToLowerInvariant() }
    )

    $conflict = $false
    foreach ($name in $Mappings.Keys) {
        if ($names -contains $name.ToLowerInvariant()) {
            $conflict = $true
            break
        }
    }

    if (-not $conflict) {
        $line
    }
}

$out = [System.Collections.Generic.List[string]]::new()

foreach ($line in $filtered) {
    $out.Add([string]$line)
}

if ($out.Count -gt 0 -and $out[$out.Count - 1].Trim().Length -ne 0) {
    $out.Add("")
}

$out.Add("# Assault Fire PH local emulator services")

foreach ($name in $Mappings.Keys) {
    $out.Add(("{0,-15} {1}" -f $Mappings[$name], $name))
}

[System.IO.File]::WriteAllLines(
    $HostsPath,
    $out,
    [System.Text.Encoding]::ASCII
)

ipconfig /flushdns | Out-Null

Write-Host ""
Write-Host "[AF] Installed mappings:"

foreach ($name in $Mappings.Keys) {
    Write-Host ("     {0,-15} {1}" -f $Mappings[$name], $name)
}

Write-Host ""
Write-Host "[AF] Backup saved to:"
Write-Host "     $BackupPath"
