<#
Records Microsoft TTD traces of the samples Sogen's TTD measurements use, so the two recorders can be compared on
recording time and trace size. Recording with ttd.exe requires administrator rights: run this from an elevated
PowerShell. On first use ttd.exe asks you to accept its EULA.

  powershell -ExecutionPolicy Bypass -File tools\msttd_record.ps1

Writes <Out>\<sample>.run (plus ttd.exe's .out log) and <Out>\results.json with native and recording wall times.
Replay-side measurements (indexing, seeks, memory queries) need no elevation and are taken afterwards with cdb.
#>
param(
    [string]$Artifacts = (Join-Path $PSScriptRoot "..\build\release\artifacts"),
    [string]$Out = (Join-Path $PSScriptRoot "..\build\msttd"),
    [string[]]$Samples = @("ttd-step-sample.exe", "test-sample.exe"),
    [int]$Runs = 3
)

$ErrorActionPreference = "Stop"
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script from an elevated PowerShell: TTD recording requires administrator rights."
}
$ttd = (Get-Command ttd.exe).Source
$Artifacts = (Resolve-Path $Artifacts).Path
New-Item -ItemType Directory -Force $Out | Out-Null
$Out = (Resolve-Path $Out).Path

function Measure-Seconds([scriptblock]$Block) {
    [math]::Round((Measure-Command $Block).TotalSeconds, 3)
}

$results = @()
Push-Location $Artifacts
try {
    foreach ($sample in $Samples) {
        $exe = Join-Path $Artifacts $sample
        $name = [IO.Path]::GetFileNameWithoutExtension($sample)
        $native = @(1..$Runs | ForEach-Object { Measure-Seconds { & $exe *> $null } })
        $recorded = @()
        foreach ($run in 1..$Runs) {
            $trace = Join-Path $Out "$name.run"
            Remove-Item "$Out\$name.*" -Force -ErrorAction SilentlyContinue
            $recorded += Measure-Seconds { & $ttd -noUI -out $trace $exe *> (Join-Path $Out "$name.console.txt") }
        }
        $results += [ordered]@{
            sample = $sample
            native_seconds = $native
            recording_seconds = $recorded
            trace_bytes = (Get-Item (Join-Path $Out "$name.run")).Length
        }
        Write-Host ("{0}: native {1} s, recording {2} s, trace {3:N1} MiB" -f $sample, ($native -join "/"),
            ($recorded -join "/"), ($results[-1].trace_bytes / 1MB))
    }
}
finally {
    Pop-Location
}
[ordered]@{
    ttd_version = (& $ttd -help 2>&1 | Select-Object -Skip 1 -First 1) -replace '^Release:\s*', ''
    machine = $env:COMPUTERNAME
    recorded_at = (Get-Date).ToString("o")
    samples = $results
} | ConvertTo-Json -Depth 4 | Set-Content -Encoding utf8 (Join-Path $Out "results.json")
Write-Host "Results: $(Join-Path $Out 'results.json')"
