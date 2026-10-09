<#
Runs WinDbg's cdb on a Microsoft TTD trace (no elevation needed) and prints the elapsed time and the log. Commands are
separated by ';' and passed through a command file, so quoted arguments survive. cdb sometimes hangs while unloading
extensions on exit, so this waits for a marker after the last command and then ends cdb.

  tools\msttd_cdb.ps1 -Trace build\msttd\test-sample.run -Commands 'dx @$curprocess.TTD.Index.BuildIndex()'
  tools\msttd_cdb.ps1 -Trace build\msttd\test-sample.run -Commands '.scriptload tools\msttd_count_instructions.js; dx @$scriptContents.countInstructions(),d'
#>
param(
    [Parameter(Mandatory)][string]$Trace,
    [Parameter(Mandatory)][string]$Commands,
    [string]$Log = (Join-Path ([IO.Path]::GetTempPath()) "msttd_cdb.log"),
    [int]$TimeoutSeconds = 1800
)

$windbg = (Get-AppxPackage Microsoft.WinDbg).InstallLocation
if (-not $windbg) {
    throw "WinDbg is not installed"
}
$cdb = Join-Path $windbg "amd64\cdb.exe"
$Trace = (Resolve-Path $Trace).Path
$empty = "$Log.stdin"
Set-Content -Encoding ascii $empty ""
Remove-Item $Log, "$Log.stdout" -ErrorAction SilentlyContinue
$marker = "MSTTD_CDB_DONE"
$commandFile = "$Log.commands"
Set-Content -Encoding ascii $commandFile (($Commands -split ';\s*') + ".echo $marker")
$watch = [Diagnostics.Stopwatch]::StartNew()
$process = Start-Process $cdb -ArgumentList @("-z", "`"$Trace`"", "-logo", "`"$Log`"", "-cf", "`"$commandFile`"") `
    -NoNewWindow -PassThru -RedirectStandardInput $empty -RedirectStandardOutput "$Log.stdout"
while ($watch.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
    if ((Test-Path $Log) -and (Select-String -Path $Log -Pattern "^$marker" -Quiet)) {
        break
    }
    if ($process.HasExited) {
        break
    }
    Start-Sleep -Milliseconds 50
}
$elapsed = $watch.Elapsed.TotalSeconds
if (-not $process.HasExited) {
    Stop-Process -Id $process.Id -Force
}
"elapsed {0:N2} s" -f $elapsed
Get-Content $Log
