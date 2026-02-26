<#
.SYNOPSIS
    Full Purview compliance configuration backup orchestrator

.DESCRIPTION
    Runs all export scripts in the correct order to create a complete
    backup of the connected tenant's compliance configuration:

    1. Custom Sensitive Information Types (SIT rule packs + dictionaries)
    2. Sensitivity Labels + Label Policies
    3. DLP Compliance Policies + Rules
    4. Auto-Labeling Policies + Rules

    Each component exports to timestamped files in the output directory.
    A backup manifest JSON is written at the end linking all exported files.

.PARAMETER OutputPath
    Custom output directory. Defaults to ./exports/backup-<timestamp>/

.PARAMETER SkipSITs
    Skip custom SIT export

.PARAMETER SkipLabels
    Skip sensitivity label export

.PARAMETER SkipDLP
    Skip DLP policy export

.PARAMETER SkipAutoLabel
    Skip auto-labeling policy export

.EXAMPLE
    .\Backup-PurviewConfig.ps1
    # Full backup to ./exports/backup-<timestamp>/

.EXAMPLE
    .\Backup-PurviewConfig.ps1 -SkipSITs -OutputPath "C:\Backup"
    # Backup labels, DLP, auto-label only

.NOTES
    Must be connected to Security & Compliance PowerShell first.
    Run: .\01-Connect-Tenant.ps1
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath,

    [switch]$SkipSITs,
    [switch]$SkipLabels,
    [switch]$SkipDLP,
    [switch]$SkipAutoLabel
)

$ErrorActionPreference = 'Stop'
$startTime = Get-Date
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'

# ── Connection check ──────────────────────────────────────────────────
try {
    $null = Get-DlpSensitiveInformationType -Identity "Credit Card Number" -ErrorAction Stop
} catch {
    Write-Host "❌ Not connected to Security & Compliance PowerShell" -ForegroundColor Red
    Write-Host "   Run: .\01-Connect-Tenant.ps1 first" -ForegroundColor Yellow
    exit 1
}

# ── Setup output ──────────────────────────────────────────────────────
if (-not $OutputPath) {
    $OutputPath = Join-Path (Join-Path $PSScriptRoot "exports") "backup-$timestamp"
}
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  📦  Purview Compliance Configuration — Full Backup" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Output: $OutputPath" -ForegroundColor Gray
Write-Host "  Time:   $timestamp" -ForegroundColor Gray
Write-Host ""

$manifest = @{
    BackupTimestamp = $timestamp
    BackupPath      = $OutputPath
    Components      = @{}
    Errors          = @()
}

$components = @(
    @{ Name = 'CustomSITs';     Skip = $SkipSITs;      Script = '03-Export-Custom-SITs.ps1';       Label = 'Custom SITs' }
    @{ Name = 'Labels';         Skip = $SkipLabels;     Script = '05-Export-SensitivityLabels.ps1'; Label = 'Sensitivity Labels' }
    @{ Name = 'DLPPolicies';    Skip = $SkipDLP;        Script = '07-Export-DlpPolicies.ps1';      Label = 'DLP Policies' }
    @{ Name = 'AutoLabeling';   Skip = $SkipAutoLabel;  Script = '09-Export-AutoLabelPolicies.ps1'; Label = 'Auto-Labeling Policies' }
)

$step = 0
$total = ($components | Where-Object { -not $_.Skip }).Count

foreach ($comp in $components) {
    if ($comp.Skip) {
        Write-Host "⏩ Skipping $($comp.Label)" -ForegroundColor DarkGray
        $manifest.Components[$comp.Name] = @{ Status = 'Skipped' }
        continue
    }
    
    $step++
    Write-Host "" -ForegroundColor White
    Write-Host "───────────────────────────────────────────────────────────" -ForegroundColor DarkCyan
    Write-Host "  [$step/$total] $($comp.Label)" -ForegroundColor White
    Write-Host "───────────────────────────────────────────────────────────" -ForegroundColor DarkCyan
    Write-Host ""
    
    $scriptPath = Join-Path $PSScriptRoot $comp.Script
    if (-not (Test-Path $scriptPath)) {
        Write-Host "   ⚠️  Script not found: $($comp.Script)" -ForegroundColor Yellow
        $manifest.Components[$comp.Name] = @{ Status = 'NotFound'; Script = $comp.Script }
        $manifest.Errors += "Script not found: $($comp.Script)"
        continue
    }
    
    try {
        & $scriptPath -OutputPath $OutputPath
        $manifest.Components[$comp.Name] = @{ Status = 'Success'; Script = $comp.Script }
    } catch {
        Write-Host "   ❌ $($comp.Label) export failed: $($_.Exception.Message)" -ForegroundColor Red
        $manifest.Components[$comp.Name] = @{ Status = 'Failed'; Error = $_.Exception.Message }
        $manifest.Errors += "$($comp.Label): $($_.Exception.Message)"
    }
}

# ── Write manifest ────────────────────────────────────────────────────
$elapsed = (Get-Date) - $startTime
$manifest.ElapsedSeconds = [math]::Round($elapsed.TotalSeconds, 1)
$manifest.CompletedAt    = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

$manifestFile = Join-Path $OutputPath "backup-manifest.json"
$manifest | ConvertTo-Json -Depth 5 | Out-File -FilePath $manifestFile -Encoding UTF8 -Force

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  ✅  Backup Complete!" -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
Write-Host "  📁 Output:   $OutputPath" -ForegroundColor White
Write-Host "  📄 Manifest: $manifestFile" -ForegroundColor White
Write-Host "  ⏱️  Duration: $($elapsed.Minutes)m $($elapsed.Seconds)s" -ForegroundColor Gray
Write-Host ""

if ($manifest.Errors.Count -gt 0) {
    Write-Host "  ⚠️  $($manifest.Errors.Count) error(s) occurred during backup:" -ForegroundColor Yellow
    foreach ($err in $manifest.Errors) {
        Write-Host "     • $err" -ForegroundColor Yellow
    }
    Write-Host ""
}

Write-Host "💡 To restore this backup on another tenant:" -ForegroundColor Yellow
Write-Host "   .\Restore-PurviewConfig.ps1 -BackupPath '$OutputPath'" -ForegroundColor Yellow
