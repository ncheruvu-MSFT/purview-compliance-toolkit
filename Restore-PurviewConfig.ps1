<#
.SYNOPSIS
    Full Purview compliance configuration restore orchestrator

.DESCRIPTION
    Restores a complete Purview compliance configuration from backup files
    created by Backup-PurviewConfig.ps1.

    Restore order (dependency-aware):
    1. Custom Sensitive Information Types (SIT rule packs + dictionaries)
    2. Sensitivity Labels + Label Policies
    3. DLP Compliance Policies + Rules (may reference SITs and labels)
    4. Auto-Labeling Policies + Rules (reference labels)

    Reads the backup manifest to locate export files, or accepts explicit
    file paths.

.PARAMETER BackupPath
    Path to the backup directory containing the manifest and export files

.PARAMETER SkipSITs
    Skip custom SIT restore

.PARAMETER SkipLabels
    Skip sensitivity label restore

.PARAMETER SkipDLP
    Skip DLP policy restore

.PARAMETER SkipAutoLabel
    Skip auto-labeling policy restore

.PARAMETER SkipExisting
    Skip items that already exist (instead of updating them)

.PARAMETER TestMode
    Import DLP and auto-label policies in TestWithNotifications mode

.PARAMETER Force
    Suppress confirmation prompts

.PARAMETER WhatIf
    Show what would be restored without making changes

.EXAMPLE
    .\Restore-PurviewConfig.ps1 -BackupPath ".\exports\backup-20260226-120000"

.EXAMPLE
    .\Restore-PurviewConfig.ps1 -BackupPath ".\exports\backup-20260226-120000" -TestMode -SkipSITs

.NOTES
    Must be connected to the TARGET tenant's Security & Compliance PowerShell.
    Run: .\01-Connect-Tenant.ps1 -TenantType Target
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path $_ })]
    [string]$BackupPath,

    [switch]$SkipSITs,
    [switch]$SkipLabels,
    [switch]$SkipDLP,
    [switch]$SkipAutoLabel,
    [switch]$SkipExisting,
    [switch]$TestMode,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$startTime = Get-Date

# ── Connection check ──────────────────────────────────────────────────
try {
    $null = Get-DlpSensitiveInformationType -Identity "Credit Card Number" -ErrorAction Stop
} catch {
    Write-Host "❌ Not connected to Security & Compliance PowerShell" -ForegroundColor Red
    Write-Host "   Run: .\01-Connect-Tenant.ps1 -TenantType Target" -ForegroundColor Yellow
    exit 1
}

Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  🔄  Purview Compliance Configuration — Restore" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Backup: $BackupPath" -ForegroundColor Gray
Write-Host ""

# ── Load manifest ────────────────────────────────────────────────────
$manifestFile = Join-Path $BackupPath "backup-manifest.json"
$manifest = $null
if (Test-Path $manifestFile) {
    $manifest = Get-Content $manifestFile -Raw | ConvertFrom-Json
    Write-Host "  📄 Manifest found — backup from $($manifest.BackupTimestamp)" -ForegroundColor Gray
} else {
    Write-Host "  ⚠️  No manifest found — will search for export files" -ForegroundColor Yellow
}
Write-Host ""

# ── Helper: find most recent export file by pattern ───────────────────
function Find-ExportFile {
    param([string]$Pattern)
    $files = Get-ChildItem -Path $BackupPath -Filter $Pattern -ErrorAction SilentlyContinue | 
             Sort-Object LastWriteTime -Descending
    if ($files.Count -gt 0) { return $files[0].FullName }
    return $null
}

$results = @{
    SITs      = 'Skipped'
    Labels    = 'Skipped'
    DLP       = 'Skipped'
    AutoLabel = 'Skipped'
}

# ─────────────────────────────────────────────────────────────────────
# STEP 1: Restore Custom SITs
# ─────────────────────────────────────────────────────────────────────
if (-not $SkipSITs) {
    Write-Host "───────────────────────────────────────────────────────────" -ForegroundColor DarkCyan
    Write-Host "  [1/4] Custom Sensitive Information Types" -ForegroundColor White
    Write-Host "───────────────────────────────────────────────────────────" -ForegroundColor DarkCyan
    Write-Host ""
    
    $sitFiles = Get-ChildItem -Path $BackupPath -Filter "source-export-*.xml" -ErrorAction SilentlyContinue
    if ($sitFiles.Count -gt 0) {
        $importScript = Join-Path $PSScriptRoot "04-Import-Custom-SITs.ps1"
        if (Test-Path $importScript) {
            foreach ($sitFile in $sitFiles) {
                Write-Host "   📄 Importing: $($sitFile.Name)" -ForegroundColor Gray
                try {
                    $importParams = @{ InputFile = $sitFile.FullName }
                    if ($Force) { $importParams['Force'] = $true }
                    & $importScript @importParams
                } catch {
                    Write-Host "   ❌ SIT import failed: $($_.Exception.Message)" -ForegroundColor Red
                }
            }
            $results.SITs = 'Completed'
        } else {
            Write-Host "   ⚠️  04-Import-Custom-SITs.ps1 not found" -ForegroundColor Yellow
            $results.SITs = 'ScriptNotFound'
        }
    } else {
        Write-Host "   ℹ️  No SIT export files found in backup" -ForegroundColor DarkGray
        $results.SITs = 'NoFiles'
    }
    Write-Host ""
}

# ─────────────────────────────────────────────────────────────────────
# STEP 2: Restore Sensitivity Labels
# ─────────────────────────────────────────────────────────────────────
if (-not $SkipLabels) {
    Write-Host "───────────────────────────────────────────────────────────" -ForegroundColor DarkCyan
    Write-Host "  [2/4] Sensitivity Labels" -ForegroundColor White
    Write-Host "───────────────────────────────────────────────────────────" -ForegroundColor DarkCyan
    Write-Host ""
    
    $labelsFile   = Find-ExportFile "labels-export-*.json"
    $policiesFile = Find-ExportFile "label-policies-export-*.json"
    
    if ($labelsFile) {
        $importScript = Join-Path $PSScriptRoot "06-Import-SensitivityLabels.ps1"
        if (Test-Path $importScript) {
            try {
                $importParams = @{ LabelsFile = $labelsFile }
                if ($policiesFile)   { $importParams['PoliciesFile'] = $policiesFile }
                if ($SkipExisting)   { $importParams['SkipExisting'] = $true }
                if ($Force)          { $importParams['Force'] = $true }
                
                & $importScript @importParams
                $results.Labels = 'Completed'
            } catch {
                Write-Host "   ❌ Label import failed: $($_.Exception.Message)" -ForegroundColor Red
                $results.Labels = 'Failed'
            }
        } else {
            Write-Host "   ⚠️  06-Import-SensitivityLabels.ps1 not found" -ForegroundColor Yellow
            $results.Labels = 'ScriptNotFound'
        }
    } else {
        Write-Host "   ℹ️  No label export files found in backup" -ForegroundColor DarkGray
        $results.Labels = 'NoFiles'
    }
    Write-Host ""
}

# ─────────────────────────────────────────────────────────────────────
# STEP 3: Restore DLP Policies
# ─────────────────────────────────────────────────────────────────────
if (-not $SkipDLP) {
    Write-Host "───────────────────────────────────────────────────────────" -ForegroundColor DarkCyan
    Write-Host "  [3/4] DLP Policies" -ForegroundColor White
    Write-Host "───────────────────────────────────────────────────────────" -ForegroundColor DarkCyan
    Write-Host ""
    
    $dlpPoliciesFile = Find-ExportFile "dlp-policies-export-*.json"
    $dlpRulesFile    = Find-ExportFile "dlp-rules-export-*.json"
    
    if ($dlpPoliciesFile) {
        $importScript = Join-Path $PSScriptRoot "08-Import-DlpPolicies.ps1"
        if (Test-Path $importScript) {
            try {
                $importParams = @{ PoliciesFile = $dlpPoliciesFile }
                if ($dlpRulesFile)   { $importParams['RulesFile'] = $dlpRulesFile }
                if ($SkipExisting)   { $importParams['SkipExisting'] = $true }
                if ($TestMode)       { $importParams['TestMode'] = $true }
                if ($Force)          { $importParams['Force'] = $true }
                
                & $importScript @importParams
                $results.DLP = 'Completed'
            } catch {
                Write-Host "   ❌ DLP import failed: $($_.Exception.Message)" -ForegroundColor Red
                $results.DLP = 'Failed'
            }
        } else {
            Write-Host "   ⚠️  08-Import-DlpPolicies.ps1 not found" -ForegroundColor Yellow
            $results.DLP = 'ScriptNotFound'
        }
    } else {
        Write-Host "   ℹ️  No DLP export files found in backup" -ForegroundColor DarkGray
        $results.DLP = 'NoFiles'
    }
    Write-Host ""
}

# ─────────────────────────────────────────────────────────────────────
# STEP 4: Restore Auto-Labeling Policies
# ─────────────────────────────────────────────────────────────────────
if (-not $SkipAutoLabel) {
    Write-Host "───────────────────────────────────────────────────────────" -ForegroundColor DarkCyan
    Write-Host "  [4/4] Auto-Labeling Policies" -ForegroundColor White
    Write-Host "───────────────────────────────────────────────────────────" -ForegroundColor DarkCyan
    Write-Host ""
    
    $autoLabelPoliciesFile = Find-ExportFile "auto-label-policies-export-*.json"
    $autoLabelRulesFile    = Find-ExportFile "auto-label-rules-export-*.json"
    
    if ($autoLabelPoliciesFile) {
        $importScript = Join-Path $PSScriptRoot "10-Import-AutoLabelPolicies.ps1"
        if (Test-Path $importScript) {
            try {
                $importParams = @{ PoliciesFile = $autoLabelPoliciesFile }
                if ($autoLabelRulesFile) { $importParams['RulesFile'] = $autoLabelRulesFile }
                if ($SkipExisting)       { $importParams['SkipExisting'] = $true }
                if ($TestMode)           { $importParams['TestMode'] = $true }
                if ($Force)              { $importParams['Force'] = $true }
                
                & $importScript @importParams
                $results.AutoLabel = 'Completed'
            } catch {
                Write-Host "   ❌ Auto-label import failed: $($_.Exception.Message)" -ForegroundColor Red
                $results.AutoLabel = 'Failed'
            }
        } else {
            Write-Host "   ⚠️  10-Import-AutoLabelPolicies.ps1 not found" -ForegroundColor Yellow
            $results.AutoLabel = 'ScriptNotFound'
        }
    } else {
        Write-Host "   ℹ️  No auto-label export files found in backup" -ForegroundColor DarkGray
        $results.AutoLabel = 'NoFiles'
    }
    Write-Host ""
}

# ── Summary ───────────────────────────────────────────────────────────
$elapsed = (Get-Date) - $startTime

Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  ✅  Restore Complete!" -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Custom SITs:      $($results.SITs)" -ForegroundColor $(if($results.SITs -eq 'Completed'){'Green'}elseif($results.SITs -eq 'Failed'){'Red'}else{'DarkGray'})
Write-Host "  Labels:           $($results.Labels)" -ForegroundColor $(if($results.Labels -eq 'Completed'){'Green'}elseif($results.Labels -eq 'Failed'){'Red'}else{'DarkGray'})
Write-Host "  DLP Policies:     $($results.DLP)" -ForegroundColor $(if($results.DLP -eq 'Completed'){'Green'}elseif($results.DLP -eq 'Failed'){'Red'}else{'DarkGray'})
Write-Host "  Auto-Labeling:    $($results.AutoLabel)" -ForegroundColor $(if($results.AutoLabel -eq 'Completed'){'Green'}elseif($results.AutoLabel -eq 'Failed'){'Red'}else{'DarkGray'})
Write-Host ""
Write-Host "  ⏱️  Duration: $($elapsed.Minutes)m $($elapsed.Seconds)s" -ForegroundColor Gray
Write-Host ""

if ($TestMode) {
    Write-Host "💡 DLP and auto-labeling policies were imported in TestWithNotifications mode." -ForegroundColor Yellow
    Write-Host "   Review in the Purview portal before switching to Enforce mode." -ForegroundColor Yellow
    Write-Host ""
}
