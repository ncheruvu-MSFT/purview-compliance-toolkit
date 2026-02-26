<#
.SYNOPSIS
    Export sensitivity labels and label policies to JSON files

.DESCRIPTION
    Exports all sensitivity labels and their publishing policies from the
    connected tenant to JSON files for backup, disaster recovery, or
    environment replication.

    Exported artefacts:
    • Sensitivity labels  → labels-export-<timestamp>.json
    • Label policies      → label-policies-export-<timestamp>.json

.PARAMETER OutputPath
    Optional custom output directory. Defaults to ./exports/

.EXAMPLE
    .\05-Export-SensitivityLabels.ps1
    # Exports to ./exports/

.EXAMPLE
    .\05-Export-SensitivityLabels.ps1 -OutputPath "C:\Backup\Purview"
    # Exports to custom directory

.NOTES
    Must be connected to Security & Compliance PowerShell first.
    Run: .\01-Connect-Tenant.ps1
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath
)

# ── Connection check ──────────────────────────────────────────────────
try {
    $null = Get-DlpSensitiveInformationType -Identity "Credit Card Number" -ErrorAction Stop
} catch {
    Write-Host "❌ Not connected to Security & Compliance PowerShell" -ForegroundColor Red
    Write-Host "   Run: .\01-Connect-Tenant.ps1 first" -ForegroundColor Yellow
    exit 1
}

Write-Host "🏷️  Exporting sensitivity labels and label policies..." -ForegroundColor Cyan
Write-Host ""

# ── Resolve output directory ─────────────────────────────────────────
if (-not $OutputPath) {
    $OutputPath = Join-Path $PSScriptRoot "exports"
}
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'

# ─────────────────────────────────────────────────────────────────────
# STEP 1: Export sensitivity labels
# ─────────────────────────────────────────────────────────────────────
Write-Host "⏳ Step 1: Exporting sensitivity labels..." -ForegroundColor Yellow

$labels = @(Get-Label -IncludeDetailedLabelActions -ErrorAction Stop)

if ($labels.Count -eq 0) {
    Write-Host "   ℹ️  No sensitivity labels found in this tenant" -ForegroundColor DarkGray
} else {
    Write-Host "   📋 Found $($labels.Count) sensitivity label(s):" -ForegroundColor Gray

    $labelExport = @()
    foreach ($label in $labels) {
        Write-Host "      • $($label.DisplayName) $(if($label.ParentId){'(sublabel)'})" -ForegroundColor Gray

        $labelExport += @{
            Identity          = $label.Identity
            DisplayName       = $label.DisplayName
            Name              = $label.Name
            Guid              = $label.Guid.ToString()
            ParentId          = $label.ParentId
            Priority          = $label.Priority
            Tooltip           = $label.Tooltip
            Comment           = $label.Comment
            Disabled          = $label.Disabled
            ContentType       = $label.ContentType
            Settings          = $label.Settings
            LocaleSettings    = $label.LocaleSettings
            AdvancedSettings  = $label.AdvancedSettings
            Conditions        = $label.Conditions
            EncryptionEnabled = $label.EncryptionEnabled
            LabelActions      = $label.LabelActions
        }
    }

    $labelsFile = Join-Path $OutputPath "labels-export-$timestamp.json"
    $labelExport | ConvertTo-Json -Depth 10 | Out-File -FilePath $labelsFile -Encoding UTF8 -Force

    Write-Host ""
    Write-Host "   ✅ Exported $($labels.Count) label(s) to:" -ForegroundColor Green
    Write-Host "      $labelsFile" -ForegroundColor Gray
}
Write-Host ""

# ─────────────────────────────────────────────────────────────────────
# STEP 2: Export label policies (publishing policies)
# ─────────────────────────────────────────────────────────────────────
Write-Host "⏳ Step 2: Exporting label policies..." -ForegroundColor Yellow

$policies = @(Get-LabelPolicy -ErrorAction Stop)

if ($policies.Count -eq 0) {
    Write-Host "   ℹ️  No label policies found in this tenant" -ForegroundColor DarkGray
} else {
    Write-Host "   📋 Found $($policies.Count) label policy(ies):" -ForegroundColor Gray

    $policyExport = @()
    foreach ($policy in $policies) {
        Write-Host "      • $($policy.Name) (Labels: $($policy.Labels.Count), Enabled: $(-not $policy.Disabled))" -ForegroundColor Gray

        $policyExport += @{
            Identity                = $policy.Identity
            Name                    = $policy.Name
            Guid                    = $policy.Guid.ToString()
            Comment                 = $policy.Comment
            Enabled                 = -not $policy.Disabled
            Labels                  = @($policy.Labels)
            ExchangeLocation        = @($policy.ExchangeLocation)
            ExchangeLocationException = @($policy.ExchangeLocationException)
            SharePointLocation      = @($policy.SharePointLocation)
            SharePointLocationException = @($policy.SharePointLocationException)
            OneDriveLocation        = @($policy.OneDriveLocation)
            OneDriveLocationException = @($policy.OneDriveLocationException)
            ModernGroupLocation     = @($policy.ModernGroupLocation)
            ModernGroupLocationException = @($policy.ModernGroupLocationException)
            Settings                = $policy.Settings
            AdvancedSettings        = $policy.AdvancedSettings
        }
    }

    $policiesFile = Join-Path $OutputPath "label-policies-export-$timestamp.json"
    $policyExport | ConvertTo-Json -Depth 10 | Out-File -FilePath $policiesFile -Encoding UTF8 -Force

    Write-Host ""
    Write-Host "   ✅ Exported $($policies.Count) label policy(ies) to:" -ForegroundColor Green
    Write-Host "      $policiesFile" -ForegroundColor Gray
}
Write-Host ""

# ── Summary ───────────────────────────────────────────────────────────
Write-Host "✅ Sensitivity label export complete!" -ForegroundColor Green
Write-Host ""
Write-Host "   Labels:   $($labels.Count)" -ForegroundColor White
Write-Host "   Policies: $($policies.Count)" -ForegroundColor White
Write-Host "   Output:   $OutputPath" -ForegroundColor Gray
Write-Host ""
Write-Host "💡 Next steps:" -ForegroundColor Yellow
Write-Host "   • To restore/replicate: .\06-Import-SensitivityLabels.ps1" -ForegroundColor Gray
Write-Host "   • Review exported JSON files before importing to another tenant" -ForegroundColor Gray
