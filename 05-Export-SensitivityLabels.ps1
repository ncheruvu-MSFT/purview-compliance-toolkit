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
    Write-Host "   Run: .\01-Connect-Tenant.ps1 -TenantType Source" -ForegroundColor Yellow
    exit 1
}

# ── Target-tenant safety warning ──────────────────────────────────────────────
if ($env:PURVIEW_TENANT_TYPE -eq 'Target') {
    Write-Host "⚠️  WARNING: Session is marked as TARGET tenant ($env:PURVIEW_CONNECTED_ORG)." -ForegroundColor Yellow
    Write-Host "   Export scripts should run against the SOURCE tenant. Continue only if intentional." -ForegroundColor Yellow
}

# ── Helper: flatten location objects to simple name strings ────────────
function Get-LocationNames {
    param([array]$Locations)
    if (-not $Locations) { return @() }
    @($Locations | Where-Object { $_ -ne $null } | ForEach-Object {
        if ($_ -is [string]) { $_ } else { $_.Name }
    } | Where-Object { $_ -ne $null })
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
            ExchangeLocation        = @(Get-LocationNames $policy.ExchangeLocation)
            ExchangeLocationException = @(Get-LocationNames $policy.ExchangeLocationException)
            SharePointLocation      = @(Get-LocationNames $policy.SharePointLocation)
            SharePointLocationException = @(Get-LocationNames $policy.SharePointLocationException)
            OneDriveLocation        = @(Get-LocationNames $policy.OneDriveLocation)
            OneDriveLocationException = @(Get-LocationNames $policy.OneDriveLocationException)
            ModernGroupLocation     = @(Get-LocationNames $policy.ModernGroupLocation)
            ModernGroupLocationException = @(Get-LocationNames $policy.ModernGroupLocationException)
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
