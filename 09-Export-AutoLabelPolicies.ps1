<#
.SYNOPSIS
    Export auto-labeling policies and rules to JSON files

.DESCRIPTION
    Exports all auto-labeling (auto-classification) policies and their
    associated rules from the connected tenant to JSON files for backup,
    disaster recovery, or environment replication.

    Exported artefacts:
    • Auto-label policies  → auto-label-policies-export-<timestamp>.json
    • Auto-label rules     → auto-label-rules-export-<timestamp>.json

.PARAMETER OutputPath
    Optional custom output directory. Defaults to ./exports/

.EXAMPLE
    .\09-Export-AutoLabelPolicies.ps1

.EXAMPLE
    .\09-Export-AutoLabelPolicies.ps1 -OutputPath "C:\Backup\Purview"

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

# ── Helper: flatten location objects to simple name strings ────────────
function Get-LocationNames {
    param([array]$Locations)
    if (-not $Locations) { return @() }
    @($Locations | Where-Object { $_ -ne $null } | ForEach-Object {
        if ($_ -is [string]) { $_ } else { $_.Name }
    } | Where-Object { $_ -ne $null })
}

Write-Host "🏷️  Exporting auto-labeling policies and rules..." -ForegroundColor Cyan
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
# STEP 1: Export auto-labeling policies
# ─────────────────────────────────────────────────────────────────────
Write-Host "⏳ Step 1: Exporting auto-labeling policies..." -ForegroundColor Yellow

$policies = @(Get-AutoSensitivityLabelPolicy -ErrorAction Stop)

if ($policies.Count -eq 0) {
    Write-Host "   ℹ️  No auto-labeling policies found in this tenant" -ForegroundColor DarkGray
} else {
    Write-Host "   📋 Found $($policies.Count) auto-labeling policy(ies):" -ForegroundColor Gray

    $policyExport = @()
    foreach ($policy in $policies) {
        Write-Host "      • $($policy.Name) (Mode: $($policy.Mode), Enabled: $($policy.Enabled))" -ForegroundColor Gray

        $policyExport += @{
            Identity                       = $policy.Identity
            Name                           = $policy.Name
            Guid                           = $policy.Guid.ToString()
            Comment                        = $policy.Comment
            Enabled                        = $policy.Enabled
            Mode                           = $policy.Mode
            Priority                       = $policy.Priority
            ApplySensitivityLabel          = $policy.ApplySensitivityLabel
            ExchangeLocation               = @(Get-LocationNames $policy.ExchangeLocation)
            ExchangeLocationException      = @(Get-LocationNames $policy.ExchangeLocationException)
            SharePointLocation             = @(Get-LocationNames $policy.SharePointLocation)
            SharePointLocationException    = @(Get-LocationNames $policy.SharePointLocationException)
            OneDriveLocation               = @(Get-LocationNames $policy.OneDriveLocation)
            OneDriveLocationException      = @(Get-LocationNames $policy.OneDriveLocationException)
            ExternalMailRightsManagementOwner = $policy.ExternalMailRightsManagementOwner
            OverwriteLabel                 = $policy.OverwriteLabel
            WhenCreated                    = $policy.WhenCreated
            WhenChanged                    = $policy.WhenChanged
        }
    }

    $policiesFile = Join-Path $OutputPath "auto-label-policies-export-$timestamp.json"
    $policyExport | ConvertTo-Json -Depth 10 | Out-File -FilePath $policiesFile -Encoding UTF8 -Force
    Write-Host ""
    Write-Host "   ✅ Exported $($policies.Count) auto-labeling policy(ies) to:" -ForegroundColor Green
    Write-Host "      $policiesFile" -ForegroundColor Gray
}
Write-Host ""

# ─────────────────────────────────────────────────────────────────────
# STEP 2: Export auto-labeling rules
# ─────────────────────────────────────────────────────────────────────
Write-Host "⏳ Step 2: Exporting auto-labeling rules..." -ForegroundColor Yellow

$rules = @(Get-AutoSensitivityLabelRule -ErrorAction Stop)

if ($rules.Count -eq 0) {
    Write-Host "   ℹ️  No auto-labeling rules found in this tenant" -ForegroundColor DarkGray
} else {
    Write-Host "   📋 Found $($rules.Count) auto-labeling rule(s):" -ForegroundColor Gray

    $ruleExport = @()
    foreach ($rule in $rules) {
        Write-Host "      • $($rule.Name) (Policy: $($rule.ParentPolicyName), Disabled: $($rule.Disabled))" -ForegroundColor Gray

        $ruleExport += @{
            Identity                       = $rule.Identity
            Name                           = $rule.Name
            Guid                           = $rule.Guid.ToString()
            ParentPolicyName               = $rule.ParentPolicyName
            Priority                       = $rule.Priority
            Disabled                       = $rule.Disabled
            Comment                        = $rule.Comment
            Workload                       = $rule.Workload
            ContentContainsSensitiveInformation  = $rule.ContentContainsSensitiveInformation
            ExceptIfContentContainsSensitiveInformation = $rule.ExceptIfContentContainsSensitiveInformation
            ContentPropertyContainsWords   = $rule.ContentPropertyContainsWords
            HeaderMatchesPatterns          = $rule.HeaderMatchesPatterns
            SubjectMatchesPatterns         = $rule.SubjectMatchesPatterns
            FromAddressMatchesPatterns     = $rule.FromAddressMatchesPatterns
            SenderIPRanges                 = $rule.SenderIPRanges
            RecipientDomainIs              = $rule.RecipientDomainIs
            SentTo                         = $rule.SentTo
            AnyOfRecipientAddressMatchesPatterns = $rule.AnyOfRecipientAddressMatchesPatterns
            DocumentIsUnsupported          = $rule.DocumentIsUnsupported
            DocumentIsPasswordProtected    = $rule.DocumentIsPasswordProtected
            DocumentNameMatchesPatterns    = $rule.DocumentNameMatchesPatterns
            ContentExtensionMatchesWords   = $rule.ContentExtensionMatchesWords
        }
    }

    $rulesFile = Join-Path $OutputPath "auto-label-rules-export-$timestamp.json"
    $ruleExport | ConvertTo-Json -Depth 10 | Out-File -FilePath $rulesFile -Encoding UTF8 -Force
    Write-Host ""
    Write-Host "   ✅ Exported $($rules.Count) auto-labeling rule(s) to:" -ForegroundColor Green
    Write-Host "      $rulesFile" -ForegroundColor Gray
}
Write-Host ""

# ── Summary ───────────────────────────────────────────────────────────
Write-Host "✅ Auto-labeling export complete!" -ForegroundColor Green
Write-Host ""
Write-Host "   Policies: $($policies.Count)" -ForegroundColor White
Write-Host "   Rules:    $($rules.Count)" -ForegroundColor White
Write-Host ""
Write-Host "💡 Next step: Import with .\10-Import-AutoLabelPolicies.ps1" -ForegroundColor Yellow
