<#
.SYNOPSIS
    Import auto-labeling policies and rules from JSON backup files

.DESCRIPTION
    Recreates auto-labeling (auto-classification) policies and their
    associated rules on the target tenant from JSON files produced by
    09-Export-AutoLabelPolicies.ps1.

    Import order:
    1. Auto-labeling policies (must exist before rules)
    2. Auto-labeling rules (linked to their parent policy by name)

    Sensitivity labels referenced by auto-labeling policies must already
    exist on the target tenant. Run 06-Import-SensitivityLabels.ps1 first.

.PARAMETER PoliciesFile
    Path to the auto-label policies JSON export file

.PARAMETER RulesFile
    Optional path to the auto-label rules JSON export file

.PARAMETER LabelGuidMap
    Optional hashtable mapping source label GUIDs to target label GUIDs.
    If not provided, policies will reference labels by their original GUID
    (works only if labels were imported with the same GUID).

.PARAMETER SkipExisting
    Skip policies/rules that already exist on the target

.PARAMETER TestMode
    Import policies in TestWithNotifications mode

.PARAMETER Force
    Suppress confirmation prompts

.PARAMETER WhatIf
    Show what would be imported without making changes

.EXAMPLE
    .\10-Import-AutoLabelPolicies.ps1 -PoliciesFile ".\exports\auto-label-policies-export-20260226-120000.json" -RulesFile ".\exports\auto-label-rules-export-20260226-120000.json"

.NOTES
    Must be connected to the TARGET tenant's Security & Compliance PowerShell.
    Run: .\01-Connect-Tenant.ps1 -TenantType Target
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path $_ })]
    [string]$PoliciesFile,

    [Parameter(Mandatory = $false)]
    [ValidateScript({ Test-Path $_ })]
    [string]$RulesFile,

    [Parameter(Mandatory = $false)]
    [hashtable]$LabelGuidMap = @{},

    [switch]$SkipExisting,
    [switch]$TestMode,
    [switch]$Force
)

# ── Connection check ──────────────────────────────────────────────────
try {
    $null = Get-DlpSensitiveInformationType -Identity "Credit Card Number" -ErrorAction Stop
} catch {
    Write-Host "❌ Not connected to Security & Compliance PowerShell" -ForegroundColor Red
    Write-Host "   Run: .\01-Connect-Tenant.ps1 -TenantType Target" -ForegroundColor Yellow
    exit 1
}

# ── Source-tenant safety guard ────────────────────────────────────────────────
if ($env:PURVIEW_TENANT_TYPE -eq 'Source') {
    Write-Host "❌ SAFETY BLOCK: Session is marked as SOURCE tenant ($env:PURVIEW_CONNECTED_ORG)." -ForegroundColor Red
    Write-Host "   Import scripts must ONLY run against the TARGET tenant." -ForegroundColor Red
    Write-Host "   Reconnect: .\01-Connect-Tenant.ps1 -TenantType Target" -ForegroundColor Yellow
    exit 1
}
if (-not $env:PURVIEW_TENANT_TYPE) {
    Write-Host "⚠️  Tenant type not confirmed — connect via .\01-Connect-Tenant.ps1 -TenantType Target to enable safety checks." -ForegroundColor Yellow
}

# ── Helper: safe JSON import (handles case-conflicting keys from older exports) ─
function ConvertFrom-JsonSafe {
    param([string]$JsonText)
    try {
        return $JsonText | ConvertFrom-Json
    } catch {
        if ($_.Exception.Message -match 'different casing') {
            $cleaned = [regex]::Replace($JsonText, '"value"\s*:\s*\d+\s*,\s*', '')
            return $cleaned | ConvertFrom-Json
        }
        throw
    }
}

# ── Helper: extract location names from complex objects or strings ────
function Get-LocationNames {
    param([array]$Locations)
    if (-not $Locations) { return @() }
    @($Locations | Where-Object { $_ -ne $null } | ForEach-Object {
        if ($_ -is [string]) { $_ }
        elseif ($_ -is [hashtable]) { $_.Name }
        else { $_.Name }
    } | Where-Object { $_ -ne $null })
}

Write-Host "🏷️  Importing auto-labeling policies to TARGET tenant..." -ForegroundColor Cyan
Write-Host ""
Write-Host "   Policies file: $PoliciesFile" -ForegroundColor Gray
if ($RulesFile)  { Write-Host "   Rules file:    $RulesFile" -ForegroundColor Gray }
if ($TestMode)   { Write-Host "   ⚠️  Test mode:   Policies will be created in TestWithNotifications mode" -ForegroundColor Yellow }
Write-Host ""

# ─────────────────────────────────────────────────────────────────────
# STEP 1: Load source data
# ─────────────────────────────────────────────────────────────────────
Write-Host "⏳ Step 1: Loading auto-labeling policy definitions..." -ForegroundColor Yellow

$sourcePolicies = ConvertFrom-JsonSafe (Get-Content $PoliciesFile -Raw)
Write-Host "   📋 Found $($sourcePolicies.Count) policy(ies) in export file" -ForegroundColor Gray

$sourceRules = @()
if ($RulesFile) {
    $sourceRules = ConvertFrom-JsonSafe (Get-Content $RulesFile -Raw)
    Write-Host "   📋 Found $($sourceRules.Count) rule(s) in export file" -ForegroundColor Gray
}
Write-Host ""

# ─────────────────────────────────────────────────────────────────────
# STEP 2: Import auto-labeling policies
# ─────────────────────────────────────────────────────────────────────
Write-Host "⏳ Step 2: Importing auto-labeling policies..." -ForegroundColor Yellow

$created  = 0
$updated  = 0
$skipped  = 0
$failures = 0

foreach ($policy in $sourcePolicies) {
    $policyName = $policy.Name
    
    if ($PSCmdlet.ShouldProcess($policyName, "Import auto-labeling policy")) {
        # Resolve the sensitivity label GUID for the target tenant
        $targetLabelGuid = $policy.ApplySensitivityLabel
        if ($LabelGuidMap.ContainsKey($policy.ApplySensitivityLabel)) {
            $targetLabelGuid = $LabelGuidMap[$policy.ApplySensitivityLabel]
            Write-Host "   🔗 Remapped label GUID: $($policy.ApplySensitivityLabel) → $targetLabelGuid" -ForegroundColor DarkGray
        }
        
        $existing = Get-AutoSensitivityLabelPolicy -Identity $policyName -ErrorAction SilentlyContinue
        
        if ($existing) {
            if ($SkipExisting) {
                Write-Host "   ⏩ $policyName (already exists — skipped)" -ForegroundColor DarkGray
                $skipped++
                continue
            }
            
            try {
                $setParams = @{ Identity = $policyName }
                if ($policy.Comment)            { $setParams['Comment'] = $policy.Comment }
                if ($targetLabelGuid)           { $setParams['ApplySensitivityLabel'] = $targetLabelGuid }
                if ($TestMode)                  { $setParams['Mode'] = 'TestWithNotifications' }
                if ($null -ne $policy.OverwriteLabel) { $setParams['OverwriteLabel'] = $policy.OverwriteLabel }
                
                Set-AutoSensitivityLabelPolicy @setParams -ErrorAction Stop
                Write-Host "   🔄 $policyName (updated)" -ForegroundColor Cyan
                $updated++
            } catch {
                Write-Host "   ❌ $policyName — update failed: $($_.Exception.Message)" -ForegroundColor Red
                $failures++
            }
        } else {
            try {
                $newParams = @{
                    Name                    = $policyName
                    ApplySensitivityLabel   = $targetLabelGuid
                }
                if ($policy.Comment)  { $newParams['Comment'] = $policy.Comment }
                if ($TestMode) {
                    $newParams['Mode'] = 'TestWithNotifications'
                } elseif ($policy.Mode) {
                    $newParams['Mode'] = $policy.Mode
                }
                if ($null -ne $policy.OverwriteLabel) {
                    $newParams['OverwriteLabel'] = $policy.OverwriteLabel
                }
                
                # Location parameters
                $exchLoc = Get-LocationNames $policy.ExchangeLocation
                if ($exchLoc.Count -gt 0) { $newParams['ExchangeLocation'] = $exchLoc }
                $spLoc = Get-LocationNames $policy.SharePointLocation
                if ($spLoc.Count -gt 0) { $newParams['SharePointLocation'] = $spLoc }
                $odLoc = Get-LocationNames $policy.OneDriveLocation
                if ($odLoc.Count -gt 0) { $newParams['OneDriveLocation'] = $odLoc }
                if ($policy.ExternalMailRightsManagementOwner) {
                    $newParams['ExternalMailRightsManagementOwner'] = $policy.ExternalMailRightsManagementOwner
                }
                
                New-AutoSensitivityLabelPolicy @newParams -ErrorAction Stop
                Write-Host "   ✅ $policyName (created)" -ForegroundColor Green
                $created++
                Start-Sleep -Seconds 2
            } catch {
                Write-Host "   ❌ $policyName — create failed: $($_.Exception.Message)" -ForegroundColor Red
                $failures++
            }
        }
    }
}
Write-Host ""

# ─────────────────────────────────────────────────────────────────────
# STEP 3: Import auto-labeling rules
# ─────────────────────────────────────────────────────────────────────
if ($sourceRules.Count -gt 0) {
    Write-Host "⏳ Step 3: Importing auto-labeling rules..." -ForegroundColor Yellow
    
    $rCreated  = 0
    $rUpdated  = 0
    $rSkipped  = 0
    $rFailures = 0
    
    foreach ($rule in $sourceRules) {
        $ruleName   = $rule.Name
        $policyName = $rule.ParentPolicyName
        
        if ($PSCmdlet.ShouldProcess($ruleName, "Import auto-labeling rule")) {
            # Verify parent policy exists
            $parentPolicy = Get-AutoSensitivityLabelPolicy -Identity $policyName -ErrorAction SilentlyContinue
            if (-not $parentPolicy) {
                Write-Host "   ❌ $ruleName — parent policy '$policyName' not found on target" -ForegroundColor Red
                $rFailures++
                continue
            }
            
            $existing = Get-AutoSensitivityLabelRule -Identity $ruleName -ErrorAction SilentlyContinue
            
            if ($existing) {
                if ($SkipExisting) {
                    Write-Host "   ⏩ $ruleName (already exists — skipped)" -ForegroundColor DarkGray
                    $rSkipped++
                    continue
                }
                
                try {
                    $setParams = @{ Identity = $ruleName }
                    if ($null -ne $rule.Disabled)  { $setParams['Disabled'] = $rule.Disabled }
                    if ($rule.Comment)             { $setParams['Comment'] = $rule.Comment }
                    if ($rule.ContentContainsSensitiveInformation) {
                        $setParams['ContentContainsSensitiveInformation'] = $rule.ContentContainsSensitiveInformation
                    }
                    if ($rule.HeaderMatchesPatterns)       { $setParams['HeaderMatchesPatterns'] = $rule.HeaderMatchesPatterns }
                    if ($rule.SubjectMatchesPatterns)      { $setParams['SubjectMatchesPatterns'] = $rule.SubjectMatchesPatterns }
                    if ($rule.DocumentNameMatchesPatterns) { $setParams['DocumentNameMatchesPatterns'] = $rule.DocumentNameMatchesPatterns }
                    
                    Set-AutoSensitivityLabelRule @setParams -ErrorAction Stop
                    Write-Host "   🔄 $ruleName (updated)" -ForegroundColor Cyan
                    $rUpdated++
                } catch {
                    Write-Host "   ❌ $ruleName — update failed: $($_.Exception.Message)" -ForegroundColor Red
                    $rFailures++
                }
            } else {
                try {
                    $newParams = @{
                        Name   = $ruleName
                        Policy = $policyName
                    }
                    if ($null -ne $rule.Disabled)  { $newParams['Disabled'] = $rule.Disabled }
                    if ($rule.Comment)             { $newParams['Comment'] = $rule.Comment }
                    if ($rule.Workload)            { $newParams['Workload'] = $rule.Workload }
                    if ($rule.ContentContainsSensitiveInformation) {
                        $newParams['ContentContainsSensitiveInformation'] = $rule.ContentContainsSensitiveInformation
                    }
                    if ($rule.ContentPropertyContainsWords) {
                        $newParams['ContentPropertyContainsWords'] = $rule.ContentPropertyContainsWords
                    }
                    if ($rule.HeaderMatchesPatterns)          { $newParams['HeaderMatchesPatterns'] = $rule.HeaderMatchesPatterns }
                    if ($rule.SubjectMatchesPatterns)         { $newParams['SubjectMatchesPatterns'] = $rule.SubjectMatchesPatterns }
                    if ($rule.FromAddressMatchesPatterns)     { $newParams['FromAddressMatchesPatterns'] = $rule.FromAddressMatchesPatterns }
                    if ($rule.SenderIPRanges)                 { $newParams['SenderIPRanges'] = $rule.SenderIPRanges }
                    if ($rule.RecipientDomainIs)              { $newParams['RecipientDomainIs'] = $rule.RecipientDomainIs }
                    if ($rule.SentTo)                         { $newParams['SentTo'] = $rule.SentTo }
                    if ($rule.DocumentNameMatchesPatterns)    { $newParams['DocumentNameMatchesPatterns'] = $rule.DocumentNameMatchesPatterns }
                    if ($rule.ContentExtensionMatchesWords)   { $newParams['ContentExtensionMatchesWords'] = $rule.ContentExtensionMatchesWords }
                    
                    New-AutoSensitivityLabelRule @newParams -ErrorAction Stop
                    Write-Host "   ✅ $ruleName → $policyName (created)" -ForegroundColor Green
                    $rCreated++
                    Start-Sleep -Seconds 1
                } catch {
                    Write-Host "   ❌ $ruleName — create failed: $($_.Exception.Message)" -ForegroundColor Red
                    $rFailures++
                }
            }
        }
    }
    Write-Host ""
} else {
    Write-Host "⏩ Step 3: No rules file specified — skipping rule import" -ForegroundColor DarkGray
    Write-Host ""
}

# ── Summary ───────────────────────────────────────────────────────────
Write-Host "✅ Auto-labeling import complete!" -ForegroundColor Green
Write-Host ""
Write-Host "   Policies — Created: $created | Updated: $updated | Skipped: $skipped | Failed: $failures" -ForegroundColor White
if ($sourceRules.Count -gt 0) {
    Write-Host "   Rules    — Created: $rCreated | Updated: $rUpdated | Skipped: $rSkipped | Failed: $rFailures" -ForegroundColor White
}
Write-Host ""
if ($TestMode) {
    Write-Host "💡 Policies were imported in TestWithNotifications mode." -ForegroundColor Yellow
    Write-Host "   Review results in the Purview compliance portal before enabling." -ForegroundColor Yellow
}
Write-Host ""
Write-Host "⚠️  Note: Auto-labeling policies may take up to 24 hours to begin processing content." -ForegroundColor Yellow
