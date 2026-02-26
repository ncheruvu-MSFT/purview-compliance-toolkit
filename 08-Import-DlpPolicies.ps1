<#
.SYNOPSIS
    Import DLP compliance policies and rules from JSON backup files

.DESCRIPTION
    Recreates DLP compliance policies and their associated rules on the target
    tenant from JSON files produced by 07-Export-DlpPolicies.ps1.

    Import order:
    1. DLP policies (must exist before rules)
    2. DLP rules (linked to their parent policy by name)

.PARAMETER PoliciesFile
    Path to the DLP policies JSON export file

.PARAMETER RulesFile
    Optional path to the DLP rules JSON export file

.PARAMETER SkipExisting
    Skip policies/rules that already exist on the target (default: update them)

.PARAMETER TestMode
    Import policies in TestWithNotifications mode for safe testing

.PARAMETER Force
    Suppress confirmation prompts

.PARAMETER WhatIf
    Show what would be imported without making changes

.EXAMPLE
    .\08-Import-DlpPolicies.ps1 -PoliciesFile ".\exports\dlp-policies-export-20260226-120000.json" -RulesFile ".\exports\dlp-rules-export-20260226-120000.json"

.EXAMPLE
    .\08-Import-DlpPolicies.ps1 -PoliciesFile ".\exports\dlp-policies-export-20260226-120000.json" -TestMode

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

Write-Host "🛡️  Importing DLP policies to TARGET tenant..." -ForegroundColor Cyan
Write-Host ""
Write-Host "   Policies file: $PoliciesFile" -ForegroundColor Gray
if ($RulesFile)  { Write-Host "   Rules file:    $RulesFile" -ForegroundColor Gray }
if ($TestMode)   { Write-Host "   ⚠️  Test mode:   Policies will be created in TestWithNotifications mode" -ForegroundColor Yellow }
Write-Host ""

# ─────────────────────────────────────────────────────────────────────
# STEP 1: Load and validate source data
# ─────────────────────────────────────────────────────────────────────
Write-Host "⏳ Step 1: Loading DLP policy definitions..." -ForegroundColor Yellow

$sourcePolicies = Get-Content $PoliciesFile -Raw | ConvertFrom-Json
Write-Host "   📋 Found $($sourcePolicies.Count) policy(ies) in export file" -ForegroundColor Gray

$sourceRules = @()
if ($RulesFile) {
    $sourceRules = Get-Content $RulesFile -Raw | ConvertFrom-Json
    Write-Host "   📋 Found $($sourceRules.Count) rule(s) in export file" -ForegroundColor Gray
}
Write-Host ""

# ─────────────────────────────────────────────────────────────────────
# STEP 2: Import DLP policies
# ─────────────────────────────────────────────────────────────────────
Write-Host "⏳ Step 2: Importing DLP policies..." -ForegroundColor Yellow

$created  = 0
$updated  = 0
$skipped  = 0
$failures = 0

foreach ($policy in $sourcePolicies) {
    $policyName = $policy.Name
    
    if ($PSCmdlet.ShouldProcess($policyName, "Import DLP policy")) {
        $existing = Get-DlpCompliancePolicy -Identity $policyName -ErrorAction SilentlyContinue
        
        if ($existing) {
            if ($SkipExisting) {
                Write-Host "   ⏩ $policyName (already exists — skipped)" -ForegroundColor DarkGray
                $skipped++
                continue
            }
            
            try {
                $setParams = @{ Identity = $policyName }
                if ($policy.Comment)  { $setParams['Comment'] = $policy.Comment }
                if ($TestMode)        { $setParams['Mode'] = 'TestWithNotifications' }
                
                Set-DlpCompliancePolicy @setParams -ErrorAction Stop
                Write-Host "   🔄 $policyName (updated)" -ForegroundColor Cyan
                $updated++
            } catch {
                Write-Host "   ❌ $policyName — update failed: $($_.Exception.Message)" -ForegroundColor Red
                $failures++
            }
        } else {
            try {
                $newParams = @{ Name = $policyName }
                if ($policy.Comment)  { $newParams['Comment'] = $policy.Comment }
                if ($TestMode) {
                    $newParams['Mode'] = 'TestWithNotifications'
                } elseif ($policy.Mode) {
                    $newParams['Mode'] = $policy.Mode
                }
                
                # Build location parameters
                if ($policy.ExchangeLocation -and $policy.ExchangeLocation.Count -gt 0) {
                    $newParams['ExchangeLocation'] = $policy.ExchangeLocation
                }
                if ($policy.SharePointLocation -and $policy.SharePointLocation.Count -gt 0) {
                    $newParams['SharePointLocation'] = $policy.SharePointLocation
                }
                if ($policy.OneDriveLocation -and $policy.OneDriveLocation.Count -gt 0) {
                    $newParams['OneDriveLocation'] = $policy.OneDriveLocation
                }
                if ($policy.TeamsLocation -and $policy.TeamsLocation.Count -gt 0) {
                    $newParams['TeamsLocation'] = $policy.TeamsLocation
                }
                if ($policy.EndpointDlpLocation -and $policy.EndpointDlpLocation.Count -gt 0) {
                    $newParams['EndpointDlpLocation'] = $policy.EndpointDlpLocation
                }
                if ($policy.OnPremisesScannerDlpLocation -and $policy.OnPremisesScannerDlpLocation.Count -gt 0) {
                    $newParams['OnPremisesScannerDlpLocation'] = $policy.OnPremisesScannerDlpLocation
                }
                if ($policy.ThirdPartyAppDlpLocation -and $policy.ThirdPartyAppDlpLocation.Count -gt 0) {
                    $newParams['ThirdPartyAppDlpLocation'] = $policy.ThirdPartyAppDlpLocation
                }
                
                New-DlpCompliancePolicy @newParams -ErrorAction Stop
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
# STEP 3: Import DLP rules
# ─────────────────────────────────────────────────────────────────────
if ($sourceRules.Count -gt 0) {
    Write-Host "⏳ Step 3: Importing DLP rules..." -ForegroundColor Yellow
    
    $rCreated  = 0
    $rUpdated  = 0
    $rSkipped  = 0
    $rFailures = 0
    
    foreach ($rule in $sourceRules) {
        $ruleName   = $rule.Name
        $policyName = $rule.ParentPolicyName
        
        if ($PSCmdlet.ShouldProcess($ruleName, "Import DLP rule")) {
            # Verify parent policy exists on target
            $parentPolicy = Get-DlpCompliancePolicy -Identity $policyName -ErrorAction SilentlyContinue
            if (-not $parentPolicy) {
                Write-Host "   ❌ $ruleName — parent policy '$policyName' not found on target" -ForegroundColor Red
                $rFailures++
                continue
            }
            
            $existing = Get-DlpComplianceRule -Identity $ruleName -ErrorAction SilentlyContinue
            
            if ($existing) {
                if ($SkipExisting) {
                    Write-Host "   ⏩ $ruleName (already exists — skipped)" -ForegroundColor DarkGray
                    $rSkipped++
                    continue
                }
                
                try {
                    $setParams = @{ Identity = $ruleName }
                    if ($null -ne $rule.Disabled)    { $setParams['Disabled'] = $rule.Disabled }
                    if ($rule.Comment)               { $setParams['Comment'] = $rule.Comment }
                    if ($null -ne $rule.BlockAccess)  { $setParams['BlockAccess'] = $rule.BlockAccess }
                    if ($rule.BlockAccessScope)       { $setParams['BlockAccessScope'] = $rule.BlockAccessScope }
                    if ($rule.NotifyUser)             { $setParams['NotifyUser'] = $rule.NotifyUser }
                    if ($rule.GenerateAlert)          { $setParams['GenerateAlert'] = $rule.GenerateAlert }
                    if ($rule.GenerateIncidentReport) { $setParams['GenerateIncidentReport'] = $rule.GenerateIncidentReport }
                    if ($rule.ReportSeverityLevel)    { $setParams['ReportSeverityLevel'] = $rule.ReportSeverityLevel }
                    if ($rule.ContentContainsSensitiveInformation) {
                        $setParams['ContentContainsSensitiveInformation'] = $rule.ContentContainsSensitiveInformation
                    }
                    
                    Set-DlpComplianceRule @setParams -ErrorAction Stop
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
                    if ($null -ne $rule.Disabled)    { $newParams['Disabled'] = $rule.Disabled }
                    if ($rule.Comment)               { $newParams['Comment'] = $rule.Comment }
                    if ($null -ne $rule.BlockAccess)  { $newParams['BlockAccess'] = $rule.BlockAccess }
                    if ($rule.BlockAccessScope)       { $newParams['BlockAccessScope'] = $rule.BlockAccessScope }
                    if ($rule.NotifyUser)             { $newParams['NotifyUser'] = $rule.NotifyUser }
                    if ($rule.GenerateAlert)          { $newParams['GenerateAlert'] = $rule.GenerateAlert }
                    if ($rule.GenerateIncidentReport) { $newParams['GenerateIncidentReport'] = $rule.GenerateIncidentReport }
                    if ($rule.ReportSeverityLevel)    { $newParams['ReportSeverityLevel'] = $rule.ReportSeverityLevel }
                    if ($rule.IncidentReportContent)  { $newParams['IncidentReportContent'] = $rule.IncidentReportContent }
                    if ($rule.ContentContainsSensitiveInformation) {
                        $newParams['ContentContainsSensitiveInformation'] = $rule.ContentContainsSensitiveInformation
                    }
                    if ($rule.AccessScope)            { $newParams['AccessScope'] = $rule.AccessScope }
                    if ($rule.NotifyOverride)         { $newParams['NotifyOverride'] = $rule.NotifyOverride }
                    if ($rule.NotifyAllowOverride)    { $newParams['NotifyAllowOverride'] = $rule.NotifyAllowOverride }
                    
                    New-DlpComplianceRule @newParams -ErrorAction Stop
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
Write-Host "✅ DLP policy import complete!" -ForegroundColor Green
Write-Host ""
Write-Host "   Policies — Created: $created | Updated: $updated | Skipped: $skipped | Failed: $failures" -ForegroundColor White
if ($sourceRules.Count -gt 0) {
    Write-Host "   Rules    — Created: $rCreated | Updated: $rUpdated | Skipped: $rSkipped | Failed: $rFailures" -ForegroundColor White
}
Write-Host ""
if ($TestMode) {
    Write-Host "💡 Policies were imported in TestWithNotifications mode." -ForegroundColor Yellow
    Write-Host "   Review results in the Purview compliance portal, then enable with:" -ForegroundColor Yellow
    Write-Host "   Set-DlpCompliancePolicy -Identity '<name>' -Mode 'Enable'" -ForegroundColor Yellow
}
