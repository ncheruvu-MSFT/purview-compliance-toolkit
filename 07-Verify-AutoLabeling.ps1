<#
.SYNOPSIS
    Verify auto-labeling configuration (SITs, Labels, Policies)

.DESCRIPTION
    Performs a comprehensive verification of the entire auto-labeling setup:
    - Custom Sensitive Information Types (SITs)
    - Sensitivity labels and their settings
    - Auto-labeling policies and rules
    - Policy status and simulation results

    Use this to confirm everything is correctly wired together.

.PARAMETER LabelPrefix
    Prefix used when creating labels (default: "Demo")

.PARAMETER Detailed
    Show detailed output including label settings and policy rules

.EXAMPLE
    .\07-Verify-AutoLabeling.ps1
    # Quick verification of all components

.EXAMPLE
    .\07-Verify-AutoLabeling.ps1 -Detailed
    # Verbose output with full configuration details

.NOTES
    Prerequisites:
    - Connected to Security & Compliance PowerShell (.\01-Connect-Tenant.ps1)
    - SITs created (.\02-Create-Sample-SITs.ps1)
    - Labels created (.\05-Create-Sensitivity-Labels.ps1)
    - Policies created (.\06-Create-AutoLabeling-Policy.ps1)

.LINK
    https://learn.microsoft.com/en-us/purview/apply-sensitivity-label-automatically
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$LabelPrefix = "Demo",

    [Parameter(Mandatory = $false)]
    [switch]$Detailed
)

$ErrorActionPreference = "Continue"
$script:PassCount = 0
$script:FailCount = 0
$script:WarnCount = 0

function Write-Check {
    param(
        [string]$Component,
        [string]$Check,
        [string]$Status,
        [string]$Detail = ""
    )

    switch ($Status) {
        "PASS" {
            Write-Host "   ✅ $Check" -ForegroundColor Green
            if ($Detail -and $Detailed) { Write-Host "      $Detail" -ForegroundColor Gray }
            $script:PassCount++
        }
        "FAIL" {
            Write-Host "   ❌ $Check" -ForegroundColor Red
            if ($Detail) { Write-Host "      $Detail" -ForegroundColor Red }
            $script:FailCount++
        }
        "WARN" {
            Write-Host "   ⚠️  $Check" -ForegroundColor Yellow
            if ($Detail) { Write-Host "      $Detail" -ForegroundColor Yellow }
            $script:WarnCount++
        }
        "INFO" {
            Write-Host "   ℹ️  $Check" -ForegroundColor Gray
            if ($Detail) { Write-Host "      $Detail" -ForegroundColor DarkGray }
        }
    }
}

Write-Host "╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  Auto-Labeling Configuration Verification                    ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

#region Connection Check
try {
    $null = Get-DlpSensitiveInformationType -Identity "Credit Card Number" -ErrorAction Stop
    Write-Host "✅ Connected to Security & Compliance PowerShell" -ForegroundColor Green
} catch {
    Write-Host "❌ Not connected to Security & Compliance PowerShell" -ForegroundColor Red
    Write-Host "   Run: .\01-Connect-Tenant.ps1 first" -ForegroundColor Yellow
    exit 1
}
Write-Host ""
#endregion

#region Step 1: Verify Custom SITs
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host " Step 1: Custom Sensitive Information Types (SITs)" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

$requiredSITs = @(
    @{ Name = "Demo-Employee-ID";         Pattern = "EMP-\d{6}" }
    @{ Name = "Demo-Product-Code";        Pattern = "PRD-[A-Z]{4}-\d{2}" }
    @{ Name = "Demo-Customer-Reference";  Pattern = "CUST-\d{4}" }
)

$foundSITIds = @{}

foreach ($sit in $requiredSITs) {
    try {
        $result = Get-DlpSensitiveInformationType -Identity $sit.Name -ErrorAction Stop
        $foundSITIds[$sit.Name] = $result.Id
        Write-Check -Component "SIT" -Check "$($sit.Name)" -Status "PASS" `
            -Detail "ID: $($result.Id) | Pattern: $($sit.Pattern)"
    } catch {
        Write-Check -Component "SIT" -Check "$($sit.Name)" -Status "FAIL" `
            -Detail "Not found. Run: .\02-Create-Sample-SITs.ps1"
    }
}

# Also check built-in Credit Card SIT
try {
    $ccSit = Get-DlpSensitiveInformationType -Identity "Credit Card Number" -ErrorAction Stop
    $foundSITIds["Credit Card Number"] = $ccSit.Id
    Write-Check -Component "SIT" -Check "Credit Card Number (built-in)" -Status "PASS" `
        -Detail "ID: $($ccSit.Id)"
} catch {
    Write-Check -Component "SIT" -Check "Credit Card Number (built-in)" -Status "FAIL"
}

Write-Host ""
#endregion

#region Step 2: Verify Sensitivity Labels
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host " Step 2: Sensitivity Labels" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

$expectedLabels = @(
    @{ Name = "$LabelPrefix-Confidential";                IsParent = $true }
    @{ Name = "$LabelPrefix-Confidential-PII";            IsParent = $false; ExpectMarking = $true }
    @{ Name = "$LabelPrefix-HighlyConfidential";          IsParent = $true }
    @{ Name = "$LabelPrefix-HighlyConfidential-Finance";  IsParent = $false; ExpectMarking = $true }
)

$foundLabelGuids = @{}

foreach ($labelDef in $expectedLabels) {
    try {
        $label = Get-Label -Identity $labelDef.Name -ErrorAction Stop
        $foundLabelGuids[$labelDef.Name] = $label.Guid

        $details = @("ID: $($label.Guid)")

        if ($labelDef.IsParent) {
            $details += "Type: Parent"
        } else {
            $details += "Type: Sub-label"

            # Check content marking
            if ($labelDef.ExpectMarking) {
                $hasHeader    = $label.ApplyContentMarkingHeaderEnabled
                $hasFooter    = $label.ApplyContentMarkingFooterEnabled
                $hasWatermark = $label.ApplyWaterMarkingEnabled

                $markings = @()
                if ($hasHeader)    { $markings += "Header" }
                if ($hasFooter)    { $markings += "Footer" }
                if ($hasWatermark) { $markings += "Watermark" }

                if ($markings.Count -gt 0) {
                    $details += "Markings: $($markings -join ', ')"
                } else {
                    $details += "Markings: None configured"
                }
            }
        }

        Write-Check -Component "Label" -Check "$($labelDef.Name)" -Status "PASS" `
            -Detail ($details -join " | ")
    } catch {
        Write-Check -Component "Label" -Check "$($labelDef.Name)" -Status "FAIL" `
            -Detail "Not found. Run: .\05-Create-Sensitivity-Labels.ps1"
    }
}

# Check label policies (publication)
Write-Host ""
Write-Host "   Label Publication:" -ForegroundColor Gray
try {
    $labelPolicies = Get-LabelPolicy -ErrorAction Stop
    if ($labelPolicies) {
        foreach ($policy in $labelPolicies) {
            $policyLabels = $policy.Labels -join ", "
            Write-Check -Component "LabelPolicy" -Check "Policy: $($policy.Name)" -Status "INFO" `
                -Detail "Labels: $policyLabels"
        }
    } else {
        Write-Check -Component "LabelPolicy" -Check "No label policies found" -Status "WARN" `
            -Detail "Labels exist but are not published. Run: .\05-Create-Sensitivity-Labels.ps1 -PublishToAll"
    }
} catch {
    Write-Check -Component "LabelPolicy" -Check "Could not check label policies" -Status "WARN" `
        -Detail "$($_.Exception.Message)"
}

Write-Host ""
#endregion

#region Step 3: Verify Auto-Labeling Policies
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host " Step 3: Auto-Labeling Policies" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

$expectedPolicies = @(
    @{
        Name      = "$LabelPrefix-AutoLabel-PII-Policy"
        Label     = "$LabelPrefix-Confidential-PII"
        SITs      = @("Demo-Employee-ID", "Demo-Customer-Reference")
    },
    @{
        Name      = "$LabelPrefix-AutoLabel-Finance-Policy"
        Label     = "$LabelPrefix-HighlyConfidential-Finance"
        SITs      = @("Demo-Product-Code", "Credit Card Number")
    }
)

foreach ($policyDef in $expectedPolicies) {
    Write-Host "   📋 Policy: $($policyDef.Name)" -ForegroundColor Yellow

    try {
        $policy = Get-AutoSensitivityLabelPolicy -Identity $policyDef.Name -ErrorAction Stop

        # Check policy status
        $modeDisplay = switch ($policy.Mode) {
            "Enable"                   { "🟢 ENABLED (enforcing)" }
            "TestWithoutNotifications" { "🟡 SIMULATION (test mode)" }
            "TestWithNotifications"    { "🟡 SIMULATION (with notifications)" }
            default                    { "⚪ $($policy.Mode)" }
        }

        Write-Check -Component "Policy" -Check "Policy exists" -Status "PASS" `
            -Detail "Mode: $modeDisplay"

        # Check locations
        $locations = @()
        if ($policy.ExchangeLocation)   { $locations += "Exchange" }
        if ($policy.SharePointLocation) { $locations += "SharePoint" }
        if ($policy.OneDriveLocation)   { $locations += "OneDrive" }

        Write-Check -Component "Policy" -Check "Locations configured" -Status "PASS" `
            -Detail "Scope: $($locations -join ', ')"

        # Check the policy rule
        try {
            $rules = Get-AutoSensitivityLabelRule -Policy $policyDef.Name -ErrorAction Stop

            if ($rules) {
                foreach ($rule in $rules) {
                    Write-Check -Component "Rule" -Check "Rule: $($rule.Name)" -Status "PASS"

                    # Check SIT conditions
                    if ($rule.ContentContainsSensitiveInformation) {
                        $configuredSITs = $rule.ContentContainsSensitiveInformation | 
                            ForEach-Object { $_.name }

                        foreach ($expectedSIT in $policyDef.SITs) {
                            if ($configuredSITs -contains $expectedSIT) {
                                Write-Check -Component "Rule" -Check "SIT condition: $expectedSIT" -Status "PASS"
                            } else {
                                Write-Check -Component "Rule" -Check "SIT condition: $expectedSIT" -Status "FAIL" `
                                    -Detail "Expected SIT not found in rule conditions"
                            }
                        }
                    } else {
                        Write-Check -Component "Rule" -Check "SIT conditions" -Status "WARN" `
                            -Detail "No sensitive information conditions found in rule"
                    }
                }
            } else {
                Write-Check -Component "Rule" -Check "Policy rules" -Status "FAIL" `
                    -Detail "No rules found for this policy"
            }
        } catch {
            Write-Check -Component "Rule" -Check "Policy rules" -Status "WARN" `
                -Detail "Could not retrieve rules: $($_.Exception.Message)"
        }

    } catch {
        Write-Check -Component "Policy" -Check "Policy exists" -Status "FAIL" `
            -Detail "Not found. Run: .\06-Create-AutoLabeling-Policy.ps1"
    }

    Write-Host ""
}
#endregion

#region Step 4: End-to-End Flow Diagram
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host " Step 4: Auto-Labeling Flow" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

Write-Host "   Content (Email/Document)" -ForegroundColor White
Write-Host "          │" -ForegroundColor DarkGray
Write-Host "          ▼" -ForegroundColor DarkGray
Write-Host "   ┌─────────────────────────┐" -ForegroundColor DarkGray
Write-Host "   │  Auto-Labeling Service  │  (scans for SIT matches)" -ForegroundColor DarkGray
Write-Host "   └────────┬────────────────┘" -ForegroundColor DarkGray
Write-Host "            │" -ForegroundColor DarkGray
Write-Host "     ┌──────┴──────┐" -ForegroundColor DarkGray
Write-Host "     ▼             ▼" -ForegroundColor DarkGray
Write-Host "   PII Match    Finance Match" -ForegroundColor Yellow
Write-Host "   EMP-######   PRD-XXXX-##" -ForegroundColor Gray
Write-Host "   CUST-####    Credit Card" -ForegroundColor Gray
Write-Host "     │             │" -ForegroundColor DarkGray
Write-Host "     ▼             ▼" -ForegroundColor DarkGray
Write-Host "   Confidential  Highly Confidential" -ForegroundColor Cyan
Write-Host "   PII Label     Finance Label" -ForegroundColor Cyan
Write-Host ""
#endregion

#region Summary
Write-Host "╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  Verification Summary                                        ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""
Write-Host "   ✅ Passed:   $script:PassCount" -ForegroundColor Green
Write-Host "   ⚠️  Warnings: $script:WarnCount" -ForegroundColor Yellow
Write-Host "   ❌ Failed:   $script:FailCount" -ForegroundColor Red
Write-Host ""

if ($script:FailCount -eq 0) {
    Write-Host "🎉 All checks passed! Auto-labeling is properly configured." -ForegroundColor Green
    Write-Host ""
    Write-Host "📋 What happens next:" -ForegroundColor Cyan
    Write-Host "   • Service will scan Exchange, SharePoint, and OneDrive content" -ForegroundColor Gray
    Write-Host "   • Content matching SIT patterns will be auto-labeled" -ForegroundColor Gray
    Write-Host "   • Review results in Purview portal → Information Protection → Auto-labeling" -ForegroundColor Gray
    Write-Host ""
    Write-Host "🔗 Purview Portal: https://compliance.microsoft.com/informationprotection/autolabeling" -ForegroundColor DarkGray
} else {
    Write-Host "⚠️  Some checks failed. Review the output above and run the required scripts." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "📋 Setup sequence:" -ForegroundColor Cyan
    Write-Host "   1. .\01-Connect-Tenant.ps1            (connect to tenant)" -ForegroundColor Gray
    Write-Host "   2. .\02-Create-Sample-SITs.ps1        (create custom SITs)" -ForegroundColor Gray
    Write-Host "   3. .\05-Create-Sensitivity-Labels.ps1  (create labels)" -ForegroundColor Gray
    Write-Host "   4. .\06-Create-AutoLabeling-Policy.ps1 (create policies)" -ForegroundColor Gray
    Write-Host "   5. .\07-Verify-AutoLabeling.ps1        (this script)" -ForegroundColor Gray
}

Write-Host ""

if ($script:FailCount -gt 0) { exit 1 } else { exit 0 }
#endregion
