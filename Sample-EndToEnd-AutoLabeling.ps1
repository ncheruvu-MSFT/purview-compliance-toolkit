<#
.SYNOPSIS
    End-to-end sample: Create SITs → Labels → Auto-Labeling Policy

.DESCRIPTION
    Demonstrates the complete auto-labeling workflow in a single script:

    Step 1: Create custom SITs (Employee ID, Product Code, Customer Reference)
    Step 2: Create sensitivity labels (Confidential/PII, Highly Confidential/Finance)
    Step 3: Publish labels to all users
    Step 4: Create auto-labeling policies linking SITs to labels
    Step 5: Verify the entire setup

    This is an orchestration script that calls the individual toolkit scripts
    in the correct sequence.

.PARAMETER LabelPrefix
    Prefix for label names (default: "Demo")

.PARAMETER SkipSITs
    Skip SIT creation (if they already exist)

.PARAMETER SkipLabels
    Skip label creation (if they already exist)

.PARAMETER EnablePolicies
    Create policies in Enable mode instead of Simulation

.EXAMPLE
    .\Sample-EndToEnd-AutoLabeling.ps1
    # Full setup: SITs + Labels + Policies (simulation mode)

.EXAMPLE
    .\Sample-EndToEnd-AutoLabeling.ps1 -SkipSITs -EnablePolicies
    # Skip SIT creation, enable policy enforcement

.NOTES
    Prerequisites:
    - Connected to Security & Compliance PowerShell (.\01-Connect-Tenant.ps1)
    - Compliance Administrator role
    
    Estimated time: 2-5 minutes for creation, 24-48 hours for full propagation

.LINK
    https://learn.microsoft.com/en-us/purview/apply-sensitivity-label-automatically
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $false)]
    [string]$LabelPrefix = "Demo",

    [Parameter(Mandatory = $false)]
    [switch]$SkipSITs,

    [Parameter(Mandatory = $false)]
    [switch]$SkipLabels,

    [Parameter(Mandatory = $false)]
    [switch]$EnablePolicies
)

$ErrorActionPreference = "Stop"
$ScriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$startTime = Get-Date

Write-Host "╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  End-to-End Auto-Labeling Setup                              ║" -ForegroundColor Cyan
Write-Host "║  SITs → Labels → Auto-Labeling Policies                     ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

#region Connection Check
Write-Host "🔗 Checking connection..." -ForegroundColor Cyan
try {
    $null = Get-DlpSensitiveInformationType -Identity "Credit Card Number" -ErrorAction Stop
    Write-Host "   ✅ Connected" -ForegroundColor Green
} catch {
    Write-Host "   ❌ Not connected to Security & Compliance PowerShell" -ForegroundColor Red
    Write-Host "   Run: .\01-Connect-Tenant.ps1 first" -ForegroundColor Yellow
    exit 1
}
Write-Host ""
#endregion

#region Step 1: Create Custom SITs
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host " Step 1/5: Create Custom Sensitive Information Types" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

if ($SkipSITs) {
    Write-Host "   ⏭️  Skipping SIT creation (flag: -SkipSITs)" -ForegroundColor Yellow

    # Verify they exist
    $sitCheck = @("Demo-Employee-ID", "Demo-Product-Code", "Demo-Customer-Reference")
    foreach ($sitName in $sitCheck) {
        try {
            $null = Get-DlpSensitiveInformationType -Identity $sitName -ErrorAction Stop
            Write-Host "   ✅ $sitName exists" -ForegroundColor Green
        } catch {
            Write-Host "   ❌ $sitName NOT found - cannot skip SIT creation" -ForegroundColor Red
            exit 1
        }
    }
} else {
    Write-Host "   Running: .\02-Create-Sample-SITs.ps1" -ForegroundColor Gray
    try {
        & (Join-Path $ScriptPath "02-Create-Sample-SITs.ps1")
        Write-Host ""
        Write-Host "   ✅ SIT creation complete" -ForegroundColor Green
    } catch {
        Write-Host "   ❌ SIT creation failed: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}

Write-Host ""
Start-Sleep -Seconds 3
#endregion

#region Step 2: Create Sensitivity Labels
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host " Step 2/5: Create Sensitivity Labels" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

if ($SkipLabels) {
    Write-Host "   ⏭️  Skipping label creation (flag: -SkipLabels)" -ForegroundColor Yellow

    # Verify they exist
    $labelCheck = @("$LabelPrefix-Confidential-PII", "$LabelPrefix-HighlyConfidential-Finance")
    foreach ($labelName in $labelCheck) {
        try {
            $null = Get-Label -Identity $labelName -ErrorAction Stop
            Write-Host "   ✅ $labelName exists" -ForegroundColor Green
        } catch {
            Write-Host "   ❌ $labelName NOT found - cannot skip label creation" -ForegroundColor Red
            exit 1
        }
    }
} else {
    Write-Host "   Running: .\05-Create-Sensitivity-Labels.ps1 -LabelPrefix `"$LabelPrefix`"" -ForegroundColor Gray
    try {
        & (Join-Path $ScriptPath "05-Create-Sensitivity-Labels.ps1") -LabelPrefix $LabelPrefix
        Write-Host ""
        Write-Host "   ✅ Label creation complete" -ForegroundColor Green
    } catch {
        Write-Host "   ❌ Label creation failed: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}

Write-Host ""
Start-Sleep -Seconds 3
#endregion

#region Step 3: Publish Labels
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host " Step 3/5: Publish Labels to All Users" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

$policyName = "$LabelPrefix-AutoLabel-Demo-LabelPolicy"
$allLabelNames = @(
    "$LabelPrefix-Confidential",
    "$LabelPrefix-Confidential-PII",
    "$LabelPrefix-HighlyConfidential",
    "$LabelPrefix-HighlyConfidential-Finance"
)

$existingPolicy = Get-LabelPolicy -Identity $policyName -ErrorAction SilentlyContinue
if ($existingPolicy) {
    Write-Host "   ✅ Label policy '$policyName' already exists" -ForegroundColor Green
} else {
    try {
        New-LabelPolicy `
            -Name $policyName `
            -Labels $allLabelNames `
            -Comment "Demo: Publishes auto-labeling sensitivity labels to all users" `
            -ExchangeLocation "All" `
            -ErrorAction Stop

        Write-Host "   ✅ Labels published to all users via policy: $policyName" -ForegroundColor Green
    } catch {
        Write-Host "   ⚠️  Could not publish labels: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "   💡 Labels can be published manually from the Purview portal" -ForegroundColor Gray
    }
}

Write-Host ""
Start-Sleep -Seconds 3
#endregion

#region Step 4: Create Auto-Labeling Policies
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host " Step 4/5: Create Auto-Labeling Policies" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

$policyMode = if ($EnablePolicies) { "Enable" } else { "Simulation" }
Write-Host "   Mode: $policyMode" -ForegroundColor $(if ($EnablePolicies) { "Green" } else { "Yellow" })
Write-Host "   Running: .\06-Create-AutoLabeling-Policy.ps1 -LabelPrefix `"$LabelPrefix`" -Mode `"$policyMode`"" -ForegroundColor Gray
Write-Host ""

try {
    & (Join-Path $ScriptPath "06-Create-AutoLabeling-Policy.ps1") `
        -LabelPrefix $LabelPrefix `
        -Mode $policyMode

    Write-Host ""
    Write-Host "   ✅ Auto-labeling policies created" -ForegroundColor Green
} catch {
    Write-Host "   ❌ Policy creation failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

Write-Host ""
Start-Sleep -Seconds 3
#endregion

#region Step 5: Verify Everything
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host " Step 5/5: Verify Configuration" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

try {
    & (Join-Path $ScriptPath "07-Verify-AutoLabeling.ps1") -LabelPrefix $LabelPrefix -Detailed
} catch {
    Write-Host "   ⚠️  Verification encountered issues: $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Host ""
#endregion

#region Final Summary
$duration = (Get-Date) - $startTime

Write-Host "╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║  ✅ End-to-End Setup Complete!                                ║" -ForegroundColor Green
Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "   Duration: $($duration.ToString('mm\:ss'))" -ForegroundColor Gray
Write-Host ""
Write-Host "   What was created:" -ForegroundColor Cyan
Write-Host "   ─────────────────" -ForegroundColor DarkGray
Write-Host "   🔍 3 Custom SITs (Employee ID, Product Code, Customer Reference)" -ForegroundColor White
Write-Host "   🏷️  4 Sensitivity Labels (2 parents + 2 sub-labels)" -ForegroundColor White
Write-Host "   📢 1 Label Policy (published to all users)" -ForegroundColor White
Write-Host "   📋 2 Auto-Labeling Policies (PII + Finance)" -ForegroundColor White
Write-Host ""
Write-Host "   How it works:" -ForegroundColor Cyan
Write-Host "   ─────────────" -ForegroundColor DarkGray
Write-Host "   • Email/document contains 'EMP-123456' or 'CUST-1234'" -ForegroundColor White
Write-Host "     → Auto-labeled: $LabelPrefix - Confidential \ PII Data" -ForegroundColor Green
Write-Host ""
Write-Host "   • Email/document contains 'PRD-ABCD-01' or credit card number" -ForegroundColor White
Write-Host "     → Auto-labeled: $LabelPrefix - Highly Confidential \ Finance" -ForegroundColor Green
Write-Host ""

if (-not $EnablePolicies) {
    Write-Host "   ⚠️  Policies are in SIMULATION mode" -ForegroundColor Yellow
    Write-Host "   Review results at: https://compliance.microsoft.com/informationprotection/autolabeling" -ForegroundColor Gray
    Write-Host "   To enable enforcement: .\Sample-EndToEnd-AutoLabeling.ps1 -SkipSITs -SkipLabels -EnablePolicies" -ForegroundColor Gray
    Write-Host ""
}

Write-Host "   ⏳ Content scanning will begin within 24 hours." -ForegroundColor Yellow
Write-Host ""
#endregion
