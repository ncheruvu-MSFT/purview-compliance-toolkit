<#
.SYNOPSIS
    Create auto-labeling policies that apply sensitivity labels based on custom SITs

.DESCRIPTION
    Creates Microsoft Purview auto-labeling policies that automatically detect
    sensitive content using custom Sensitive Information Types (SITs) and apply
    the appropriate sensitivity label.

    This script creates two auto-labeling policies:

    1. PII Auto-Label Policy
       - Detects: Demo-Employee-ID, Demo-Customer-Reference SITs
       - Applies: Demo-Confidential-PII label
       - Scope: Exchange (email) + SharePoint/OneDrive (documents)

    2. Finance Auto-Label Policy
       - Detects: Demo-Product-Code SIT + built-in "Credit Card Number"
       - Applies: Demo-HighlyConfidential-Finance label
       - Scope: Exchange (email) + SharePoint/OneDrive (documents)

    Policies are created in SIMULATION mode by default so you can review
    matches before enforcing. Use -EnablePolicy to turn on enforcement.

.PARAMETER LabelPrefix
    Prefix used when creating labels (must match 05-Create-Sensitivity-Labels.ps1)
    Default: "Demo"

.PARAMETER Mode
    Policy mode: "Simulation" (default, safe) or "Enable" (enforces labeling)

.PARAMETER SharePointLocations
    SharePoint site URLs to include. Default: "All" (all sites)

.PARAMETER ExcludeSharePointLocations
    SharePoint site URLs to exclude from the policy

.EXAMPLE
    .\06-Create-AutoLabeling-Policy.ps1
    # Creates policies in simulation mode (safe to test)

.EXAMPLE
    .\06-Create-AutoLabeling-Policy.ps1 -Mode Enable
    # Creates policies with enforcement enabled (applies labels automatically)

.EXAMPLE
    .\06-Create-AutoLabeling-Policy.ps1 -LabelPrefix "Contoso"
    # Uses labels created with "Contoso" prefix

.NOTES
    Prerequisites:
    - Connected to Security & Compliance PowerShell (.\01-Connect-Tenant.ps1)
    - Custom SITs created (.\02-Create-Sample-SITs.ps1)
    - Sensitivity labels created (.\05-Create-Sensitivity-Labels.ps1)
    - Compliance Administrator role

    Auto-labeling policies:
    - Simulation mode lets you review what WOULD be labeled before enforcement
    - Policies can take up to 24 hours to start detecting content
    - Maximum of 100 auto-labeling policies per tenant

.LINK
    https://learn.microsoft.com/en-us/purview/apply-sensitivity-label-automatically
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $false)]
    [string]$LabelPrefix = "Demo",

    [Parameter(Mandatory = $false)]
    [ValidateSet("Simulation", "Enable")]
    [string]$Mode = "Simulation",

    [Parameter(Mandatory = $false)]
    [string[]]$SharePointLocations = @("All"),

    [Parameter(Mandatory = $false)]
    [string[]]$ExcludeSharePointLocations = @()
)

$ErrorActionPreference = "Stop"

Write-Host "╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  Create Auto-Labeling Policies with SIT Detection            ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

#region Connection Check
try {
    $null = Get-DlpSensitiveInformationType -Identity "Credit Card Number" -ErrorAction Stop
} catch {
    Write-Host "❌ Not connected to Security & Compliance PowerShell" -ForegroundColor Red
    Write-Host "   Run: .\01-Connect-Tenant.ps1 first" -ForegroundColor Yellow
    exit 1
}
Write-Host "✅ Connected to Security & Compliance PowerShell" -ForegroundColor Green
Write-Host ""
#endregion

#region Verify Prerequisites
Write-Host "🔍 Verifying prerequisites..." -ForegroundColor Cyan
Write-Host ""

# Verify custom SITs exist
$requiredSITs = @("Demo-Employee-ID", "Demo-Product-Code", "Demo-Customer-Reference")
$foundSITs = @{}
$missingSITs = @()

foreach ($sitName in $requiredSITs) {
    try {
        $sit = Get-DlpSensitiveInformationType -Identity $sitName -ErrorAction Stop
        $foundSITs[$sitName] = $sit
        Write-Host "   ✅ SIT found: $sitName (ID: $($sit.Id))" -ForegroundColor Green
    } catch {
        $missingSITs += $sitName
        Write-Host "   ❌ SIT missing: $sitName" -ForegroundColor Red
    }
}

# Check for built-in Credit Card SIT
try {
    $ccSit = Get-DlpSensitiveInformationType -Identity "Credit Card Number" -ErrorAction Stop
    $foundSITs["Credit Card Number"] = $ccSit
    Write-Host "   ✅ Built-in SIT: Credit Card Number" -ForegroundColor Green
} catch {
    Write-Host "   ❌ Built-in SIT 'Credit Card Number' not accessible" -ForegroundColor Red
    $missingSITs += "Credit Card Number"
}

if ($missingSITs.Count -gt 0) {
    Write-Host ""
    Write-Host "❌ Missing SITs. Create them first:" -ForegroundColor Red
    Write-Host "   Run: .\02-Create-Sample-SITs.ps1" -ForegroundColor Yellow
    exit 1
}

Write-Host ""

# Verify sensitivity labels exist
$requiredLabels = @(
    "$LabelPrefix-Confidential-PII",
    "$LabelPrefix-HighlyConfidential-Finance"
)
$foundLabels = @{}
$missingLabels = @()

foreach ($labelName in $requiredLabels) {
    try {
        $label = Get-Label -Identity $labelName -ErrorAction Stop
        $foundLabels[$labelName] = $label
        Write-Host "   ✅ Label found: $labelName (ID: $($label.Guid))" -ForegroundColor Green
    } catch {
        $missingLabels += $labelName
        Write-Host "   ❌ Label missing: $labelName" -ForegroundColor Red
    }
}

if ($missingLabels.Count -gt 0) {
    Write-Host ""
    Write-Host "❌ Missing sensitivity labels. Create them first:" -ForegroundColor Red
    Write-Host "   Run: .\05-Create-Sensitivity-Labels.ps1" -ForegroundColor Yellow
    exit 1
}

Write-Host ""
Write-Host "✅ All prerequisites verified" -ForegroundColor Green
Write-Host ""
#endregion

#region Define Auto-Labeling Policies
$autoLabelPolicies = @(
    @{
        Name        = "$LabelPrefix-AutoLabel-PII-Policy"
        Comment     = "Automatically labels content containing PII data (Employee IDs, Customer References)"
        LabelName   = "$LabelPrefix-Confidential-PII"
        SITNames    = @("Demo-Employee-ID", "Demo-Customer-Reference")
        MinCount    = 1
        MaxCount    = -1   # unlimited
        Confidence  = 75
    },
    @{
        Name        = "$LabelPrefix-AutoLabel-Finance-Policy"
        Comment     = "Automatically labels content containing financial data (Product Codes, Credit Card Numbers)"
        LabelName   = "$LabelPrefix-HighlyConfidential-Finance"
        SITNames    = @("Demo-Product-Code", "Credit Card Number")
        MinCount    = 1
        MaxCount    = -1
        Confidence  = 75
    }
)
#endregion

#region Create Policies
Write-Host "📋 Creating auto-labeling policies (Mode: $Mode)..." -ForegroundColor Cyan
Write-Host ""

$createdPolicies = @()

foreach ($policyDef in $autoLabelPolicies) {
    $policyName = $policyDef.Name

    Write-Host "🏷️  Policy: $policyName" -ForegroundColor Yellow
    Write-Host "   Label: $($policyDef.LabelName)" -ForegroundColor Gray
    Write-Host "   SITs:  $($policyDef.SITNames -join ', ')" -ForegroundColor Gray
    Write-Host ""

    # Check if policy already exists
    $existingPolicy = Get-AutoSensitivityLabelPolicy -Identity $policyName -ErrorAction SilentlyContinue
    if ($existingPolicy) {
        Write-Host "   ⚠️  Policy '$policyName' already exists" -ForegroundColor Yellow
        Write-Host "   Do you want to update it? (Y/N): " -NoNewline -ForegroundColor Yellow
        $response = Read-Host
        if ($response -ne 'Y' -and $response -ne 'y') {
            Write-Host "   ⏭️  Skipping..." -ForegroundColor Gray
            continue
        }

        # Remove existing policy to recreate
        try {
            Remove-AutoSensitivityLabelPolicy -Identity $policyName -Confirm:$false -ErrorAction Stop
            Write-Host "   🗑️  Removed existing policy" -ForegroundColor Gray
            Start-Sleep -Seconds 3
        } catch {
            Write-Host "   ❌ Failed to remove existing policy: $($_.Exception.Message)" -ForegroundColor Red
            continue
        }
    }

    # Build SIT condition rules
    # Each SIT becomes a condition group in the policy
    $sensitiveInformationConditions = @()

    foreach ($sitName in $policyDef.SITNames) {
        $sit = $foundSITs[$sitName]
        if ($sit) {
            $sensitiveInformationConditions += @{
                name           = $sitName
                id             = $sit.Id
                type           = "Fingerprint"
                mincount       = $policyDef.MinCount
                maxcount       = $policyDef.MaxCount
                confidencelevel = if ($policyDef.Confidence -eq 75) { "Medium" } 
                                  elseif ($policyDef.Confidence -ge 85) { "High" } 
                                  else { "Low" }
                minconfidence  = $policyDef.Confidence
                maxconfidence  = 100
            }
        }
    }

    # Create the auto-labeling policy
    try {
        $policyParams = @{
            Name                      = $policyName
            Comment                   = $policyDef.Comment
            ApplySensitivityLabel     = $foundLabels[$policyDef.LabelName].Guid
            ExchangeLocation          = @("All")
            Mode                      = if ($Mode -eq "Enable") { "Enable" } else { "TestWithoutNotifications" }
        }

        # Add SharePoint locations
        if ($SharePointLocations -contains "All") {
            $policyParams["SharePointLocation"] = @("All")
            $policyParams["OneDriveLocation"]   = @("All")
        } else {
            $policyParams["SharePointLocation"] = $SharePointLocations
            $policyParams["OneDriveLocation"]   = @("All")
        }

        if ($ExcludeSharePointLocations.Count -gt 0) {
            $policyParams["SharePointLocationException"] = $ExcludeSharePointLocations
        }

        $newPolicy = New-AutoSensitivityLabelPolicy @policyParams -ErrorAction Stop
        Write-Host "   ✅ Policy created: $policyName" -ForegroundColor Green

        # Create the auto-labeling rule with SIT conditions
        $ruleName = "$policyName-Rule"

        $ruleParams = @{
            Name                        = $ruleName
            Policy                      = $policyName
            ContentContainsSensitiveInformation = $sensitiveInformationConditions
        }

        $newRule = New-AutoSensitivityLabelRule @ruleParams -ErrorAction Stop
        Write-Host "   ✅ Rule created: $ruleName" -ForegroundColor Green
        Write-Host "      Conditions: $($policyDef.SITNames.Count) SIT(s) configured" -ForegroundColor Gray

        $createdPolicies += @{
            PolicyName = $policyName
            RuleName   = $ruleName
            Label      = $policyDef.LabelName
            SITs       = $policyDef.SITNames
            Mode       = $Mode
        }

    } catch {
        Write-Host "   ❌ Failed to create policy: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host ""
        Write-Host "   💡 Common issues:" -ForegroundColor Yellow
        Write-Host "      • Label must be published before use in auto-labeling" -ForegroundColor Gray
        Write-Host "      • Maximum 100 auto-labeling policies per tenant" -ForegroundColor Gray
        Write-Host "      • Policy names must be unique" -ForegroundColor Gray
    }

    Write-Host ""
}
#endregion

#region Summary
Write-Host "╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║  ✅ Auto-Labeling Policies Created                            ║" -ForegroundColor Green
Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""

if ($createdPolicies.Count -gt 0) {
    Write-Host "📊 Summary:" -ForegroundColor Cyan
    Write-Host ""

    foreach ($policy in $createdPolicies) {
        $modeIcon = if ($policy.Mode -eq "Enable") { "🟢 ENABLED" } else { "🟡 SIMULATION" }
        Write-Host "   Policy: $($policy.PolicyName)" -ForegroundColor White
        Write-Host "   Mode:   $modeIcon" -ForegroundColor $(if ($policy.Mode -eq "Enable") { "Green" } else { "Yellow" })
        Write-Host "   Label:  $($policy.Label)" -ForegroundColor Gray
        Write-Host "   SITs:   $($policy.SITs -join ', ')" -ForegroundColor Gray
        Write-Host ""
    }

    Write-Host "📋 How Auto-Labeling Works:" -ForegroundColor Cyan
    Write-Host "   1. Service scans content in Exchange, SharePoint, and OneDrive" -ForegroundColor Gray
    Write-Host "   2. When content matches a SIT pattern, the policy is triggered" -ForegroundColor Gray
    Write-Host "   3. The associated sensitivity label is applied automatically" -ForegroundColor Gray
    Write-Host ""

    if ($Mode -eq "Simulation") {
        Write-Host "🟡 Policies are in SIMULATION mode:" -ForegroundColor Yellow
        Write-Host "   • Content will be scanned but labels will NOT be applied yet" -ForegroundColor Gray
        Write-Host "   • Review simulation results in the Purview compliance portal:" -ForegroundColor Gray
        Write-Host "     https://compliance.microsoft.com/informationprotection/autolabeling" -ForegroundColor DarkGray
        Write-Host "   • When ready, enable enforcement:" -ForegroundColor Gray
        Write-Host "     .\06-Create-AutoLabeling-Policy.ps1 -Mode Enable" -ForegroundColor DarkGray
    } else {
        Write-Host "🟢 Policies are ENABLED - labels will be applied automatically" -ForegroundColor Green
    }
} else {
    Write-Host "⚠️  No policies were created. Review the errors above." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "💡 Next steps:" -ForegroundColor Yellow
Write-Host "   1. Verify setup:            .\07-Verify-AutoLabeling.ps1" -ForegroundColor Gray
Write-Host "   2. Review in portal:        https://compliance.microsoft.com" -ForegroundColor Gray
Write-Host "   3. Wait 24h for scanning to start detecting content" -ForegroundColor Gray
Write-Host ""
Write-Host "⏳ Note: Auto-labeling policies can take up to 24 hours to begin scanning content." -ForegroundColor Yellow
Write-Host ""
#endregion
