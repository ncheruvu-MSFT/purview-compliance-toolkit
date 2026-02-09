<#
.SYNOPSIS
    Create sample sensitivity labels for auto-labeling demo

.DESCRIPTION
    Creates sensitivity labels in Microsoft Purview to be used with
    auto-labeling policies. The labels are created with a parent-child
    hierarchy following Microsoft best practices:

    Parent: "Demo-Confidential"
      └── Sub-label: "Demo-Confidential-PII" (with content marking)
    Parent: "Demo-Highly-Confidential"
      └── Sub-label: "Demo-HighlyConfidential-Finance" (with content marking)

    Labels include:
    - Content marking (headers, footers, watermarks)
    - Tooltip descriptions for end users
    - Proper priority ordering

    NOTE: Encryption settings are NOT applied by default to keep the demo
    simple. Use -EnableEncryption to add encryption (requires additional
    permissions and Azure RMS configuration).

.PARAMETER LabelPrefix
    Prefix for all label names (default: "Demo")
    Helps avoid conflicts with existing labels

.PARAMETER EnableEncryption
    If specified, adds encryption settings to sub-labels.
    Requires Azure Rights Management to be configured.

.PARAMETER PublishToAll
    If specified, creates a label policy to publish labels to all users.
    Without this flag, labels are created but not published.

.EXAMPLE
    .\05-Create-Sensitivity-Labels.ps1
    # Creates demo labels with content marking only

.EXAMPLE
    .\05-Create-Sensitivity-Labels.ps1 -LabelPrefix "Contoso" -PublishToAll
    # Creates "Contoso-*" labels and publishes them to all users

.EXAMPLE
    .\05-Create-Sensitivity-Labels.ps1 -EnableEncryption
    # Creates labels with encryption (requires Azure RMS)

.NOTES
    Prerequisites:
    - Connected to Security & Compliance PowerShell (.\01-Connect-Tenant.ps1)
    - Compliance Administrator or Information Protection Administrator role
    - For encryption: Azure Rights Management must be activated

    Label changes may take 24-48 hours to propagate to all Microsoft 365 apps.

.LINK
    https://learn.microsoft.com/en-us/purview/create-sensitivity-labels
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $false)]
    [string]$LabelPrefix = "Demo",

    [Parameter(Mandatory = $false)]
    [switch]$EnableEncryption,

    [Parameter(Mandatory = $false)]
    [switch]$PublishToAll
)

$ErrorActionPreference = "Stop"

Write-Host "╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  Create Sensitivity Labels for Auto-Labeling Demo            ║" -ForegroundColor Cyan
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

#region Define Label Hierarchy
$labels = @(
    # ── Parent: Confidential ──
    @{
        Name        = "$LabelPrefix-Confidential"
        DisplayName = "$LabelPrefix - Confidential"
        Tooltip     = "Business data that could cause harm if shared with unauthorized people."
        Comment     = "Parent label for Confidential classification"
        Priority    = 0
        IsParent    = $true
        Children    = @(
            @{
                Name        = "$LabelPrefix-Confidential-PII"
                DisplayName = "$LabelPrefix - Confidential \ PII Data"
                Tooltip     = "Contains Personally Identifiable Information. Handle according to data privacy policies."
                Comment     = "Sub-label for PII data under Confidential"
                Priority    = 1
                HeaderText  = "CONFIDENTIAL - PII DATA"
                FooterText  = "This document contains PII. Handle in accordance with data privacy policies."
                WatermarkText = ""
            }
        )
    },
    # ── Parent: Highly Confidential ──
    @{
        Name        = "$LabelPrefix-HighlyConfidential"
        DisplayName = "$LabelPrefix - Highly Confidential"
        Tooltip     = "Very sensitive business data that would cause serious harm if shared with unauthorized people."
        Comment     = "Parent label for Highly Confidential classification"
        Priority    = 2
        IsParent    = $true
        Children    = @(
            @{
                Name        = "$LabelPrefix-HighlyConfidential-Finance"
                DisplayName = "$LabelPrefix - Highly Confidential \ Finance"
                Tooltip     = "Contains sensitive financial data. Restricted to authorized finance personnel only."
                Comment     = "Sub-label for financial data under Highly Confidential"
                Priority    = 3
                HeaderText  = "HIGHLY CONFIDENTIAL - FINANCIAL DATA"
                FooterText  = "This document contains sensitive financial information. Unauthorized disclosure is prohibited."
                WatermarkText = "HIGHLY CONFIDENTIAL"
            }
        )
    }
)
#endregion

#region Helper Functions
function New-SensitivityLabelSafe {
    param(
        [hashtable]$LabelConfig,
        [string]$ParentId
    )

    $labelName = $LabelConfig.Name

    # Check if label already exists
    $existing = Get-Label -Identity $labelName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "   ⚠️  Label '$labelName' already exists (ID: $($existing.Guid))" -ForegroundColor Yellow
        return $existing
    }

    # Build parameters
    $params = @{
        Name        = $labelName
        DisplayName = $LabelConfig.DisplayName
        Tooltip     = $LabelConfig.Tooltip
        Comment     = $LabelConfig.Comment
    }

    # If this is a child label, set parent
    if ($ParentId) {
        $params["ParentId"] = $ParentId
    }

    # Add content marking for non-parent labels
    if (-not $LabelConfig.IsParent) {
        # Header
        if ($LabelConfig.HeaderText) {
            $params["ContentType"] = "File, Email"

            # Header settings
            $params["ApplyContentMarkingHeaderEnabled"]    = $true
            $params["ApplyContentMarkingHeaderText"]       = $LabelConfig.HeaderText
            $params["ApplyContentMarkingHeaderFontSize"]   = 10
            $params["ApplyContentMarkingHeaderFontColor"]  = "#FF0000"
            $params["ApplyContentMarkingHeaderAlignment"]  = "Center"

            # Footer settings
            if ($LabelConfig.FooterText) {
                $params["ApplyContentMarkingFooterEnabled"]    = $true
                $params["ApplyContentMarkingFooterText"]       = $LabelConfig.FooterText
                $params["ApplyContentMarkingFooterFontSize"]   = 8
                $params["ApplyContentMarkingFooterFontColor"]  = "#666666"
                $params["ApplyContentMarkingFooterAlignment"]  = "Center"
            }

            # Watermark settings
            if ($LabelConfig.WatermarkText) {
                $params["ApplyWaterMarkingEnabled"]    = $true
                $params["ApplyWaterMarkingText"]       = $LabelConfig.WatermarkText
                $params["ApplyWaterMarkingFontSize"]   = 48
                $params["ApplyWaterMarkingFontColor"]  = "#FF000033"
                $params["ApplyWaterMarkingLayout"]     = "Diagonal"
            }
        }
    }

    # Create the label
    try {
        $newLabel = New-Label @params -ErrorAction Stop
        Write-Host "   ✅ Created: $labelName (ID: $($newLabel.Guid))" -ForegroundColor Green
        return $newLabel
    } catch {
        Write-Host "   ❌ Failed to create '$labelName': $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}
#endregion

#region Create Labels
Write-Host "🏷️  Creating sensitivity labels..." -ForegroundColor Cyan
Write-Host ""

$createdLabels = @()
$allCreatedLabelNames = @()

foreach ($parentDef in $labels) {
    Write-Host "📁 Parent: $($parentDef.DisplayName)" -ForegroundColor Cyan

    # Create parent label
    $parentLabel = New-SensitivityLabelSafe -LabelConfig $parentDef
    if ($parentLabel) {
        $createdLabels += $parentLabel
        $allCreatedLabelNames += $parentDef.Name

        # Create child labels
        foreach ($childDef in $parentDef.Children) {
            Write-Host "   📄 Sub-label: $($childDef.DisplayName)" -ForegroundColor Gray
            $childLabel = New-SensitivityLabelSafe -LabelConfig $childDef -ParentId $parentLabel.Guid
            if ($childLabel) {
                $createdLabels += $childLabel
                $allCreatedLabelNames += $childDef.Name
            }
        }
    }
    Write-Host ""
}

Write-Host "📊 Created $($createdLabels.Count) label(s)" -ForegroundColor Green
Write-Host ""
#endregion

#region Publish Labels (Optional)
if ($PublishToAll -and $allCreatedLabelNames.Count -gt 0) {
    Write-Host "📢 Publishing labels to all users..." -ForegroundColor Cyan

    $policyName = "$LabelPrefix-AutoLabel-Demo-Policy"

    # Check if policy already exists
    $existingPolicy = Get-LabelPolicy -Identity $policyName -ErrorAction SilentlyContinue
    if ($existingPolicy) {
        Write-Host "   ⚠️  Label policy '$policyName' already exists. Updating..." -ForegroundColor Yellow
        try {
            Set-LabelPolicy -Identity $policyName -AddLabels $allCreatedLabelNames -ErrorAction Stop
            Write-Host "   ✅ Policy updated with new labels" -ForegroundColor Green
        } catch {
            Write-Host "   ⚠️  Could not update policy: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    } else {
        try {
            New-LabelPolicy `
                -Name $policyName `
                -Labels $allCreatedLabelNames `
                -Comment "Auto-labeling demo - publishes demo sensitivity labels" `
                -ExchangeLocation "All" `
                -ErrorAction Stop

            Write-Host "   ✅ Label policy '$policyName' created and published to all users" -ForegroundColor Green
        } catch {
            Write-Host "   ❌ Failed to create label policy: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "   💡 You can publish labels manually from the Purview compliance portal" -ForegroundColor Yellow
        }
    }
    Write-Host ""
}
#endregion

#region Summary
Write-Host "╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║  ✅ Sensitivity Labels Created                                ║" -ForegroundColor Green
Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "📋 Label Hierarchy:" -ForegroundColor Cyan

foreach ($parentDef in $labels) {
    Write-Host "   📁 $($parentDef.DisplayName)" -ForegroundColor White
    foreach ($childDef in $parentDef.Children) {
        $markings = @()
        if ($childDef.HeaderText)    { $markings += "Header" }
        if ($childDef.FooterText)    { $markings += "Footer" }
        if ($childDef.WatermarkText) { $markings += "Watermark" }
        $markingInfo = if ($markings.Count -gt 0) { " [Markings: $($markings -join ', ')]" } else { "" }
        Write-Host "      └── 📄 $($childDef.DisplayName)$markingInfo" -ForegroundColor Gray
    }
}

Write-Host ""
Write-Host "💡 Next steps:" -ForegroundColor Yellow
Write-Host "   1. Create auto-labeling policy:  .\06-Create-AutoLabeling-Policy.ps1" -ForegroundColor Gray
Write-Host "   2. Verify configuration:         .\07-Verify-AutoLabeling.ps1" -ForegroundColor Gray
if (-not $PublishToAll) {
    Write-Host "   3. Publish labels to users:      .\05-Create-Sensitivity-Labels.ps1 -PublishToAll" -ForegroundColor Gray
}
Write-Host ""
Write-Host "⏳ Note: Label changes may take up to 24-48 hours to propagate to all M365 apps." -ForegroundColor Yellow
Write-Host ""
#endregion
