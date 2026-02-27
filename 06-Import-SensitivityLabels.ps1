<#
.SYNOPSIS
    Import sensitivity labels and label policies from JSON backup files

.DESCRIPTION
    Recreates sensitivity labels and their publishing policies on the target
    tenant from JSON files produced by 05-Export-SensitivityLabels.ps1.

    Import order:
    1. Parent labels (no ParentId)
    2. Sub-labels (with ParentId, mapped to new parent GUID)
    3. Label policies (with label references remapped)

.PARAMETER LabelsFile
    Path to the labels JSON export file

.PARAMETER PoliciesFile
    Optional path to the label policies JSON export file

.PARAMETER SkipExisting
    Skip labels that already exist on the target (default: update them)

.PARAMETER Force
    Suppress confirmation prompts

.PARAMETER WhatIf
    Show what would be imported without making changes

.EXAMPLE
    .\06-Import-SensitivityLabels.ps1 -LabelsFile ".\exports\labels-export-20260226-120000.json"

.EXAMPLE
    .\06-Import-SensitivityLabels.ps1 -LabelsFile ".\exports\labels-export-20260226-120000.json" -PoliciesFile ".\exports\label-policies-export-20260226-120000.json"

.NOTES
    Must be connected to the TARGET tenant's Security & Compliance PowerShell.
    Run: .\01-Connect-Tenant.ps1 -TenantType Target
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path $_ })]
    [string]$LabelsFile,

    [Parameter(Mandatory = $false)]
    [ValidateScript({ Test-Path $_ })]
    [string]$PoliciesFile,

    [switch]$SkipExisting,
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

# ── Helper: safe JSON import (handles case-conflicting keys from older exports) ─
function ConvertFrom-JsonSafe {
    param([string]$JsonText)
    try {
        return $JsonText | ConvertFrom-Json
    } catch {
        if ($_.Exception.Message -match 'different casing') {
            # Remove numeric "value" keys that conflict with string "Value" in
            # location objects from older exports (e.g. {"value":1,"Value":"Tenant"})
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

Write-Host "🏷️  Importing sensitivity labels to TARGET tenant..." -ForegroundColor Cyan
Write-Host ""
Write-Host "   Labels file:   $LabelsFile" -ForegroundColor Gray
if ($PoliciesFile) { Write-Host "   Policies file:  $PoliciesFile" -ForegroundColor Gray }
Write-Host ""

# ─────────────────────────────────────────────────────────────────────
# STEP 1: Load and validate source data
# ─────────────────────────────────────────────────────────────────────
Write-Host "⏳ Step 1: Loading label definitions..." -ForegroundColor Yellow

$sourceLabels = ConvertFrom-JsonSafe (Get-Content $LabelsFile -Raw)
Write-Host "   📋 Found $($sourceLabels.Count) label(s) in export file" -ForegroundColor Gray

$parentLabels = @($sourceLabels | Where-Object { -not $_.ParentId })
$subLabels    = @($sourceLabels | Where-Object { $_.ParentId })
Write-Host "      Parent labels: $($parentLabels.Count)" -ForegroundColor Gray
Write-Host "      Sub-labels:    $($subLabels.Count)" -ForegroundColor Gray
Write-Host ""

# ─────────────────────────────────────────────────────────────────────
# STEP 2: Import parent labels first
# ─────────────────────────────────────────────────────────────────────
Write-Host "⏳ Step 2: Importing parent labels..." -ForegroundColor Yellow

$guidMap = @{}  # sourceGuid → targetGuid
$created = 0
$updated = 0
$skipped = 0

foreach ($label in $parentLabels) {
    $displayName = $label.DisplayName
    
    if ($PSCmdlet.ShouldProcess($displayName, "Import sensitivity label")) {
        # Try by display name first; fall back to exported Name/GUID in case
        # Get-Label -Identity doesn't match GUID-named labels by display name.
        $existing = Get-Label -Identity $displayName -ErrorAction SilentlyContinue
        if (-not $existing -and $label.Name) {
            $existing = Get-Label -Identity $label.Name -ErrorAction SilentlyContinue
        }

        if ($existing) {
            if ($SkipExisting) {
                Write-Host "   ⏩ $displayName (already exists — skipped)" -ForegroundColor DarkGray
                $guidMap[$label.Guid] = $existing.Guid.ToString()
                $skipped++
                continue
            }
            
            # Update existing label
            try {
                $setParams = @{
                    Identity = $existing.Guid.ToString()
                    DisplayName = $displayName
                }
                if ($label.Tooltip)  { $setParams['Tooltip']  = $label.Tooltip }
                if ($label.Comment)  { $setParams['Comment']  = $label.Comment }
                if ($label.AdvancedSettings -and $label.AdvancedSettings.Count -gt 0) {
                    $setParams['AdvancedSettings'] = $label.AdvancedSettings
                }
                
                Set-Label @setParams -ErrorAction Stop
                Write-Host "   🔄 $displayName (updated)" -ForegroundColor Cyan
                $guidMap[$label.Guid] = $existing.Guid.ToString()
                $updated++
            } catch {
                Write-Host "   ❌ $displayName — update failed: $($_.Exception.Message)" -ForegroundColor Red
            }
        } else {
            # Create new label
            try {
                $newParams = @{
                    DisplayName = $displayName
                    Name        = $label.Name
                }
                if ($label.Tooltip)  { $newParams['Tooltip']  = $label.Tooltip }
                if ($label.Comment)  { $newParams['Comment']  = $label.Comment }
                if ($label.AdvancedSettings -and $label.AdvancedSettings.Count -gt 0) {
                    $newParams['AdvancedSettings'] = $label.AdvancedSettings
                }
                
                $newLabel = New-Label @newParams -ErrorAction Stop
                Write-Host "   ✅ $displayName (created)" -ForegroundColor Green
                $guidMap[$label.Guid] = $newLabel.Guid.ToString()
                $created++
                Start-Sleep -Seconds 1
            } catch {
                Write-Host "   ❌ $displayName — create failed: $($_.Exception.Message)" -ForegroundColor Red
            }
        }    } else {
        # WhatIf mode: map source GUID to itself so sub-labels can resolve parents
        $guidMap[$label.Guid] = $label.Guid    }
}
Write-Host ""

# ─────────────────────────────────────────────────────────────────────
# STEP 3: Import sub-labels (with parent GUID remapping)
# ─────────────────────────────────────────────────────────────────────
if ($subLabels.Count -gt 0) {
    Write-Host "⏳ Step 3: Importing sub-labels..." -ForegroundColor Yellow
    
    foreach ($label in $subLabels) {
        $displayName = $label.DisplayName
        $sourceParentGuid = $label.ParentId
        
        # Remap parent GUID
        $targetParentGuid = $guidMap[$sourceParentGuid]
        if (-not $targetParentGuid) {
            Write-Host "   ❌ $displayName — parent label not found (source parent: $sourceParentGuid)" -ForegroundColor Red
            continue
        }
        
        if ($PSCmdlet.ShouldProcess($displayName, "Import sub-label")) {
            # Look up by name, but verify it is actually nested under the correct parent.
            # A parent label and a sub-label can share the same DisplayName; Get-Label
            # returns whichever it finds first, which may be the same-named parent label.
            # Try by display name first; fall back to exported Name/GUID.
            $candidateLabel = Get-Label -Identity $displayName -ErrorAction SilentlyContinue
            if (-not $candidateLabel -and $label.Name) {
                $candidateLabel = Get-Label -Identity $label.Name -ErrorAction SilentlyContinue
            }
            $existing = $null
            if ($candidateLabel) {
                $candidateParent = if ($candidateLabel.ParentId) { $candidateLabel.ParentId.ToString() } else { '' }
                if ($candidateParent -eq $targetParentGuid) {
                    $existing = $candidateLabel
                } else {
                    # Same display name exists at a different hierarchy level.
                    # Do a full scan to see whether the correct sub-label already exists.
                    $existing = Get-Label -ErrorAction SilentlyContinue | Where-Object {
                        $_.DisplayName -eq $displayName -and
                        $_.ParentId -and $_.ParentId.ToString() -eq $targetParentGuid
                    } | Select-Object -First 1
                }
            }

            if ($existing) {
                if ($SkipExisting) {
                    Write-Host "   ⏩ $displayName (already exists — skipped)" -ForegroundColor DarkGray
                    $guidMap[$label.Guid] = $existing.Guid.ToString()
                    $skipped++
                    continue
                }
                
                try {
                    $setParams = @{ Identity = $existing.Guid.ToString() }
                    if ($label.Tooltip) { $setParams['Tooltip'] = $label.Tooltip }
                    if ($label.Comment) { $setParams['Comment'] = $label.Comment }
                    
                    Set-Label @setParams -ErrorAction Stop
                    Write-Host "   🔄 $displayName (updated)" -ForegroundColor Cyan
                    $guidMap[$label.Guid] = $existing.Guid.ToString()
                    $updated++
                } catch {
                    Write-Host "   ❌ $displayName — update failed: $($_.Exception.Message)" -ForegroundColor Red
                }
            } else {
                try {
                    $newParams = @{
                        DisplayName = $displayName
                        Name        = $label.Name
                        ParentId    = $targetParentGuid
                    }
                    if ($label.Tooltip) { $newParams['Tooltip'] = $label.Tooltip }
                    if ($label.Comment) { $newParams['Comment'] = $label.Comment }
                    
                    $newLabel = New-Label @newParams -ErrorAction Stop
                    Write-Host "   ✅ $displayName (created under parent)" -ForegroundColor Green
                    $guidMap[$label.Guid] = $newLabel.Guid.ToString()
                    $created++
                    Start-Sleep -Seconds 1
                } catch {
                    Write-Host "   ❌ $displayName — create failed: $($_.Exception.Message)" -ForegroundColor Red
                }
            }
        }
    }
    Write-Host ""
} else {
    Write-Host "⏩ Step 3: No sub-labels to import" -ForegroundColor DarkGray
    Write-Host ""
}

# ─────────────────────────────────────────────────────────────────────
# STEP 4: Import label policies (if provided)
# ─────────────────────────────────────────────────────────────────────
if ($PoliciesFile) {
    Write-Host "⏳ Step 4: Importing label policies..." -ForegroundColor Yellow
    
    $sourcePolicies = ConvertFrom-JsonSafe (Get-Content $PoliciesFile -Raw)
    Write-Host "   📋 Found $($sourcePolicies.Count) policy(ies) in export file" -ForegroundColor Gray
    
    foreach ($policy in $sourcePolicies) {
        $policyName = $policy.Name
        
        if ($PSCmdlet.ShouldProcess($policyName, "Import label policy")) {
            # Remap label references to target GUIDs
            $targetLabels = @()
            foreach ($srcLabel in $policy.Labels) {
                $srcGuid = $srcLabel
                if ($guidMap.ContainsKey($srcGuid)) {
                    $targetLabels += $guidMap[$srcGuid]
                } else {
                    # Try to find by name on target
                    $targetLabels += $srcGuid
                }
            }
            
            $existing = Get-LabelPolicy -Identity $policyName -ErrorAction SilentlyContinue
            
            if ($existing) {
                Write-Host "   🔄 $policyName (already exists — updating labels)" -ForegroundColor Cyan
                try {
                    Set-LabelPolicy -Identity $policyName -ErrorAction Stop
                    $updated++
                } catch {
                    Write-Host "   ❌ $policyName — update failed: $($_.Exception.Message)" -ForegroundColor Red
                }
            } else {
                try {
                    $newParams = @{
                        Name   = $policyName
                        Labels = $targetLabels
                    }
                    if ($policy.Comment) { $newParams['Comment'] = $policy.Comment }
                    $exchLoc = Get-LocationNames $policy.ExchangeLocation
                    if ($exchLoc.Count -gt 0) { $newParams['ExchangeLocation'] = $exchLoc }
                    $spLoc = Get-LocationNames $policy.SharePointLocation
                    if ($spLoc.Count -gt 0) { $newParams['SharePointLocation'] = $spLoc }
                    $mgLoc = Get-LocationNames $policy.ModernGroupLocation
                    if ($mgLoc.Count -gt 0) { $newParams['ModernGroupLocation'] = $mgLoc }
                    if ($policy.AdvancedSettings -and $policy.AdvancedSettings.Count -gt 0) {
                        $newParams['AdvancedSettings'] = $policy.AdvancedSettings
                    }
                    
                    New-LabelPolicy @newParams -ErrorAction Stop
                    Write-Host "   ✅ $policyName (created)" -ForegroundColor Green
                    $created++
                    Start-Sleep -Seconds 2
                } catch {
                    Write-Host "   ❌ $policyName — create failed: $($_.Exception.Message)" -ForegroundColor Red
                }
            }
        }
    }
    Write-Host ""
} else {
    Write-Host "⏩ Step 4: No policies file specified — skipping policy import" -ForegroundColor DarkGray
    Write-Host ""
}

# ── Summary ───────────────────────────────────────────────────────────
Write-Host "✅ Label import complete!" -ForegroundColor Green
Write-Host ""
Write-Host "   Created: $created" -ForegroundColor Green
Write-Host "   Updated: $updated" -ForegroundColor Cyan
Write-Host "   Skipped: $skipped" -ForegroundColor DarkGray
Write-Host ""
Write-Host "💡 Note: Label policies may take up to 24 hours to propagate to all users." -ForegroundColor Yellow
