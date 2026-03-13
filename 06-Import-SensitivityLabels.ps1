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

    All exported label properties are now applied during import, including:
    - ContentType (scopes: File, Email, Site, UnifiedGroup, Teamwork)
    - LabelActions (content marking footers/headers/watermarks, encryption)
    - Conditions (auto-labeling with SIT references)
    - LocaleSettings (multilingual display names and tooltips)
    - Policy Settings (default labels, mandatory labeling, etc.)

.PARAMETER LabelsFile
    Path to the labels JSON export file

.PARAMETER PoliciesFile
    Optional path to the label policies JSON export file

.PARAMETER SkipExisting
    Skip labels that already exist on the target (default: update them)

.PARAMETER SitGuidMap
    Optional hashtable mapping source SIT GUIDs to target SIT GUIDs.
    Used when labels have auto-labeling Conditions referencing custom SITs.

.PARAMETER EncryptionIdentityMap
    Optional hashtable mapping source tenant domains to target tenant domains
    in RightsDefinitions. Example: @{ "source.onmicrosoft.com" = "target.onmicrosoft.com" }

.PARAMETER RecipientMap
    Optional hashtable mapping source user/group email addresses to target
    tenant equivalents. Applied to encryption RightsDefinitions and label
    policy location fields (ExchangeLocation, etc.).
    Example: @{ "UserA@source.com" = "UserA@target.com" }

.PARAMETER MappingFile
    Optional JSON file providing SitGuidMap, EncryptionIdentityMap, and
    RecipientMap.
    Example structure:
    {
      "SitIdMap": { "source-guid": "target-guid" },
      "EncryptionIdentityMap": { "source.onmicrosoft.com": "target.onmicrosoft.com" },
      "RecipientMap": { "User@source.com": "User@target.com", "Group@source.com": "Group@target.com" }
    }

.PARAMETER Force
    Suppress confirmation prompts

.PARAMETER WhatIf
    Show what would be imported without making changes

.EXAMPLE
    .\06-Import-SensitivityLabels.ps1 -LabelsFile ".\exports\labels-export-20260226-120000.json"

.EXAMPLE
    .\06-Import-SensitivityLabels.ps1 -LabelsFile ".\exports\labels-export-20260226-120000.json" -PoliciesFile ".\exports\label-policies-export-20260226-120000.json"

.EXAMPLE
    .\06-Import-SensitivityLabels.ps1 -LabelsFile ".\exports\labels-export.json" -PoliciesFile ".\exports\label-policies-export.json" -MappingFile ".\label-import-mapping.json"

.EXAMPLE
    .\06-Import-SensitivityLabels.ps1 -LabelsFile ".\exports\labels-export.json" -PoliciesFile ".\exports\label-policies-export.json" -MappingFile ".\label-import-mapping.json" -RecipientMap @{ "User@source.com" = "User@target.com" }

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

    [Parameter(Mandatory = $false)]
    [hashtable]$SitGuidMap = @{},

    [Parameter(Mandatory = $false)]
    [hashtable]$EncryptionIdentityMap = @{},

    [Parameter(Mandatory = $false)]
    [hashtable]$RecipientMap = @{},

    [Parameter(Mandatory = $false)]
    [ValidateScript({ Test-Path $_ })]
    [string]$MappingFile,

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

# ── Load mapping file if provided ─────────────────────────────────────
if ($MappingFile) {
    Write-Host "📄 Loading mapping file: $MappingFile" -ForegroundColor Gray
    $mapping = Get-Content $MappingFile -Raw | ConvertFrom-Json
    if ($mapping.SitIdMap) {
        $mapping.SitIdMap.PSObject.Properties | ForEach-Object {
            if (-not $SitGuidMap.ContainsKey($_.Name)) { $SitGuidMap[$_.Name] = $_.Value }
        }
    }
    if ($mapping.EncryptionIdentityMap) {
        $mapping.EncryptionIdentityMap.PSObject.Properties | ForEach-Object {
            if (-not $EncryptionIdentityMap.ContainsKey($_.Name)) { $EncryptionIdentityMap[$_.Name] = $_.Value }
        }
    }
    if ($mapping.RecipientMap) {
        $mapping.RecipientMap.PSObject.Properties | ForEach-Object {
            if (-not $RecipientMap.ContainsKey($_.Name)) { $RecipientMap[$_.Name] = $_.Value }
        }
    }
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

# ── Helper: remap recipient addresses in location name arrays ────────
function Invoke-LocationRemap {
    param(
        [array]$LocationNames,
        [hashtable]$RecMap = @{}
    )
    if (-not $LocationNames -or $LocationNames.Count -eq 0) { return $LocationNames }
    if (-not $RecMap -or $RecMap.Count -eq 0) { return $LocationNames }
    @($LocationNames | ForEach-Object {
        $name = $_
        if ($RecMap.ContainsKey($name)) { $RecMap[$name] } else { $name }
    })
}

# ── Helper: parse LabelActions JSON array into Set-Label parameters ────
function ConvertFrom-LabelActions {
    param(
        [array]$LabelActions,
        [hashtable]$IdentityMap = @{},
        [hashtable]$RecipientMap = @{}
    )
    $params = @{}
    if (-not $LabelActions -or $LabelActions.Count -eq 0) { return $params }

    foreach ($actionJson in $LabelActions) {
        $action = $actionJson | ConvertFrom-Json

        $settings = @{}
        foreach ($s in $action.Settings) { $settings[$s.Key] = $s.Value }

        switch ($action.Type) {
            'applycontentmarking' {
                $prefix = switch ($action.SubType) {
                    'footer' { 'ApplyContentMarkingFooter' }
                    'header' { 'ApplyContentMarkingHeader' }
                    default  { $null }
                }
                if (-not $prefix) { continue }

                if ($settings.ContainsKey('disabled')) {
                    $params["${prefix}Enabled"] = ($settings['disabled'] -eq 'false')
                }
                if ($settings.ContainsKey('alignment')) { $params["${prefix}Alignment"] = $settings['alignment'] }
                if ($settings.ContainsKey('fontcolor')) { $params["${prefix}FontColor"]  = $settings['fontcolor'] }
                if ($settings.ContainsKey('fontsize'))  { $params["${prefix}FontSize"]   = [int]$settings['fontsize'] }
                if ($settings.ContainsKey('margin'))    { $params["${prefix}Margin"]     = [int]$settings['margin'] }
                if ($settings.ContainsKey('text'))      { $params["${prefix}Text"]       = $settings['text'] }
            }

            'applywatermarking' {
                if ($settings.ContainsKey('disabled')) {
                    $params['ApplyWaterMarkingEnabled'] = ($settings['disabled'] -eq 'false')
                }
                if ($settings.ContainsKey('fontcolor')) { $params['ApplyWaterMarkingFontColor'] = $settings['fontcolor'] }
                if ($settings.ContainsKey('fontsize'))  { $params['ApplyWaterMarkingFontSize']  = [int]$settings['fontsize'] }
                if ($settings.ContainsKey('layout'))    { $params['ApplyWaterMarkingLayout']    = $settings['layout'] }
                if ($settings.ContainsKey('text'))      { $params['ApplyWaterMarkingText']      = $settings['text'] }
            }

            'encrypt' {
                if ($settings.ContainsKey('disabled')) {
                    $params['EncryptionEnabled'] = ($settings['disabled'] -eq 'false')
                }
                if ($settings.ContainsKey('protectiontype')) {
                    $params['EncryptionProtectionType'] = $settings['protectiontype']
                }
                if ($settings.ContainsKey('donotforward')) {
                    $params['EncryptionDoNotForward'] = ($settings['donotforward'] -eq 'true')
                }
                if ($settings.ContainsKey('promptuser')) {
                    $params['EncryptionPromptUser'] = ($settings['promptuser'] -eq 'true')
                }
                if ($settings.ContainsKey('encryptonly')) {
                    $params['EncryptionEncryptOnly'] = ($settings['encryptonly'] -eq 'true')
                }
                if ($settings.ContainsKey('contentexpiredondateindaysornever')) {
                    $params['EncryptionContentExpiredOnDateInDaysOrNever'] = $settings['contentexpiredondateindaysornever']
                }
                if ($settings.ContainsKey('offlineaccessdays')) {
                    $params['EncryptionOfflineAccessDays'] = [int]$settings['offlineaccessdays']
                }
                if ($settings.ContainsKey('rightsdefinitions')) {
                    $rdValue = $settings['rightsdefinitions']
                    # Remap tenant domains in Identity fields
                    if ($IdentityMap -and $IdentityMap.Count -gt 0) {
                        foreach ($srcDomain in $IdentityMap.Keys) {
                            $rdValue = $rdValue -replace [regex]::Escape($srcDomain), $IdentityMap[$srcDomain]
                        }
                    }
                    # Remap individual user/group email addresses
                    if ($RecipientMap -and $RecipientMap.Count -gt 0) {
                        foreach ($srcAddr in $RecipientMap.Keys) {
                            $rdValue = $rdValue -replace [regex]::Escape($srcAddr), $RecipientMap[$srcAddr]
                        }
                    }
                    $params['EncryptionRightsDefinitions'] = $rdValue
                }
                # Skip templateid, linkedtemplateid, templatearchived (auto-generated)
            }
        }
    }
    return $params
}

# ── Helper: remap SIT GUIDs in Conditions JSON array ─────────────────
function Invoke-ConditionsSitRemap {
    param(
        [array]$Conditions,
        [hashtable]$SitMap = @{}
    )
    if (-not $Conditions -or $Conditions.Count -eq 0) { return $Conditions }
    if (-not $SitMap -or $SitMap.Count -eq 0) { return $Conditions }

    [System.Collections.ArrayList]$remapped = @()
    foreach ($condJson in $Conditions) {
        $text = if ($condJson -is [string]) { $condJson } else { $condJson | ConvertTo-Json -Depth 20 -Compress }
        # Walk JSON and replace SIT GUIDs that are NOT built-in
        # Built-in SITs have rulepackage = 00000000-0000-0000-0000-000000000000
        # We remap the Value (SIT GUID) in CCSI nodes by checking the SitMap
        foreach ($srcGuid in $SitMap.Keys) {
            $text = $text -replace [regex]::Escape($srcGuid), $SitMap[$srcGuid]
        }
        $null = $remapped.Add($text)
    }
    return @($remapped)
}

# ── Helper: parse policy Settings array and remap label GUIDs ────────
function ConvertFrom-PolicySettings {
    param(
        [array]$Settings,
        [hashtable]$GuidMap = @{}
    )
    $result = @{}
    if (-not $Settings -or $Settings.Count -eq 0) { return $result }

    # Keys whose values are label GUIDs that need remapping
    $guidKeys = @('defaultlabelid', 'teamworkdefaultlabelid', 'outlookdefaultlabel')

    foreach ($entry in $Settings) {
        # Parse "[key, value]" format
        if ($entry -match '^\[(.+?),\s*(.+)\]$') {
            $key   = $Matches[1].Trim()
            $value = $Matches[2].Trim()

            if ($key -in $guidKeys -and $GuidMap.ContainsKey($value)) {
                $result[$key] = $GuidMap[$value]
            } else {
                $result[$key] = $value
            }
        }
    }
    return $result
}

# ── Helper: apply label actions and conditions via Set-Label ──────────
function Set-LabelProperties {
    param(
        [string]$LabelGuid,
        [string]$DisplayName,
        $Label,
        [hashtable]$IdMap = @{},
        [hashtable]$SitMap = @{},
        [hashtable]$RecMap = @{}
    )
    # Apply LabelActions (content marking, encryption, watermarking)
    if ($Label.LabelActions -and $Label.LabelActions.Count -gt 0) {
        try {
            $actionParams = ConvertFrom-LabelActions -LabelActions $Label.LabelActions -IdentityMap $IdMap -RecipientMap $RecMap
            if ($actionParams.Count -gt 0) {
                $actionParams['Identity'] = $LabelGuid
                Set-Label @actionParams -ErrorAction Stop
                Write-Host "      + Applied LabelActions ($($actionParams.Count - 1) properties)" -ForegroundColor DarkGray
                Start-Sleep -Seconds 2
            }
        } catch {
            Write-Host "      ! LabelActions failed for $DisplayName : $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }

    # Apply Conditions (auto-labeling for files/emails)
    if ($Label.Conditions -and $Label.Conditions.Count -gt 0) {
        try {
            $remappedConditions = Invoke-ConditionsSitRemap -Conditions $Label.Conditions -SitMap $SitMap
            Set-Label -Identity $LabelGuid -Conditions $remappedConditions -ErrorAction Stop
            Write-Host "      + Applied Conditions ($($remappedConditions.Count) rule(s))" -ForegroundColor DarkGray
        } catch {
            Write-Host "      ! Conditions failed for $DisplayName : $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
}

Write-Host "🏷️  Importing sensitivity labels to TARGET tenant..." -ForegroundColor Cyan
Write-Host ""
Write-Host "   Labels file:   $LabelsFile" -ForegroundColor Gray
if ($PoliciesFile)  { Write-Host "   Policies file:  $PoliciesFile" -ForegroundColor Gray }
if ($MappingFile)   { Write-Host "   Mapping file:   $MappingFile" -ForegroundColor Gray }
if ($SitGuidMap.Count -gt 0)           { Write-Host "   SIT mappings:   $($SitGuidMap.Count)" -ForegroundColor Gray }
if ($EncryptionIdentityMap.Count -gt 0) { Write-Host "   ID mappings:    $($EncryptionIdentityMap.Count)" -ForegroundColor Gray }
if ($RecipientMap.Count -gt 0)         { Write-Host "   Recipient maps: $($RecipientMap.Count)" -ForegroundColor Gray }
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

$guidMap = @{}  # sourceGuid -> targetGuid
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
                # ContentType (scopes) — skip "None" which is the default for parent containers
                if ($label.ContentType -and $label.ContentType -ne 'None') {
                    $setParams['ContentType'] = $label.ContentType
                }
                # LocaleSettings (multilingual display names/tooltips)
                if ($label.LocaleSettings -and $label.LocaleSettings.Count -gt 0) {
                    $setParams['LocaleSettings'] = $label.LocaleSettings
                }

                Set-Label @setParams -ErrorAction Stop
                Write-Host "   🔄 $displayName (updated)" -ForegroundColor Cyan
                $guidMap[$label.Guid] = $existing.Guid.ToString()
                $updated++

                # Apply LabelActions and Conditions in a second pass
                Set-LabelProperties -LabelGuid $existing.Guid.ToString() -DisplayName $displayName `
                    -Label $label -IdMap $EncryptionIdentityMap -SitMap $SitGuidMap -RecMap $RecipientMap
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
                # ContentType (scopes) — skip "None" which is the default for parent containers
                if ($label.ContentType -and $label.ContentType -ne 'None') {
                    $newParams['ContentType'] = $label.ContentType
                }
                # LocaleSettings (multilingual display names/tooltips)
                if ($label.LocaleSettings -and $label.LocaleSettings.Count -gt 0) {
                    $newParams['LocaleSettings'] = $label.LocaleSettings
                }

                $newLabel = New-Label @newParams -ErrorAction Stop
                Write-Host "   ✅ $displayName (created)" -ForegroundColor Green
                $guidMap[$label.Guid] = $newLabel.Guid.ToString()
                $created++
                Start-Sleep -Seconds 1

                # Apply LabelActions and Conditions in a second pass
                Set-LabelProperties -LabelGuid $newLabel.Guid.ToString() -DisplayName $displayName `
                    -Label $label -IdMap $EncryptionIdentityMap -SitMap $SitGuidMap -RecMap $RecipientMap
            } catch {
                Write-Host "   ❌ $displayName — create failed: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    } else {
        # WhatIf mode: map source GUID to itself so sub-labels can resolve parents
        $guidMap[$label.Guid] = $label.Guid
    }
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
                    if ($label.AdvancedSettings -and $label.AdvancedSettings.Count -gt 0) {
                        $setParams['AdvancedSettings'] = $label.AdvancedSettings
                    }
                    # ContentType (scopes)
                    if ($label.ContentType -and $label.ContentType -ne 'None') {
                        $setParams['ContentType'] = $label.ContentType
                    }
                    # LocaleSettings
                    if ($label.LocaleSettings -and $label.LocaleSettings.Count -gt 0) {
                        $setParams['LocaleSettings'] = $label.LocaleSettings
                    }

                    Set-Label @setParams -ErrorAction Stop
                    Write-Host "   🔄 $displayName (updated)" -ForegroundColor Cyan
                    $guidMap[$label.Guid] = $existing.Guid.ToString()
                    $updated++

                    # Apply LabelActions and Conditions in a second pass
                    Set-LabelProperties -LabelGuid $existing.Guid.ToString() -DisplayName $displayName `
                        -Label $label -IdMap $EncryptionIdentityMap -SitMap $SitGuidMap -RecMap $RecipientMap
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
                    if ($label.AdvancedSettings -and $label.AdvancedSettings.Count -gt 0) {
                        $newParams['AdvancedSettings'] = $label.AdvancedSettings
                    }
                    # ContentType (scopes)
                    if ($label.ContentType -and $label.ContentType -ne 'None') {
                        $newParams['ContentType'] = $label.ContentType
                    }
                    # LocaleSettings
                    if ($label.LocaleSettings -and $label.LocaleSettings.Count -gt 0) {
                        $newParams['LocaleSettings'] = $label.LocaleSettings
                    }

                    $newLabel = New-Label @newParams -ErrorAction Stop
                    Write-Host "   ✅ $displayName (created under parent)" -ForegroundColor Green
                    $guidMap[$label.Guid] = $newLabel.Guid.ToString()
                    $created++
                    Start-Sleep -Seconds 1

                    # Apply LabelActions and Conditions in a second pass
                    Set-LabelProperties -LabelGuid $newLabel.Guid.ToString() -DisplayName $displayName `
                        -Label $label -IdMap $EncryptionIdentityMap -SitMap $SitGuidMap -RecMap $RecipientMap
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
                Write-Host "   🔄 $policyName (already exists — updating)" -ForegroundColor Cyan
                try {
                    $setParams = @{ Identity = $policyName }
                    if ($policy.Comment) { $setParams['Comment'] = $policy.Comment }
                    if ($policy.AdvancedSettings -and $policy.AdvancedSettings.Count -gt 0) {
                        $setParams['AdvancedSettings'] = $policy.AdvancedSettings
                    }

                    Set-LabelPolicy @setParams -ErrorAction Stop

                    # Apply Settings (default labels, mandatory labeling, etc.)
                    if ($policy.Settings -and $policy.Settings.Count -gt 0) {
                        $policySettings = ConvertFrom-PolicySettings -Settings $policy.Settings -GuidMap $guidMap
                        if ($policySettings.Count -gt 0) {
                            Set-LabelPolicy -Identity $policyName -Settings $policySettings -ErrorAction Stop
                            Write-Host "      + Applied Settings ($($policySettings.Count) properties)" -ForegroundColor DarkGray
                        }
                    }
                    $updated++
                } catch {
                    Write-Host "   ❌ $policyName — update failed: $($_.Exception.Message)" -ForegroundColor Red
                }
            } else {
                # Build the creation params with all location data
                $newParams = @{
                    Name   = $policyName
                    Labels = $targetLabels
                }
                if ($policy.Comment) { $newParams['Comment'] = $policy.Comment }

                # Exchange locations with recipient validation
                $exchLoc = Invoke-LocationRemap (Get-LocationNames $policy.ExchangeLocation) $RecipientMap
                if ($exchLoc.Count -gt 0) {
                    if ($exchLoc.Count -eq 1 -and $exchLoc[0] -eq 'All') {
                        $newParams['ExchangeLocation'] = $exchLoc
                    } else {
                        $newParams['ExchangeLocation'] = $exchLoc
                    }
                }
                # SharePoint locations
                $spLoc = Invoke-LocationRemap (Get-LocationNames $policy.SharePointLocation) $RecipientMap
                if ($spLoc.Count -gt 0) { $newParams['SharePointLocation'] = $spLoc }
                # OneDrive locations (was missing)
                $odLoc = Invoke-LocationRemap (Get-LocationNames $policy.OneDriveLocation) $RecipientMap
                if ($odLoc.Count -gt 0) { $newParams['OneDriveLocation'] = $odLoc }
                # Modern Group locations
                $mgLoc = Invoke-LocationRemap (Get-LocationNames $policy.ModernGroupLocation) $RecipientMap
                if ($mgLoc.Count -gt 0) { $newParams['ModernGroupLocation'] = $mgLoc }

                # Location exceptions (all were missing)
                $exchExc = Invoke-LocationRemap (Get-LocationNames $policy.ExchangeLocationException) $RecipientMap
                if ($exchExc.Count -gt 0) { $newParams['ExchangeLocationException'] = $exchExc }
                $spExc = Invoke-LocationRemap (Get-LocationNames $policy.SharePointLocationException) $RecipientMap
                if ($spExc.Count -gt 0) { $newParams['SharePointLocationException'] = $spExc }
                $odExc = Invoke-LocationRemap (Get-LocationNames $policy.OneDriveLocationException) $RecipientMap
                if ($odExc.Count -gt 0) { $newParams['OneDriveLocationException'] = $odExc }
                $mgExc = Invoke-LocationRemap (Get-LocationNames $policy.ModernGroupLocationException) $RecipientMap
                if ($mgExc.Count -gt 0) { $newParams['ModernGroupLocationException'] = $mgExc }

                if ($policy.AdvancedSettings -and $policy.AdvancedSettings.Count -gt 0) {
                    $newParams['AdvancedSettings'] = $policy.AdvancedSettings
                }

                try {
                    New-LabelPolicy @newParams -ErrorAction Stop
                    Write-Host "   ✅ $policyName (created)" -ForegroundColor Green
                    $created++

                    # Apply Settings in a second pass (New-LabelPolicy doesn't accept -Settings directly)
                    if ($policy.Settings -and $policy.Settings.Count -gt 0) {
                        $policySettings = ConvertFrom-PolicySettings -Settings $policy.Settings -GuidMap $guidMap
                        if ($policySettings.Count -gt 0) {
                            Start-Sleep -Seconds 2
                            Set-LabelPolicy -Identity $policyName -Settings $policySettings -ErrorAction Stop
                            Write-Host "      + Applied Settings ($($policySettings.Count) properties)" -ForegroundColor DarkGray
                        }
                    }
                    Start-Sleep -Seconds 2
                } catch {
                    # Handle recipient-related failures: retry without specific-user locations
                    if ($_.Exception.Message -match 'recipient|mailbox|not found|couldn.t be found|invalid') {
                        Write-Host "   ⚠️  $policyName — recipient error, retrying without specific-user locations..." -ForegroundColor Yellow
                        Write-Host "      Error: $($_.Exception.Message)" -ForegroundColor Yellow

                        # Log the excluded locations
                        $excludedLocs = @()
                        foreach ($locKey in @('ExchangeLocation','SharePointLocation','OneDriveLocation','ModernGroupLocation')) {
                            $locVal = $newParams[$locKey]
                            if ($locVal -and $locVal -ne 'All' -and ($locVal -is [array] -and $locVal[0] -ne 'All')) {
                                $excludedLocs += "$locKey : $($locVal -join ', ')"
                                $newParams.Remove($locKey)
                            }
                        }
                        foreach ($locKey in @('ExchangeLocationException','SharePointLocationException','OneDriveLocationException','ModernGroupLocationException')) {
                            if ($newParams.ContainsKey($locKey)) {
                                $excludedLocs += "$locKey : $($newParams[$locKey] -join ', ')"
                                $newParams.Remove($locKey)
                            }
                        }
                        if ($excludedLocs.Count -gt 0) {
                            Write-Host "      Excluded locations:" -ForegroundColor Yellow
                            $excludedLocs | ForEach-Object { Write-Host "         - $_" -ForegroundColor Yellow }
                        }

                        try {
                            New-LabelPolicy @newParams -ErrorAction Stop
                            Write-Host "   ✅ $policyName (created without specific locations)" -ForegroundColor Green
                            Write-Host "      ⚠️  Location scoping must be configured manually in the portal" -ForegroundColor Yellow
                            $created++
                            Start-Sleep -Seconds 2
                        } catch {
                            Write-Host "   ❌ $policyName — create failed: $($_.Exception.Message)" -ForegroundColor Red
                        }
                    } else {
                        Write-Host "   ❌ $policyName — create failed: $($_.Exception.Message)" -ForegroundColor Red
                    }
                }
            }
        }
    }
    Write-Host ""
} else {
    Write-Host "⏩ Step 4: No policies file specified — skipping policy import" -ForegroundColor DarkGray
    Write-Host ""
}

# ── Output label GUID map for downstream scripts ─────────────────────
if ($guidMap.Count -gt 0) {
    $mapFile = Join-Path (Split-Path $LabelsFile -Parent) "label-guid-map.json"
    $guidMap | ConvertTo-Json | Out-File -FilePath $mapFile -Encoding UTF8 -Force
    Write-Host "📄 Label GUID map written to: $mapFile ($($guidMap.Count) mapping(s))" -ForegroundColor Gray
}

# ── Summary ───────────────────────────────────────────────────────────
Write-Host ""
Write-Host "✅ Label import complete!" -ForegroundColor Green
Write-Host ""
Write-Host "   Created: $created" -ForegroundColor Green
Write-Host "   Updated: $updated" -ForegroundColor Cyan
Write-Host "   Skipped: $skipped" -ForegroundColor DarkGray
Write-Host ""
Write-Host "💡 Note: Label policies may take up to 24 hours to propagate to all users." -ForegroundColor Yellow
