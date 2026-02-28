<#
.SYNOPSIS
    Import DLP compliance policies and rules from JSON backup files

.DESCRIPTION
    Recreates DLP compliance policies and their associated rules on the target
    tenant from JSON files produced by 07-Export-DlpPolicies.ps1.

    Import order:
    1. DLP policies (must exist before rules)
    2. DLP rules (linked to their parent policy by name)

    Optional transform layer (-MappingFile / switches) performs these cleanups
    before any tenant write, matching the 5 "dirty tricks" used for cross-tenant
    or prod→test migrations:

    Transform 1 — Name sanitisation (-SanitizeNames)
        Replaces PS-unfriendly characters (|, :, /, \, etc.) with "_" in policy
        and rule names.

    Transform 2 — Locations → All (-LocationsToAll)
        Replaces every specific location (user/group UPN or GUID) with "All".
        Location *exceptions* (…Exception arrays) are replaced with the value of
        MappingFile.DummyExclusionGroup so the scope stays broad but is not open
        to literally everyone. A console warning is printed for each policy that
        needs manual follow-up.

    Transform 3 — Printer group remapping (MappingFile.PrinterGroupMap)
        Swaps source endpoint printer-group IDs for their target equivalents in
        EndpointDlpLocation and EndpointDlpLocationException.

    Transform 4 — External domain exception → exemption group (MappingFile.ExemptionGroupId)
        ExchangeLocationException entries that look like domains (@domain.com or
        domain.com) are removed and the ExemptionGroupId is injected instead.

    Transform 5 — Label and SIT ID remapping (MappingFile.LabelIdMap / .SitIdMap)
        Walks each rule's ContentContainsSensitiveInformation array. Replaces
        every SIT "id" field found in SitIdMap and every label GUID found in
        LabelIdMap with the corresponding target ID.

    Transform 6 — Evidence storage location remapping (MappingFile.EvidenceStorageMap)
        Replaces EvidenceStorage and IncidentReportDestination values on each
        rule using a source→target map. Typically SharePoint site URLs or
        storage IDs that differ between source and target tenants.

.PARAMETER PoliciesFile
    Path to the DLP policies JSON export file.

.PARAMETER RulesFile
    Optional path to the DLP rules JSON export file.

.PARAMETER MappingFile
    Optional path to a JSON mapping configuration file.
    See dlp-import-mapping.sample.json for the expected schema.
    Enables Transforms 3, 4, and 5 automatically when the relevant sections are
    present. Also provides DummyExclusionGroup used by -LocationsToAll.

.PARAMETER LocationsToAll
    Enable Transform 2: replace all specific location values with "All" and
    route location exceptions to MappingFile.DummyExclusionGroup.
    Requires MappingFile.DummyExclusionGroup to be set if any exceptions exist.

.PARAMETER SanitizeNames
    Enable Transform 1: replace PS-unfriendly characters in policy/rule names
    with "_". Uses MappingFile.CharSanitization map if provided, otherwise
    applies the built-in default set ( | : / \ ).

.PARAMETER SkipExisting
    Skip policies/rules that already exist on the target (default: update them).

.PARAMETER TestMode
    Import policies in TestWithNotifications mode for safe testing.

.PARAMETER Force
    Suppress confirmation prompts.

.PARAMETER WhatIf
    Show what would be imported without making changes.

.EXAMPLE
    # Straight import — no transforms
    .\08-Import-DlpPolicies.ps1 `
        -PoliciesFile ".\exports\dlp-policies-export-20260226-120000.json" `
        -RulesFile    ".\exports\dlp-rules-export-20260226-120000.json"

.EXAMPLE
    # Full prod→test migration with all 5 transforms
    .\08-Import-DlpPolicies.ps1 `
        -PoliciesFile  ".\exports\dlp-policies-export-20260226-120000.json" `
        -RulesFile     ".\exports\dlp-rules-export-20260226-120000.json" `
        -MappingFile   ".\dlp-import-mapping.json" `
        -LocationsToAll `
        -SanitizeNames `
        -TestMode

.EXAMPLE
    # Dry run — see what would be created without touching the tenant
    .\08-Import-DlpPolicies.ps1 `
        -PoliciesFile ".\exports\dlp-policies-export-20260226-120000.json" `
        -MappingFile  ".\dlp-import-mapping.json" `
        -LocationsToAll -SanitizeNames -WhatIf

.NOTES
    Must be connected to the TARGET tenant's Security & Compliance PowerShell.
    Run: .\01-Connect-Tenant.ps1 -TenantType Target

    Copy dlp-import-mapping.sample.json → dlp-import-mapping.json and fill in
    the target-tenant GUIDs before running with -MappingFile.
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
    [ValidateScript({ Test-Path $_ })]
    [string]$MappingFile,

    [switch]$LocationsToAll,
    [switch]$SanitizeNames,
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

# ── Transform 1: Name sanitisation ───────────────────────────────────
# Replaces characters that are troublesome in PowerShell command values.
function Invoke-NameSanitization {
    param([string]$Name, [hashtable]$CharMap)
    $result = $Name
    if ($CharMap -and $CharMap.Count -gt 0) {
        foreach ($k in $CharMap.Keys) { $result = $result.Replace($k, $CharMap[$k]) }
    } else {
        # Built-in defaults
        foreach ($ch in @('|',':','/','\','<','>','"',"'",'?','*')) {
            $result = $result.Replace($ch, '_')
        }
    }
    return $result.Trim()
}

# ── Transform 2: Locations → All ─────────────────────────────────────
# Replaces specific location arrays with @('All').
# Replaces exception arrays with the DummyExclusionGroup.
function Invoke-LocationToAll {
    param(
        [PSCustomObject]$Policy,
        [string]$DummyExclusionGroup
    )
    $locationProps  = @('ExchangeLocation','SharePointLocation','OneDriveLocation',
                        'TeamsLocation','EndpointDlpLocation','OnPremisesScannerDlpLocation',
                        'ThirdPartyAppDlpLocation')
    $exceptionProps = @('ExchangeLocationException','SharePointLocationException',
                        'OneDriveLocationException','TeamsLocationException',
                        'EndpointDlpLocationException','OnPremisesScannerDlpLocationException',
                        'ThirdPartyAppDlpLocationException')
    $warnings = @()

    foreach ($prop in $locationProps) {
        $val = Get-LocationNames $Policy.$prop
        if ($val.Count -gt 0 -and -not ($val.Count -eq 1 -and $val[0] -eq 'All')) {
            $Policy.$prop = @('All')
            $warnings += "  ⚠️  $prop → 'All'  (was: $($val -join ', '))"
        }
    }
    foreach ($prop in $exceptionProps) {
        $val = Get-LocationNames $Policy.$prop
        if ($val.Count -gt 0) {
            if ($DummyExclusionGroup) {
                $Policy.$prop = @($DummyExclusionGroup)
                $warnings += "  ⚠️  $prop → DummyExclusionGroup  (was: $($val -join ', '))"
            } else {
                $warnings += "  ⚠️  $prop has exceptions but no DummyExclusionGroup set — left unchanged: $($val -join ', ')"
            }
        }
    }
    return $warnings
}

# ── Transform 3: Printer group ID remapping ───────────────────────────
# Remaps EndpointDlpLocation / EndpointDlpLocationException entries by
# matching against PrinterGroupMap keys.
function Invoke-PrinterGroupRemap {
    param([PSCustomObject]$Policy, [hashtable]$PrinterGroupMap)
    if (-not $PrinterGroupMap -or $PrinterGroupMap.Count -eq 0) { return }
    foreach ($prop in @('EndpointDlpLocation','EndpointDlpLocationException')) {
        $vals = Get-LocationNames $Policy.$prop
        if ($vals.Count -gt 0) {
            $remapped = @($vals | ForEach-Object {
                if ($PrinterGroupMap.ContainsKey($_)) { $PrinterGroupMap[$_] } else { $_ }
            })
            $Policy.$prop = $remapped
        }
    }
}

# ── Transform 4: External domain exceptions → exemption group ────────
# Any ExchangeLocationException entry that looks like a domain
# (starts with @ or contains a dot but no spaces) is removed and
# replaced with ExemptionGroupId.
function Invoke-ExternalDomainTransform {
    param([PSCustomObject]$Policy, [string]$ExemptionGroupId)
    if (-not $ExemptionGroupId) { return $false }
    $vals    = @(Get-LocationNames $Policy.ExchangeLocationException)
    $domains = @($vals | Where-Object { $_ -match '^@|^[^@\s]+\.[^@\s]+$' })
    if ($domains.Count -eq 0) { return $false }
    $keep    = @($vals | Where-Object { $_ -notmatch '^@|^[^@\s]+\.[^@\s]+$' })
    $keep   += $ExemptionGroupId
    $Policy.ExchangeLocationException = $keep
    return $true
}

# ── Transform 5: Label and SIT ID remapping in rules ─────────────────
# Walks ContentContainsSensitiveInformation and replaces GUIDs using
# the provided maps. Works on both array-of-hashtable and JSON objects.
function Invoke-IdRemap {
    param([PSCustomObject]$Rule, [hashtable]$SitIdMap, [hashtable]$LabelIdMap)
    if (-not $Rule.ContentContainsSensitiveInformation) { return }
    $remapped = @()
    foreach ($item in $Rule.ContentContainsSensitiveInformation) {
        # Convert PSCustomObject → hashtable for easy mutation
        $ht = @{}
        $item.PSObject.Properties | ForEach-Object { $ht[$_.Name] = $_.Value }

        # SIT id field
        if ($ht.ContainsKey('id') -and $SitIdMap -and $SitIdMap.ContainsKey($ht['id'])) {
            $ht['id'] = $SitIdMap[$ht['id']]
        }
        # Label GUID embedded in SIT conditions
        if ($ht.ContainsKey('labelId') -and $LabelIdMap -and $LabelIdMap.ContainsKey($ht['labelId'])) {
            $ht['labelId'] = $LabelIdMap[$ht['labelId']]
        }
        $remapped += $ht
    }
    $Rule.ContentContainsSensitiveInformation = $remapped
}

# ── Transform 6: Evidence storage location remapping ────────────────
# Replaces EvidenceStorage and IncidentReportDestination SharePoint URLs
# (or storage IDs) in rules using a source→target map.
function Invoke-EvidenceStorageRemap {
    param([PSCustomObject]$Rule, [hashtable]$EvidenceStorageMap)
    if (-not $EvidenceStorageMap -or $EvidenceStorageMap.Count -eq 0) { return $false }
    $changed = $false
    if ($Rule.EvidenceStorage -and $EvidenceStorageMap.ContainsKey($Rule.EvidenceStorage)) {
        $Rule.EvidenceStorage = $EvidenceStorageMap[$Rule.EvidenceStorage]
        $changed = $true
    }
    if ($Rule.IncidentReportDestination -and $EvidenceStorageMap.ContainsKey($Rule.IncidentReportDestination)) {
        $Rule.IncidentReportDestination = $EvidenceStorageMap[$Rule.IncidentReportDestination]
        $changed = $true
    }
    return $changed
}


Write-Host ""
Write-Host "   Policies file: $PoliciesFile" -ForegroundColor Gray
if ($RulesFile)    { Write-Host "   Rules file:    $RulesFile"    -ForegroundColor Gray }
if ($MappingFile)  { Write-Host "   Mapping file:  $MappingFile"  -ForegroundColor Gray }
if ($SanitizeNames){ Write-Host "   🔧 Transform 1: Name sanitisation — ON"  -ForegroundColor DarkYellow }
if ($LocationsToAll){ Write-Host "   🔧 Transform 2: Locations → All — ON"   -ForegroundColor DarkYellow }
if ($TestMode)     { Write-Host "   ⚠️  Test mode:   Policies will be created in TestWithNotifications mode" -ForegroundColor Yellow }
Write-Host ""

# ─────────────────────────────────────────────────────────────────────
# STEP 1: Load source data
# ─────────────────────────────────────────────────────────────────────
Write-Host "⏳ Step 1: Loading DLP policy definitions..." -ForegroundColor Yellow

$sourcePolicies = ConvertFrom-JsonSafe (Get-Content $PoliciesFile -Raw)
Write-Host "   📋 Found $($sourcePolicies.Count) policy(ies) in export file" -ForegroundColor Gray

$sourceRules = @()
if ($RulesFile) {
    $sourceRules = ConvertFrom-JsonSafe (Get-Content $RulesFile -Raw)
    Write-Host "   📋 Found $($sourceRules.Count) rule(s) in export file" -ForegroundColor Gray
}
Write-Host ""

# ─────────────────────────────────────────────────────────────────────
# STEP 2: Load mapping / transform configuration
# ─────────────────────────────────────────────────────────────────────
$mapping           = $null
$charMap           = @{}
$labelIdMap        = @{}
$sitIdMap          = @{}
$printerGroupMap   = @{}
$evidenceStorageMap = @{}
$exemptionGroupId  = $null
$dummyExclusionGroup = $null

if ($MappingFile) {
    Write-Host "⏳ Step 2: Loading mapping configuration..." -ForegroundColor Yellow
    try {
        $mapping = Get-Content $MappingFile -Raw | ConvertFrom-Json
        Write-Host "   ✅ Mapping file loaded" -ForegroundColor Green

        if ($mapping.CharSanitization) {
            $mapping.CharSanitization.PSObject.Properties | ForEach-Object { $charMap[$_.Name] = $_.Value }
            Write-Host "   🔧 T1 CharSanitization: $($charMap.Count) rule(s)" -ForegroundColor DarkGray
        }
        if ($mapping.LabelIdMap) {
            $mapping.LabelIdMap.PSObject.Properties | ForEach-Object { $labelIdMap[$_.Name] = $_.Value }
            Write-Host "   🔧 T5 LabelIdMap:        $($labelIdMap.Count) mapping(s)" -ForegroundColor DarkGray
        }
        if ($mapping.SitIdMap) {
            $mapping.SitIdMap.PSObject.Properties | ForEach-Object { $sitIdMap[$_.Name] = $_.Value }
            Write-Host "   🔧 T5 SitIdMap:          $($sitIdMap.Count) mapping(s)" -ForegroundColor DarkGray
        }
        if ($mapping.PrinterGroupMap) {
            $mapping.PrinterGroupMap.PSObject.Properties | ForEach-Object { $printerGroupMap[$_.Name] = $_.Value }
            Write-Host "   🔧 T3 PrinterGroupMap:   $($printerGroupMap.Count) mapping(s)" -ForegroundColor DarkGray
        }
        if ($mapping.ExemptionGroupId) {
            $exemptionGroupId = $mapping.ExemptionGroupId
            Write-Host "   🔧 T4 ExemptionGroupId:  $exemptionGroupId" -ForegroundColor DarkGray
        }
        if ($mapping.DummyExclusionGroup) {
            $dummyExclusionGroup = $mapping.DummyExclusionGroup
            Write-Host "   🔧 T2 DummyExclusionGroup: $dummyExclusionGroup" -ForegroundColor DarkGray
        }
        if ($mapping.EvidenceStorageMap) {
            $mapping.EvidenceStorageMap.PSObject.Properties | ForEach-Object { $evidenceStorageMap[$_.Name] = $_.Value }
            Write-Host "   🔧 T6 EvidenceStorageMap: $($evidenceStorageMap.Count) mapping(s)" -ForegroundColor DarkGray
        }
    } catch {
        Write-Host "   ❌ Failed to load mapping file: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
    Write-Host ""
} else {
    Write-Host "⏩ Step 2: No mapping file — transforms 3/4/5 disabled" -ForegroundColor DarkGray
    Write-Host ""
}

# ─────────────────────────────────────────────────────────────────────
# STEP 3: Apply transforms (in-memory, before any tenant write)
# ─────────────────────────────────────────────────────────────────────
$anyTransform = $SanitizeNames -or $LocationsToAll -or $printerGroupMap.Count -gt 0 `
                -or $exemptionGroupId -or $labelIdMap.Count -gt 0 -or $sitIdMap.Count -gt 0 `
                -or $evidenceStorageMap.Count -gt 0

if ($anyTransform) {
    Write-Host "⏳ Step 3: Applying transforms..." -ForegroundColor Yellow

    # Build a name→sanitised-name map so rules can track their parent policy rename
    $policyNameMap = @{}   # oldName → newName

    foreach ($policy in $sourcePolicies) {
        $originalName = $policy.Name

        # T1 — Name sanitisation
        if ($SanitizeNames) {
            $cleanName = Invoke-NameSanitization -Name $policy.Name -CharMap $charMap
            if ($cleanName -ne $policy.Name) {
                Write-Host "   T1 ✏️  '$($policy.Name)' → '$cleanName'" -ForegroundColor DarkYellow
                $policyNameMap[$policy.Name] = $cleanName
                $policy.Name = $cleanName
            }
        }

        # T2 — Locations → All
        if ($LocationsToAll) {
            $warnings = Invoke-LocationToAll -Policy $policy -DummyExclusionGroup $dummyExclusionGroup
            if ($warnings.Count -gt 0) {
                Write-Host "   T2 📋 $($policy.Name):" -ForegroundColor DarkYellow
                $warnings | ForEach-Object { Write-Host "     $_" -ForegroundColor DarkGray }
                Write-Host "     💡 TODO: Manually assign correct groups/users in Purview portal." -ForegroundColor Yellow
            }
        }

        # T3 — Printer group remapping
        if ($printerGroupMap.Count -gt 0) {
            Invoke-PrinterGroupRemap -Policy $policy -PrinterGroupMap $printerGroupMap
        }

        # T4 — External domain exceptions → exemption group
        if ($exemptionGroupId) {
            $changed = Invoke-ExternalDomainTransform -Policy $policy -ExemptionGroupId $exemptionGroupId
            if ($changed) {
                Write-Host "   T4 🌐 $($policy.Name): domain exceptions replaced with exemption group" -ForegroundColor DarkYellow
            }
        }
    }

    # T1 — Sanitise rule names and fix parent policy references
    if ($SanitizeNames -or $policyNameMap.Count -gt 0) {
        foreach ($rule in $sourceRules) {
            if ($SanitizeNames) {
                $cleanName = Invoke-NameSanitization -Name $rule.Name -CharMap $charMap
                if ($cleanName -ne $rule.Name) {
                    Write-Host "   T1 ✏️  Rule '$($rule.Name)' → '$cleanName'" -ForegroundColor DarkYellow
                    $rule.Name = $cleanName
                }
            }
            # Remap ParentPolicyName if the policy was renamed
            if ($policyNameMap.ContainsKey($rule.ParentPolicyName)) {
                $rule.ParentPolicyName = $policyNameMap[$rule.ParentPolicyName]
            }
        }
    }

    # T5 — SIT and Label ID remapping in rules
    if ($sitIdMap.Count -gt 0 -or $labelIdMap.Count -gt 0) {
        foreach ($rule in $sourceRules) {
            Invoke-IdRemap -Rule $rule -SitIdMap $sitIdMap -LabelIdMap $labelIdMap
        }
        Write-Host "   T5 🔑 SIT/Label ID remapping applied to $($sourceRules.Count) rule(s)" -ForegroundColor DarkYellow
    }

    # T6 — Evidence storage location remapping
    if ($evidenceStorageMap.Count -gt 0) {
        $t6Count = 0
        foreach ($rule in $sourceRules) {
            if (Invoke-EvidenceStorageRemap -Rule $rule -EvidenceStorageMap $evidenceStorageMap) {
                Write-Host "   T6 🗄️  Rule '$($rule.Name)': evidence storage remapped" -ForegroundColor DarkYellow
                $t6Count++
            }
        }
        if ($t6Count -eq 0) {
            Write-Host "   T6 🗄️  EvidenceStorageMap loaded but no matching locations found in rules" -ForegroundColor DarkGray
        }
    }

    Write-Host "   ✅ Transforms complete" -ForegroundColor Green
    Write-Host ""
} else {
    Write-Host "⏩ Step 3: No transforms configured — importing as-is" -ForegroundColor DarkGray
    Write-Host ""
}

# ─────────────────────────────────────────────────────────────────────
# STEP 4: Import DLP policies
# ─────────────────────────────────────────────────────────────────────
Write-Host "⏳ Step 4: Importing DLP policies..." -ForegroundColor Yellow

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
                $exchLoc = Get-LocationNames $policy.ExchangeLocation
                if ($exchLoc.Count -gt 0) { $newParams['ExchangeLocation'] = $exchLoc }
                $spLoc = Get-LocationNames $policy.SharePointLocation
                if ($spLoc.Count -gt 0) { $newParams['SharePointLocation'] = $spLoc }
                $odLoc = Get-LocationNames $policy.OneDriveLocation
                if ($odLoc.Count -gt 0) { $newParams['OneDriveLocation'] = $odLoc }
                $teamsLoc = Get-LocationNames $policy.TeamsLocation
                if ($teamsLoc.Count -gt 0) { $newParams['TeamsLocation'] = $teamsLoc }
                $endpointLoc = Get-LocationNames $policy.EndpointDlpLocation
                if ($endpointLoc.Count -gt 0) { $newParams['EndpointDlpLocation'] = $endpointLoc }
                $onPremLoc = Get-LocationNames $policy.OnPremisesScannerDlpLocation
                if ($onPremLoc.Count -gt 0) { $newParams['OnPremisesScannerDlpLocation'] = $onPremLoc }
                $thirdPartyLoc = Get-LocationNames $policy.ThirdPartyAppDlpLocation
                if ($thirdPartyLoc.Count -gt 0) { $newParams['ThirdPartyAppDlpLocation'] = $thirdPartyLoc }
                
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
# STEP 5: Import DLP rules
# ─────────────────────────────────────────────────────────────────────
if ($sourceRules.Count -gt 0) {
    Write-Host "⏳ Step 5: Importing DLP rules..." -ForegroundColor Yellow
    
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
                    if ($rule.NotifyAllowOverride)    { $newParams['NotifyAllowOverride'] = $rule.NotifyAllowOverride }                    if ($rule.EvidenceStorage)        { $setParams['EvidenceStorage'] = $rule.EvidenceStorage }
                    if ($rule.IncidentReportDestination) { $setParams['IncidentReportDestination'] = $rule.IncidentReportDestination }                    if ($rule.EvidenceStorage)        { $newParams['EvidenceStorage'] = $rule.EvidenceStorage }
                    if ($rule.IncidentReportDestination) { $newParams['IncidentReportDestination'] = $rule.IncidentReportDestination }
                    
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
    Write-Host "⏩ Step 5: No rules file specified — skipping rule import" -ForegroundColor DarkGray
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
if ($LocationsToAll) {
    Write-Host "💡 Locations were set to 'All'. Policies marked with TODO need manual group" -ForegroundColor Yellow
    Write-Host "   assignment in the Purview portal before enabling in production." -ForegroundColor Yellow
}
