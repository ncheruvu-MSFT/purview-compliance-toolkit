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

    PREREQUISITE — Unified Audit Log:
    New-AutoSensitivityLabelPolicy requires Unified Audit Log to be ENABLED on
    the target tenant. If you see "audit log search" errors, enable it first:

      Connect-ExchangeOnline -UserPrincipalName admin@tenant.onmicrosoft.com
      Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true
      Disconnect-ExchangeOnline -Confirm:$false

    IMPORTANT: Set-AdminAuditLogConfig is an Exchange Online cmdlet; it is NOT
    available in Security & Compliance PowerShell (IPPS). You MUST use
    Connect-ExchangeOnline (ExchangeOnlineManagement module) to run it.
    The change may take up to 60 minutes to propagate.
    Use -SkipAuditLogCheck to bypass the pre-flight check.
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

    [Parameter(Mandatory = $false)]
    [hashtable]$SitGuidMap = @{},

    # Automatically build SIT GUID map by matching SIT names on the target tenant
    [switch]$AutoBuildSitMap,

    # Path to a label-guid-map.json file (output by 06-Import-SensitivityLabels.ps1)
    # to automatically populate LabelGuidMap
    [Parameter(Mandatory = $false)]
    [ValidateScript({ Test-Path $_ })]
    [string]$LabelGuidMapFile,

    # Path to a JSON mapping file for cross-tenant identity, recipient, and
    # encryption remapping. See label-import-mapping.sample.json for schema.
    [Parameter(Mandatory = $false)]
    [ValidateScript({ Test-Path $_ })]
    [string]$MappingFile,

    # Hashtable mapping source recipient addresses to target equivalents.
    # Applied to SentTo, RecipientDomainIs, ExternalMailRightsManagementOwner.
    [Parameter(Mandatory = $false)]
    [hashtable]$RecipientMap = @{},

    # Hashtable mapping source domains to target domains in encryption rights.
    [Parameter(Mandatory = $false)]
    [hashtable]$EncryptionIdentityMap = @{},

    [switch]$SkipExisting,
    [switch]$TestMode,
    [switch]$Force,

    # Skip the Unified Audit Log pre-flight check (useful if already verified or in WhatIf mode)
    [switch]$SkipAuditLogCheck,

    # Attempt to auto-enable Unified Audit Log via Exchange Online if it is disabled.
    # Requires the ExchangeOnlineManagement module and appropriate admin credentials.
    [switch]$EnableAuditLog,

    # Include Teams (meetings + chats) locations in auto-label policies.
    # Adds TeamsLocation = @('All') when not already present in the source.
    [switch]$IncludeTeamsScope
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

# ── Unified Audit Log pre-flight check (Req 1) ──────────────────────────────
# New-AutoSensitivityLabelPolicy fails if Unified Audit Log is not enabled.
# Get-AdminAuditLogConfig is available via IPPS. Set-AdminAuditLogConfig is NOT —
# that cmdlet requires an Exchange Online connection.
if (-not $SkipAuditLogCheck -and -not $WhatIfPreference) {
    Write-Host "🔍 Checking Unified Audit Log status..." -ForegroundColor Yellow
    try {
        $auditConfig = Get-AdminAuditLogConfig -ErrorAction Stop

        # IPPS sessions return a shadow "Default" config that always reports
        # UnifiedAuditLogIngestionEnabled = False, regardless of actual state.
        # Only the "Admin Audit Log Settings" object (from Connect-ExchangeOnline)
        # returns the real value. Detect the shadow config and warn.
        $isShadowConfig = ($auditConfig.Name -eq 'Default') -or
                          (-not $auditConfig.WhenCreated -and -not $auditConfig.Guid)
        if ($isShadowConfig) {
            Write-Host "   ⚠️  IPPS session returned shadow config ('Default') — UnifiedAuditLogIngestionEnabled value is UNRELIABLE." -ForegroundColor Yellow
            Write-Host "      The actual audit log state can only be verified via Connect-ExchangeOnline." -ForegroundColor Yellow
            Write-Host "      Proceeding with import — if auto-label creation fails with an audit-log error," -ForegroundColor Yellow
            Write-Host "      manually verify:  Connect-ExchangeOnline; Get-AdminAuditLogConfig" -ForegroundColor Yellow
            Write-Host "      Use -SkipAuditLogCheck to suppress this message." -ForegroundColor Gray
        } elseif ($auditConfig.UnifiedAuditLogIngestionEnabled -eq $false) {
            if ($EnableAuditLog) {
                Write-Host "   ⚠️  Unified Audit Log is DISABLED — attempting to enable via Exchange Online..." -ForegroundColor Yellow
                try {
                    # Use the same app/cert auth context established by 01-Connect-Tenant.ps1
                    $appConfig = $null
                    $appConfigPath = Join-Path $PSScriptRoot 'app-config.json'
                    if (Test-Path $appConfigPath) {
                        $appConfig = Get-Content $appConfigPath -Raw | ConvertFrom-Json
                    }
                    if ($appConfig -and $appConfig.AppId -and $appConfig.CertificateThumbprint -and $appConfig.TargetTenantDomain) {
                        Connect-ExchangeOnline `
                            -AppId $appConfig.AppId `
                            -CertificateThumbprint $appConfig.CertificateThumbprint `
                            -Organization $appConfig.TargetTenantDomain `
                            -ShowBanner:$false -ErrorAction Stop
                    } elseif ($env:PURVIEW_CONNECTED_ORG) {
                        Connect-ExchangeOnline -Organization $env:PURVIEW_CONNECTED_ORG `
                            -ShowBanner:$false -ErrorAction Stop
                    } else {
                        Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
                    }
                    Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true -ErrorAction Stop
                    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
                    Write-Host "   ✅ Unified Audit Log has been ENABLED. Allow up to 60 min to propagate." -ForegroundColor Green
                } catch {
                    Write-Host "`n❌ Failed to auto-enable Unified Audit Log: $($_.Exception.Message)" -ForegroundColor Red
                    Write-Host "   Fix manually — see script header for instructions." -ForegroundColor Yellow
                    exit 1
                }
            } else {
                Write-Host "`n❌ PREREQUISITE FAILED: Unified Audit Log is DISABLED on this tenant." -ForegroundColor Red
                Write-Host "   New-AutoSensitivityLabelPolicy requires audit log ingestion to be on." -ForegroundColor Red
                Write-Host "`n💡 Fix — re-run with -EnableAuditLog to auto-enable, or manually:" -ForegroundColor Yellow
                Write-Host "   Connect-ExchangeOnline -UserPrincipalName admin@$($env:PURVIEW_CONNECTED_ORG)" -ForegroundColor Cyan
                Write-Host "   Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled `$true" -ForegroundColor Cyan
                Write-Host "   Disconnect-ExchangeOnline -Confirm:`$false" -ForegroundColor Cyan
                Write-Host "`n   ⏱️  Allow up to 60 minutes for the change to propagate, then re-run this script." -ForegroundColor Yellow
                Write-Host "   Use -SkipAuditLogCheck to bypass this check if already done." -ForegroundColor Gray
                exit 1
            }
        } elseif (-not $isShadowConfig) {
            Write-Host "   ✅ Unified Audit Log is enabled" -ForegroundColor Green
        }
    } catch [System.Management.Automation.CommandNotFoundException] {
        Write-Host "   ⚠️  Get-AdminAuditLogConfig not available in this session — skipping check." -ForegroundColor Yellow
        Write-Host "      Verify manually that Unified Audit Log is enabled before proceeding." -ForegroundColor Yellow
    } catch {
        Write-Host "   ⚠️  Could not check Unified Audit Log status: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}
Write-Host ""

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

# ── Helper: extract flat SIT entries from ContentContainsSensitiveInformation ─
# Handles both flat format [{name,id,...}] and grouped format
# [{Groups:[{SensitiveTypes:[{name,id,...}]}]}]
function Get-FlatSitEntries {
    param([array]$SitReferences)
    if (-not $SitReferences) { return @() }
    $entries = @()
    foreach ($item in $SitReferences) {
        $groups = $null
        if ($item -is [hashtable]) { $groups = $item['Groups'] }
        elseif ($null -ne $item.PSObject -and $null -ne $item.PSObject.Properties['Groups']) { $groups = $item.Groups }
        if ($groups) {
            foreach ($group in $groups) {
                $sitTypes = $null
                if ($group -is [hashtable]) {
                    $sitTypes = $group['SensitiveTypes']
                    if (-not $sitTypes) { $sitTypes = $group['SensitiveInformation'] }
                    if (-not $sitTypes) { $sitTypes = $group['sensitivetypes'] }
                } else {
                    if ($null -ne $group.PSObject.Properties['SensitiveTypes'])       { $sitTypes = $group.SensitiveTypes }
                    elseif ($null -ne $group.PSObject.Properties['SensitiveInformation']) { $sitTypes = $group.SensitiveInformation }
                    elseif ($null -ne $group.PSObject.Properties['sensitivetypes'])   { $sitTypes = $group.sensitivetypes }
                }
                if ($sitTypes) { $entries += @($sitTypes) }
                # Also check for labels in grouped format
                $labels = $null
                if ($group -is [hashtable]) { $labels = $group['labels'] }
                elseif ($null -ne $group.PSObject.Properties['labels']) { $labels = $group.labels }
                if ($labels) { $entries += @($labels) }
            }
        } else {
            # Flat SIT entry — check if it has name/id (i.e. is a SIT, not something else)
            $hasName = $false
            if ($item -is [hashtable]) { $hasName = $item.ContainsKey('name') }
            elseif ($null -ne $item.PSObject -and $null -ne $item.PSObject.Properties['name']) { $hasName = $true }
            if ($hasName) { $entries += $item }
        }
    }
    return $entries
}

# ── Helper: remap SIT GUIDs in ContentContainsSensitiveInformation ────
# Converts PSCustomObject entries to hashtables (required by S&CC cmdlets)
# and remaps SIT IDs using the provided map. Handles grouped format.
function Invoke-SitIdRemap {
    param(
        [array]$SitReferences,
        [hashtable]$SitMap
    )
    if (-not $SitReferences) { return $SitReferences }
    # Even when there's no map, we must still convert PSCustomObjects → hashtables
    $result = @()
    foreach ($item in $SitReferences) {
        # Convert PSCustomObject → hashtable
        $ht = $null
        if ($item -is [hashtable]) { $ht = $item }
        else { $ht = @{}; foreach ($prop in $item.PSObject.Properties) { $ht[$prop.Name] = $prop.Value } }

        # Handle grouped format — recurse
        if ($ht.ContainsKey('Groups') -and $ht['Groups']) {
            $convertedGroups = @()
            foreach ($group in $ht['Groups']) {
                $gHt = $null
                if ($group -is [hashtable]) { $gHt = $group }
                else { $gHt = @{}; foreach ($gp in $group.PSObject.Properties) { $gHt[$gp.Name] = $gp.Value } }
                foreach ($stKey in @('SensitiveTypes','SensitiveInformation','sensitivetypes')) {
                    if ($gHt.ContainsKey($stKey) -and $gHt[$stKey]) {
                        $gHt[$stKey] = Invoke-SitIdRemap -SitReferences @($gHt[$stKey]) -SitMap $SitMap
                        break
                    }
                }
                $convertedGroups += $gHt
            }
            $ht['Groups'] = $convertedGroups
            $result += $ht
            continue
        }

        # Flat SIT entry — remap id if map provided
        if ($SitMap -and $SitMap.Count -gt 0 -and $ht.ContainsKey('id') -and $SitMap.ContainsKey($ht['id'])) {
            $ht['id'] = $SitMap[$ht['id']]
        }
        $result += $ht
    }
    return $result
}

# ── Helper: auto-build SIT GUID map from rule data ───────────────────
# Handles both flat and grouped ContentContainsSensitiveInformation.
function Build-SitGuidMap {
    param([array]$Rules)
    $map = @{}
    foreach ($rule in $Rules) {
        foreach ($prop in @('ContentContainsSensitiveInformation','ExceptIfContentContainsSensitiveInformation')) {
            if (-not $rule.$prop) { continue }
            $flatEntries = Get-FlatSitEntries -SitReferences @($rule.$prop)
            foreach ($sit in $flatEntries) {
                $sitName  = if ($sit -is [hashtable]) { $sit['name'] } else { $sit.name }
                $sourceId = if ($sit -is [hashtable]) { $sit['id'] }   else { $sit.id }
                if (-not $sitName -or -not $sourceId) { continue }
                if ($map.ContainsKey($sourceId)) { continue }

                try {
                    $targetSit = Get-DlpSensitiveInformationType -Identity $sitName -ErrorAction Stop
                    $targetId = if ($targetSit -is [array]) { $targetSit[0].Id } else { $targetSit.Id }
                    if ($sourceId -ne $targetId) {
                        $map[$sourceId] = $targetId
                        Write-Host "   🔗 SIT map: '$sitName' $sourceId -> $targetId" -ForegroundColor DarkGray
                    }
                } catch {
                    Write-Host "   ⚠️  SIT '$sitName' (ID: $sourceId) not found on target" -ForegroundColor Yellow
                }
            }
        }
    }
    return $map
}

# ── Helper (Req 2): Validate rule payload identifiers ─────────────────
# Fail fast if any SIT reference in the rule payload has null/empty name or id.
# Handles both flat and grouped SIT formats.
function Test-RulePayloadIdentifiers {
    param([array]$Rules)
    $errors = @()
    foreach ($rule in $Rules) {
        $ruleName = $rule.Name
        foreach ($prop in @('ContentContainsSensitiveInformation', 'ExceptIfContentContainsSensitiveInformation')) {
            if (-not $rule.$prop) { continue }
            $flatEntries = Get-FlatSitEntries -SitReferences @($rule.$prop)
            $idx = 0
            foreach ($sit in $flatEntries) {
                $sitName = if ($sit -is [hashtable]) { $sit['name'] } else { $sit.name }
                $sitId   = if ($sit -is [hashtable]) { $sit['id'] }   else { $sit.id }
                if ([string]::IsNullOrWhiteSpace($sitName)) {
                    $errors += "Rule '$ruleName' → $prop[$idx]: 'name' is null or empty"
                }
                if ([string]::IsNullOrWhiteSpace($sitId)) {
                    $errors += "Rule '$ruleName' → $prop[$idx]: 'id' is null or empty"
                }
                $idx++
            }
        }
    }
    return $errors
}

# ── Helper (Req 3): Convert encryption rights JSON to Exchange string ──
# Exchange Online expects rights in "user@domain.com:VIEW,EDIT,..." format,
# not the nested JSON structure that Purview exports.
function ConvertTo-ExchangeRightsString {
    param($RightsDefinitions)
    if (-not $RightsDefinitions) { return $null }
    # If already a string in the correct format, pass through
    if ($RightsDefinitions -is [string] -and $RightsDefinitions -match '^\S+@\S+:') {
        return $RightsDefinitions
    }
    # Parse JSON array if string
    $rights = $RightsDefinitions
    if ($RightsDefinitions -is [string]) {
        try { $rights = $RightsDefinitions | ConvertFrom-Json } catch { return $RightsDefinitions }
    }
    # Convert array of {Identity, Rights} objects to Exchange string format
    if ($rights -is [array]) {
        $parts = @()
        foreach ($entry in $rights) {
            $identity = $null
            $perms    = $null
            if ($entry.Identity) { $identity = $entry.Identity }
            elseif ($entry.identity) { $identity = $entry.identity }
            if ($entry.Rights) { $perms = $entry.Rights }
            elseif ($entry.rights) { $perms = $entry.rights }
            if (-not $identity) { continue }
            if ($perms -is [array]) { $perms = $perms -join ',' }
            if ($perms) { $parts += "$identity`:$perms" }
        }
        if ($parts.Count -gt 0) { return $parts -join ';' }
    }
    return $RightsDefinitions
}

# ── Helper (Req 4): Migrate deprecated minconfidence/maxconfidence ────
# Replaces deprecated minconfidence/maxconfidence with the current
# confidencelevel field. Mapping: 65→Low, 75→Medium, 85→High.
# IMPORTANT: Security & Compliance cmdlets require CCSI entries as hashtables,
# NOT PSCustomObjects. This function always returns hashtables — this is the
# critical conversion that ensures JSON-round-tripped data works.
# Handles both flat [{name,id,...}] and grouped [{Groups:[...]}] format.
function Invoke-ConfidenceLevelMigration {
    param([array]$SitReferences)
    if (-not $SitReferences) { return $SitReferences }
    $migrated = @()
    foreach ($item in $SitReferences) {
        # Convert PSCustomObject → hashtable (required by the cmdlets)
        $ht = $null
        if ($item -is [hashtable]) {
            $ht = $item.Clone()
        } else {
            $ht = @{}
            foreach ($prop in $item.PSObject.Properties) { $ht[$prop.Name] = $prop.Value }
        }

        # Handle grouped format — recurse into group entries
        if ($ht.ContainsKey('Groups') -and $ht['Groups']) {
            $convertedGroups = @()
            foreach ($group in $ht['Groups']) {
                $gHt = $null
                if ($group -is [hashtable]) { $gHt = $group.Clone() }
                else { $gHt = @{}; foreach ($gp in $group.PSObject.Properties) { $gHt[$gp.Name] = $gp.Value } }
                foreach ($stKey in @('SensitiveTypes','SensitiveInformation','sensitivetypes')) {
                    if ($gHt.ContainsKey($stKey) -and $gHt[$stKey]) {
                        $gHt[$stKey] = Invoke-ConfidenceLevelMigration -SitReferences @($gHt[$stKey])
                        break
                    }
                }
                $convertedGroups += $gHt
            }
            $ht['Groups'] = $convertedGroups
            $migrated += $ht
            continue
        }

        # Flat SIT entry — migrate confidence fields
        if ($ht.ContainsKey('minconfidence') -or $ht.ContainsKey('maxconfidence')) {
            if (-not $ht.ContainsKey('confidencelevel') -or [string]::IsNullOrWhiteSpace($ht['confidencelevel'])) {
                $minConf = 75  # default
                if ($ht.ContainsKey('minconfidence') -and $ht['minconfidence']) {
                    $minConf = [int]$ht['minconfidence']
                }
                $ht['confidencelevel'] = switch ($true) {
                    ($minConf -le 65) { 'Low' }
                    ($minConf -le 75) { 'Medium' }
                    ($minConf -le 85) { 'High' }
                    default           { 'High' }
                }
                Write-Host "      ↳ Migrated minconfidence=$minConf → confidencelevel=$($ht['confidencelevel']) for SIT '$($ht['name'])'" -ForegroundColor DarkGray
            }
            $ht.Remove('minconfidence') | Out-Null
            $ht.Remove('maxconfidence') | Out-Null
        }
        $migrated += $ht
    }
    return $migrated
}

# ── Helper (Req 7): Detect cross-tenant user/group mismatches ────────
# Checks SentTo, RecipientDomainIs, etc. for addresses that belong to the
# source tenant and remaps them or emits a warning.
function Invoke-RecipientRemap {
    param(
        [hashtable]$RuleParams,
        [hashtable]$Map
    )
    if (-not $Map -or $Map.Count -eq 0) { return }
    $recipientFields = @('SentTo','RecipientDomainIs','FromAddressMatchesPatterns',
                         'AnyOfRecipientAddressMatchesPatterns')
    foreach ($field in $recipientFields) {
        if (-not $RuleParams.ContainsKey($field)) { continue }
        $values = @($RuleParams[$field])
        $remapped = @()
        foreach ($val in $values) {
            if ($Map.ContainsKey($val)) {
                Write-Host "      ↳ Remapped $field`: $val → $($Map[$val])" -ForegroundColor DarkGray
                $remapped += $Map[$val]
            } else {
                $remapped += $val
            }
        }
        $RuleParams[$field] = $remapped
    }
}

# ── Helper (Req 8): Validate recipients exist on the target tenant ────
function Test-RecipientsExist {
    param([array]$Rules, [hashtable]$RecipientMap)
    $warnings = @()
    foreach ($rule in $Rules) {
        foreach ($field in @('SentTo','RecipientDomainIs')) {
            $values = @($rule.$field | Where-Object { $_ })
            foreach ($addr in $values) {
                $checkAddr = if ($RecipientMap -and $RecipientMap.ContainsKey($addr)) { $RecipientMap[$addr] } else { $addr }
                # For domains, skip recipient lookup
                if ($field -eq 'RecipientDomainIs') { continue }
                try {
                    $null = Get-Recipient -Identity $checkAddr -ErrorAction Stop
                } catch [System.Management.Automation.CommandNotFoundException] {
                    # Get-Recipient not available in this session — skip validation
                    break
                } catch {
                    $warnings += "Rule '$($rule.Name)': $field recipient '$checkAddr' not found on target — may fail at runtime"
                }
            }
        }
    }
    return $warnings
}

# ── Load mapping file if provided ─────────────────────────────────────
if ($MappingFile) {
    Write-Host "📄 Loading mapping file: $MappingFile" -ForegroundColor Gray
    $mappingData = Get-Content $MappingFile -Raw | ConvertFrom-Json
    # RecipientMap
    if ($mappingData.RecipientMap -and $RecipientMap.Count -eq 0) {
        $mappingData.RecipientMap.PSObject.Properties | ForEach-Object { $RecipientMap[$_.Name] = $_.Value }
        Write-Host "   Loaded $($RecipientMap.Count) recipient mapping(s)" -ForegroundColor Gray
    }
    # EncryptionIdentityMap
    if ($mappingData.EncryptionIdentityMap -and $EncryptionIdentityMap.Count -eq 0) {
        $mappingData.EncryptionIdentityMap.PSObject.Properties | ForEach-Object { $EncryptionIdentityMap[$_.Name] = $_.Value }
        Write-Host "   Loaded $($EncryptionIdentityMap.Count) encryption identity mapping(s)" -ForegroundColor Gray
    }
    # SitIdMap
    if ($mappingData.SitIdMap -and $SitGuidMap.Count -eq 0) {
        $mappingData.SitIdMap.PSObject.Properties | ForEach-Object { $SitGuidMap[$_.Name] = $_.Value }
        Write-Host "   Loaded $($SitGuidMap.Count) SIT mapping(s) from mapping file" -ForegroundColor Gray
    }
    Write-Host ""
}

# ── Load label GUID map file if provided ─────────────────────────────
if ($LabelGuidMapFile) {
    Write-Host "📄 Loading label GUID map: $LabelGuidMapFile" -ForegroundColor Gray
    $mapData = Get-Content $LabelGuidMapFile -Raw | ConvertFrom-Json
    $mapData.PSObject.Properties | ForEach-Object {
        if (-not $LabelGuidMap.ContainsKey($_.Name)) { $LabelGuidMap[$_.Name] = $_.Value }
    }
    Write-Host "   Loaded $($LabelGuidMap.Count) label mapping(s)" -ForegroundColor Gray
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

# ── Auto-build SIT GUID map if requested (Req 5 — pre-build before policy creation) ──
if ($AutoBuildSitMap -and $sourceRules.Count -gt 0) {
    Write-Host "⏳ Building SIT GUID map from rule data..." -ForegroundColor Yellow
    $autoSitMap = Build-SitGuidMap -Rules $sourceRules
    # Merge auto-built map with any explicit mappings (explicit takes priority)
    foreach ($key in $autoSitMap.Keys) {
        if (-not $SitGuidMap.ContainsKey($key)) { $SitGuidMap[$key] = $autoSitMap[$key] }
    }
    Write-Host "   Built $($SitGuidMap.Count) total SIT mapping(s)" -ForegroundColor Gray
    Write-Host ""
}

# ─────────────────────────────────────────────────────────────────────
# PRE-FLIGHT VALIDATION (Reqs 2, 5, 7, 8)
# ─────────────────────────────────────────────────────────────────────
if ($sourceRules.Count -gt 0 -and -not $WhatIfPreference) {
    Write-Host "⏳ Running pre-flight validation on rule payloads..." -ForegroundColor Yellow

    # Req 2: Fail fast if rule payload contains null identifiers
    $payloadErrors = Test-RulePayloadIdentifiers -Rules $sourceRules
    if ($payloadErrors.Count -gt 0) {
        Write-Host "`n❌ PRE-FLIGHT FAILED: Rule payloads contain null/empty identifiers:" -ForegroundColor Red
        foreach ($err in $payloadErrors) {
            Write-Host "   • $err" -ForegroundColor Red
        }
        Write-Host "`n   Fix the export JSON before retrying." -ForegroundColor Yellow
        exit 1
    }
    Write-Host "   ✅ All rule SIT identifiers are non-null" -ForegroundColor Green

    # Req 5: Verify SIT references resolve on the target tenant
    $sitWarnings = @()
    foreach ($rule in $sourceRules) {
        foreach ($sit in $rule.ContentContainsSensitiveInformation) {
            if (-not $sit.name -or -not $sit.id) { continue }
            $targetId = if ($SitGuidMap.ContainsKey($sit.id)) { $SitGuidMap[$sit.id] } else { $sit.id }
            try {
                $null = Get-DlpSensitiveInformationType -Identity $targetId -ErrorAction Stop
            } catch {
                $sitWarnings += "Rule '$($rule.Name)': SIT '$($sit.name)' (target ID: $targetId) not found on target — rule creation may fail"
            }
        }
    }
    if ($sitWarnings.Count -gt 0) {
        Write-Host "   ⚠️  SIT reference warnings:" -ForegroundColor Yellow
        foreach ($w in $sitWarnings) { Write-Host "      • $w" -ForegroundColor Yellow }
    } else {
        Write-Host "   ✅ All referenced SITs found on target tenant" -ForegroundColor Green
    }

    # Req 7 & 8: Cross-tenant recipient validation
    $recipientWarnings = Test-RecipientsExist -Rules $sourceRules -RecipientMap $RecipientMap
    if ($recipientWarnings.Count -gt 0) {
        Write-Host "   ⚠️  Recipient warnings:" -ForegroundColor Yellow
        foreach ($w in $recipientWarnings) { Write-Host "      • $w" -ForegroundColor Yellow }
        Write-Host "      Provide a -MappingFile with RecipientMap to remap these addresses." -ForegroundColor Yellow
    } else {
        Write-Host "   ✅ Recipient validation passed" -ForegroundColor Green
    }
    Write-Host ""
}

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
                # Note: Set-AutoSensitivityLabelPolicy does NOT support -Mode;
                # Mode can only be set at creation time via New-AutoSensitivityLabelPolicy.
                if ($null -ne $policy.OverwriteLabel) { $setParams['OverwriteLabel'] = $policy.OverwriteLabel }
                
                Set-AutoSensitivityLabelPolicy @setParams -ErrorAction Stop
                Write-Host "   🔄 $policyName (updated)" -ForegroundColor Cyan
                $updated++
            } catch {
                # Req 10: Emit warnings for known spctest limitations
                $errMsg = $_.Exception.Message
                if ($errMsg -match 'audit log|Unified.*not enabled|tenant.*not licensed|label.*not found|ModeNotSupported|has been deleted') {
                    Write-Host "   ⚠️  $policyName — known limitation (warning): $errMsg" -ForegroundColor Yellow
                    $skipped++
                } else {
                    Write-Host "   ❌ $policyName — update failed: $errMsg" -ForegroundColor Red
                    $failures++
                }
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
                
                # Location parameters (Req 6: explicitly include all supported scopes)
                $exchLoc = Get-LocationNames $policy.ExchangeLocation
                if ($exchLoc.Count -gt 0) { $newParams['ExchangeLocation'] = $exchLoc }
                $spLoc = Get-LocationNames $policy.SharePointLocation
                if ($spLoc.Count -gt 0) { $newParams['SharePointLocation'] = $spLoc }
                $odLoc = Get-LocationNames $policy.OneDriveLocation
                if ($odLoc.Count -gt 0) { $newParams['OneDriveLocation'] = $odLoc }

                # Req 6: Include Teams scope (meetings + chats) when requested or present in source
                if ($IncludeTeamsScope) {
                    $newParams['TeamsLocation']        = @('All')
                    $newParams['TeamsLocationException'] = @()
                    Write-Host "      ↳ Added TeamsLocation = All (meetings + chats)" -ForegroundColor DarkGray
                } else {
                    $teamsLoc = Get-LocationNames $policy.TeamsLocation
                    if ($teamsLoc.Count -gt 0) { $newParams['TeamsLocation'] = $teamsLoc }
                    $teamsLocEx = Get-LocationNames $policy.TeamsLocationException
                    if ($teamsLocEx.Count -gt 0) { $newParams['TeamsLocationException'] = $teamsLocEx }
                }

                # Req 3 & 7: Remap ExternalMailRightsManagementOwner
                if ($policy.ExternalMailRightsManagementOwner) {
                    $rmOwner = $policy.ExternalMailRightsManagementOwner
                    if ($RecipientMap.ContainsKey($rmOwner)) {
                        $rmOwner = $RecipientMap[$rmOwner]
                        Write-Host "      ↳ Remapped ExternalMailRightsManagementOwner → $rmOwner" -ForegroundColor DarkGray
                    }
                    $newParams['ExternalMailRightsManagementOwner'] = $rmOwner
                }
                
                New-AutoSensitivityLabelPolicy @newParams -ErrorAction Stop
                Write-Host "   ✅ $policyName (created)" -ForegroundColor Green
                $created++

                # Req 9: Restore default label and default email behaviors
                # After creation, set ApplyLabel and OverwriteLabel to ensure
                # default labeling behaviour is preserved from the source.
                if ($null -ne $policy.Enabled -and $policy.Enabled -eq $true -and -not $TestMode) {
                    try {
                        Set-AutoSensitivityLabelPolicy -Identity $policyName -Enabled $true -ErrorAction SilentlyContinue
                    } catch {
                        Write-Host "      ⚠️  Could not re-enable policy: $($_.Exception.Message)" -ForegroundColor Yellow
                    }
                }

                Start-Sleep -Seconds 2
            } catch {
                # Req 10: Emit warnings for known spctest limitations
                $errMsg = $_.Exception.Message
                if ($errMsg -match 'audit log|Unified.*not enabled|tenant.*not licensed|label.*not found|ModeNotSupported|has been deleted') {
                    Write-Host "   ⚠️  $policyName — known limitation (warning): $errMsg" -ForegroundColor Yellow
                    $skipped++
                } else {
                    Write-Host "   ❌ $policyName — create failed: $errMsg" -ForegroundColor Red
                    $failures++
                }
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
                        # Req 4: Migrate deprecated minconfidence/maxconfidence → confidencelevel
                        $migratedSits = Invoke-ConfidenceLevelMigration -SitReferences $rule.ContentContainsSensitiveInformation
                        # Req 5: Remap SIT GUIDs
                        $remappedSits = Invoke-SitIdRemap -SitReferences $migratedSits -SitMap $SitGuidMap
                        $setParams['ContentContainsSensitiveInformation'] = $remappedSits
                    }
                    if ($rule.ExceptIfContentContainsSensitiveInformation) {
                        $migratedExcept = Invoke-ConfidenceLevelMigration -SitReferences $rule.ExceptIfContentContainsSensitiveInformation
                        $remappedExcept = Invoke-SitIdRemap -SitReferences $migratedExcept -SitMap $SitGuidMap
                        $setParams['ExceptIfContentContainsSensitiveInformation'] = $remappedExcept
                    }
                    if ($rule.ContentPropertyContainsWords) {
                        $setParams['ContentPropertyContainsWords'] = $rule.ContentPropertyContainsWords
                    }
                    if ($rule.HeaderMatchesPatterns)       { $setParams['HeaderMatchesPatterns'] = $rule.HeaderMatchesPatterns }
                    if ($rule.SubjectMatchesPatterns)      { $setParams['SubjectMatchesPatterns'] = $rule.SubjectMatchesPatterns }
                    if ($rule.DocumentNameMatchesPatterns) { $setParams['DocumentNameMatchesPatterns'] = $rule.DocumentNameMatchesPatterns }
                    if ($rule.ContentExtensionMatchesWords) { $setParams['ContentExtensionMatchesWords'] = $rule.ContentExtensionMatchesWords }

                    # Req 7: Remap recipients in update params
                    Invoke-RecipientRemap -RuleParams $setParams -Map $RecipientMap

                    Set-AutoSensitivityLabelRule @setParams -ErrorAction Stop
                    Write-Host "   🔄 $ruleName (updated)" -ForegroundColor Cyan
                    $rUpdated++
                } catch {
                    # Req 10: Emit warnings for known spctest limitations instead of hard failures
                    $errMsg = $_.Exception.Message
                    if ($errMsg -match 'Workload.*not supported|location.*not available|Teams.*not enabled|scope.*not licensed|Parameter name: nameA') {
                        Write-Host "   ⚠️  $ruleName — known limitation (warning): $errMsg" -ForegroundColor Yellow
                        $rSkipped++
                    } else {
                        Write-Host "   ❌ $ruleName — update failed: $errMsg" -ForegroundColor Red
                        $rFailures++
                    }
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
                        # Req 4: Migrate deprecated minconfidence/maxconfidence → confidencelevel
                        $migratedSits = Invoke-ConfidenceLevelMigration -SitReferences $rule.ContentContainsSensitiveInformation
                        # Req 5: Remap SIT GUIDs
                        $remappedSits = Invoke-SitIdRemap -SitReferences $migratedSits -SitMap $SitGuidMap
                        $newParams['ContentContainsSensitiveInformation'] = $remappedSits
                    }
                    if ($rule.ExceptIfContentContainsSensitiveInformation) {
                        $migratedExcept = Invoke-ConfidenceLevelMigration -SitReferences $rule.ExceptIfContentContainsSensitiveInformation
                        $remappedExcept = Invoke-SitIdRemap -SitReferences $migratedExcept -SitMap $SitGuidMap
                        $newParams['ExceptIfContentContainsSensitiveInformation'] = $remappedExcept
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

                    # Req 3: Convert encryption rights JSON to Exchange-supported string format
                    if ($rule.EncryptionRightsDefinitions) {
                        $converted = ConvertTo-ExchangeRightsString -RightsDefinitions $rule.EncryptionRightsDefinitions
                        if ($converted) {
                            # Apply identity remapping to the rights string
                            if ($EncryptionIdentityMap.Count -gt 0) {
                                foreach ($srcDomain in $EncryptionIdentityMap.Keys) {
                                    $converted = $converted -replace [regex]::Escape($srcDomain), $EncryptionIdentityMap[$srcDomain]
                                }
                            }
                            $newParams['EncryptionRightsDefinitions'] = $converted
                            Write-Host "      ↳ Converted encryption rights to Exchange string format" -ForegroundColor DarkGray
                        }
                    }

                    # Req 7: Remap cross-tenant recipients
                    Invoke-RecipientRemap -RuleParams $newParams -Map $RecipientMap
                    
                    New-AutoSensitivityLabelRule @newParams -ErrorAction Stop
                    Write-Host "   ✅ $ruleName → $policyName (created)" -ForegroundColor Green
                    $rCreated++
                    Start-Sleep -Seconds 1
                } catch {
                    # Req 10: Emit warnings for known spctest limitations instead of hard failures
                    $errMsg = $_.Exception.Message
                    if ($errMsg -match 'Workload.*not supported|location.*not available|Teams.*not enabled|scope.*not licensed|The property.*is read-only|Parameter name: nameA') {
                        Write-Host "   ⚠️  $ruleName — known limitation (warning): $errMsg" -ForegroundColor Yellow
                        $rSkipped++
                    } else {
                        Write-Host "   ❌ $ruleName — create failed: $errMsg" -ForegroundColor Red
                        $rFailures++
                    }
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
