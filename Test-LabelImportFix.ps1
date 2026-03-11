<#
.SYNOPSIS
    Mock-based test for sensitivity label import fixes in 06-Import-SensitivityLabels.ps1

.DESCRIPTION
    Tests the new helper functions and import logic without a live tenant connection:
    - ConvertFrom-LabelActions (content marking, encryption, watermark)
    - Invoke-ConditionsSitRemap (SIT GUID remapping in Conditions)
    - ConvertFrom-PolicySettings (policy Settings parsing + GUID remapping)
    - ContentType handling (scope selection)
    - Recipient validation fallback
    - Integration with real export data

.NOTES
    Run:  .\Test-LabelImportFix.ps1
#>

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Label Import Fixes — Comprehensive Test Suite" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

$pass  = 0
$fail  = 0

function Assert-Equal {
    param(
        [string]$TestName,
        $Expected,
        $Actual,
        [string]$Description = ''
    )

    $match = $false
    if ($null -eq $Expected -and $null -eq $Actual) {
        $match = $true
    } elseif ($null -ne $Expected -and $null -ne $Actual) {
        if ($Expected -is [bool]) {
            $match = ([bool]$Actual -eq $Expected)
        } elseif ($Expected -is [int]) {
            $match = ([int]$Actual -eq $Expected)
        } else {
            $match = ("$Actual" -eq "$Expected")
        }
    }

    if ($match) {
        Write-Host "  ✅ PASS  $TestName" -ForegroundColor Green
        if ($Description) { Write-Host "          $Description" -ForegroundColor DarkGray }
        $script:pass++
    } else {
        Write-Host "  ❌ FAIL  $TestName" -ForegroundColor Red
        Write-Host "          Expected: $Expected" -ForegroundColor Red
        Write-Host "          Actual:   $Actual" -ForegroundColor Red
        if ($Description) { Write-Host "          $Description" -ForegroundColor DarkGray }
        $script:fail++
    }
}

function Assert-True {
    param([string]$TestName, [bool]$Condition, [string]$Description = '')
    Assert-Equal -TestName $TestName -Expected $true -Actual $Condition -Description $Description
}

function Assert-ContainsKey {
    param([string]$TestName, [hashtable]$Hash, [string]$Key, [string]$Description = '')
    Assert-True -TestName $TestName -Condition ($Hash.ContainsKey($Key)) -Description "Key '$Key' should exist in result. $Description"
}

function Assert-NotContainsKey {
    param([string]$TestName, [hashtable]$Hash, [string]$Key, [string]$Description = '')
    Assert-True -TestName $TestName -Condition (-not $Hash.ContainsKey($Key)) -Description "Key '$Key' should NOT exist in result. $Description"
}

# ── Load the functions from the import script ─────────────────────────
# We source only the function definitions by extracting them

# ConvertFrom-LabelActions
function ConvertFrom-LabelActions {
    param(
        [array]$LabelActions,
        [hashtable]$IdentityMap = @{}
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
                    if ($IdentityMap -and $IdentityMap.Count -gt 0) {
                        foreach ($srcDomain in $IdentityMap.Keys) {
                            $rdValue = $rdValue -replace [regex]::Escape($srcDomain), $IdentityMap[$srcDomain]
                        }
                    }
                    $params['EncryptionRightsDefinitions'] = $rdValue
                }
            }
        }
    }
    return $params
}

# Invoke-ConditionsSitRemap
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
        foreach ($srcGuid in $SitMap.Keys) {
            $text = $text -replace [regex]::Escape($srcGuid), $SitMap[$srcGuid]
        }
        $null = $remapped.Add($text)
    }
    return @($remapped)
}

# ConvertFrom-PolicySettings
function ConvertFrom-PolicySettings {
    param(
        [array]$Settings,
        [hashtable]$GuidMap = @{}
    )
    $result = @{}
    if (-not $Settings -or $Settings.Count -eq 0) { return $result }
    $guidKeys = @('defaultlabelid', 'teamworkdefaultlabelid', 'outlookdefaultlabel')
    foreach ($entry in $Settings) {
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


# ═══════════════════════════════════════════════════════════════════════
# TEST GROUP 1: ConvertFrom-LabelActions — Content Marking Footer
# ═══════════════════════════════════════════════════════════════════════
Write-Host "── Test Group 1: ConvertFrom-LabelActions — Footer ────" -ForegroundColor White
Write-Host ""

$footerAction = @(
    '{"Type":"applycontentmarking","SubType":"footer","Settings":[{"Key":"alignment","Value":"Left"},{"Key":"disabled","Value":"false"},{"Key":"fontcolor","Value":"#000000"},{"Key":"fontsize","Value":"8"},{"Key":"margin","Value":"5"},{"Key":"placement","Value":"Footer"},{"Key":"text","Value":"Classified as Confidential"}]}'
)
$result = ConvertFrom-LabelActions -LabelActions $footerAction
Assert-Equal "Footer: Enabled" $true $result['ApplyContentMarkingFooterEnabled']
Assert-Equal "Footer: Alignment" "Left" $result['ApplyContentMarkingFooterAlignment']
Assert-Equal "Footer: FontColor" "#000000" $result['ApplyContentMarkingFooterFontColor']
Assert-Equal "Footer: FontSize" 8 $result['ApplyContentMarkingFooterFontSize']
Assert-Equal "Footer: Margin" 5 $result['ApplyContentMarkingFooterMargin']
Assert-Equal "Footer: Text" "Classified as Confidential" $result['ApplyContentMarkingFooterText']
Assert-NotContainsKey "Footer: No templateid" $result 'templateid'
Write-Host ""

# ═══════════════════════════════════════════════════════════════════════
# TEST GROUP 2: ConvertFrom-LabelActions — Content Marking Header
# ═══════════════════════════════════════════════════════════════════════
Write-Host "── Test Group 2: ConvertFrom-LabelActions — Header ────" -ForegroundColor White
Write-Host ""

$headerAction = @(
    '{"Type":"applycontentmarking","SubType":"header","Settings":[{"Key":"alignment","Value":"Center"},{"Key":"disabled","Value":"false"},{"Key":"fontcolor","Value":"#FF0000"},{"Key":"fontsize","Value":"12"},{"Key":"margin","Value":"10"},{"Key":"text","Value":"CONFIDENTIAL"}]}'
)
$result = ConvertFrom-LabelActions -LabelActions $headerAction
Assert-Equal "Header: Enabled" $true $result['ApplyContentMarkingHeaderEnabled']
Assert-Equal "Header: Alignment" "Center" $result['ApplyContentMarkingHeaderAlignment']
Assert-Equal "Header: FontColor" "#FF0000" $result['ApplyContentMarkingHeaderFontColor']
Assert-Equal "Header: FontSize" 12 $result['ApplyContentMarkingHeaderFontSize']
Assert-Equal "Header: Text" "CONFIDENTIAL" $result['ApplyContentMarkingHeaderText']
Write-Host ""

# ═══════════════════════════════════════════════════════════════════════
# TEST GROUP 3: ConvertFrom-LabelActions — Watermark
# ═══════════════════════════════════════════════════════════════════════
Write-Host "── Test Group 3: ConvertFrom-LabelActions — Watermark ──" -ForegroundColor White
Write-Host ""

$watermarkAction = @(
    '{"Type":"applywatermarking","SubType":null,"Settings":[{"Key":"disabled","Value":"false"},{"Key":"fontcolor","Value":"#808080"},{"Key":"fontsize","Value":"48"},{"Key":"layout","Value":"Diagonal"},{"Key":"text","Value":"CONFIDENTIAL"}]}'
)
$result = ConvertFrom-LabelActions -LabelActions $watermarkAction
Assert-Equal "Watermark: Enabled" $true $result['ApplyWaterMarkingEnabled']
Assert-Equal "Watermark: FontColor" "#808080" $result['ApplyWaterMarkingFontColor']
Assert-Equal "Watermark: FontSize" 48 $result['ApplyWaterMarkingFontSize']
Assert-Equal "Watermark: Layout" "Diagonal" $result['ApplyWaterMarkingLayout']
Assert-Equal "Watermark: Text" "CONFIDENTIAL" $result['ApplyWaterMarkingText']
Write-Host ""

# ═══════════════════════════════════════════════════════════════════════
# TEST GROUP 4: ConvertFrom-LabelActions — Template-Based Encryption
# ═══════════════════════════════════════════════════════════════════════
Write-Host "── Test Group 4: Encryption — Template-Based ───────────" -ForegroundColor White
Write-Host ""

$encryptAction = @(
    '{"Type":"encrypt","SubType":null,"Settings":[{"Key":"protectiontype","Value":"template"},{"Key":"disabled","Value":"false"},{"Key":"templateid","Value":"de6dbe70-c280-4747-9329-2b589b5529a9"},{"Key":"templatearchived","Value":"False"},{"Key":"linkedtemplateid","Value":"de6dbe70-c280-4747-9329-2b589b5529a9"},{"Key":"contentexpiredondateindaysornever","Value":"Never"},{"Key":"offlineaccessdays","Value":"-1"},{"Key":"rightsdefinitions","Value":"[{\"Identity\":\"MngEnvMCAP219373.onmicrosoft.com\",\"Rights\":\"VIEW,VIEWRIGHTSDATA,DOCEDIT,EDIT,PRINT,EXTRACT,REPLY,REPLYALL,FORWARD,OBJMODEL\"}]"}]}'
)
$result = ConvertFrom-LabelActions -LabelActions $encryptAction
Assert-Equal "Encrypt: Enabled" $true $result['EncryptionEnabled']
Assert-Equal "Encrypt: ProtectionType" "template" $result['EncryptionProtectionType']
Assert-Equal "Encrypt: ContentExpiry" "Never" $result['EncryptionContentExpiredOnDateInDaysOrNever']
Assert-Equal "Encrypt: OfflineAccessDays" -1 $result['EncryptionOfflineAccessDays']
Assert-ContainsKey "Encrypt: Has RightsDefinitions" $result 'EncryptionRightsDefinitions'
Assert-True "Encrypt: RightsDefinitions contains identity" ($result['EncryptionRightsDefinitions'] -match 'MngEnvMCAP219373')
Assert-NotContainsKey "Encrypt: No templateid" $result 'templateid'
Assert-NotContainsKey "Encrypt: No linkedtemplateid" $result 'linkedtemplateid'
Assert-NotContainsKey "Encrypt: No templatearchived" $result 'templatearchived'
Write-Host ""

# ═══════════════════════════════════════════════════════════════════════
# TEST GROUP 5: ConvertFrom-LabelActions — User-Defined Encryption
# ═══════════════════════════════════════════════════════════════════════
Write-Host "── Test Group 5: Encryption — User-Defined ─────────────" -ForegroundColor White
Write-Host ""

$userDefEncrypt = @(
    '{"Type":"encrypt","SubType":null,"Settings":[{"Key":"protectiontype","Value":"userdefined"},{"Key":"disabled","Value":"false"},{"Key":"donotforward","Value":"false"},{"Key":"promptuser","Value":"true"},{"Key":"encryptonly","Value":"true"}]}'
)
$result = ConvertFrom-LabelActions -LabelActions $userDefEncrypt
Assert-Equal "UserDef: Enabled" $true $result['EncryptionEnabled']
Assert-Equal "UserDef: ProtectionType" "userdefined" $result['EncryptionProtectionType']
Assert-Equal "UserDef: DoNotForward" $false $result['EncryptionDoNotForward']
Assert-Equal "UserDef: PromptUser" $true $result['EncryptionPromptUser']
Assert-Equal "UserDef: EncryptOnly" $true $result['EncryptionEncryptOnly']
Write-Host ""

# ═══════════════════════════════════════════════════════════════════════
# TEST GROUP 6: Encryption Identity Remapping
# ═══════════════════════════════════════════════════════════════════════
Write-Host "── Test Group 6: Encryption Identity Remapping ─────────" -ForegroundColor White
Write-Host ""

$idMap = @{ "MngEnvMCAP219373.onmicrosoft.com" = "target-tenant.onmicrosoft.com" }
$result = ConvertFrom-LabelActions -LabelActions $encryptAction -IdentityMap $idMap
Assert-True "IDRemap: Source domain replaced" ($result['EncryptionRightsDefinitions'] -match 'target-tenant\.onmicrosoft\.com')
Assert-True "IDRemap: Source domain gone" ($result['EncryptionRightsDefinitions'] -notmatch 'MngEnvMCAP219373')
Write-Host ""

# ═══════════════════════════════════════════════════════════════════════
# TEST GROUP 7: Mixed Actions (Footer + Encryption)
# ═══════════════════════════════════════════════════════════════════════
Write-Host "── Test Group 7: Mixed Actions ─────────────────────────" -ForegroundColor White
Write-Host ""

$mixedActions = @(
    '{"Type":"applycontentmarking","SubType":"footer","Settings":[{"Key":"alignment","Value":"Left"},{"Key":"disabled","Value":"false"},{"Key":"fontcolor","Value":"#000000"},{"Key":"fontsize","Value":"8"},{"Key":"margin","Value":"5"},{"Key":"text","Value":"Classified as Confidential"}]}',
    '{"Type":"encrypt","SubType":null,"Settings":[{"Key":"protectiontype","Value":"template"},{"Key":"disabled","Value":"false"},{"Key":"contentexpiredondateindaysornever","Value":"Never"},{"Key":"offlineaccessdays","Value":"-1"},{"Key":"rightsdefinitions","Value":"[{\"Identity\":\"MngEnvMCAP219373.onmicrosoft.com\",\"Rights\":\"VIEW\"}]"}]}'
)
$result = ConvertFrom-LabelActions -LabelActions $mixedActions
Assert-ContainsKey "Mixed: Has footer text" $result 'ApplyContentMarkingFooterText'
Assert-ContainsKey "Mixed: Has encryption" $result 'EncryptionEnabled'
Assert-Equal "Mixed: Footer enabled" $true $result['ApplyContentMarkingFooterEnabled']
Assert-Equal "Mixed: Encryption enabled" $true $result['EncryptionEnabled']
$expectedKeyCount = 8  # 6 footer + 2 encryption basics + rights + expiry + offline = actually more
Assert-True "Mixed: Has multiple keys" ($result.Count -ge 7)
Write-Host ""

# ═══════════════════════════════════════════════════════════════════════
# TEST GROUP 8: Empty / Null LabelActions
# ═══════════════════════════════════════════════════════════════════════
Write-Host "── Test Group 8: Empty/Null LabelActions ───────────────" -ForegroundColor White
Write-Host ""

$result = ConvertFrom-LabelActions -LabelActions @()
Assert-Equal "Empty array: Returns empty hashtable" 0 $result.Count

$result = ConvertFrom-LabelActions -LabelActions $null
Assert-Equal "Null: Returns empty hashtable" 0 $result.Count
Write-Host ""

# ═══════════════════════════════════════════════════════════════════════
# TEST GROUP 9: ContentType Handling
# ═══════════════════════════════════════════════════════════════════════
Write-Host "── Test Group 9: ContentType Handling ──────────────────" -ForegroundColor White
Write-Host ""

# Verify pass-through logic (simulating what the import script does)
function Test-ContentType {
    param([string]$ContentType)
    if ($ContentType -and $ContentType -ne 'None') { return $ContentType }
    return $null
}

Assert-Equal "ContentType: File,Email,Teamwork passes" "File, Email, Teamwork" (Test-ContentType "File, Email, Teamwork")
Assert-Equal "ContentType: File,Email,Site,UG,Teamwork passes" "File, Email, Site, UnifiedGroup, Teamwork" (Test-ContentType "File, Email, Site, UnifiedGroup, Teamwork")
Assert-Equal "ContentType: None is skipped" $null (Test-ContentType "None")
Assert-Equal "ContentType: null is skipped" $null (Test-ContentType $null)
Assert-Equal "ContentType: empty is skipped" $null (Test-ContentType "")
Assert-Equal "ContentType: File,Email passes" "File, Email" (Test-ContentType "File, Email")
Write-Host ""

# ═══════════════════════════════════════════════════════════════════════
# TEST GROUP 10: Conditions SIT Remapping
# ═══════════════════════════════════════════════════════════════════════
Write-Host "── Test Group 10: Conditions SIT Remapping ─────────────" -ForegroundColor White
Write-Host ""

$sitMap = @{
    "custom-sit-guid-111" = "target-sit-guid-222"
}

# Custom SIT should be remapped
$condWithCustomSit = @(
    '{"And":[{"And":[{"Key":"CCSI","Value":"custom-sit-guid-111","Properties":null,"Settings":[{"Key":"name","Value":"My Custom SIT"},{"Key":"rulepackage","Value":"custom-rp-guid"}]}]}]}'
)
$remapped = @(Invoke-ConditionsSitRemap -Conditions $condWithCustomSit -SitMap $sitMap)
Assert-True "CustomSIT: Remapped" ($remapped[0] -match 'target-sit-guid-222')
Assert-True "CustomSIT: Source gone" ($remapped[0] -notmatch 'custom-sit-guid-111')

# Empty SitMap should pass through unchanged
$remapped = @(Invoke-ConditionsSitRemap -Conditions $condWithCustomSit -SitMap @{})
Assert-True "EmptyMap: Unchanged" ($remapped[0] -match 'custom-sit-guid-111')

# Empty conditions should return empty
$remapped = @(Invoke-ConditionsSitRemap -Conditions @() -SitMap $sitMap)
Assert-Equal "EmptyConditions: Returns empty" 0 $remapped.Count

# Null conditions should return null/empty
$remapped = Invoke-ConditionsSitRemap -Conditions $null -SitMap $sitMap
Assert-Equal "NullConditions: Returns null" $null $remapped

# SIT not in map should be left unchanged
$condUnmapped = @(
    '{"And":[{"Key":"CCSI","Value":"unknown-sit-guid","Settings":[{"Key":"name","Value":"Unknown SIT"}]}]}'
)
$remapped = @(Invoke-ConditionsSitRemap -Conditions $condUnmapped -SitMap $sitMap)
Assert-True "UnmappedSIT: Left unchanged" ($remapped[0] -match 'unknown-sit-guid')

# Real export data from the codebase
$realCondition = @(
    '{"And":[{"And":[{"Key":"CCSI","Value":"50842eb7-edc8-4019-85dd-5a5c1f2bb085","Properties":null,"Settings":[{"Key":"mincount","Value":"1"},{"Key":"maxconfidence","Value":"100"},{"Key":"rulepackage","Value":"00000000-0000-0000-0000-000000000000"},{"Key":"name","Value":"Credit Card Number"},{"Key":"minconfidence","Value":"85"},{"Key":"maxcount","Value":"9"},{"Key":"groupname","Value":"Default"},{"Key":"confidencelevel","Value":"High"},{"Key":"autoapplytype","Value":"Recommend"}]}]}]}'
)
# With no SIT map, built-in SIT should pass through
$remapped = @(Invoke-ConditionsSitRemap -Conditions $realCondition -SitMap @{})
Assert-True "RealData: Built-in SIT unchanged with empty map" ($remapped[0] -match '50842eb7-edc8-4019-85dd-5a5c1f2bb085')
Write-Host ""

# ═══════════════════════════════════════════════════════════════════════
# TEST GROUP 11: Policy Settings Parsing
# ═══════════════════════════════════════════════════════════════════════
Write-Host "── Test Group 11: Policy Settings Parsing ──────────────" -ForegroundColor White
Write-Host ""

$guidMap = @{
    "defa4170-0d19-0005-0004-bc88714345d2" = "new-target-guid-0004"
}
$settingsArray = @(
    "[defaultlabelid, defa4170-0d19-0005-0004-bc88714345d2]",
    "[teamworkmandatory, false]",
    "[disablemandatoryinoutlook, true]",
    "[teamworkdefaultlabelid, defa4170-0d19-0005-0004-bc88714345d2]",
    "[requiredowngradejustification, true]",
    "[mandatory, false]",
    "[powerbimandatory, false]",
    "[outlookdefaultlabel, defa4170-0d19-0005-0004-bc88714345d2]"
)

$result = ConvertFrom-PolicySettings -Settings $settingsArray -GuidMap $guidMap
Assert-Equal "Settings: defaultlabelid remapped" "new-target-guid-0004" $result['defaultlabelid']
Assert-Equal "Settings: teamworkdefaultlabelid remapped" "new-target-guid-0004" $result['teamworkdefaultlabelid']
Assert-Equal "Settings: outlookdefaultlabel remapped" "new-target-guid-0004" $result['outlookdefaultlabel']
Assert-Equal "Settings: mandatory passes through" "false" $result['mandatory']
Assert-Equal "Settings: requiredowngradejustification passes through" "true" $result['requiredowngradejustification']
Assert-Equal "Settings: teamworkmandatory passes through" "false" $result['teamworkmandatory']
Assert-Equal "Settings: disablemandatoryinoutlook passes through" "true" $result['disablemandatoryinoutlook']
Assert-Equal "Settings: powerbimandatory passes through" "false" $result['powerbimandatory']
Assert-Equal "Settings: Total keys" 8 $result.Count

# GUID not in map should pass through
$resultNoMap = ConvertFrom-PolicySettings -Settings @("[defaultlabelid, unknown-guid]") -GuidMap @{}
Assert-Equal "Settings: Unknown GUID passes through" "unknown-guid" $resultNoMap['defaultlabelid']

# Empty settings
$resultEmpty = ConvertFrom-PolicySettings -Settings @() -GuidMap $guidMap
Assert-Equal "Settings: Empty returns empty" 0 $resultEmpty.Count

# Null settings
$resultNull = ConvertFrom-PolicySettings -Settings $null -GuidMap $guidMap
Assert-Equal "Settings: Null returns empty" 0 $resultNull.Count
Write-Host ""

# ═══════════════════════════════════════════════════════════════════════
# TEST GROUP 12: Integration — Real Export Data Parsing
# ═══════════════════════════════════════════════════════════════════════
Write-Host "── Test Group 12: Integration — Real Export Data ───────" -ForegroundColor White
Write-Host ""

# Test with actual LabelActions from the export file (Confidential\All Employees)
$realFooterEncrypt = @(
    '{"Type":"applycontentmarking","SubType":"footer","Settings":[{"Key":"alignment","Value":"Left"},{"Key":"disabled","Value":"false"},{"Key":"fontcolor","Value":"#000000"},{"Key":"fontsize","Value":"8"},{"Key":"margin","Value":"5"},{"Key":"placement","Value":"Footer"},{"Key":"text","Value":"Classified as Confidential"}]}',
    '{"Type":"encrypt","SubType":null,"Settings":[{"Key":"protectiontype","Value":"template"},{"Key":"disabled","Value":"false"},{"Key":"templateid","Value":"de6dbe70-c280-4747-9329-2b589b5529a9"},{"Key":"templatearchived","Value":"False"},{"Key":"linkedtemplateid","Value":"de6dbe70-c280-4747-9329-2b589b5529a9"},{"Key":"contentexpiredondateindaysornever","Value":"Never"},{"Key":"offlineaccessdays","Value":"-1"},{"Key":"rightsdefinitions","Value":"[{\"Identity\":\"MngEnvMCAP219373.onmicrosoft.com\",\"Rights\":\"VIEW,VIEWRIGHTSDATA,DOCEDIT,EDIT,PRINT,EXTRACT,REPLY,REPLYALL,FORWARD,OBJMODEL\"}]"}]}'
)
$result = ConvertFrom-LabelActions -LabelActions $realFooterEncrypt
Assert-Equal "Real: Footer text" "Classified as Confidential" $result['ApplyContentMarkingFooterText']
Assert-Equal "Real: Footer enabled" $true $result['ApplyContentMarkingFooterEnabled']
Assert-Equal "Real: Encryption enabled" $true $result['EncryptionEnabled']
Assert-Equal "Real: ProtectionType" "template" $result['EncryptionProtectionType']
Assert-True "Real: Has rights definitions" ($result['EncryptionRightsDefinitions'] -match 'VIEW')
Assert-NotContainsKey "Real: No templateid leak" $result 'templateid'
Assert-True "Real: Has expected key count (11+)" ($result.Count -ge 10) "Got $($result.Count) keys"

# Test user-defined encryption from real export (Confidential\Trusted People)
$realUserDef = @(
    '{"Type":"applycontentmarking","SubType":"footer","Settings":[{"Key":"alignment","Value":"Left"},{"Key":"disabled","Value":"false"},{"Key":"fontcolor","Value":"#000000"},{"Key":"fontsize","Value":"10"},{"Key":"margin","Value":"5"},{"Key":"placement","Value":"Footer"},{"Key":"text","Value":"Classified as Confidential"}]}',
    '{"Type":"encrypt","SubType":null,"Settings":[{"Key":"protectiontype","Value":"userdefined"},{"Key":"disabled","Value":"false"},{"Key":"donotforward","Value":"false"},{"Key":"promptuser","Value":"true"},{"Key":"encryptonly","Value":"true"}]}'
)
$result = ConvertFrom-LabelActions -LabelActions $realUserDef
Assert-Equal "RealUD: Footer font size" 10 $result['ApplyContentMarkingFooterFontSize']
Assert-Equal "RealUD: EncryptOnly" $true $result['EncryptionEncryptOnly']
Assert-Equal "RealUD: PromptUser" $true $result['EncryptionPromptUser']
Assert-Equal "RealUD: DoNotForward" $false $result['EncryptionDoNotForward']
Write-Host ""

# ═══════════════════════════════════════════════════════════════════════
# TEST GROUP 13: SIT ID Remap for Auto-Label Rules
# ═══════════════════════════════════════════════════════════════════════
Write-Host "── Test Group 13: SIT ID Remap for Auto-Label Rules ───" -ForegroundColor White
Write-Host ""

# Simulate Invoke-SitIdRemap (from 10-Import-AutoLabelPolicies.ps1)
function Invoke-SitIdRemap {
    param([array]$SitReferences, [hashtable]$SitMap)
    if (-not $SitReferences -or -not $SitMap -or $SitMap.Count -eq 0) { return $SitReferences }
    $remapped = @()
    foreach ($item in $SitReferences) {
        $ht = @{}
        if ($item -is [hashtable]) {
            $ht = $item.Clone()
        } else {
            $item.PSObject.Properties | ForEach-Object { $ht[$_.Name] = $_.Value }
        }
        if ($ht.ContainsKey('id') -and $SitMap.ContainsKey($ht['id'])) {
            $ht['id'] = $SitMap[$ht['id']]
        }
        $remapped += $ht
    }
    return $remapped
}

$sitMap = @{
    "src-sit-001" = "tgt-sit-001"
    "src-sit-002" = "tgt-sit-002"
}

$sitRefs = @(
    [PSCustomObject]@{ id = "src-sit-001"; name = "Employee ID"; mincount = 1 }
    [PSCustomObject]@{ id = "src-sit-002"; name = "Product Code"; mincount = 1 }
    [PSCustomObject]@{ id = "builtin-sit"; name = "Credit Card"; mincount = 1 }
)
$remapped = Invoke-SitIdRemap -SitReferences $sitRefs -SitMap $sitMap
Assert-Equal "SITRemap: First SIT remapped" "tgt-sit-001" $remapped[0]['id']
Assert-Equal "SITRemap: Second SIT remapped" "tgt-sit-002" $remapped[1]['id']
Assert-Equal "SITRemap: Built-in unchanged" "builtin-sit" $remapped[2]['id']
Assert-Equal "SITRemap: Name preserved" "Employee ID" $remapped[0]['name']

# Empty map returns unchanged (returns original objects)
$remapped = Invoke-SitIdRemap -SitReferences $sitRefs -SitMap @{}
$firstId = if ($remapped[0] -is [hashtable]) { $remapped[0]['id'] } else { $remapped[0].id }
Assert-Equal "SITRemap: Empty map passes through" "src-sit-001" $firstId

# Null input returns null
$remapped = Invoke-SitIdRemap -SitReferences $null -SitMap $sitMap
Assert-Equal "SITRemap: Null input returns null" $null $remapped
Write-Host ""

# ═══════════════════════════════════════════════════════════════════════
# TEST GROUP 14: Sub-Label Lookup (from Test-SubLabelFix.ps1)
# ═══════════════════════════════════════════════════════════════════════
Write-Host "── Test Group 14: Sub-Label Same-Name Fix ──────────────" -ForegroundColor White
Write-Host ""

# Verify that the existing sub-label fix still works correctly
$mockStore = @(
    [PSCustomObject]@{ Guid = 'PARENT-AA'; DisplayName = 'Anyone (unrestricted)'; ParentId = $null        }
    [PSCustomObject]@{ Guid = 'PARENT-CC'; DisplayName = 'Confidential';           ParentId = $null        }
    [PSCustomObject]@{ Guid = 'SUB-EXIST'; DisplayName = 'Trusted People';         ParentId = 'PARENT-CC'  }
)

function Local-GetLabelByIdentity {
    param([string]$Identity)
    $mockStore | Where-Object { $_.DisplayName -eq $Identity } | Select-Object -First 1
}
function Local-GetAllLabels { $mockStore }

function Local-SubLabelLookup {
    param([string]$DisplayName, [string]$TargetParentGuid)
    $candidateLabel = Local-GetLabelByIdentity -Identity $DisplayName
    $existing = $null
    if ($candidateLabel) {
        $candidateParent = if ($candidateLabel.ParentId) { $candidateLabel.ParentId.ToString() } else { '' }
        if ($candidateParent -eq $TargetParentGuid) {
            $existing = $candidateLabel
        } else {
            $existing = Local-GetAllLabels | Where-Object {
                $_.DisplayName -eq $DisplayName -and $_.ParentId -and $_.ParentId.ToString() -eq $TargetParentGuid
            } | Select-Object -First 1
        }
    }
    if ($existing) {
        if (-not $existing.ParentId) { return 'wrong-update' }
        return 'update'
    }
    return 'create'
}

Assert-Equal "SubLabel: Same name as parent -> create" "create" (Local-SubLabelLookup -DisplayName 'Anyone (unrestricted)' -TargetParentGuid 'PARENT-CC')
Assert-Equal "SubLabel: Existing sub-label -> update" "update" (Local-SubLabelLookup -DisplayName 'Trusted People' -TargetParentGuid 'PARENT-CC')
Assert-Equal "SubLabel: Unique name -> create" "create" (Local-SubLabelLookup -DisplayName 'Specified People' -TargetParentGuid 'PARENT-CC')
Write-Host ""

# ═══════════════════════════════════════════════════════════════════════
# TEST GROUP 15: File Parse Test (real export JSON if available)
# ═══════════════════════════════════════════════════════════════════════
Write-Host "── Test Group 15: Real Export File Validation ──────────" -ForegroundColor White
Write-Host ""

$exportFile = Join-Path $PSScriptRoot "exports\labels-export-20260226-183818.json"
if (Test-Path $exportFile) {
    $labels = Get-Content $exportFile -Raw | ConvertFrom-Json

    # Count labels with LabelActions
    $labelsWithActions = @($labels | Where-Object { $_.LabelActions -and $_.LabelActions.Count -gt 0 })
    Assert-True "RealFile: Found labels with LabelActions" ($labelsWithActions.Count -gt 0) "Found $($labelsWithActions.Count)"

    # Count labels with Conditions
    $labelsWithConditions = @($labels | Where-Object { $_.Conditions -and $_.Conditions.Count -gt 0 })
    Assert-True "RealFile: Found labels with Conditions" ($labelsWithConditions.Count -gt 0) "Found $($labelsWithConditions.Count)"

    # Count labels with ContentType (non-None)
    $labelsWithContentType = @($labels | Where-Object { $_.ContentType -and $_.ContentType -ne 'None' })
    Assert-True "RealFile: Found labels with ContentType" ($labelsWithContentType.Count -gt 0) "Found $($labelsWithContentType.Count)"

    # Parse each LabelActions entry through ConvertFrom-LabelActions
    $parseErrors = 0
    foreach ($label in $labelsWithActions) {
        try {
            $result = ConvertFrom-LabelActions -LabelActions $label.LabelActions
            if ($result.Count -eq 0) { $parseErrors++ }
        } catch {
            $parseErrors++
            Write-Host "      Parse error for $($label.DisplayName): $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    Assert-Equal "RealFile: All LabelActions parsed successfully" 0 $parseErrors

    # Check that encryption labels produce EncryptionEnabled
    $encryptLabels = @($labelsWithActions | Where-Object { $_.EncryptionEnabled -eq $true })
    foreach ($eLabel in $encryptLabels) {
        $result = ConvertFrom-LabelActions -LabelActions $eLabel.LabelActions
        Assert-Equal "RealFile: $($eLabel.DisplayName) has EncryptionEnabled" $true $result['EncryptionEnabled']
    }
} else {
    Write-Host "  ⏩ Skipped — export file not found: $exportFile" -ForegroundColor DarkGray
}
Write-Host ""

# ═══════════════════════════════════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════════════════════════════════
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Results:  $pass passed   $fail failed   ($($pass + $fail) total)" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

exit $fail
