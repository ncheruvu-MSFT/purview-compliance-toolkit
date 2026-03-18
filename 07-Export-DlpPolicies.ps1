<#
.SYNOPSIS
    Export DLP compliance policies and rules to JSON files

.DESCRIPTION
    Exports all DLP compliance policies and their associated rules from the
    connected tenant to JSON files for backup, disaster recovery, or
    environment replication.

    Exported artefacts:
    • DLP policies  → dlp-policies-export-<timestamp>.json
    • DLP rules     → dlp-rules-export-<timestamp>.json

.PARAMETER OutputPath
    Optional custom output directory. Defaults to ./exports/

.PARAMETER IncludeExtendedProperties
    Include extended properties in the export (may increase export time)

.EXAMPLE
    .\07-Export-DlpPolicies.ps1

.EXAMPLE
    .\07-Export-DlpPolicies.ps1 -OutputPath "C:\Backup\Purview" -IncludeExtendedProperties

.NOTES
    Must be connected to Security & Compliance PowerShell first.
    Run: .\01-Connect-Tenant.ps1
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath,

    [switch]$IncludeExtendedProperties
)

# ── Connection check ──────────────────────────────────────────────────
try {
    $null = Get-DlpSensitiveInformationType -Identity "Credit Card Number" -ErrorAction Stop
} catch {
    Write-Host "❌ Not connected to Security & Compliance PowerShell" -ForegroundColor Red
    Write-Host "   Run: .\01-Connect-Tenant.ps1 -TenantType Source" -ForegroundColor Yellow
    exit 1
}

# ── Target-tenant safety warning ──────────────────────────────────────────────
if ($env:PURVIEW_TENANT_TYPE -eq 'Target') {
    Write-Host "⚠️  WARNING: Session is marked as TARGET tenant ($env:PURVIEW_CONNECTED_ORG)." -ForegroundColor Yellow
    Write-Host "   Export scripts should run against the SOURCE tenant. Continue only if intentional." -ForegroundColor Yellow
}

# ── Helper: flatten location objects to simple name strings ────────────
function Get-LocationNames {
    param([array]$Locations)
    if (-not $Locations) { return @() }
    @($Locations | Where-Object { $_ -ne $null } | ForEach-Object {
        if ($_ -is [string]) { $_ } else { $_.Name }
    } | Where-Object { $_ -ne $null })
}

Write-Host "🛡️  Exporting DLP compliance policies and rules..." -ForegroundColor Cyan
Write-Host ""

# ── Resolve output directory ─────────────────────────────────────────
if (-not $OutputPath) {
    $OutputPath = Join-Path $PSScriptRoot "exports"
}
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'

# ─────────────────────────────────────────────────────────────────────
# STEP 1: Export DLP compliance policies
# ─────────────────────────────────────────────────────────────────────
Write-Host "⏳ Step 1: Exporting DLP compliance policies..." -ForegroundColor Yellow

$getParams = @{ ErrorAction = 'Stop' }
if ($IncludeExtendedProperties) {
    $getParams['IncludeExtendedProperties'] = $true
}
$policies = @(Get-DlpCompliancePolicy @getParams)

if ($policies.Count -eq 0) {
    Write-Host "   ℹ️  No DLP policies found in this tenant" -ForegroundColor DarkGray
} else {
    Write-Host "   📋 Found $($policies.Count) DLP policy(ies):" -ForegroundColor Gray

    $policyExport = @()
    foreach ($policy in $policies) {
        $mode = $policy.Mode
        Write-Host "      • $($policy.Name) (Mode: $mode, Enabled: $($policy.Enabled))" -ForegroundColor Gray

        $policyExport += @{
            Identity                       = $policy.Identity
            Name                           = $policy.Name
            Guid                           = $policy.Guid.ToString()
            Comment                        = $policy.Comment
            Enabled                        = $policy.Enabled
            Mode                           = $policy.Mode
            Type                           = $policy.Type
            Workload                       = $policy.Workload
            Priority                       = $policy.Priority
            ExchangeLocation               = @(Get-LocationNames $policy.ExchangeLocation)
            ExchangeLocationException      = @(Get-LocationNames $policy.ExchangeLocationException)
            SharePointLocation             = @(Get-LocationNames $policy.SharePointLocation)
            SharePointLocationException    = @(Get-LocationNames $policy.SharePointLocationException)
            OneDriveLocation               = @(Get-LocationNames $policy.OneDriveLocation)
            OneDriveLocationException      = @(Get-LocationNames $policy.OneDriveLocationException)
            TeamsLocation                  = @(Get-LocationNames $policy.TeamsLocation)
            TeamsLocationException         = @(Get-LocationNames $policy.TeamsLocationException)
            EndpointDlpLocation            = @(Get-LocationNames $policy.EndpointDlpLocation)
            EndpointDlpLocationException   = @(Get-LocationNames $policy.EndpointDlpLocationException)
            OnPremisesScannerDlpLocation   = @(Get-LocationNames $policy.OnPremisesScannerDlpLocation)
            OnPremisesScannerDlpLocationException = @(Get-LocationNames $policy.OnPremisesScannerDlpLocationException)
            ThirdPartyAppDlpLocation       = @(Get-LocationNames $policy.ThirdPartyAppDlpLocation)
            ThirdPartyAppDlpLocationException = @(Get-LocationNames $policy.ThirdPartyAppDlpLocationException)
            ExchangeOnlineWorkload         = $policy.ExchangeOnlineWorkload
            SharePointOnlineWorkload       = $policy.SharePointOnlineWorkload
            OneDriveForBusinessWorkload    = $policy.OneDriveForBusinessWorkload
            TeamsWorkload                  = $policy.TeamsWorkload
            EndpointDlpWorkload            = $policy.EndpointDlpWorkload
            CreatedBy                      = $policy.CreatedBy
            LastModifiedBy                 = $policy.LastModifiedBy
            WhenCreated                    = $policy.WhenCreated
            WhenChanged                    = $policy.WhenChanged
        }
    }

    $policiesFile = Join-Path $OutputPath "dlp-policies-export-$timestamp.json"
    $policyExport | ConvertTo-Json -Depth 10 | Out-File -FilePath $policiesFile -Encoding UTF8 -Force
    Write-Host ""
    Write-Host "   ✅ Exported $($policies.Count) DLP policy(ies) to:" -ForegroundColor Green
    Write-Host "      $policiesFile" -ForegroundColor Gray
}
Write-Host ""

# ─────────────────────────────────────────────────────────────────────
# STEP 2: Export DLP compliance rules
# ─────────────────────────────────────────────────────────────────────
Write-Host "⏳ Step 2: Exporting DLP compliance rules..." -ForegroundColor Yellow

$rules = @(Get-DlpComplianceRule -ErrorAction Stop)

if ($rules.Count -eq 0) {
    Write-Host "   ℹ️  No DLP rules found in this tenant" -ForegroundColor DarkGray
} else {
    Write-Host "   📋 Found $($rules.Count) DLP rule(s):" -ForegroundColor Gray

    $ruleExport = @()
    foreach ($rule in $rules) {
        Write-Host "      • $($rule.Name) (Policy: $($rule.ParentPolicyName), Disabled: $($rule.Disabled))" -ForegroundColor Gray

        $ruleExport += @{
            Identity                      = $rule.Identity
            Name                          = $rule.Name
            Guid                          = $rule.Guid.ToString()
            ParentPolicyName              = $rule.ParentPolicyName
            Priority                      = $rule.Priority
            Disabled                      = $rule.Disabled
            Comment                       = $rule.Comment
            # ── Mandatory predicate conditions (at least one required) ────
            ContentContainsSensitiveInformation  = $rule.ContentContainsSensitiveInformation
            ExceptIfContentContainsSensitiveInformation = $rule.ExceptIfContentContainsSensitiveInformation
            ContentPropertyContainsWords  = $rule.ContentPropertyContainsWords
            ExceptIfContentPropertyContainsWords = $rule.ExceptIfContentPropertyContainsWords
            ContentIsNotLabeled           = $rule.ContentIsNotLabeled
            AttachmentIsNotLabeled        = $rule.AttachmentIsNotLabeled
            MessageIsNotLabeled           = $rule.MessageIsNotLabeled
            ContentMissingSensitivityLabel = $rule.ContentMissingSensitivityLabel
            ContentIsShared               = $rule.ContentIsShared
            ExceptIfContentIsShared       = $rule.ExceptIfContentIsShared
            AccessScope                   = $rule.AccessScope
            ExceptIfAccessScope           = $rule.ExceptIfAccessScope
            NonBifurcatingAccessScope     = $rule.NonBifurcatingAccessScope
            FromScope                     = $rule.FromScope
            ExceptIfFromScope             = $rule.ExceptIfFromScope
            HasSenderOverride             = $rule.HasSenderOverride
            ExceptIfHasSenderOverride     = $rule.ExceptIfHasSenderOverride
            ProcessingLimitExceeded       = $rule.ProcessingLimitExceeded
            ExceptIfProcessingLimitExceeded = $rule.ExceptIfProcessingLimitExceeded
            DocumentIsUnsupported         = $rule.DocumentIsUnsupported
            ExceptIfDocumentIsUnsupported  = $rule.ExceptIfDocumentIsUnsupported
            DocumentIsPasswordProtected   = $rule.DocumentIsPasswordProtected
            ExceptIfDocumentIsPasswordProtected = $rule.ExceptIfDocumentIsPasswordProtected
            RestrictBrowserAccess         = $rule.RestrictBrowserAccess
            # ── Sender/Recipient conditions ────────────────────────────────
            SenderIPRanges                = $rule.SenderIPRanges
            ExceptIfSenderIPRanges        = $rule.ExceptIfSenderIPRanges
            SenderDomainIs                = $rule.SenderDomainIs
            ExceptIfSenderDomainIs        = $rule.ExceptIfSenderDomainIs
            SentTo                        = $rule.SentTo
            ExceptIfSentTo                = $rule.ExceptIfSentTo
            SentToMemberOf                = $rule.SentToMemberOf
            ExceptIfSentToMemberOf        = $rule.ExceptIfSentToMemberOf
            RecipientDomainIs             = $rule.RecipientDomainIs
            ExceptIfRecipientDomainIs     = $rule.ExceptIfRecipientDomainIs
            From                          = $rule.From
            ExceptIfFrom                  = $rule.ExceptIfFrom
            FromMemberOf                  = $rule.FromMemberOf
            ExceptIfFromMemberOf          = $rule.ExceptIfFromMemberOf
            FromAddressContainsWords      = $rule.FromAddressContainsWords
            ExceptIfFromAddressContainsWords = $rule.ExceptIfFromAddressContainsWords
            FromAddressMatchesPatterns    = $rule.FromAddressMatchesPatterns
            ExceptIfFromAddressMatchesPatterns = $rule.ExceptIfFromAddressMatchesPatterns
            AnyOfRecipientAddressMatchesPatterns  = $rule.AnyOfRecipientAddressMatchesPatterns
            ExceptIfAnyOfRecipientAddressMatchesPatterns = $rule.ExceptIfAnyOfRecipientAddressMatchesPatterns
            AnyOfRecipientAddressContainsWords   = $rule.AnyOfRecipientAddressContainsWords
            ExceptIfAnyOfRecipientAddressContainsWords = $rule.ExceptIfAnyOfRecipientAddressContainsWords
            SharedWithDomain              = $rule.SharedWithDomain
            ExceptIfSharedWithDomain      = $rule.ExceptIfSharedWithDomain
            # ── Subject/Header/Body conditions ─────────────────────────────
            SubjectContainsWords          = $rule.SubjectContainsWords
            ExceptIfSubjectContainsWords  = $rule.ExceptIfSubjectContainsWords
            SubjectMatchesPatterns        = $rule.SubjectMatchesPatterns
            ExceptIfSubjectMatchesPatterns = $rule.ExceptIfSubjectMatchesPatterns
            SubjectOrBodyMatchesPatterns  = $rule.SubjectOrBodyMatchesPatterns
            ExceptIfSubjectOrBodyMatchesPatterns = $rule.ExceptIfSubjectOrBodyMatchesPatterns
            SubjectOrBodyContainsWords    = $rule.SubjectOrBodyContainsWords
            ExceptIfSubjectOrBodyContainsWords = $rule.ExceptIfSubjectOrBodyContainsWords
            HeaderContainsWords           = $rule.HeaderContainsWords
            ExceptIfHeaderContainsWords   = $rule.ExceptIfHeaderContainsWords
            HeaderMatchesPatterns         = $rule.HeaderMatchesPatterns
            ExceptIfHeaderMatchesPatterns  = $rule.ExceptIfHeaderMatchesPatterns
            # ── Document conditions ────────────────────────────────────────
            DocumentNameMatchesPatterns   = $rule.DocumentNameMatchesPatterns
            ExceptIfDocumentNameMatchesPatterns = $rule.ExceptIfDocumentNameMatchesPatterns
            DocumentNameMatchesWords      = $rule.DocumentNameMatchesWords
            ExceptIfDocumentNameMatchesWords = $rule.ExceptIfDocumentNameMatchesWords
            DocumentContainsWords         = $rule.DocumentContainsWords
            ExceptIfDocumentContainsWords  = $rule.ExceptIfDocumentContainsWords
            DocumentMatchesPatterns       = $rule.DocumentMatchesPatterns
            ExceptIfDocumentMatchesPatterns = $rule.ExceptIfDocumentMatchesPatterns
            DocumentSizeOver              = $rule.DocumentSizeOver
            ExceptIfDocumentSizeOver      = $rule.ExceptIfDocumentSizeOver
            DocumentCreatedBy             = $rule.DocumentCreatedBy
            ExceptIfDocumentCreatedBy     = $rule.ExceptIfDocumentCreatedBy
            DocumentCreatedByMemberOf     = $rule.DocumentCreatedByMemberOf
            ExceptIfDocumentCreatedByMemberOf = $rule.ExceptIfDocumentCreatedByMemberOf
            ContentExtensionMatchesWords  = $rule.ContentExtensionMatchesWords
            ExceptIfContentExtensionMatchesWords = $rule.ExceptIfContentExtensionMatchesWords
            ContentFileTypeMatches        = $rule.ContentFileTypeMatches
            ExceptIfContentFileTypeMatches = $rule.ExceptIfContentFileTypeMatches
            ContentCharacterSetContainsWords = $rule.ContentCharacterSetContainsWords
            UnscannableDocumentExtensionIs = $rule.UnscannableDocumentExtensionIs
            # ── Message conditions ─────────────────────────────────────────
            MessageSizeOver               = $rule.MessageSizeOver
            ExceptIfMessageSizeOver       = $rule.ExceptIfMessageSizeOver
            MessageTypeMatches            = $rule.MessageTypeMatches
            # ── AD attribute conditions ────────────────────────────────────
            SenderADAttributeMatchesPatterns  = $rule.SenderADAttributeMatchesPatterns
            SenderADAttributeContainsWords   = $rule.SenderADAttributeContainsWords
            RecipientADAttributeContainsWords = $rule.RecipientADAttributeContainsWords
            RecipientADAttributeMatchesPatterns = $rule.RecipientADAttributeMatchesPatterns
            # ── Label conditions ────────────────────────────────────────────
            HasLabelDowngradedFrom        = $rule.HasLabelDowngradedFrom
            MessageLabelChangeDetected    = $rule.MessageLabelChangeDetected
            ExceptIfMessageLabelChangeDetected = $rule.ExceptIfMessageLabelChangeDetected
            # ── IRM/Risk conditions ─────────────────────────────────────────
            SharedByIRMUserRisk           = $rule.SharedByIRMUserRisk
            SharedByIRMAgentRisk          = $rule.SharedByIRMAgentRisk
            # ── Actions / Notifications ─────────────────────────────────────
            BlockAccess                   = $rule.BlockAccess
            BlockAccessScope              = $rule.BlockAccessScope
            NotifyUser                    = $rule.NotifyUser
            NotifyUserType                = $rule.NotifyUserType
            NotifyEmailCustomText         = $rule.NotifyEmailCustomText
            NotifyPolicyTipCustomText     = $rule.NotifyPolicyTipCustomText
            NotifyOverride                = $rule.NotifyOverride
            NotifyAllowOverride           = $rule.NotifyAllowOverride
            GenerateAlert                 = $rule.GenerateAlert
            GenerateIncidentReport        = $rule.GenerateIncidentReport
            IncidentReportContent         = $rule.IncidentReportContent
            ReportSeverityLevel           = $rule.ReportSeverityLevel
            RuleErrorAction               = $rule.RuleErrorAction
            AdvancedRule                  = $rule.AdvancedRule
            ConfidenceLevel               = $rule.ConfidenceLevel
            ActionOnError                 = $rule.ActionOnError
            EvidenceStorage               = $rule.EvidenceStorage
            IncidentReportDestination     = $rule.IncidentReportDestination
        }
    }

    $rulesFile = Join-Path $OutputPath "dlp-rules-export-$timestamp.json"
    $ruleExport | ConvertTo-Json -Depth 10 | Out-File -FilePath $rulesFile -Encoding UTF8 -Force
    Write-Host ""
    Write-Host "   ✅ Exported $($rules.Count) DLP rule(s) to:" -ForegroundColor Green
    Write-Host "      $rulesFile" -ForegroundColor Gray
}
Write-Host ""

# ── Summary ───────────────────────────────────────────────────────────
Write-Host "✅ DLP policy export complete!" -ForegroundColor Green
Write-Host ""
Write-Host "   Policies: $($policies.Count)" -ForegroundColor White
Write-Host "   Rules:    $($rules.Count)" -ForegroundColor White
Write-Host ""
Write-Host "💡 Next step: Import with .\08-Import-DlpPolicies.ps1" -ForegroundColor Yellow
