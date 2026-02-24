<#
.SYNOPSIS
    Import custom SITs from XML file to target tenant

.DESCRIPTION
    Imports custom SIT definitions from an XML file exported from source tenant.
    
    Process:
    1. Validate the source XML (structure, text processor references, encoding)
    2. Check for name conflicts with existing SITs in target tenant
    3. Import the rule pack directly using New/Set-DlpSensitiveInformationTypeRulePackage
    4. Verify the import succeeded

.PARAMETER SourceXmlPath
    Path to the XML file exported from source tenant

.PARAMETER Force
    Skip confirmation prompts and overwrite existing rule packs

.PARAMETER SkipValidation
    Skip pre-import XML validation (not recommended)

.EXAMPLE
    .\04-Import-Custom-SITs.ps1 -SourceXmlPath ".\exports\source-export-20260202-120000.xml"
    # Import SITs from specified XML file

.EXAMPLE
    .\04-Import-Custom-SITs.ps1 -SourceXmlPath ".\exports\source-export-20260202-120000.xml" -Force
    # Import without confirmation prompts

.NOTES
    Must be connected to TARGET tenant Security & Compliance PowerShell first.
    Run: .\01-Connect-Tenant.ps1
    
    This script imports the XML rule pack directly — no placeholder creation needed.
    The New-DlpSensitiveInformationType cmdlet is for document-fingerprinting SITs only
    and cannot be used for regex/keyword-based SITs.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path $_ })]
    [string]$SourceXmlPath,

    [Parameter(Mandatory = $false)]
    [switch]$Force,

    [Parameter(Mandatory = $false)]
    [switch]$SkipValidation
)

# Check if connected
try {
    $null = Get-DlpSensitiveInformationType -Identity "Credit Card Number" -ErrorAction Stop
} catch {
    Write-Host "❌ Not connected to Security & Compliance PowerShell" -ForegroundColor Red
    Write-Host "   Run: .\01-Connect-Tenant.ps1 first" -ForegroundColor Yellow
    exit 1
}

Write-Host "📥 Importing custom SITs to TARGET tenant..." -ForegroundColor Cyan
Write-Host ""
Write-Host "Source XML: $SourceXmlPath" -ForegroundColor Gray
Write-Host ""

# ─────────────────────────────────────────────────────────────────────
# STEP 1: Load and validate the source XML
# ─────────────────────────────────────────────────────────────────────
Write-Host "⏳ Step 1: Loading and validating source XML..." -ForegroundColor Yellow
Write-Host ""

try {
    # Use XmlDocument.Load to handle encoding automatically (BOM, declarations, etc.)
    $sourceXml = New-Object System.Xml.XmlDocument
    $sourceXml.Load((Resolve-Path $SourceXmlPath).Path)
    
    # Entities can be directly under Rules or inside Version elements
    $sourceEntities = @()
    if ($sourceXml.RulePackage.Rules.Entity) {
        $sourceEntities += @($sourceXml.RulePackage.Rules.Entity)
    }
    if ($sourceXml.RulePackage.Rules.Version) {
        foreach ($ver in @($sourceXml.RulePackage.Rules.Version)) {
            if ($ver.Entity) {
                $sourceEntities += @($ver.Entity)
            }
        }
    }
    
    if ($sourceEntities.Count -eq 0) {
        Write-Host "❌ No SIT entities found in the XML file." -ForegroundColor Red
        Write-Host "   Verify the export was successful and the file is not empty." -ForegroundColor Yellow
        exit 1
    }
    
    Write-Host "📋 Found $($sourceEntities.Count) SIT(s) in source XML:" -ForegroundColor Green
    
    foreach ($entity in $sourceEntities) {
        $sitId = $entity.id
        # LocalizedStrings can be under Rules or Rules.LocalizedStrings
        $resource = $sourceXml.RulePackage.Rules.LocalizedStrings.Resource | 
            Where-Object { $_.idRef -eq $sitId }
        if (-not $resource) {
            $resource = $sourceXml.RulePackage.LocalizedStrings.Resource |
                Where-Object { $_.idRef -eq $sitId }
        }
        
        if ($resource) {
            Write-Host "   • $($resource.Name.'#text')" -ForegroundColor White
        } else {
            Write-Host "   • (unnamed entity: $sitId)" -ForegroundColor DarkGray
        }
    }
    Write-Host ""
    
} catch {
    Write-Host "❌ Failed to parse source XML: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    Write-Host "💡 Common parse issues:" -ForegroundColor Yellow
    Write-Host "   • File was re-saved with wrong encoding (UTF-16 → UTF-8 corruption)" -ForegroundColor Gray
    Write-Host "   • Use Validate-ExportXml.ps1 to diagnose encoding issues" -ForegroundColor Gray
    Write-Host "   • Re-export using 03-Export-Custom-SITs.ps1 (uses raw byte export)" -ForegroundColor Gray
    exit 1
}

# ─────────────────────────────────────────────────────────────────────
# STEP 2: Validate text processor references (pre-import check)
# ─────────────────────────────────────────────────────────────────────
if (-not $SkipValidation) {
    Write-Host "⏳ Step 2: Validating text processor references..." -ForegroundColor Yellow
    Write-Host ""
    
    $rules = $sourceXml.RulePackage.Rules
    
    # Collect all defined text processors in this rule pack
    $definedProcessors = @{}
    $processorTypes = @('Regex', 'Keyword', 'Function', 'Fingerprint', 'ExtendedKeyword')
    
    foreach ($pType in $processorTypes) {
        $nodes = $rules.SelectNodes("//*[local-name()='$pType']")
        if ($nodes) {
            foreach ($node in $nodes) {
                $procId = $node.GetAttribute('id')
                if ($procId) {
                    $definedProcessors[$procId] = $pType
                }
            }
        }
    }
    
    # Collect all referenced text processors (idRef in IdMatch, Match, Any, etc.)
    $referencedProcessors = @{}
    $refNodes = $rules.SelectNodes("//*[@idRef]")
    if ($refNodes) {
        foreach ($refNode in $refNodes) {
            $localName = $refNode.LocalName
            # Skip LocalizedStrings Resource references (those are entity refs, not text processors)
            if ($localName -eq 'Resource') { continue }
            
            $refId = $refNode.GetAttribute('idRef')
            if ($refId -and -not $referencedProcessors.ContainsKey($refId)) {
                $referencedProcessors[$refId] = $localName
            }
        }
    }
    
    # Find missing references
    $missingRefs = @()
    $externalRefs = @()
    
    foreach ($refId in $referencedProcessors.Keys) {
        if (-not $definedProcessors.ContainsKey($refId)) {
            # Check if it's a well-known built-in reference
            if ($refId -match '^(CEP_|Func_|Keyword_)') {
                $externalRefs += $refId
            } else {
                $missingRefs += $refId
            }
        }
    }
    
    if ($missingRefs.Count -gt 0) {
        Write-Host "❌ VALIDATION FAILED: Missing text processor definitions" -ForegroundColor Red
        Write-Host ""
        Write-Host "   The following text processors are referenced but NOT defined in the XML:" -ForegroundColor Red
        foreach ($ref in $missingRefs) {
            Write-Host "   • $ref (used by: $($referencedProcessors[$ref]))" -ForegroundColor Red
        }
        Write-Host ""
        Write-Host "💡 This means the XML was exported with broken/external references." -ForegroundColor Yellow
        Write-Host "   Common causes:" -ForegroundColor Yellow
        Write-Host "   • SITs were created in the Purview UI and reference built-in text processors" -ForegroundColor Gray
        Write-Host "   • The rule pack was split across multiple packages in the source tenant" -ForegroundColor Gray
        Write-Host "   • The source SITs reference text processors from Microsoft's default rule pack" -ForegroundColor Gray
        Write-Host ""
        Write-Host "   Fix options:" -ForegroundColor Yellow
        Write-Host "   1. Re-export including ALL rule packs (not just custom ones)" -ForegroundColor Gray
        Write-Host "   2. Edit the XML to add missing Regex/Keyword definitions" -ForegroundColor Gray
        Write-Host "   3. Use -SkipValidation to attempt import anyway (may fail)" -ForegroundColor Gray
        
        if (-not $Force) {
            exit 1
        }
        Write-Host ""
        Write-Host "   ⚠️  -Force specified, continuing despite validation errors..." -ForegroundColor Yellow
    }
    
    if ($externalRefs.Count -gt 0) {
        Write-Host "⚠️  External text processor references detected:" -ForegroundColor Yellow
        foreach ($ref in $externalRefs) {
            Write-Host "   • $ref" -ForegroundColor Yellow
        }
        Write-Host ""
        Write-Host "   These reference Microsoft's built-in rule pack (CEP_/Func_/Keyword_ prefixes)." -ForegroundColor Gray
        Write-Host "   They should exist in the target tenant, but import will fail if they don't." -ForegroundColor Gray
        Write-Host ""
    }
    
    if ($missingRefs.Count -eq 0 -and $externalRefs.Count -eq 0) {
        Write-Host "   ✅ All text processor references are self-contained" -ForegroundColor Green
    }
    
    Write-Host "   Defined processors: $($definedProcessors.Count)" -ForegroundColor Gray
    Write-Host "   Referenced processors: $($referencedProcessors.Count)" -ForegroundColor Gray
    Write-Host ""
} else {
    Write-Host "⏩ Step 2: Skipping validation (-SkipValidation specified)" -ForegroundColor DarkGray
    Write-Host ""
}

# ─────────────────────────────────────────────────────────────────────
# STEP 3: Check for conflicts in target tenant
# ─────────────────────────────────────────────────────────────────────
Write-Host "⏳ Step 3: Checking for conflicts in target tenant..." -ForegroundColor Yellow
Write-Host ""

$conflicts = @()
$rulePackId = $sourceXml.RulePackage.RulePack.id

# Check if this rule pack already exists in the target
$existingRulePack = $null
try {
    $existingRulePack = Get-DlpSensitiveInformationTypeRulePackage -Identity $rulePackId -ErrorAction SilentlyContinue
} catch {
    # Not found — that's fine
}

$isUpdate = $false
if ($existingRulePack) {
    Write-Host "   ⚠️  Rule pack '$rulePackId' already exists in target tenant" -ForegroundColor Yellow
    Write-Host "      This will UPDATE the existing rule pack." -ForegroundColor Yellow
    $isUpdate = $true
}

# Check for individual SIT name conflicts
foreach ($entity in $sourceEntities) {
    $sitId = $entity.id
    $resource = $sourceXml.RulePackage.Rules.LocalizedStrings.Resource | 
        Where-Object { $_.idRef -eq $sitId }
    if (-not $resource) {
        $resource = $sourceXml.RulePackage.LocalizedStrings.Resource |
            Where-Object { $_.idRef -eq $sitId }
    }
    
    if ($resource) {
        $sitName = $resource.Name.'#text'
        $existing = Get-DlpSensitiveInformationType -Identity $sitName -ErrorAction SilentlyContinue
        if ($existing) {
            $conflicts += @{
                Name      = $sitName
                SourceId  = $sitId
                TargetId  = if ($existing -is [array]) { $existing[0].Id } else { $existing.Id }
            }
        }
    }
}

if ($conflicts.Count -gt 0) {
    Write-Host "   ⚠️  $($conflicts.Count) SIT(s) already exist in target:" -ForegroundColor Yellow
    foreach ($c in $conflicts) {
        Write-Host "      • $($c.Name) (target ID: $($c.TargetId))" -ForegroundColor Yellow
    }
    Write-Host ""
    
    if (-not $Force -and -not $isUpdate) {
        $confirm = Read-Host "   Proceed with import? This will create a NEW rule pack alongside existing SITs. (Y/N)"
        if ($confirm -ne 'Y' -and $confirm -ne 'y') {
            Write-Host "   ❌ Import cancelled by user." -ForegroundColor Red
            exit 0
        }
    }
} else {
    Write-Host "   ✅ No name conflicts found" -ForegroundColor Green
}
Write-Host ""

# ─────────────────────────────────────────────────────────────────────
# STEP 4: Import the rule pack directly
# ─────────────────────────────────────────────────────────────────────
Write-Host "⏳ Step 4: Importing rule pack..." -ForegroundColor Yellow
Write-Host ""

try {
    $fileBytes = [System.IO.File]::ReadAllBytes((Resolve-Path $SourceXmlPath).Path)
    
    if ($isUpdate) {
        Write-Host "   Updating existing rule pack..." -ForegroundColor Cyan
        Set-DlpSensitiveInformationTypeRulePackage -FileData $fileBytes -Confirm:$false -ErrorAction Stop
        Write-Host "   ✅ Rule pack updated successfully!" -ForegroundColor Green
    } else {
        Write-Host "   Creating new rule pack..." -ForegroundColor Cyan
        try {
            New-DlpSensitiveInformationTypeRulePackage -FileData $fileBytes -ErrorAction Stop
            Write-Host "   ✅ Rule pack created successfully!" -ForegroundColor Green
        } catch {
            if ($_.Exception.Message -match "already exists|duplicate") {
                Write-Host "   Rule pack already exists, falling back to Set (update)..." -ForegroundColor Yellow
                Set-DlpSensitiveInformationTypeRulePackage -FileData $fileBytes -Confirm:$false -ErrorAction Stop
                Write-Host "   ✅ Rule pack updated successfully!" -ForegroundColor Green
            } else {
                throw
            }
        }
    }
    
    Write-Host ""
    
    # Wait for propagation
    Start-Sleep -Seconds 3
    
    # Verify import
    Write-Host "📋 Verifying imported SITs:" -ForegroundColor Cyan
    
    $verifyErrors = @()
    foreach ($entity in $sourceEntities) {
        $sitId = $entity.id
        $resource = $sourceXml.RulePackage.Rules.LocalizedStrings.Resource | 
            Where-Object { $_.idRef -eq $sitId }
        if (-not $resource) {
            $resource = $sourceXml.RulePackage.LocalizedStrings.Resource |
                Where-Object { $_.idRef -eq $sitId }
        }
        
        if ($resource) {
            $sitName = $resource.Name.'#text'
            try {
                $imported = Get-DlpSensitiveInformationType -Identity $sitName -ErrorAction Stop
                Write-Host "   ✅ $sitName" -ForegroundColor Green
            } catch {
                Write-Host "   ❌ $sitName — not found after import" -ForegroundColor Red
                $verifyErrors += $sitName
            }
        }
    }
    
    Write-Host ""
    
    if ($verifyErrors.Count -eq 0) {
        Write-Host "✅ Import complete! All $($sourceEntities.Count) SIT(s) verified." -ForegroundColor Green
    } else {
        Write-Host "⚠️  Import finished but $($verifyErrors.Count) SIT(s) could not be verified." -ForegroundColor Yellow
        Write-Host "   This may be due to propagation delay. Wait a minute and check manually." -ForegroundColor Gray
    }
    
    # Show all custom SITs in target
    $allCustom = Get-DlpSensitiveInformationType | 
        Where-Object { 
            $_.Publisher -ne "Microsoft Corporation" -and 
            $_.Publisher -notlike "Microsoft.SCCManaged*" 
        }
    
    if (-not $allCustom) {
        $allCustom = Get-DlpSensitiveInformationType | 
            Where-Object { $_.Publisher -eq "Microsoft.SCCManaged.CustomRulePack" }
    }
    
    if ($allCustom) {
        Write-Host ""
        Write-Host "   Total custom SITs in target tenant: $($allCustom.Count)" -ForegroundColor White
    }
    
} catch {
    Write-Host "❌ Import failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    
    # Provide targeted diagnostics based on the error
    if ($_.Exception.Message -match "text processor") {
        Write-Host "💡 ROOT CAUSE: Invalid text processor reference(s)" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "   The XML references text processors (Regex, Keyword, Function patterns)" -ForegroundColor Gray
        Write-Host "   that are NOT defined in the rule pack and don't exist in this tenant." -ForegroundColor Gray
        Write-Host ""
        Write-Host "   Fix options:" -ForegroundColor Yellow
        Write-Host "   1. Run: .\Validate-ExportXml.ps1 -XmlPath '$SourceXmlPath'" -ForegroundColor Gray
        Write-Host "      This will show which text processors are missing." -ForegroundColor Gray
        Write-Host "   2. If the source SITs were created via the Purview Compliance Portal," -ForegroundColor Gray
        Write-Host "      export ALL rule packs (not just custom), or recreate the SITs" -ForegroundColor Gray
        Write-Host "      using XML with self-contained text processor definitions." -ForegroundColor Gray
        Write-Host "   3. Edit the XML to add the missing Regex/Keyword/Function definitions." -ForegroundColor Gray
    }
    elseif ($_.Exception.Message -match "document does not contain any content") {
        Write-Host "💡 ROOT CAUSE: Empty document content" -ForegroundColor Yellow
        Write-Host "   The XML file may be empty, corrupted, or have encoding issues." -ForegroundColor Gray
        Write-Host "   Run: .\Validate-ExportXml.ps1 -XmlPath '$SourceXmlPath'" -ForegroundColor Gray
    }
    elseif ($_.Exception.Message -match "ClassificationRulePackageValidation") {
        Write-Host "💡 ROOT CAUSE: Rule pack validation error" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "   Common causes:" -ForegroundColor Yellow
        Write-Host "   • Duplicate SIT names that conflict with existing ones" -ForegroundColor Gray
        Write-Host "   • XML format not valid for this tenant/version" -ForegroundColor Gray
        Write-Host "   • Missing text processors referenced by external ID" -ForegroundColor Gray
        Write-Host "   • Missing permissions for your admin account" -ForegroundColor Gray
        Write-Host ""
        Write-Host "   Run: .\Validate-ExportXml.ps1 -XmlPath '$SourceXmlPath'" -ForegroundColor Gray
    }
    else {
        Write-Host "💡 Common causes:" -ForegroundColor Yellow
        Write-Host "   • Duplicate SIT names that conflict with existing ones" -ForegroundColor Gray
        Write-Host "   • XML format not valid for this tenant/version" -ForegroundColor Gray
        Write-Host "   • Missing permissions for your admin account" -ForegroundColor Gray
    }
}
