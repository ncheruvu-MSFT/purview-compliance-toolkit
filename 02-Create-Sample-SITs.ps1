<#
.SYNOPSIS
    Create sample custom SITs for testing migration

.DESCRIPTION
    Creates sample custom Sensitive Information Types in the current tenant:
    - 3 regex-based SITs (via XML rule pack)
    - 1 keyword dictionary SIT with 3744 terms (via New-DlpKeywordDictionary)
    - 4 additional SITs that reference the same dictionary (cross-pack refs)

    The dictionary SIT produces a <Dictionary> element in exports, matching
    real-world large keyword SITs used in production tenants. The 4 referencing
    SITs live in a separate rule pack and use <IdMatch idRef="dict-guid"/>
    to point to the shared dictionary — this exercises the two-pass export
    cross-pack injection logic.

.EXAMPLE
    .\02-Create-Sample-SITs.ps1
    # Creates Demo-Employee-ID, Demo-Product-Code, Demo-Customer-Reference,
    #         Demo-Large-Dictionary,
    #         Demo-Dict-Ref-Medical, Demo-Dict-Ref-Legal,
    #         Demo-Dict-Ref-Finance, Demo-Dict-Ref-HR

.NOTES
    Must be connected to Security & Compliance PowerShell first.
    Run: .\01-Connect-Tenant.ps1
#>

[CmdletBinding()]
param()

# Check if connected
try {
    $null = Get-DlpSensitiveInformationType -Identity "Credit Card Number" -ErrorAction Stop
} catch {
    Write-Host "❌ Not connected to Security & Compliance PowerShell" -ForegroundColor Red
    Write-Host "   Run: .\01-Connect-Tenant.ps1 first" -ForegroundColor Yellow
    exit 1
}

Write-Host "📝 Creating sample custom SITs..." -ForegroundColor Cyan
Write-Host ""

$createdCount = 0
$skippedCount = 0
$failedCount = 0

# ═══════════════════════════════════════════════════════════════════════
# PART 1: Regex-based SITs via XML rule pack
# ═══════════════════════════════════════════════════════════════════════
Write-Host "── Part 1: Regex-based SITs (XML rule pack) ──" -ForegroundColor Cyan

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$guid1 = [guid]::NewGuid().ToString()
$guid2 = [guid]::NewGuid().ToString()
$guid3 = [guid]::NewGuid().ToString()
$rulePackGuid = [guid]::NewGuid().ToString()
$publisherGuid = [guid]::NewGuid().ToString()

$xmlContent = @"
<?xml version="1.0" encoding="utf-8"?>
<RulePackage xmlns="http://schemas.microsoft.com/office/2011/mce">
  <RulePack id="$rulePackGuid">
    <Version major="1" minor="0" build="0" revision="0"/>
    <Publisher id="$publisherGuid"/>
    <Details defaultLangCode="en-us">
      <LocalizedDetails langcode="en-us">
        <PublisherName>Demo Custom SITs</PublisherName>
        <Name>Demo Sample SIT Rule Pack</Name>
        <Description>Test SITs for migration demo</Description>
      </LocalizedDetails>
    </Details>
  </RulePack>
  <Rules>
    <Entity id="$guid1" patternsProximity="300" recommendedConfidence="75">
      <Pattern confidenceLevel="75">
        <IdMatch idRef="Regex_EmployeeID"/>
      </Pattern>
    </Entity>
    <Entity id="$guid2" patternsProximity="300" recommendedConfidence="75">
      <Pattern confidenceLevel="75">
        <IdMatch idRef="Regex_ProductCode"/>
      </Pattern>
    </Entity>
    <Entity id="$guid3" patternsProximity="300" recommendedConfidence="75">
      <Pattern confidenceLevel="75">
        <IdMatch idRef="Regex_CustomerRef"/>
      </Pattern>
    </Entity>

    <Regex id="Regex_EmployeeID">EMP-\d{6}</Regex>
    <Regex id="Regex_ProductCode">PRD-[A-Z]{4}-\d{2}</Regex>
    <Regex id="Regex_CustomerRef">CUST-\d{4}</Regex>

    <LocalizedStrings>
      <Resource idRef="$guid1">
        <Name default="true" langcode="en-us">Demo-Employee-ID</Name>
        <Description default="true" langcode="en-us">Detects company employee ID format (EMP-123456)</Description>
      </Resource>
      <Resource idRef="$guid2">
        <Name default="true" langcode="en-us">Demo-Product-Code</Name>
        <Description default="true" langcode="en-us">Detects product codes (PRD-XXXX-XX)</Description>
      </Resource>
      <Resource idRef="$guid3">
        <Name default="true" langcode="en-us">Demo-Customer-Reference</Name>
        <Description default="true" langcode="en-us">Detects customer reference numbers (CUST-9999)</Description>
      </Resource>
    </LocalizedStrings>
  </Rules>
</RulePackage>
"@

$tempXmlPath = Join-Path $env:TEMP "sample-sits-$timestamp.xml"
$xmlContent | Out-File -FilePath $tempXmlPath -Encoding UTF8 -Force

try {
    # Check if demo regex SITs already exist — remove old rule pack first
    $existingDemo = Get-DlpSensitiveInformationType -ErrorAction SilentlyContinue | 
        Where-Object { $_.Name -in @('Demo-Employee-ID','Demo-Product-Code','Demo-Customer-Reference') }
    
    if ($existingDemo) {
        $oldRpIds = $existingDemo | Select-Object -ExpandProperty RulePackId -Unique
        Write-Host "   ⚠️  Found existing demo regex SITs. Removing old rule pack(s)..." -ForegroundColor Yellow
        foreach ($oldRpId in $oldRpIds) {
            try {
                Remove-DlpSensitiveInformationTypeRulePackage -Identity $oldRpId -Confirm:$false -ErrorAction Stop
                Write-Host "   ✅ Removed old rule pack: $oldRpId" -ForegroundColor Green
            } catch {
                Write-Host "   ⚠️  Could not remove $oldRpId : $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
        Start-Sleep -Seconds 3
    }
    
    Write-Host "   ⏳ Importing regex SIT rule pack..." -ForegroundColor Yellow
    New-DlpSensitiveInformationTypeRulePackage -FileData ([System.IO.File]::ReadAllBytes($tempXmlPath)) -ErrorAction Stop
    Start-Sleep -Seconds 3
    
    Write-Host "   ✅ Regex SIT rule pack imported!" -ForegroundColor Green
    $createdCount += 3
    
    # Verify
    foreach ($name in @('Demo-Employee-ID', 'Demo-Product-Code', 'Demo-Customer-Reference')) {
        try {
            $sit = Get-DlpSensitiveInformationType -Identity $name -ErrorAction Stop
            Write-Host "   ✓ $name (ID: $($sit.Id))" -ForegroundColor Green
        } catch {
            Write-Host "   ⚠️  $name not found" -ForegroundColor Yellow
        }
    }
    
    Remove-Item $tempXmlPath -Force -ErrorAction SilentlyContinue
} catch {
    Write-Host "   ❌ Failed to import regex SITs: $($_.Exception.Message)" -ForegroundColor Red
    $failedCount += 3
    Write-Host "   Temp XML saved at: $tempXmlPath" -ForegroundColor Gray
}

Write-Host ""

# ═══════════════════════════════════════════════════════════════════════
# PART 2: Dictionary SIT via New-DlpKeywordDictionary (3744 terms)
# ═══════════════════════════════════════════════════════════════════════
Write-Host "── Part 2: Dictionary SIT (3744 keywords, a-z) ──" -ForegroundColor Cyan
Write-Host "   ⏳ Generating 3744 keywords (26 letters × 144 each)..." -ForegroundColor Yellow

# Build keyword list: aterm001, aterm002, ..., zterm144
$keywords = [System.Text.StringBuilder]::new(100000)
foreach ($letter in [char[]]('a'..'z')) {
    for ($i = 1; $i -le 144; $i++) {
        if ($keywords.Length -gt 0) { [void]$keywords.AppendLine() }
        [void]$keywords.Append("${letter}term$($i.ToString('D3'))")
    }
}
$keywordString = $keywords.ToString()
$keywordCount = ($keywordString -split "`n").Count
Write-Host "   ✅ Generated $keywordCount keywords" -ForegroundColor Green

# Convert to byte array (UTF-8) — New-DlpKeywordDictionary expects -FileData bytes
$keywordBytes = [System.Text.Encoding]::UTF8.GetBytes($keywordString)

try {
    # Check if dictionary already exists — remove it first
    $existingDict = Get-DlpKeywordDictionary -Name "Demo-Large-Dictionary" -ErrorAction SilentlyContinue
    if ($existingDict) {
        Write-Host "   ⚠️  Found existing Demo-Large-Dictionary. Removing..." -ForegroundColor Yellow
        Remove-DlpKeywordDictionary -Identity "Demo-Large-Dictionary" -Confirm:$false -ErrorAction Stop
        Write-Host "   ✅ Removed old dictionary" -ForegroundColor Green
        Start-Sleep -Seconds 3
    }
    
    Write-Host "   ⏳ Creating keyword dictionary (this may take a moment)..." -ForegroundColor Yellow
    $dict = New-DlpKeywordDictionary `
        -Name "Demo-Large-Dictionary" `
        -Description "Demo dictionary with 3744 keywords (a-z × 144) for migration testing" `
        -FileData $keywordBytes `
        -ErrorAction Stop
    
    Start-Sleep -Seconds 3
    Write-Host "   ✅ Dictionary created!" -ForegroundColor Green
    Write-Host "   ✓ Demo-Large-Dictionary (ID: $($dict.Identity)) — 3744 keywords" -ForegroundColor Green
    $createdCount += 1
    
} catch {
    Write-Host "   ❌ Failed to create dictionary: $($_.Exception.Message)" -ForegroundColor Red
    $failedCount += 1
}

Write-Host ""

# ═══════════════════════════════════════════════════════════════════════
# PART 3: 4 SITs that reference the shared dictionary (cross-pack refs)
# ═══════════════════════════════════════════════════════════════════════
Write-Host "── Part 3: 4 SITs referencing shared dictionary (cross-pack) ──" -ForegroundColor Cyan

# Get the dictionary's Identity GUID — needed as idRef in the XML
$dictObj = Get-DlpKeywordDictionary -Name "Demo-Large-Dictionary" -ErrorAction SilentlyContinue
if (-not $dictObj) {
    Write-Host "   ⚠️  Demo-Large-Dictionary not found — skipping Part 3" -ForegroundColor Yellow
    $skippedCount += 4
} else {
    $dictIdentity = $dictObj.Identity
    Write-Host "   ✅ Dictionary Identity: $dictIdentity" -ForegroundColor Green

    $refGuid1 = [guid]::NewGuid().ToString()
    $refGuid2 = [guid]::NewGuid().ToString()
    $refGuid3 = [guid]::NewGuid().ToString()
    $refGuid4 = [guid]::NewGuid().ToString()
    $refRpGuid = [guid]::NewGuid().ToString()
    $refPubGuid = [guid]::NewGuid().ToString()

    # Each entity uses <IdMatch idRef="$dictIdentity"/> to reference the shared dictionary.
    # This creates the cross-pack scenario: dictionary lives in its own rule pack,
    # these 4 SITs live in a second rule pack and reference the dictionary by GUID.
    $refXml = @"
<?xml version="1.0" encoding="utf-8"?>
<RulePackage xmlns="http://schemas.microsoft.com/office/2011/mce">
  <RulePack id="$refRpGuid">
    <Version major="1" minor="0" build="0" revision="0"/>
    <Publisher id="$refPubGuid"/>
    <Details defaultLangCode="en-us">
      <LocalizedDetails langcode="en-us">
        <PublisherName>Demo Dictionary Ref SITs</PublisherName>
        <Name>Demo Dictionary Reference Rule Pack</Name>
        <Description>SITs that reference the shared Demo-Large-Dictionary</Description>
      </LocalizedDetails>
    </Details>
  </RulePack>
  <Rules>
    <Entity id="$refGuid1" patternsProximity="300" recommendedConfidence="75">
      <Pattern confidenceLevel="75">
        <IdMatch idRef="$dictIdentity"/>
      </Pattern>
    </Entity>
    <Entity id="$refGuid2" patternsProximity="300" recommendedConfidence="75">
      <Pattern confidenceLevel="75">
        <IdMatch idRef="$dictIdentity"/>
      </Pattern>
    </Entity>
    <Entity id="$refGuid3" patternsProximity="300" recommendedConfidence="75">
      <Pattern confidenceLevel="75">
        <IdMatch idRef="$dictIdentity"/>
      </Pattern>
    </Entity>
    <Entity id="$refGuid4" patternsProximity="300" recommendedConfidence="75">
      <Pattern confidenceLevel="75">
        <IdMatch idRef="$dictIdentity"/>
      </Pattern>
    </Entity>

    <LocalizedStrings>
      <Resource idRef="$refGuid1">
        <Name default="true" langcode="en-us">Demo-Dict-Ref-Medical</Name>
        <Description default="true" langcode="en-us">Medical terms referencing shared dictionary</Description>
      </Resource>
      <Resource idRef="$refGuid2">
        <Name default="true" langcode="en-us">Demo-Dict-Ref-Legal</Name>
        <Description default="true" langcode="en-us">Legal terms referencing shared dictionary</Description>
      </Resource>
      <Resource idRef="$refGuid3">
        <Name default="true" langcode="en-us">Demo-Dict-Ref-Finance</Name>
        <Description default="true" langcode="en-us">Finance terms referencing shared dictionary</Description>
      </Resource>
      <Resource idRef="$refGuid4">
        <Name default="true" langcode="en-us">Demo-Dict-Ref-HR</Name>
        <Description default="true" langcode="en-us">HR terms referencing shared dictionary</Description>
      </Resource>
    </LocalizedStrings>
  </Rules>
</RulePackage>
"@

    $refXmlPath = Join-Path $env:TEMP "dict-ref-sits-$timestamp.xml"
    $refXml | Out-File -FilePath $refXmlPath -Encoding UTF8 -Force

    try {
        # Check if these SITs already exist — remove old rule pack first
        $existingRefs = Get-DlpSensitiveInformationType -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -in @('Demo-Dict-Ref-Medical','Demo-Dict-Ref-Legal','Demo-Dict-Ref-Finance','Demo-Dict-Ref-HR') }

        if ($existingRefs) {
            $oldRefRpIds = $existingRefs | Select-Object -ExpandProperty RulePackId -Unique
            Write-Host "   ⚠️  Found existing dict-ref SITs. Removing old rule pack(s)..." -ForegroundColor Yellow
            foreach ($oldRefRpId in $oldRefRpIds) {
                try {
                    Remove-DlpSensitiveInformationTypeRulePackage -Identity $oldRefRpId -Confirm:$false -ErrorAction Stop
                    Write-Host "   ✅ Removed old rule pack: $oldRefRpId" -ForegroundColor Green
                } catch {
                    Write-Host "   ⚠️  Could not remove $oldRefRpId : $($_.Exception.Message)" -ForegroundColor Yellow
                }
            }
            Start-Sleep -Seconds 3
        }

        Write-Host "   ⏳ Importing dictionary-reference SIT rule pack..." -ForegroundColor Yellow
        New-DlpSensitiveInformationTypeRulePackage -FileData ([System.IO.File]::ReadAllBytes($refXmlPath)) -ErrorAction Stop
        Start-Sleep -Seconds 3

        Write-Host "   ✅ Dictionary-reference rule pack imported!" -ForegroundColor Green
        $createdCount += 4

        # Verify
        foreach ($name in @('Demo-Dict-Ref-Medical', 'Demo-Dict-Ref-Legal', 'Demo-Dict-Ref-Finance', 'Demo-Dict-Ref-HR')) {
            try {
                $sit = Get-DlpSensitiveInformationType -Identity $name -ErrorAction Stop
                Write-Host "   ✓ $name (ID: $($sit.Id)) → refs dictionary $dictIdentity" -ForegroundColor Green
            } catch {
                Write-Host "   ⚠️  $name not found" -ForegroundColor Yellow
            }
        }

        Remove-Item $refXmlPath -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Host "   ❌ Failed to import dict-ref SITs: $($_.Exception.Message)" -ForegroundColor Red
        $failedCount += 4
        Write-Host "   Temp XML saved at: $refXmlPath" -ForegroundColor Gray
    }
}

# ═══════════════════════════════════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════════════════════════════════
Write-Host ""
Write-Host "📊 Summary:" -ForegroundColor Cyan
Write-Host "   Created: $createdCount" -ForegroundColor Green
Write-Host "   Skipped: $skippedCount" -ForegroundColor Yellow
Write-Host "   Failed:  $failedCount" -ForegroundColor Red

if ($createdCount -gt 0) {
    Write-Host "`n💡 Next step: Export these SITs" -ForegroundColor Cyan
    Write-Host "   Run: .\03-Export-Custom-SITs.ps1" -ForegroundColor Gray
    Write-Host "   The dictionary SIT exports with a <Dictionary> element." -ForegroundColor Gray
    Write-Host "   The 4 dict-ref SITs reference it cross-pack via <IdMatch idRef>." -ForegroundColor Gray
    Write-Host "   The two-pass export will inject the missing Dictionary processor." -ForegroundColor Gray
}

# List all custom SITs
Write-Host "`n📋 All custom SITs in this tenant:" -ForegroundColor Cyan
$customSITs = Get-DlpSensitiveInformationType | 
    Where-Object { $_.Publisher -ne "Microsoft Corporation" -and $_.Publisher -notlike "Microsoft.SCCManaged*" }
if (-not $customSITs) {
    $customSITs = Get-DlpSensitiveInformationType | 
        Where-Object { $_.Publisher -eq "Microsoft.SCCManaged.CustomRulePack" }
}

if ($customSITs) {
    $customSITs | Select-Object Name, Id, Description | Format-Table -AutoSize
    Write-Host "Total: $($customSITs.Count) custom SITs" -ForegroundColor Gray
} else {
    Write-Host "   No custom SITs found" -ForegroundColor Yellow
}
