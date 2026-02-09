<#
.SYNOPSIS
    Create sample custom SITs for testing migration

.DESCRIPTION
    Creates 3 sample custom Sensitive Information Types in the current tenant.
    These are simple pattern-based SITs for testing the migration workflow.

.EXAMPLE
    .\02-Create-Sample-SITs.ps1
    # Creates Demo-Employee-ID, Demo-Product-Code, Demo-Customer-Reference

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

Write-Host "📝 Creating sample custom SITs using XML rule pack..." -ForegroundColor Cyan
Write-Host ""

# Generate minimal XML rule pack with sample SITs
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"

# Generate unique GUIDs
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

# Save to temp file
$tempXmlPath = Join-Path $env:TEMP "sample-sits-$timestamp.xml"
$xmlContent | Out-File -FilePath $tempXmlPath -Encoding UTF8 -Force

Write-Host "📄 Generated XML rule pack: $tempXmlPath" -ForegroundColor Gray
Write-Host ""

$createdCount = 0
$skippedCount = 0
$failedCount = 0

try {
    Write-Host "⏳ Importing SIT rule pack..." -ForegroundColor Yellow
    
    # Import the rule pack
    try {
        New-DlpSensitiveInformationTypeRulePackage -FileData ([System.IO.File]::ReadAllBytes($tempXmlPath)) -ErrorAction Stop
    } catch {
        # If it already exists, try Set (Update)
        Write-Warning "New-DlpSensitiveInformationTypeRulePackage failed, trying Set- (Update)..."
        Set-DlpSensitiveInformationTypeRulePackage -FileData ([System.IO.File]::ReadAllBytes($tempXmlPath)) -ErrorAction Stop
    }
    
    # Wait a moment for propagation
    Start-Sleep -Seconds 3
    
    Write-Host "✅ Rule pack imported successfully!" -ForegroundColor Green
    $createdCount = 3
    
    # Verify import
    Write-Host "`n📋 Verifying created SITs:" -ForegroundColor Cyan
    try {
        $verifyEmployeeID = Get-DlpSensitiveInformationType -Identity "Demo-Employee-ID" -ErrorAction Stop
        Write-Host "   ✓ Demo-Employee-ID (ID: $($verifyEmployeeID.Id))" -ForegroundColor Green
    } catch {
        Write-Host "   ⚠️  Demo-Employee-ID not found" -ForegroundColor Yellow
    }
    
    try {
        $verifyProductCode = Get-DlpSensitiveInformationType -Identity "Demo-Product-Code" -ErrorAction Stop
        Write-Host "   ✓ Demo-Product-Code (ID: $($verifyProductCode.Id))" -ForegroundColor Green
    } catch {
        Write-Host "   ⚠️  Demo-Product-Code not found" -ForegroundColor Yellow
    }
    
    try {
        $verifyCustomerRef = Get-DlpSensitiveInformationType -Identity "Demo-Customer-Reference" -ErrorAction Stop
        Write-Host "   ✓ Demo-Customer-Reference (ID: $($verifyCustomerRef.Id))" -ForegroundColor Green
    } catch {
        Write-Host "   ⚠️  Demo-Customer-Reference not found" -ForegroundColor Yellow
    }
    
    # Clean up temp file
    Remove-Item $tempXmlPath -Force -ErrorAction SilentlyContinue
    
} catch {
    Write-Host "❌ Failed to import rule pack: $($_.Exception.Message)" -ForegroundColor Red
    $failedCount = 3
    $createdCount = 0
    
    Write-Host "`n💡 Common issues:" -ForegroundColor Yellow
    Write-Host "   • SITs with these names already exist" -ForegroundColor Gray
    Write-Host "   • Invalid XML format or schema" -ForegroundColor Gray
    Write-Host "   • Insufficient permissions" -ForegroundColor Gray
    Write-Host "`nTemp XML saved at: $tempXmlPath" -ForegroundColor Gray
}

Write-Host ""
Write-Host "📊 Summary:" -ForegroundColor Cyan
Write-Host "   Created: $createdCount" -ForegroundColor Green
Write-Host "   Skipped: $skippedCount" -ForegroundColor Yellow
Write-Host "   Failed:  $failedCount" -ForegroundColor Red

if ($createdCount -gt 0) {
    Write-Host "`n💡 Next step: Export these SITs" -ForegroundColor Cyan
    Write-Host "   Run: .\03-Export-Custom-SITs.ps1" -ForegroundColor Gray
}

# List all custom SITs
Write-Host "`n📋 All custom SITs in this tenant:" -ForegroundColor Cyan
$customSITs = Get-DlpSensitiveInformationType | 
    Where-Object { $_.Publisher -eq "Microsoft.SCCManaged.CustomRulePack" }

if ($customSITs) {
    $customSITs | Select-Object Name, Id, Description | Format-Table -AutoSize
    Write-Host "Total: $($customSITs.Count) custom SITs" -ForegroundColor Gray
} else {
    Write-Host "   No custom SITs found" -ForegroundColor Yellow
}
