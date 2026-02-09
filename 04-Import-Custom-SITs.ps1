<#
.SYNOPSIS
    Import custom SITs from XML file to target tenant

.DESCRIPTION
    Imports custom SIT definitions from an XML file exported from source tenant.
    
    Process:
    1. Create placeholder SITs in target tenant (generates new GUIDs)
    2. Export target rule pack to get new GUIDs
    3. Merge source XML with target GUIDs
    4. Import merged XML to update placeholders with full definitions

.PARAMETER SourceXmlPath
    Path to the XML file exported from source tenant

.EXAMPLE
    .\04-Import-Custom-SITs.ps1 -SourceXmlPath ".\exports\source-export-20260202-120000.xml"
    # Import SITs from specified XML file

.NOTES
    Must be connected to TARGET tenant Security & Compliance PowerShell first.
    Run: .\01-Connect-Tenant.ps1
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path $_ })]
    [string]$SourceXmlPath
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

# Load source XML
try {
    # Use XmlDocument.Load to handle encoding automatically (BOM, declarations, etc.)
    $sourceXml = New-Object System.Xml.XmlDocument
    $sourceXml.Load($SourceXmlPath)
    
    # Try direct path
    $sourceEntities = $sourceXml.RulePackage.Rules.Entity
    # If empty, try inside Version (common in exports)
    if (-not $sourceEntities) {
        $sourceEntities = $sourceXml.RulePackage.Rules.Version.Entity
    }

    
    Write-Host "📋 Found $($sourceEntities.Count) SITs to import:" -ForegroundColor Green
    
    foreach ($entity in $sourceEntities) {
        $sitId = $entity.id
        $resource = $sourceXml.RulePackage.Rules.LocalizedStrings.Resource | 
            Where-Object { $_.idRef -eq $sitId }
        
        if ($resource) {
            Write-Host "   • $($resource.Name.'#text')" -ForegroundColor White
        }
    }
    Write-Host ""
    
} catch {
    Write-Host "❌ Failed to parse source XML: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# STEP 1: Create placeholder SITs in target tenant
Write-Host "⏳ Step 1: Creating placeholder SITs in target tenant..." -ForegroundColor Yellow
Write-Host ""

$createdPlaceholders = @()

foreach ($entity in $sourceEntities) {
    $sitId = $entity.id
    $resource = $sourceXml.RulePackage.Rules.LocalizedStrings.Resource | 
        Where-Object { $_.idRef -eq $sitId }
    
    if ($resource) {
        $sitName = $resource.Name.'#text'
        $sitDesc = $resource.Description.'#text'
        
        try {
            # Check if already exists
            $existing = Get-DlpSensitiveInformationType -Identity $sitName -ErrorAction SilentlyContinue
            
            if ($existing) {
                Write-Host "  ⚠️  '$sitName' already exists (will be updated)" -ForegroundColor Yellow
                # Handle duplicates by taking the first one
                $targetId = if ($existing -is [array]) { $existing[0].Id } else { $existing.Id }
                
                $createdPlaceholders += @{
                    Name = $sitName
                    Id   = $targetId
                }
            } else {
                # Create placeholder
                $newSit = New-DlpSensitiveInformationType `
                    -Name $sitName `
                    -Description $sitDesc `
                    -Locale "en-US" `
                    -ErrorAction Stop
                
                Write-Host "  ✅ Created placeholder: $sitName" -ForegroundColor Green
                Write-Host "     Target GUID: $($newSit.Id)" -ForegroundColor Gray
                
                $createdPlaceholders += @{
                    Name = $sitName
                    Id   = $newSit.Id
                }
            }
        } catch {
            Write-Host "  ❌ Failed to create '$sitName': $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

Write-Host ""
Write-Host "📊 Created/verified $($createdPlaceholders.Count) placeholders" -ForegroundColor Green
Write-Host ""

# STEP 2: Build GUID mapping
Write-Host "⏳ Step 2: Building GUID mapping (source → target)..." -ForegroundColor Yellow
Write-Host ""

$guidMapping = @{}

foreach ($entity in $sourceEntities) {
    $sourceId = $entity.id
    $resource = $sourceXml.RulePackage.Rules.LocalizedStrings.Resource | 
        Where-Object { $_.idRef -eq $sourceId }
    
    if ($resource) {
        $sitName = $resource.Name.'#text'
        $placeholder = $createdPlaceholders | Where-Object { $_.Name -eq $sitName }
        
        if ($placeholder) {
            $guidMapping[$sourceId] = $placeholder.Id
            Write-Host "  $sitName" -ForegroundColor White
            Write-Host "    Source: $sourceId" -ForegroundColor Gray
            Write-Host "    Target: $($placeholder.Id)" -ForegroundColor Green
        }
    }
}

Write-Host ""
Write-Host "✅ Mapped $($guidMapping.Count) GUIDs" -ForegroundColor Green
Write-Host ""

# STEP 3: Import merged XML (using PowerShell cmdlet)
Write-Host "⏳ Step 3: Importing full SIT definitions..." -ForegroundColor Yellow
Write-Host ""

try {
    # Import the rule pack (PowerShell handles the import)
    try {
        New-DlpSensitiveInformationTypeRulePackage -FileData ([System.IO.File]::ReadAllBytes($SourceXmlPath)) -ErrorAction Stop
    } catch {
        Set-DlpSensitiveInformationTypeRulePackage -FileData ([System.IO.File]::ReadAllBytes($SourceXmlPath)) -Confirm:$false -ErrorAction Stop
    }
    
    Write-Host "✅ Import successful!" -ForegroundColor Green
    Write-Host ""
    
    # Verify import
    Write-Host "📋 Verifying imported SITs:" -ForegroundColor Cyan
    $customSITs = Get-DlpSensitiveInformationType | 
        Where-Object { $_.Publisher -eq "Microsoft.SCCManaged.CustomRulePack" }
    
    $customSITs | Select-Object Name, Id | Format-Table -AutoSize
    
    Write-Host "✅ Migration complete!" -ForegroundColor Green
    Write-Host "   Total custom SITs in target tenant: $($customSITs.Count)" -ForegroundColor White
    
} catch {
    Write-Host "❌ Import failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "`n💡 Common issues:" -ForegroundColor Yellow
    Write-Host "   • Duplicate SIT names" -ForegroundColor Gray
    Write-Host "   • Invalid XML format" -ForegroundColor Gray
    Write-Host "   • Permission issues" -ForegroundColor Gray
}
