<#
.SYNOPSIS
    Test the full migration loop (Export -> DELETE -> Import)
    
.DESCRIPTION
    This script verifies the migration fidelity by performing a "Loop Test":
    1. Optionally creates sample SITs (or lets you pick an existing Rule Pack)
    2. Exports the Rule Pack to XML
    3. DELETES the Rule Pack from the tenant (Simulating a migration to a clean tenant)
    4. Imports the XML back into the tenant
    5. Verifies the restoration was successful

.EXAMPLE
    .\99-Test-Migration-Loop.ps1
    # Interactive mode (asks to create samples or pick existing)

.NOTES
    WARNING: THIS SCRIPT DELETES DATA. 
    Only use on "Demo" rule packs or in non-production environments.
#>

[CmdletBinding()]
param()

# Check connections and permissions
try {
    $null = Get-DlpSensitiveInformationType -Identity "Credit Card Number" -ErrorAction Stop
} catch {
    Write-Host "❌ Not connected. Run .\01-Connect-Tenant.ps1 first." -ForegroundColor Red
    exit 1
}

if (-not (Get-Command "Remove-DlpSensitiveInformationTypeRulePackage" -ErrorAction SilentlyContinue)) {
    Write-Host "❌ Missing Permissions: 'Remove-DlpSensitiveInformationTypeRulePackage' command not found." -ForegroundColor Red
    Write-Host "   Ensure you have 'Compliance Administrator' or 'Organization Management' roles." -ForegroundColor Yellow
    exit 1
}

Write-Host "🔄 SIT Migration Loop Test (Export -> Delete -> Import)" -ForegroundColor Cyan
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host ""

# Step 1: Limit Scope (Create Sample or Select Existing)
$targetRulePack = $null

$choice = Read-Host "Do you want to create and test with SAMPLE SITs? (Y/N)"
if ($choice -eq 'Y' -or $choice -eq 'y') {
    Write-Host "`n📝 Running 02-Create-Sample-SITs.ps1..." -ForegroundColor Gray
    .\02-Create-Sample-SITs.ps1 | Out-Null
    
    # Verify it exists and get ID
    # Handle case where multiple demo runs have left multiple packs
    $candidates = Get-DlpSensitiveInformationTypeRulePackage | Where-Object { $_.Publisher -eq "Demo Custom SITs" }
    $targetRulePack = $candidates | Sort-Object WhenChanged -Descending | Select-Object -First 1
    
    if (-not $targetRulePack) {
        Write-Host "❌ Failed to create sample rule pack." -ForegroundColor Red
        exit 1
    }
} else {
    # List custom rule packs to pick from
    $customRPs = Get-DlpSensitiveInformationTypeRulePackage | Where-Object { 
        $_.Publisher -ne "Microsoft Corporation" 
    }
    
    if (-not $customRPs) {
        Write-Host "❌ No custom rule packs found to test." -ForegroundColor Red
        exit 1
    }
    
    Write-Host "`n📋 Available Custom Rule Packs:" -ForegroundColor Cyan
    $i = 0
    $customRPs | ForEach-Object {
        Write-Host "   [$i] $($_.Name) (ID: $($_.Identity))" -ForegroundColor White
        $i++
    }
    
    $selection = Read-Host "`nEnter number to test (WARNING: This Rule Pack will be DELETED and Restored)"
    if ($selection -match "^\d+$" -and $selection -lt $customRPs.Count) {
        $targetRulePack = $customRPs[$selection] # Ensure single object is selected
    } else {
        Write-Host "❌ Invalid selection." -ForegroundColor Red
        exit 1
    }
}

# Capture ID (for deletion) and Name (for file finding)
if ($targetRulePack -is [array]) {
    Write-Warning "Multiple rule packs were selected. Picking the most recent one."
    $targetRulePack = $targetRulePack | Sort-Object WhenChanged -Descending | Select-Object -First 1
}

$rpIdentity = $targetRulePack.Identity
$rpName = $targetRulePack.Name

if ([string]::IsNullOrWhiteSpace($rpName)) {
    # Fallback if Name is empty (rare)
    $rpName = $rpIdentity
}

Write-Host "`n🎯 Target locked: '$rpName'" -ForegroundColor Yellow

# Step 2: Export
Write-Host "`n💾 Step 2: Exporting..." -ForegroundColor Cyan
# Run export script
.\03-Export-Custom-SITs.ps1 | Out-Null

# Find the specific exported file by Name (GUID) or Content
Write-Host "   🔍 Searching for export file for '$rpName'..." -ForegroundColor Gray

# Method A: Look for filename containing the Name (GUID)
$exportFile = $null
$recentExports = Get-ChildItem ".\exports\*.xml" | Where-Object { $_.LastWriteTime -gt (Get-Date).AddMinutes(-5) } | Sort-Object LastWriteTime -Descending

# Try finding by filename match first (Fastest)
$match = $recentExports | Where-Object { $_.Name -match $rpName } | Select-Object -First 1
if ($match) {
    $exportFile = $match.FullName
} else {
    # Method B: Content inspection (Slower but accurate if filename differs)
    foreach ($file in $recentExports) {
        try {
            $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
            if ($content -match $rpName -or $content -match $rpIdentity) {
                $exportFile = $file.FullName
                break
            }
        } catch { }
    }
}

if (-not $exportFile) {
    Write-Host "❌ Export file not found for '$rpName' in .\exports\" -ForegroundColor Red
    exit 1
}
Write-Host "   ✅ Found Export: $exportFile" -ForegroundColor Green

# Step 3: Delete (The "Test")
Write-Host "`n🗑️  Step 3: DELETING Rule Pack to simulate migration..." -ForegroundColor Red
Write-Warning "Deleting Rule Pack '$rpName'..."
try {
    # Use Identity for deletion
    Remove-DlpSensitiveInformationTypeRulePackage -Identity $rpIdentity -Confirm:$false -ErrorAction Stop
    Write-Host "   ✅ Deleted successfully." -ForegroundColor Green
} catch {
    Write-Host "   ❌ Delete failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Verify it's gone
if (Get-DlpSensitiveInformationTypeRulePackage -Identity $rpIdentity -ErrorAction SilentlyContinue) {
    Write-Host "   ❌ Verify failed: Rule Pack still exists!" -ForegroundColor Red
    exit 1
}

Start-Sleep -Seconds 2

# Step 4: Import
Write-Host "`n📥 Step 4: Importing back..." -ForegroundColor Cyan
try {
    .\04-Import-Custom-SITs.ps1 -SourceXmlPath $exportFile | Out-Null
    Write-Host "   ✅ Import script finished." -ForegroundColor Green
} catch {
    Write-Host "   ❌ Import script failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Step 5: Final Verification
Write-Host "`n✅ Step 5: Verification" -ForegroundColor Cyan
$restoredRp = Get-DlpSensitiveInformationTypeRulePackage -Identity $rpIdentity -ErrorAction SilentlyContinue

if ($restoredRp) {
    Write-Host "   🎉 SUCCESS: Rule Pack '$rpName' was successfully restored!" -ForegroundColor Green
    
    # Check duplicate status (publisher name often changes to guid in some mig scenarios, checking creation)
    Write-Host "   Publisher: $($restoredRp.Publisher)" -ForegroundColor Gray
    if ($restoredRp.SerializedClassificationRuleCollection) {
        Write-Host "   RuleCount: $($restoredRp.SerializedClassificationRuleCollection.Length) bytes" -ForegroundColor Gray
    }
} else {
    Write-Host "   ❌ FAILURE: Rule Pack was not found after import." -ForegroundColor Red
    Write-Host "   Check logs and try running import manually." -ForegroundColor Yellow
}
