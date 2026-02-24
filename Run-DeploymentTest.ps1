<#
.SYNOPSIS
    Full deployment test: Connect → Create → Export → Validate → Delete → Import → Verify

.DESCRIPTION
    Non-interactive end-to-end test of the SIT migration workflow.
    Creates sample SITs, exports them, validates the XML, deletes the rule pack,
    imports it back, and verifies the round-trip.

.PARAMETER ConfigPath
    Path to app-config.json (default: .\app-config.json)

.EXAMPLE
    .\Run-DeploymentTest.ps1
#>

[CmdletBinding()]
param(
    [string]$ConfigPath = ".\app-config.json"
)

$ErrorActionPreference = "Stop"
$ScriptRoot = $PSScriptRoot

Write-Host ""
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "  DEPLOYMENT TEST: Full SIT Migration Round-Trip" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "  Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
Write-Host ""

$stepNum = 0
$totalSteps = 7
function Write-Step {
    param([string]$Message)
    $script:stepNum++
    Write-Host ""
    Write-Host "[$script:stepNum/$totalSteps] $Message" -ForegroundColor Cyan
    Write-Host ("-" * 60) -ForegroundColor DarkGray
}

# ─────────────────────────────────────────────────────────────
# STEP 1: Connect
# ─────────────────────────────────────────────────────────────
Write-Step "Connecting to tenant..."

Import-Module ExchangeOnlineManagement -ErrorAction Stop
Write-Host "   Module imported: ExchangeOnlineManagement" -ForegroundColor Green

# Disconnect any existing sessions
$existing = Get-ConnectionInformation -ErrorAction SilentlyContinue
if ($existing) {
    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
}

$config = Get-Content $ConfigPath -Raw | ConvertFrom-Json
Write-Host "   Organization: $($config.Organization)" -ForegroundColor Gray

Connect-IPPSSession `
    -CertificateThumbPrint $config.CertificateThumbprint `
    -AppID $config.AppId `
    -Organization $config.Organization `
    -ShowBanner:$false `
    -ErrorAction Stop

$null = Get-DlpSensitiveInformationType -Identity "Credit Card Number" -ErrorAction Stop
Write-Host "   Connected and verified!" -ForegroundColor Green

# ─────────────────────────────────────────────────────────────
# STEP 2: Create sample SITs
# ─────────────────────────────────────────────────────────────
Write-Step "Creating sample SITs..."

& "$ScriptRoot\02-Create-Sample-SITs.ps1"

Start-Sleep -Seconds 3

# Verify sample rule pack exists
$demoPacks = Get-DlpSensitiveInformationTypeRulePackage | Where-Object { $_.Publisher -eq "Demo Custom SITs" }
if (-not $demoPacks) {
    Write-Host "   FAILED: No 'Demo Custom SITs' rule pack found after creation." -ForegroundColor Red
    exit 1
}

$targetPack = $demoPacks | Sort-Object WhenChanged -Descending | Select-Object -First 1
$rpIdentity = $targetPack.Identity
Write-Host "   Rule Pack ID: $rpIdentity" -ForegroundColor Gray
Write-Host "   Rule Pack created successfully!" -ForegroundColor Green

# ─────────────────────────────────────────────────────────────
# STEP 3: Export
# ─────────────────────────────────────────────────────────────
Write-Step "Exporting SITs to XML..."

& "$ScriptRoot\03-Export-Custom-SITs.ps1"

# Find the export file for our rule pack
# Extract GUID from the full Exchange identity path
$rpGuid = if ($rpIdentity -match '[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}') {
    $Matches[0]
} else {
    $rpIdentity
}
Write-Host "   Looking for GUID: $rpGuid" -ForegroundColor Gray

$recentExports = Get-ChildItem "$ScriptRoot\exports\*.xml" |
    Where-Object { $_.LastWriteTime -gt (Get-Date).AddMinutes(-5) } |
    Sort-Object LastWriteTime -Descending

$exportFile = $null
foreach ($file in $recentExports) {
    if ($file.Name -match $rpGuid) {
        $exportFile = $file.FullName
        break
    }
}

# Fallback: content inspection
if (-not $exportFile) {
    foreach ($file in $recentExports) {
        try {
            $xmlDoc = New-Object System.Xml.XmlDocument
            $xmlDoc.Load($file.FullName)
            $xmlId = $xmlDoc.RulePackage.RulePack.id
            if ($xmlId -eq $rpGuid -or $xmlId -eq $rpIdentity) {
                $exportFile = $file.FullName
                break
            }
        } catch {}
    }
}

if (-not $exportFile) {
    Write-Host "   FAILED: Could not find export file for rule pack $rpIdentity" -ForegroundColor Red
    exit 1
}

Write-Host "   Export file: $(Split-Path $exportFile -Leaf)" -ForegroundColor Green

# ─────────────────────────────────────────────────────────────
# STEP 4: Validate exported XML
# ─────────────────────────────────────────────────────────────
Write-Step "Validating exported XML..."

& "$ScriptRoot\Validate-ExportXml.ps1" -XmlPath $exportFile

# ─────────────────────────────────────────────────────────────
# STEP 5: Delete rule pack (simulate migration to clean tenant)
# ─────────────────────────────────────────────────────────────
Write-Step "Deleting rule pack (simulating migration)..."

Write-Host "   Deleting rule pack: $rpIdentity" -ForegroundColor Yellow
Remove-DlpSensitiveInformationTypeRulePackage -Identity $rpIdentity -Confirm:$false -ErrorAction Stop
Write-Host "   Deleted!" -ForegroundColor Green

# Verify deletion
Start-Sleep -Seconds 5
$check = Get-DlpSensitiveInformationTypeRulePackage | Where-Object {
    $_.Identity -eq $rpIdentity -or $_.Identity -match $rpGuid
}
if ($check) {
    Write-Host "   WARNING: Rule pack still exists after deletion (propagation delay?)" -ForegroundColor Yellow
} else {
    Write-Host "   Verified: Rule pack no longer exists" -ForegroundColor Green
}

# ─────────────────────────────────────────────────────────────
# STEP 6: Import (using the updated script)
# ─────────────────────────────────────────────────────────────
Write-Step "Importing SITs back from XML..."

& "$ScriptRoot\04-Import-Custom-SITs.ps1" -SourceXmlPath $exportFile -Force

# ─────────────────────────────────────────────────────────────
# STEP 7: Final verification
# ─────────────────────────────────────────────────────────────
Write-Step "Final verification..."

Start-Sleep -Seconds 5

# Look for rule pack by GUID in identity (may have a new identity path after re-import)
$restoredPack = Get-DlpSensitiveInformationTypeRulePackage | Where-Object {
    $_.Publisher -eq "Demo Custom SITs" -and $_.Identity -match $rpGuid
}
# Fallback: look for any "Demo Custom SITs" pack
if (-not $restoredPack) {
    $restoredPack = Get-DlpSensitiveInformationTypeRulePackage | Where-Object {
        $_.Publisher -eq "Demo Custom SITs"
    } | Sort-Object WhenChanged -Descending | Select-Object -First 1
}

Write-Host ""
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "  RESULTS" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan

if ($restoredPack) {
    Write-Host ""
    Write-Host "  PASS: Rule pack '$rpIdentity' was successfully round-tripped!" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Publisher:  $($restoredPack.Publisher)" -ForegroundColor Gray
    Write-Host "  Data size:  $($restoredPack.SerializedClassificationRuleCollection.Length) bytes" -ForegroundColor Gray
    
    # Verify individual SITs
    $sitNames = @("Demo-Employee-ID", "Demo-Product-Code", "Demo-Customer-Reference")
    $allFound = $true
    foreach ($name in $sitNames) {
        $sit = Get-DlpSensitiveInformationType -Identity $name -ErrorAction SilentlyContinue
        if ($sit) {
            Write-Host "  SIT verified: $name (ID: $($sit.Id))" -ForegroundColor Green
        } else {
            Write-Host "  SIT MISSING:  $name" -ForegroundColor Red
            $allFound = $false
        }
    }
    
    Write-Host ""
    if ($allFound) {
        Write-Host "  ALL TESTS PASSED" -ForegroundColor Green
    } else {
        Write-Host "  PARTIAL PASS: Rule pack exists but some SITs are missing" -ForegroundColor Yellow
    }
} else {
    Write-Host ""
    Write-Host "  FAIL: Rule pack was NOT found after import." -ForegroundColor Red
    Write-Host "  Check the import output above for errors." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "=================================================================" -ForegroundColor Cyan

# Disconnect
Write-Host ""
Write-Host "Disconnecting..." -ForegroundColor Gray
Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
Write-Host "Done." -ForegroundColor Green
