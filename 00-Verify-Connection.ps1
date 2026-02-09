<#
.SYNOPSIS
    Verify connection and list all SITs

.DESCRIPTION
    Checks which tenant you're connected to and lists all custom SITs.
    Use this to verify you're in the correct tenant before making changes.

.EXAMPLE
    .\00-Verify-Connection.ps1
#>

[CmdletBinding()]
param()

Write-Host "🔍 Verifying connection and tenant..." -ForegroundColor Cyan
Write-Host ""

# Check if connected
try {
    $null = Get-DlpSensitiveInformationType -Identity "Credit Card Number" -ErrorAction Stop
} catch {
    Write-Host "❌ Not connected to Security & Compliance PowerShell" -ForegroundColor Red
    Write-Host "   Run: .\01-Connect-Tenant.ps1 first" -ForegroundColor Yellow
    exit 1
}

# Get tenant information
Write-Host "📋 Tenant Information:" -ForegroundColor Cyan
try {
    $orgConfig = Get-OrganizationConfig -ErrorAction Stop
    Write-Host "   Organization Name: $($orgConfig.DisplayName)" -ForegroundColor White
    Write-Host "   Organization ID: $($orgConfig.Guid)" -ForegroundColor White
    Write-Host "   Domain: $($orgConfig.Identity)" -ForegroundColor White
} catch {
    Write-Host "   Could not retrieve organization config" -ForegroundColor Yellow
}

Write-Host ""

# Get ALL custom SITs (try multiple publisher filters)
Write-Host "🔍 Searching for custom SITs..." -ForegroundColor Cyan
Write-Host ""

$allSITs = Get-DlpSensitiveInformationType

# Group by publisher
$sitsByPublisher = $allSITs | Group-Object -Property Publisher

Write-Host "📊 SITs by Publisher:" -ForegroundColor Cyan
foreach ($group in $sitsByPublisher | Sort-Object Count -Descending) {
    Write-Host "   $($group.Name): $($group.Count) SITs" -ForegroundColor White
}

Write-Host ""

# Look for our custom SITs specifically
Write-Host "🔎 Looking for Demo SITs:" -ForegroundColor Cyan
$demoSITs = $allSITs | Where-Object { $_.Name -like "Demo-*" }

if ($demoSITs) {
    Write-Host "   ✅ Found $($demoSITs.Count) Demo SITs!" -ForegroundColor Green
    $demoSITs | ForEach-Object {
        Write-Host "      • $($_.Name)" -ForegroundColor White
        Write-Host "        ID: $($_.Id)" -ForegroundColor Gray
        Write-Host "        Publisher: $($_.Publisher)" -ForegroundColor Gray
    }
} else {
    Write-Host "   ⚠️  No Demo SITs found" -ForegroundColor Yellow
}

Write-Host ""

# List ALL custom (non-Microsoft) SITs
Write-Host "📋 All Custom/Non-Microsoft SITs:" -ForegroundColor Cyan
$customSITs = $allSITs | Where-Object { 
    $_.Publisher -notlike "*Microsoft*" -or 
    $_.Publisher -eq "Microsoft.SCCManaged.CustomRulePack" -or
    $_.Name -like "Demo-*"
}

if ($customSITs) {
    Write-Host "   Found $($customSITs.Count) custom SITs:" -ForegroundColor Green
    Write-Host ""
    $customSITs | Select-Object Name, Publisher, Id | Format-Table -AutoSize
} else {
    Write-Host "   No custom SITs found in this tenant" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "💡 This could mean:" -ForegroundColor Cyan
    Write-Host "   • You're in the wrong tenant" -ForegroundColor Gray
    Write-Host "   • SITs weren't created successfully" -ForegroundColor Gray
    Write-Host "   • SITs are still propagating (wait 5-10 minutes)" -ForegroundColor Gray
}

Write-Host ""
Write-Host "📊 Total SITs in tenant: $($allSITs.Count)" -ForegroundColor Cyan
