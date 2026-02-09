<#
.SYNOPSIS
    Test certificate-based authentication for SIT migration app

.DESCRIPTION
    Tests the connection to Security & Compliance PowerShell using the
    app registration and certificate created by 00-Setup-AppRegistration.ps1

.PARAMETER ConfigPath
    Path to the app-config.json file (default: looks in script directory)

.PARAMETER UseThumbprint
    Use certificate thumbprint from local certificate store
    (default: $true, requires certificate to be installed)

.PARAMETER UsePfxFile
    Use .pfx certificate file instead of thumbprint
    Requires certificate password

.EXAMPLE
    .\00a-Test-AppConnection.ps1
    
    Tests connection using thumbprint from config file

.EXAMPLE
    .\00a-Test-AppConnection.ps1 -UsePfxFile
    
    Tests connection using .pfx file (prompts for password)

.NOTES
    Requirements:
    - ExchangeOnlineManagement module
    - App registration created via 00-Setup-AppRegistration.ps1
    - app-config.json file with connection details
#>

[CmdletBinding(DefaultParameterSetName = 'Thumbprint')]
param(
    [Parameter(Mandatory = $false)]
    [string]$ConfigPath,

    [Parameter(ParameterSetName = 'Thumbprint')]
    [switch]$UseThumbprint = $true,

    [Parameter(ParameterSetName = 'PfxFile')]
    [switch]$UsePfxFile
)

$ErrorActionPreference = "Stop"
$ScriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  Test App-Only Authentication Connection                     ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

#region Load Configuration
Write-Host "📂 Loading configuration..." -ForegroundColor Yellow

if (-not $ConfigPath) {
    $ConfigPath = Join-Path $ScriptPath "app-config.json"
}

if (-not (Test-Path $ConfigPath)) {
    Write-Host "❌ Configuration file not found: $ConfigPath" -ForegroundColor Red
    Write-Host "   Run: .\00-Setup-AppRegistration.ps1 first" -ForegroundColor Yellow
    exit 1
}

try {
    $config = Get-Content $ConfigPath -Raw | ConvertFrom-Json
    Write-Host "✅ Configuration loaded" -ForegroundColor Green
    Write-Host "   App Name: $($config.AppName)" -ForegroundColor Gray
    Write-Host "   App ID: $($config.AppId)" -ForegroundColor Gray
    Write-Host "   Organization: $($config.Organization)" -ForegroundColor Gray
    Write-Host ""
} catch {
    Write-Host "❌ Failed to load configuration: $_" -ForegroundColor Red
    exit 1
}
#endregion

#region Check Module
Write-Host "📦 Checking ExchangeOnlineManagement module..." -ForegroundColor Yellow

$moduleName = "ExchangeOnlineManagement"
if (-not (Get-Module $moduleName -ListAvailable)) {
    Write-Host "   Installing $moduleName..." -ForegroundColor Yellow
    Install-Module $moduleName -Scope CurrentUser -Force -AllowClobber
    Write-Host "   ✅ Module installed" -ForegroundColor Green
} else {
    Write-Host "   ✅ Module found" -ForegroundColor Green
}

Import-Module $moduleName -ErrorAction Stop
Write-Host ""
#endregion

#region Disconnect Existing Sessions
$existingSession = Get-ConnectionInformation -ErrorAction SilentlyContinue
if ($existingSession) {
    Write-Host "⚠️  Disconnecting existing sessions..." -ForegroundColor Yellow
    Disconnect-ExchangeOnline -Confirm:$false
}
#endregion

#region Connect with Certificate
Write-Host "🔗 Connecting to Security & Compliance PowerShell..." -ForegroundColor Cyan

try {
    if ($UsePfxFile) {
        # Connect using .pfx file
        Write-Host "   Using certificate file: $($config.CertificatePath)" -ForegroundColor Gray
        
        if (-not (Test-Path $config.CertificatePath)) {
            Write-Host "   ❌ Certificate file not found: $($config.CertificatePath)" -ForegroundColor Red
            exit 1
        }

        Write-Host "   📝 Enter certificate password:" -ForegroundColor Yellow
        $certPassword = Read-Host -AsSecureString -Prompt "      Password"

        Connect-IPPSSession `
            -CertificateFilePath $config.CertificatePath `
            -CertificatePassword $certPassword `
            -AppID $config.AppId `
            -Organization $config.Organization `
            -ShowBanner:$false
    } else {
        # Connect using thumbprint (default)
        Write-Host "   Using certificate thumbprint: $($config.CertificateThumbprint)" -ForegroundColor Gray
        
        Connect-IPPSSession `
            -CertificateThumbPrint $config.CertificateThumbprint `
            -AppID $config.AppId `
            -Organization $config.Organization `
            -ShowBanner:$false
    }

    Write-Host "   ✅ Connection successful!" -ForegroundColor Green
    Write-Host ""

} catch {
    Write-Host "   ❌ Connection failed: $_" -ForegroundColor Red
    Write-Host ""
    Write-Host "Troubleshooting:" -ForegroundColor Yellow
    Write-Host "   1. Verify the app has Exchange.ManageAsApp permission granted" -ForegroundColor White
    Write-Host "   2. Verify the certificate is still valid" -ForegroundColor White
    Write-Host "   3. Check that the organization domain is correct (use .onmicrosoft.com)" -ForegroundColor White
    Write-Host "   4. Wait a few minutes after app registration for permissions to propagate" -ForegroundColor White
    exit 1
}
#endregion

#region Test Commands
Write-Host "🧪 Testing commands..." -ForegroundColor Cyan
Write-Host ""

# Test 1: Get built-in SIT
Write-Host "   Test 1: Get built-in SIT (Credit Card Number)" -ForegroundColor Yellow
try {
    $testSIT = Get-DlpSensitiveInformationType -Identity "Credit Card Number" -ErrorAction Stop
    Write-Host "      ✅ Successfully retrieved: $($testSIT.Name)" -ForegroundColor Green
} catch {
    Write-Host "      ❌ Failed: $_" -ForegroundColor Red
}
Write-Host ""

# Test 2: List custom SITs
Write-Host "   Test 2: List custom SITs" -ForegroundColor Yellow
try {
    $customSITs = Get-DlpSensitiveInformationType | Where-Object { $_.Publisher -ne "Microsoft Corporation" }
    Write-Host "      ✅ Found $($customSITs.Count) custom SIT(s)" -ForegroundColor Green
    
    if ($customSITs.Count -gt 0) {
        Write-Host "      Custom SITs:" -ForegroundColor Gray
        $customSITs | ForEach-Object {
            Write-Host "         • $($_.Name)" -ForegroundColor Gray
        }
    }
} catch {
    Write-Host "      ❌ Failed: $_" -ForegroundColor Red
}
Write-Host ""

# Test 3: Get connection info
Write-Host "   Test 3: Get connection information" -ForegroundColor Yellow
try {
    $connInfo = Get-ConnectionInformation
    Write-Host "      ✅ Connection Details:" -ForegroundColor Green
    Write-Host "         State: $($connInfo.State)" -ForegroundColor Gray
    Write-Host "         TokenStatus: $($connInfo.TokenStatus)" -ForegroundColor Gray
    Write-Host "         AppId: $($connInfo.AppId)" -ForegroundColor Gray
    Write-Host "         CertificateAuthentication: $($connInfo.CertificateAuthentication)" -ForegroundColor Gray
} catch {
    Write-Host "      ❌ Failed: $_" -ForegroundColor Red
}
Write-Host ""
#endregion

#region Disconnect
Write-Host "🔌 Disconnecting..." -ForegroundColor Yellow
Disconnect-ExchangeOnline -Confirm:$false
Write-Host "✅ Disconnected" -ForegroundColor Green
Write-Host ""
#endregion

#region Summary
Write-Host "╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║  ✅ Test Complete!                                            ║" -ForegroundColor Green
Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "Your app registration is working correctly! 🎉" -ForegroundColor Green
Write-Host ""
Write-Host "You can now use this configuration for unattended automation:" -ForegroundColor White
Write-Host ""
Write-Host "   Connect-IPPSSession ``" -ForegroundColor Gray
Write-Host "       -CertificateThumbPrint `"$($config.CertificateThumbprint)`" ``" -ForegroundColor Gray
Write-Host "       -AppID `"$($config.AppId)`" ``" -ForegroundColor Gray
Write-Host "       -Organization `"$($config.Organization)`"" -ForegroundColor Gray
Write-Host ""
#endregion
