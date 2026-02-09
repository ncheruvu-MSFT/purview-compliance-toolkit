<#
.SYNOPSIS
    Connect to Security & Compliance PowerShell

.DESCRIPTION
    Connects to Microsoft Security & Compliance Center PowerShell.
    Supports both certificate-based (default) and interactive authentication.

.PARAMETER TenantType
    Specify 'Source' or 'Target' for logging purposes

.PARAMETER UseInteractive
    Use interactive authentication (browser login) instead of app-only

.PARAMETER ConfigPath
    Path to app-config.json file (default: .\app-config.json)

.EXAMPLE
    .\01-Connect-Tenant.ps1
    # App-only authentication (certificate-based) - DEFAULT

.EXAMPLE
    .\01-Connect-Tenant.ps1 -TenantType "Source"
    # Connect to source tenant with app-only auth

.EXAMPLE
    .\01-Connect-Tenant.ps1 -UseInteractive
    # Use interactive authentication (browser opens)

.EXAMPLE
    .\01-Connect-Tenant.ps1 -ConfigPath ".\source-app-config.json"
    # Connect using specific config file

.NOTES
    Requirements:
    - ExchangeOnlineManagement module installed
    - Compliance Administrator role
    - Run 00-Setup-AppRegistration.ps1 first (for app-only auth)
    - app-config.json file must exist
    
    For interactive authentication (not recommended):
    - Use -UseInteractive flag
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet('Source', 'Target')]
    [string]$TenantType = 'Source',

    [Parameter(Mandatory = $false)]
    [switch]$UseInteractive,

    [Parameter(Mandatory = $false)]
    [string]$ConfigPath = ".\app-config.json"
)

# Check if module is installed
$moduleName = "ExchangeOnlineManagement"
if (-not (Get-Module $moduleName -ListAvailable)) {
    Write-Host "📦 Module '$moduleName' not found. Installing..." -ForegroundColor Yellow
    Install-Module $moduleName -Scope CurrentUser -Force -AllowClobber
    Write-Host "✅ Module installed" -ForegroundColor Green
}

# Import module
Import-Module $moduleName -ErrorAction Stop
Write-Host "✅ Module imported: $moduleName" -ForegroundColor Green

# Disconnect any existing sessions
$existingSession = Get-ConnectionInformation -ErrorAction SilentlyContinue
if ($existingSession) {
    Write-Host "⚠️  Existing connection found. Disconnecting..." -ForegroundColor Yellow
    Disconnect-ExchangeOnline -Confirm:$false
}

# Determine authentication method
if ($UseInteractive) {
    Write-Host "🔐 Using interactive authentication (browser-based)" -ForegroundColor Cyan
} else {
    Write-Host "🔐 Using app-only authentication (certificate-based) - DEFAULT" -ForegroundColor Cyan
    
    # Load configuration
    if (-not (Test-Path $ConfigPath)) {
        Write-Host "❌ Configuration file not found: $ConfigPath" -ForegroundColor Red
        Write-Host "   Run: .\00-Setup-AppRegistration.ps1 first" -ForegroundColor Yellow
        Write-Host "   Or use: .\01-Connect-Tenant.ps1 -UseInteractive" -ForegroundColor Yellow
        exit 1
    }
    
    try {
        $config = Get-Content $ConfigPath -Raw | ConvertFrom-Json
        Write-Host "✅ Configuration loaded: $($config.AppName)" -ForegroundColor Green
        Write-Host "   Organization: $($config.Organization)" -ForegroundColor Gray
        Write-Host "   App ID: $($config.AppId)" -ForegroundColor Gray
    } catch {
        Write-Host "❌ Failed to load configuration: $_" -ForegroundColor Red
        exit 1
    }
}

# Connect to Security & Compliance PowerShell
try {
    Write-Host "`n🔌 Connecting to Security & Compliance PowerShell ($TenantType)..." -ForegroundColor Cyan
    
    if ($UseInteractive) {
        # Interactive authentication
        Write-Host "   Browser window will open for authentication" -ForegroundColor Gray
        Connect-IPPSSession -ShowBanner:$false -ErrorAction Stop
    } else {
        # App-only authentication (DEFAULT)
        Write-Host "   Using certificate thumbprint: $($config.CertificateThumbprint)" -ForegroundColor Gray
        
        Connect-IPPSSession `
            -CertificateThumbPrint $config.CertificateThumbprint `
            -AppID $config.AppId `
            -Organization $config.Organization `
            -ShowBanner:$false `
            -ErrorAction Stop
    }
    
    Write-Host "✅ Connected successfully!" -ForegroundColor Green
    
    # Test connection
    Write-Host "`n🔍 Testing connection..." -ForegroundColor Cyan
    $testSit = Get-DlpSensitiveInformationType -Identity "Credit Card Number" -ErrorAction Stop
    
    Write-Host "✅ Connection verified" -ForegroundColor Green
    Write-Host "   Test query returned: $($testSit.Name)" -ForegroundColor Gray
    
    # Display connection info
    $connectionInfo = Get-ConnectionInformation
    Write-Host "`n📊 Connection Details:" -ForegroundColor Cyan
    Write-Host "   Organization: $($connectionInfo.TenantId)" -ForegroundColor Gray
    
    if ($UseInteractive) {
        Write-Host "   User: $($connectionInfo.UserPrincipalName)" -ForegroundColor Gray
    } else {
        Write-Host "   App ID: $($connectionInfo.AppId)" -ForegroundColor Gray
        Write-Host "   Certificate Auth: $($connectionInfo.CertificateAuthentication)" -ForegroundColor Gray
    }
    
    Write-Host "   Token Status: $($connectionInfo.TokenStatus)" -ForegroundColor Gray
    Write-Host "   Tenant Type: $TenantType" -ForegroundColor Gray
    
    Write-Host "`n✅ Ready to proceed with SIT operations" -ForegroundColor Green
    
} catch {
    Write-Host "❌ Connection failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "`n💡 Troubleshooting:" -ForegroundColor Yellow
    
    if ($UseInteractive) {
        Write-Host "   1. Ensure you have Compliance Administrator role" -ForegroundColor Gray
        Write-Host "   2. Check if MFA is enabled (may require app password)" -ForegroundColor Gray
        Write-Host "   3. Try running PowerShell as Administrator" -ForegroundColor Gray
    } else {
        Write-Host "   1. Verify certificate is installed (check thumbprint)" -ForegroundColor Gray
        Write-Host "   2. Ensure app has Exchange.ManageAsApp permission granted" -ForegroundColor Gray
        Write-Host "   3. Check that the organization domain is correct (.onmicrosoft.com)" -ForegroundColor Gray
        Write-Host "   4. Verify Compliance Administrator role is assigned to the app" -ForegroundColor Gray
        Write-Host "   5. Run: .\00a-Test-AppConnection.ps1 to verify setup" -ForegroundColor Gray
    }
    exit 1
}
