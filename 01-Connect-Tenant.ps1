<#
.SYNOPSIS
    Connect to Security & Compliance PowerShell

.DESCRIPTION
    Connects to Microsoft Security & Compliance Center PowerShell.
    Supports three authentication modes:
      1. App-only / certificate thumbprint (default) — cert must be in local cert store
      2. Key Vault — Managed Identity pulls cert from Azure Key Vault (no PFX on disk)
      3. Interactive — browser-based user login (testing only)

.PARAMETER TenantType
    Specify 'Source' or 'Target' for logging purposes

.PARAMETER UseInteractive
    Use interactive authentication (browser login) instead of app-only

.PARAMETER UseKeyVault
    Retrieve the certificate from Azure Key Vault using Managed Identity (or
    Connect-AzAccount for local dev). Requires 'KeyVaultName' and
    'KeyVaultCertName' fields in app-config.json. Cert is loaded ephemerally
    (EphemeralKeySet) — the private key never touches disk.

.PARAMETER ConfigPath
    Path to app-config.json file (default: .\app-config.json)

.EXAMPLE
    .\01-Connect-Tenant.ps1
    # App-only authentication using thumbprint from local cert store (DEFAULT)

.EXAMPLE
    .\01-Connect-Tenant.ps1 -UseKeyVault
    # Managed Identity pulls cert from Azure Key Vault — recommended for Azure VMs

.EXAMPLE
    .\01-Connect-Tenant.ps1 -UseKeyVault -TenantType "Source"
    # Key Vault mode, marking session as Source tenant

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

    For Key Vault mode (-UseKeyVault):
    - Az.Accounts and Az.KeyVault modules required (auto-installed if missing)
    - app-config.json must contain: KeyVaultName, KeyVaultCertName
    - On Azure VM: System-Assigned Managed Identity must have 'Key Vault Secrets User' role
    - Local dev: Connect-AzAccount (interactive) used as fallback
#>

[CmdletBinding(DefaultParameterSetName = 'Thumbprint')]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet('Source', 'Target')]
    [string]$TenantType = 'Source',

    [Parameter(ParameterSetName = 'Interactive', Mandatory = $false)]
    [switch]$UseInteractive,

    [Parameter(ParameterSetName = 'KeyVault', Mandatory = $false)]
    [switch]$UseKeyVault,

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

# ── Helper: load certificate from Azure Key Vault via Managed Identity ────────
function Get-CertFromKeyVault {
    param(
        [string]$VaultName,
        [string]$CertName
    )

    Write-Host "   Checking Az modules..." -ForegroundColor Gray
    @('Az.Accounts', 'Az.KeyVault') | ForEach-Object {
        if (-not (Get-Module $_ -ListAvailable)) {
            Write-Host "   Installing $_..." -ForegroundColor Yellow
            Install-Module $_ -Scope CurrentUser -Force -AllowClobber -Repository PSGallery
        }
        Import-Module $_ -ErrorAction Stop
    }

    # Try Managed Identity first (runs on Azure VM / Automation / Functions)
    Write-Host "   Authenticating to Azure (Managed Identity)..." -ForegroundColor Gray
    $azCtx = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $azCtx) {
        try {
            Connect-AzAccount -Identity -ErrorAction Stop | Out-Null
            Write-Host "   ✅ Authenticated via Managed Identity" -ForegroundColor Green
        } catch {
            Write-Host "   ⚠️  Managed Identity not available — falling back to interactive Azure login" -ForegroundColor Yellow
            Connect-AzAccount -ErrorAction Stop | Out-Null
            Write-Host "   ✅ Authenticated interactively" -ForegroundColor Green
        }
    } else {
        Write-Host "   ✅ Using existing Azure context: $($azCtx.Account)" -ForegroundColor Green
    }

    # Retrieve certificate PFX via the Key Vault secret (contains full PFX as base64)
    Write-Host "   Retrieving certificate '$CertName' from Key Vault '$VaultName'..." -ForegroundColor Gray
    try {
        $kvSecret = Get-AzKeyVaultSecret `
            -VaultName  $VaultName `
            -Name       $CertName `
            -AsPlainText `
            -ErrorAction Stop
    } catch {
        throw "Failed to retrieve '$CertName' from Key Vault '$VaultName': $($_.Exception.Message)`n" +
              "  Ensure the Managed Identity has 'Key Vault Secrets User' role on the vault."
    }

    # Build an in-memory X509Certificate2 — EphemeralKeySet means private key NEVER touches disk
    $certBytes  = [Convert]::FromBase64String($kvSecret)
    $certObject = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
        $certBytes,
        [string]::Empty,
        [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet
    )

    Write-Host "   ✅ Certificate loaded: Subject=$($certObject.Subject)" -ForegroundColor Green
    Write-Host "      Thumbprint : $($certObject.Thumbprint)" -ForegroundColor Gray
    Write-Host "      Expires    : $($certObject.NotAfter.ToString('yyyy-MM-dd'))" -ForegroundColor Gray

    # Warn if cert is expiring within 30 days
    $daysLeft = ($certObject.NotAfter - (Get-Date)).Days
    if ($daysLeft -lt 30) {
        Write-Warning "Certificate expires in $daysLeft day(s)! Rotate before: $($certObject.NotAfter.ToString('yyyy-MM-dd'))"
    }

    return $certObject
}

# Determine authentication method
if ($UseInteractive) {
    Write-Host "🔐 Using interactive authentication (browser-based)" -ForegroundColor Cyan
} elseif ($UseKeyVault) {
    Write-Host "🔐 Using Key Vault mode (Managed Identity → Azure Key Vault → certificate)" -ForegroundColor Cyan

    if (-not (Test-Path $ConfigPath)) {
        Write-Host "❌ Configuration file not found: $ConfigPath" -ForegroundColor Red
        exit 1
    }
    try {
        $config = Get-Content $ConfigPath -Raw | ConvertFrom-Json
        Write-Host "✅ Configuration loaded: $($config.AppName)" -ForegroundColor Green
        Write-Host "   Organization : $($config.Organization)" -ForegroundColor Gray
        Write-Host "   App ID       : $($config.AppId)" -ForegroundColor Gray
    } catch {
        Write-Host "❌ Failed to load configuration: $_" -ForegroundColor Red
        exit 1
    }
    if (-not $config.KeyVaultName -or -not $config.KeyVaultCertName) {
        Write-Host "❌ app-config.json is missing 'KeyVaultName' and/or 'KeyVaultCertName'" -ForegroundColor Red
        Write-Host "   Add these fields (see app-config.sample.json) and retry." -ForegroundColor Yellow
        exit 1
    }
    Write-Host "   Key Vault    : $($config.KeyVaultName)" -ForegroundColor Gray
    Write-Host "   Cert name    : $($config.KeyVaultCertName)" -ForegroundColor Gray
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
    } elseif ($UseKeyVault) {
        # Key Vault → ephemeral cert (Managed Identity)
        $kvCert = Get-CertFromKeyVault -VaultName $config.KeyVaultName -CertName $config.KeyVaultCertName
        Connect-IPPSSession `
            -Certificate  $kvCert `
            -AppID        $config.AppId `
            -Organization $config.Organization `
            -ShowBanner:$false `
            -ErrorAction Stop
    } else {
        # App-only authentication (DEFAULT) — thumbprint from local store
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

    # ── Stamp tenant-type so import/export scripts can enforce source-read-only ──
    $env:PURVIEW_TENANT_TYPE    = $TenantType
    $env:PURVIEW_CONNECTED_ORG  = if ($UseInteractive) { $connectionInfo.TenantId } else { $config.Organization }
    Write-Host "   🔖 Session marked as: $TenantType ($env:PURVIEW_CONNECTED_ORG)" -ForegroundColor DarkCyan
    
} catch {
    Write-Host "❌ Connection failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "`n💡 Troubleshooting:" -ForegroundColor Yellow
    
    if ($UseInteractive) {
        Write-Host "   1. Ensure you have Compliance Administrator role" -ForegroundColor Gray
        Write-Host "   2. Check if MFA is enabled (may require app password)" -ForegroundColor Gray
        Write-Host "   3. Try running PowerShell as Administrator" -ForegroundColor Gray
    } elseif ($UseKeyVault) {
        Write-Host "   1. Confirm Managed Identity is enabled on this VM/resource" -ForegroundColor Gray
        Write-Host "   2. Verify MI has 'Key Vault Secrets User' role on '$($config.KeyVaultName)'" -ForegroundColor Gray
        Write-Host "   3. Ensure cert is stored as a Secret (PFX/base64) not just Certificate" -ForegroundColor Gray
        Write-Host "   4. Ensure app has Exchange.ManageAsApp permission granted" -ForegroundColor Gray
        Write-Host "   5. Check that the organization domain is correct (.onmicrosoft.com)" -ForegroundColor Gray
        Write-Host "   6. Run: .\00a-Test-AppConnection.ps1 -UseKeyVault to verify setup" -ForegroundColor Gray
    } else {
        Write-Host "   1. Verify certificate is installed (check thumbprint)" -ForegroundColor Gray
        Write-Host "   2. Ensure app has Exchange.ManageAsApp permission granted" -ForegroundColor Gray
        Write-Host "   3. Check that the organization domain is correct (.onmicrosoft.com)" -ForegroundColor Gray
        Write-Host "   4. Verify Compliance Administrator role is assigned to the app" -ForegroundColor Gray
        Write-Host "   5. Run: .\00a-Test-AppConnection.ps1 to verify setup" -ForegroundColor Gray
    }
    exit 1
}
