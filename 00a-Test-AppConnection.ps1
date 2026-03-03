<#
.SYNOPSIS
    Test certificate-based authentication for SIT migration app

.DESCRIPTION
    Tests the connection to Security & Compliance PowerShell using the
    app registration and certificate created by 00-Setup-AppRegistration.ps1.
    Supports three auth modes:
      - Thumbprint  (default) — cert installed in local store
      - PfxFile               — .pfx file on disk (prompts for password)
      - KeyVault              — Managed Identity → Azure Key Vault ephemeral cert

.PARAMETER ConfigPath
    Path to the app-config.json file (default: looks in script directory)

.PARAMETER UseThumbprint
    Use certificate thumbprint from local certificate store
    (default: $true, requires certificate to be installed)

.PARAMETER UsePfxFile
    Use .pfx certificate file instead of thumbprint
    Requires certificate password

.PARAMETER UseKeyVault
    Retrieve the certificate from Azure Key Vault via Managed Identity.
    Requires KeyVaultName and KeyVaultCertName fields in app-config.json.
    On an Azure VM with Managed Identity assigned the certificate private key
    is loaded ephemerally — it never touches disk.

.EXAMPLE
    .\00a-Test-AppConnection.ps1
    
    Tests connection using thumbprint from config file

.EXAMPLE
    .\00a-Test-AppConnection.ps1 -UsePfxFile
    
    Tests connection using .pfx file (prompts for password)

.EXAMPLE
    .\00a-Test-AppConnection.ps1 -UseKeyVault
    
    Tests connection via Managed Identity → Key Vault (ideal for Azure VMs / automation)

.NOTES
    Requirements:
    - ExchangeOnlineManagement module
    - App registration created via 00-Setup-AppRegistration.ps1
    - app-config.json file with connection details
    - For -UseKeyVault: Az.Accounts + Az.KeyVault modules; VM Managed Identity with
      'Key Vault Secrets User' role on the vault
#>

[CmdletBinding(DefaultParameterSetName = 'Thumbprint')]
param(
    [Parameter(Mandatory = $false)]
    [string]$ConfigPath,

    [Parameter(ParameterSetName = 'Thumbprint')]
    [switch]$UseThumbprint,

    [Parameter(ParameterSetName = 'PfxFile')]
    [switch]$UsePfxFile,

    [Parameter(ParameterSetName = 'KeyVault')]
    [switch]$UseKeyVault
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

#region Key Vault Helper
function Get-CertFromKeyVault {
    <#
    .SYNOPSIS  Retrieve a PFX certificate from Azure Key Vault and return it as
               an in-memory X509Certificate2 (EphemeralKeySet — never touches disk).
    #>
    param(
        [Parameter(Mandatory)][string]$VaultName,
        [Parameter(Mandatory)][string]$CertName
    )

    Write-Host "   📦 Ensuring Az.Accounts / Az.KeyVault modules..." -ForegroundColor Gray
    foreach ($mod in @('Az.Accounts','Az.KeyVault')) {
        if (-not (Get-Module $mod -ListAvailable)) {
            Install-Module $mod -Scope CurrentUser -Force -AllowClobber
        }
        Import-Module $mod -ErrorAction Stop
    }

    # Try Managed Identity first (works on Azure VMs / automation); fall back to interactive
    $azCtx = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $azCtx) {
        Write-Host "   🔑 Authenticating to Azure..." -ForegroundColor Gray
        try {
            Connect-AzAccount -Identity -ErrorAction Stop | Out-Null
            Write-Host "      ✅ Managed Identity login succeeded" -ForegroundColor Green
        } catch {
            Write-Host "      ⚠️  Managed Identity unavailable — falling back to interactive" -ForegroundColor Yellow
            Connect-AzAccount -ErrorAction Stop | Out-Null
        }
    }

    Write-Host "   🔓 Retrieving secret '$CertName' from Key Vault '$VaultName'..." -ForegroundColor Gray
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

    $certBytes  = [Convert]::FromBase64String($kvSecret)
    $certObject = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
        $certBytes,
        [string]::Empty,
        [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet
    )

    Write-Host "   ✅ Certificate loaded: $($certObject.Subject)" -ForegroundColor Green
    Write-Host "      Thumbprint : $($certObject.Thumbprint)" -ForegroundColor Gray
    Write-Host "      Expires    : $($certObject.NotAfter.ToString('yyyy-MM-dd'))" -ForegroundColor Gray

    $daysLeft = ($certObject.NotAfter - (Get-Date)).Days
    if ($daysLeft -lt 30) {
        Write-Warning "Certificate expires in $daysLeft day(s)! Rotate before: $($certObject.NotAfter.ToString('yyyy-MM-dd'))"
    }

    return $certObject
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
    } elseif ($UseKeyVault) {
        # Connect using ephemeral cert from Azure Key Vault (Managed Identity)
        if (-not $config.KeyVaultName -or -not $config.KeyVaultCertName) {
            Write-Host "   ❌ app-config.json is missing 'KeyVaultName' and/or 'KeyVaultCertName'" -ForegroundColor Red
            Write-Host "      Add these fields and retry with -UseKeyVault" -ForegroundColor Yellow
            exit 1
        }
        Write-Host "   Key Vault : $($config.KeyVaultName)" -ForegroundColor Gray
        Write-Host "   Cert name : $($config.KeyVaultCertName)" -ForegroundColor Gray

        $kvCert = Get-CertFromKeyVault -VaultName $config.KeyVaultName -CertName $config.KeyVaultCertName

        Connect-IPPSSession `
            -Certificate  $kvCert `
            -AppID        $config.AppId `
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
    if ($UseKeyVault) {
        Write-Host "   5. Verify Managed Identity has 'Key Vault Secrets User' on '$($config.KeyVaultName)'" -ForegroundColor White
        Write-Host "   6. Confirm the cert is stored as a Secret (PFX/base64) not just a Certificate object" -ForegroundColor White
    }
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
