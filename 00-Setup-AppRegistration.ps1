<#
.SYNOPSIS
    Setup Azure App Registration for SIT Migration Automation

.DESCRIPTION
    Creates an Azure AD App Registration with certificate-based authentication
    for unattended Security & Compliance PowerShell operations.
    
    This script performs:
    1. Creates self-signed certificate for authentication
    2. Registers application in Microsoft Entra ID
    3. Assigns Office 365 Exchange Online API permissions (Exchange.ManageAsApp)
    4. Grants admin consent
    5. Assigns Compliance Administrator role to the application
    6. Exports configuration for use in migration scripts

.PARAMETER AppName
    Name for the Azure AD application registration (default: "Purview-SIT-Migration-App")

.PARAMETER CertificateYears
    Number of years the certificate is valid (default: 1)

.PARAMETER Organization
    Your tenant's primary domain (e.g., "contoso.onmicrosoft.com")
    Required for connecting with app-only authentication

.PARAMETER AssignRole
    Microsoft Entra role to assign to the application
    Default: "Compliance Administrator"
    Options: "Compliance Administrator", "Compliance Data Administrator", "Global Administrator", "Security Administrator"

.EXAMPLE
    .\00-Setup-AppRegistration.ps1 -Organization "contoso.onmicrosoft.com"
    
    Creates app registration with default settings for the specified organization

.EXAMPLE
    .\00-Setup-AppRegistration.ps1 -AppName "My-SIT-App" -Organization "contoso.onmicrosoft.com" -CertificateYears 2
    
    Creates app registration with custom name and 2-year certificate

.NOTES
    Requirements:
    - Microsoft.Graph PowerShell module
    - Global Administrator or Application Administrator role
    - Permission to create app registrations in Entra ID
    
    Output:
    - Certificate files: mycert.pfx and mycert.cer (in script directory)
    - Configuration file: app-config.json (contains connection details)

.LINK
    https://learn.microsoft.com/en-us/powershell/exchange/app-only-auth-powershell-v2
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$AppName = "Purview-SIT-Migration-App",

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 10)]
    [int]$CertificateYears = 1,

    [Parameter(Mandatory = $true)]
    [string]$Organization,

    [Parameter(Mandatory = $false)]
    [ValidateSet(
        "Compliance Administrator",
        "Compliance Data Administrator",
        "Global Administrator",
        "Security Administrator"
    )]
    [string]$AssignRole = "Compliance Administrator"
)

$ErrorActionPreference = "Stop"
$ScriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  Azure App Registration Setup for SIT Migration              ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

#region Check and Install Required Modules
Write-Host "📦 Checking required PowerShell modules..." -ForegroundColor Yellow

$requiredModules = @(
    @{ Name = "Microsoft.Graph.Authentication"; MinVersion = "2.0.0" }
    @{ Name = "Microsoft.Graph.Applications"; MinVersion = "2.0.0" }
    @{ Name = "Microsoft.Graph.Identity.DirectoryManagement"; MinVersion = "2.0.0" }
)

foreach ($module in $requiredModules) {
    $installed = Get-Module -ListAvailable -Name $module.Name | 
        Where-Object { $_.Version -ge [Version]$module.MinVersion }
    
    if (-not $installed) {
        Write-Host "   Installing $($module.Name)..." -ForegroundColor Yellow
        Install-Module -Name $module.Name -Scope CurrentUser -Force -AllowClobber -MinimumVersion $module.MinVersion
        Write-Host "   ✅ $($module.Name) installed" -ForegroundColor Green
    } else {
        Write-Host "   ✅ $($module.Name) already installed" -ForegroundColor Green
    }
}
Write-Host ""
#endregion

#region Step 1: Generate Self-Signed Certificate
Write-Host "🔐 Step 1: Generating self-signed certificate..." -ForegroundColor Cyan
Write-Host "   Certificate will be valid for $CertificateYears year(s)" -ForegroundColor Gray

$certPath = Join-Path $ScriptPath "mycert"
$cerFile = "$certPath.cer"
$pfxFile = "$certPath.pfx"

try {
    # Create certificate with SHA256 (CSP key provider, not CNG)
    $cert = New-SelfSignedCertificate `
        -Subject "CN=$AppName" `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -KeyExportPolicy Exportable `
        -KeySpec Signature `
        -KeyLength 2048 `
        -KeyAlgorithm RSA `
        -HashAlgorithm SHA256 `
        -NotAfter (Get-Date).AddYears($CertificateYears) `
        -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider"

    Write-Host "   ✅ Certificate created" -ForegroundColor Green
    Write-Host "      Thumbprint: $($cert.Thumbprint)" -ForegroundColor Gray

    # Export certificate to .cer file (public key)
    Export-Certificate -Cert $cert -FilePath $cerFile -Force | Out-Null
    Write-Host "   ✅ Public certificate exported: $cerFile" -ForegroundColor Green

    # Get password for .pfx file (private key)
    Write-Host ""
    Write-Host "   📝 Enter password to protect the private key (.pfx file):" -ForegroundColor Yellow
    $certPassword = Read-Host -AsSecureString -Prompt "      Password"
    
    # Export certificate to .pfx file (private key)
    Export-PfxCertificate -Cert $cert -FilePath $pfxFile -Password $certPassword -Force | Out-Null
    Write-Host "   ✅ Private certificate exported: $pfxFile" -ForegroundColor Green
    Write-Host "   ⚠️  Keep the .pfx file and password secure!" -ForegroundColor Yellow
    Write-Host ""

} catch {
    Write-Host "   ❌ Failed to create certificate: $_" -ForegroundColor Red
    exit 1
}
#endregion

#region Step 2: Connect to Microsoft Graph
Write-Host "🔗 Step 2: Connecting to Microsoft Graph..." -ForegroundColor Cyan

try {
    # Connect with required permissions
    Connect-MgGraph -Scopes @(
        "Application.ReadWrite.All",
        "AppRoleAssignment.ReadWrite.All",
        "RoleManagement.ReadWrite.Directory"
    ) -NoWelcome

    $context = Get-MgContext
    Write-Host "   ✅ Connected to tenant: $($context.TenantId)" -ForegroundColor Green
    Write-Host "   👤 Signed in as: $($context.Account)" -ForegroundColor Gray
    Write-Host ""

} catch {
    Write-Host "   ❌ Failed to connect to Microsoft Graph: $_" -ForegroundColor Red
    exit 1
}
#endregion

#region Step 3: Register Application in Entra ID
Write-Host "📝 Step 3: Registering application in Microsoft Entra ID..." -ForegroundColor Cyan

try {
    # Check if app already exists
    $existingApp = Get-MgApplication -Filter "displayName eq '$AppName'" -ErrorAction SilentlyContinue

    if ($existingApp) {
        Write-Host "   ⚠️  Application '$AppName' already exists" -ForegroundColor Yellow
        Write-Host "   Do you want to update it? (Y/N): " -NoNewline -ForegroundColor Yellow
        $response = Read-Host
        
        if ($response -ne 'Y') {
            Write-Host "   ❌ Operation cancelled by user" -ForegroundColor Red
            exit 1
        }
        
        $app = $existingApp
        Write-Host "   ✅ Using existing application" -ForegroundColor Green
    } else {
        # Create new application
        $app = New-MgApplication -DisplayName $AppName -SignInAudience "AzureADMyOrg"
        Write-Host "   ✅ Application registered: $AppName" -ForegroundColor Green
    }

    Write-Host "      Application ID: $($app.AppId)" -ForegroundColor Gray
    Write-Host "      Object ID: $($app.Id)" -ForegroundColor Gray
    Write-Host ""

} catch {
    Write-Host "   ❌ Failed to register application: $_" -ForegroundColor Red
    Disconnect-MgGraph
    exit 1
}
#endregion

#region Step 4: Upload Certificate to Application
Write-Host "📤 Step 4: Uploading certificate to application..." -ForegroundColor Cyan

try {
    # Read certificate file
    $certData = Get-Content $cerFile -AsByteStream -Raw
    $certBase64 = [System.Convert]::ToBase64String($certData)

    # Create key credential
    $keyCredential = @{
        Type = "AsymmetricX509Cert"
        Usage = "Verify"
        Key = [System.Convert]::FromBase64String($certBase64)
    }

    # Update application with certificate
    Update-MgApplication -ApplicationId $app.Id -KeyCredentials @($keyCredential)
    
    Write-Host "   ✅ Certificate attached to application" -ForegroundColor Green
    Write-Host ""

} catch {
    Write-Host "   ❌ Failed to upload certificate: $_" -ForegroundColor Red
    Disconnect-MgGraph
    exit 1
}
#endregion

#region Step 5: Assign API Permissions
Write-Host "🔑 Step 5: Assigning API permissions..." -ForegroundColor Cyan

try {
    # Office 365 Exchange Online API
    $exchangeResourceId = "00000002-0000-0ff1-ce00-000000000000"
    $exchangeManageAsAppPermissionId = "dc50a0fb-09a3-484d-be87-e023b12c6440"

    # Get current permissions
    $currentPermissions = (Get-MgApplication -ApplicationId $app.Id).RequiredResourceAccess

    # Check if permission already exists
    $exchangePermission = $currentPermissions | Where-Object { $_.ResourceAppId -eq $exchangeResourceId }

    if (-not $exchangePermission) {
        # Add Exchange.ManageAsApp permission
        $requiredResourceAccess = @{
            ResourceAppId = $exchangeResourceId
            ResourceAccess = @(
                @{
                    Id = $exchangeManageAsAppPermissionId
                    Type = "Role"
                }
            )
        }

        $allPermissions = @($requiredResourceAccess)
        if ($currentPermissions) {
            $allPermissions += $currentPermissions
        }

        Update-MgApplication -ApplicationId $app.Id -RequiredResourceAccess $allPermissions
        Write-Host "   ✅ Office 365 Exchange Online API permission added" -ForegroundColor Green
    } else {
        Write-Host "   ✅ Exchange.ManageAsApp permission already exists" -ForegroundColor Green
    }

    # Grant admin consent
    Write-Host "   ⏳ Waiting for permission to propagate..." -ForegroundColor Gray
    Start-Sleep -Seconds 10

    # Get service principal for the app
    $servicePrincipal = Get-MgServicePrincipal -Filter "appId eq '$($app.AppId)'" -ErrorAction SilentlyContinue
    
    if (-not $servicePrincipal) {
        # Create service principal if it doesn't exist
        $servicePrincipal = New-MgServicePrincipal -AppId $app.AppId
        Write-Host "   ✅ Service principal created" -ForegroundColor Green
    }

    # Get Exchange Online service principal
    $exchangeSP = Get-MgServicePrincipal -Filter "appId eq '$exchangeResourceId'"

    # Grant admin consent
    $grant = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $servicePrincipal.Id |
        Where-Object { $_.AppRoleId -eq $exchangeManageAsAppPermissionId }

    if (-not $grant) {
        New-MgServicePrincipalAppRoleAssignment `
            -ServicePrincipalId $servicePrincipal.Id `
            -PrincipalId $servicePrincipal.Id `
            -ResourceId $exchangeSP.Id `
            -AppRoleId $exchangeManageAsAppPermissionId | Out-Null
        
        Write-Host "   ✅ Admin consent granted for Exchange.ManageAsApp" -ForegroundColor Green
    } else {
        Write-Host "   ✅ Admin consent already granted" -ForegroundColor Green
    }

    Write-Host ""

} catch {
    Write-Host "   ❌ Failed to assign API permissions: $_" -ForegroundColor Red
    Write-Host "   ⚠️  You may need to grant admin consent manually in the Azure Portal" -ForegroundColor Yellow
    Write-Host ""
}
#endregion

#region Step 6: Assign Directory Role
Write-Host "👥 Step 6: Assigning directory role to application..." -ForegroundColor Cyan

try {
    # Map role name to role template ID
    $roleMapping = @{
        "Compliance Administrator" = "17315797-102d-40b4-93e0-432062caca18"
        "Compliance Data Administrator" = "e6d1a23a-da11-4be4-9570-befc86d067a7"
        "Global Administrator" = "62e90394-69f5-4237-9190-012177145e10"
        "Security Administrator" = "194ae4cb-b126-40b2-bd5b-6091b380977d"
    }

    $roleTemplateId = $roleMapping[$AssignRole]

    # Get the directory role
    $directoryRole = Get-MgDirectoryRole -Filter "roleTemplateId eq '$roleTemplateId'" -ErrorAction SilentlyContinue

    if (-not $directoryRole) {
        # Activate the role if not already activated
        $directoryRole = New-MgDirectoryRole -RoleTemplateId $roleTemplateId
        Write-Host "   ✅ Directory role activated: $AssignRole" -ForegroundColor Green
    }

    # Check if already assigned
    $existingAssignment = Get-MgDirectoryRoleMember -DirectoryRoleId $directoryRole.Id |
        Where-Object { $_.Id -eq $servicePrincipal.Id }

    if (-not $existingAssignment) {
        # Assign the role to the service principal
        New-MgDirectoryRoleMemberByRef -DirectoryRoleId $directoryRole.Id `
            -OdataId "https://graph.microsoft.com/v1.0/servicePrincipals/$($servicePrincipal.Id)" | Out-Null
        
        Write-Host "   ✅ Role assigned: $AssignRole" -ForegroundColor Green
    } else {
        Write-Host "   ✅ Role already assigned: $AssignRole" -ForegroundColor Green
    }

    Write-Host ""

} catch {
    Write-Host "   ❌ Failed to assign directory role: $_" -ForegroundColor Red
    Write-Host "   ⚠️  You may need to assign the role manually in the Azure Portal" -ForegroundColor Yellow
    Write-Host ""
}
#endregion

#region Step 7: Save Configuration
Write-Host "💾 Step 7: Saving configuration..." -ForegroundColor Cyan

try {
    $configPath = Join-Path $ScriptPath "app-config.json"
    
    $config = @{
        AppName = $AppName
        AppId = $app.AppId
        TenantId = $context.TenantId
        Organization = $Organization
        CertificateThumbprint = $cert.Thumbprint
        CertificatePath = $pfxFile
        CerPath = $cerFile
        AssignedRole = $AssignRole
        CreatedDate = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        ExpiryDate = $cert.NotAfter.ToString("yyyy-MM-dd HH:mm:ss")
    }

    $config | ConvertTo-Json -Depth 10 | Out-File -FilePath $configPath -Encoding UTF8
    
    Write-Host "   ✅ Configuration saved: $configPath" -ForegroundColor Green
    Write-Host ""

} catch {
    Write-Host "   ⚠️  Failed to save configuration: $_" -ForegroundColor Yellow
    Write-Host ""
}
#endregion

#region Disconnect
Disconnect-MgGraph | Out-Null
#endregion

#region Display Summary
Write-Host "╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║  ✅ Setup Complete!                                           ║" -ForegroundColor Green
Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "📋 Summary:" -ForegroundColor Cyan
Write-Host "   Application Name:        $AppName" -ForegroundColor White
Write-Host "   Application ID:          $($app.AppId)" -ForegroundColor White
Write-Host "   Tenant ID:               $($context.TenantId)" -ForegroundColor White
Write-Host "   Organization:            $Organization" -ForegroundColor White
Write-Host "   Certificate Thumbprint:  $($cert.Thumbprint)" -ForegroundColor White
Write-Host "   Directory Role:          $AssignRole" -ForegroundColor White
Write-Host ""
Write-Host "📂 Files Created:" -ForegroundColor Cyan
Write-Host "   Certificate (Public):    $cerFile" -ForegroundColor White
Write-Host "   Certificate (Private):   $pfxFile" -ForegroundColor White
Write-Host "   Configuration:           $configPath" -ForegroundColor White
Write-Host ""
Write-Host "🔗 Next Steps:" -ForegroundColor Yellow
Write-Host "   1. Test connection with certificate:" -ForegroundColor White
Write-Host "      Connect-IPPSSession -CertificateThumbPrint `"$($cert.Thumbprint)`" ``" -ForegroundColor Gray
Write-Host "          -AppID `"$($app.AppId)`" ``" -ForegroundColor Gray
Write-Host "          -Organization `"$Organization`"" -ForegroundColor Gray
Write-Host ""
Write-Host "   2. Update your automation scripts to use app-only authentication" -ForegroundColor White
Write-Host ""
Write-Host "⚠️  Important Security Notes:" -ForegroundColor Yellow
Write-Host "   • Keep the .pfx file secure (contains private key)" -ForegroundColor White
Write-Host "   • Store the certificate password in a secure vault (Azure Key Vault)" -ForegroundColor White
Write-Host "   • Do not commit certificates or passwords to source control" -ForegroundColor White
Write-Host "   • Review app permissions periodically" -ForegroundColor White
Write-Host ""
#endregion
