# App Registration Setup Guide

This guide covers setting up Azure AD App Registration with certificate-based authentication for unattended SIT migration automation.

## 📋 Why App-Only Authentication?

**Traditional User Authentication:**
- ❌ Requires interactive login with username/password
- ❌ Subject to MFA prompts
- ❌ Cannot be automated securely
- ❌ Credentials stored in scripts (security risk)

**App-Only Authentication (Certificate-Based):**
- ✅ Fully automated, no user interaction
- ✅ No passwords stored in scripts
- ✅ Certificate-based authentication (more secure)
- ✅ Perfect for CI/CD pipelines and scheduled tasks
- ✅ Granular permissions via Azure AD roles

---

## 🚀 Quick Start

### Option 1: Automated Setup (Recommended)

Run the setup script with your organization domain:

```powershell
.\00-Setup-AppRegistration.ps1 -Organization "contoso.onmicrosoft.com"
```

This will:
1. ✅ Create a self-signed certificate
2. ✅ Register the app in Azure AD
3. ✅ Assign Exchange.ManageAsApp permission
4. ✅ Grant admin consent
5. ✅ Assign Compliance Administrator role
6. ✅ Save configuration for later use

Then test the connection:

```powershell
.\00a-Test-AppConnection.ps1
```

### Option 2: Manual Setup via Azure Portal

If you prefer manual setup or need to understand the process, follow the [detailed manual steps](#manual-setup-steps) below.

---

## 📦 Prerequisites

### 1. Permissions Required

You need **one of these roles** in Azure AD:
- Global Administrator
- Application Administrator
- Cloud Application Administrator

### 2. PowerShell Modules

The setup script will automatically install required modules:
- `Microsoft.Graph.Authentication` (v2.0.0+)
- `Microsoft.Graph.Applications` (v2.0.0+)
- `Microsoft.Graph.Identity.DirectoryManagement` (v2.0.0+)

To install manually:

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser -Force
```

### 3. Organization Domain

You need your tenant's primary `.onmicrosoft.com` domain:
- Example: `contoso.onmicrosoft.com`
- Find it in Azure Portal → Azure Active Directory → Overview

---

## 🔧 Configuration Options

### Custom App Name

```powershell
.\00-Setup-AppRegistration.ps1 `
    -AppName "My-Custom-SIT-App" `
    -Organization "contoso.onmicrosoft.com"
```

### Extended Certificate Validity

```powershell
.\00-Setup-AppRegistration.ps1 `
    -Organization "contoso.onmicrosoft.com" `
    -CertificateYears 2
```

### Different Directory Role

```powershell
.\00-Setup-AppRegistration.ps1 `
    -Organization "contoso.onmicrosoft.com" `
    -AssignRole "Security Administrator"
```

Available roles:
- `Compliance Administrator` (default, recommended)
- `Compliance Data Administrator`
- `Security Administrator`
- `Global Administrator` (not recommended - too broad)

---

## 📂 Files Created

After running the setup script, you'll have:

| File | Description | Security |
|------|-------------|----------|
| `mycert.cer` | Public certificate | ✅ Safe to share |
| `mycert.pfx` | Private certificate | ⚠️ **KEEP SECURE** |
| `app-config.json` | Connection details | ⚠️ Contains IDs (no secrets) |

### Example `app-config.json`:

```json
{
    "AppName": "Purview-SIT-Migration-App",
    "AppId": "12345678-1234-1234-1234-123456789abc",
    "TenantId": "87654321-4321-4321-4321-cba987654321",
    "Organization": "contoso.onmicrosoft.com",
    "CertificateThumbprint": "ABC123DEF456...",
    "CertificatePath": "C:\\Git\\AZ\\purview-sit-migration-script\\mycert.pfx",
    "CerPath": "C:\\Git\\AZ\\purview-sit-migration-script\\mycert.cer",
    "AssignedRole": "Compliance Administrator",
    "CreatedDate": "2026-02-03 14:30:00",
    "ExpiryDate": "2027-02-03 14:30:00"
}
```

---

## 🔐 Security Best Practices

### 1. Protect the Private Key

The `.pfx` file contains the private key. Protect it:

```powershell
# Set restrictive permissions (Windows)
$acl = Get-Acl "mycert.pfx"
$acl.SetAccessRuleProtection($true, $false)
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    [System.Security.Principal.WindowsIdentity]::GetCurrent().Name,
    "FullControl",
    "Allow"
)
$acl.SetAccessRule($rule)
Set-Acl "mycert.pfx" $acl
```

### 2. Store Certificate Password Securely

**For production automation:**

Use Azure Key Vault:

```powershell
# Store in Key Vault
$secretValue = ConvertTo-SecureString "YourCertPassword" -AsPlainText -Force
Set-AzKeyVaultSecret -VaultName "your-keyvault" -Name "SITMigrationCertPassword" -SecretValue $secretValue

# Retrieve in automation script
$certPassword = Get-AzKeyVaultSecret -VaultName "your-keyvault" -Name "SITMigrationCertPassword" -AsPlainText
```

### 3. Certificate Rotation

Certificates expire! Set a reminder to rotate before expiry:

```powershell
# Check certificate expiry
$config = Get-Content "app-config.json" | ConvertFrom-Json
$expiryDate = [datetime]$config.ExpiryDate

$daysUntilExpiry = ($expiryDate - (Get-Date)).Days
Write-Host "Certificate expires in $daysUntilExpiry days"

if ($daysUntilExpiry -lt 30) {
    Write-Warning "Certificate expiring soon! Rotate before: $expiryDate"
}
```

### 4. Least Privilege

Use the minimum required role:
- ✅ **Compliance Administrator** - Can manage SITs (recommended)
- ❌ **Global Administrator** - Too broad, avoid if possible

### 5. Monitor App Usage

Regularly review app sign-in logs in Azure AD:
1. Azure Portal → Azure Active Directory
2. Enterprise Applications → Your app
3. Sign-in logs

---

## 🔗 Using the App Registration

### Connect with Thumbprint (Recommended)

```powershell
# Certificate must be installed in CurrentUser\My store
Connect-IPPSSession `
    -CertificateThumbPrint "ABC123DEF456..." `
    -AppID "12345678-1234-1234-1234-123456789abc" `
    -Organization "contoso.onmicrosoft.com"
```

### Connect with Certificate File

```powershell
# For automation servers where cert isn't installed
$certPassword = Get-Secret -Name "CertPassword" # From secure vault
Connect-IPPSSession `
    -CertificateFilePath "C:\certs\mycert.pfx" `
    -CertificatePassword $certPassword `
    -AppID "12345678-1234-1234-1234-123456789abc" `
    -Organization "contoso.onmicrosoft.com"
```

### Connect with Certificate Object

```powershell
# For advanced scenarios (e.g., cert from Azure Key Vault)
$cert = Get-AzKeyVaultCertificate -VaultName "vault" -Name "cert"
Connect-IPPSSession `
    -Certificate $cert `
    -AppID "12345678-1234-1234-1234-123456789abc" `
    -Organization "contoso.onmicrosoft.com"
```

---

## 🧪 Testing Your Setup

### Test 1: Basic Connection

```powershell
.\00a-Test-AppConnection.ps1
```

Expected output:
```
✅ Connection successful!
✅ Successfully retrieved: Credit Card Number
✅ Found X custom SIT(s)
```

### Test 2: Manual Commands

```powershell
# Connect
Connect-IPPSSession -CertificateThumbPrint "..." -AppID "..." -Organization "..."

# Test command
Get-DlpSensitiveInformationType -Identity "Credit Card Number"

# Disconnect
Disconnect-ExchangeOnline -Confirm:$false
```

---

## 🐛 Troubleshooting

### Error: "AADSTS700016: Application not found"

**Cause:** App ID incorrect or app doesn't exist

**Solution:**
```powershell
# Verify app exists
Connect-MgGraph -Scopes "Application.Read.All"
Get-MgApplication -Filter "displayName eq 'Purview-SIT-Migration-App'"
```

### Error: "AADSTS700027: Client assertion failed signature validation"

**Cause:** Certificate issue (wrong cert, expired, or CNG cert)

**Solution:**
```powershell
# Check certificate
$cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Thumbprint -eq "ABC123..." }
Write-Host "Valid From: $($cert.NotBefore)"
Write-Host "Valid To: $($cert.NotAfter)"
Write-Host "Has Private Key: $($cert.HasPrivateKey)"

# Verify it's CSP not CNG
$cert.PrivateKey.GetType().Name # Should be "RSACryptoServiceProvider" not "CNG"
```

### Error: "Insufficient privileges to complete the operation"

**Cause:** App doesn't have required permissions or role

**Solution:**
1. Azure Portal → App registrations → Your app
2. API Permissions → Verify Exchange.ManageAsApp is granted
3. Roles and administrators → Verify Compliance Administrator assigned

### Connection Succeeds but Commands Fail

**Cause:** Role assignment propagation delay

**Solution:** Wait 10-15 minutes after setup, then try again

### Certificate Not Found

**Cause:** Thumbprint connection requires cert in certificate store

**Solution:** Use `.pfx` file method instead:
```powershell
.\00a-Test-AppConnection.ps1 -UsePfxFile
```

---

## 🔄 Updating/Rotating Certificates

### When to Rotate

- Certificate expiring (< 30 days)
- Security breach suspected
- Regular policy (e.g., annual rotation)

### Rotation Process

1. **Generate new certificate:**

```powershell
$newCert = New-SelfSignedCertificate `
    -Subject "CN=Purview-SIT-Migration-App" `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -KeyExportPolicy Exportable `
    -KeySpec Signature `
    -KeyLength 2048 `
    -KeyAlgorithm RSA `
    -HashAlgorithm SHA256 `
    -NotAfter (Get-Date).AddYears(1) `
    -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider"

Export-Certificate -Cert $newCert -FilePath "mycert-new.cer"
```

2. **Upload to existing app:**

```powershell
Connect-MgGraph -Scopes "Application.ReadWrite.All"

$config = Get-Content "app-config.json" | ConvertFrom-Json
$app = Get-MgApplication -Filter "appId eq '$($config.AppId)'"

$certData = Get-Content "mycert-new.cer" -AsByteStream -Raw
$certBase64 = [System.Convert]::ToBase64String($certData)

$keyCredential = @{
    Type = "AsymmetricX509Cert"
    Usage = "Verify"
    Key = [System.Convert]::FromBase64String($certBase64)
}

# Adds new cert (keeps old one for rollback)
Update-MgApplication -ApplicationId $app.Id -KeyCredentials @($keyCredential)
```

3. **Test new certificate**

4. **Remove old certificate** from app after verification

---

## 📖 Additional Resources

### Microsoft Documentation
- [App-only authentication for Exchange Online PowerShell](https://learn.microsoft.com/en-us/powershell/exchange/app-only-auth-powershell-v2?view=exchange-ps)
- [Connect to Security & Compliance PowerShell](https://learn.microsoft.com/en-us/powershell/exchange/connect-to-scc-powershell?view=exchange-ps)
- [Exchange Online PowerShell V3 module](https://learn.microsoft.com/en-us/powershell/exchange/exchange-online-powershell-v2?view=exchange-ps)

### Microsoft Graph
- [Application and service principal objects](https://learn.microsoft.com/en-us/entra/identity-platform/app-objects-and-service-principals)
- [Permissions required for app registration](https://learn.microsoft.com/en-us/entra/identity-platform/howto-create-service-principal-portal#permissions-required-for-registering-an-app)

---

## 🏢 Enterprise Scenarios

### Multi-Tenant Migrations

For CSP/Partner scenarios migrating multiple customer tenants:

1. Create **one app per customer tenant**
2. Use GDAP (Granular Delegated Admin Privileges)
3. Store certificates in Azure Key Vault per customer

```powershell
# Example: Connect to customer tenant
$customer = "customer-contoso"
$certPassword = Get-AzKeyVaultSecret -VaultName "MyVault" -Name "$customer-cert-password"
$certPath = "C:\certs\$customer-cert.pfx"

Connect-IPPSSession `
    -CertificateFilePath $certPath `
    -CertificatePassword $certPassword `
    -AppID (Get-Secret "$customer-appid") `
    -Organization "$customer.onmicrosoft.com"
```

### CI/CD Pipeline Integration

Azure DevOps / GitHub Actions example:

```yaml
# Azure Pipeline
steps:
- task: AzureKeyVault@2
  inputs:
    azureSubscription: 'MySubscription'
    KeyVaultName: 'my-keyvault'
    SecretsFilter: 'SITMigrationCert,AppId,Organization'

- pwsh: |
    Connect-IPPSSession `
      -CertificateThumbPrint $(SITMigrationCert) `
      -AppID $(AppId) `
      -Organization $(Organization)
    
    # Run migration scripts
    .\03-Export-Custom-SITs.ps1
```

### Scheduled Task (Windows)

```powershell
# Create scheduled task
$action = New-ScheduledTaskAction `
    -Execute 'pwsh.exe' `
    -Argument '-File "C:\Scripts\SIT-Migration.ps1"'

$trigger = New-ScheduledTaskTrigger -Daily -At "2:00AM"

$principal = New-ScheduledTaskPrincipal `
    -UserId "SYSTEM" `
    -LogonType ServiceAccount

Register-ScheduledTask `
    -TaskName "SIT Migration" `
    -Action $action `
    -Trigger $trigger `
    -Principal $principal
```

---

## ❓ FAQ

**Q: Can I use the same app for source and target tenants?**

A: No. Each tenant needs its own app registration. You'll create one app in the source tenant and another in the target tenant.

**Q: How do I delete the app registration?**

A: 
```powershell
Connect-MgGraph -Scopes "Application.ReadWrite.All"
$app = Get-MgApplication -Filter "displayName eq 'Purview-SIT-Migration-App'"
Remove-MgApplication -ApplicationId $app.Id
```

**Q: Can I use a certificate from a Certificate Authority (CA)?**

A: Yes! Self-signed certificates are for testing. In production, use a CA-issued certificate:
1. Request certificate from your CA
2. Export as .pfx with private key
3. Upload .cer to app registration

**Q: What if I lose the certificate?**

A: Generate a new certificate and upload it to the existing app registration (rotation process above). The old certificate will stop working.

**Q: Can I use client secrets instead of certificates?**

A: Yes, but **not recommended** for security reasons. Certificates are more secure and preferred by Microsoft for production automation.

---

## 📞 Support

For issues:
1. Check [Troubleshooting](#-troubleshooting) section
2. Review Azure AD sign-in logs
3. Verify all prerequisites are met
4. Ensure sufficient permissions

---

**Last Updated:** February 2026
