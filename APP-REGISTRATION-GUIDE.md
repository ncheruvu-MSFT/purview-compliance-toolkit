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

### Option 3: Managed Identity + Azure Key Vault (Recommended for Azure VMs)

For scripts running **on an Azure VM, Azure Automation, or any Azure-hosted compute**, use a System-Assigned Managed Identity to pull the certificate from Key Vault. No credentials are ever stored locally.

**One-time Key Vault setup:**

```powershell
# 1. Enable system-assigned managed identity on your VM
az vm identity assign --name <vm-name> --resource-group <rg-name>

# 2. Create Key Vault and upload certificate
az keyvault create --name "kv-purview-tools" --resource-group <rg-name> --location eastus

# Upload the PFX created by 00-Setup-AppRegistration.ps1
az keyvault certificate import \
  --vault-name "kv-purview-tools" \
  --name "purview-source-cert" \
  --file "mycert-source.pfx"

# 3. Grant Managed Identity access (Key Vault Secrets User)
$miPrincipalId = az vm show --name <vm-name> --resource-group <rg-name> \
  --query identity.principalId -o tsv

az role assignment create \
  --role "Key Vault Secrets User" \
  --assignee $miPrincipalId \
  --scope $(az keyvault show --name kv-purview-tools --query id -o tsv)
```

**Add Key Vault details to your `app-config.json`:**

```json
{
    "AppId": "12345678-1234-1234-1234-123456789abc",
    "Organization": "contoso.onmicrosoft.com",
    "KeyVaultName": "kv-purview-tools",
    "KeyVaultCertName": "purview-source-cert"
}
```

**Connect using the `-UseKeyVault` flag:**

```powershell
.\01-Connect-Tenant.ps1 -UseKeyVault
# Authenticates to Azure via Managed Identity, pulls cert from KV, connects — no PFX on disk
```

Test it:

```powershell
.\00a-Test-AppConnection.ps1 -UseKeyVault
```

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
    "CertificatePath": "C:\\certs\\mycert.pfx",
    "CerPath": "C:\\certs\\mycert.cer",
    "AssignedRole": "Compliance Administrator",
    "CreatedDate": "2026-02-03 14:30:00",
    "ExpiryDate": "2027-02-03 14:30:00",

    "_comment_kv": "Optional — Key Vault fields for Managed Identity auth (leave blank for local cert mode)",
    "KeyVaultName": "",
    "KeyVaultCertName": ""
}
```

> **Key Vault mode**: when `KeyVaultName` and `KeyVaultCertName` are populated and `-UseKeyVault` is passed, the scripts skip `CertificateThumbprint` / `CertificatePath` entirely. The certificate is loaded ephemerally from Key Vault — it is **never written to disk**.

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

### Connect with Certificate Object (from Azure Key Vault)

> **Note:** `Get-AzKeyVaultCertificate` returns metadata only — it does **not** return the private key.
> To get a usable `X509Certificate2` with private key, retrieve the certificate from the Key Vault **secret** (which stores the full PFX as base64).

```powershell
# Authenticate to Azure — works on VM (Managed Identity), CI/CD (service principal), or locally (interactive)
Connect-AzAccount -Identity -ErrorAction SilentlyContinue   # Managed Identity
# For local dev: Connect-AzAccount

# Retrieve the full PFX (base64) via the Key Vault Secret — this includes the private key
$kvSecret   = Get-AzKeyVaultSecret `
                  -VaultName  "kv-purview-tools" `
                  -Name       "purview-source-cert" `
                  -AsPlainText

# Build an in-memory X509Certificate2 — EphemeralKeySet means private key NEVER touches disk
$certBytes  = [Convert]::FromBase64String($kvSecret)
$certObject = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
    $certBytes,
    [string]::Empty,
    [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet
)

Write-Host "Certificate loaded: $($certObject.Subject) | Expires: $($certObject.NotAfter) | Thumbprint: $($certObject.Thumbprint)"

# Connect to Security & Compliance using the in-memory certificate
Connect-IPPSSession `
    -Certificate  $certObject `
    -AppID        "12345678-1234-1234-1234-123456789abc" `
    -Organization "contoso.onmicrosoft.com" `
    -ShowBanner:$false
```

Or use the built-in wrapper in `-UseKeyVault` mode:

```powershell
.\01-Connect-Tenant.ps1 -UseKeyVault
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

## 🖥️ Azure VM with Managed Identity — Complete Setup

This section covers the end-to-end setup for running Purview toolkit scripts on an **Azure VM using Managed Identity** to authenticate to Key Vault.

### Architecture

```
┌─────────────────────┐        ┌──────────────────────┐        ┌───────────────────────────┐
│  Azure VM           │        │  Azure Key Vault      │        │  Microsoft Purview /      │
│                     │        │                       │        │  Security & Compliance    │
│  System-Assigned  ──┼──RBAC─▶│  purview-source-cert  │        │  PowerShell               │
│  Managed Identity   │        │  (PFX stored as       │        │                           │
│                     │──Gets──▶│   Secret/base64)      │──Cert─▶│  Connect-IPPSSession      │
│  *.ps1 scripts      │        │                       │        │  -Certificate $certObj    │
└─────────────────────┘        └──────────────────────┘        └───────────────────────────┘
      No PFX on disk               No shared keys                   App Registration
      No stored credentials        MI token only                    (Entra ID)
```

### Step 1 — Enable Managed Identity on the VM

```powershell
# Azure CLI
az vm identity assign `
    --name        "vm-purview-automation" `
    --resource-group "rg-purview"

# Capture the Principal ID (needed for RBAC assignment)
$principalId = az vm show `
    --name        "vm-purview-automation" `
    --resource-group "rg-purview" `
    --query identity.principalId -o tsv

Write-Host "Managed Identity Principal ID: $principalId"
```

### Step 2 — Upload Certificate to Key Vault

```powershell
# Import the PFX generated by 00-Setup-AppRegistration.ps1
az keyvault certificate import `
    --vault-name  "kv-purview-tools" `
    --name        "purview-source-cert" `
    --file        ".\mycert-source.pfx"
# Note: if the PFX has a password, add: --password "<pfx-password>"

# Verify it was imported
az keyvault certificate show `
    --vault-name  "kv-purview-tools" `
    --name        "purview-source-cert" `
    --query "{name:name, expires:attributes.expires, thumbprint:x509ThumbprintHex}" -o table
```

### Step 3 — Grant VM Managed Identity Access to Key Vault

```powershell
# Get Key Vault resource ID
$kvId = az keyvault show --name "kv-purview-tools" --query id -o tsv

# Assign Key Vault Secrets User (read-only, least privilege)
az role assignment create `
    --role      "Key Vault Secrets User" `
    --assignee  $principalId `
    --scope     $kvId

# Assign Key Vault Certificate User (to read cert metadata)
az role assignment create `
    --role      "Key Vault Certificate User" `
    --assignee  $principalId `
    --scope     $kvId
```

### Step 4 — Update `app-config.json` on the VM

```json
{
    "AppName":         "Purview-SIT-Migration-App",
    "AppId":           "12345678-1234-1234-1234-123456789abc",
    "TenantId":        "87654321-4321-4321-4321-cba987654321",
    "Organization":    "contoso.onmicrosoft.com",
    "KeyVaultName":    "kv-purview-tools",
    "KeyVaultCertName":"purview-source-cert"
}
```

> The `CertificateThumbprint` and `CertificatePath` fields are **not needed** in Key Vault mode — the scripts derive the thumbprint from the loaded certificate object.

### Step 5 — Connect and Test

```powershell
# On the VM — Managed Identity authenticates automatically
.\01-Connect-Tenant.ps1 -UseKeyVault -TenantType Source

# Validate
.\00a-Test-AppConnection.ps1 -UseKeyVault
```

### Troubleshooting Key Vault Access

```powershell
# Verify Managed Identity can reach Key Vault (run on the VM)
Connect-AzAccount -Identity
$secret = Get-AzKeyVaultSecret -VaultName "kv-purview-tools" -Name "purview-source-cert" -AsPlainText
if ($secret) { Write-Host "✅ Key Vault access works" } else { Write-Host "❌ Access denied — check RBAC" }

# Check role assignments on the KV
az role assignment list --scope $(az keyvault show --name kv-purview-tools --query id -o tsv) -o table
```

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

**Last Updated:** March 2026  
**Added:** Managed Identity + Azure Key Vault authentication option (Option 3) for Azure VM scenarios
