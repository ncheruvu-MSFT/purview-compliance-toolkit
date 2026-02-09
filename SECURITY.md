# 🔒 Security Guidelines

## ⚠️ CRITICAL - Files That Must NEVER Be Committed

This repository contains scripts that generate and use sensitive files. **These files must NEVER be committed to source control:**

### 🚨 High Risk Files

| File Type | Pattern | Risk | Protected By |
|-----------|---------|------|--------------|
| **Private Certificates** | `*.pfx`, `*.p12`, `mycert.pfx` | **CRITICAL** - Contains private keys that authenticate your app | `.gitignore` |
| **Certificate Files** | `*.cer`, `*.crt`, `*.pem` | **HIGH** - Public certs can reveal your tenant config | `.gitignore` |
| **Config Files** | `app-config.json`, `*-config.json` | **MEDIUM** - Contains App IDs and tenant info | `.gitignore` |
| **Export Data** | `exports/*.xml` | **HIGH** - Contains custom SIT patterns and rules | `.gitignore` |
| **Credentials** | `*password*`, `*secret*`, `*.cred` | **CRITICAL** - Any stored credentials | `.gitignore` |
| **Logs** | `*.log`, `migration-log-*.log` | **MEDIUM** - May contain sensitive operation details | `.gitignore` |

---

## ✅ Pre-Commit Security Checklist

Before committing any changes, verify:

```powershell
# Check for any sensitive files that might be staged
git status

# View what will be committed
git diff --cached

# Ensure .gitignore is working
git check-ignore -v mycert.pfx app-config.json exports/*.xml

# Should output the .gitignore rules for each file
```

---

## 🛡️ Security Best Practices

### 1. Certificate Management

**DO:**
- ✅ Store `.pfx` files in secure locations (Azure Key Vault, on-premises secure storage)
- ✅ Use strong passwords for certificate private keys
- ✅ Set restrictive file permissions on certificate files
- ✅ Rotate certificates annually or per security policy
- ✅ Delete certificates from disk after importing to certificate store

**DON'T:**
- ❌ Commit certificates to git (even private repos)
- ❌ Store certificates in shared folders
- ❌ Email certificates
- ❌ Store certificate passwords in plain text
- ❌ Use self-signed certs in production (use CA-issued)

### 2. Configuration Files

**DO:**
- ✅ Use separate config files per environment (source-app-config.json, target-app-config.json)
- ✅ Store configs outside the repo in production
- ✅ Use environment variables for sensitive values
- ✅ Document required config structure (without actual values)

**DON'T:**
- ❌ Commit any `*-config.json` files
- ❌ Share configs via unsecured channels
- ❌ Include production credentials in config files

### 3. Export Data

**DO:**
- ✅ Treat export XML files as sensitive (they contain custom patterns)
- ✅ Delete exports after successful import
- ✅ Encrypt exports if storing long-term
- ✅ Restrict access to exports folder

**DON'T:**
- ❌ Commit export XML files to git
- ❌ Store exports in public locations
- ❌ Share exports without encryption

---

## 🔐 Setting Up Secure Automation

### For Local Development
```powershell
# Store certificate password securely
$password = Read-Host -AsSecureString "Certificate Password"
$password | ConvertFrom-SecureString | Out-File "encrypted-password.txt"

# Load when needed
$encryptedPassword = Get-Content "encrypted-password.txt" | ConvertTo-SecureString
```

### For Production (Azure Key Vault)
```powershell
# Store certificate in Key Vault
$cert = Get-Content "mycert.pfx" -AsByteStream
$secret = [Convert]::ToBase64String($cert)
$secretValue = ConvertTo-SecureString $secret -AsPlainText -Force
Set-AzKeyVaultSecret -VaultName "MyVault" -Name "SITMigrationCert" -SecretValue $secretValue

# Retrieve when needed
$kvCert = Get-AzKeyVaultSecret -VaultName "MyVault" -Name "SITMigrationCert"
$certBytes = [Convert]::FromBase64String($kvCert.SecretValue)
[System.IO.File]::WriteAllBytes("temp-cert.pfx", $certBytes)
```

### For CI/CD Pipelines
```yaml
# Use pipeline secrets
variables:
  - group: 'SIT-Migration-Secrets'  # Contains CertPassword, AppId, etc.

steps:
- task: AzureKeyVault@2
  inputs:
    azureSubscription: 'MySubscription'
    KeyVaultName: 'MyVault'
    SecretsFilter: 'SITMigrationCert,CertPassword'
```

---

## 🚨 What To Do If Secrets Are Committed

If you accidentally commit sensitive files:

### 1. Immediate Actions
```powershell
# Remove from git but keep locally
git rm --cached mycert.pfx app-config.json exports/*.xml

# Commit the removal
git commit -m "Remove sensitive files"

# Push immediately
git push
```

### 2. Rotate Compromised Credentials
```powershell
# If certificates were committed:
# 1. Delete the app registration in Azure Portal
# 2. Run setup again with new certificate
.\00-Setup-AppRegistration.ps1 -Organization "contoso.onmicrosoft.com"

# If configs were committed:
# 1. Note the exposed App IDs
# 2. Disable/delete those apps in Azure Portal
# 3. Create new apps with different credentials
```

### 3. Clean Git History (If Needed)
```powershell
# WARNING: Rewrites git history - coordinate with team
git filter-branch --force --index-filter \
  "git rm --cached --ignore-unmatch mycert.pfx app-config.json" \
  --prune-empty --tag-name-filter cat -- --all

# Force push (dangerous - only if necessary)
git push --force --all
```

### 4. Notify Security Team
- Report the incident
- Document what was exposed
- Review access logs
- Update security procedures

---

## 📝 Sample Config Template

Create a `config-template.json` for documentation (safe to commit):

```json
{
    "AppName": "<your-app-name>",
    "AppId": "<guid>",
    "TenantId": "<guid>",
    "Organization": "<tenant>.onmicrosoft.com",
    "CertificateThumbprint": "<thumbprint>",
    "CertificatePath": "<path-to-pfx>",
    "AssignedRole": "Compliance Administrator",
    "Notes": "DO NOT commit actual config files!"
}
```

---

## 🔍 Auditing and Monitoring

### Regular Security Checks
```powershell
# Check for any sensitive files in working directory
Get-ChildItem -Recurse -Include *.pfx,*.p12,*-config.json,*.cer | 
    Where-Object { $_.FullName -notmatch 'node_modules|.git' }

# Review git status before commits
git status --ignored

# Check what's actually tracked
git ls-files | Select-String -Pattern "cert|config|secret|password"
```

### Azure AD App Audit
```powershell
# Review app permissions regularly
Connect-MgGraph -Scopes "Application.Read.All"
$app = Get-MgApplication -Filter "displayName eq 'Purview-SIT-Migration-App'"
Get-MgApplication -ApplicationId $app.Id | 
    Select-Object DisplayName, RequiredResourceAccess | 
    Format-List
```

---

## 📋 Security Compliance

### For Enterprise Environments

1. **Certificate Requirements**
   - Use CA-issued certificates (not self-signed)
   - Minimum 2048-bit key length
   - Store in HSM or Azure Key Vault
   - Rotate annually

2. **Access Control**
   - Limit who can run setup scripts (Global Admins only)
   - Use separate apps per environment (dev/staging/prod)
   - Apply principle of least privilege
   - Enable Azure AD Privileged Identity Management

3. **Audit Logging**
   - Enable Azure AD sign-in logs
   - Monitor app authentication events
   - Set up alerts for suspicious activity
   - Retain logs per compliance requirements

4. **Documentation**
   - Maintain app registration inventory
   - Document certificate locations
   - Create runbooks for certificate rotation
   - Define incident response procedures

---

## 🆘 Support

For security concerns or questions:
1. Review this document
2. Check [APP-REGISTRATION-GUIDE.md](APP-REGISTRATION-GUIDE.md) for setup details
3. Consult your organization's security team
4. Review Microsoft's security best practices

---

## 📚 Additional Resources

- [Microsoft Identity Platform Security](https://learn.microsoft.com/en-us/azure/active-directory/develop/security-best-practices-for-app-registration)
- [Azure Key Vault Best Practices](https://learn.microsoft.com/en-us/azure/key-vault/general/best-practices)
- [Git Security Best Practices](https://docs.github.com/en/code-security/getting-started/best-practices-for-preventing-data-leaks-in-your-organization)

---

**Last Updated:** February 3, 2026  
**Security Review:** Required before production deployment
