# 🚀 Quick Start Guide - SIT Migration

> 💡 **Visual Diagrams**: See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed architecture diagrams including app registration flow, migration workflow, and security architecture.

## Authentication Setup

### Option 1: Interactive (Quick Start)
No setup needed - just run the scripts!

### Option 2: App-Only (Automation)
```powershell
# One-time setup
.\00-Setup-AppRegistration.ps1 -Organization "contoso.onmicrosoft.com"

# Test it works
.\00a-Test-AppConnection.ps1
```

---

## Migration Commands

### INTERACTIVE AUTHENTICATION

#### Source Tenant
```powershell
# 1. Connect to source
.\01-Connect-Tenant.ps1

# 2. Export SITs
.\03-Export-Custom-SITs.ps1
```

#### Target Tenant
```powershell
# 3. Connect to target (new PowerShell window)
.\01-Connect-Tenant.ps1

# 4. Import SITs
.\04-Import-Custom-SITs.ps1 -SourceXmlPath ".\exports\source-export-GUID.xml"
```

---

### APP-ONLY AUTHENTICATION

#### Source Tenant
```powershell
# 1. Connect with cert (source tenant)
Connect-IPPSSession `
    -CertificateThumbPrint "ABC123..." `
    -AppID "12345678..." `
    -Organization "source.onmicrosoft.com"

# 2. Export SITs
.\03-Export-Custom-SITs.ps1

# 3. Disconnect
Disconnect-ExchangeOnline -Confirm:$false
```

#### Target Tenant
```powershell
# 4. Connect with cert (target tenant)
Connect-IPPSSession `
    -CertificateThumbPrint "DEF456..." `
    -AppID "87654321..." `
    -Organization "target.onmicrosoft.com"

# 5. Import SITs
.\04-Import-Custom-SITs.ps1 -SourceXmlPath ".\exports\source-export-GUID.xml"

# 6. Disconnect
Disconnect-ExchangeOnline -Confirm:$false
```

---

## Automated Script Example

```powershell
<#
    Automated SIT Migration Script
    Requires: App registrations in both source and target tenants
#>

# Load configurations
$sourceConfig = Get-Content "source-app-config.json" | ConvertFrom-Json
$targetConfig = Get-Content "target-app-config.json" | ConvertFrom-Json

# === SOURCE TENANT ===
Write-Host "Connecting to source tenant..." -ForegroundColor Cyan
Connect-IPPSSession `
    -CertificateThumbPrint $sourceConfig.CertificateThumbprint `
    -AppID $sourceConfig.AppId `
    -Organization $sourceConfig.Organization `
    -ShowBanner:$false

Write-Host "Exporting SITs from source..." -ForegroundColor Cyan
.\03-Export-Custom-SITs.ps1

# Get latest export file
$exportFile = Get-ChildItem ".\exports\source-export-*.xml" | 
    Sort-Object LastWriteTime -Descending | 
    Select-Object -First 1

Write-Host "Disconnecting from source..." -ForegroundColor Cyan
Disconnect-ExchangeOnline -Confirm:$false

# === TARGET TENANT ===
Write-Host "Connecting to target tenant..." -ForegroundColor Cyan
Connect-IPPSSession `
    -CertificateThumbPrint $targetConfig.CertificateThumbprint `
    -AppID $targetConfig.AppId `
    -Organization $targetConfig.Organization `
    -ShowBanner:$false

Write-Host "Importing SITs to target..." -ForegroundColor Cyan
.\04-Import-Custom-SITs.ps1 -SourceXmlPath $exportFile.FullName

Write-Host "Disconnecting from target..." -ForegroundColor Cyan
Disconnect-ExchangeOnline -Confirm:$false

Write-Host "✅ Migration complete!" -ForegroundColor Green
```

---

## Troubleshooting

### Connection Issues
```powershell
# Check current connection
Get-ConnectionInformation

# Force disconnect
Disconnect-ExchangeOnline -Confirm:$false

# Reconnect
.\01-Connect-Tenant.ps1
```

### Check What's Installed
```powershell
# List custom SITs
Get-DlpSensitiveInformationType | Where-Object { $_.Publisher -ne "Microsoft Corporation" }

# Verify specific SIT
Get-DlpSensitiveInformationType -Identity "YourSITName"
```

### Module Issues
```powershell
# Check module version
Get-Module ExchangeOnlineManagement -ListAvailable

# Update module
Update-Module ExchangeOnlineManagement -Force

# Reimport module
Remove-Module ExchangeOnlineManagement
Import-Module ExchangeOnlineManagement
```

---

## File Locations

| File | Purpose | Security |
|------|---------|----------|
| `exports/*.xml` | Exported SIT definitions | Contains sensitive patterns |
| `app-config.json` | Connection details | IDs only (safe) |
| `mycert.pfx` | Private certificate | ⚠️ KEEP SECURE |
| `mycert.cer` | Public certificate | Safe to share |

---

## Common Scenarios

### Test Migration (Same Tenant)
```powershell
.\99-Test-Migration-Loop.ps1
```

### Create Sample Data
```powershell
.\02-Create-Sample-SITs.ps1
```

### Verify Connection
```powershell
.\00-Verify-Connection.ps1
```

### Check App Config
```powershell
Get-Content "app-config.json" | ConvertFrom-Json | Format-List
```

---

## Security Checklist

- [ ] Certificate password stored in secure vault (not in scripts)
- [ ] `.pfx` files have restrictive file permissions
- [ ] Certificates added to `.gitignore`
- [ ] Regular certificate rotation scheduled
- [ ] App permissions reviewed (principle of least privilege)
- [ ] Sign-in logs monitored for suspicious activity

---

## Need Help?

1. Check [README.md](README.md) - Migration workflow
2. Check [APP-REGISTRATION-GUIDE.md](APP-REGISTRATION-GUIDE.md) - App setup details
3. Review error messages in console output
4. Check Azure AD sign-in logs for authentication issues
