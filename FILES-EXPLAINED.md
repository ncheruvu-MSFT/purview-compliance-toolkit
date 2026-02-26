# 📦 Toolkit Files - Quick Reference

## ✅ Current Files

### 🎯 CORE WORKFLOW — SIT Migration (6 files)

| File | Purpose | When to Use |
|------|---------|-------------|
| `00-Setup-AppRegistration.ps1` | Create app registration + certificate | **Run ONCE per tenant** (source & target) |
| `00a-Test-AppConnection.ps1` | Test certificate authentication works | After setup, before migration |
| `01-Connect-Tenant.ps1` | Connect to tenant (interactive or app-only) | Every migration session |
| `03-Export-Custom-SITs.ps1` | Export SITs from source tenant | Source tenant only |
| `04-Import-Custom-SITs.ps1` | Import SITs to target tenant | Target tenant only |
| `Validate-ExportXml.ps1` | Validate/preview exported XML (encoding, structure) | After export, before import |

---

### 🏷️ SENSITIVITY LABELS (2 files)

| File | Purpose | When to Use |
|------|---------|-------------|
| `05-Export-SensitivityLabels.ps1` | Export labels + label policies to JSON | Source tenant — backup/migration |
| `06-Import-SensitivityLabels.ps1` | Import labels + policies from JSON | Target tenant — restore/migration |

---

### 🛡️ DLP POLICIES (2 files)

| File | Purpose | When to Use |
|------|---------|-------------|
| `07-Export-DlpPolicies.ps1` | Export DLP policies + rules to JSON | Source tenant — backup/migration |
| `08-Import-DlpPolicies.ps1` | Import DLP policies + rules from JSON | Target tenant — supports `-TestMode` |

---

### 🏷️ AUTO-LABELING POLICIES (2 files)

| File | Purpose | When to Use |
|------|---------|-------------|
| `09-Export-AutoLabelPolicies.ps1` | Export auto-labeling policies + rules to JSON | Source tenant — backup/migration |
| `10-Import-AutoLabelPolicies.ps1` | Import auto-labeling policies + rules from JSON | Target tenant — supports `-TestMode` |

---

### 📦 ORCHESTRATORS (2 files)

| File | Purpose | When to Use |
|------|---------|-------------|
| `Backup-PurviewConfig.ps1` | Full backup — runs all exports, writes manifest | One-command backup |
| `Restore-PurviewConfig.ps1` | Full restore — reads manifest, runs all imports | One-command restore |

---

### 🔄 CI/CD PIPELINES (4 files)

| File | Purpose |
|------|---------|
| `.github/workflows/purview-backup.yml` | GitHub Actions — scheduled weekly backup |
| `.github/workflows/purview-migration.yml` | GitHub Actions — on-demand tenant migration |
| `.azure-pipelines/purview-backup.yml` | Azure DevOps — scheduled backup pipeline |
| `.azure-pipelines/purview-migration.yml` | Azure DevOps — two-stage migration pipeline |

---

### 🛠️ HELPER SCRIPTS (6 files) - **OPTIONAL**

| File | Purpose | Optional Because |
|------|---------|------------------|
| `00-Verify-Connection.ps1` | Quick connection test | Can use 01-Connect-Tenant instead |
| `02-Create-Sample-SITs.ps1` | Create test SITs for demo | Only needed for testing |
| `99-Test-Migration-Loop.ps1` | Test export/import on same tenant | Only for validation |
| `Sample-Automated-Migration.ps1` | Full automation example | Template for building your own |
| `Test-Toolkit.ps1` | Run all validation tests | Dev/QA use only |
| `Verify-Security.ps1` | Check for sensitive files before commit | Security audit |

---

### 📚 DOCUMENTATION (6 files) - **READ THESE**

| File | What's Inside | Priority |
|------|---------------|----------|
| `README.md` | Main documentation, workflow | ⭐⭐⭐ Read first |
| `SECURITY.md` | Security guidelines, what NOT to commit | ⭐⭐⭐ Critical |
| `APP-REGISTRATION-GUIDE.md` | Detailed app setup instructions | ⭐⭐ If using app-only auth |
| `QUICK-START.md` | Command cheat sheet | ⭐⭐ Quick reference |
| `ARCHITECTURE.md` | Diagrams and architecture | ⭐ For presentations |
| `REPOSITORY-SECURITY.md` | Pre-commit checklist | ⭐ Before git commit |

---

### 🔧 CONFIGURATION (4 files) - **LOCAL ONLY**

| File | Protected By | Purpose |
|------|--------------|---------|
| `.gitignore` | N/A | Protects sensitive files from git |
| `.gitkeep` | N/A | Preserves empty directory structure |
| `mycert.pfx`, `mycert.cer` | ✅ .gitignore | Your certificates (NEVER commit) |
| `app-config.json` | ✅ .gitignore | Connection config (NEVER commit) |

---

## 🏢 App Registration: Source AND Target!

### ⚠️ IMPORTANT: You need **TWO** app registrations!

```
┌─────────────────────────────────────────────────────────────┐
│ Source Tenant (contoso.onmicrosoft.com)                    │
│                                                             │
│  ✅ Run: .\00-Setup-AppRegistration.ps1                    │
│     -Organization "contoso.onmicrosoft.com"                │
│                                                             │
│  Creates:                                                   │
│  • App Registration: "Purview-SIT-Migration-App"           │
│  • Certificate: mycert-source.pfx                          │
│  • Config: source-app-config.json                          │
│                                                             │
│  Roles: Compliance Administrator                           │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ Target Tenant (fabrikam.onmicrosoft.com)                   │
│                                                             │
│  ✅ Run: .\00-Setup-AppRegistration.ps1                    │
│     -Organization "fabrikam.onmicrosoft.com"               │
│                                                             │
│  Creates:                                                   │
│  • App Registration: "Purview-SIT-Migration-App"           │
│  • Certificate: mycert-target.pfx                          │
│  • Config: target-app-config.json                          │
│                                                             │
│  Roles: Compliance Administrator                           │
└─────────────────────────────────────────────────────────────┘
```

### Why Two App Registrations?

1. **Different Tenants** - Each tenant has its own Azure AD
2. **Separate Security** - If source is compromised, target is still safe
3. **Separate Permissions** - Each app only has access to its own tenant
4. **Different Certificates** - Each tenant verifies its own certificate

### Naming Convention Suggestion

To avoid confusion, rename files after creation:

```powershell
# After running setup in SOURCE tenant
Rename-Item "mycert.pfx" "mycert-source.pfx"
Rename-Item "mycert.cer" "mycert-source.cer"
Rename-Item "app-config.json" "source-app-config.json"

# After running setup in TARGET tenant
Rename-Item "mycert.pfx" "mycert-target.pfx"
Rename-Item "mycert.cer" "mycert-target.cer"
Rename-Item "app-config.json" "target-app-config.json"
```

---

## 🧹 Can I Delete Any Files?

### ✅ Safe to Delete (Optional Helpers):

```powershell
# If you don't need these features:
Remove-Item "00-Verify-Connection.ps1"         # Use 01-Connect-Tenant.ps1 instead
Remove-Item "02-Create-Sample-SITs.ps1"        # Only for testing
Remove-Item "99-Test-Migration-Loop.ps1"       # Only for testing
Remove-Item "Sample-Automated-Migration.ps1"   # Just an example
Remove-Item "Test-Toolkit.ps1"                 # Dev/QA only

# Reduces to 17 files
```

### ❌ DO NOT Delete:

- Any file starting with `00-Setup`, `01-Connect`, `03-Export`, `04-Import`
- Any `.md` documentation file
- `.gitignore` or `.gitkeep`
- `Verify-Security.ps1` (important for security)

---

## 📊 Minimal Setup

**Absolute minimum for production:**

```
Required Files (11):
├── Core Scripts (5)
│   ├── 00-Setup-AppRegistration.ps1
│   ├── 01-Connect-Tenant.ps1
│   ├── 03-Export-Custom-SITs.ps1
│   ├── 04-Import-Custom-SITs.ps1
│   └── Verify-Security.ps1
├── Documentation (4)
│   ├── README.md
│   ├── SECURITY.md
│   ├── APP-REGISTRATION-GUIDE.md
│   └── QUICK-START.md
└── Configuration (2)
    ├── .gitignore
    └── .gitkeep
```

Everything else is optional!

---

## 🎯 Quick Decision Guide

**I want to...**

- ✅ **Do a one-time migration** → Keep core 6 scripts only
- ✅ **Test before real migration** → Keep 02-Create-Sample-SITs.ps1
- ✅ **Build automation** → Keep Sample-Automated-Migration.ps1 as template
- ✅ **Understand architecture** → Keep all .md documentation
- ✅ **Minimal footprint** → Delete all helpers, keep core 11 files

---

## 📝 Summary

- **22 files total** = 6 core + 6 helpers + 6 docs + 4 config
- **Minimum needed** = 11 files
- **App registrations** = 2 (one per tenant)
- **Certificates** = 2 pairs (source + target)

**Bottom line:** The toolkit is comprehensive but you only *need* 11 files for production!

---

**Last Updated:** February 3, 2026
