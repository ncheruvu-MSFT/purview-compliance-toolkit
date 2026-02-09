<#
.SYNOPSIS
    Verify security configuration before committing to source control

.DESCRIPTION
    Checks for sensitive files that should not be committed to git.
    Run this before git add/commit to ensure no secrets are exposed.

.EXAMPLE
    .\Verify-Security.ps1

.NOTES
    This script helps prevent accidental commits of sensitive data.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = "Continue"

Write-Host "╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  Security Verification Check                                 ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

$issues = @()
$warnings = @()

# Define sensitive file patterns
$sensitivePatterns = @{
    "Certificates" = @("*.pfx", "*.p12", "*.cer", "*.pem", "*.key", "mycert*")
    "Configurations" = @("app-config*.json", "*-config.json", "source-app-config.json", "target-app-config.json")
    "Credentials" = @("*password*", "*secret*", "*credential*", "*.cred")
    "Exports" = @("exports/*.xml")
}

Write-Host "🔍 Scanning for sensitive files..." -ForegroundColor Yellow
Write-Host ""

foreach ($category in $sensitivePatterns.Keys) {
    Write-Host "Checking $category..." -ForegroundColor Cyan
    
    $patterns = $sensitivePatterns[$category]
    $foundFiles = @()
    
    foreach ($pattern in $patterns) {
        $files = Get-ChildItem -Path . -Filter $pattern -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -notmatch '\.git|node_modules|\.vs' }
        
        if ($files) {
            $foundFiles += $files
        }
    }
    
    if ($foundFiles.Count -gt 0) {
        Write-Host "   ⚠️  Found $($foundFiles.Count) file(s):" -ForegroundColor Yellow
        foreach ($file in $foundFiles) {
            $relativePath = $file.FullName.Replace((Get-Location).Path + "\", "")
            Write-Host "      • $relativePath" -ForegroundColor Gray
            $warnings += $relativePath
        }
    } else {
        Write-Host "   ✅ No $category files found" -ForegroundColor Green
    }
    Write-Host ""
}

# Check .gitignore exists and is comprehensive
Write-Host "📄 Checking .gitignore..." -ForegroundColor Cyan
if (Test-Path ".gitignore") {
    $gitignoreContent = Get-Content ".gitignore" -Raw
    
    $requiredPatterns = @("*.pfx", "*.cer", "app-config*.json", "exports/*.xml", "*password*", "*secret*")
    $missingPatterns = @()
    
    foreach ($pattern in $requiredPatterns) {
        $escapedPattern = [regex]::Escape($pattern)
        if ($gitignoreContent -notmatch $escapedPattern) {
            $missingPatterns += $pattern
        }
    }
    
    if ($missingPatterns.Count -eq 0) {
        Write-Host "   ✅ .gitignore is properly configured" -ForegroundColor Green
    } else {
        Write-Host "   ⚠️  Missing patterns in .gitignore:" -ForegroundColor Yellow
        $missingPatterns | ForEach-Object { Write-Host "      • $_" -ForegroundColor Gray }
        $issues += ".gitignore missing patterns"
    }
} else {
    Write-Host "   ❌ .gitignore not found!" -ForegroundColor Red
    $issues += ".gitignore missing"
}
Write-Host ""

# Check git status for tracked sensitive files
Write-Host "📊 Checking git status..." -ForegroundColor Cyan
if (Test-Path ".git") {
    try {
        $gitStatus = git status --short 2>&1
        $trackedSensitive = @()
        
        foreach ($line in $gitStatus) {
            foreach ($category in $sensitivePatterns.Keys) {
                foreach ($pattern in $sensitivePatterns[$category]) {
                    $simplePattern = $pattern.Replace("*", "").Replace("?", "")
                    if ($line -like "*$simplePattern*") {
                        $trackedSensitive += $line
                    }
                }
            }
        }
        
        if ($trackedSensitive.Count -gt 0) {
            Write-Host "   ⚠️  Potentially sensitive files in git status:" -ForegroundColor Yellow
            $trackedSensitive | ForEach-Object { Write-Host "      $_" -ForegroundColor Gray }
            $issues += "Sensitive files in git status"
        } else {
            Write-Host "   ✅ No sensitive files staged or modified" -ForegroundColor Green
        }
    } catch {
        Write-Host "   ⚠️  Could not check git status: $_" -ForegroundColor Yellow
    }
} else {
    Write-Host "   ℹ️  Not a git repository" -ForegroundColor Gray
}
Write-Host ""

# Deep scan: Check PowerShell scripts for hardcoded secrets and tenant-specific values
Write-Host "🔬 Deep scanning scripts for hardcoded secrets..." -ForegroundColor Cyan

$deepScanPatterns = @(
    @{ Name = "Hardcoded GUID (possible TenantId/AppId)"; Pattern = '["\u0027][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}["\u0027]'; Severity = "Warning" }
    @{ Name = "Certificate Thumbprint (40-char hex)";     Pattern = '["\u0027][0-9A-Fa-f]{40}["\u0027]'; Severity = "Warning" }
    @{ Name = "Hardcoded password assignment";            Pattern = '(?i)(password|secret|apikey)\s*=\s*["\u0027][^"\u0027$]{4,}["\u0027]'; Severity = "Critical" }
    @{ Name = "Plaintext connection string";              Pattern = '(?i)(Server|Data Source)=[^;\s]+.*Password=[^;\s]+'; Severity = "Critical" }
    @{ Name = "Private key block";                        Pattern = '-----BEGIN (RSA |EC )?PRIVATE KEY-----'; Severity = "Critical" }
    @{ Name = "Hardcoded Bearer token";                   Pattern = '(?i)bearer\s+eyJ[a-zA-Z0-9\-._~\+/]+=*'; Severity = "Critical" }
    @{ Name = "Real .onmicrosoft.com domain";             Pattern = '(?i)["\u0027][a-z0-9]+\.onmicrosoft\.com["\u0027]'; Severity = "Warning" }
)

# Known safe patterns (in documentation examples, help text, etc.)
$safePatterns = @(
    'contoso\.onmicrosoft\.com',
    'fabrikam\.onmicrosoft\.com',
    'source\.onmicrosoft\.com',
    'target\.onmicrosoft\.com',
    '<your-tenant>',
    '<YOUR-',
    'example\.com',
    '00000000-0000',
    '00000002-0000-0ff1-ce00',        # Well-known Exchange Online resource ID
    'dc50a0fb-09a3-484d-be87',        # Well-known Exchange.ManageAsApp permission ID
    '17315797-102d-40b4',             # Well-known role template IDs
    'e6d1a23a-da11-4be4',
    '62e90394-69f5-4237',
    '194ae4cb-b126-40b2',
    '\$\(',                            # PowerShell variable expansion
    '\$config\.',                      # Config file reference
    '\$cert\.',                        # Certificate object reference
    '\$app\.',                         # App object reference
    '\$context\.'                      # Context object reference
)

$scriptFiles = Get-ChildItem -Path . -Filter "*.ps1" -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -notmatch '\.git' }

$deepIssues = @()

foreach ($scriptFile in $scriptFiles) {
    $content = Get-Content $scriptFile.FullName -Raw -ErrorAction SilentlyContinue
    if (-not $content) { continue }

    $relativePath = $scriptFile.FullName.Replace((Get-Location).Path + "\", "")

    foreach ($check in $deepScanPatterns) {
        $matches = [regex]::Matches($content, $check.Pattern)
        foreach ($match in $matches) {
            $matchValue = $match.Value
            $isSafe = $false

            # Check the surrounding context (±50 chars) against safe patterns
            $start = [Math]::Max(0, $match.Index - 50)
            $length = [Math]::Min($content.Length - $start, $match.Length + 100)
            $context = $content.Substring($start, $length)

            foreach ($safe in $safePatterns) {
                if ($context -match $safe) {
                    $isSafe = $true
                    break
                }
            }

            if (-not $isSafe) {
                $lineNumber = ($content.Substring(0, $match.Index) -split "`n").Count
                $deepIssues += @{
                    File     = $relativePath
                    Line     = $lineNumber
                    Check    = $check.Name
                    Severity = $check.Severity
                    Value    = if ($matchValue.Length -gt 20) { $matchValue.Substring(0, 20) + "..." } else { $matchValue }
                }
            }
        }
    }
}

if ($deepIssues.Count -gt 0) {
    $criticalCount = ($deepIssues | Where-Object { $_.Severity -eq "Critical" }).Count
    $warningCount = ($deepIssues | Where-Object { $_.Severity -eq "Warning" }).Count

    if ($criticalCount -gt 0) {
        Write-Host "   ❌ Found $criticalCount CRITICAL issue(s):" -ForegroundColor Red
        $deepIssues | Where-Object { $_.Severity -eq "Critical" } | ForEach-Object {
            Write-Host "      • $($_.File):$($_.Line) - $($_.Check)" -ForegroundColor Red
            $issues += "Hardcoded secret in $($_.File):$($_.Line)"
        }
    }
    if ($warningCount -gt 0) {
        Write-Host "   ⚠️  Found $warningCount warning(s) (review recommended):" -ForegroundColor Yellow
        $deepIssues | Where-Object { $_.Severity -eq "Warning" } | ForEach-Object {
            Write-Host "      • $($_.File):$($_.Line) - $($_.Check): $($_.Value)" -ForegroundColor Yellow
        }
    }
} else {
    Write-Host "   ✅ No hardcoded secrets or tenant-specific values found in scripts" -ForegroundColor Green
}
Write-Host ""

# Check for certificates in certificate store
Write-Host "🔐 Checking certificate store..." -ForegroundColor Cyan
try {
    $certs = Get-ChildItem Cert:\CurrentUser\My | 
        Where-Object { $_.Subject -like "*Purview*" -or $_.Subject -like "*SIT*Migration*" }
    
    if ($certs) {
        Write-Host "   ℹ️  Found $($certs.Count) related certificate(s) in store" -ForegroundColor Gray
        $certs | ForEach-Object {
            Write-Host "      • Subject: $($_.Subject)" -ForegroundColor DarkGray
            Write-Host "        Thumbprint: $($_.Thumbprint)" -ForegroundColor DarkGray
            Write-Host "        Expires: $($_.NotAfter)" -ForegroundColor DarkGray
        }
        Write-Host "   ✅ Certificates stored securely" -ForegroundColor Green
    } else {
        Write-Host "   ℹ️  No related certificates found in store" -ForegroundColor Gray
    }
} catch {
    Write-Host "   ⚠️  Could not access certificate store: $_" -ForegroundColor Yellow
}
Write-Host ""

# Check pre-commit hook installation
Write-Host "🪝 Checking pre-commit hook..." -ForegroundColor Cyan
$preCommitHook = Join-Path "." ".git\hooks\pre-commit"
if (Test-Path $preCommitHook) {
    Write-Host "   ✅ Pre-commit security hook is installed" -ForegroundColor Green
} else {
    Write-Host "   ⚠️  Pre-commit hook NOT installed" -ForegroundColor Yellow
    Write-Host "      Install with: .\hooks\Install-PreCommitHook.ps1" -ForegroundColor Gray
    $warnings += "Pre-commit hook not installed"
}
Write-Host ""

# Check .gitattributes exists
Write-Host "📝 Checking .gitattributes..." -ForegroundColor Cyan
if (Test-Path ".gitattributes") {
    Write-Host "   ✅ .gitattributes is configured" -ForegroundColor Green
} else {
    Write-Host "   ⚠️  .gitattributes not found" -ForegroundColor Yellow
    $warnings += ".gitattributes missing"
}
Write-Host ""

# Summary
Write-Host "╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  Security Check Summary                                       ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

if ($issues.Count -eq 0 -and $warnings.Count -eq 0) {
    Write-Host "✅ ALL CHECKS PASSED!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Repository is safe to commit." -ForegroundColor Green
} else {
    if ($issues.Count -gt 0) {
        Write-Host "❌ CRITICAL ISSUES FOUND: $($issues.Count)" -ForegroundColor Red
        $issues | ForEach-Object { Write-Host "   • $_" -ForegroundColor Red }
        Write-Host ""
        Write-Host "⚠️  DO NOT COMMIT until issues are resolved!" -ForegroundColor Red
    }
    
    if ($warnings.Count -gt 0) {
        Write-Host "⚠️  WARNINGS: $($warnings.Count) sensitive file(s) found" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "These files exist locally but are protected by .gitignore:" -ForegroundColor Yellow
        $warnings | Select-Object -Unique | ForEach-Object { Write-Host "   • $_" -ForegroundColor Gray }
        Write-Host ""
        Write-Host "✅ Files are protected - safe to commit" -ForegroundColor Green
    }
}

Write-Host ""
Write-Host "📖 For more information, see:" -ForegroundColor Cyan
Write-Host "   • SECURITY.md - Complete security guidelines" -ForegroundColor Gray
Write-Host "   • .gitignore - Protected file patterns" -ForegroundColor Gray
Write-Host ""

# Recommendations
Write-Host "💡 Recommendations:" -ForegroundColor Cyan
Write-Host "   1. Always run this script before 'git commit'" -ForegroundColor Gray
Write-Host "   2. Install the pre-commit hook: .\hooks\Install-PreCommitHook.ps1" -ForegroundColor Gray
Write-Host "   3. Review 'git status' output carefully" -ForegroundColor Gray
Write-Host "   4. Use 'git diff --cached' to review staged changes" -ForegroundColor Gray
Write-Host "   5. Store certificates in Azure Key Vault for production" -ForegroundColor Gray
Write-Host "   6. Never commit app-config.json — use app-config.sample.json as template" -ForegroundColor Gray
Write-Host ""

if ($issues.Count -gt 0) {
    exit 1
} else {
    exit 0
}
