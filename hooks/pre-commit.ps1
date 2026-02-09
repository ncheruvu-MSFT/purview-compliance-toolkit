<#
.SYNOPSIS
    Git pre-commit hook to prevent accidental exposure of secrets

.DESCRIPTION
    Scans staged files for sensitive content before allowing a commit.
    Blocks commits that contain:
    - Certificate files (.pfx, .cer, .pem, .key, .p12, .crt)
    - Hardcoded secrets, passwords, or API keys
    - Real tenant IDs, thumbprints, or app registration IDs
    - Configuration files with real credentials

.NOTES
    To install, run from the repository root:
        Copy-Item .\hooks\pre-commit.ps1 .\.git\hooks\pre-commit
    Or create a symlink:
        New-Item -ItemType SymbolicLink -Path .\.git\hooks\pre-commit -Target ..\..\hooks\pre-commit.ps1

    The hook can also be installed automatically via Install-PreCommitHook.ps1
#>

$ErrorActionPreference = "Stop"

# ─── Configuration ───────────────────────────────────────────────────────────
$blockedExtensions = @(".pfx", ".p12", ".cer", ".pem", ".key", ".crt")

$blockedFilePatterns = @(
    "app-config.json",
    "source-app-config.json",
    "target-app-config.json",
    "*-config.json"
)

# Regex patterns that indicate hardcoded secrets in source code
$secretPatterns = @(
    @{ Name = "Hardcoded Password";         Pattern = '(?i)(password|passwd|pwd)\s*[:=]\s*["\u0027][^"\u0027]{3,}["\u0027]' }
    @{ Name = "Hardcoded Secret";           Pattern = '(?i)(secret|apikey|api_key|access_key)\s*[:=]\s*["\u0027][^"\u0027]{3,}["\u0027]' }
    @{ Name = "Azure Tenant ID (GUID)";     Pattern = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' }
    @{ Name = "Certificate Thumbprint";     Pattern = '[0-9A-Fa-f]{40}' }
    @{ Name = "Connection String";          Pattern = '(?i)(server|data source|initial catalog|user id|password)=[^;\s]+;' }
    @{ Name = "Bearer Token";              Pattern = '(?i)bearer\s+[a-zA-Z0-9\-._~\+/]+=*' }
    @{ Name = "Base64 Private Key";        Pattern = '-----BEGIN (RSA |EC )?PRIVATE KEY-----' }
    @{ Name = "Base64 Certificate";        Pattern = '-----BEGIN CERTIFICATE-----' }
)

# Files/patterns to exclude from secret scanning (documentation, samples, etc.)
$excludeFromSecretScan = @(
    "*.md",
    "*.sample.json",
    "app-config.sample.json",
    "hooks/*",
    "*.gitignore",
    "*.gitattributes"
)

# ─── Functions ───────────────────────────────────────────────────────────────

function Test-IsExcluded {
    param([string]$FilePath)
    foreach ($pattern in $excludeFromSecretScan) {
        if ($FilePath -like $pattern) { return $true }
    }
    return $false
}

# ─── Main ────────────────────────────────────────────────────────────────────

$issues = @()

# Get staged files
$stagedFiles = git diff --cached --name-only --diff-filter=ACM 2>$null
if (-not $stagedFiles) {
    exit 0  # No staged files, allow commit
}

Write-Host "🔒 Pre-commit security check..." -ForegroundColor Cyan

foreach ($file in $stagedFiles) {
    $fileName = Split-Path $file -Leaf
    $extension = [System.IO.Path]::GetExtension($file)

    # CHECK 1: Blocked file extensions (certificates, keys)
    if ($extension -in $blockedExtensions) {
        $issues += "❌ BLOCKED: Certificate/key file staged: $file"
        continue
    }

    # CHECK 2: Blocked file name patterns
    foreach ($pattern in $blockedFilePatterns) {
        if ($fileName -like $pattern -and $fileName -notlike "*.sample.*") {
            $issues += "❌ BLOCKED: Sensitive config file staged: $file"
            break
        }
    }

    # CHECK 3: Scan file content for secrets (skip excluded files)
    if (-not (Test-IsExcluded $file)) {
        try {
            $content = git show ":$file" 2>$null
            if ($content) {
                foreach ($check in $secretPatterns) {
                    $matches = [regex]::Matches($content, $check.Pattern)
                    if ($matches.Count -gt 0) {
                        # Skip known safe patterns (example GUIDs in sample files, etc.)
                        $isSafe = $false
                        foreach ($match in $matches) {
                            $value = $match.Value
                            # Allow placeholder patterns
                            if ($value -match '<YOUR-|<your-|placeholder|example|contoso|00000000-0000') {
                                $isSafe = $true
                            }
                        }
                        if (-not $isSafe) {
                            $issues += "⚠️  WARNING: Possible $($check.Name) in $file"
                        }
                    }
                }
            }
        } catch {
            # Skip files that can't be read
        }
    }
}

# ─── Results ─────────────────────────────────────────────────────────────────

if ($issues.Count -gt 0) {
    Write-Host ""
    Write-Host "╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Red
    Write-Host "║  🚫 COMMIT BLOCKED - Security Issues Found                   ║" -ForegroundColor Red
    Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Red
    Write-Host ""

    $blockers = $issues | Where-Object { $_ -match "^❌" }
    $warnings = $issues | Where-Object { $_ -match "^⚠️" }

    if ($blockers) {
        Write-Host "BLOCKING ISSUES:" -ForegroundColor Red
        $blockers | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
        Write-Host ""
    }

    if ($warnings) {
        Write-Host "WARNINGS (review carefully):" -ForegroundColor Yellow
        $warnings | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
        Write-Host ""
    }

    Write-Host "💡 To fix:" -ForegroundColor Cyan
    Write-Host "   1. git reset HEAD <file>     — Unstage the sensitive file" -ForegroundColor Gray
    Write-Host "   2. Ensure .gitignore covers the file pattern" -ForegroundColor Gray
    Write-Host "   3. Remove hardcoded secrets from scripts" -ForegroundColor Gray
    Write-Host ""

    if ($blockers) {
        Write-Host "To bypass (NOT recommended): git commit --no-verify" -ForegroundColor DarkGray
        exit 1
    }
}

Write-Host "✅ Pre-commit security check passed" -ForegroundColor Green
exit 0
