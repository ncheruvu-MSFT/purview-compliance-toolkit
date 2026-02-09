<#
.SYNOPSIS
    Installs the pre-commit security hook into the local git repository

.DESCRIPTION
    Copies the pre-commit hook script to .git/hooks/ so it runs automatically
    before every commit. This prevents accidental exposure of certificates,
    secrets, and sensitive configuration files.

.EXAMPLE
    .\hooks\Install-PreCommitHook.ps1
#>

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$ScriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptPath

Write-Host "🔧 Installing pre-commit security hook..." -ForegroundColor Cyan

# Verify we're in a git repo
$gitHooksDir = Join-Path $RepoRoot ".git\hooks"
if (-not (Test-Path $gitHooksDir)) {
    Write-Host "❌ Not a git repository or .git/hooks not found" -ForegroundColor Red
    exit 1
}

# Source hook script
$sourceHook = Join-Path $ScriptPath "pre-commit.ps1"
if (-not (Test-Path $sourceHook)) {
    Write-Host "❌ pre-commit.ps1 not found in hooks directory" -ForegroundColor Red
    exit 1
}

# Create the pre-commit hook wrapper (git runs shell scripts by default)
$hookPath = Join-Path $gitHooksDir "pre-commit"

# Write a shell wrapper that invokes PowerShell
$hookContent = @'
#!/bin/sh
# Pre-commit hook - invokes PowerShell security scanner
# Installed by Install-PreCommitHook.ps1

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "./hooks/pre-commit.ps1"
exit $?
'@

$hookContent | Out-File -FilePath $hookPath -Encoding ascii -NoNewline -Force

Write-Host "✅ Pre-commit hook installed: $hookPath" -ForegroundColor Green
Write-Host ""
Write-Host "The hook will now run automatically before every 'git commit'." -ForegroundColor Gray
Write-Host "It checks for:" -ForegroundColor Gray
Write-Host "   • Certificate files (.pfx, .cer, .pem, .key)" -ForegroundColor Gray
Write-Host "   • Sensitive config files (app-config.json)" -ForegroundColor Gray
Write-Host "   • Hardcoded secrets in PowerShell scripts" -ForegroundColor Gray
Write-Host ""
Write-Host "To bypass (NOT recommended): git commit --no-verify" -ForegroundColor DarkGray
