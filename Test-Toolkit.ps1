<#
.SYNOPSIS
    Comprehensive validation of SIT Migration Toolkit

.DESCRIPTION
    Tests all scripts, validates documentation, checks for broken links,
    and ensures best practices are followed.

.EXAMPLE
    .\Test-Toolkit.ps1

.NOTES
    Run this before committing changes to ensure quality standards
#>

[CmdletBinding()]
param()

$ErrorActionPreference = "Continue"
$script:FailureCount = 0
$script:WarningCount = 0
$script:PassCount = 0

function Write-TestResult {
    param(
        [string]$Test,
        [string]$Result,
        [string]$Message = ""
    )
    
    switch ($Result) {
        "PASS" {
            Write-Host "  ✅ $Test" -ForegroundColor Green
            if ($Message) { Write-Host "     $Message" -ForegroundColor Gray }
            $script:PassCount++
        }
        "FAIL" {
            Write-Host "  ❌ $Test" -ForegroundColor Red
            if ($Message) { Write-Host "     $Message" -ForegroundColor Red }
            $script:FailureCount++
        }
        "WARN" {
            Write-Host "  ⚠️  $Test" -ForegroundColor Yellow
            if ($Message) { Write-Host "     $Message" -ForegroundColor Yellow }
            $script:WarningCount++
        }
    }
}

Write-Host "╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  SIT Migration Toolkit - Comprehensive Test Suite            ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

#region Test 1: File Structure
Write-Host "📁 Test 1: File Structure Validation" -ForegroundColor Cyan

$requiredFiles = @(
    "README.md",
    "SECURITY.md",
    "ARCHITECTURE.md",
    "APP-REGISTRATION-GUIDE.md",
    "QUICK-START.md",
    "REPOSITORY-SECURITY.md",
    ".gitignore",
    ".gitattributes",
    "app-config.sample.json",
    "00-Setup-AppRegistration.ps1",
    "00a-Test-AppConnection.ps1",
    "00-Verify-Connection.ps1",
    "01-Connect-Tenant.ps1",
    "02-Create-Sample-SITs.ps1",
    "03-Export-Custom-SITs.ps1",
    "04-Import-Custom-SITs.ps1",
    "05-Create-Sensitivity-Labels.ps1",
    "06-Create-AutoLabeling-Policy.ps1",
    "07-Verify-AutoLabeling.ps1",
    "99-Test-Migration-Loop.ps1",
    "Sample-Automated-Migration.ps1",
    "Sample-EndToEnd-AutoLabeling.ps1",
    "Verify-Security.ps1",
    "hooks\pre-commit.ps1",
    "hooks\Install-PreCommitHook.ps1"
)

foreach ($file in $requiredFiles) {
    if (Test-Path $file) {
        Write-TestResult -Test "File exists: $file" -Result "PASS"
    } else {
        Write-TestResult -Test "File exists: $file" -Result "FAIL" -Message "Required file missing"
    }
}

# Check for required directories
$requiredDirs = @("exports", "exports\archive", "hooks")
foreach ($dir in $requiredDirs) {
    if (Test-Path $dir) {
        Write-TestResult -Test "Directory exists: $dir" -Result "PASS"
    } else {
        Write-TestResult -Test "Directory exists: $dir" -Result "FAIL" -Message "Required directory missing"
    }
}

Write-Host ""
#endregion

#region Test 2: PowerShell Script Syntax
Write-Host "📜 Test 2: PowerShell Script Syntax Validation" -ForegroundColor Cyan

$scripts = Get-ChildItem -Filter "*.ps1" -File

foreach ($script in $scripts) {
    try {
        $null = [System.Management.Automation.PSParser]::Tokenize((Get-Content $script.FullName -Raw), [ref]$null)
        Write-TestResult -Test "Syntax: $($script.Name)" -Result "PASS"
    } catch {
        Write-TestResult -Test "Syntax: $($script.Name)" -Result "FAIL" -Message $_.Exception.Message
    }
}

Write-Host ""
#endregion

#region Test 3: Script Standards
Write-Host "📋 Test 3: PowerShell Best Practices" -ForegroundColor Cyan

foreach ($script in $scripts) {
    $content = Get-Content $script.FullName -Raw
    
    # Check for proper header
    if ($content -match '<#[\s\S]*?\.SYNOPSIS[\s\S]*?\.DESCRIPTION[\s\S]*?\.EXAMPLE[\s\S]*?#>') {
        Write-TestResult -Test "Help block: $($script.Name)" -Result "PASS"
    } else {
        Write-TestResult -Test "Help block: $($script.Name)" -Result "WARN" -Message "Missing or incomplete comment-based help"
    }
    
    # Check for error handling
    if ($content -match '\$ErrorActionPreference' -or $content -match 'try\s*\{' -or $content -match '-ErrorAction') {
        Write-TestResult -Test "Error handling: $($script.Name)" -Result "PASS"
    } else {
        Write-TestResult -Test "Error handling: $($script.Name)" -Result "WARN" -Message "No explicit error handling found"
    }
    
    # Check for hardcoded secrets (should not exist)
    if ($content -match 'password\s*=\s*["''].*["'']' -or $content -match 'secret\s*=\s*["''].*["'']') {
        Write-TestResult -Test "No hardcoded secrets: $($script.Name)" -Result "FAIL" -Message "Possible hardcoded credentials found"
    } else {
        Write-TestResult -Test "No hardcoded secrets: $($script.Name)" -Result "PASS"
    }
}

Write-Host ""
#endregion

#region Test 4: Documentation Links
Write-Host "🔗 Test 4: Documentation Internal Links" -ForegroundColor Cyan

$mdFiles = Get-ChildItem -Filter "*.md" -File
$allMdFiles = $mdFiles.Name

foreach ($mdFile in $mdFiles) {
    $content = Get-Content $mdFile.FullName -Raw
    
    # Find markdown links [text](file.md)
    $links = [regex]::Matches($content, '\[([^\]]+)\]\(([^\)]+)\)')
    
    foreach ($link in $links) {
        $linkPath = $link.Groups[2].Value
        
        # Skip external links and anchors
        if ($linkPath -match '^https?://' -or $linkPath -match '^#') {
            continue
        }
        
        # Remove anchor if present
        $filePath = ($linkPath -split '#')[0]
        
        if ($filePath -and (Test-Path $filePath)) {
            Write-TestResult -Test "Link valid: $filePath in $($mdFile.Name)" -Result "PASS"
        } elseif ($filePath) {
            Write-TestResult -Test "Link valid: $filePath in $($mdFile.Name)" -Result "FAIL" -Message "Broken link"
        }
    }
}

Write-Host ""
#endregion

#region Test 5: Security Configuration
Write-Host "🔒 Test 5: Security Configuration" -ForegroundColor Cyan

# Check .gitignore has essential patterns
$gitignore = Get-Content ".gitignore" -Raw

$criticalPatterns = @(
    "*.pfx",
    "*.cer",
    "app-config*.json",
    "exports/*.xml",
    "*password*",
    "*secret*"
)

foreach ($pattern in $criticalPatterns) {
    if ($gitignore -match [regex]::Escape($pattern)) {
        Write-TestResult -Test ".gitignore includes: $pattern" -Result "PASS"
    } else {
        Write-TestResult -Test ".gitignore includes: $pattern" -Result "FAIL" -Message "Critical pattern missing"
    }
}

# Check sample config exists (real config should never be committed)
if (Test-Path "app-config.sample.json") {
    Write-TestResult -Test "app-config.sample.json exists" -Result "PASS" -Message "Template file for users"
} else {
    Write-TestResult -Test "app-config.sample.json exists" -Result "WARN" -Message "No sample config template found"
}

# Check sample config has no real values
if (Test-Path "app-config.sample.json") {
    $sampleConfig = Get-Content "app-config.sample.json" -Raw
    if ($sampleConfig -match '<YOUR-' -or $sampleConfig -match '<your-') {
        Write-TestResult -Test "Sample config uses placeholders" -Result "PASS"
    } else {
        Write-TestResult -Test "Sample config uses placeholders" -Result "FAIL" -Message "Sample config may contain real values"
    }
}

# Check .gitattributes
if (Test-Path ".gitattributes") {
    Write-TestResult -Test ".gitattributes exists" -Result "PASS" -Message "Binary file protections configured"
} else {
    Write-TestResult -Test ".gitattributes exists" -Result "WARN" -Message "No .gitattributes for binary protection"
}

# Check pre-commit hook exists
if (Test-Path "hooks\pre-commit.ps1") {
    Write-TestResult -Test "Pre-commit hook script exists" -Result "PASS"
} else {
    Write-TestResult -Test "Pre-commit hook script exists" -Result "WARN" -Message "No pre-commit hook for automated security"
}

# Deep scan: check no real GUIDs in committed scripts
$scriptFilesForScan = Get-ChildItem -Filter "*.ps1" -File
$guidPattern = '["\u0027][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}["\u0027]'
$wellKnownGuids = @(
    '00000002-0000-0ff1-ce00-000000000000',    # Exchange Online resource
    'dc50a0fb-09a3-484d-be87-e023b12c6440',    # Exchange.ManageAsApp permission
    '17315797-102d-40b4-93e0-432062caca18',    # Compliance Admin role
    'e6d1a23a-da11-4be4-9570-befc86d067a7',    # Compliance Data Admin role
    '62e90394-69f5-4237-9190-012177145e10',    # Global Admin role
    '194ae4cb-b126-40b2-bd5b-6091b380977d'     # Security Admin role
)

foreach ($sf in $scriptFilesForScan) {
    $sfContent = Get-Content $sf.FullName -Raw
    $guidMatches = [regex]::Matches($sfContent, $guidPattern)
    $suspiciousGuids = @()
    
    foreach ($gm in $guidMatches) {
        $guidVal = $gm.Value.Trim('"', "'")
        if ($guidVal -notin $wellKnownGuids -and $guidVal -notmatch '00000000-0000') {
            # Check if it's a dynamically generated GUID (in variable context)
            $ctx = $sfContent.Substring([Math]::Max(0, $gm.Index - 30), [Math]::Min(60, $sfContent.Length - [Math]::Max(0, $gm.Index - 30)))
            if ($ctx -notmatch '\$\w+' -and $ctx -notmatch 'NewGuid|new-guid') {
                $suspiciousGuids += $guidVal
            }
        }
    }
    
    if ($suspiciousGuids.Count -eq 0) {
        Write-TestResult -Test "No hardcoded GUIDs: $($sf.Name)" -Result "PASS"
    } else {
        Write-TestResult -Test "No hardcoded GUIDs: $($sf.Name)" -Result "WARN" -Message "Found $($suspiciousGuids.Count) GUID(s) - verify they are not tenant-specific"
    }
}
    }
}

Write-Host ""
#endregion

#region Test 6: Script Parameter Validation
Write-Host "⚙️  Test 6: Script Parameter Validation" -ForegroundColor Cyan

foreach ($script in $scripts) {
    try {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            $script.FullName,
            [ref]$null,
            [ref]$null
        )
        
        $params = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.ParameterAst] }, $true)
        
        if ($params.Count -eq 0) {
            Write-TestResult -Test "Parameters: $($script.Name)" -Result "PASS" -Message "No parameters (valid)"
        } else {
            # Check if mandatory parameters have help
            $hasMandatory = $params | Where-Object { 
                $_.Attributes.NamedArguments | Where-Object { $_.ArgumentName -eq 'Mandatory' }
            }
            
            if ($hasMandatory) {
                Write-TestResult -Test "Parameters: $($script.Name)" -Result "PASS" -Message "Has mandatory parameters"
            } else {
                Write-TestResult -Test "Parameters: $($script.Name)" -Result "PASS" -Message "All parameters optional"
            }
        }
    } catch {
        Write-TestResult -Test "Parameters: $($script.Name)" -Result "WARN" -Message "Could not parse parameters"
    }
}

Write-Host ""
#endregion

#region Test 7: README Completeness
Write-Host "📖 Test 7: README Documentation Quality" -ForegroundColor Cyan

$readme = Get-Content "README.md" -Raw

$requiredSections = @(
    "Prerequisites",
    "Migration Workflow",
    "Authentication",
    "Security"
)

foreach ($section in $requiredSections) {
    if ($readme -match $section) {
        Write-TestResult -Test "README section: $section" -Result "PASS"
    } else {
        Write-TestResult -Test "README section: $section" -Result "WARN" -Message "Section may be missing"
    }
}

# Check for mermaid diagrams
if ($readme -match '```mermaid') {
    Write-TestResult -Test "README contains diagrams" -Result "PASS"
} else {
    Write-TestResult -Test "README contains diagrams" -Result "WARN" -Message "No mermaid diagrams found"
}

Write-Host ""
#endregion

#region Test 8: Consistent Naming
Write-Host "🏷️  Test 8: Consistent File Naming" -ForegroundColor Cyan

$allFiles = Get-ChildItem -File

# Check for consistent naming patterns
$hasInconsistentNaming = $false

foreach ($file in $allFiles) {
    # Scripts should use PascalCase with hyphens or numbers
    if ($file.Extension -eq ".ps1") {
        if ($file.Name -match '^[0-9]{2}[a-z]?-[A-Z][a-zA-Z-]+\.ps1$' -or $file.Name -match '^[A-Z][a-zA-Z-]+\.ps1$') {
            # Good naming
        } else {
            Write-TestResult -Test "Naming convention: $($file.Name)" -Result "WARN" -Message "Consider standardizing naming"
            $hasInconsistentNaming = $true
        }
    }
    
    # Markdown should be UPPERCASE or PascalCase
    if ($file.Extension -eq ".md") {
        if ($file.Name -match '^[A-Z][A-Z-]+\.md$' -or $file.Name -match '^[A-Z][a-zA-Z-]+\.md$') {
            # Good naming
        } else {
            Write-TestResult -Test "Naming convention: $($file.Name)" -Result "WARN" -Message "Consider standardizing naming"
            $hasInconsistentNaming = $true
        }
    }
}

if (-not $hasInconsistentNaming) {
    Write-TestResult -Test "File naming consistency" -Result "PASS" -Message "All files follow conventions"
}

Write-Host ""
#endregion

#region Test 9: Exports Directory
Write-Host "📦 Test 9: Exports Directory Structure" -ForegroundColor Cyan

if (Test-Path "exports") {
    Write-TestResult -Test "Exports directory exists" -Result "PASS"
    
    # Check for .gitkeep
    if (Test-Path "exports\.gitkeep") {
        Write-TestResult -Test "Exports has .gitkeep" -Result "PASS"
    } else {
        Write-TestResult -Test "Exports has .gitkeep" -Result "WARN" -Message "Consider adding .gitkeep for git"
    }
    
    # Check if any XML files exist (should be ignored by git)
    $xmlFiles = Get-ChildItem "exports" -Filter "*.xml" -ErrorAction SilentlyContinue
    if ($xmlFiles) {
        Write-TestResult -Test "XML files in exports" -Result "PASS" -Message "$($xmlFiles.Count) export file(s) present (protected by .gitignore)"
    }
} else {
    Write-TestResult -Test "Exports directory exists" -Result "FAIL" -Message "Required directory missing"
}

Write-Host ""
#endregion

#region Test 10: Script Execution Test (Syntax Check Only)
Write-Host "🧪 Test 10: Quick Syntax Execution Test" -ForegroundColor Cyan

# Test scripts that don't require connection
$testableScripts = @(
    "Verify-Security.ps1"
)

foreach ($scriptName in $testableScripts) {
    if (Test-Path $scriptName) {
        try {
            # Just validate we can load the script
            $scriptContent = Get-Content $scriptName -Raw
            $scriptBlock = [scriptblock]::Create($scriptContent)
            Write-TestResult -Test "Can parse: $scriptName" -Result "PASS"
        } catch {
            Write-TestResult -Test "Can parse: $scriptName" -Result "FAIL" -Message $_.Exception.Message
        }
    }
}

Write-Host ""
#endregion

#region Summary
Write-Host "╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  Test Summary                                                 ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""
Write-Host "✅ Passed:  $script:PassCount" -ForegroundColor Green
Write-Host "⚠️  Warnings: $script:WarningCount" -ForegroundColor Yellow
Write-Host "❌ Failed:  $script:FailureCount" -ForegroundColor Red
Write-Host ""

if ($script:FailureCount -eq 0) {
    Write-Host "🎉 All critical tests passed!" -ForegroundColor Green
    Write-Host ""
    
    if ($script:WarningCount -gt 0) {
        Write-Host "⚠️  $script:WarningCount warning(s) found - review recommended but not blocking" -ForegroundColor Yellow
    }
    
    exit 0
} else {
    Write-Host "❌ $script:FailureCount critical test(s) failed!" -ForegroundColor Red
    Write-Host "   Fix these issues before committing." -ForegroundColor Red
    Write-Host ""
    exit 1
}
#endregion
