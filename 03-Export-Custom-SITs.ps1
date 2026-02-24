<#
.SYNOPSIS
    Export all custom SITs to XML file

.DESCRIPTION
    Exports the complete custom SIT rule pack to an XML file.
    This XML contains all custom Sensitive Information Type definitions.

.PARAMETER OutputPath
    Optional custom output path. Defaults to ./exports/

.EXAMPLE
    .\03-Export-Custom-SITs.ps1
    # Exports to ./exports/source-export-YYYYMMDD-HHMMSS.xml

.EXAMPLE
    .\03-Export-Custom-SITs.ps1 -OutputPath "C:\Temp\my-sits.xml"
    # Exports to custom location

.NOTES
    Must be connected to Security & Compliance PowerShell first.
    Run: .\01-Connect-Tenant.ps1
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath
)

# Check if connected
try {
    $null = Get-DlpSensitiveInformationType -Identity "Credit Card Number" -ErrorAction Stop
} catch {
    Write-Host "❌ Not connected to Security & Compliance PowerShell" -ForegroundColor Red
    Write-Host "   Run: .\01-Connect-Tenant.ps1 first" -ForegroundColor Yellow
    exit 1
}

Write-Host "💾 Exporting custom SITs..." -ForegroundColor Cyan
Write-Host ""

# Check if any custom SITs exist
# Filter for typical custom SIT publishers (exclude Microsoft)
$customSITs = Get-DlpSensitiveInformationType | 
    Where-Object { 
        $_.Publisher -ne "Microsoft Corporation" -and 
        $_.Publisher -notlike "Microsoft.SCCManaged*" 
    }

# Also verify specifically if we found our 'Demo Custom SITs' or similar
if (-not $customSITs) {
    # Fallback to check specific demo SITs
    $customSITs = Get-DlpSensitiveInformationType | Where-Object {$_.Publisher -eq "Demo Custom SITs"}
}

if (-not $customSITs) {
    Write-Host "⚠️  No custom SITs found in this tenant" -ForegroundColor Yellow
    Write-Host "`n💡 Create some first:" -ForegroundColor Cyan
    Write-Host "   Run: .\02-Create-Sample-SITs.ps1" -ForegroundColor Gray
    exit 0
}

Write-Host "📋 Found $($customSITs.Count) custom SITs:" -ForegroundColor Green
$customSITs | ForEach-Object {
    Write-Host "   • $($_.Name)" -ForegroundColor White
}

# Determine output path
if (-not $OutputPath) {
    $exportsDir = Join-Path $PSScriptRoot "exports"
    if (-not (Test-Path $exportsDir)) {
        New-Item -ItemType Directory -Path $exportsDir -Force | Out-Null
    }
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $OutputPath = Join-Path $exportsDir "source-export-$timestamp.xml"
}

# Ensure directory exists
$outputDir = Split-Path $OutputPath -Parent
if (-not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}

# Export the custom rule pack
try {
    Write-Host "`n⏳ Exporting rule pack..." -ForegroundColor Yellow
    
    # Get unique RulePackage IDs
    $uniqueRulePackIds = $customSITs | Select-Object -ExpandProperty RulePackId -Unique
    $exportedFiles = @()
    $failedExports = @()
    
    foreach ($rpId in $uniqueRulePackIds) {
        Write-Host "   Processing RulePack: $rpId" -ForegroundColor Cyan
        
        try {
            $rulePack = Get-DlpSensitiveInformationTypeRulePackage -Identity $rpId -ErrorAction Stop
            
            # Use RP ID for filename to ensure uniqueness
            $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
            
            # Determine path
            if ($uniqueRulePackIds.Count -gt 1 -or -not $OutputPath.EndsWith('.xml')) {
                $dir = Split-Path $OutputPath -Parent
                $finalPath = Join-Path $dir "source-export-${timestamp}-${rpId}.xml"
            } else {
                $finalPath = $OutputPath
            }
            
            # Export bytes directly
            $bytes = $rulePack.SerializedClassificationRuleCollection
            [System.IO.File]::WriteAllBytes($finalPath, $bytes)
            
            Write-Host "   ✅ Exported: $finalPath" -ForegroundColor Green
            $exportedFiles += $finalPath
            
        } catch {
            Write-Host "   ❌ Failed to export RulePack ${rpId}: $($_.Exception.Message)" -ForegroundColor Red
            $failedExports += $rpId
        }
    }
    
    # Display summary
    Write-Host ""
    if ($exportedFiles.Count -gt 0) {
        Write-Host "✅ Export successful! ($($exportedFiles.Count) file(s) created)" -ForegroundColor Green
        Write-Host ""
        
        foreach ($file in $exportedFiles) {
            $fileSize = (Get-Item $file).Length / 1KB
            
            Write-Host "📄 File: $(Split-Path $file -Leaf)" -ForegroundColor Cyan
            Write-Host "   Path: $file" -ForegroundColor Gray
            Write-Host "   Size: $([math]::Round($fileSize, 2)) KB" -ForegroundColor Gray
            
            # Parse and show summary
            # Note: SerializedClassificationRuleCollection is UTF-16 encoded.
            # Use XmlDocument.Load() which auto-detects encoding from the XML declaration/BOM,
            # rather than Get-Content -Encoding UTF8 which would fail on UTF-16 null bytes.
            try {
                $preview = New-Object System.Xml.XmlDocument
                $preview.Load($file)
                # Entities can be directly under Rules or inside Version elements
                $entities = @()
                if ($preview.RulePackage.Rules.Entity) {
                    $entities += @($preview.RulePackage.Rules.Entity)
                }
                if ($preview.RulePackage.Rules.Version) {
                    foreach ($ver in @($preview.RulePackage.Rules.Version)) {
                        if ($ver.Entity) {
                            $entities += @($ver.Entity)
                        }
                    }
                }
                
                Write-Host "   SITs: $($entities.Count)" -ForegroundColor Gray
                foreach ($entity in $entities | Select-Object -First 3) {
                    $sitId = $entity.id
                    $resource = $preview.RulePackage.LocalizedStrings.Resource | 
                        Where-Object { $_.idRef -eq $sitId }
                    if (-not $resource) {
                        $resource = $preview.RulePackage.Rules.LocalizedStrings.Resource | 
                            Where-Object { $_.idRef -eq $sitId }
                    }
                    
                    if ($resource) {
                        $sitName = $resource.Name.'#text'
                        Write-Host "      • $sitName" -ForegroundColor White
                    }
                }
                if ($entities.Count -gt 3) {
                    Write-Host "      ... and $($entities.Count - 3) more" -ForegroundColor Gray
                }

                # Post-export validation: check text processor references
                $rules = $preview.RulePackage.Rules
                $definedProcs = @{}
                foreach ($pType in @('Regex', 'Keyword', 'Function', 'Fingerprint', 'ExtendedKeyword')) {
                    $pNodes = $rules.SelectNodes("//*[local-name()='$pType']")
                    if ($pNodes) {
                        foreach ($pNode in $pNodes) {
                            $procId = $pNode.GetAttribute('id')
                            if ($procId) { $definedProcs[$procId] = $pType }
                        }
                    }
                }
                $missingProcs = @()
                $externalProcs = @()
                $refNodes = $rules.SelectNodes("//*[@idRef]")
                if ($refNodes) {
                    foreach ($refNode in $refNodes) {
                        if ($refNode.LocalName -eq 'Resource') { continue }
                        $refId = $refNode.GetAttribute('idRef')
                        if ($refId -and -not $definedProcs.ContainsKey($refId)) {
                            if ($refId -match '^(CEP_|Func_|Keyword_)') {
                                if ($refId -notin $externalProcs) { $externalProcs += $refId }
                            } else {
                                if ($refId -notin $missingProcs) { $missingProcs += $refId }
                            }
                        }
                    }
                }

                if ($missingProcs.Count -gt 0) {
                    Write-Host ""
                    Write-Host "   ❌ WARNING: Missing text processor references detected!" -ForegroundColor Red
                    foreach ($mp in $missingProcs) {
                        Write-Host "      • $mp" -ForegroundColor Red
                    }
                    Write-Host "      This file will FAIL to import to another tenant." -ForegroundColor Red
                    Write-Host "      Run: .\Validate-ExportXml.ps1 -XmlPath `"$file`"" -ForegroundColor Yellow
                }
                if ($externalProcs.Count -gt 0) {
                    Write-Host "   ⚠️  External refs: $($externalProcs -join ', ')" -ForegroundColor Yellow
                    Write-Host "      These reference Microsoft built-in processors." -ForegroundColor DarkGray
                }
            } catch {
                Write-Host "   (Could not parse XML summary)" -ForegroundColor DarkGray
            }
            Write-Host ""
        }
        
        Write-Host "💡 Next steps:" -ForegroundColor Cyan
        Write-Host "   1. Connect to target tenant: .\01-Connect-Tenant.ps1" -ForegroundColor Gray
        Write-Host "   2. Import each file:" -ForegroundColor Gray
        foreach ($file in $exportedFiles) {
            Write-Host "      .\04-Import-Custom-SITs.ps1 -SourceXmlPath `"$file`"" -ForegroundColor DarkGray
        }
        
        # Save most recent path to clipboard
        Write-Host "`n💾 Latest export path copied to clipboard" -ForegroundColor Green
        $exportedFiles[-1] | Set-Clipboard
        
    } else {
        Write-Host "❌ No files were created" -ForegroundColor Red
    }
    
    if ($failedExports.Count -gt 0) {
        Write-Host "⚠️  Failed to export $($failedExports.Count) rule pack(s)" -ForegroundColor Yellow
    }
    
} catch {
    Write-Host "❌ Export failed: $($_.Exception.Message)" -ForegroundColor Red
    
    if ($_.Exception.Message -like "*not found*") {
        Write-Host "`n💡 The custom rule pack may not exist yet" -ForegroundColor Yellow
        Write-Host "   This happens if no custom SITs have been created." -ForegroundColor Gray
    }
}
