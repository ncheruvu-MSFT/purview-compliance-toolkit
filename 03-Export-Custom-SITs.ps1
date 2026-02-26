<#
.SYNOPSIS
    Export all custom SITs to XML file

.DESCRIPTION
    Exports the complete custom SIT rule pack to an XML file.
    This XML contains all custom Sensitive Information Type definitions.
    
    Keyword dictionaries referenced by any SIT are automatically detected
    and exported as JSON sidecar files alongside the rule pack XML.
    The import script (04-Import-Custom-SITs.ps1) uses these sidecar files
    to recreate dictionaries on the target tenant and remap idRef GUIDs.

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
    
    # ── PASS 1: Load all rule packs into memory ──────────────────────
    # We need all packs loaded first so we can resolve cross-pack
    # text processor references before writing any files.
    $loadedPacks = @{}          # rpId → XmlDocument
    $globalProcessors = @{}     # processorId → @{ Type; Node; SourceRpId }
    $globalResources  = @{}     # resourceIdRef → XmlNode  (LocalizedStrings)
    
    foreach ($rpId in $uniqueRulePackIds) {
        Write-Host "   Loading RulePack: $rpId" -ForegroundColor Cyan
        
        try {
            $rulePack = Get-DlpSensitiveInformationTypeRulePackage -Identity $rpId -ErrorAction Stop
            
            # Parse UTF-16 bytes from API into XmlDocument
            $bytes  = $rulePack.SerializedClassificationRuleCollection
            $xmlDoc = New-Object System.Xml.XmlDocument
            $ms     = New-Object System.IO.MemoryStream(, $bytes)
            $xmlDoc.Load($ms)
            $ms.Dispose()
            
            $loadedPacks[$rpId] = $xmlDoc
            
            # Catalog every text processor defined in this pack
            $rules = $xmlDoc.RulePackage.Rules
            foreach ($pType in @('Regex', 'Keyword', 'Function', 'Fingerprint', 'ExtendedKeyword', 'Dictionary')) {
                $pNodes = $rules.SelectNodes("//*[local-name()='$pType']")
                if ($pNodes) {
                    foreach ($pNode in $pNodes) {
                        $procId = $pNode.GetAttribute('id')
                        if ($procId -and -not $globalProcessors.ContainsKey($procId)) {
                            $globalProcessors[$procId] = @{
                                Type       = $pType
                                Node       = $pNode
                                SourceRpId = $rpId
                            }
                        }
                    }
                }
            }
            
            # Catalog LocalizedStrings resources (for injected processors that
            # may carry their own Resource entries)
            $locStrings = $xmlDoc.RulePackage.LocalizedStrings
            if (-not $locStrings) { $locStrings = $rules.LocalizedStrings }
            if ($locStrings -and $locStrings.Resource) {
                foreach ($res in @($locStrings.Resource)) {
                    $resId = $res.GetAttribute('idRef')
                    if ($resId -and -not $globalResources.ContainsKey($resId)) {
                        $globalResources[$resId] = @{ Node = $res; SourceRpId = $rpId }
                    }
                }
            }
            
        } catch {
            Write-Host "   ❌ Failed to load RulePack ${rpId}: $($_.Exception.Message)" -ForegroundColor Red
            $failedExports += $rpId
        }
    }
    
    Write-Host "   📦 Loaded $($loadedPacks.Count) rule pack(s), $($globalProcessors.Count) text processors catalogued" -ForegroundColor Gray
    
    # ── Load keyword dictionaries ────────────────────────────────────
    # Keyword dictionaries created via New-DlpKeywordDictionary live as
    # separate objects, NOT inside any XML rule pack.  SITs reference
    # them by Identity GUID via <IdMatch idRef="dict-guid"/>.  We load
    # them here so we can (a) recognise dictionary refs during PASS 2
    # and (b) export sidecar files for migration.
    $globalDictionaries = @{}   # identity → dictionary object
    $referencedDictIds  = @{}   # identity → $true  (populated in PASS 2)
    try {
        $allDicts = @(Get-DlpKeywordDictionary -ErrorAction SilentlyContinue)
        foreach ($dictItem in $allDicts) {
            if ($dictItem.Identity) {
                $globalDictionaries[$dictItem.Identity.ToString()] = $dictItem
            }
        }
        if ($allDicts.Count -gt 0) {
            Write-Host "   📖 Loaded $($allDicts.Count) keyword dictionar$(if($allDicts.Count -eq 1){'y'}else{'ies'})" -ForegroundColor Gray
        }
    } catch {
        Write-Host "   ⚠️  Could not load keyword dictionaries: $($_.Exception.Message)" -ForegroundColor Yellow
    }
    
    # ── PASS 2: Resolve missing processors & write files ─────────────
    foreach ($rpId in $loadedPacks.Keys) {
        Write-Host "   Processing RulePack: $rpId" -ForegroundColor Cyan
        
        $xmlDoc = $loadedPacks[$rpId]
        $rules  = $xmlDoc.RulePackage.Rules
        
        # Build local processor set for this pack
        $localProcs = @{}
        foreach ($pType in @('Regex', 'Keyword', 'Function', 'Fingerprint', 'ExtendedKeyword', 'Dictionary')) {
            $pNodes = $rules.SelectNodes("//*[local-name()='$pType']")
            if ($pNodes) {
                foreach ($pNode in $pNodes) {
                    $procId = $pNode.GetAttribute('id')
                    if ($procId) { $localProcs[$procId] = $pType }
                }
            }
        }
        
        # Find missing idRef targets (exclude Resource elements and known built-in prefixes)
        $missingIds = @()
        $refNodes = $rules.SelectNodes("//*[@idRef]")
        if ($refNodes) {
            foreach ($refNode in $refNodes) {
                if ($refNode.LocalName -eq 'Resource') { continue }
                $refId = $refNode.GetAttribute('idRef')
                if ($refId -and -not $localProcs.ContainsKey($refId) `
                         -and $refId -notmatch '^(CEP_|Func_|Keyword_)') {
                    if ($refId -notin $missingIds) { $missingIds += $refId }
                }
            }
        }
        
        # Inject missing processors from sibling rule packs
        $injectedCount = 0
        if ($missingIds.Count -gt 0) {
            # Find (or create) the LocalizedStrings container for injected resources
            $locStringsNode = $xmlDoc.RulePackage.SelectSingleNode('LocalizedStrings')
            if (-not $locStringsNode) {
                $locStringsNode = $rules.SelectSingleNode('LocalizedStrings')
            }
            
            foreach ($mid in $missingIds) {
                if ($globalProcessors.ContainsKey($mid)) {
                    $src = $globalProcessors[$mid]
                    # Import the processor node into this document and append to <Rules>
                    $imported = $xmlDoc.ImportNode($src.Node, $true)
                    $rules.AppendChild($imported) | Out-Null
                    $injectedCount++
                    Write-Host "      🔧 Injected $($src.Type) '$mid' from RulePack $($src.SourceRpId)" -ForegroundColor DarkYellow
                    
                    # Also inject the matching LocalizedStrings Resource if it exists
                    if ($locStringsNode -and $globalResources.ContainsKey($mid)) {
                        $resSrc = $globalResources[$mid]
                        # Only inject if not already present
                        $existing = $locStringsNode.SelectSingleNode("Resource[@idRef='$mid']")
                        if (-not $existing) {
                            $importedRes = $xmlDoc.ImportNode($resSrc.Node, $true)
                            $locStringsNode.AppendChild($importedRes) | Out-Null
                        }
                    }
                } elseif ($globalDictionaries.ContainsKey($mid)) {
                    # This idRef points to a keyword dictionary (separate object).
                    # It will be exported as a sidecar file for the import script
                    # to recreate on the target tenant.
                    $dictName = $globalDictionaries[$mid].Name
                    $referencedDictIds[$mid] = $true
                    Write-Host "      📖 Dictionary ref '$mid' → '$dictName' (will export sidecar)" -ForegroundColor DarkCyan
                } else {
                    Write-Host "      ⚠️  Cannot resolve processor '$mid' — not found in any exported rule pack or dictionary" -ForegroundColor Yellow
                }
            }
            
            if ($injectedCount -gt 0) {
                Write-Host "      ✅ Injected $injectedCount missing text processor(s) from sibling rule packs" -ForegroundColor Green
            }
        }
        
        # Determine output path
        $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
        if ($loadedPacks.Count -gt 1 -or -not $OutputPath.EndsWith('.xml')) {
            $dir = Split-Path $OutputPath -Parent
            $finalPath = Join-Path $dir "source-export-${timestamp}-${rpId}.xml"
        } else {
            $finalPath = $OutputPath
        }
        
        # Update the XML declaration to reflect UTF-8 encoding
        if ($xmlDoc.FirstChild -is [System.Xml.XmlDeclaration]) {
            $xmlDoc.FirstChild.Encoding = 'utf-8'
        }
        
        # Write as UTF-8 (with BOM so XmlDocument.Load auto-detects)
        $utf8Bom = New-Object System.Text.UTF8Encoding($true)
        $writerSettings = New-Object System.Xml.XmlWriterSettings
        $writerSettings.Encoding = $utf8Bom
        $writerSettings.Indent = $true
        $writer = [System.Xml.XmlWriter]::Create($finalPath, $writerSettings)
        $xmlDoc.Save($writer)
        $writer.Close()
        
        Write-Host "   ✅ Exported (UTF-8): $finalPath" -ForegroundColor Green
        $exportedFiles += $finalPath
    }
    
    # ── Export referenced keyword dictionaries as sidecar files ─────
    $dictExportFiles = @()
    if ($referencedDictIds.Count -gt 0) {
        Write-Host ""
        Write-Host "📖 Exporting $($referencedDictIds.Count) referenced keyword dictionar$(if($referencedDictIds.Count -eq 1){'y'}else{'ies'})..." -ForegroundColor Cyan
        
        foreach ($dictId in $referencedDictIds.Keys) {
            $dictObj = $globalDictionaries[$dictId]
            $dictName = $dictObj.Name
            $safeName = $dictName -replace '[^\w\-]', '_'
            $dictJsonPath = Join-Path (Split-Path $OutputPath -Parent) "dictionary-${safeName}.json"
            $dictTxtPath  = Join-Path (Split-Path $OutputPath -Parent) "dictionary-${safeName}-keywords.txt"
            
            # Build sidecar JSON with metadata
            $keywords = $dictObj.KeywordDictionary
            $keywordLines = @($keywords -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            
            $sidecar = @{
                sourceIdentity = $dictId
                name           = $dictName
                description    = $dictObj.Description
                keywordCount   = $keywordLines.Count
                keywordsFile   = (Split-Path $dictTxtPath -Leaf)
                exportedAt     = (Get-Date -Format 'o')
            }
            
            $sidecar | ConvertTo-Json -Depth 5 | Out-File -FilePath $dictJsonPath -Encoding UTF8 -Force
            $keywords | Out-File -FilePath $dictTxtPath -Encoding UTF8 -Force
            
            Write-Host "   ✅ $dictName" -ForegroundColor Green
            Write-Host "      Metadata: $(Split-Path $dictJsonPath -Leaf)" -ForegroundColor Gray
            Write-Host "      Keywords: $(Split-Path $dictTxtPath -Leaf) ($($keywordLines.Count) terms)" -ForegroundColor Gray
            $dictExportFiles += $dictJsonPath
            $dictExportFiles += $dictTxtPath
        }
    }
    
    # ── Display summary ──────────────────────────────────────────────
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
                foreach ($pType in @('Regex', 'Keyword', 'Function', 'Fingerprint', 'ExtendedKeyword', 'Dictionary')) {
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

                # Separate dictionary refs from truly missing processors
                $dictRefs = @()
                $trulyMissing = @()
                foreach ($mp in $missingProcs) {
                    if ($referencedDictIds.ContainsKey($mp)) {
                        $dictRefs += $mp
                    } else {
                        $trulyMissing += $mp
                    }
                }
                
                if ($dictRefs.Count -gt 0) {
                    Write-Host "   📖 Dictionary refs: $($dictRefs.Count) (sidecar files exported)" -ForegroundColor DarkCyan
                    foreach ($dr in $dictRefs) {
                        $dn = if ($globalDictionaries.ContainsKey($dr)) { $globalDictionaries[$dr].Name } else { '?' }
                        Write-Host "      • $dr → $dn" -ForegroundColor DarkCyan
                    }
                }
                if ($trulyMissing.Count -gt 0) {
                    Write-Host ""
                    Write-Host "   ❌ WARNING: Missing text processor references still detected!" -ForegroundColor Red
                    foreach ($mp in $trulyMissing) {
                        Write-Host "      • $mp" -ForegroundColor Red
                    }
                    Write-Host "      This file may FAIL to import to another tenant." -ForegroundColor Red
                    Write-Host "      These processors were not found in any exported rule pack." -ForegroundColor Yellow
                    Write-Host "      Run: .\Validate-ExportXml.ps1 -XmlPath `"$file`"" -ForegroundColor Yellow
                }
                if ($externalProcs.Count -gt 0) {
                    Write-Host "   ⚠️  External refs: $($externalProcs -join ', ')" -ForegroundColor Yellow
                    Write-Host "      These reference Microsoft built-in processors." -ForegroundColor DarkGray
                }
                if ($trulyMissing.Count -eq 0 -and $dictRefs.Count -eq 0 -and $externalProcs.Count -eq 0) {
                    Write-Host "   ✅ All text processor references are resolved" -ForegroundColor Green
                } elseif ($trulyMissing.Count -eq 0 -and $externalProcs.Count -eq 0) {
                    Write-Host "   ✅ All refs resolved (dictionary refs via sidecar files)" -ForegroundColor Green
                }
            } catch {
                Write-Host "   (Could not parse XML summary)" -ForegroundColor DarkGray
            }
            Write-Host ""
        }
        
        Write-Host "💡 Next steps:" -ForegroundColor Cyan
        Write-Host "   1. Connect to target tenant: .\01-Connect-Tenant.ps1" -ForegroundColor Gray
        if ($dictExportFiles.Count -gt 0) {
            Write-Host "   2. Dictionary sidecar files will be auto-detected during import" -ForegroundColor Gray
        }
        $stepNum = if ($dictExportFiles.Count -gt 0) { 3 } else { 2 }
        Write-Host "   ${stepNum}. Import each file:" -ForegroundColor Gray
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
