<#
.SYNOPSIS
    Validate and preview an exported SIT rule pack XML file.

.DESCRIPTION
    Checks encoding, structure, and content of XML files exported via
    SerializedClassificationRuleCollection (from Get-DlpSensitiveInformationTypeRulePackage).

    Key facts about the exported bytes:
      - The export script now converts API output to UTF-8 (with BOM).
      - The XML declaration reads: <?xml version="1.0" encoding="utf-8"?>
      - Legacy exports may still be UTF-16 LE (BOM: 0xFF 0xFE); both are supported.
      - Use [System.Xml.XmlDocument]::Load() which auto-detects encoding from
        the XML declaration and BOM.

.PARAMETER XmlPath
    Path to one or more XML files to validate.

.EXAMPLE
    .\Validate-ExportXml.ps1 -XmlPath ".\exports\source-export-20260223-092037.xml"

.EXAMPLE
    Get-ChildItem .\exports\*.xml | .\Validate-ExportXml.ps1
    # Validate all exports

.NOTES
    Does NOT require a connection to Security & Compliance PowerShell.
    Safe to run offline for pre-import validation.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [Alias("FullName", "Path")]
    [string[]]$XmlPath
)

begin {
    $totalFiles = 0
    $passedFiles = 0
    $failedFiles = 0

    function Test-ExportXml {
        param([string]$FilePath)

        $result = [PSCustomObject]@{
            File       = Split-Path $FilePath -Leaf
            FullPath   = $FilePath
            Valid      = $false
            Encoding   = "Unknown"
            SizeKB     = 0
            SITCount   = 0
            SITs       = @()
            RulePackId = ""
            Publisher  = ""
            Errors     = @()
            Warnings   = @()
            DefinedProcessors    = @()
            ReferencedProcessors = @()
            MissingProcessors    = @()
            ExternalProcessors   = @()
            DictionaryRefs       = @()
        }

        # --- Check file exists ---
        if (-not (Test-Path $FilePath)) {
            $result.Errors += "File not found: $FilePath"
            return $result
        }

        $result.SizeKB = [math]::Round((Get-Item $FilePath).Length / 1KB, 2)

        # --- Detect encoding from first bytes ---
        try {
            $rawBytes = [System.IO.File]::ReadAllBytes($FilePath)

            if ($rawBytes.Length -ge 2) {
                if ($rawBytes[0] -eq 0xFF -and $rawBytes[1] -eq 0xFE) {
                    $result.Encoding = "UTF-16 LE (BOM)"
                }
                elseif ($rawBytes[0] -eq 0xFE -and $rawBytes[1] -eq 0xFF) {
                    $result.Encoding = "UTF-16 BE (BOM)"
                }
                elseif ($rawBytes.Length -ge 3 -and $rawBytes[0] -eq 0xEF -and $rawBytes[1] -eq 0xBB -and $rawBytes[2] -eq 0xBF) {
                    $result.Encoding = "UTF-8 (BOM)"
                }
                else {
                    # Check for null bytes in first 100 chars → likely UTF-16 without BOM
                    $sampleLen = [math]::Min(200, $rawBytes.Length)
                    $nullCount = ($rawBytes[0..($sampleLen - 1)] | Where-Object { $_ -eq 0 }).Count
                    if ($nullCount -gt ($sampleLen * 0.3)) {
                        $result.Encoding = "UTF-16 (no BOM, detected)"
                    }
                    else {
                        $result.Encoding = "UTF-8 (no BOM)"
                    }
                }
            }
        }
        catch {
            $result.Errors += "Failed to read raw bytes: $($_.Exception.Message)"
        }

        # --- Parse XML using encoding-safe method ---
        try {
            $xmlDoc = New-Object System.Xml.XmlDocument
            # XmlDocument.Load() reads the XML declaration to determine encoding.
            # This correctly handles UTF-16, UTF-8, and any declared encoding.
            $xmlDoc.Load($FilePath)

            # --- Validate structure ---
            if (-not $xmlDoc.RulePackage) {
                $result.Errors += "Missing root <RulePackage> element"
                return $result
            }

            # RulePack metadata
            $rulePackNode = $xmlDoc.RulePackage.RulePack
            if ($rulePackNode) {
                $result.RulePackId = $rulePackNode.id
                $publisherDetails = $rulePackNode.Details.LocalizedDetails
                if ($publisherDetails) {
                    $result.Publisher = $publisherDetails.PublisherName
                }
            }
            else {
                $result.Errors += "Missing <RulePack> metadata element"
            }

            # Rules / Entities
            $rules = $xmlDoc.RulePackage.Rules
            if (-not $rules) {
                $result.Errors += "Missing <Rules> element"
                return $result
            }

            # Entities can be directly under Rules or inside Version elements
            $entities = @()
            if ($rules.Entity) {
                $entities += @($rules.Entity)
            }
            if ($rules.Version) {
                $versions = @($rules.Version)
                foreach ($ver in $versions) {
                    if ($ver.Entity) {
                        $entities += @($ver.Entity)
                    }
                }
            }

            if ($entities.Count -eq 0) {
                $result.Errors += "No <Entity> elements found (no SITs defined)"
                return $result
            }

            $result.SITCount = $entities.Count

            # Resolve names from LocalizedStrings
            $localizedStrings = $rules.LocalizedStrings
            foreach ($entity in $entities) {
                $sitId = $entity.id
                $sitInfo = [PSCustomObject]@{
                    Id          = $sitId
                    Name        = "(unnamed)"
                    Description = ""
                    Confidence  = $entity.recommendedConfidence
                    Patterns    = 0
                }

                if ($entity.Pattern) {
                    $sitInfo.Patterns = @($entity.Pattern).Count
                }

                if ($localizedStrings) {
                    $resource = $localizedStrings.Resource | Where-Object { $_.idRef -eq $sitId }
                    if ($resource) {
                        $sitInfo.Name = $resource.Name.'#text'
                        $sitInfo.Description = $resource.Description.'#text'
                    }
                }

                $result.SITs += $sitInfo
            }

            # --- Validate text processor references ---
            $definedProcs = @{}
            $processorTypes = @('Regex', 'Keyword', 'Function', 'Fingerprint', 'ExtendedKeyword', 'Dictionary')
            foreach ($pType in $processorTypes) {
                $pNodes = $rules.SelectNodes("//*[local-name()='$pType']")
                if ($pNodes) {
                    foreach ($pNode in $pNodes) {
                        $procId = $pNode.GetAttribute('id')
                        if ($procId) {
                            $definedProcs[$procId] = $pType
                        }
                    }
                }
            }
            $result.DefinedProcessors = @($definedProcs.Keys)

            $referencedProcs = @{}
            $refNodes = $rules.SelectNodes("//*[@idRef]")
            if ($refNodes) {
                foreach ($refNode in $refNodes) {
                    $localName = $refNode.LocalName
                    if ($localName -eq 'Resource') { continue }
                    $refId = $refNode.GetAttribute('idRef')
                    if ($refId -and -not $referencedProcs.ContainsKey($refId)) {
                        $referencedProcs[$refId] = $localName
                    }
                }
            }
            $result.ReferencedProcessors = @($referencedProcs.Keys)

            foreach ($refId in $referencedProcs.Keys) {
                if (-not $definedProcs.ContainsKey($refId)) {
                    if ($refId -match '^(CEP_|Func_|Keyword_)') {
                        $result.ExternalProcessors += $refId
                        $result.Warnings += "External text processor reference: '$refId' (built-in, may not exist in target tenant)"
                    } elseif ($refId -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
                        # GUID-shaped idRef — likely a keyword dictionary reference
                        $result.DictionaryRefs += $refId
                        $result.Warnings += "Possible keyword dictionary reference: '$refId' (external to XML, needs sidecar file for migration)"
                    } else {
                        $result.MissingProcessors += $refId
                        $result.Errors += "Missing text processor: '$refId' referenced by $($referencedProcs[$refId]) but not defined in XML"
                        $result.Valid = $false
                    }
                }
            }

            if ($result.MissingProcessors.Count -eq 0 -and $result.Errors.Count -eq 0) {
                $result.Valid = $true
            }
        }
        catch {
            $result.Errors += "XML parse error: $($_.Exception.Message)"
        }

        return $result
    }
}

process {
    foreach ($path in $XmlPath) {
        $totalFiles++

        # Resolve wildcards
        $resolvedPaths = Resolve-Path $path -ErrorAction SilentlyContinue
        if (-not $resolvedPaths) {
            Write-Host "❌ Not found: $path" -ForegroundColor Red
            $failedFiles++
            continue
        }

        foreach ($resolved in $resolvedPaths) {
            $result = Test-ExportXml -FilePath $resolved.Path

            Write-Host ""
            Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor DarkGray
            Write-Host "📄 File: $($result.File)" -ForegroundColor Cyan
            Write-Host "   Path: $($result.FullPath)" -ForegroundColor Gray
            Write-Host "   Size: $($result.SizeKB) KB" -ForegroundColor Gray
            Write-Host "   Encoding: $($result.Encoding)" -ForegroundColor Gray

            if ($result.Encoding -like "*UTF-8*") {
                Write-Host "   ℹ️  UTF-8 encoded (converted from API's native UTF-16 during export)" -ForegroundColor DarkGray
            }

            if ($result.Valid) {
                $passedFiles++
                Write-Host "   Status: ✅ VALID" -ForegroundColor Green
                Write-Host ""

                if ($result.Publisher) {
                    Write-Host "   Publisher: $($result.Publisher)" -ForegroundColor Gray
                }
                if ($result.RulePackId) {
                    Write-Host "   RulePackId: $($result.RulePackId)" -ForegroundColor Gray
                }
                Write-Host "   SIT Count: $($result.SITCount)" -ForegroundColor Green
                Write-Host ""

                foreach ($sit in $result.SITs) {
                    Write-Host "   • $($sit.Name)" -ForegroundColor White
                    Write-Host "     ID: $($sit.Id)" -ForegroundColor DarkGray
                    if ($sit.Description) {
                        Write-Host "     Desc: $($sit.Description)" -ForegroundColor DarkGray
                    }
                    Write-Host "     Confidence: $($sit.Confidence) | Patterns: $($sit.Patterns)" -ForegroundColor DarkGray
                }

                # Text processor validation
                Write-Host ""
                Write-Host "   Text Processors:" -ForegroundColor Cyan
                Write-Host "     Defined:    $($result.DefinedProcessors.Count)" -ForegroundColor Gray
                Write-Host "     Referenced: $($result.ReferencedProcessors.Count)" -ForegroundColor Gray

                if ($result.MissingProcessors.Count -gt 0) {
                    Write-Host ""
                    Write-Host "   ❌ MISSING text processors (will cause import failure):" -ForegroundColor Red
                    foreach ($mp in $result.MissingProcessors) {
                        Write-Host "     • $mp" -ForegroundColor Red
                    }
                    Write-Host ""
                    Write-Host "   These processors are referenced but NOT defined in the XML." -ForegroundColor Yellow
                    Write-Host "   The import WILL FAIL with 'Invalid text processor reference' error." -ForegroundColor Yellow
                    Write-Host "   Fix: add the missing Regex/Keyword definitions, or re-export" -ForegroundColor Yellow
                    Write-Host "   the source including ALL rule packs." -ForegroundColor Yellow
                }

                if ($result.DictionaryRefs.Count -gt 0) {
                    Write-Host ""
                    Write-Host "   📖 Keyword dictionary references ($($result.DictionaryRefs.Count)):" -ForegroundColor DarkCyan
                    foreach ($dr in $result.DictionaryRefs) {
                        Write-Host "     • $dr" -ForegroundColor DarkCyan
                    }
                    Write-Host "   These reference keyword dictionaries (created via New-DlpKeywordDictionary)." -ForegroundColor Gray
                    Write-Host "   Dictionary sidecar files must exist for migration (exported by 03-Export-Custom-SITs.ps1)." -ForegroundColor Gray
                    Write-Host "   The import script (04-Import-Custom-SITs.ps1) will recreate them on the target." -ForegroundColor Gray
                }

                if ($result.ExternalProcessors.Count -gt 0) {
                    Write-Host ""
                    Write-Host "   ⚠️  External text processor references (built-in):" -ForegroundColor Yellow
                    foreach ($ep in $result.ExternalProcessors) {
                        Write-Host "     • $ep" -ForegroundColor Yellow
                    }
                    Write-Host "   These reference Microsoft's built-in rule pack." -ForegroundColor Gray
                    Write-Host "   Import will succeed ONLY if these exist in the target tenant." -ForegroundColor Gray
                }

                if ($result.MissingProcessors.Count -eq 0 -and $result.ExternalProcessors.Count -eq 0 -and $result.DictionaryRefs.Count -eq 0) {
                    Write-Host "     ✅ All references are self-contained" -ForegroundColor Green
                } elseif ($result.MissingProcessors.Count -eq 0) {
                    Write-Host "     ✅ All references resolvable (dict refs via sidecar, externals via built-in)" -ForegroundColor Green
                }

                if ($result.Warnings.Count -gt 0) {
                    Write-Host ""
                    foreach ($warn in $result.Warnings) {
                        Write-Host "   ⚠️  $warn" -ForegroundColor Yellow
                    }
                }
            }
            else {
                $failedFiles++
                Write-Host "   Status: ❌ INVALID" -ForegroundColor Red
                foreach ($err in $result.Errors) {
                    Write-Host "   Error: $err" -ForegroundColor Red
                }
            }
        }
    }
}

end {
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor DarkGray
    Write-Host "📊 Validation Summary" -ForegroundColor Cyan
    Write-Host "   Total files: $totalFiles" -ForegroundColor Gray
    Write-Host "   Passed: $passedFiles" -ForegroundColor Green
    Write-Host "   Failed: $failedFiles" -ForegroundColor $(if ($failedFiles -gt 0) { "Red" } else { "Gray" })
    Write-Host ""

    if ($failedFiles -gt 0) {
        Write-Host "💡 Common issues:" -ForegroundColor Yellow
        Write-Host "   • 'hexadecimal value 0x00' → File is UTF-16 but was re-saved incorrectly" -ForegroundColor Gray
        Write-Host "   • 'Name cannot begin with . character' → Same encoding mismatch" -ForegroundColor Gray
        Write-Host "   • 'Missing text processor' → XML references undefined Regex/Keyword/Function" -ForegroundColor Gray
        Write-Host '   • Fix encoding: re-export with the latest 03-Export-Custom-SITs.ps1 (outputs UTF-8)' -ForegroundColor Gray
        Write-Host "   • Fix text processors: include missing definitions or re-export all rule packs" -ForegroundColor Gray
    }
    else {
        Write-Host "✅ All files are valid and ready for import." -ForegroundColor Green
        Write-Host '   Import with: .\04-Import-Custom-SITs.ps1 -SourceXmlPath <file>' -ForegroundColor Gray
    }
}
