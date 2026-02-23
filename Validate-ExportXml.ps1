<#
.SYNOPSIS
    Validate and preview an exported SIT rule pack XML file.

.DESCRIPTION
    Checks encoding, structure, and content of XML files exported via
    SerializedClassificationRuleCollection (from Get-DlpSensitiveInformationTypeRulePackage).

    Key facts about the exported bytes:
      - The API returns UTF-16 (LE) encoded XML with a BOM (0xFF 0xFE).
      - The XML declaration reads: <?xml version="1.0" encoding="utf-16"?>
      - Attempting to read with Get-Content -Encoding UTF8 will FAIL because
        UTF-16 interleaves 0x00 (null) bytes between ASCII characters.
      - Use [System.Xml.XmlDocument]::Load() which auto-detects encoding from
        the XML declaration and BOM, or use Get-Content -Encoding Unicode.

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

            $result.Valid = $true
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
                Write-Host "   ⚠️  Expected UTF-16 from SerializedClassificationRuleCollection" -ForegroundColor Yellow
                Write-Host "      Import may still work, but verify the source." -ForegroundColor Yellow
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
        Write-Host "   • 'hexadecimal value 0x00' → File is UTF-16 but was re-saved as UTF-8" -ForegroundColor Gray
        Write-Host "   • 'Name cannot begin with . character' → Same encoding mismatch" -ForegroundColor Gray
        Write-Host "   • Fix: re-export using raw bytes: [IO.File]::WriteAllBytes()" -ForegroundColor Gray
        Write-Host "   • Do NOT use Get-Content -Encoding UTF8 to read/re-save these files" -ForegroundColor Gray
    }
    else {
        Write-Host "✅ All files are valid and ready for import." -ForegroundColor Green
        Write-Host "   Import with: .\04-Import-Custom-SITs.ps1 -SourceXmlPath <file>" -ForegroundColor Gray
    }
}
