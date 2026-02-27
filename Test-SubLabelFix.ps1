<#
.SYNOPSIS
    Mock-based test for the sub-label same-name fix in 06-Import-SensitivityLabels.ps1

.DESCRIPTION
    Simulates the Step 3 label lookup logic without a live tenant connection.
    Verifies that a sub-label sharing a DisplayName with a parent label is
    correctly CREATED rather than incorrectly "updated" against the parent.

.NOTES
    Run:  .\Test-SubLabelFix.ps1
#>

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Sub-Label Same-Name Fix — Mock Test" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

$pass  = 0
$fail  = 0
$cases = @()

# ── Mock the tenant label store ───────────────────────────────────────
# Simulates labels already on the target after Step 2 (parents created).
# Key:   DisplayName  (what Get-Label -Identity resolves by)
# ParentId: $null = parent label, <guid> = sub-label
$mockStore = @(
    [PSCustomObject]@{ Guid = 'PARENT-AA'; DisplayName = 'Anyone (unrestricted)'; ParentId = $null        }
    [PSCustomObject]@{ Guid = 'PARENT-BB'; DisplayName = 'All Employees';          ParentId = $null        }
    [PSCustomObject]@{ Guid = 'PARENT-CC'; DisplayName = 'Confidential';           ParentId = $null        }
    [PSCustomObject]@{ Guid = 'PARENT-DD'; DisplayName = 'Highly Confidential';    ParentId = $null        }
    # Sub-label that already exists (created in a previous run)
    [PSCustomObject]@{ Guid = 'SUB-EXIST'; DisplayName = 'Trusted People';         ParentId = 'PARENT-CC'  }
)

# Simulates:  Get-Label -Identity <name>
function Mock-GetLabelByIdentity {
    param([string]$Identity)
    $mockStore | Where-Object { $_.DisplayName -eq $Identity } | Select-Object -First 1
}

# Simulates:  Get-Label  (full list, for the fallback scan)
function Mock-GetAllLabels { $mockStore }

# ── Core logic extracted from 06-Import-SensitivityLabels.ps1 Step 3 ──
# Returns: 'create' | 'update' | 'wrong-update'
function Invoke-SubLabelLookup {
    param(
        [string]$DisplayName,
        [string]$TargetParentGuid   # the remapped parent GUID on the target
    )

    $candidateLabel = Mock-GetLabelByIdentity -Identity $DisplayName
    $existing = $null

    if ($candidateLabel) {
        $candidateParent = if ($candidateLabel.ParentId) { $candidateLabel.ParentId.ToString() } else { '' }
        if ($candidateParent -eq $TargetParentGuid) {
            $existing = $candidateLabel          # correct sub-label found fast
        } else {
            # Name collision — full scan to find sub-label under the right parent
            $existing = Mock-GetAllLabels | Where-Object {
                $_.DisplayName -eq $DisplayName -and
                $_.ParentId    -and $_.ParentId.ToString() -eq $TargetParentGuid
            } | Select-Object -First 1
        }
    }

    if ($existing) {
        # Safety check: did we accidentally grab the parent?
        if (-not $existing.ParentId) {
            return 'wrong-update'   # bug: would update the parent label
        }
        return 'update'             # legitimately updating an existing sub-label
    }
    return 'create'                 # correctly creating a new sub-label
}

# ── Test cases ────────────────────────────────────────────────────────
$cases = @(
    @{
        Name            = 'Sub-label shares name with parent (Anyone unrestricted under Confidential)'
        DisplayName     = 'Anyone (unrestricted)'
        TargetParentGuid = 'PARENT-CC'
        Expected        = 'create'
        Description     = 'Parent "Anyone (unrestricted)" exists; sub-label under Confidential does NOT yet exist → must CREATE'
    }
    @{
        Name            = 'Sub-label shares name with parent (All Employees under Highly Confidential)'
        DisplayName     = 'All Employees'
        TargetParentGuid = 'PARENT-DD'
        Expected        = 'create'
        Description     = 'Parent "All Employees" exists; sub-label under Highly Confidential does NOT yet exist → must CREATE'
    }
    @{
        Name            = 'Sub-label with unique name (does not exist yet)'
        DisplayName     = 'Specified People'
        TargetParentGuid = 'PARENT-DD'
        Expected        = 'create'
        Description     = 'No label with this name exists at all → must CREATE'
    }
    @{
        Name            = 'Sub-label that already exists correctly (Trusted People under Confidential)'
        DisplayName     = 'Trusted People'
        TargetParentGuid = 'PARENT-CC'
        Expected        = 'update'
        Description     = 'Sub-label already exists under the correct parent → must UPDATE (idempotent re-run)'
    }
    @{
        Name            = 'Sub-label with unique name that IS the parent itself (should not match)'
        DisplayName     = 'Confidential'
        TargetParentGuid = 'PARENT-DD'
        Expected        = 'create'
        Description     = '"Confidential" exists only as a top-level parent; sub-label under Highly Confidential does not exist → must CREATE'
    }
)

# ── Run tests ─────────────────────────────────────────────────────────
foreach ($tc in $cases) {
    $result = Invoke-SubLabelLookup -DisplayName $tc.DisplayName -TargetParentGuid $tc.TargetParentGuid

    if ($result -eq $tc.Expected) {
        Write-Host "  ✅ PASS  $($tc.Name)" -ForegroundColor Green
        Write-Host "          Result: $result  |  $($tc.Description)" -ForegroundColor DarkGray
        $pass++
    } elseif ($result -eq 'wrong-update') {
        Write-Host "  ❌ FAIL  $($tc.Name)" -ForegroundColor Red
        Write-Host "          BUG: would have updated the PARENT label instead of creating the sub-label!" -ForegroundColor Red
        Write-Host "          Expected: $($tc.Expected)  |  Got: $result" -ForegroundColor Red
        $fail++
    } else {
        Write-Host "  ❌ FAIL  $($tc.Name)" -ForegroundColor Red
        Write-Host "          Expected: $($tc.Expected)  |  Got: $result" -ForegroundColor Red
        Write-Host "          $($tc.Description)" -ForegroundColor DarkGray
        $fail++
    }
    Write-Host ""
}

# ── Summary ───────────────────────────────────────────────────────────
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Results:  $pass passed   $fail failed   ($($cases.Count) total)" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

exit $fail
