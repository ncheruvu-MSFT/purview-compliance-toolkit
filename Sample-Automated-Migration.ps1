<#
.SYNOPSIS
    Automated SIT Migration using Certificate-Based Authentication

.DESCRIPTION
    This is a sample automation script demonstrating how to use app-only
    authentication for unattended SIT migration between tenants.
    
    This script:
    1. Connects to source tenant with certificate
    2. Exports all custom SITs
    3. Disconnects from source
    4. Connects to target tenant with certificate
    5. Imports SITs to target tenant
    6. Disconnects from target
    7. Sends notification (optional)

.PARAMETER SourceConfigPath
    Path to source tenant app-config.json file

.PARAMETER TargetConfigPath
    Path to target tenant app-config.json file

.PARAMETER NotificationEmail
    Optional email address for completion notification

.PARAMETER UseAzureKeyVault
    If specified, retrieves certificate passwords from Azure Key Vault

.PARAMETER KeyVaultName
    Name of Azure Key Vault containing certificate passwords

.EXAMPLE
    .\Sample-Automated-Migration.ps1 `
        -SourceConfigPath ".\source-app-config.json" `
        -TargetConfigPath ".\target-app-config.json"

.EXAMPLE
    .\Sample-Automated-Migration.ps1 `
        -SourceConfigPath ".\source-app-config.json" `
        -TargetConfigPath ".\target-app-config.json" `
        -UseAzureKeyVault `
        -KeyVaultName "my-keyvault"

.NOTES
    Prerequisites:
    - App registrations created in both tenants (run 00-Setup-AppRegistration.ps1)
    - Certificates installed or .pfx files accessible
    - ExchangeOnlineManagement module installed
    
    For Azure Key Vault:
    - Az.KeyVault module installed
    - Appropriate permissions to access secrets

    Ideal for:
    - Scheduled tasks
    - Azure Automation runbooks
    - CI/CD pipelines
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path $_ })]
    [string]$SourceConfigPath,

    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path $_ })]
    [string]$TargetConfigPath,

    [Parameter(Mandatory = $false)]
    [string]$NotificationEmail,

    [Parameter(Mandatory = $false)]
    [switch]$UseAzureKeyVault,

    [Parameter(Mandatory = $false)]
    [string]$KeyVaultName
)

$ErrorActionPreference = "Stop"
$ScriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path

#region Helper Functions
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Success', 'Warning', 'Error')]
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $colors = @{
        'Info' = 'Cyan'
        'Success' = 'Green'
        'Warning' = 'Yellow'
        'Error' = 'Red'
    }
    
    $logMessage = "[$timestamp] [$Level] $Message"
    Write-Host $logMessage -ForegroundColor $colors[$Level]
    
    # Optional: Write to log file
    $logFile = Join-Path $ScriptPath "migration-log-$(Get-Date -Format 'yyyyMMdd').log"
    $logMessage | Out-File -FilePath $logFile -Append
}

function Get-CertificatePassword {
    param(
        [string]$TenantName,
        [string]$KeyVaultName
    )
    
    if ($UseAzureKeyVault) {
        Write-Log "Retrieving certificate password from Azure Key Vault..." -Level Info
        
        # Connect to Azure if not already connected
        $context = Get-AzContext -ErrorAction SilentlyContinue
        if (-not $context) {
            Connect-AzAccount | Out-Null
        }
        
        # Get secret from Key Vault
        $secretName = "$TenantName-CertPassword"
        $secret = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $secretName
        return $secret.SecretValue
    } else {
        # For demo/testing - prompt for password
        # In production, use Key Vault or other secure credential store
        Write-Log "Enter certificate password for $TenantName tenant:" -Level Warning
        return Read-Host -AsSecureString -Prompt "Password"
    }
}

function Send-NotificationEmail {
    param(
        [string]$To,
        [string]$Subject,
        [string]$Body,
        [bool]$Success
    )
    
    # This is a placeholder - implement based on your email service
    # Options: Send-MailMessage, Microsoft Graph API, SendGrid, etc.
    
    Write-Log "Email notification would be sent to: $To" -Level Info
    Write-Log "Subject: $Subject" -Level Info
    
    <#
    # Example using Microsoft Graph
    $mailParams = @{
        Message = @{
            Subject = $Subject
            Body = @{
                ContentType = "HTML"
                Content = $Body
            }
            ToRecipients = @(
                @{
                    EmailAddress = @{
                        Address = $To
                    }
                }
            )
        }
    }
    Send-MgUserMail -UserId "automation@contoso.com" -BodyParameter $mailParams
    #>
}
#endregion

#region Initialization
$startTime = Get-Date
Write-Log "═══════════════════════════════════════════════════════" -Level Info
Write-Log "  Automated SIT Migration - Starting" -Level Info
Write-Log "═══════════════════════════════════════════════════════" -Level Info
Write-Log ""

# Load configurations
Write-Log "Loading configuration files..." -Level Info
try {
    $sourceConfig = Get-Content $SourceConfigPath -Raw | ConvertFrom-Json
    $targetConfig = Get-Content $TargetConfigPath -Raw | ConvertFrom-Json
    
    Write-Log "✅ Source: $($sourceConfig.Organization)" -Level Success
    Write-Log "✅ Target: $($targetConfig.Organization)" -Level Success
} catch {
    Write-Log "❌ Failed to load configurations: $_" -Level Error
    exit 1
}
Write-Log ""
#endregion

#region Phase 1: Export from Source Tenant
try {
    Write-Log "═══════════════════════════════════════════════════════" -Level Info
    Write-Log "  PHASE 1: Export from Source Tenant" -Level Info
    Write-Log "═══════════════════════════════════════════════════════" -Level Info
    
    Write-Log "Connecting to source tenant: $($sourceConfig.Organization)..." -Level Info
    
    # Connect using certificate thumbprint (assumes cert is installed)
    # For .pfx file method, use -CertificateFilePath instead
    Connect-IPPSSession `
        -CertificateThumbPrint $sourceConfig.CertificateThumbprint `
        -AppID $sourceConfig.AppId `
        -Organization $sourceConfig.Organization `
        -ShowBanner:$false `
        -ErrorAction Stop
    
    Write-Log "✅ Connected to source tenant" -Level Success
    
    # Verify connection
    $connInfo = Get-ConnectionInformation
    Write-Log "   Connection State: $($connInfo.State)" -Level Info
    Write-Log "   Token Status: $($connInfo.TokenStatus)" -Level Info
    
    # Run export script
    Write-Log "Exporting custom SITs from source..." -Level Info
    $exportScript = Join-Path $ScriptPath "03-Export-Custom-SITs.ps1"
    
    if (Test-Path $exportScript) {
        & $exportScript
        Write-Log "✅ Export completed" -Level Success
    } else {
        Write-Log "❌ Export script not found: $exportScript" -Level Error
        throw "Export script not found"
    }
    
    # Get the latest export file
    $exportFolder = Join-Path $ScriptPath "exports"
    $exportFile = Get-ChildItem "$exportFolder\source-export-*.xml" -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
    
    if (-not $exportFile) {
        Write-Log "❌ No export file found in $exportFolder" -Level Error
        throw "Export file not found"
    }
    
    Write-Log "✅ Export file: $($exportFile.Name)" -Level Success
    Write-Log "   Size: $([math]::Round($exportFile.Length / 1KB, 2)) KB" -Level Info
    
    # Disconnect from source
    Write-Log "Disconnecting from source tenant..." -Level Info
    Disconnect-ExchangeOnline -Confirm:$false
    Write-Log "✅ Disconnected from source" -Level Success
    
} catch {
    Write-Log "❌ Error in Phase 1: $_" -Level Error
    
    # Cleanup: ensure disconnection
    try { Disconnect-ExchangeOnline -Confirm:$false } catch {}
    
    # Send failure notification
    if ($NotificationEmail) {
        Send-NotificationEmail `
            -To $NotificationEmail `
            -Subject "SIT Migration Failed - Phase 1" `
            -Body "Error during export from source tenant: $_" `
            -Success $false
    }
    
    exit 1
}
Write-Log ""
#endregion

#region Phase 2: Import to Target Tenant
try {
    Write-Log "═══════════════════════════════════════════════════════" -Level Info
    Write-Log "  PHASE 2: Import to Target Tenant" -Level Info
    Write-Log "═══════════════════════════════════════════════════════" -Level Info
    
    # Optional: Add delay between source and target operations
    Write-Log "Waiting 5 seconds before connecting to target..." -Level Info
    Start-Sleep -Seconds 5
    
    Write-Log "Connecting to target tenant: $($targetConfig.Organization)..." -Level Info
    
    Connect-IPPSSession `
        -CertificateThumbPrint $targetConfig.CertificateThumbprint `
        -AppID $targetConfig.AppId `
        -Organization $targetConfig.Organization `
        -ShowBanner:$false `
        -ErrorAction Stop
    
    Write-Log "✅ Connected to target tenant" -Level Success
    
    # Verify connection
    $connInfo = Get-ConnectionInformation
    Write-Log "   Connection State: $($connInfo.State)" -Level Info
    Write-Log "   Token Status: $($connInfo.TokenStatus)" -Level Info
    
    # Run import script
    Write-Log "Importing SITs to target..." -Level Info
    $importScript = Join-Path $ScriptPath "04-Import-Custom-SITs.ps1"
    
    if (Test-Path $importScript) {
        & $importScript -SourceXmlPath $exportFile.FullName
        Write-Log "✅ Import completed" -Level Success
    } else {
        Write-Log "❌ Import script not found: $importScript" -Level Error
        throw "Import script not found"
    }
    
    # Verify imported SITs
    Write-Log "Verifying imported SITs..." -Level Info
    $customSITs = Get-DlpSensitiveInformationType | 
        Where-Object { $_.Publisher -ne "Microsoft Corporation" }
    
    Write-Log "✅ Found $($customSITs.Count) custom SIT(s) in target tenant" -Level Success
    
    # Disconnect from target
    Write-Log "Disconnecting from target tenant..." -Level Info
    Disconnect-ExchangeOnline -Confirm:$false
    Write-Log "✅ Disconnected from target" -Level Success
    
} catch {
    Write-Log "❌ Error in Phase 2: $_" -Level Error
    
    # Cleanup: ensure disconnection
    try { Disconnect-ExchangeOnline -Confirm:$false } catch {}
    
    # Send failure notification
    if ($NotificationEmail) {
        Send-NotificationEmail `
            -To $NotificationEmail `
            -Subject "SIT Migration Failed - Phase 2" `
            -Body "Error during import to target tenant: $_" `
            -Success $false
    }
    
    exit 1
}
Write-Log ""
#endregion

#region Summary and Cleanup
$endTime = Get-Date
$duration = $endTime - $startTime

Write-Log "═══════════════════════════════════════════════════════" -Level Success
Write-Log "  ✅ Migration Completed Successfully!" -Level Success
Write-Log "═══════════════════════════════════════════════════════" -Level Success
Write-Log ""
Write-Log "Summary:" -Level Info
Write-Log "   Source Tenant: $($sourceConfig.Organization)" -Level Info
Write-Log "   Target Tenant: $($targetConfig.Organization)" -Level Info
Write-Log "   Export File: $($exportFile.Name)" -Level Info
Write-Log "   Duration: $($duration.ToString('mm\:ss'))" -Level Info
Write-Log "   Completed: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -Level Info
Write-Log ""

# Send success notification
if ($NotificationEmail) {
    $emailBody = @"
<html>
<body>
    <h2>SIT Migration Completed Successfully</h2>
    <p><strong>Summary:</strong></p>
    <ul>
        <li><strong>Source Tenant:</strong> $($sourceConfig.Organization)</li>
        <li><strong>Target Tenant:</strong> $($targetConfig.Organization)</li>
        <li><strong>Export File:</strong> $($exportFile.Name)</li>
        <li><strong>Custom SITs Migrated:</strong> $($customSITs.Count)</li>
        <li><strong>Duration:</strong> $($duration.ToString('mm\:ss'))</li>
        <li><strong>Completed:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</li>
    </ul>
    <p>The migration completed without errors.</p>
</body>
</html>
"@
    
    Send-NotificationEmail `
        -To $NotificationEmail `
        -Subject "SIT Migration Completed Successfully" `
        -Body $emailBody `
        -Success $true
}

# Optional: Archive export file
$archiveFolder = Join-Path $ScriptPath "exports\archive"
if (-not (Test-Path $archiveFolder)) {
    New-Item -ItemType Directory -Path $archiveFolder | Out-Null
}

$archiveName = "archived-$($exportFile.Name)"
$archivePath = Join-Path $archiveFolder $archiveName
Copy-Item -Path $exportFile.FullName -Destination $archivePath
Write-Log "📁 Export file archived: $archiveName" -Level Info
Write-Log ""

Write-Log "Migration completed successfully! 🎉" -Level Success
#endregion

# Exit with success
exit 0
