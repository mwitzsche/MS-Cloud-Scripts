<#
.SYNOPSIS
    Manages Microsoft Purview data protection and compliance features.

.DESCRIPTION
    This script manages Microsoft Purview data protection and compliance features,
    including sensitivity labels, data loss prevention policies, retention policies,
    and information barriers. It supports creating, updating, removing, and reporting
    on various Purview components.

.PARAMETER Action
    The action to perform (Get, Create, Update, Remove, Report).

.PARAMETER ComponentType
    The type of Purview component to manage (SensitivityLabel, DLPPolicy, RetentionPolicy, InformationBarrier).

.PARAMETER Name
    The name of the component to manage.

.PARAMETER Description
    The description for the component.

.PARAMETER Settings
    Hashtable of settings for the component.

.PARAMETER Locations
    Array of locations to apply the component to (Exchange, SharePoint, OneDrive, Teams, Devices).

.PARAMETER TargetGroups
    Array of group IDs to target with the component.

.PARAMETER ExcludedGroups
    Array of group IDs to exclude from the component.

.PARAMETER ReportType
    The type of report to generate (Usage, Violations, Compliance).

.PARAMETER TimeFrame
    The time frame for the report (Last7Days, Last30Days, Last90Days).

.PARAMETER ExportPath
    The path where the report will be saved.

.PARAMETER ExportFormat
    The format of the export file (CSV, JSON, Excel).

.PARAMETER LogPath
    Path where logs will be stored. Defaults to Windows log directory.

.EXAMPLE
    .\Manage-MicrosoftPurview.ps1 -Action Create -ComponentType SensitivityLabel -Name "Confidential" -Description "For confidential data" -Settings @{EncryptionEnabled=$true; MarkingEnabled=$true}
    Creates a new sensitivity label with encryption and marking enabled.

.EXAMPLE
    .\Manage-MicrosoftPurview.ps1 -Action Report -ComponentType DLPPolicy -ReportType Violations -TimeFrame Last30Days -ExportPath "C:\Reports\DLPViolations.csv" -ExportFormat CSV
    Generates a DLP policy violations report for the last 30 days and exports it to CSV format.

.NOTES
    Author: Michael Witzsche
    Date: April 26, 2025
    Version: 1.0.0
    
    History:
    1.0.0 - Initial release
#>

#Requires -Modules ExchangeOnlineManagement, Microsoft.Graph.Identity.Governance, Microsoft.Graph.Authentication, ImportExcel

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$LogPath = "$env:SystemRoot\Logs\Manage-MicrosoftPurview",
    
    [Parameter(Mandatory = $true)]
    [ValidateSet("Get", "Create", "Update", "Remove", "Report")]
    [string]$Action,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("SensitivityLabel", "DLPPolicy", "RetentionPolicy", "InformationBarrier", "")]
    [string]$ComponentType = "",
    
    [Parameter(Mandatory = $false)]
    [string]$Name = "",
    
    [Parameter(Mandatory = $false)]
    [string]$Description = "",
    
    [Parameter(Mandatory = $false)]
    [hashtable]$Settings = @{},
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Exchange", "SharePoint", "OneDrive", "Teams", "Devices")]
    [string[]]$Locations = @(),
    
    [Parameter(Mandatory = $false)]
    [string[]]$TargetGroups = @(),
    
    [Parameter(Mandatory = $false)]
    [string[]]$ExcludedGroups = @(),
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Usage", "Violations", "Compliance", "")]
    [string]$ReportType = "",
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Last7Days", "Last30Days", "Last90Days", "LastYear", "")]
    [string]$TimeFrame = "Last30Days",
    
    [Parameter(Mandatory = $false)]
    [string]$ExportPath = "",
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("CSV", "JSON", "Excel")]
    [string]$ExportFormat = "CSV"
)

#region Functions
function Write-Log {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Information', 'Warning', 'Error')]
        [string]$Level = 'Information'
    )
    
    # Create log directory if it doesn't exist
    if (-not (Test-Path -Path $LogPath)) {
        try {
            New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
            Write-Verbose "Created log directory: $LogPath"
        }
        catch {
            Write-Error "Failed to create log directory: $_"
            return
        }
    }
    
    # Format log entry
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    $logFile = Join-Path -Path $LogPath -ChildPath "Log_$(Get-Date -Format 'yyyyMMdd').log"
    
    # Write to log file
    try {
        Add-Content -Path $logFile -Value $logEntry
        
        # Also output to console based on level
        switch ($Level) {
            'Information' { Write-Host $logEntry }
            'Warning' { Write-Host $logEntry -ForegroundColor Yellow }
            'Error' { Write-Host $logEntry -ForegroundColor Red }
        }
    }
    catch {
        Write-Error "Failed to write to log file: $_"
    }
}

function Connect-ToExchangeOnline {
    [CmdletBinding()]
    param()
    
    try {
        # Check if already connected
        try {
            $connectionStatus = Get-ConnectionInformation -ErrorAction SilentlyContinue
            if ($null -ne $connectionStatus) {
                Write-Log "Already connected to Exchange Online as $($connectionStatus.UserPrincipalName)"
                return $true
            }
        }
        catch {
            # Not connected
        }
        
        # Connect to Exchange Online
        Write-Log "Connecting to Exchange Online..."
        Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
        
        # Verify connection
        $connectionStatus = Get-ConnectionInformation
        if ($null -ne $connectionStatus) {
            Write-Log "Successfully connected to Exchange Online as $($connectionStatus.UserPrincipalName)"
            return $true
        }
        else {
            Write-Log "Failed to verify Exchange Online connection" -Level Error
            return $false
        }
    }
    catch {
        Write-Log "Error connecting to Exchange Online: $_" -Level Error
        return $false
    }
}

function Connect-ToMicrosoftGraph {
    [CmdletBinding()]
    param()
    
    try {
        # Check if already connected
        try {
            $context = Get-MgContext
            if ($null -ne $context) {
                Write-Log "Already connected to Microsoft Graph as $($context.Account)"
                return $true
            }
        }
        catch {
            # Not connected
        }
        
        # Connect to Microsoft Graph
        Write-Log "Connecting to Microsoft Graph..."
        
        # Define required scopes
        $scopes = @(
            "Policy.Read.All",
            "Policy.ReadWrite.All",
            "Group.Read.All",
            "User.Read.All",
            "ComplianceManager.Read.All"
        )
        
        Connect-MgGraph -Scopes $scopes -ErrorAction Stop
        
        # Verify connection
        $context = Get-MgContext
        if ($null -ne $context) {
            Write-Log "Successfully connected to Microsoft Graph as $($context.Account)"
            return $true
        }
        else {
            Write-Log "Failed to verify Microsoft Graph connection" -Level Error
            return $false
        }
    }
    catch {
        Write-Log "Error connecting to Microsoft Graph: $_" -Level Error
        return $false
    }
}

function Get-SensitivityLabels {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$Name = ""
    )
    
    try {
        Write-Log "Retrieving sensitivity labels..."
        
        # Get sensitivity labels
        $labels = Get-Label
        
        if ($null -eq $labels) {
            Write-Log "No sensitivity labels found" -Level Warning
            return $null
        }
        
        # Filter by name if specified
        if (-not [string]::IsNullOrEmpty($Name)) {
            $filteredLabels = $labels | Where-Object { $_.Name -eq $Name }
            
            if ($null -eq $filteredLabels -or $filteredLabels.Count -eq 0) {
                Write-Log "No sensitivity label found with name: $Name" -Level Warning
                return $null
            }
            
            return $filteredLabels
        }
        
        Write-Log "Retrieved $($labels.Count) sensitivity labels"
        return $labels
    }
    catch {
        Write-Log "Error retrieving sensitivity labels: $_" -Level Error
        return $null
    }
}

function Create-SensitivityLabel {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $false)]
        [string]$Description = "",
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Settings = @{}
    )
    
    try {
        Write-Log "Creating sensitivity label: $Name..."
        
        # Check if label already exists
        $existingLabels = Get-SensitivityLabels -Name $Name
        
        if ($null -ne $existingLabels) {
            Write-Log "Sensitivity label already exists with name: $Name" -Level Warning
            return $null
        }
        
        # Extract settings
        $encryptionEnabled = $Settings.ContainsKey("EncryptionEnabled") -and $Settings.EncryptionEnabled
        $markingEnabled = $Settings.ContainsKey("MarkingEnabled") -and $Settings.MarkingEnabled
        $headerText = if ($Settings.ContainsKey("HeaderText")) { $Settings.HeaderText } else { $Name }
        $footerText = if ($Settings.ContainsKey("FooterText")) { $Settings.FooterText } else { $Name }
        $watermarkText = if ($Settings.ContainsKey("WatermarkText")) { $Settings.WatermarkText } else { $Name }
        $protectionEnabled = $Settings.ContainsKey("ProtectionEnabled") -and $Settings.ProtectionEnabled
        $contentExpirationEnabled = $Settings.ContainsKey("ContentExpirationEnabled") -and $Settings.ContentExpirationEnabled
        $contentExpirationDays = if ($Settings.ContainsKey("ContentExpirationDays")) { $Settings.ContentExpirationDays } else { 365 }
        
        # Create label parameters
        $labelParams = @{
            Name = $Name
            Comment = $Description
        }
        
        # Add encryption settings if enabled
        if ($encryptionEnabled) {
            $labelParams.EncryptionEnabled = $true
            $labelParams.EncryptionProtectionType = "Template"
            $labelParams.EncryptionContentExpirationType = if ($contentExpirationEnabled) { "DateFixed" } else { "Never" }
            
            if ($contentExpirationEnabled) {
                $labelParams.EncryptionContentExpirationDays = $contentExpirationDays
            }
        }
        
        # Add marking settings if enabled
        if ($markingEnabled) {
            $labelParams.HeaderEnabled = $true
            $labelParams.HeaderText = $headerText
            $labelParams.FooterEnabled = $true
            $labelParams.FooterText = $footerText
            $labelParams.WaterMarkingEnabled = $true
            $labelParams.WaterMarkingText = $watermarkText
        }
        
        # Create label
        $label = New-Label @labelParams
        
        Write-Log "Sensitivity label created successfully: $Name"
        return $label
    }
    catch {
        Write-Log "Error creating sensitivity label: $_" -Level Error
        return $null
    }
}

function Update-SensitivityLabel {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $false)]
        [string]$Description = "",
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Settings = @{}
    )
    
    try {
        Write-Log "Updating sensitivity label: $Name..."
        
        # Get existing label
        $existingLabels = Get-SensitivityLabels -Name $Name
        
        if ($null -eq $existingLabels) {
            Write-Log "Sensitivity label not found with name: $Name" -Level Warning
            return $null
        }
        
        $existingLabel = $existingLabels[0]
        
        # Extract settings
        $encryptionEnabled = $Settings.ContainsKey("EncryptionEnabled") ? $Settings.EncryptionEnabled : $existingLabel.EncryptionEnabled
        $markingEnabled = $Settings.ContainsKey("MarkingEnabled") ? $Settings.MarkingEnabled : ($existingLabel.HeaderEnabled -or $existingLabel.FooterEnabled -or $existingLabel.WaterMarkingEnabled)
        $headerText = if ($Settings.ContainsKey("HeaderText")) { $Settings.HeaderText } else { $existingLabel.HeaderText }
        $footerText = if ($Settings.ContainsKey("FooterText")) { $Settings.FooterText } else { $existingLabel.FooterText }
        $watermarkText = if ($Settings.ContainsKey("WatermarkText")) { $Settings.WatermarkText } else { $existingLabel.WaterMarkingText }
        $contentExpirationEnabled = $Settings.ContainsKey("ContentExpirationEnabled") ? $Settings.ContentExpirationEnabled : ($existingLabel.EncryptionContentExpirationType -ne "Never")
        $contentExpirationDays = if ($Settings.ContainsKey("ContentExpirationDays")) { $Settings.ContentExpirationDays } else { $existingLabel.EncryptionContentExpirationDays }
        
        # Create update parameters
        $updateParams = @{
            Identity = $existingLabel.Identity
        }
        
        # Add description if provided
        if (-not [string]::IsNullOrEmpty($Description)) {
            $updateParams.Comment = $Description
        }
        
        # Add encryption settings if changed
        if ($Settings.ContainsKey("EncryptionEnabled")) {
            $updateParams.EncryptionEnabled = $encryptionEnabled
            
            if ($encryptionEnabled) {
                $updateParams.EncryptionProtectionType = "Template"
                $updateParams.EncryptionContentExpirationType = if ($contentExpirationEnabled) { "DateFixed" } else { "Never" }
                
                if ($contentExpirationEnabled) {
                    $updateParams.EncryptionContentExpirationDays = $contentExpirationDays
                }
            }
        }
        
        # Add marking settings if changed
        if ($Settings.ContainsKey("MarkingEnabled") -or $Settings.ContainsKey("HeaderText")) {
            $updateParams.HeaderEnabled = $markingEnabled
            $updateParams.HeaderText = $headerText
        }
        
        if ($Settings.ContainsKey("MarkingEnabled") -or $Settings.ContainsKey("FooterText")) {
            $updateParams.FooterEnabled = $markingEnabled
            $updateParams.FooterText = $footerText
        }
        
        if ($Settings.ContainsKey("MarkingEnabled") -or $Settings.ContainsKey("WatermarkText")) {
            $updateParams.WaterMarkingEnabled = $markingEnabled
            $updateParams.WaterMarkingText = $watermarkText
        }
        
        # Update label
        $label = Set-Label @updateParams
        
        Write-Log "Sensitivity label updated successfully: $Name"
        return $label
    }
    catch {
        Write-Log "Error updating sensitivity label: $_" -Level Error
        return $null
    }
}

function Remove-SensitivityLabel {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Name
    )
    
    try {
        Write-Log "Removing sensitivity label: $Name..."
        
        # Get existing label
        $existingLabels = Get-SensitivityLabels -Name $Name
        
        if ($null -eq $existingLabels) {
            Write-Log "Sensitivity label not found with name: $Name" -Level Warning
            return $false
        }
        
        $existingLabel = $existingLabels[0]
        
        # Remove label
        Remove-Label -Identity $existingLabel.Identity -Confirm:$false
        
        Write-Log "Sensitivity label removed successfully: $Name"
        return $true
    }
    catch {
        Write-Log "Error removing sensitivity label: $_" -Level Error
        return $false
    }
}

function Get-DLPPolicies {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$Name = ""
    )
    
    try {
        Write-Log "Retrieving DLP policies..."
        
        # Get DLP policies
        $policies = Get-DlpCompliancePolicy
        
        if ($null -eq $policies) {
            Write-Log "No DLP policies found" -Level Warning
            return $null
        }
        
        # Filter by name if specified
        if (-not [string]::IsNullOrEmpty($Name)) {
            $filteredPolicies = $policies | Where-Object { $_.Name -eq $Name }
            
            if ($null -eq $filteredPolicies -or $filteredPolicies.Count -eq 0) {
                Write-Log "No DLP policy found with name: $Name" -Level Warning
                return $null
            }
            
            return $filteredPolicies
        }
        
        Write-Log "Retrieved $($policies.Count) DLP policies"
        return $policies
    }
    catch {
        Write-Log "Error retrieving DLP policies: $_" -Level Error
        return $null
    }
}

function Create-DLPPolicy {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $false)]
        [string]$Description = "",
        
        [Parameter(Mandatory = $false)]
        [string[]]$Locations = @(),
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Settings = @{},
        
        [Parameter(Mandatory = $false)]
        [string[]]$TargetGroups = @(),
        
        [Parameter(Mandatory = $false)]
        [string[]]$ExcludedGroups = @()
    )
    
    try {
        Write-Log "Creating DLP policy: $Name..."
        
        # Check if policy already exists
        $existingPolicies = Get-DLPPolicies -Name $Name
        
        if ($null -ne $existingPolicies) {
            Write-Log "DLP policy already exists with name: $Name" -Level Warning
            return $null
        }
        
        # Extract settings
        $mode = if ($Settings.ContainsKey("Mode")) { $Settings.Mode } else { "Enable" }
        $sensitiveInfoTypes = if ($Settings.ContainsKey("SensitiveInfoTypes")) { $Settings.SensitiveInfoTypes } else { @("Credit Card Number", "U.S. Social Security Number (SSN)") }
        $highConfidenceThreshold = if ($Settings.ContainsKey("HighConfidenceThreshold")) { $Settings.HighConfidenceThreshold } else { 75 }
        $lowConfidenceThreshold = if ($Settings.ContainsKey("LowConfidenceThreshold")) { $Settings.LowConfidenceThreshold } else { 65 }
        $blockAccess = $Settings.ContainsKey("BlockAccess") -and $Settings.BlockAccess
        $notifyUser = $Settings.ContainsKey("NotifyUser") -and $Settings.NotifyUser
        $notifyUserText = if ($Settings.ContainsKey("NotifyUserText")) { $Settings.NotifyUserText } else { "This content contains sensitive information." }
        
        # Map locations
        $locationsMap = @{
            Exchange = "All"
            SharePoint = "All"
            OneDrive = "All"
            Teams = "All"
            Devices = "All"
        }
        
        foreach ($location in $Locations) {
            $locationsMap[$location] = "All"
        }
        
        # Create policy parameters
        $policyParams = @{
            Name = $Name
            Comment = $Description
            Mode = $mode
            ExchangeLocation = $locationsMap.Exchange
            SharePointLocation = $locationsMap.SharePoint
            OneDriveLocation = $locationsMap.OneDrive
            TeamsLocation = $locationsMap.Teams
        }
        
        # Add target groups if specified
        if ($TargetGroups.Count -gt 0) {
            $policyParams.ExchangeSenderMemberOf = $TargetGroups
            $policyParams.ExchangeSenderMemberOfException = $ExcludedGroups
        }
        
        # Create policy
        $policy = New-DlpCompliancePolicy @policyParams
        
        # Create rule parameters
        $ruleParams = @{
            Name = "$Name Rule"
            Policy = $Name
            ContentContainsSensitiveInformation = @()
        }
        
        # Add sensitive info types
        foreach ($infoType in $sensitiveInfoTypes) {
            $ruleParams.ContentContainsSensitiveInformation += @{
                Name = $infoType
                MinConfidence = $lowConfidenceThreshold
                MinCount = 1
            }
        }
        
        # Add actions
        if ($blockAccess) {
            $ruleParams.BlockAccess = $true
        }
        
        if ($notifyUser) {
            $ruleParams.NotifyUser = @("LastModifier", "Owner")
            $ruleParams.NotifyUserType = "NotifyOnly"
            $ruleParams.NotifyUserText = $notifyUserText
        }
        
        # Create rule
        $rule = New-DlpComplianceRule @ruleParams
        
        Write-Log "DLP policy created successfully: $Name"
        return $policy
    }
    catch {
        Write-Log "Error creating DLP policy: $_" -Level Error
        return $null
    }
}

function Update-DLPPolicy {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $false)]
        [string]$Description = "",
        
        [Parameter(Mandatory = $false)]
        [string[]]$Locations = @(),
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Settings = @{},
        
        [Parameter(Mandatory = $false)]
        [string[]]$TargetGroups = @(),
        
        [Parameter(Mandatory = $false)]
        [string[]]$ExcludedGroups = @()
    )
    
    try {
        Write-Log "Updating DLP policy: $Name..."
        
        # Get existing policy
        $existingPolicies = Get-DLPPolicies -Name $Name
        
        if ($null -eq $existingPolicies) {
            Write-Log "DLP policy not found with name: $Name" -Level Warning
            return $null
        }
        
        $existingPolicy = $existingPolicies[0]
        
        # Extract settings
        $mode = if ($Settings.ContainsKey("Mode")) { $Settings.Mode } else { $existingPolicy.Mode }
        
        # Map locations
        $locationsMap = @{
            Exchange = $existingPolicy.ExchangeLocation
            SharePoint = $existingPolicy.SharePointLocation
            OneDrive = $existingPolicy.OneDriveLocation
            Teams = $existingPolicy.TeamsLocation
        }
        
        foreach ($location in $Locations) {
            $locationsMap[$location] = "All"
        }
        
        # Create update parameters
        $updateParams = @{
            Identity = $existingPolicy.Identity
            Mode = $mode
        }
        
        # Add description if provided
        if (-not [string]::IsNullOrEmpty($Description)) {
            $updateParams.Comment = $Description
        }
        
        # Add locations if changed
        if ($Locations.Count -gt 0) {
            $updateParams.ExchangeLocation = $locationsMap.Exchange
            $updateParams.SharePointLocation = $locationsMap.SharePoint
            $updateParams.OneDriveLocation = $locationsMap.OneDrive
            $updateParams.TeamsLocation = $locationsMap.Teams
        }
        
        # Add target groups if specified
        if ($TargetGroups.Count -gt 0) {
            $updateParams.ExchangeSenderMemberOf = $TargetGroups
            $updateParams.ExchangeSenderMemberOfException = $ExcludedGroups
        }
        
        # Update policy
        $policy = Set-DlpCompliancePolicy @updateParams
        
        # Update rule if settings are provided
        if ($Settings.Count -gt 0) {
            # Get existing rule
            $existingRule = Get-DlpComplianceRule -Policy $Name
            
            if ($null -ne $existingRule) {
                # Extract rule settings
                $sensitiveInfoTypes = if ($Settings.ContainsKey("SensitiveInfoTypes")) { $Settings.SensitiveInfoTypes } else { $null }
                $highConfidenceThreshold = if ($Settings.ContainsKey("HighConfidenceThreshold")) { $Settings.HighConfidenceThreshold } else { $null }
                $lowConfidenceThreshold = if ($Settings.ContainsKey("LowConfidenceThreshold")) { $Settings.LowConfidenceThreshold } else { $null }
                $blockAccess = if ($Settings.ContainsKey("BlockAccess")) { $Settings.BlockAccess } else { $null }
                $notifyUser = if ($Settings.ContainsKey("NotifyUser")) { $Settings.NotifyUser } else { $null }
                $notifyUserText = if ($Settings.ContainsKey("NotifyUserText")) { $Settings.NotifyUserText } else { $null }
                
                # Create rule update parameters
                $ruleUpdateParams = @{
                    Identity = $existingRule.Identity
                }
                
                # Add sensitive info types if provided
                if ($null -ne $sensitiveInfoTypes) {
                    $ruleUpdateParams.ContentContainsSensitiveInformation = @()
                    
                    foreach ($infoType in $sensitiveInfoTypes) {
                        $ruleUpdateParams.ContentContainsSensitiveInformation += @{
                            Name = $infoType
                            MinConfidence = $lowConfidenceThreshold ?? 65
                            MinCount = 1
                        }
                    }
                }
                
                # Add actions if provided
                if ($null -ne $blockAccess) {
                    $ruleUpdateParams.BlockAccess = $blockAccess
                }
                
                if ($null -ne $notifyUser) {
                    if ($notifyUser) {
                        $ruleUpdateParams.NotifyUser = @("LastModifier", "Owner")
                        $ruleUpdateParams.NotifyUserType = "NotifyOnly"
                        
                        if ($null -ne $notifyUserText) {
                            $ruleUpdateParams.NotifyUserText = $notifyUserText
                        }
                    }
                    else {
                        $ruleUpdateParams.NotifyUser = $null
                    }
                }
                
                # Update rule
                Set-DlpComplianceRule @ruleUpdateParams
            }
        }
        
        Write-Log "DLP policy updated successfully: $Name"
        return $policy
    }
    catch {
        Write-Log "Error updating DLP policy: $_" -Level Error
        return $null
    }
}

function Remove-DLPPolicy {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Name
    )
    
    try {
        Write-Log "Removing DLP policy: $Name..."
        
        # Get existing policy
        $existingPolicies = Get-DLPPolicies -Name $Name
        
        if ($null -eq $existingPolicies) {
            Write-Log "DLP policy not found with name: $Name" -Level Warning
            return $false
        }
        
        $existingPolicy = $existingPolicies[0]
        
        # Remove policy
        Remove-DlpCompliancePolicy -Identity $existingPolicy.Identity -Confirm:$false
        
        Write-Log "DLP policy removed successfully: $Name"
        return $true
    }
    catch {
        Write-Log "Error removing DLP policy: $_" -Level Error
        return $false
    }
}

function Get-RetentionPolicies {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$Name = ""
    )
    
    try {
        Write-Log "Retrieving retention policies..."
        
        # Get retention policies
        $policies = Get-RetentionCompliancePolicy
        
        if ($null -eq $policies) {
            Write-Log "No retention policies found" -Level Warning
            return $null
        }
        
        # Filter by name if specified
        if (-not [string]::IsNullOrEmpty($Name)) {
            $filteredPolicies = $policies | Where-Object { $_.Name -eq $Name }
            
            if ($null -eq $filteredPolicies -or $filteredPolicies.Count -eq 0) {
                Write-Log "No retention policy found with name: $Name" -Level Warning
                return $null
            }
            
            return $filteredPolicies
        }
        
        Write-Log "Retrieved $($policies.Count) retention policies"
        return $policies
    }
    catch {
        Write-Log "Error retrieving retention policies: $_" -Level Error
        return $null
    }
}

function Create-RetentionPolicy {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $false)]
        [string]$Description = "",
        
        [Parameter(Mandatory = $false)]
        [string[]]$Locations = @(),
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Settings = @{},
        
        [Parameter(Mandatory = $false)]
        [string[]]$TargetGroups = @(),
        
        [Parameter(Mandatory = $false)]
        [string[]]$ExcludedGroups = @()
    )
    
    try {
        Write-Log "Creating retention policy: $Name..."
        
        # Check if policy already exists
        $existingPolicies = Get-RetentionPolicies -Name $Name
        
        if ($null -ne $existingPolicies) {
            Write-Log "Retention policy already exists with name: $Name" -Level Warning
            return $null
        }
        
        # Extract settings
        $retentionDuration = if ($Settings.ContainsKey("RetentionDuration")) { $Settings.RetentionDuration } else { 365 }
        $retentionAction = if ($Settings.ContainsKey("RetentionAction")) { $Settings.RetentionAction } else { "Keep" }
        $retentionType = if ($Settings.ContainsKey("RetentionType")) { $Settings.RetentionType } else { "ModificationAgeInDays" }
        
        # Map locations
        $locationsMap = @{
            Exchange = $false
            SharePoint = $false
            OneDrive = $false
            Teams = $false
        }
        
        foreach ($location in $Locations) {
            $locationsMap[$location] = $true
        }
        
        # Create policy parameters
        $policyParams = @{
            Name = $Name
            Comment = $Description
            Enabled = $true
        }
        
        # Add locations
        if ($locationsMap.Exchange) {
            $policyParams.ExchangeLocation = "All"
        }
        
        if ($locationsMap.SharePoint) {
            $policyParams.SharePointLocation = "All"
        }
        
        if ($locationsMap.OneDrive) {
            $policyParams.OneDriveLocation = "All"
        }
        
        if ($locationsMap.Teams) {
            $policyParams.TeamsChannelLocation = "All"
            $policyParams.TeamsChatLocation = "All"
        }
        
        # Add target groups if specified
        if ($TargetGroups.Count -gt 0) {
            $policyParams.ExchangeLocationException = $ExcludedGroups
            $policyParams.ModernGroupLocationException = $ExcludedGroups
        }
        
        # Create policy
        $policy = New-RetentionCompliancePolicy @policyParams
        
        # Create rule parameters
        $ruleParams = @{
            Name = "$Name Rule"
            Policy = $Name
            RetentionDuration = $retentionDuration
            RetentionComplianceAction = $retentionAction
            ExpirationDateOption = $retentionType
        }
        
        # Create rule
        $rule = New-RetentionComplianceRule @ruleParams
        
        Write-Log "Retention policy created successfully: $Name"
        return $policy
    }
    catch {
        Write-Log "Error creating retention policy: $_" -Level Error
        return $null
    }
}

function Update-RetentionPolicy {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $false)]
        [string]$Description = "",
        
        [Parameter(Mandatory = $false)]
        [string[]]$Locations = @(),
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Settings = @{},
        
        [Parameter(Mandatory = $false)]
        [string[]]$TargetGroups = @(),
        
        [Parameter(Mandatory = $false)]
        [string[]]$ExcludedGroups = @()
    )
    
    try {
        Write-Log "Updating retention policy: $Name..."
        
        # Get existing policy
        $existingPolicies = Get-RetentionPolicies -Name $Name
        
        if ($null -eq $existingPolicies) {
            Write-Log "Retention policy not found with name: $Name" -Level Warning
            return $null
        }
        
        $existingPolicy = $existingPolicies[0]
        
        # Map locations
        $locationsMap = @{
            Exchange = $existingPolicy.ExchangeLocation -ne $null
            SharePoint = $existingPolicy.SharePointLocation -ne $null
            OneDrive = $existingPolicy.OneDriveLocation -ne $null
            Teams = $existingPolicy.TeamsChannelLocation -ne $null -or $existingPolicy.TeamsChatLocation -ne $null
        }
        
        foreach ($location in $Locations) {
            $locationsMap[$location] = $true
        }
        
        # Create update parameters
        $updateParams = @{
            Identity = $existingPolicy.Identity
            Enabled = $true
        }
        
        # Add description if provided
        if (-not [string]::IsNullOrEmpty($Description)) {
            $updateParams.Comment = $Description
        }
        
        # Add locations if changed
        if ($Locations.Count -gt 0) {
            if ($locationsMap.Exchange) {
                $updateParams.ExchangeLocation = "All"
            }
            else {
                $updateParams.ExchangeLocation = $null
            }
            
            if ($locationsMap.SharePoint) {
                $updateParams.SharePointLocation = "All"
            }
            else {
                $updateParams.SharePointLocation = $null
            }
            
            if ($locationsMap.OneDrive) {
                $updateParams.OneDriveLocation = "All"
            }
            else {
                $updateParams.OneDriveLocation = $null
            }
            
            if ($locationsMap.Teams) {
                $updateParams.TeamsChannelLocation = "All"
                $updateParams.TeamsChatLocation = "All"
            }
            else {
                $updateParams.TeamsChannelLocation = $null
                $updateParams.TeamsChatLocation = $null
            }
        }
        
        # Add target groups if specified
        if ($TargetGroups.Count -gt 0) {
            $updateParams.ExchangeLocationException = $ExcludedGroups
            $updateParams.ModernGroupLocationException = $ExcludedGroups
        }
        
        # Update policy
        $policy = Set-RetentionCompliancePolicy @updateParams
        
        # Update rule if settings are provided
        if ($Settings.Count -gt 0) {
            # Get existing rule
            $existingRule = Get-RetentionComplianceRule -Policy $Name
            
            if ($null -ne $existingRule) {
                # Extract rule settings
                $retentionDuration = if ($Settings.ContainsKey("RetentionDuration")) { $Settings.RetentionDuration } else { $null }
                $retentionAction = if ($Settings.ContainsKey("RetentionAction")) { $Settings.RetentionAction } else { $null }
                $retentionType = if ($Settings.ContainsKey("RetentionType")) { $Settings.RetentionType } else { $null }
                
                # Create rule update parameters
                $ruleUpdateParams = @{
                    Identity = $existingRule.Identity
                }
                
                # Add settings if provided
                if ($null -ne $retentionDuration) {
                    $ruleUpdateParams.RetentionDuration = $retentionDuration
                }
                
                if ($null -ne $retentionAction) {
                    $ruleUpdateParams.RetentionComplianceAction = $retentionAction
                }
                
                if ($null -ne $retentionType) {
                    $ruleUpdateParams.ExpirationDateOption = $retentionType
                }
                
                # Update rule
                Set-RetentionComplianceRule @ruleUpdateParams
            }
        }
        
        Write-Log "Retention policy updated successfully: $Name"
        return $policy
    }
    catch {
        Write-Log "Error updating retention policy: $_" -Level Error
        return $null
    }
}

function Remove-RetentionPolicy {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Name
    )
    
    try {
        Write-Log "Removing retention policy: $Name..."
        
        # Get existing policy
        $existingPolicies = Get-RetentionPolicies -Name $Name
        
        if ($null -eq $existingPolicies) {
            Write-Log "Retention policy not found with name: $Name" -Level Warning
            return $false
        }
        
        $existingPolicy = $existingPolicies[0]
        
        # Remove policy
        Remove-RetentionCompliancePolicy -Identity $existingPolicy.Identity -Confirm:$false
        
        Write-Log "Retention policy removed successfully: $Name"
        return $true
    }
    catch {
        Write-Log "Error removing retention policy: $_" -Level Error
        return $false
    }
}

function Get-InformationBarriers {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$Name = ""
    )
    
    try {
        Write-Log "Retrieving information barriers..."
        
        # Get information barriers
        $barriers = Get-InformationBarrierPolicy
        
        if ($null -eq $barriers) {
            Write-Log "No information barriers found" -Level Warning
            return $null
        }
        
        # Filter by name if specified
        if (-not [string]::IsNullOrEmpty($Name)) {
            $filteredBarriers = $barriers | Where-Object { $_.Name -eq $Name }
            
            if ($null -eq $filteredBarriers -or $filteredBarriers.Count -eq 0) {
                Write-Log "No information barrier found with name: $Name" -Level Warning
                return $null
            }
            
            return $filteredBarriers
        }
        
        Write-Log "Retrieved $($barriers.Count) information barriers"
        return $barriers
    }
    catch {
        Write-Log "Error retrieving information barriers: $_" -Level Error
        return $null
    }
}

function Create-InformationBarrier {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $false)]
        [string]$Description = "",
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Settings = @{},
        
        [Parameter(Mandatory = $false)]
        [string[]]$TargetGroups = @(),
        
        [Parameter(Mandatory = $false)]
        [string[]]$RestrictedGroups = @()
    )
    
    try {
        Write-Log "Creating information barrier: $Name..."
        
        # Check if barrier already exists
        $existingBarriers = Get-InformationBarriers -Name $Name
        
        if ($null -ne $existingBarriers) {
            Write-Log "Information barrier already exists with name: $Name" -Level Warning
            return $null
        }
        
        # Extract settings
        $state = if ($Settings.ContainsKey("State")) { $Settings.State } else { "Active" }
        
        # Create barrier parameters
        $barrierParams = @{
            Name = $Name
            Comment = $Description
            State = $state
        }
        
        # Add segment filters
        if ($TargetGroups.Count -gt 0 -and $RestrictedGroups.Count -gt 0) {
            $barrierParams.AssignmentMethod = "SegmentName"
            $barrierParams.SegmentsAllowed = $TargetGroups
            $barrierParams.SegmentsBlocked = $RestrictedGroups
        }
        
        # Create barrier
        $barrier = New-InformationBarrierPolicy @barrierParams
        
        Write-Log "Information barrier created successfully: $Name"
        return $barrier
    }
    catch {
        Write-Log "Error creating information barrier: $_" -Level Error
        return $null
    }
}

function Update-InformationBarrier {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $false)]
        [string]$Description = "",
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Settings = @{},
        
        [Parameter(Mandatory = $false)]
        [string[]]$TargetGroups = @(),
        
        [Parameter(Mandatory = $false)]
        [string[]]$RestrictedGroups = @()
    )
    
    try {
        Write-Log "Updating information barrier: $Name..."
        
        # Get existing barrier
        $existingBarriers = Get-InformationBarriers -Name $Name
        
        if ($null -eq $existingBarriers) {
            Write-Log "Information barrier not found with name: $Name" -Level Warning
            return $null
        }
        
        $existingBarrier = $existingBarriers[0]
        
        # Extract settings
        $state = if ($Settings.ContainsKey("State")) { $Settings.State } else { $existingBarrier.State }
        
        # Create update parameters
        $updateParams = @{
            Identity = $existingBarrier.Identity
            State = $state
        }
        
        # Add description if provided
        if (-not [string]::IsNullOrEmpty($Description)) {
            $updateParams.Comment = $Description
        }
        
        # Add segment filters if provided
        if ($TargetGroups.Count -gt 0 -and $RestrictedGroups.Count -gt 0) {
            $updateParams.AssignmentMethod = "SegmentName"
            $updateParams.SegmentsAllowed = $TargetGroups
            $updateParams.SegmentsBlocked = $RestrictedGroups
        }
        
        # Update barrier
        $barrier = Set-InformationBarrierPolicy @updateParams
        
        Write-Log "Information barrier updated successfully: $Name"
        return $barrier
    }
    catch {
        Write-Log "Error updating information barrier: $_" -Level Error
        return $null
    }
}

function Remove-InformationBarrier {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Name
    )
    
    try {
        Write-Log "Removing information barrier: $Name..."
        
        # Get existing barrier
        $existingBarriers = Get-InformationBarriers -Name $Name
        
        if ($null -eq $existingBarriers) {
            Write-Log "Information barrier not found with name: $Name" -Level Warning
            return $false
        }
        
        $existingBarrier = $existingBarriers[0]
        
        # Remove barrier
        Remove-InformationBarrierPolicy -Identity $existingBarrier.Identity -Confirm:$false
        
        Write-Log "Information barrier removed successfully: $Name"
        return $true
    }
    catch {
        Write-Log "Error removing information barrier: $_" -Level Error
        return $false
    }
}

function Get-DLPViolationsReport {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$TimeFrame = "Last30Days"
    )
    
    try {
        Write-Log "Generating DLP violations report for time frame: $TimeFrame..."
        
        # Calculate date range based on time frame
        $endDate = Get-Date
        $startDate = $endDate
        
        switch ($TimeFrame) {
            "Last7Days" {
                $startDate = $endDate.AddDays(-7)
            }
            "Last30Days" {
                $startDate = $endDate.AddDays(-30)
            }
            "Last90Days" {
                $startDate = $endDate.AddDays(-90)
            }
            "LastYear" {
                $startDate = $endDate.AddDays(-365)
            }
        }
        
        # Format dates
        $startDateStr = $startDate.ToString("MM/dd/yyyy")
        $endDateStr = $endDate.ToString("MM/dd/yyyy")
        
        # Get DLP incidents
        $incidents = Get-DlpDetailReport -StartDate $startDateStr -EndDate $endDateStr
        
        if ($null -eq $incidents) {
            Write-Log "No DLP incidents found" -Level Warning
            return $null
        }
        
        # Create violations report
        $violationsReport = @()
        
        foreach ($incident in $incidents) {
            $violationsReport += [PSCustomObject]@{
                Date = $incident.Date
                Policy = $incident.Policy
                Rule = $incident.Rule
                User = $incident.User
                UserAction = $incident.UserAction
                Severity = $incident.Severity
                Source = $incident.Source
                Action = $incident.Action
                SensitiveInformation = $incident.SensitiveInformation
                DocumentName = $incident.DocumentName
                DocumentPath = $incident.DocumentPath
                TimeFrame = $TimeFrame
            }
        }
        
        Write-Log "Generated DLP violations report with $($violationsReport.Count) incidents"
        return $violationsReport
    }
    catch {
        Write-Log "Error generating DLP violations report: $_" -Level Error
        return $null
    }
}

function Get-SensitivityLabelUsageReport {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$TimeFrame = "Last30Days"
    )
    
    try {
        Write-Log "Generating sensitivity label usage report for time frame: $TimeFrame..."
        
        # Calculate date range based on time frame
        $endDate = Get-Date
        $startDate = $endDate
        
        switch ($TimeFrame) {
            "Last7Days" {
                $startDate = $endDate.AddDays(-7)
            }
            "Last30Days" {
                $startDate = $endDate.AddDays(-30)
            }
            "Last90Days" {
                $startDate = $endDate.AddDays(-90)
            }
            "LastYear" {
                $startDate = $endDate.AddDays(-365)
            }
        }
        
        # Format dates
        $startDateStr = $startDate.ToString("MM/dd/yyyy")
        $endDateStr = $endDate.ToString("MM/dd/yyyy")
        
        # Get label usage
        $labelUsage = Get-LabelActivityExplorer -StartTime $startDateStr -EndTime $endDateStr
        
        if ($null -eq $labelUsage) {
            Write-Log "No sensitivity label usage found" -Level Warning
            return $null
        }
        
        # Create usage report
        $usageReport = @()
        
        foreach ($usage in $labelUsage) {
            $usageReport += [PSCustomObject]@{
                Date = $usage.Date
                User = $usage.User
                Label = $usage.Label
                Action = $usage.Action
                ItemType = $usage.ItemType
                ItemName = $usage.ItemName
                Location = $usage.Location
                TimeFrame = $TimeFrame
            }
        }
        
        Write-Log "Generated sensitivity label usage report with $($usageReport.Count) activities"
        return $usageReport
    }
    catch {
        Write-Log "Error generating sensitivity label usage report: $_" -Level Error
        return $null
    }
}

function Get-ComplianceReport {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$ComponentType = "",
        
        [Parameter(Mandatory = $false)]
        [string]$TimeFrame = "Last30Days"
    )
    
    try {
        Write-Log "Generating compliance report for component type: $ComponentType, time frame: $TimeFrame..."
        
        # Create compliance report
        $complianceReport = @()
        
        switch ($ComponentType) {
            "SensitivityLabel" {
                # Get sensitivity labels
                $labels = Get-SensitivityLabels
                
                if ($null -ne $labels) {
                    # Get label usage
                    $labelUsage = Get-SensitivityLabelUsageReport -TimeFrame $TimeFrame
                    
                    foreach ($label in $labels) {
                        $usageCount = 0
                        
                        if ($null -ne $labelUsage) {
                            $usageCount = ($labelUsage | Where-Object { $_.Label -eq $label.Name }).Count
                        }
                        
                        $complianceReport += [PSCustomObject]@{
                            ComponentType = "SensitivityLabel"
                            Name = $label.Name
                            Status = $label.Enabled ? "Enabled" : "Disabled"
                            UsageCount = $usageCount
                            TimeFrame = $TimeFrame
                            LastUpdated = Get-Date
                        }
                    }
                }
            }
            "DLPPolicy" {
                # Get DLP policies
                $policies = Get-DLPPolicies
                
                if ($null -ne $policies) {
                    # Get DLP violations
                    $violations = Get-DLPViolationsReport -TimeFrame $TimeFrame
                    
                    foreach ($policy in $policies) {
                        $violationCount = 0
                        
                        if ($null -ne $violations) {
                            $violationCount = ($violations | Where-Object { $_.Policy -eq $policy.Name }).Count
                        }
                        
                        $complianceReport += [PSCustomObject]@{
                            ComponentType = "DLPPolicy"
                            Name = $policy.Name
                            Status = $policy.Enabled ? "Enabled" : "Disabled"
                            ViolationCount = $violationCount
                            TimeFrame = $TimeFrame
                            LastUpdated = Get-Date
                        }
                    }
                }
            }
            "RetentionPolicy" {
                # Get retention policies
                $policies = Get-RetentionPolicies
                
                if ($null -ne $policies) {
                    foreach ($policy in $policies) {
                        $complianceReport += [PSCustomObject]@{
                            ComponentType = "RetentionPolicy"
                            Name = $policy.Name
                            Status = $policy.Enabled ? "Enabled" : "Disabled"
                            Locations = ($policy.ExchangeLocation -ne $null ? "Exchange, " : "") + 
                                       ($policy.SharePointLocation -ne $null ? "SharePoint, " : "") + 
                                       ($policy.OneDriveLocation -ne $null ? "OneDrive, " : "") + 
                                       ($policy.TeamsChannelLocation -ne $null ? "Teams" : "")
                            TimeFrame = $TimeFrame
                            LastUpdated = Get-Date
                        }
                    }
                }
            }
            "InformationBarrier" {
                # Get information barriers
                $barriers = Get-InformationBarriers
                
                if ($null -ne $barriers) {
                    foreach ($barrier in $barriers) {
                        $complianceReport += [PSCustomObject]@{
                            ComponentType = "InformationBarrier"
                            Name = $barrier.Name
                            Status = $barrier.State
                            SegmentsAllowed = $barrier.SegmentsAllowed -join ", "
                            SegmentsBlocked = $barrier.SegmentsBlocked -join ", "
                            TimeFrame = $TimeFrame
                            LastUpdated = Get-Date
                        }
                    }
                }
            }
            default {
                # Get all components
                $labelReport = Get-ComplianceReport -ComponentType "SensitivityLabel" -TimeFrame $TimeFrame
                $dlpReport = Get-ComplianceReport -ComponentType "DLPPolicy" -TimeFrame $TimeFrame
                $retentionReport = Get-ComplianceReport -ComponentType "RetentionPolicy" -TimeFrame $TimeFrame
                $barrierReport = Get-ComplianceReport -ComponentType "InformationBarrier" -TimeFrame $TimeFrame
                
                $complianceReport = $labelReport + $dlpReport + $retentionReport + $barrierReport
            }
        }
        
        Write-Log "Generated compliance report with $($complianceReport.Count) entries"
        return $complianceReport
    }
    catch {
        Write-Log "Error generating compliance report: $_" -Level Error
        return $null
    }
}

function Export-Report {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSObject[]]$Data,
        
        [Parameter(Mandatory = $true)]
        [string]$ExportPath,
        
        [Parameter(Mandatory = $true)]
        [string]$ExportFormat
    )
    
    try {
        Write-Log "Exporting report to $ExportFormat format..."
        
        # Create directory if it doesn't exist
        $directory = Split-Path -Path $ExportPath -Parent
        if (-not [string]::IsNullOrEmpty($directory) -and -not (Test-Path -Path $directory)) {
            New-Item -Path $directory -ItemType Directory -Force | Out-Null
        }
        
        # Export data based on format
        switch ($ExportFormat) {
            "CSV" {
                $Data | Export-Csv -Path $ExportPath -NoTypeInformation
            }
            "JSON" {
                $Data | ConvertTo-Json -Depth 10 | Out-File -FilePath $ExportPath
            }
            "Excel" {
                $Data | Export-Excel -Path $ExportPath -AutoSize -TableName "PurviewReport" -WorksheetName "Purview Report"
            }
        }
        
        Write-Log "Report exported successfully to: $ExportPath"
        return $true
    }
    catch {
        Write-Log "Error exporting report: $_" -Level Error
        return $false
    }
}
#endregion

#region Main Script
try {
    # Script start
    Write-Log "Script started with parameters: Action=$Action, ComponentType=$ComponentType"
    
    # Connect to required services
    $connectedToExchange = Connect-ToExchangeOnline
    if (-not $connectedToExchange) {
        Write-Log "Cannot proceed without Exchange Online connection" -Level Error
        exit 1
    }
    
    $connectedToGraph = Connect-ToMicrosoftGraph
    if (-not $connectedToGraph) {
        Write-Log "Cannot proceed without Microsoft Graph connection" -Level Error
        exit 1
    }
    
    # Process based on action
    switch ($Action) {
        "Get" {
            if ([string]::IsNullOrEmpty($ComponentType)) {
                Write-Log "ComponentType parameter is required for Get action" -Level Error
                exit 1
            }
            
            switch ($ComponentType) {
                "SensitivityLabel" {
                    $labels = Get-SensitivityLabels -Name $Name
                    
                    if ($null -ne $labels) {
                        Write-Output "Sensitivity Labels:"
                        $labels | Format-Table -Property Name, Comment, EncryptionEnabled, HeaderEnabled, FooterEnabled, WaterMarkingEnabled
                        
                        # Export report if path is specified
                        if (-not [string]::IsNullOrEmpty($ExportPath)) {
                            $exportResult = Export-Report -Data $labels -ExportPath $ExportPath -ExportFormat $ExportFormat
                            
                            if ($exportResult) {
                                Write-Output "Sensitivity labels exported to: $ExportPath"
                            }
                        }
                    }
                    else {
                        Write-Output "No sensitivity labels found"
                    }
                }
                "DLPPolicy" {
                    $policies = Get-DLPPolicies -Name $Name
                    
                    if ($null -ne $policies) {
                        Write-Output "DLP Policies:"
                        $policies | Format-Table -Property Name, Mode, Comment
                        
                        # Export report if path is specified
                        if (-not [string]::IsNullOrEmpty($ExportPath)) {
                            $exportResult = Export-Report -Data $policies -ExportPath $ExportPath -ExportFormat $ExportFormat
                            
                            if ($exportResult) {
                                Write-Output "DLP policies exported to: $ExportPath"
                            }
                        }
                    }
                    else {
                        Write-Output "No DLP policies found"
                    }
                }
                "RetentionPolicy" {
                    $policies = Get-RetentionPolicies -Name $Name
                    
                    if ($null -ne $policies) {
                        Write-Output "Retention Policies:"
                        $policies | Format-Table -Property Name, Enabled, Comment
                        
                        # Export report if path is specified
                        if (-not [string]::IsNullOrEmpty($ExportPath)) {
                            $exportResult = Export-Report -Data $policies -ExportPath $ExportPath -ExportFormat $ExportFormat
                            
                            if ($exportResult) {
                                Write-Output "Retention policies exported to: $ExportPath"
                            }
                        }
                    }
                    else {
                        Write-Output "No retention policies found"
                    }
                }
                "InformationBarrier" {
                    $barriers = Get-InformationBarriers -Name $Name
                    
                    if ($null -ne $barriers) {
                        Write-Output "Information Barriers:"
                        $barriers | Format-Table -Property Name, State, Comment
                        
                        # Export report if path is specified
                        if (-not [string]::IsNullOrEmpty($ExportPath)) {
                            $exportResult = Export-Report -Data $barriers -ExportPath $ExportPath -ExportFormat $ExportFormat
                            
                            if ($exportResult) {
                                Write-Output "Information barriers exported to: $ExportPath"
                            }
                        }
                    }
                    else {
                        Write-Output "No information barriers found"
                    }
                }
            }
        }
        "Create" {
            if ([string]::IsNullOrEmpty($ComponentType)) {
                Write-Log "ComponentType parameter is required for Create action" -Level Error
                exit 1
            }
            
            if ([string]::IsNullOrEmpty($Name)) {
                Write-Log "Name parameter is required for Create action" -Level Error
                exit 1
            }
            
            switch ($ComponentType) {
                "SensitivityLabel" {
                    $label = Create-SensitivityLabel -Name $Name -Description $Description -Settings $Settings
                    
                    if ($null -ne $label) {
                        Write-Output "Sensitivity label created successfully: $Name"
                    }
                    else {
                        Write-Output "Failed to create sensitivity label"
                        exit 1
                    }
                }
                "DLPPolicy" {
                    $policy = Create-DLPPolicy -Name $Name -Description $Description -Locations $Locations -Settings $Settings -TargetGroups $TargetGroups -ExcludedGroups $ExcludedGroups
                    
                    if ($null -ne $policy) {
                        Write-Output "DLP policy created successfully: $Name"
                    }
                    else {
                        Write-Output "Failed to create DLP policy"
                        exit 1
                    }
                }
                "RetentionPolicy" {
                    $policy = Create-RetentionPolicy -Name $Name -Description $Description -Locations $Locations -Settings $Settings -TargetGroups $TargetGroups -ExcludedGroups $ExcludedGroups
                    
                    if ($null -ne $policy) {
                        Write-Output "Retention policy created successfully: $Name"
                    }
                    else {
                        Write-Output "Failed to create retention policy"
                        exit 1
                    }
                }
                "InformationBarrier" {
                    $barrier = Create-InformationBarrier -Name $Name -Description $Description -Settings $Settings -TargetGroups $TargetGroups -RestrictedGroups $ExcludedGroups
                    
                    if ($null -ne $barrier) {
                        Write-Output "Information barrier created successfully: $Name"
                    }
                    else {
                        Write-Output "Failed to create information barrier"
                        exit 1
                    }
                }
            }
        }
        "Update" {
            if ([string]::IsNullOrEmpty($ComponentType)) {
                Write-Log "ComponentType parameter is required for Update action" -Level Error
                exit 1
            }
            
            if ([string]::IsNullOrEmpty($Name)) {
                Write-Log "Name parameter is required for Update action" -Level Error
                exit 1
            }
            
            switch ($ComponentType) {
                "SensitivityLabel" {
                    $label = Update-SensitivityLabel -Name $Name -Description $Description -Settings $Settings
                    
                    if ($null -ne $label) {
                        Write-Output "Sensitivity label updated successfully: $Name"
                    }
                    else {
                        Write-Output "Failed to update sensitivity label"
                        exit 1
                    }
                }
                "DLPPolicy" {
                    $policy = Update-DLPPolicy -Name $Name -Description $Description -Locations $Locations -Settings $Settings -TargetGroups $TargetGroups -ExcludedGroups $ExcludedGroups
                    
                    if ($null -ne $policy) {
                        Write-Output "DLP policy updated successfully: $Name"
                    }
                    else {
                        Write-Output "Failed to update DLP policy"
                        exit 1
                    }
                }
                "RetentionPolicy" {
                    $policy = Update-RetentionPolicy -Name $Name -Description $Description -Locations $Locations -Settings $Settings -TargetGroups $TargetGroups -ExcludedGroups $ExcludedGroups
                    
                    if ($null -ne $policy) {
                        Write-Output "Retention policy updated successfully: $Name"
                    }
                    else {
                        Write-Output "Failed to update retention policy"
                        exit 1
                    }
                }
                "InformationBarrier" {
                    $barrier = Update-InformationBarrier -Name $Name -Description $Description -Settings $Settings -TargetGroups $TargetGroups -RestrictedGroups $ExcludedGroups
                    
                    if ($null -ne $barrier) {
                        Write-Output "Information barrier updated successfully: $Name"
                    }
                    else {
                        Write-Output "Failed to update information barrier"
                        exit 1
                    }
                }
            }
        }
        "Remove" {
            if ([string]::IsNullOrEmpty($ComponentType)) {
                Write-Log "ComponentType parameter is required for Remove action" -Level Error
                exit 1
            }
            
            if ([string]::IsNullOrEmpty($Name)) {
                Write-Log "Name parameter is required for Remove action" -Level Error
                exit 1
            }
            
            switch ($ComponentType) {
                "SensitivityLabel" {
                    $result = Remove-SensitivityLabel -Name $Name
                    
                    if ($result) {
                        Write-Output "Sensitivity label removed successfully: $Name"
                    }
                    else {
                        Write-Output "Failed to remove sensitivity label"
                        exit 1
                    }
                }
                "DLPPolicy" {
                    $result = Remove-DLPPolicy -Name $Name
                    
                    if ($result) {
                        Write-Output "DLP policy removed successfully: $Name"
                    }
                    else {
                        Write-Output "Failed to remove DLP policy"
                        exit 1
                    }
                }
                "RetentionPolicy" {
                    $result = Remove-RetentionPolicy -Name $Name
                    
                    if ($result) {
                        Write-Output "Retention policy removed successfully: $Name"
                    }
                    else {
                        Write-Output "Failed to remove retention policy"
                        exit 1
                    }
                }
                "InformationBarrier" {
                    $result = Remove-InformationBarrier -Name $Name
                    
                    if ($result) {
                        Write-Output "Information barrier removed successfully: $Name"
                    }
                    else {
                        Write-Output "Failed to remove information barrier"
                        exit 1
                    }
                }
            }
        }
        "Report" {
            if ([string]::IsNullOrEmpty($ReportType)) {
                Write-Log "ReportType parameter is required for Report action" -Level Error
                exit 1
            }
            
            if ([string]::IsNullOrEmpty($ExportPath)) {
                Write-Log "ExportPath parameter is required for Report action" -Level Error
                exit 1
            }
            
            switch ($ReportType) {
                "Usage" {
                    $usageReport = Get-SensitivityLabelUsageReport -TimeFrame $TimeFrame
                    
                    if ($null -ne $usageReport) {
                        Write-Output "Sensitivity Label Usage Report:"
                        $usageReport | Format-Table -Property Date, User, Label, Action, ItemType
                        
                        $exportResult = Export-Report -Data $usageReport -ExportPath $ExportPath -ExportFormat $ExportFormat
                        
                        if ($exportResult) {
                            Write-Output "Sensitivity label usage report exported to: $ExportPath"
                        }
                        else {
                            Write-Output "Failed to export sensitivity label usage report"
                            exit 1
                        }
                    }
                    else {
                        Write-Output "No sensitivity label usage data found"
                    }
                }
                "Violations" {
                    $violationsReport = Get-DLPViolationsReport -TimeFrame $TimeFrame
                    
                    if ($null -ne $violationsReport) {
                        Write-Output "DLP Violations Report:"
                        $violationsReport | Format-Table -Property Date, Policy, User, Severity, Action
                        
                        $exportResult = Export-Report -Data $violationsReport -ExportPath $ExportPath -ExportFormat $ExportFormat
                        
                        if ($exportResult) {
                            Write-Output "DLP violations report exported to: $ExportPath"
                        }
                        else {
                            Write-Output "Failed to export DLP violations report"
                            exit 1
                        }
                    }
                    else {
                        Write-Output "No DLP violations data found"
                    }
                }
                "Compliance" {
                    $complianceReport = Get-ComplianceReport -ComponentType $ComponentType -TimeFrame $TimeFrame
                    
                    if ($null -ne $complianceReport) {
                        Write-Output "Compliance Report:"
                        $complianceReport | Format-Table -Property ComponentType, Name, Status
                        
                        $exportResult = Export-Report -Data $complianceReport -ExportPath $ExportPath -ExportFormat $ExportFormat
                        
                        if ($exportResult) {
                            Write-Output "Compliance report exported to: $ExportPath"
                        }
                        else {
                            Write-Output "Failed to export compliance report"
                            exit 1
                        }
                    }
                    else {
                        Write-Output "No compliance data found"
                    }
                }
            }
        }
    }
    
    # Output success message
    Write-Output "Microsoft Purview management operation completed successfully"
}
catch {
    Write-Log "Script execution failed: $_" -Level Error
    exit 1
}
finally {
    # No specific cleanup needed
    Write-Log "Script execution completed"
}
#endregion
