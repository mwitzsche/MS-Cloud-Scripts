<#
.SYNOPSIS
    Manages Microsoft Purview Information Protection (MIP) labels and policies.

.DESCRIPTION
    This script manages Microsoft Purview Information Protection (MIP) labels and policies,
    including creating, updating, and removing sensitivity labels, label policies, and
    auto-labeling policies. It also supports reporting on label usage and policy compliance.

.PARAMETER Action
    The action to perform (Get, Create, Update, Remove, Report).

.PARAMETER ComponentType
    The type of MIP component to manage (SensitivityLabel, LabelPolicy, AutoLabelPolicy).

.PARAMETER Name
    The name of the component to manage.

.PARAMETER Description
    The description for the component.

.PARAMETER Settings
    Hashtable of settings for the component.

.PARAMETER TargetLocations
    Array of locations to apply the component to (Exchange, SharePoint, OneDrive, Teams, Devices).

.PARAMETER TargetGroups
    Array of group IDs to target with the component.

.PARAMETER ExcludedGroups
    Array of group IDs to exclude from the component.

.PARAMETER ReportType
    The type of report to generate (Usage, Compliance, Effectiveness).

.PARAMETER TimeFrame
    The time frame for the report (Last7Days, Last30Days, Last90Days).

.PARAMETER ExportPath
    The path where the report will be saved.

.PARAMETER ExportFormat
    The format of the export file (CSV, JSON, Excel).

.PARAMETER LogPath
    Path where logs will be stored. Defaults to Windows log directory.

.EXAMPLE
    .\Manage-PurviewInformationProtection.ps1 -Action Create -ComponentType SensitivityLabel -Name "Confidential" -Description "For confidential data" -Settings @{EncryptionEnabled=$true; MarkingEnabled=$true}
    Creates a new sensitivity label with encryption and marking enabled.

.EXAMPLE
    .\Manage-PurviewInformationProtection.ps1 -Action Report -ReportType Usage -TimeFrame Last30Days -ExportPath "C:\Reports\LabelUsage.csv" -ExportFormat CSV
    Generates a sensitivity label usage report for the last 30 days and exports it to CSV format.

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
    [string]$LogPath = "$env:SystemRoot\Logs\Manage-PurviewInformationProtection",
    
    [Parameter(Mandatory = $true)]
    [ValidateSet("Get", "Create", "Update", "Remove", "Report")]
    [string]$Action,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("SensitivityLabel", "LabelPolicy", "AutoLabelPolicy", "")]
    [string]$ComponentType = "",
    
    [Parameter(Mandatory = $false)]
    [string]$Name = "",
    
    [Parameter(Mandatory = $false)]
    [string]$Description = "",
    
    [Parameter(Mandatory = $false)]
    [hashtable]$Settings = @{},
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Exchange", "SharePoint", "OneDrive", "Teams", "Devices")]
    [string[]]$TargetLocations = @(),
    
    [Parameter(Mandatory = $false)]
    [string[]]$TargetGroups = @(),
    
    [Parameter(Mandatory = $false)]
    [string[]]$ExcludedGroups = @(),
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Usage", "Compliance", "Effectiveness", "")]
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

function Connect-ToComplianceCenter {
    [CmdletBinding()]
    param()
    
    try {
        # Check if already connected
        try {
            $connectionStatus = Get-IPPSSession -ErrorAction SilentlyContinue
            if ($null -ne $connectionStatus) {
                Write-Log "Already connected to Security & Compliance Center"
                return $true
            }
        }
        catch {
            # Not connected
        }
        
        # Connect to Security & Compliance Center
        Write-Log "Connecting to Security & Compliance Center..."
        Connect-IPPSSession -ErrorAction Stop
        
        # Verify connection
        $connectionStatus = Get-IPPSSession -ErrorAction SilentlyContinue
        if ($null -ne $connectionStatus) {
            Write-Log "Successfully connected to Security & Compliance Center"
            return $true
        }
        else {
            Write-Log "Failed to verify Security & Compliance Center connection" -Level Error
            return $false
        }
    }
    catch {
        Write-Log "Error connecting to Security & Compliance Center: $_" -Level Error
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
        $encryptionEnabled = if ($Settings.ContainsKey("EncryptionEnabled")) { $Settings.EncryptionEnabled } else { $existingLabel.EncryptionEnabled }
        $markingEnabled = if ($Settings.ContainsKey("MarkingEnabled")) { $Settings.MarkingEnabled } else { ($existingLabel.HeaderEnabled -or $existingLabel.FooterEnabled -or $existingLabel.WaterMarkingEnabled) }
        $headerText = if ($Settings.ContainsKey("HeaderText")) { $Settings.HeaderText } else { $existingLabel.HeaderText }
        $footerText = if ($Settings.ContainsKey("FooterText")) { $Settings.FooterText } else { $existingLabel.FooterText }
        $watermarkText = if ($Settings.ContainsKey("WatermarkText")) { $Settings.WatermarkText } else { $existingLabel.WaterMarkingText }
        $contentExpirationEnabled = if ($Settings.ContainsKey("ContentExpirationEnabled")) { $Settings.ContentExpirationEnabled } else { ($existingLabel.EncryptionContentExpirationType -ne "Never") }
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

function Get-LabelPolicies {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$Name = ""
    )
    
    try {
        Write-Log "Retrieving label policies..."
        
        # Get label policies
        $policies = Get-LabelPolicy
        
        if ($null -eq $policies) {
            Write-Log "No label policies found" -Level Warning
            return $null
        }
        
        # Filter by name if specified
        if (-not [string]::IsNullOrEmpty($Name)) {
            $filteredPolicies = $policies | Where-Object { $_.Name -eq $Name }
            
            if ($null -eq $filteredPolicies -or $filteredPolicies.Count -eq 0) {
                Write-Log "No label policy found with name: $Name" -Level Warning
                return $null
            }
            
            return $filteredPolicies
        }
        
        Write-Log "Retrieved $($policies.Count) label policies"
        return $policies
    }
    catch {
        Write-Log "Error retrieving label policies: $_" -Level Error
        return $null
    }
}

function Create-LabelPolicy {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $false)]
        [string]$Description = "",
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Settings = @{},
        
        [Parameter(Mandatory = $false)]
        [string[]]$TargetLocations = @(),
        
        [Parameter(Mandatory = $false)]
        [string[]]$TargetGroups = @(),
        
        [Parameter(Mandatory = $false)]
        [string[]]$ExcludedGroups = @()
    )
    
    try {
        Write-Log "Creating label policy: $Name..."
        
        # Check if policy already exists
        $existingPolicies = Get-LabelPolicies -Name $Name
        
        if ($null -ne $existingPolicies) {
            Write-Log "Label policy already exists with name: $Name" -Level Warning
            return $null
        }
        
        # Extract settings
        $labels = if ($Settings.ContainsKey("Labels")) { $Settings.Labels } else { @() }
        $defaultLabel = if ($Settings.ContainsKey("DefaultLabel")) { $Settings.DefaultLabel } else { "" }
        $mandatory = $Settings.ContainsKey("Mandatory") -and $Settings.Mandatory
        $disallowOverride = $Settings.ContainsKey("DisallowOverride") -and $Settings.DisallowOverride
        
        # Map locations
        $locationsMap = @{
            Exchange = $false
            SharePoint = $false
            OneDrive = $false
            Teams = $false
            Devices = $false
        }
        
        foreach ($location in $TargetLocations) {
            $locationsMap[$location] = $true
        }
        
        # Create policy parameters
        $policyParams = @{
            Name = $Name
            Comment = $Description
        }
        
        # Add labels if specified
        if ($labels.Count -gt 0) {
            $policyParams.Labels = $labels
        }
        
        # Add default label if specified
        if (-not [string]::IsNullOrEmpty($defaultLabel)) {
            $policyParams.DefaultLabel = $defaultLabel
        }
        
        # Add mandatory setting if specified
        if ($mandatory) {
            $policyParams.AdvancedSettings = @{
                "RequireDowngradeJustification" = "True"
            }
        }
        
        # Add disallow override setting if specified
        if ($disallowOverride) {
            if (-not $policyParams.ContainsKey("AdvancedSettings")) {
                $policyParams.AdvancedSettings = @{}
            }
            
            $policyParams.AdvancedSettings["AllowedOverride"] = "False"
        }
        
        # Add locations
        $policyParams.ExchangeLocation = if ($locationsMap.Exchange) { "All" } else { "None" }
        $policyParams.SharePointLocation = if ($locationsMap.SharePoint) { "All" } else { "None" }
        $policyParams.OneDriveLocation = if ($locationsMap.OneDrive) { "All" } else { "None" }
        $policyParams.ModernGroupLocation = if ($locationsMap.Teams) { "All" } else { "None" }
        
        # Add target groups if specified
        if ($TargetGroups.Count -gt 0) {
            $policyParams.AdvancedSettings = @{
                "ScopingRules" = ($TargetGroups -join ",")
            }
        }
        
        # Add excluded groups if specified
        if ($ExcludedGroups.Count -gt 0) {
            if (-not $policyParams.ContainsKey("AdvancedSettings")) {
                $policyParams.AdvancedSettings = @{}
            }
            
            $policyParams.AdvancedSettings["ExcludedScopingRules"] = ($ExcludedGroups -join ",")
        }
        
        # Create policy
        $policy = New-LabelPolicy @policyParams
        
        Write-Log "Label policy created successfully: $Name"
        return $policy
    }
    catch {
        Write-Log "Error creating label policy: $_" -Level Error
        return $null
    }
}

function Update-LabelPolicy {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $false)]
        [string]$Description = "",
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Settings = @{},
        
        [Parameter(Mandatory = $false)]
        [string[]]$TargetLocations = @(),
        
        [Parameter(Mandatory = $false)]
        [string[]]$TargetGroups = @(),
        
        [Parameter(Mandatory = $false)]
        [string[]]$ExcludedGroups = @()
    )
    
    try {
        Write-Log "Updating label policy: $Name..."
        
        # Get existing policy
        $existingPolicies = Get-LabelPolicies -Name $Name
        
        if ($null -eq $existingPolicies) {
            Write-Log "Label policy not found with name: $Name" -Level Warning
            return $null
        }
        
        $existingPolicy = $existingPolicies[0]
        
        # Extract settings
        $labels = if ($Settings.ContainsKey("Labels")) { $Settings.Labels } else { $null }
        $defaultLabel = if ($Settings.ContainsKey("DefaultLabel")) { $Settings.DefaultLabel } else { $null }
        $mandatory = if ($Settings.ContainsKey("Mandatory")) { $Settings.Mandatory } else { $null }
        $disallowOverride = if ($Settings.ContainsKey("DisallowOverride")) { $Settings.DisallowOverride } else { $null }
        
        # Map locations
        $locationsMap = @{
            Exchange = $existingPolicy.ExchangeLocation -ne "None"
            SharePoint = $existingPolicy.SharePointLocation -ne "None"
            OneDrive = $existingPolicy.OneDriveLocation -ne "None"
            Teams = $existingPolicy.ModernGroupLocation -ne "None"
            Devices = $false
        }
        
        foreach ($location in $TargetLocations) {
            $locationsMap[$location] = $true
        }
        
        # Create update parameters
        $updateParams = @{
            Identity = $existingPolicy.Identity
        }
        
        # Add description if provided
        if (-not [string]::IsNullOrEmpty($Description)) {
            $updateParams.Comment = $Description
        }
        
        # Add labels if specified
        if ($null -ne $labels) {
            $updateParams.Labels = $labels
        }
        
        # Add default label if specified
        if ($null -ne $defaultLabel) {
            $updateParams.DefaultLabel = $defaultLabel
        }
        
        # Add locations if changed
        if ($TargetLocations.Count -gt 0) {
            $updateParams.ExchangeLocation = if ($locationsMap.Exchange) { "All" } else { "None" }
            $updateParams.SharePointLocation = if ($locationsMap.SharePoint) { "All" } else { "None" }
            $updateParams.OneDriveLocation = if ($locationsMap.OneDrive) { "All" } else { "None" }
            $updateParams.ModernGroupLocation = if ($locationsMap.Teams) { "All" } else { "None" }
        }
        
        # Add advanced settings if specified
        $advancedSettings = @{}
        
        if ($null -ne $mandatory) {
            $advancedSettings["RequireDowngradeJustification"] = if ($mandatory) { "True" } else { "False" }
        }
        
        if ($null -ne $disallowOverride) {
            $advancedSettings["AllowedOverride"] = if ($disallowOverride) { "False" } else { "True" }
        }
        
        if ($TargetGroups.Count -gt 0) {
            $advancedSettings["ScopingRules"] = ($TargetGroups -join ",")
        }
        
        if ($ExcludedGroups.Count -gt 0) {
            $advancedSettings["ExcludedScopingRules"] = ($ExcludedGroups -join ",")
        }
        
        if ($advancedSettings.Count -gt 0) {
            $updateParams.AdvancedSettings = $advancedSettings
        }
        
        # Update policy
        $policy = Set-LabelPolicy @updateParams
        
        Write-Log "Label policy updated successfully: $Name"
        return $policy
    }
    catch {
        Write-Log "Error updating label policy: $_" -Level Error
        return $null
    }
}

function Remove-LabelPolicy {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Name
    )
    
    try {
        Write-Log "Removing label policy: $Name..."
        
        # Get existing policy
        $existingPolicies = Get-LabelPolicies -Name $Name
        
        if ($null -eq $existingPolicies) {
            Write-Log "Label policy not found with name: $Name" -Level Warning
            return $false
        }
        
        $existingPolicy = $existingPolicies[0]
        
        # Remove policy
        Remove-LabelPolicy -Identity $existingPolicy.Identity -Confirm:$false
        
        Write-Log "Label policy removed successfully: $Name"
        return $true
    }
    catch {
        Write-Log "Error removing label policy: $_" -Level Error
        return $false
    }
}

function Get-AutoLabelPolicies {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$Name = ""
    )
    
    try {
        Write-Log "Retrieving auto-labeling policies..."
        
        # Get auto-labeling policies
        $policies = Get-AutoSensitivityLabelPolicy
        
        if ($null -eq $policies) {
            Write-Log "No auto-labeling policies found" -Level Warning
            return $null
        }
        
        # Filter by name if specified
        if (-not [string]::IsNullOrEmpty($Name)) {
            $filteredPolicies = $policies | Where-Object { $_.Name -eq $Name }
            
            if ($null -eq $filteredPolicies -or $filteredPolicies.Count -eq 0) {
                Write-Log "No auto-labeling policy found with name: $Name" -Level Warning
                return $null
            }
            
            return $filteredPolicies
        }
        
        Write-Log "Retrieved $($policies.Count) auto-labeling policies"
        return $policies
    }
    catch {
        Write-Log "Error retrieving auto-labeling policies: $_" -Level Error
        return $null
    }
}

function Create-AutoLabelPolicy {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $false)]
        [string]$Description = "",
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Settings = @{},
        
        [Parameter(Mandatory = $false)]
        [string[]]$TargetLocations = @(),
        
        [Parameter(Mandatory = $false)]
        [string[]]$TargetGroups = @(),
        
        [Parameter(Mandatory = $false)]
        [string[]]$ExcludedGroups = @()
    )
    
    try {
        Write-Log "Creating auto-labeling policy: $Name..."
        
        # Check if policy already exists
        $existingPolicies = Get-AutoLabelPolicies -Name $Name
        
        if ($null -ne $existingPolicies) {
            Write-Log "Auto-labeling policy already exists with name: $Name" -Level Warning
            return $null
        }
        
        # Extract settings
        $label = if ($Settings.ContainsKey("Label")) { $Settings.Label } else { "" }
        $sensitiveInfoTypes = if ($Settings.ContainsKey("SensitiveInfoTypes")) { $Settings.SensitiveInfoTypes } else { @() }
        $confidenceLevel = if ($Settings.ContainsKey("ConfidenceLevel")) { $Settings.ConfidenceLevel } else { "Medium" }
        $mode = if ($Settings.ContainsKey("Mode")) { $Settings.Mode } else { "TestWithoutNotifications" }
        
        if ([string]::IsNullOrEmpty($label)) {
            Write-Log "Label parameter is required for auto-labeling policy" -Level Error
            return $null
        }
        
        if ($sensitiveInfoTypes.Count -eq 0) {
            Write-Log "SensitiveInfoTypes parameter is required for auto-labeling policy" -Level Error
            return $null
        }
        
        # Map locations
        $locationsMap = @{
            Exchange = $false
            SharePoint = $false
            OneDrive = $false
        }
        
        foreach ($location in $TargetLocations) {
            if ($location -eq "Exchange" -or $location -eq "SharePoint" -or $location -eq "OneDrive") {
                $locationsMap[$location] = $true
            }
        }
        
        # Create policy parameters
        $policyParams = @{
            Name = $Name
            Comment = $Description
            ApplySensitivityLabel = $label
            Mode = $mode
        }
        
        # Add locations
        $policyParams.ExchangeLocation = if ($locationsMap.Exchange) { "All" } else { "None" }
        $policyParams.SharePointLocation = if ($locationsMap.SharePoint) { "All" } else { "None" }
        $policyParams.OneDriveLocation = if ($locationsMap.OneDrive) { "All" } else { "None" }
        
        # Add target groups if specified
        if ($TargetGroups.Count -gt 0) {
            $policyParams.ExchangeSenderMemberOf = $TargetGroups
        }
        
        # Add excluded groups if specified
        if ($ExcludedGroups.Count -gt 0) {
            $policyParams.ExchangeSenderMemberOfException = $ExcludedGroups
        }
        
        # Create policy
        $policy = New-AutoSensitivityLabelPolicy @policyParams
        
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
                MinConfidence = $confidenceLevel
                MinCount = 1
            }
        }
        
        # Create rule
        $rule = New-AutoSensitivityLabelRule @ruleParams
        
        Write-Log "Auto-labeling policy created successfully: $Name"
        return $policy
    }
    catch {
        Write-Log "Error creating auto-labeling policy: $_" -Level Error
        return $null
    }
}

function Update-AutoLabelPolicy {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $false)]
        [string]$Description = "",
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Settings = @{},
        
        [Parameter(Mandatory = $false)]
        [string[]]$TargetLocations = @(),
        
        [Parameter(Mandatory = $false)]
        [string[]]$TargetGroups = @(),
        
        [Parameter(Mandatory = $false)]
        [string[]]$ExcludedGroups = @()
    )
    
    try {
        Write-Log "Updating auto-labeling policy: $Name..."
        
        # Get existing policy
        $existingPolicies = Get-AutoLabelPolicies -Name $Name
        
        if ($null -eq $existingPolicies) {
            Write-Log "Auto-labeling policy not found with name: $Name" -Level Warning
            return $null
        }
        
        $existingPolicy = $existingPolicies[0]
        
        # Extract settings
        $label = if ($Settings.ContainsKey("Label")) { $Settings.Label } else { $null }
        $mode = if ($Settings.ContainsKey("Mode")) { $Settings.Mode } else { $null }
        $sensitiveInfoTypes = if ($Settings.ContainsKey("SensitiveInfoTypes")) { $Settings.SensitiveInfoTypes } else { $null }
        $confidenceLevel = if ($Settings.ContainsKey("ConfidenceLevel")) { $Settings.ConfidenceLevel } else { $null }
        
        # Map locations
        $locationsMap = @{
            Exchange = $existingPolicy.ExchangeLocation -ne "None"
            SharePoint = $existingPolicy.SharePointLocation -ne "None"
            OneDrive = $existingPolicy.OneDriveLocation -ne "None"
        }
        
        foreach ($location in $TargetLocations) {
            if ($location -eq "Exchange" -or $location -eq "SharePoint" -or $location -eq "OneDrive") {
                $locationsMap[$location] = $true
            }
        }
        
        # Create update parameters
        $updateParams = @{
            Identity = $existingPolicy.Identity
        }
        
        # Add description if provided
        if (-not [string]::IsNullOrEmpty($Description)) {
            $updateParams.Comment = $Description
        }
        
        # Add label if specified
        if ($null -ne $label) {
            $updateParams.ApplySensitivityLabel = $label
        }
        
        # Add mode if specified
        if ($null -ne $mode) {
            $updateParams.Mode = $mode
        }
        
        # Add locations if changed
        if ($TargetLocations.Count -gt 0) {
            $updateParams.ExchangeLocation = if ($locationsMap.Exchange) { "All" } else { "None" }
            $updateParams.SharePointLocation = if ($locationsMap.SharePoint) { "All" } else { "None" }
            $updateParams.OneDriveLocation = if ($locationsMap.OneDrive) { "All" } else { "None" }
        }
        
        # Add target groups if specified
        if ($TargetGroups.Count -gt 0) {
            $updateParams.ExchangeSenderMemberOf = $TargetGroups
        }
        
        # Add excluded groups if specified
        if ($ExcludedGroups.Count -gt 0) {
            $updateParams.ExchangeSenderMemberOfException = $ExcludedGroups
        }
        
        # Update policy
        $policy = Set-AutoSensitivityLabelPolicy @updateParams
        
        # Update rule if sensitive info types or confidence level is specified
        if ($null -ne $sensitiveInfoTypes -or $null -ne $confidenceLevel) {
            # Get existing rule
            $existingRule = Get-AutoSensitivityLabelRule -Policy $Name
            
            if ($null -ne $existingRule) {
                # Create rule update parameters
                $ruleUpdateParams = @{
                    Identity = $existingRule.Identity
                }
                
                # Add sensitive info types if specified
                if ($null -ne $sensitiveInfoTypes -and $sensitiveInfoTypes.Count -gt 0) {
                    $ruleUpdateParams.ContentContainsSensitiveInformation = @()
                    
                    foreach ($infoType in $sensitiveInfoTypes) {
                        $ruleUpdateParams.ContentContainsSensitiveInformation += @{
                            Name = $infoType
                            MinConfidence = $confidenceLevel ?? "Medium"
                            MinCount = 1
                        }
                    }
                }
                
                # Update rule
                Set-AutoSensitivityLabelRule @ruleUpdateParams
            }
        }
        
        Write-Log "Auto-labeling policy updated successfully: $Name"
        return $policy
    }
    catch {
        Write-Log "Error updating auto-labeling policy: $_" -Level Error
        return $null
    }
}

function Remove-AutoLabelPolicy {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Name
    )
    
    try {
        Write-Log "Removing auto-labeling policy: $Name..."
        
        # Get existing policy
        $existingPolicies = Get-AutoLabelPolicies -Name $Name
        
        if ($null -eq $existingPolicies) {
            Write-Log "Auto-labeling policy not found with name: $Name" -Level Warning
            return $false
        }
        
        $existingPolicy = $existingPolicies[0]
        
        # Remove policy
        Remove-AutoSensitivityLabelPolicy -Identity $existingPolicy.Identity -Confirm:$false
        
        Write-Log "Auto-labeling policy removed successfully: $Name"
        return $true
    }
    catch {
        Write-Log "Error removing auto-labeling policy: $_" -Level Error
        return $false
    }
}

function Get-LabelUsageReport {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$TimeFrame = "Last30Days"
    )
    
    try {
        Write-Log "Generating label usage report for time frame: $TimeFrame..."
        
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
            Write-Log "No label usage found" -Level Warning
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
        
        # Get label usage summary
        $labelSummary = $usageReport | Group-Object -Property Label | Select-Object Name, Count
        
        # Get user usage summary
        $userSummary = $usageReport | Group-Object -Property User | Select-Object Name, Count
        
        # Get action summary
        $actionSummary = $usageReport | Group-Object -Property Action | Select-Object Name, Count
        
        # Get location summary
        $locationSummary = $usageReport | Group-Object -Property Location | Select-Object Name, Count
        
        # Create final report
        $finalReport = [PSCustomObject]@{
            TimeFrame = $TimeFrame
            StartDate = $startDateStr
            EndDate = $endDateStr
            TotalEvents = $usageReport.Count
            LabelSummary = $labelSummary
            UserSummary = $userSummary
            ActionSummary = $actionSummary
            LocationSummary = $locationSummary
            DetailedEvents = $usageReport
        }
        
        Write-Log "Generated label usage report with $($usageReport.Count) events"
        return $finalReport
    }
    catch {
        Write-Log "Error generating label usage report: $_" -Level Error
        return $null
    }
}

function Get-LabelComplianceReport {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$TimeFrame = "Last30Days"
    )
    
    try {
        Write-Log "Generating label compliance report for time frame: $TimeFrame..."
        
        # Get sensitivity labels
        $labels = Get-SensitivityLabels
        
        if ($null -eq $labels) {
            Write-Log "No sensitivity labels found" -Level Warning
            return $null
        }
        
        # Get label usage
        $labelUsage = Get-LabelUsageReport -TimeFrame $TimeFrame
        
        if ($null -eq $labelUsage) {
            Write-Log "No label usage found" -Level Warning
            return $null
        }
        
        # Get label policies
        $labelPolicies = Get-LabelPolicies
        
        if ($null -eq $labelPolicies) {
            Write-Log "No label policies found" -Level Warning
            return $null
        }
        
        # Get auto-labeling policies
        $autoLabelPolicies = Get-AutoLabelPolicies
        
        # Create compliance report
        $complianceReport = @()
        
        foreach ($label in $labels) {
            $labelName = $label.Name
            
            # Get usage count
            $usageCount = 0
            $labelSummary = $labelUsage.LabelSummary | Where-Object { $_.Name -eq $labelName }
            
            if ($null -ne $labelSummary) {
                $usageCount = $labelSummary.Count
            }
            
            # Get policies using this label
            $policiesUsingLabel = @()
            
            foreach ($policy in $labelPolicies) {
                if ($policy.Labels -contains $labelName) {
                    $policiesUsingLabel += $policy.Name
                }
            }
            
            # Get auto-labeling policies using this label
            $autoLabelPoliciesUsingLabel = @()
            
            if ($null -ne $autoLabelPolicies) {
                foreach ($policy in $autoLabelPolicies) {
                    if ($policy.ApplySensitivityLabel -eq $labelName) {
                        $autoLabelPoliciesUsingLabel += $policy.Name
                    }
                }
            }
            
            $complianceReport += [PSCustomObject]@{
                Label = $labelName
                Description = $label.Comment
                UsageCount = $usageCount
                Policies = $policiesUsingLabel -join ", "
                AutoLabelPolicies = $autoLabelPoliciesUsingLabel -join ", "
                EncryptionEnabled = $label.EncryptionEnabled
                MarkingEnabled = ($label.HeaderEnabled -or $label.FooterEnabled -or $label.WaterMarkingEnabled)
                TimeFrame = $TimeFrame
            }
        }
        
        Write-Log "Generated label compliance report for $($labels.Count) labels"
        return $complianceReport
    }
    catch {
        Write-Log "Error generating label compliance report: $_" -Level Error
        return $null
    }
}

function Get-LabelEffectivenessReport {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$TimeFrame = "Last30Days"
    )
    
    try {
        Write-Log "Generating label effectiveness report for time frame: $TimeFrame..."
        
        # Get label usage
        $labelUsage = Get-LabelUsageReport -TimeFrame $TimeFrame
        
        if ($null -eq $labelUsage) {
            Write-Log "No label usage found" -Level Warning
            return $null
        }
        
        # Get auto-labeling policies
        $autoLabelPolicies = Get-AutoLabelPolicies
        
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
        $dlpIncidents = Get-DlpDetailReport -StartDate $startDateStr -EndDate $endDateStr
        
        # Create effectiveness report
        $effectivenessReport = @()
        
        # Calculate manual vs. auto-labeling
        $manualLabelingCount = ($labelUsage.DetailedEvents | Where-Object { $_.Action -eq "LabelApplied" -or $_.Action -eq "LabelChanged" }).Count
        $autoLabelingCount = ($labelUsage.DetailedEvents | Where-Object { $_.Action -eq "LabelAutoApplied" }).Count
        $totalLabelingCount = $manualLabelingCount + $autoLabelingCount
        
        $manualLabelingPercentage = if ($totalLabelingCount -gt 0) { [math]::Round(($manualLabelingCount / $totalLabelingCount) * 100, 2) } else { 0 }
        $autoLabelingPercentage = if ($totalLabelingCount -gt 0) { [math]::Round(($autoLabelingCount / $totalLabelingCount) * 100, 2) } else { 0 }
        
        # Calculate label changes
        $labelChangesCount = ($labelUsage.DetailedEvents | Where-Object { $_.Action -eq "LabelChanged" }).Count
        $labelChangesPercentage = if ($totalLabelingCount -gt 0) { [math]::Round(($labelChangesCount / $totalLabelingCount) * 100, 2) } else { 0 }
        
        # Calculate DLP incidents
        $dlpIncidentsCount = if ($null -ne $dlpIncidents) { $dlpIncidents.Count } else { 0 }
        
        # Calculate auto-labeling policy effectiveness
        $autoLabelingPolicyEffectiveness = @()
        
        if ($null -ne $autoLabelPolicies) {
            foreach ($policy in $autoLabelPolicies) {
                $policyLabel = $policy.ApplySensitivityLabel
                $policyLabelCount = ($labelUsage.DetailedEvents | Where-Object { $_.Label -eq $policyLabel -and $_.Action -eq "LabelAutoApplied" }).Count
                
                $autoLabelingPolicyEffectiveness += [PSCustomObject]@{
                    Policy = $policy.Name
                    Label = $policyLabel
                    Mode = $policy.Mode
                    Count = $policyLabelCount
                }
            }
        }
        
        # Create final report
        $effectivenessReport = [PSCustomObject]@{
            TimeFrame = $TimeFrame
            StartDate = $startDateStr
            EndDate = $endDateStr
            TotalLabelingEvents = $totalLabelingCount
            ManualLabelingCount = $manualLabelingCount
            ManualLabelingPercentage = $manualLabelingPercentage
            AutoLabelingCount = $autoLabelingCount
            AutoLabelingPercentage = $autoLabelingPercentage
            LabelChangesCount = $labelChangesCount
            LabelChangesPercentage = $labelChangesPercentage
            DLPIncidentsCount = $dlpIncidentsCount
            AutoLabelingPolicyEffectiveness = $autoLabelingPolicyEffectiveness
        }
        
        Write-Log "Generated label effectiveness report"
        return $effectivenessReport
    }
    catch {
        Write-Log "Error generating label effectiveness report: $_" -Level Error
        return $null
    }
}

function Export-Report {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSObject]$Data,
        
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
                # Handle complex objects
                if ($Data.GetType().Name -eq "PSCustomObject" -and ($Data | Get-Member -MemberType NoteProperty -Name "DetailedEvents")) {
                    $Data.DetailedEvents | Export-Csv -Path $ExportPath -NoTypeInformation
                }
                elseif ($Data.GetType().Name -eq "PSCustomObject" -and ($Data | Get-Member -MemberType NoteProperty -Name "AutoLabelingPolicyEffectiveness")) {
                    $Data.AutoLabelingPolicyEffectiveness | Export-Csv -Path $ExportPath -NoTypeInformation
                }
                else {
                    $Data | Export-Csv -Path $ExportPath -NoTypeInformation
                }
            }
            "JSON" {
                $Data | ConvertTo-Json -Depth 10 | Out-File -FilePath $ExportPath
            }
            "Excel" {
                # Handle complex objects
                if ($Data.GetType().Name -eq "PSCustomObject" -and ($Data | Get-Member -MemberType NoteProperty -Name "DetailedEvents")) {
                    $excelPackage = $Data.DetailedEvents | Export-Excel -Path $ExportPath -WorksheetName "Label Usage" -TableName "LabelUsage" -AutoSize -PassThru
                    
                    $Data.LabelSummary | Export-Excel -ExcelPackage $excelPackage -WorksheetName "Label Summary" -TableName "LabelSummary" -AutoSize
                    $Data.UserSummary | Export-Excel -ExcelPackage $excelPackage -WorksheetName "User Summary" -TableName "UserSummary" -AutoSize
                    $Data.ActionSummary | Export-Excel -ExcelPackage $excelPackage -WorksheetName "Action Summary" -TableName "ActionSummary" -AutoSize
                    $Data.LocationSummary | Export-Excel -ExcelPackage $excelPackage -WorksheetName "Location Summary" -TableName "LocationSummary" -AutoSize
                    
                    Close-ExcelPackage $excelPackage
                }
                elseif ($Data.GetType().Name -eq "PSCustomObject" -and ($Data | Get-Member -MemberType NoteProperty -Name "AutoLabelingPolicyEffectiveness")) {
                    $excelPackage = New-Object OfficeOpenXml.ExcelPackage
                    $workbook = $excelPackage.Workbook
                    
                    # Create summary worksheet
                    $summarySheet = $workbook.Worksheets.Add("Summary")
                    $summarySheet.Cells[1, 1].Value = "Metric"
                    $summarySheet.Cells[1, 2].Value = "Value"
                    
                    $summarySheet.Cells[2, 1].Value = "Time Frame"
                    $summarySheet.Cells[2, 2].Value = $Data.TimeFrame
                    
                    $summarySheet.Cells[3, 1].Value = "Start Date"
                    $summarySheet.Cells[3, 2].Value = $Data.StartDate
                    
                    $summarySheet.Cells[4, 1].Value = "End Date"
                    $summarySheet.Cells[4, 2].Value = $Data.EndDate
                    
                    $summarySheet.Cells[5, 1].Value = "Total Labeling Events"
                    $summarySheet.Cells[5, 2].Value = $Data.TotalLabelingEvents
                    
                    $summarySheet.Cells[6, 1].Value = "Manual Labeling Count"
                    $summarySheet.Cells[6, 2].Value = $Data.ManualLabelingCount
                    
                    $summarySheet.Cells[7, 1].Value = "Manual Labeling Percentage"
                    $summarySheet.Cells[7, 2].Value = $Data.ManualLabelingPercentage
                    
                    $summarySheet.Cells[8, 1].Value = "Auto Labeling Count"
                    $summarySheet.Cells[8, 2].Value = $Data.AutoLabelingCount
                    
                    $summarySheet.Cells[9, 1].Value = "Auto Labeling Percentage"
                    $summarySheet.Cells[9, 2].Value = $Data.AutoLabelingPercentage
                    
                    $summarySheet.Cells[10, 1].Value = "Label Changes Count"
                    $summarySheet.Cells[10, 2].Value = $Data.LabelChangesCount
                    
                    $summarySheet.Cells[11, 1].Value = "Label Changes Percentage"
                    $summarySheet.Cells[11, 2].Value = $Data.LabelChangesPercentage
                    
                    $summarySheet.Cells[12, 1].Value = "DLP Incidents Count"
                    $summarySheet.Cells[12, 2].Value = $Data.DLPIncidentsCount
                    
                    # Create policy effectiveness worksheet
                    $policySheet = $workbook.Worksheets.Add("Policy Effectiveness")
                    $policySheet.Cells[1, 1].Value = "Policy"
                    $policySheet.Cells[1, 2].Value = "Label"
                    $policySheet.Cells[1, 3].Value = "Mode"
                    $policySheet.Cells[1, 4].Value = "Count"
                    
                    for ($i = 0; $i -lt $Data.AutoLabelingPolicyEffectiveness.Count; $i++) {
                        $policy = $Data.AutoLabelingPolicyEffectiveness[$i]
                        $policySheet.Cells[$i + 2, 1].Value = $policy.Policy
                        $policySheet.Cells[$i + 2, 2].Value = $policy.Label
                        $policySheet.Cells[$i + 2, 3].Value = $policy.Mode
                        $policySheet.Cells[$i + 2, 4].Value = $policy.Count
                    }
                    
                    # Auto-size columns
                    $summarySheet.Cells.AutoFitColumns()
                    $policySheet.Cells.AutoFitColumns()
                    
                    # Save the workbook
                    $excelPackage.SaveAs($ExportPath)
                }
                else {
                    $Data | Export-Excel -Path $ExportPath -AutoSize -TableName "MIPReport" -WorksheetName "MIP Report"
                }
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
    
    $connectedToComplianceCenter = Connect-ToComplianceCenter
    if (-not $connectedToComplianceCenter) {
        Write-Log "Cannot proceed without Security & Compliance Center connection" -Level Error
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
                "LabelPolicy" {
                    $policies = Get-LabelPolicies -Name $Name
                    
                    if ($null -ne $policies) {
                        Write-Output "Label Policies:"
                        $policies | Format-Table -Property Name, Comment, ExchangeLocation, SharePointLocation, OneDriveLocation, ModernGroupLocation
                        
                        # Export report if path is specified
                        if (-not [string]::IsNullOrEmpty($ExportPath)) {
                            $exportResult = Export-Report -Data $policies -ExportPath $ExportPath -ExportFormat $ExportFormat
                            
                            if ($exportResult) {
                                Write-Output "Label policies exported to: $ExportPath"
                            }
                        }
                    }
                    else {
                        Write-Output "No label policies found"
                    }
                }
                "AutoLabelPolicy" {
                    $policies = Get-AutoLabelPolicies -Name $Name
                    
                    if ($null -ne $policies) {
                        Write-Output "Auto-Labeling Policies:"
                        $policies | Format-Table -Property Name, Comment, ApplySensitivityLabel, Mode, ExchangeLocation, SharePointLocation, OneDriveLocation
                        
                        # Export report if path is specified
                        if (-not [string]::IsNullOrEmpty($ExportPath)) {
                            $exportResult = Export-Report -Data $policies -ExportPath $ExportPath -ExportFormat $ExportFormat
                            
                            if ($exportResult) {
                                Write-Output "Auto-labeling policies exported to: $ExportPath"
                            }
                        }
                    }
                    else {
                        Write-Output "No auto-labeling policies found"
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
                "LabelPolicy" {
                    $policy = Create-LabelPolicy -Name $Name -Description $Description -Settings $Settings -TargetLocations $TargetLocations -TargetGroups $TargetGroups -ExcludedGroups $ExcludedGroups
                    
                    if ($null -ne $policy) {
                        Write-Output "Label policy created successfully: $Name"
                    }
                    else {
                        Write-Output "Failed to create label policy"
                        exit 1
                    }
                }
                "AutoLabelPolicy" {
                    $policy = Create-AutoLabelPolicy -Name $Name -Description $Description -Settings $Settings -TargetLocations $TargetLocations -TargetGroups $TargetGroups -ExcludedGroups $ExcludedGroups
                    
                    if ($null -ne $policy) {
                        Write-Output "Auto-labeling policy created successfully: $Name"
                    }
                    else {
                        Write-Output "Failed to create auto-labeling policy"
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
                "LabelPolicy" {
                    $policy = Update-LabelPolicy -Name $Name -Description $Description -Settings $Settings -TargetLocations $TargetLocations -TargetGroups $TargetGroups -ExcludedGroups $ExcludedGroups
                    
                    if ($null -ne $policy) {
                        Write-Output "Label policy updated successfully: $Name"
                    }
                    else {
                        Write-Output "Failed to update label policy"
                        exit 1
                    }
                }
                "AutoLabelPolicy" {
                    $policy = Update-AutoLabelPolicy -Name $Name -Description $Description -Settings $Settings -TargetLocations $TargetLocations -TargetGroups $TargetGroups -ExcludedGroups $ExcludedGroups
                    
                    if ($null -ne $policy) {
                        Write-Output "Auto-labeling policy updated successfully: $Name"
                    }
                    else {
                        Write-Output "Failed to update auto-labeling policy"
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
                "LabelPolicy" {
                    $result = Remove-LabelPolicy -Name $Name
                    
                    if ($result) {
                        Write-Output "Label policy removed successfully: $Name"
                    }
                    else {
                        Write-Output "Failed to remove label policy"
                        exit 1
                    }
                }
                "AutoLabelPolicy" {
                    $result = Remove-AutoLabelPolicy -Name $Name
                    
                    if ($result) {
                        Write-Output "Auto-labeling policy removed successfully: $Name"
                    }
                    else {
                        Write-Output "Failed to remove auto-labeling policy"
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
                    $usageReport = Get-LabelUsageReport -TimeFrame $TimeFrame
                    
                    if ($null -ne $usageReport) {
                        Write-Output "Label Usage Report:"
                        Write-Output "Time Frame: $TimeFrame"
                        Write-Output "Total Events: $($usageReport.TotalEvents)"
                        Write-Output "Label Summary:"
                        $usageReport.LabelSummary | Format-Table -Property Name, Count
                        
                        $exportResult = Export-Report -Data $usageReport -ExportPath $ExportPath -ExportFormat $ExportFormat
                        
                        if ($exportResult) {
                            Write-Output "Label usage report exported to: $ExportPath"
                        }
                        else {
                            Write-Output "Failed to export label usage report"
                            exit 1
                        }
                    }
                    else {
                        Write-Output "No label usage data found"
                    }
                }
                "Compliance" {
                    $complianceReport = Get-LabelComplianceReport -TimeFrame $TimeFrame
                    
                    if ($null -ne $complianceReport) {
                        Write-Output "Label Compliance Report:"
                        Write-Output "Time Frame: $TimeFrame"
                        $complianceReport | Format-Table -Property Label, UsageCount, Policies, AutoLabelPolicies
                        
                        $exportResult = Export-Report -Data $complianceReport -ExportPath $ExportPath -ExportFormat $ExportFormat
                        
                        if ($exportResult) {
                            Write-Output "Label compliance report exported to: $ExportPath"
                        }
                        else {
                            Write-Output "Failed to export label compliance report"
                            exit 1
                        }
                    }
                    else {
                        Write-Output "No label compliance data found"
                    }
                }
                "Effectiveness" {
                    $effectivenessReport = Get-LabelEffectivenessReport -TimeFrame $TimeFrame
                    
                    if ($null -ne $effectivenessReport) {
                        Write-Output "Label Effectiveness Report:"
                        Write-Output "Time Frame: $TimeFrame"
                        Write-Output "Total Labeling Events: $($effectivenessReport.TotalLabelingEvents)"
                        Write-Output "Manual Labeling: $($effectivenessReport.ManualLabelingCount) ($($effectivenessReport.ManualLabelingPercentage)%)"
                        Write-Output "Auto Labeling: $($effectivenessReport.AutoLabelingCount) ($($effectivenessReport.AutoLabelingPercentage)%)"
                        Write-Output "Label Changes: $($effectivenessReport.LabelChangesCount) ($($effectivenessReport.LabelChangesPercentage)%)"
                        Write-Output "DLP Incidents: $($effectivenessReport.DLPIncidentsCount)"
                        
                        Write-Output "Auto-Labeling Policy Effectiveness:"
                        $effectivenessReport.AutoLabelingPolicyEffectiveness | Format-Table -Property Policy, Label, Mode, Count
                        
                        $exportResult = Export-Report -Data $effectivenessReport -ExportPath $ExportPath -ExportFormat $ExportFormat
                        
                        if ($exportResult) {
                            Write-Output "Label effectiveness report exported to: $ExportPath"
                        }
                        else {
                            Write-Output "Failed to export label effectiveness report"
                            exit 1
                        }
                    }
                    else {
                        Write-Output "No label effectiveness data found"
                    }
                }
            }
        }
    }
    
    # Output success message
    Write-Output "Microsoft Purview Information Protection management operation completed successfully"
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
