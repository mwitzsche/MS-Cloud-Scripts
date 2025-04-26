<#
.SYNOPSIS
    Configures Microsoft Defender XDR settings.

.DESCRIPTION
    This script configures various Microsoft Defender XDR settings including
    advanced features, detection settings, exclusions, and integration settings.
    It supports both tenant-wide and device-specific configurations.

.PARAMETER ConfigType
    The type of configuration to modify (AdvancedFeatures, DetectionSettings, Exclusions, Integration).

.PARAMETER Action
    The action to perform (Get, Set, Enable, Disable, Add, Remove).

.PARAMETER SettingName
    The name of the specific setting to configure.

.PARAMETER SettingValue
    The value to set for the specified setting.

.PARAMETER DeviceId
    The device ID to apply the configuration to. If not specified, applies to tenant-wide settings.

.PARAMETER ExclusionType
    The type of exclusion to configure (Path, Extension, Process, IP).

.PARAMETER ExclusionValue
    The value for the exclusion.

.PARAMETER ExclusionScope
    The scope for the exclusion (All, Windows, Mac, Linux).

.PARAMETER IntegrationType
    The type of integration to configure (SIEM, SOAR, Ticketing).

.PARAMETER IntegrationValue
    The configuration value for the integration.

.PARAMETER OutputPath
    The path where the configuration report will be saved.

.PARAMETER LogPath
    Path where logs will be stored. Defaults to Windows log directory.

.EXAMPLE
    .\Configure-DefenderXDR.ps1 -ConfigType AdvancedFeatures -Action Enable -SettingName "EDR_BlockMode"
    Enables the EDR Block Mode advanced feature.

.EXAMPLE
    .\Configure-DefenderXDR.ps1 -ConfigType Exclusions -Action Add -ExclusionType Path -ExclusionValue "C:\Program Files\MyApp" -ExclusionScope Windows
    Adds a path exclusion for Windows devices.

.NOTES
    Author: Michael Witzsche
    Date: April 26, 2025
    Version: 1.1
#>

#Requires -Modules Microsoft.Graph.Security, Microsoft.Graph.DeviceManagement

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$LogPath = "$env:SystemRoot\Logs\Configure-DefenderXDR",
    
    [Parameter(Mandatory = $true)]
    [ValidateSet("AdvancedFeatures", "DetectionSettings", "Exclusions", "Integration")]
    [string]$ConfigType,
    
    [Parameter(Mandatory = $true)]
    [ValidateSet("Get", "Set", "Enable", "Disable", "Add", "Remove")]
    [string]$Action,
    
    [Parameter(Mandatory = $false)]
    [string]$SettingName = "",
    
    [Parameter(Mandatory = $false)]
    [string]$SettingValue = "",
    
    [Parameter(Mandatory = $false)]
    [string]$DeviceId = "",
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Path", "Extension", "Process", "IP", "")]
    [string]$ExclusionType = "",
    
    [Parameter(Mandatory = $false)]
    [string]$ExclusionValue = "",
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("All", "Windows", "Mac", "Linux", "")]
    [string]$ExclusionScope = "All",
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("SIEM", "SOAR", "Ticketing", "")]
    [string]$IntegrationType = "",
    
    [Parameter(Mandatory = $false)]
    [string]$IntegrationValue = "",
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "$env:USERPROFILE\Desktop\DefenderXDR_Config_Report_$(Get-Date -Format 'yyyyMMdd').csv"
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

function Connect-ToMSGraph {
    [CmdletBinding()]
    param()
    
    try {
        # Check if already connected
        try {
            $graphSecurity = Get-MgSecuritySecurityConfigurationSetting -Top 1 -ErrorAction Stop
            Write-Log "Already connected to Microsoft Graph"
            return $true
        }
        catch {
            # Not connected, proceed with connection
        }
        
        # Connect to Microsoft Graph with required scopes
        Write-Log "Connecting to Microsoft Graph..."
        Connect-MgGraph -Scopes "SecurityConfiguration.ReadWrite.All", "DeviceManagementConfiguration.ReadWrite.All" -ErrorAction Stop
        
        # Verify connection
        try {
            $graphSecurity = Get-MgSecuritySecurityConfigurationSetting -Top 1 -ErrorAction Stop
            Write-Log "Successfully connected to Microsoft Graph"
            return $true
        }
        catch {
            Write-Log "Failed to verify Microsoft Graph connection" -Level Error
            return $false
        }
    }
    catch {
        Write-Log "Error connecting to Microsoft Graph: $_" -Level Error
        return $false
    }
}

function Get-AdvancedFeatures {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$SettingName = ""
    )
    
    try {
        # Get advanced features configuration
        $advancedFeatures = Get-MgSecuritySecurityConfigurationSetting -Filter "category eq 'AdvancedFeatures'"
        
        if ([string]::IsNullOrEmpty($SettingName)) {
            # Return all advanced features
            return $advancedFeatures
        }
        else {
            # Return specific advanced feature
            return $advancedFeatures | Where-Object { $_.DisplayName -eq $SettingName }
        }
    }
    catch {
        Write-Log "Error getting advanced features: $_" -Level Error
        return $null
    }
}

function Set-AdvancedFeature {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$SettingName,
        
        [Parameter(Mandatory = $true)]
        [bool]$Enabled
    )
    
    try {
        # Get the current setting
        $setting = Get-AdvancedFeatures -SettingName $SettingName
        
        if ($null -eq $setting) {
            Write-Log "Advanced feature not found: $SettingName" -Level Error
            return $false
        }
        
        # Update the setting
        $updateParams = @{
            "@odata.type" = "#microsoft.graph.securityConfigurationSetting"
            Enabled = $Enabled
        }
        
        Update-MgSecuritySecurityConfigurationSetting -SecurityConfigurationSettingId $setting.Id -BodyParameter $updateParams
        
        Write-Log "Advanced feature $SettingName updated successfully: Enabled=$Enabled"
        return $true
    }
    catch {
        Write-Log "Error updating advanced feature: $_" -Level Error
        return $false
    }
}

function Get-DetectionSettings {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$SettingName = ""
    )
    
    try {
        # Get detection settings configuration
        $detectionSettings = Get-MgSecuritySecurityConfigurationSetting -Filter "category eq 'DetectionSettings'"
        
        if ([string]::IsNullOrEmpty($SettingName)) {
            # Return all detection settings
            return $detectionSettings
        }
        else {
            # Return specific detection setting
            return $detectionSettings | Where-Object { $_.DisplayName -eq $SettingName }
        }
    }
    catch {
        Write-Log "Error getting detection settings: $_" -Level Error
        return $null
    }
}

function Set-DetectionSetting {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$SettingName,
        
        [Parameter(Mandatory = $true)]
        [string]$SettingValue
    )
    
    try {
        # Get the current setting
        $setting = Get-DetectionSettings -SettingName $SettingName
        
        if ($null -eq $setting) {
            Write-Log "Detection setting not found: $SettingName" -Level Error
            return $false
        }
        
        # Update the setting
        $updateParams = @{
            "@odata.type" = "#microsoft.graph.securityConfigurationSetting"
            Value = $SettingValue
        }
        
        Update-MgSecuritySecurityConfigurationSetting -SecurityConfigurationSettingId $setting.Id -BodyParameter $updateParams
        
        Write-Log "Detection setting $SettingName updated successfully: Value=$SettingValue"
        return $true
    }
    catch {
        Write-Log "Error updating detection setting: $_" -Level Error
        return $false
    }
}

function Get-Exclusions {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$ExclusionType = "",
        
        [Parameter(Mandatory = $false)]
        [string]$ExclusionScope = ""
    )
    
    try {
        # Get exclusions configuration
        $filter = "category eq 'Exclusions'"
        
        if (-not [string]::IsNullOrEmpty($ExclusionType)) {
            $filter += " and contains(displayName, '$ExclusionType')"
        }
        
        if (-not [string]::IsNullOrEmpty($ExclusionScope) -and $ExclusionScope -ne "All") {
            $filter += " and contains(displayName, '$ExclusionScope')"
        }
        
        $exclusions = Get-MgSecuritySecurityConfigurationSetting -Filter $filter
        
        return $exclusions
    }
    catch {
        Write-Log "Error getting exclusions: $_" -Level Error
        return $null
    }
}

function Add-Exclusion {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ExclusionType,
        
        [Parameter(Mandatory = $true)]
        [string]$ExclusionValue,
        
        [Parameter(Mandatory = $true)]
        [string]$ExclusionScope
    )
    
    try {
        # Validate exclusion type
        if (-not @("Path", "Extension", "Process", "IP").Contains($ExclusionType)) {
            Write-Log "Invalid exclusion type: $ExclusionType" -Level Error
            return $false
        }
        
        # Get the appropriate exclusion setting
        $settingName = "$ExclusionType"
        if ($ExclusionScope -ne "All") {
            $settingName += "_$ExclusionScope"
        }
        
        $exclusionSetting = Get-Exclusions -ExclusionType $ExclusionType -ExclusionScope $ExclusionScope | 
            Where-Object { $_.DisplayName -eq $settingName }
        
        if ($null -eq $exclusionSetting) {
            Write-Log "Exclusion setting not found: $settingName" -Level Error
            return $false
        }
        
        # Get current exclusions
        $currentExclusions = $exclusionSetting.Value -split ";"
        
        # Check if exclusion already exists
        if ($currentExclusions -contains $ExclusionValue) {
            Write-Log "Exclusion already exists: $ExclusionValue" -Level Warning
            return $true
        }
        
        # Add new exclusion
        $newExclusions = $currentExclusions + $ExclusionValue
        $newExclusionsString = $newExclusions -join ";"
        
        # Update the setting
        $updateParams = @{
            "@odata.type" = "#microsoft.graph.securityConfigurationSetting"
            Value = $newExclusionsString
        }
        
        Update-MgSecuritySecurityConfigurationSetting -SecurityConfigurationSettingId $exclusionSetting.Id -BodyParameter $updateParams
        
        Write-Log "Exclusion added successfully: Type=$ExclusionType, Value=$ExclusionValue, Scope=$ExclusionScope"
        return $true
    }
    catch {
        Write-Log "Error adding exclusion: $_" -Level Error
        return $false
    }
}

function Remove-Exclusion {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ExclusionType,
        
        [Parameter(Mandatory = $true)]
        [string]$ExclusionValue,
        
        [Parameter(Mandatory = $true)]
        [string]$ExclusionScope
    )
    
    try {
        # Validate exclusion type
        if (-not @("Path", "Extension", "Process", "IP").Contains($ExclusionType)) {
            Write-Log "Invalid exclusion type: $ExclusionType" -Level Error
            return $false
        }
        
        # Get the appropriate exclusion setting
        $settingName = "$ExclusionType"
        if ($ExclusionScope -ne "All") {
            $settingName += "_$ExclusionScope"
        }
        
        $exclusionSetting = Get-Exclusions -ExclusionType $ExclusionType -ExclusionScope $ExclusionScope | 
            Where-Object { $_.DisplayName -eq $settingName }
        
        if ($null -eq $exclusionSetting) {
            Write-Log "Exclusion setting not found: $settingName" -Level Error
            return $false
        }
        
        # Get current exclusions
        $currentExclusions = $exclusionSetting.Value -split ";"
        
        # Check if exclusion exists
        if ($currentExclusions -notcontains $ExclusionValue) {
            Write-Log "Exclusion does not exist: $ExclusionValue" -Level Warning
            return $true
        }
        
        # Remove exclusion
        $newExclusions = $currentExclusions | Where-Object { $_ -ne $ExclusionValue }
        $newExclusionsString = $newExclusions -join ";"
        
        # Update the setting
        $updateParams = @{
            "@odata.type" = "#microsoft.graph.securityConfigurationSetting"
            Value = $newExclusionsString
        }
        
        Update-MgSecuritySecurityConfigurationSetting -SecurityConfigurationSettingId $exclusionSetting.Id -BodyParameter $updateParams
        
        Write-Log "Exclusion removed successfully: Type=$ExclusionType, Value=$ExclusionValue, Scope=$ExclusionScope"
        return $true
    }
    catch {
        Write-Log "Error removing exclusion: $_" -Level Error
        return $false
    }
}

function Get-IntegrationSettings {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$IntegrationType = ""
    )
    
    try {
        # Get integration settings configuration
        $filter = "category eq 'Integration'"
        
        if (-not [string]::IsNullOrEmpty($IntegrationType)) {
            $filter += " and contains(displayName, '$IntegrationType')"
        }
        
        $integrationSettings = Get-MgSecuritySecurityConfigurationSetting -Filter $filter
        
        return $integrationSettings
    }
    catch {
        Write-Log "Error getting integration settings: $_" -Level Error
        return $null
    }
}

function Set-IntegrationSetting {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$IntegrationType,
        
        [Parameter(Mandatory = $true)]
        [string]$IntegrationValue
    )
    
    try {
        # Validate integration type
        if (-not @("SIEM", "SOAR", "Ticketing").Contains($IntegrationType)) {
            Write-Log "Invalid integration type: $IntegrationType" -Level Error
            return $false
        }
        
        # Get the integration setting
        $integrationSetting = Get-IntegrationSettings -IntegrationType $IntegrationType | 
            Where-Object { $_.DisplayName -eq $IntegrationType }
        
        if ($null -eq $integrationSetting) {
            Write-Log "Integration setting not found: $IntegrationType" -Level Error
            return $false
        }
        
        # Update the setting
        $updateParams = @{
            "@odata.type" = "#microsoft.graph.securityConfigurationSetting"
            Value = $IntegrationValue
        }
        
        Update-MgSecuritySecurityConfigurationSetting -SecurityConfigurationSettingId $integrationSetting.Id -BodyParameter $updateParams
        
        Write-Log "Integration setting updated successfully: Type=$IntegrationType, Value=$IntegrationValue"
        return $true
    }
    catch {
        Write-Log "Error updating integration setting: $_" -Level Error
        return $false
    }
}

function Export-ConfigurationReport {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )
    
    try {
        # Get all configuration settings
        $advancedFeatures = Get-AdvancedFeatures
        $detectionSettings = Get-DetectionSettings
        $exclusions = Get-Exclusions
        $integrationSettings = Get-IntegrationSettings
        
        # Combine all settings
        $allSettings = @()
        $allSettings += $advancedFeatures | Select-Object @{Name="ConfigType"; Expression={"AdvancedFeatures"}}, DisplayName, Enabled, Value, Category, Description
        $allSettings += $detectionSettings | Select-Object @{Name="ConfigType"; Expression={"DetectionSettings"}}, DisplayName, Enabled, Value, Category, Description
        $allSettings += $exclusions | Select-Object @{Name="ConfigType"; Expression={"Exclusions"}}, DisplayName, Enabled, Value, Category, Description
        $allSettings += $integrationSettings | Select-Object @{Name="ConfigType"; Expression={"Integration"}}, DisplayName, Enabled, Value, Category, Description
        
        # Export to CSV
        $allSettings | Export-Csv -Path $OutputPath -NoTypeInformation
        Write-Log "Configuration report exported to: $OutputPath"
        
        return $true
    }
    catch {
        Write-Log "Error exporting configuration report: $_" -Level Error
        return $false
    }
}
#endregion

#region Main Script
try {
    # Script start
    Write-Log "Script started with parameters: ConfigType=$ConfigType, Action=$Action"
    
    # Connect to Microsoft Graph
    $connectedToGraph = Connect-ToMSGraph
    if (-not $connectedToGraph) {
        Write-Log "Cannot proceed without Microsoft Graph connection" -Level Error
        exit 1
    }
    
    # Validate parameters based on config type and action
    switch ($ConfigType) {
        "AdvancedFeatures" {
            if ($Action -in @("Enable", "Disable") -and [string]::IsNullOrEmpty($SettingName)) {
                Write-Log "SettingName is required for $Action action on $ConfigType" -Level Error
                exit 1
            }
        }
        "DetectionSettings" {
            if ($Action -eq "Set" -and ([string]::IsNullOrEmpty($SettingName) -or [string]::IsNullOrEmpty($SettingValue))) {
                Write-Log "SettingName and SettingValue are required for $Action action on $ConfigType" -Level Error
                exit 1
            }
        }
        "Exclusions" {
            if ($Action -in @("Add", "Remove") -and ([string]::IsNullOrEmpty($ExclusionType) -or [string]::IsNullOrEmpty($ExclusionValue))) {
                Write-Log "ExclusionType and ExclusionValue are required for $Action action on $ConfigType" -Level Error
                exit 1
            }
        }
        "Integration" {
            if ($Action -eq "Set" -and ([string]::IsNullOrEmpty($IntegrationType) -or [string]::IsNullOrEmpty($IntegrationValue))) {
                Write-Log "IntegrationType and IntegrationValue are required for $Action action on $ConfigType" -Level Error
                exit 1
            }
        }
    }
    
    # Perform the action
    switch ($ConfigType) {
        "AdvancedFeatures" {
            switch ($Action) {
                "Get" {
                    $features = Get-AdvancedFeatures -SettingName $SettingName
                    
                    if ($null -eq $features) {
                        Write-Log "No advanced features found" -Level Warning
                        exit 0
                    }
                    
                    # Display features
                    Write-Output "Advanced Features:"
                    $features | Select-Object DisplayName, Enabled, Description | Format-Table -AutoSize
                    
                    # Export to file if specified
                    if (-not [string]::IsNullOrEmpty($OutputPath)) {
                        Export-ConfigurationReport -OutputPath $OutputPath
                    }
                }
                "Enable" {
                    $result = Set-AdvancedFeature -SettingName $SettingName -Enabled $true
                    
                    if ($result) {
                        Write-Output "Advanced feature $SettingName enabled successfully"
                    }
                    else {
                        Write-Output "Failed to enable advanced feature $SettingName"
                        exit 1
                    }
                }
                "Disable" {
                    $result = Set-AdvancedFeature -SettingName $SettingName -Enabled $false
                    
                    if ($result) {
                        Write-Output "Advanced feature $SettingName disabled successfully"
                    }
                    else {
                        Write-Output "Failed to disable advanced feature $SettingName"
                        exit 1
                    }
                }
                default {
                    Write-Log "Action $Action not supported for $ConfigType" -Level Error
                    exit 1
                }
            }
        }
        "DetectionSettings" {
            switch ($Action) {
                "Get" {
                    $settings = Get-DetectionSettings -SettingName $SettingName
                    
                    if ($null -eq $settings) {
                        Write-Log "No detection settings found" -Level Warning
                        exit 0
                    }
                    
                    # Display settings
                    Write-Output "Detection Settings:"
                    $settings | Select-Object DisplayName, Value, Description | Format-Table -AutoSize
                    
                    # Export to file if specified
                    if (-not [string]::IsNullOrEmpty($OutputPath)) {
                        Export-ConfigurationReport -OutputPath $OutputPath
                    }
                }
                "Set" {
                    $result = Set-DetectionSetting -SettingName $SettingName -SettingValue $SettingValue
                    
                    if ($result) {
                        Write-Output "Detection setting $SettingName set to $SettingValue successfully"
                    }
                    else {
                        Write-Output "Failed to set detection setting $SettingName"
                        exit 1
                    }
                }
                default {
                    Write-Log "Action $Action not supported for $ConfigType" -Level Error
                    exit 1
                }
            }
        }
        "Exclusions" {
            switch ($Action) {
                "Get" {
                    $exclusions = Get-Exclusions -ExclusionType $ExclusionType -ExclusionScope $ExclusionScope
                    
                    if ($null -eq $exclusions) {
                        Write-Log "No exclusions found" -Level Warning
                        exit 0
                    }
                    
                    # Display exclusions
                    Write-Output "Exclusions:"
                    foreach ($exclusion in $exclusions) {
                        Write-Output "  $($exclusion.DisplayName):"
                        $values = $exclusion.Value -split ";"
                        foreach ($value in $values) {
                            if (-not [string]::IsNullOrEmpty($value)) {
                                Write-Output "    - $value"
                            }
                        }
                    }
                    
                    # Export to file if specified
                    if (-not [string]::IsNullOrEmpty($OutputPath)) {
                        Export-ConfigurationReport -OutputPath $OutputPath
                    }
                }
                "Add" {
                    $result = Add-Exclusion -ExclusionType $ExclusionType -ExclusionValue $ExclusionValue -ExclusionScope $ExclusionScope
                    
                    if ($result) {
                        Write-Output "Exclusion added successfully: Type=$ExclusionType, Value=$ExclusionValue, Scope=$ExclusionScope"
                    }
                    else {
                        Write-Output "Failed to add exclusion"
                        exit 1
                    }
                }
                "Remove" {
                    $result = Remove-Exclusion -ExclusionType $ExclusionType -ExclusionValue $ExclusionValue -ExclusionScope $ExclusionScope
                    
                    if ($result) {
                        Write-Output "Exclusion removed successfully: Type=$ExclusionType, Value=$ExclusionValue, Scope=$ExclusionScope"
                    }
                    else {
                        Write-Output "Failed to remove exclusion"
                        exit 1
                    }
                }
                default {
                    Write-Log "Action $Action not supported for $ConfigType" -Level Error
                    exit 1
                }
            }
        }
        "Integration" {
            switch ($Action) {
                "Get" {
                    $integrations = Get-IntegrationSettings -IntegrationType $IntegrationType
                    
                    if ($null -eq $integrations) {
                        Write-Log "No integration settings found" -Level Warning
                        exit 0
                    }
                    
                    # Display integrations
                    Write-Output "Integration Settings:"
                    $integrations | Select-Object DisplayName, Value, Description | Format-Table -AutoSize
                    
                    # Export to file if specified
                    if (-not [string]::IsNullOrEmpty($OutputPath)) {
                        Export-ConfigurationReport -OutputPath $OutputPath
                    }
                }
                "Set" {
                    $result = Set-IntegrationSetting -IntegrationType $IntegrationType -IntegrationValue $IntegrationValue
                    
                    if ($result) {
                        Write-Output "Integration setting $IntegrationType set to $IntegrationValue successfully"
                    }
                    else {
                        Write-Output "Failed to set integration setting $IntegrationType"
                        exit 1
                    }
                }
                default {
                    Write-Log "Action $Action not supported for $ConfigType" -Level Error
                    exit 1
                }
            }
        }
    }
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
