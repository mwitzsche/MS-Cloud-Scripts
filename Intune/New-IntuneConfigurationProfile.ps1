<#
.SYNOPSIS
    Creates a new Intune device configuration profile.

.DESCRIPTION
    This script creates a new Microsoft Intune device configuration profile with specified parameters
    including profile name, description, platform, and settings.
    It supports various platforms and profile types.

.PARAMETER ProfileName
    The name for the new configuration profile.

.PARAMETER Description
    The description for the new configuration profile.

.PARAMETER Platform
    The platform for the configuration profile (Windows10, iOS, Android, macOS).

.PARAMETER ProfileType
    The type of configuration profile to create (DeviceRestrictions, EndpointProtection, WiFi, VPN, Email).

.PARAMETER AssignToAllUsers
    Whether to assign the profile to all users.

.PARAMETER AssignToAllDevices
    Whether to assign the profile to all devices.

.PARAMETER AssignToGroups
    An array of Azure AD group IDs to assign the profile to.

.PARAMETER SettingsJSON
    A JSON string containing the settings for the configuration profile.

.PARAMETER SettingsFile
    Path to a JSON file containing the settings for the configuration profile.

.PARAMETER LogPath
    Path where logs will be stored. Defaults to Windows log directory.

.EXAMPLE
    .\New-IntuneConfigurationProfile.ps1 -ProfileName "Windows 10 Security Baseline" -Description "Security baseline for Windows 10 devices" -Platform "Windows10" -ProfileType "EndpointProtection" -AssignToAllDevices $true -SettingsFile "C:\Configs\Win10SecuritySettings.json"
    Creates a new Windows 10 endpoint protection configuration profile with settings from the specified file and assigns it to all devices.

.NOTES
    Author: Michael Witzsche
    Date: April 26, 2025
    Version: 1.1
#>

#Requires -Modules Microsoft.Graph.Intune, Microsoft.Graph.DeviceManagement

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$LogPath = "$env:SystemRoot\Logs\New-IntuneConfigurationProfile",
    
    [Parameter(Mandatory = $true)]
    [string]$ProfileName,
    
    [Parameter(Mandatory = $false)]
    [string]$Description = "",
    
    [Parameter(Mandatory = $true)]
    [ValidateSet("Windows10", "iOS", "Android", "macOS")]
    [string]$Platform,
    
    [Parameter(Mandatory = $true)]
    [ValidateSet("DeviceRestrictions", "EndpointProtection", "WiFi", "VPN", "Email")]
    [string]$ProfileType,
    
    [Parameter(Mandatory = $false)]
    [bool]$AssignToAllUsers = $false,
    
    [Parameter(Mandatory = $false)]
    [bool]$AssignToAllDevices = $false,
    
    [Parameter(Mandatory = $false)]
    [string[]]$AssignToGroups = @(),
    
    [Parameter(Mandatory = $false)]
    [string]$SettingsJSON = "",
    
    [Parameter(Mandatory = $false)]
    [string]$SettingsFile = ""
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
            $graphDevice = Get-MgDeviceManagementDeviceConfiguration -Top 1 -ErrorAction Stop
            Write-Log "Already connected to Microsoft Graph"
            return $true
        }
        catch {
            # Not connected, proceed with connection
        }
        
        # Connect to Microsoft Graph with required scopes
        Write-Log "Connecting to Microsoft Graph..."
        Connect-MgGraph -Scopes "DeviceManagementConfiguration.ReadWrite.All", "DeviceManagementApps.ReadWrite.All", "Group.Read.All" -ErrorAction Stop
        
        # Verify connection
        try {
            $graphDevice = Get-MgDeviceManagementDeviceConfiguration -Top 1 -ErrorAction Stop
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

function Get-ProfileTypeMapping {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Platform,
        
        [Parameter(Mandatory = $true)]
        [string]$ProfileType
    )
    
    # Define mappings for different platforms and profile types
    $mappings = @{
        "Windows10" = @{
            "DeviceRestrictions" = "windows10GeneralConfiguration"
            "EndpointProtection" = "windows10EndpointProtectionConfiguration"
            "WiFi" = "windows10WiFiConfiguration"
            "VPN" = "windows10VpnConfiguration"
            "Email" = "windows10EmailProfileConfiguration"
        }
        "iOS" = @{
            "DeviceRestrictions" = "iosGeneralDeviceConfiguration"
            "EndpointProtection" = "iosEndpointProtectionConfiguration"
            "WiFi" = "iosWiFiConfiguration"
            "VPN" = "iosVpnConfiguration"
            "Email" = "iosEmailProfileConfiguration"
        }
        "Android" = @{
            "DeviceRestrictions" = "androidDeviceOwnerGeneralDeviceConfiguration"
            "EndpointProtection" = "androidDeviceOwnerEndpointProtectionConfiguration"
            "WiFi" = "androidDeviceOwnerWiFiConfiguration"
            "VPN" = "androidDeviceOwnerVpnConfiguration"
            "Email" = "androidDeviceOwnerEmailProfileConfiguration"
        }
        "macOS" = @{
            "DeviceRestrictions" = "macOSGeneralDeviceConfiguration"
            "EndpointProtection" = "macOSEndpointProtectionConfiguration"
            "WiFi" = "macOSWiFiConfiguration"
            "VPN" = "macOSVpnConfiguration"
            "Email" = "macOSEmailProfileConfiguration"
        }
    }
    
    # Return the appropriate mapping
    if ($mappings.ContainsKey($Platform) -and $mappings[$Platform].ContainsKey($ProfileType)) {
        return $mappings[$Platform][$ProfileType]
    }
    else {
        throw "No mapping found for platform '$Platform' and profile type '$ProfileType'"
    }
}
#endregion

#region Main Script
try {
    # Script start
    Write-Log "Script started with parameters: ProfileName=$ProfileName, Platform=$Platform, ProfileType=$ProfileType"
    
    # Connect to Microsoft Graph
    $connectedToGraph = Connect-ToMSGraph
    if (-not $connectedToGraph) {
        Write-Log "Cannot proceed without Microsoft Graph connection" -Level Error
        exit 1
    }
    
    # Get settings from file if specified
    if (-not [string]::IsNullOrEmpty($SettingsFile)) {
        if (-not (Test-Path -Path $SettingsFile)) {
            Write-Log "Settings file not found: $SettingsFile" -Level Error
            exit 1
        }
        
        try {
            $SettingsJSON = Get-Content -Path $SettingsFile -Raw
            Write-Log "Loaded settings from file: $SettingsFile"
        }
        catch {
            Write-Log "Failed to load settings from file: $_" -Level Error
            exit 1
        }
    }
    
    # Validate settings
    if ([string]::IsNullOrEmpty($SettingsJSON)) {
        Write-Log "No settings provided. Either SettingsJSON or SettingsFile must be specified." -Level Error
        exit 1
    }
    
    try {
        $settings = ConvertFrom-Json -InputObject $SettingsJSON -ErrorAction Stop
        Write-Log "Settings JSON validated successfully"
    }
    catch {
        Write-Log "Invalid settings JSON: $_" -Level Error
        exit 1
    }
    
    # Check if profile already exists
    Write-Log "Checking if profile $ProfileName already exists..."
    $existingProfiles = Get-MgDeviceManagementDeviceConfiguration -All | Where-Object { $_.DisplayName -eq $ProfileName }
    
    if ($null -ne $existingProfiles -and $existingProfiles.Count -gt 0) {
        Write-Log "Profile $ProfileName already exists. Cannot create duplicate profile." -Level Error
        exit 1
    }
    
    # Get profile type mapping
    try {
        $odataType = Get-ProfileTypeMapping -Platform $Platform -ProfileType $ProfileType
        Write-Log "Using profile type mapping: $odataType"
    }
    catch {
        Write-Log "Failed to get profile type mapping: $_" -Level Error
        exit 1
    }
    
    # Create the configuration profile
    try {
        Write-Log "Creating new configuration profile $ProfileName..."
        
        # Prepare profile parameters
        $profileParams = @{
            "@odata.type" = "#microsoft.graph.${odataType}"
            DisplayName = $ProfileName
            Description = $Description
        }
        
        # Add settings from JSON
        $settingsProperties = $settings | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name
        foreach ($property in $settingsProperties) {
            $profileParams[$property] = $settings.$property
        }
        
        # Create the profile
        $newProfile = New-MgDeviceManagementDeviceConfiguration -BodyParameter $profileParams
        Write-Log "Configuration profile created successfully with ID: $($newProfile.Id)"
        
        # Assign the profile if specified
        if ($AssignToAllUsers -or $AssignToAllDevices -or $AssignToGroups.Count -gt 0) {
            Write-Log "Creating profile assignments..."
            
            $assignments = @()
            
            if ($AssignToAllUsers) {
                $assignments += @{
                    Target = @{
                        "@odata.type" = "#microsoft.graph.allLicensedUsersAssignmentTarget"
                    }
                }
                Write-Log "Added assignment to all users"
            }
            
            if ($AssignToAllDevices) {
                $assignments += @{
                    Target = @{
                        "@odata.type" = "#microsoft.graph.allDevicesAssignmentTarget"
                    }
                }
                Write-Log "Added assignment to all devices"
            }
            
            foreach ($groupId in $AssignToGroups) {
                $assignments += @{
                    Target = @{
                        "@odata.type" = "#microsoft.graph.groupAssignmentTarget"
                        GroupId = $groupId
                    }
                }
                Write-Log "Added assignment to group: $groupId"
            }
            
            if ($assignments.Count -gt 0) {
                $assignmentParams = @{
                    Assignments = $assignments
                }
                
                Update-MgDeviceManagementDeviceConfiguration -DeviceConfigurationId $newProfile.Id -BodyParameter $assignmentParams
                Write-Log "Profile assignments created successfully"
            }
        }
        
        # Output profile details
        Write-Output "Configuration profile created successfully:"
        Write-Output "  Name: $ProfileName"
        Write-Output "  Description: $Description"
        Write-Output "  Platform: $Platform"
        Write-Output "  Profile Type: $ProfileType"
        Write-Output "  Profile ID: $($newProfile.Id)"
        
        if ($AssignToAllUsers) {
            Write-Output "  Assigned to: All Users"
        }
        
        if ($AssignToAllDevices) {
            Write-Output "  Assigned to: All Devices"
        }
        
        if ($AssignToGroups.Count -gt 0) {
            Write-Output "  Assigned to Groups: $($AssignToGroups -join ', ')"
        }
        
        return $newProfile
    }
    catch {
        Write-Log "Failed to create configuration profile: $_" -Level Error
        throw $_
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
