<#
.SYNOPSIS
    Creates a new Intune compliance policy.

.DESCRIPTION
    This script creates a new Microsoft Intune compliance policy with specified parameters
    including policy name, description, platform, and compliance settings.
    It supports various platforms and provides options for assignment to users and devices.

.PARAMETER PolicyName
    The name for the new compliance policy.

.PARAMETER Description
    The description for the new compliance policy.

.PARAMETER Platform
    The platform for the compliance policy (Windows10, iOS, Android, macOS).

.PARAMETER AssignToAllUsers
    Whether to assign the policy to all users.

.PARAMETER AssignToAllDevices
    Whether to assign the policy to all devices.

.PARAMETER AssignToGroups
    An array of Azure AD group IDs to assign the policy to.

.PARAMETER SettingsJSON
    A JSON string containing the settings for the compliance policy.

.PARAMETER SettingsFile
    Path to a JSON file containing the settings for the compliance policy.

.PARAMETER ActionForNoncompliance
    The action to take when a device is noncompliant (None, Notify, Block).

.PARAMETER GracePeriodInDays
    The number of days before taking action for noncompliance.

.PARAMETER LogPath
    Path where logs will be stored. Defaults to Windows log directory.

.EXAMPLE
    .\New-IntuneCompliancePolicy.ps1 -PolicyName "Windows 10 Compliance" -Description "Basic compliance policy for Windows 10 devices" -Platform "Windows10" -AssignToAllUsers $true -SettingsFile "C:\Configs\Win10ComplianceSettings.json" -ActionForNoncompliance "Block" -GracePeriodInDays 5
    Creates a new Windows 10 compliance policy with settings from the specified file, assigns it to all users, and blocks noncompliant devices after 5 days.

.NOTES
    Author: Michael Witzsche
    Date: April 26, 2025
    Version: 1.1
#>

#Requires -Modules Microsoft.Graph.Intune, Microsoft.Graph.DeviceManagement

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$LogPath = "$env:SystemRoot\Logs\New-IntuneCompliancePolicy",
    
    [Parameter(Mandatory = $true)]
    [string]$PolicyName,
    
    [Parameter(Mandatory = $false)]
    [string]$Description = "",
    
    [Parameter(Mandatory = $true)]
    [ValidateSet("Windows10", "iOS", "Android", "macOS")]
    [string]$Platform,
    
    [Parameter(Mandatory = $false)]
    [bool]$AssignToAllUsers = $false,
    
    [Parameter(Mandatory = $false)]
    [bool]$AssignToAllDevices = $false,
    
    [Parameter(Mandatory = $false)]
    [string[]]$AssignToGroups = @(),
    
    [Parameter(Mandatory = $false)]
    [string]$SettingsJSON = "",
    
    [Parameter(Mandatory = $false)]
    [string]$SettingsFile = "",
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("None", "Notify", "Block")]
    [string]$ActionForNoncompliance = "None",
    
    [Parameter(Mandatory = $false)]
    [int]$GracePeriodInDays = 0
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
            $graphPolicy = Get-MgDeviceManagementDeviceCompliancePolicy -Top 1 -ErrorAction Stop
            Write-Log "Already connected to Microsoft Graph"
            return $true
        }
        catch {
            # Not connected, proceed with connection
        }
        
        # Connect to Microsoft Graph with required scopes
        Write-Log "Connecting to Microsoft Graph..."
        Connect-MgGraph -Scopes "DeviceManagementConfiguration.ReadWrite.All", "Group.Read.All" -ErrorAction Stop
        
        # Verify connection
        try {
            $graphPolicy = Get-MgDeviceManagementDeviceCompliancePolicy -Top 1 -ErrorAction Stop
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

function Get-PlatformTypeMapping {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Platform
    )
    
    # Define mappings for different platforms
    $mappings = @{
        "Windows10" = "#microsoft.graph.windows10CompliancePolicy"
        "iOS" = "#microsoft.graph.iosCompliancePolicy"
        "Android" = "#microsoft.graph.androidCompliancePolicy"
        "macOS" = "#microsoft.graph.macOSCompliancePolicy"
    }
    
    # Return the appropriate mapping
    if ($mappings.ContainsKey($Platform)) {
        return $mappings[$Platform]
    }
    else {
        throw "No mapping found for platform '$Platform'"
    }
}

function Get-DefaultPolicySettings {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Platform
    )
    
    # Define default settings for different platforms
    switch ($Platform) {
        "Windows10" {
            return @{
                PasswordRequired = $true
                PasswordMinimumLength = 8
                PasswordRequiredType = "alphanumeric"
                RequireHealthyDeviceReport = $true
                OsMinimumVersion = "10.0.18363"
                OsMaximumVersion = ""
                MobileOsMinimumVersion = ""
                MobileOsMaximumVersion = ""
                EarlyLaunchAntiMalwareDriverEnabled = $true
                BitLockerEnabled = $true
                SecureBootEnabled = $true
                CodeIntegrityEnabled = $true
                StorageRequireEncryption = $true
                ActiveFirewallRequired = $true
                DefenderEnabled = $true
                DefenderVersion = ""
                SignedAndReputableFileOriginRequired = $true
                DeviceThreatProtectionEnabled = $false
                DeviceThreatProtectionRequiredSecurityLevel = "medium"
                ConfigurationManagerComplianceRequired = $false
                TPMRequired = $true
                DeviceCompliancePolicyScript = $null
                ValidOperatingSystemBuildRanges = @()
            }
        }
        "iOS" {
            return @{
                PasscodeBlockSimple = $true
                PasscodeRequired = $true
                PasscodeMinimumLength = 6
                PasscodeRequiredType = "alphanumeric"
                PasscodeMinutesOfInactivityBeforeLock = 15
                PasscodePreviousPasscodeBlockCount = 5
                PasscodeMinutesOfInactivityBeforeScreenTimeout = 15
                OsMinimumVersion = "13.0"
                OsMaximumVersion = ""
                SecurityBlockJailbrokenDevices = $true
                DeviceThreatProtectionEnabled = $false
                DeviceThreatProtectionRequiredSecurityLevel = "medium"
                ManagedEmailProfileRequired = $false
            }
        }
        "Android" {
            return @{
                passwordRequired = $true
                passwordMinimumLength = 6
                passwordRequiredType = "alphanumeric"
                securityBlockJailbrokenDevices = $true
                securityDisableUsbDebugging = $true
                securityRequireVerifyApps = $true
                deviceThreatProtectionEnabled = $false
                deviceThreatProtectionRequiredSecurityLevel = "medium"
                securityBlockDeviceAdministratorManagedDevices = $false
                osMinimumVersion = "10.0"
                osMaximumVersion = ""
                minAndroidSecurityPatchLevel = ""
                storageRequireEncryption = $true
                securityRequireSafetyNetAttestationBasicIntegrity = $false
                securityRequireSafetyNetAttestationCertifiedDevice = $false
                securityRequireGooglePlayServices = $true
                securityRequireUpToDateSecurityProviders = $true
                securityRequireCompanyPortalAppIntegrity = $true
            }
        }
        "macOS" {
            return @{
                passwordRequired = $true
                passwordBlockSimple = $true
                passwordMinimumLength = 8
                passwordRequiredType = "alphanumeric"
                passwordMinutesOfInactivityBeforeLock = 15
                passwordPreviousPasswordBlockCount = 5
                passwordMinutesOfInactivityBeforeScreenTimeout = 15
                osMinimumVersion = "10.15"
                osMaximumVersion = ""
                systemIntegrityProtectionEnabled = $true
                deviceThreatProtectionEnabled = $false
                deviceThreatProtectionRequiredSecurityLevel = "medium"
                storageRequireEncryption = $true
                gatekeeperAllowedAppSource = "macAppStoreAndIdentifiedDevelopers"
                firewallEnabled = $true
                firewallBlockAllIncoming = $false
                firewallEnableStealthMode = $true
            }
        }
        default {
            throw "No default settings found for platform '$Platform'"
        }
    }
}
#endregion

#region Main Script
try {
    # Script start
    Write-Log "Script started with parameters: PolicyName=$PolicyName, Platform=$Platform"
    
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
    
    # Get platform type mapping
    try {
        $odataType = Get-PlatformTypeMapping -Platform $Platform
        Write-Log "Using platform type mapping: $odataType"
    }
    catch {
        Write-Log "Failed to get platform type mapping: $_" -Level Error
        exit 1
    }
    
    # Prepare policy settings
    $policySettings = $null
    
    if (-not [string]::IsNullOrEmpty($SettingsJSON)) {
        # Use provided settings
        try {
            $policySettings = ConvertFrom-Json -InputObject $SettingsJSON -ErrorAction Stop
            Write-Log "Using provided settings from JSON"
        }
        catch {
            Write-Log "Invalid settings JSON: $_" -Level Error
            exit 1
        }
    }
    else {
        # Use default settings
        try {
            $policySettings = Get-DefaultPolicySettings -Platform $Platform
            Write-Log "Using default settings for platform: $Platform"
        }
        catch {
            Write-Log "Failed to get default settings: $_" -Level Error
            exit 1
        }
    }
    
    # Check if policy already exists
    Write-Log "Checking if policy $PolicyName already exists..."
    $existingPolicies = Get-MgDeviceManagementDeviceCompliancePolicy -All | Where-Object { $_.DisplayName -eq $PolicyName }
    
    if ($null -ne $existingPolicies -and $existingPolicies.Count -gt 0) {
        Write-Log "Policy $PolicyName already exists. Cannot create duplicate policy." -Level Error
        exit 1
    }
    
    # Create the compliance policy
    try {
        Write-Log "Creating new compliance policy $PolicyName..."
        
        # Prepare policy parameters
        $policyParams = @{
            "@odata.type" = $odataType
            DisplayName = $PolicyName
            Description = $Description
        }
        
        # Add settings from JSON or default settings
        $settingsProperties = $policySettings | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name
        foreach ($property in $settingsProperties) {
            $policyParams[$property] = $policySettings.$property
        }
        
        # Create the policy
        $newPolicy = New-MgDeviceManagementDeviceCompliancePolicy -BodyParameter $policyParams
        Write-Log "Compliance policy created successfully with ID: $($newPolicy.Id)"
        
        # Configure noncompliance actions if specified
        if ($ActionForNoncompliance -ne "None") {
            Write-Log "Configuring noncompliance actions..."
            
            $actionType = switch ($ActionForNoncompliance) {
                "Notify" { "emailNotification" }
                "Block" { "block" }
                default { "none" }
            }
            
            $scheduleParams = @{
                DeviceCompliancePolicyId = $newPolicy.Id
                BodyParameter = @{
                    GracePeriodHours = $GracePeriodInDays * 24
                    ScheduledActionConfigurations = @(
                        @{
                            ActionType = $actionType
                            GracePeriodHours = 0
                            NotificationTemplateId = ""
                            NotificationMessageCCList = @()
                        }
                    )
                }
            }
            
            New-MgDeviceManagementDeviceCompliancePolicyScheduledActionForRule @scheduleParams
            Write-Log "Noncompliance actions configured successfully"
        }
        
        # Assign the policy if specified
        if ($AssignToAllUsers -or $AssignToAllDevices -or $AssignToGroups.Count -gt 0) {
            Write-Log "Creating policy assignments..."
            
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
                foreach ($assignment in $assignments) {
                    New-MgDeviceManagementDeviceCompliancePolicyAssignment -DeviceCompliancePolicyId $newPolicy.Id -BodyParameter $assignment
                }
                Write-Log "Policy assignments created successfully"
            }
        }
        
        # Output policy details
        Write-Output "Compliance policy created successfully:"
        Write-Output "  Name: $PolicyName"
        Write-Output "  Description: $Description"
        Write-Output "  Platform: $Platform"
        Write-Output "  Policy ID: $($newPolicy.Id)"
        
        if ($ActionForNoncompliance -ne "None") {
            Write-Output "  Noncompliance Action: $ActionForNoncompliance"
            Write-Output "  Grace Period: $GracePeriodInDays days"
        }
        
        if ($AssignToAllUsers) {
            Write-Output "  Assigned to: All Users"
        }
        
        if ($AssignToAllDevices) {
            Write-Output "  Assigned to: All Devices"
        }
        
        if ($AssignToGroups.Count -gt 0) {
            Write-Output "  Assigned to Groups: $($AssignToGroups -join ', ')"
        }
        
        return $newPolicy
    }
    catch {
        Write-Log "Failed to create compliance policy: $_" -Level Error
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
