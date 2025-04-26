<#
.SYNOPSIS
    Manages Intune device operations.

.DESCRIPTION
    This script performs various device management operations in Microsoft Intune
    including retrieving device information, taking actions on devices, and managing device properties.
    It supports operations like wipe, reset, rename, and retrieving detailed device information.

.PARAMETER Action
    The action to perform on the device(s) (Get, Wipe, Reset, Rename, Retire, Delete, Sync).

.PARAMETER DeviceId
    The Intune device ID to perform the action on. Required for single device operations.

.PARAMETER DeviceName
    The device name to search for. Can be used instead of DeviceId for some operations.

.PARAMETER SerialNumber
    The device serial number to search for. Can be used instead of DeviceId for some operations.

.PARAMETER NewDeviceName
    The new name for the device when using the Rename action.

.PARAMETER ExportPath
    The path to export device information to when using the Get action with multiple devices.

.PARAMETER FilterByOS
    Filter devices by operating system (Windows, iOS, Android, macOS).

.PARAMETER FilterByOwnership
    Filter devices by ownership type (Corporate, Personal).

.PARAMETER FilterByComplianceStatus
    Filter devices by compliance status (Compliant, NonCompliant).

.PARAMETER FilterByEnrollmentStatus
    Filter devices by enrollment status (Enrolled, NotEnrolled).

.PARAMETER LogPath
    Path where logs will be stored. Defaults to Windows log directory.

.EXAMPLE
    .\Manage-IntuneDevice.ps1 -Action Get -DeviceId "12345678-1234-1234-1234-123456789012"
    Retrieves detailed information about the specified device.

.EXAMPLE
    .\Manage-IntuneDevice.ps1 -Action Wipe -DeviceName "DESKTOP-ABC123" -KeepEnrollmentData $true
    Wipes the specified device while keeping enrollment data.

.EXAMPLE
    .\Manage-IntuneDevice.ps1 -Action Get -FilterByOS "Windows" -FilterByComplianceStatus "NonCompliant" -ExportPath "C:\Reports\NonCompliantDevices.csv"
    Retrieves all non-compliant Windows devices and exports the information to a CSV file.

.NOTES
    Author: Michael Witzsche
    Date: April 26, 2025
    Version: 1.1
#>

#Requires -Modules Microsoft.Graph.Intune, Microsoft.Graph.DeviceManagement

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$LogPath = "$env:SystemRoot\Logs\Manage-IntuneDevice",
    
    [Parameter(Mandatory = $true)]
    [ValidateSet("Get", "Wipe", "Reset", "Rename", "Retire", "Delete", "Sync")]
    [string]$Action,
    
    [Parameter(Mandatory = $false)]
    [string]$DeviceId = "",
    
    [Parameter(Mandatory = $false)]
    [string]$DeviceName = "",
    
    [Parameter(Mandatory = $false)]
    [string]$SerialNumber = "",
    
    [Parameter(Mandatory = $false)]
    [string]$NewDeviceName = "",
    
    [Parameter(Mandatory = $false)]
    [string]$ExportPath = "",
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Windows", "iOS", "Android", "macOS", "")]
    [string]$FilterByOS = "",
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Corporate", "Personal", "")]
    [string]$FilterByOwnership = "",
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Compliant", "NonCompliant", "")]
    [string]$FilterByComplianceStatus = "",
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Enrolled", "NotEnrolled", "")]
    [string]$FilterByEnrollmentStatus = "",
    
    [Parameter(Mandatory = $false)]
    [bool]$KeepEnrollmentData = $false
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
            $graphDevice = Get-MgDeviceManagementManagedDevice -Top 1 -ErrorAction Stop
            Write-Log "Already connected to Microsoft Graph"
            return $true
        }
        catch {
            # Not connected, proceed with connection
        }
        
        # Connect to Microsoft Graph with required scopes
        Write-Log "Connecting to Microsoft Graph..."
        Connect-MgGraph -Scopes "DeviceManagementManagedDevices.ReadWrite.All", "Device.ReadWrite.All" -ErrorAction Stop
        
        # Verify connection
        try {
            $graphDevice = Get-MgDeviceManagementManagedDevice -Top 1 -ErrorAction Stop
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

function Get-IntuneDeviceByIdentifier {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$DeviceId = "",
        
        [Parameter(Mandatory = $false)]
        [string]$DeviceName = "",
        
        [Parameter(Mandatory = $false)]
        [string]$SerialNumber = ""
    )
    
    try {
        if (-not [string]::IsNullOrEmpty($DeviceId)) {
            # Get device by ID
            $device = Get-MgDeviceManagementManagedDevice -ManagedDeviceId $DeviceId -ErrorAction Stop
            return $device
        }
        elseif (-not [string]::IsNullOrEmpty($DeviceName)) {
            # Get device by name
            $devices = Get-MgDeviceManagementManagedDevice -All -ErrorAction Stop | Where-Object { $_.DeviceName -eq $DeviceName }
            
            if ($null -eq $devices -or $devices.Count -eq 0) {
                Write-Log "No devices found with name: $DeviceName" -Level Warning
                return $null
            }
            elseif ($devices.Count -gt 1) {
                Write-Log "Multiple devices found with name: $DeviceName. Using the first one." -Level Warning
                return $devices[0]
            }
            else {
                return $devices
            }
        }
        elseif (-not [string]::IsNullOrEmpty($SerialNumber)) {
            # Get device by serial number
            $devices = Get-MgDeviceManagementManagedDevice -All -ErrorAction Stop | Where-Object { $_.SerialNumber -eq $SerialNumber }
            
            if ($null -eq $devices -or $devices.Count -eq 0) {
                Write-Log "No devices found with serial number: $SerialNumber" -Level Warning
                return $null
            }
            elseif ($devices.Count -gt 1) {
                Write-Log "Multiple devices found with serial number: $SerialNumber. Using the first one." -Level Warning
                return $devices[0]
            }
            else {
                return $devices
            }
        }
        else {
            Write-Log "No device identifier provided" -Level Error
            return $null
        }
    }
    catch {
        Write-Log "Error getting device: $_" -Level Error
        return $null
    }
}

function Get-FilteredDevices {
    [CmdletBinding()]
    param()
    
    try {
        # Get all devices
        $devices = Get-MgDeviceManagementManagedDevice -All -ErrorAction Stop
        
        # Apply filters
        if (-not [string]::IsNullOrEmpty($FilterByOS)) {
            switch ($FilterByOS) {
                "Windows" { $devices = $devices | Where-Object { $_.OperatingSystem -eq "Windows" -or $_.OperatingSystem -eq "Windows 10" } }
                "iOS" { $devices = $devices | Where-Object { $_.OperatingSystem -eq "iOS" } }
                "Android" { $devices = $devices | Where-Object { $_.OperatingSystem -eq "Android" } }
                "macOS" { $devices = $devices | Where-Object { $_.OperatingSystem -eq "macOS" } }
            }
        }
        
        if (-not [string]::IsNullOrEmpty($FilterByOwnership)) {
            switch ($FilterByOwnership) {
                "Corporate" { $devices = $devices | Where-Object { $_.ManagedDeviceOwnerType -eq "Company" } }
                "Personal" { $devices = $devices | Where-Object { $_.ManagedDeviceOwnerType -eq "Personal" } }
            }
        }
        
        if (-not [string]::IsNullOrEmpty($FilterByComplianceStatus)) {
            switch ($FilterByComplianceStatus) {
                "Compliant" { $devices = $devices | Where-Object { $_.ComplianceState -eq "Compliant" } }
                "NonCompliant" { $devices = $devices | Where-Object { $_.ComplianceState -ne "Compliant" } }
            }
        }
        
        if (-not [string]::IsNullOrEmpty($FilterByEnrollmentStatus)) {
            switch ($FilterByEnrollmentStatus) {
                "Enrolled" { $devices = $devices | Where-Object { $_.EnrollmentState -eq "Enrolled" } }
                "NotEnrolled" { $devices = $devices | Where-Object { $_.EnrollmentState -ne "Enrolled" } }
            }
        }
        
        return $devices
    }
    catch {
        Write-Log "Error getting filtered devices: $_" -Level Error
        return $null
    }
}

function Format-DeviceDetails {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Device
    )
    
    # Create a custom object with the device details
    $deviceDetails = [PSCustomObject]@{
        DeviceId = $Device.Id
        DeviceName = $Device.DeviceName
        SerialNumber = $Device.SerialNumber
        IMEI = $Device.IMEI
        OperatingSystem = $Device.OperatingSystem
        OSVersion = $Device.OsVersion
        Model = $Device.Model
        Manufacturer = $Device.Manufacturer
        UserPrincipalName = $Device.UserPrincipalName
        LastSyncDateTime = $Device.LastSyncDateTime
        EnrollmentDate = $Device.EnrolledDateTime
        ComplianceState = $Device.ComplianceState
        JailBroken = $Device.JailBroken
        ManagementState = $Device.ManagementState
        OwnerType = $Device.ManagedDeviceOwnerType
        FreeStorageSpace = [math]::Round($Device.FreeStorageSpaceInBytes / 1GB, 2)
        TotalStorageSpace = [math]::Round($Device.TotalStorageSpaceInBytes / 1GB, 2)
        EncryptionState = $Device.EncryptionState
        AADRegistered = $Device.AadRegistered
        AutoPilotEnrolled = $Device.AutoPilotEnrolled
        DeviceCategory = $Device.DeviceCategory
        DeviceRegistrationState = $Device.DeviceRegistrationState
        EASActivated = $Device.EasActivated
        EASDeviceId = $Device.EasDeviceId
        IsSupervised = $Device.IsSupervised
        WiFiMACAddress = $Device.WiFiMacAddress
        EThernetMACAddress = $Device.EthernetMacAddress
    }
    
    return $deviceDetails
}

function Export-DeviceDetails {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object[]]$Devices,
        
        [Parameter(Mandatory = $true)]
        [string]$ExportPath
    )
    
    try {
        # Create an array to hold the formatted device details
        $deviceDetailsList = @()
        
        # Format each device
        foreach ($device in $Devices) {
            $deviceDetails = Format-DeviceDetails -Device $device
            $deviceDetailsList += $deviceDetails
        }
        
        # Export to CSV
        $deviceDetailsList | Export-Csv -Path $ExportPath -NoTypeInformation
        Write-Log "Exported device details to: $ExportPath"
        
        return $true
    }
    catch {
        Write-Log "Error exporting device details: $_" -Level Error
        return $false
    }
}
#endregion

#region Main Script
try {
    # Script start
    Write-Log "Script started with parameters: Action=$Action, DeviceId=$DeviceId, DeviceName=$DeviceName"
    
    # Connect to Microsoft Graph
    $connectedToGraph = Connect-ToMSGraph
    if (-not $connectedToGraph) {
        Write-Log "Cannot proceed without Microsoft Graph connection" -Level Error
        exit 1
    }
    
    # Validate parameters based on action
    switch ($Action) {
        "Get" {
            # No additional validation needed
        }
        "Rename" {
            if ([string]::IsNullOrEmpty($NewDeviceName)) {
                Write-Log "NewDeviceName is required for Rename action" -Level Error
                exit 1
            }
        }
        default {
            if ([string]::IsNullOrEmpty($DeviceId) -and [string]::IsNullOrEmpty($DeviceName) -and [string]::IsNullOrEmpty($SerialNumber)) {
                Write-Log "DeviceId, DeviceName, or SerialNumber is required for $Action action" -Level Error
                exit 1
            }
        }
    }
    
    # Perform the action
    switch ($Action) {
        "Get" {
            if (-not [string]::IsNullOrEmpty($DeviceId) -or -not [string]::IsNullOrEmpty($DeviceName) -or -not [string]::IsNullOrEmpty($SerialNumber)) {
                # Get a single device
                $device = Get-IntuneDeviceByIdentifier -DeviceId $DeviceId -DeviceName $DeviceName -SerialNumber $SerialNumber
                
                if ($null -eq $device) {
                    Write-Log "Device not found" -Level Error
                    exit 1
                }
                
                # Format and display device details
                $deviceDetails = Format-DeviceDetails -Device $device
                
                # Output device details
                Write-Output "Device Details:"
                $deviceDetails | Format-List
                
                # Export to file if specified
                if (-not [string]::IsNullOrEmpty($ExportPath)) {
                    Export-DeviceDetails -Devices @($device) -ExportPath $ExportPath
                }
            }
            else {
                # Get multiple devices based on filters
                $devices = Get-FilteredDevices
                
                if ($null -eq $devices -or $devices.Count -eq 0) {
                    Write-Log "No devices found matching the specified filters" -Level Warning
                    exit 0
                }
                
                Write-Log "Found $($devices.Count) devices matching the specified filters"
                
                # Export to file if specified
                if (-not [string]::IsNullOrEmpty($ExportPath)) {
                    Export-DeviceDetails -Devices $devices -ExportPath $ExportPath
                    Write-Output "Exported $($devices.Count) devices to $ExportPath"
                }
                else {
                    # Display summary of devices
                    Write-Output "Device Summary:"
                    $devices | Select-Object DeviceName, Id, OperatingSystem, OsVersion, UserPrincipalName, ComplianceState | Format-Table -AutoSize
                }
            }
        }
        "Wipe" {
            # Get the device
            $device = Get-IntuneDeviceByIdentifier -DeviceId $DeviceId -DeviceName $DeviceName -SerialNumber $SerialNumber
            
            if ($null -eq $device) {
                Write-Log "Device not found" -Level Error
                exit 1
            }
            
            # Confirm the action
            Write-Log "Wiping device: $($device.DeviceName) ($($device.Id))"
            
            # Perform the wipe
            Invoke-MgDeviceManagementManagedDeviceWipe -ManagedDeviceId $device.Id -KeepEnrollmentData:$KeepEnrollmentData
            
            Write-Log "Wipe command sent successfully"
            Write-Output "Wipe command sent successfully to device: $($device.DeviceName) ($($device.Id))"
        }
        "Reset" {
            # Get the device
            $device = Get-IntuneDeviceByIdentifier -DeviceId $DeviceId -DeviceName $DeviceName -SerialNumber $SerialNumber
            
            if ($null -eq $device) {
                Write-Log "Device not found" -Level Error
                exit 1
            }
            
            # Confirm the action
            Write-Log "Resetting device: $($device.DeviceName) ($($device.Id))"
            
            # Perform the reset
            Invoke-MgDeviceManagementManagedDeviceResetPasscode -ManagedDeviceId $device.Id
            
            Write-Log "Reset command sent successfully"
            Write-Output "Reset command sent successfully to device: $($device.DeviceName) ($($device.Id))"
        }
        "Rename" {
            # Get the device
            $device = Get-IntuneDeviceByIdentifier -DeviceId $DeviceId -DeviceName $DeviceName -SerialNumber $SerialNumber
            
            if ($null -eq $device) {
                Write-Log "Device not found" -Level Error
                exit 1
            }
            
            # Confirm the action
            Write-Log "Renaming device from $($device.DeviceName) to $NewDeviceName"
            
            # Perform the rename
            Update-MgDeviceManagementManagedDevice -ManagedDeviceId $device.Id -DeviceName $NewDeviceName
            
            Write-Log "Rename command sent successfully"
            Write-Output "Device renamed successfully from $($device.DeviceName) to $NewDeviceName"
        }
        "Retire" {
            # Get the device
            $device = Get-IntuneDeviceByIdentifier -DeviceId $DeviceId -DeviceName $DeviceName -SerialNumber $SerialNumber
            
            if ($null -eq $device) {
                Write-Log "Device not found" -Level Error
                exit 1
            }
            
            # Confirm the action
            Write-Log "Retiring device: $($device.DeviceName) ($($device.Id))"
            
            # Perform the retire
            Invoke-MgDeviceManagementManagedDeviceRetire -ManagedDeviceId $device.Id
            
            Write-Log "Retire command sent successfully"
            Write-Output "Retire command sent successfully to device: $($device.DeviceName) ($($device.Id))"
        }
        "Delete" {
            # Get the device
            $device = Get-IntuneDeviceByIdentifier -DeviceId $DeviceId -DeviceName $DeviceName -SerialNumber $SerialNumber
            
            if ($null -eq $device) {
                Write-Log "Device not found" -Level Error
                exit 1
            }
            
            # Confirm the action
            Write-Log "Deleting device: $($device.DeviceName) ($($device.Id))"
            
            # Perform the delete
            Remove-MgDeviceManagementManagedDevice -ManagedDeviceId $device.Id
            
            Write-Log "Delete command sent successfully"
            Write-Output "Device deleted successfully: $($device.DeviceName) ($($device.Id))"
        }
        "Sync" {
            # Get the device
            $device = Get-IntuneDeviceByIdentifier -DeviceId $DeviceId -DeviceName $DeviceName -SerialNumber $SerialNumber
            
            if ($null -eq $device) {
                Write-Log "Device not found" -Level Error
                exit 1
            }
            
            # Confirm the action
            Write-Log "Syncing device: $($device.DeviceName) ($($device.Id))"
            
            # Perform the sync
            Invoke-MgDeviceManagementManagedDeviceSyncDevice -ManagedDeviceId $device.Id
            
            Write-Log "Sync command sent successfully"
            Write-Output "Sync command sent successfully to device: $($device.DeviceName) ($($device.Id))"
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
