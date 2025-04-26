<#
.SYNOPSIS
    Generates comprehensive device reports from Microsoft Intune and Azure AD.

.DESCRIPTION
    This script generates detailed reports about devices in Microsoft Intune and Azure AD,
    including device information, compliance status, configuration profiles, installed applications,
    and security status. Reports can be filtered by various criteria and exported in multiple formats.

.PARAMETER ReportType
    The type of device report to generate (Basic, Detailed, Compliance, Profiles, Apps, Security, All).

.PARAMETER Filter
    Hashtable of filters to apply to the report (e.g. @{OS="Windows"; Model="Surface"}).

.PARAMETER TimeFrame
    The time frame for activity data (Last7Days, Last30Days, Last90Days, LastYear).

.PARAMETER IncludePersonal
    Whether to include personal devices in the report.

.PARAMETER IncludeRetired
    Whether to include retired devices in the report.

.PARAMETER ExportPath
    The path where the report will be saved.

.PARAMETER ExportFormat
    The format of the export file (CSV, JSON, Excel, HTML).

.PARAMETER LogPath
    Path where logs will be stored. Defaults to Windows log directory.

.EXAMPLE
    .\Get-DeviceReport.ps1 -ReportType Basic -ExportPath "C:\Reports\DeviceBasicReport.csv" -ExportFormat CSV
    Generates a basic device report and exports it to CSV format.

.EXAMPLE
    .\Get-DeviceReport.ps1 -ReportType Compliance -Filter @{OS="Windows"} -ExportPath "C:\Reports\WindowsCompliance.xlsx" -ExportFormat Excel
    Generates a compliance report for Windows devices and exports it to Excel format.

.NOTES
    Author: Michael Witzsche
    Date: April 26, 2025
    Version: 1.0.0
    
    History:
    1.0.0 - Initial release
#>

#Requires -Modules Microsoft.Graph.DeviceManagement, Microsoft.Graph.DeviceManagement.Administration, Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.Authentication, ImportExcel

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$LogPath = "$env:SystemRoot\Logs\Get-DeviceReport",
    
    [Parameter(Mandatory = $true)]
    [ValidateSet("Basic", "Detailed", "Compliance", "Profiles", "Apps", "Security", "All")]
    [string]$ReportType,
    
    [Parameter(Mandatory = $false)]
    [hashtable]$Filter = @{},
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Last7Days", "Last30Days", "Last90Days", "LastYear")]
    [string]$TimeFrame = "Last30Days",
    
    [Parameter(Mandatory = $false)]
    [bool]$IncludePersonal = $false,
    
    [Parameter(Mandatory = $false)]
    [bool]$IncludeRetired = $false,
    
    [Parameter(Mandatory = $true)]
    [string]$ExportPath,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("CSV", "JSON", "Excel", "HTML")]
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
            "DeviceManagementManagedDevices.Read.All",
            "DeviceManagementConfiguration.Read.All",
            "DeviceManagementApps.Read.All",
            "Directory.Read.All",
            "AuditLog.Read.All"
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

function Get-FilteredDevices {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [hashtable]$Filter = @{},
        
        [Parameter(Mandatory = $false)]
        [bool]$IncludePersonal = $false,
        
        [Parameter(Mandatory = $false)]
        [bool]$IncludeRetired = $false
    )
    
    try {
        Write-Log "Retrieving devices with applied filters..."
        
        # Build filter string
        $filterStrings = @()
        
        # Add ownership filter
        if (-not $IncludePersonal) {
            $filterStrings += "managedDeviceOwnerType eq 'company'"
        }
        
        # Add retired filter
        if (-not $IncludeRetired) {
            $filterStrings += "not (managementState eq 'retired')"
        }
        
        # Add custom filters
        foreach ($key in $Filter.Keys) {
            $value = $Filter[$key]
            
            # Handle different property types
            switch ($key) {
                "OS" { $filterStrings += "contains(operatingSystem, '$value')" }
                "OSVersion" { $filterStrings += "contains(osVersion, '$value')" }
                "Model" { $filterStrings += "contains(model, '$value')" }
                "Manufacturer" { $filterStrings += "contains(manufacturer, '$value')" }
                "ComplianceState" { $filterStrings += "complianceState eq '$value'" }
                "DeviceName" { $filterStrings += "contains(deviceName, '$value')" }
                "SerialNumber" { $filterStrings += "contains(serialNumber, '$value')" }
                "UserPrincipalName" { $filterStrings += "contains(userPrincipalName, '$value')" }
                "UserDisplayName" { $filterStrings += "contains(userDisplayName, '$value')" }
                default { $filterStrings += "contains($key, '$value')" }
            }
        }
        
        # Combine filter strings
        $filterString = $filterStrings -join " and "
        
        # Get devices with filter
        if ([string]::IsNullOrEmpty($filterString)) {
            $devices = Get-MgDeviceManagementManagedDevice -All
        }
        else {
            $devices = Get-MgDeviceManagementManagedDevice -Filter $filterString -All
        }
        
        if ($null -eq $devices -or $devices.Count -eq 0) {
            Write-Log "No devices found with the specified filters" -Level Warning
            return $null
        }
        
        Write-Log "Retrieved $($devices.Count) devices"
        return $devices
    }
    catch {
        Write-Log "Error retrieving devices: $_" -Level Error
        return $null
    }
}

function Get-BasicDeviceReport {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object[]]$Devices
    )
    
    try {
        Write-Log "Generating basic device report..."
        
        $report = @()
        
        foreach ($device in $Devices) {
            $report += [PSCustomObject]@{
                DeviceName = $device.DeviceName
                SerialNumber = $device.SerialNumber
                IMEI = $device.IMEI
                OperatingSystem = $device.OperatingSystem
                OSVersion = $device.OsVersion
                Model = $device.Model
                Manufacturer = $device.Manufacturer
                UserDisplayName = $device.UserDisplayName
                UserPrincipalName = $device.UserPrincipalName
                EnrollmentDate = $device.EnrolledDateTime
                LastSyncDateTime = $device.LastSyncDateTime
                ComplianceState = $device.ComplianceState
                ManagementState = $device.ManagementState
                OwnerType = $device.ManagedDeviceOwnerType
                JoinType = $device.JoinType
            }
        }
        
        Write-Log "Generated basic device report with $($report.Count) entries"
        return $report
    }
    catch {
        Write-Log "Error generating basic device report: $_" -Level Error
        return $null
    }
}

function Get-DetailedDeviceReport {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object[]]$Devices
    )
    
    try {
        Write-Log "Generating detailed device report..."
        
        $report = @()
        
        foreach ($device in $Devices) {
            # Get additional device details
            $deviceDetails = Get-MgDeviceManagementManagedDevice -ManagedDeviceId $device.Id -Expand physicalMemoryInBytes,totalStorageSpaceInBytes,freeStorageSpaceInBytes
            
            $report += [PSCustomObject]@{
                DeviceName = $device.DeviceName
                SerialNumber = $device.SerialNumber
                IMEI = $device.IMEI
                OperatingSystem = $device.OperatingSystem
                OSVersion = $device.OsVersion
                Model = $device.Model
                Manufacturer = $device.Manufacturer
                UserDisplayName = $device.UserDisplayName
                UserPrincipalName = $device.UserPrincipalName
                EnrollmentDate = $device.EnrolledDateTime
                LastSyncDateTime = $device.LastSyncDateTime
                ComplianceState = $device.ComplianceState
                ManagementState = $device.ManagementState
                OwnerType = $device.ManagedDeviceOwnerType
                JoinType = $device.JoinType
                WiFiMACAddress = $device.WiFiMacAddress
                EthernetMACAddress = $device.EthernetMacAddress
                DeviceCategory = $device.DeviceCategory
                DeviceRegistrationState = $device.DeviceRegistrationState
                SubscriberCarrier = $device.SubscriberCarrier
                CellularTechnology = $device.CellularTechnology
                PhoneNumber = $device.PhoneNumber
                SupervisedStatus = $device.IsSupervised
                EncryptionStatus = $device.EncryptionState
                ActivationLockBypassCode = $device.ActivationLockBypassCode
                EmailAddress = $device.EmailAddress
                AzureADRegistered = $device.AzureADRegistered
                AzureADDeviceId = $device.AzureADDeviceId
                DeviceEnrollmentType = $device.DeviceEnrollmentType
                PhysicalMemoryInBytes = $deviceDetails.PhysicalMemoryInBytes
                TotalStorageSpaceInBytes = $deviceDetails.TotalStorageSpaceInBytes
                FreeStorageSpaceInBytes = $deviceDetails.FreeStorageSpaceInBytes
                PhysicalMemoryInGB = [math]::Round($deviceDetails.PhysicalMemoryInBytes / 1GB, 2)
                TotalStorageSpaceInGB = [math]::Round($deviceDetails.TotalStorageSpaceInBytes / 1GB, 2)
                FreeStorageSpaceInGB = [math]::Round($deviceDetails.FreeStorageSpaceInBytes / 1GB, 2)
                FreeStoragePercentage = if ($deviceDetails.TotalStorageSpaceInBytes -gt 0) { [math]::Round(($deviceDetails.FreeStorageSpaceInBytes / $deviceDetails.TotalStorageSpaceInBytes) * 100, 2) } else { 0 }
            }
        }
        
        Write-Log "Generated detailed device report with $($report.Count) entries"
        return $report
    }
    catch {
        Write-Log "Error generating detailed device report: $_" -Level Error
        return $null
    }
}

function Get-DeviceComplianceReport {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object[]]$Devices
    )
    
    try {
        Write-Log "Generating device compliance report..."
        
        $report = @()
        
        foreach ($device in $Devices) {
            # Get device compliance policy status
            $compliancePolicyStatuses = Get-MgDeviceManagementManagedDeviceCompliancePolicyState -ManagedDeviceId $device.Id
            
            if ($null -eq $compliancePolicyStatuses -or $compliancePolicyStatuses.Count -eq 0) {
                # Device has no compliance policies
                $report += [PSCustomObject]@{
                    DeviceName = $device.DeviceName
                    SerialNumber = $device.SerialNumber
                    OperatingSystem = $device.OperatingSystem
                    OSVersion = $device.OsVersion
                    UserDisplayName = $device.UserDisplayName
                    UserPrincipalName = $device.UserPrincipalName
                    OverallComplianceState = $device.ComplianceState
                    LastSyncDateTime = $device.LastSyncDateTime
                    PolicyName = "No Compliance Policies Assigned"
                    PolicyState = ""
                    PolicySettingStates = ""
                }
            }
            else {
                # Device has compliance policies
                foreach ($policyStatus in $compliancePolicyStatuses) {
                    # Get policy details
                    $policy = Get-MgDeviceManagementDeviceCompliancePolicy -DeviceCompliancePolicyId $policyStatus.PolicyId
                    
                    # Get policy setting states
                    $settingStates = Get-MgDeviceManagementManagedDeviceCompliancePolicySettingState -ManagedDeviceId $device.Id -DeviceCompliancePolicySettingStateId $policyStatus.Id
                    
                    # Format setting states
                    $formattedSettingStates = ""
                    if ($null -ne $settingStates) {
                        $formattedSettingStates = ($settingStates | ForEach-Object {
                            "$($_.Setting): $($_.State)"
                        }) -join "; "
                    }
                    
                    $report += [PSCustomObject]@{
                        DeviceName = $device.DeviceName
                        SerialNumber = $device.SerialNumber
                        OperatingSystem = $device.OperatingSystem
                        OSVersion = $device.OsVersion
                        UserDisplayName = $device.UserDisplayName
                        UserPrincipalName = $device.UserPrincipalName
                        OverallComplianceState = $device.ComplianceState
                        LastSyncDateTime = $device.LastSyncDateTime
                        PolicyName = $policy.DisplayName
                        PolicyState = $policyStatus.State
                        PolicySettingStates = $formattedSettingStates
                    }
                }
            }
        }
        
        Write-Log "Generated device compliance report with $($report.Count) entries"
        return $report
    }
    catch {
        Write-Log "Error generating device compliance report: $_" -Level Error
        return $null
    }
}

function Get-DeviceConfigurationReport {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object[]]$Devices
    )
    
    try {
        Write-Log "Generating device configuration profile report..."
        
        $report = @()
        
        foreach ($device in $Devices) {
            # Get device configuration profile status
            $configurationProfileStatuses = Get-MgDeviceManagementManagedDeviceConfigurationState -ManagedDeviceId $device.Id
            
            if ($null -eq $configurationProfileStatuses -or $configurationProfileStatuses.Count -eq 0) {
                # Device has no configuration profiles
                $report += [PSCustomObject]@{
                    DeviceName = $device.DeviceName
                    SerialNumber = $device.SerialNumber
                    OperatingSystem = $device.OperatingSystem
                    OSVersion = $device.OsVersion
                    UserDisplayName = $device.UserDisplayName
                    UserPrincipalName = $device.UserPrincipalName
                    LastSyncDateTime = $device.LastSyncDateTime
                    ProfileName = "No Configuration Profiles Assigned"
                    ProfileType = ""
                    ProfileState = ""
                    ProfileSettingStates = ""
                }
            }
            else {
                # Device has configuration profiles
                foreach ($profileStatus in $configurationProfileStatuses) {
                    # Get profile details
                    $profile = Get-MgDeviceManagementDeviceConfiguration -DeviceConfigurationId $profileStatus.SettingId
                    
                    # Get profile setting states
                    $settingStates = Get-MgDeviceManagementManagedDeviceConfigurationSettingState -ManagedDeviceId $device.Id -DeviceConfigurationSettingStateId $profileStatus.Id
                    
                    # Format setting states
                    $formattedSettingStates = ""
                    if ($null -ne $settingStates) {
                        $formattedSettingStates = ($settingStates | ForEach-Object {
                            "$($_.Setting): $($_.State)"
                        }) -join "; "
                    }
                    
                    $report += [PSCustomObject]@{
                        DeviceName = $device.DeviceName
                        SerialNumber = $device.SerialNumber
                        OperatingSystem = $device.OperatingSystem
                        OSVersion = $device.OsVersion
                        UserDisplayName = $device.UserDisplayName
                        UserPrincipalName = $device.UserPrincipalName
                        LastSyncDateTime = $device.LastSyncDateTime
                        ProfileName = $profile.DisplayName
                        ProfileType = $profile.AdditionalProperties.'@odata.type'
                        ProfileState = $profileStatus.State
                        ProfileSettingStates = $formattedSettingStates
                    }
                }
            }
        }
        
        Write-Log "Generated device configuration profile report with $($report.Count) entries"
        return $report
    }
    catch {
        Write-Log "Error generating device configuration profile report: $_" -Level Error
        return $null
    }
}

function Get-DeviceAppReport {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object[]]$Devices
    )
    
    try {
        Write-Log "Generating device application report..."
        
        $report = @()
        
        foreach ($device in $Devices) {
            # Get device installed apps
            $installedApps = Get-MgDeviceManagementManagedDeviceInstalledApp -ManagedDeviceId $device.Id
            
            if ($null -eq $installedApps -or $installedApps.Count -eq 0) {
                # Device has no installed apps
                $report += [PSCustomObject]@{
                    DeviceName = $device.DeviceName
                    SerialNumber = $device.SerialNumber
                    OperatingSystem = $device.OperatingSystem
                    OSVersion = $device.OsVersion
                    UserDisplayName = $device.UserDisplayName
                    UserPrincipalName = $device.UserPrincipalName
                    LastSyncDateTime = $device.LastSyncDateTime
                    AppName = "No Installed Apps Reported"
                    AppVersion = ""
                    AppSize = ""
                    AppPublisher = ""
                    AppInstallDate = ""
                }
            }
            else {
                # Device has installed apps
                foreach ($app in $installedApps) {
                    $report += [PSCustomObject]@{
                        DeviceName = $device.DeviceName
                        SerialNumber = $device.SerialNumber
                        OperatingSystem = $device.OperatingSystem
                        OSVersion = $device.OsVersion
                        UserDisplayName = $device.UserDisplayName
                        UserPrincipalName = $device.UserPrincipalName
                        LastSyncDateTime = $device.LastSyncDateTime
                        AppName = $app.DisplayName
                        AppVersion = $app.Version
                        AppSize = if ($null -ne $app.SizeInByte) { [math]::Round($app.SizeInByte / 1MB, 2) } else { "" }
                        AppPublisher = $app.Publisher
                        AppInstallDate = $app.InstallDate
                    }
                }
            }
        }
        
        Write-Log "Generated device application report with $($report.Count) entries"
        return $report
    }
    catch {
        Write-Log "Error generating device application report: $_" -Level Error
        return $null
    }
}

function Get-DeviceSecurityReport {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object[]]$Devices,
        
        [Parameter(Mandatory = $false)]
        [string]$TimeFrame = "Last30Days"
    )
    
    try {
        Write-Log "Generating device security report for time frame: $TimeFrame..."
        
        $report = @()
        
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
        
        foreach ($device in $Devices) {
            # Get device security state
            $securityState = Get-MgDeviceManagementManagedDevice -ManagedDeviceId $device.Id -Expand securityBaselineStates,detectedApps
            
            # Get device sign-in activity
            $signIns = Get-MgAuditLogSignIn -Filter "deviceDetail/deviceId eq '$($device.AzureADDeviceId)' and createdDateTime ge $($startDate.ToString('yyyy-MM-ddTHH:mm:ssZ'))" -Top 100
            
            # Count sign-ins by status
            $successfulSignIns = ($signIns | Where-Object { $_.Status.ErrorCode -eq 0 }).Count
            $failedSignIns = ($signIns | Where-Object { $_.Status.ErrorCode -ne 0 }).Count
            
            # Get last sign-in
            $lastSignIn = $signIns | Sort-Object CreatedDateTime -Descending | Select-Object -First 1
            
            # Format security baseline states
            $baselineStates = ""
            if ($null -ne $securityState.SecurityBaselineStates) {
                $baselineStates = ($securityState.SecurityBaselineStates | ForEach-Object {
                    "$($_.DisplayName): $($_.State)"
                }) -join "; "
            }
            
            # Format detected apps
            $detectedAppsCount = if ($null -ne $securityState.DetectedApps) { $securityState.DetectedApps.Count } else { 0 }
            
            $report += [PSCustomObject]@{
                DeviceName = $device.DeviceName
                SerialNumber = $device.SerialNumber
                OperatingSystem = $device.OperatingSystem
                OSVersion = $device.OsVersion
                UserDisplayName = $device.UserDisplayName
                UserPrincipalName = $device.UserPrincipalName
                LastSyncDateTime = $device.LastSyncDateTime
                EncryptionState = $device.EncryptionState
                JailBroken = $device.JailBroken
                ComplianceState = $device.ComplianceState
                ManagementAgent = $device.ManagementAgent
                SecurityPatchLevel = $device.SecurityPatchLevel
                LastSignInDateTime = if ($null -ne $lastSignIn) { $lastSignIn.CreatedDateTime } else { $null }
                LastSignInStatus = if ($null -ne $lastSignIn) { if ($lastSignIn.Status.ErrorCode -eq 0) { "Success" } else { "Failure: $($lastSignIn.Status.FailureReason)" } } else { "No sign-ins" }
                LastSignInLocation = if ($null -ne $lastSignIn -and $null -ne $lastSignIn.Location) { "$($lastSignIn.Location.City), $($lastSignIn.Location.CountryOrRegion)" } else { "Unknown" }
                LastSignInApplication = if ($null -ne $lastSignIn) { $lastSignIn.AppDisplayName } else { "Unknown" }
                SuccessfulSignInsCount = $successfulSignIns
                FailedSignInsCount = $failedSignIns
                SecurityBaselineStates = $baselineStates
                DetectedAppsCount = $detectedAppsCount
                TimeFrame = $TimeFrame
            }
        }
        
        Write-Log "Generated device security report with $($report.Count) entries"
        return $report
    }
    catch {
        Write-Log "Error generating device security report: $_" -Level Error
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
        [string]$ExportFormat,
        
        [Parameter(Mandatory = $false)]
        [string]$ReportTitle = "Device Report"
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
                $Data | Export-Excel -Path $ExportPath -AutoSize -TableName "DeviceReport" -WorksheetName $ReportTitle
            }
            "HTML" {
                $htmlHeader = @"
<!DOCTYPE html>
<html>
<head>
    <title>$ReportTitle</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #0078D4; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
        th { background-color: #0078D4; color: white; text-align: left; padding: 8px; }
        td { border: 1px solid #ddd; padding: 8px; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        tr:hover { background-color: #ddd; }
    </style>
</head>
<body>
    <h1>$ReportTitle</h1>
    <p>Generated on: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
"@

                $htmlFooter = @"
</body>
</html>
"@

                $htmlTable = $Data | ConvertTo-Html -Fragment
                
                $htmlContent = $htmlHeader + $htmlTable + $htmlFooter
                $htmlContent | Out-File -FilePath $ExportPath
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
    Write-Log "Script started with parameters: ReportType=$ReportType, TimeFrame=$TimeFrame"
    
    # Connect to Microsoft Graph
    $connectedToGraph = Connect-ToMicrosoftGraph
    if (-not $connectedToGraph) {
        Write-Log "Cannot proceed without Microsoft Graph connection" -Level Error
        exit 1
    }
    
    # Get filtered devices
    $devices = Get-FilteredDevices -Filter $Filter -IncludePersonal $IncludePersonal -IncludeRetired $IncludeRetired
    
    if ($null -eq $devices) {
        Write-Log "No devices found with the specified filters" -Level Error
        exit 1
    }
    
    Write-Log "Retrieved $($devices.Count) devices for reporting"
    
    # Generate reports based on report type
    switch ($ReportType) {
        "Basic" {
            $report = Get-BasicDeviceReport -Devices $devices
            $reportTitle = "Basic Device Report"
        }
        "Detailed" {
            $report = Get-DetailedDeviceReport -Devices $devices
            $reportTitle = "Detailed Device Report"
        }
        "Compliance" {
            $report = Get-DeviceComplianceReport -Devices $devices
            $reportTitle = "Device Compliance Report"
        }
        "Profiles" {
            $report = Get-DeviceConfigurationReport -Devices $devices
            $reportTitle = "Device Configuration Profile Report"
        }
        "Apps" {
            $report = Get-DeviceAppReport -Devices $devices
            $reportTitle = "Device Application Report"
        }
        "Security" {
            $report = Get-DeviceSecurityReport -Devices $devices -TimeFrame $TimeFrame
            $reportTitle = "Device Security Report"
        }
        "All" {
            # Generate all reports
            $basicReport = Get-BasicDeviceReport -Devices $devices
            $detailedReport = Get-DetailedDeviceReport -Devices $devices
            $complianceReport = Get-DeviceComplianceReport -Devices $devices
            $profileReport = Get-DeviceConfigurationReport -Devices $devices
            $appReport = Get-DeviceAppReport -Devices $devices
            $securityReport = Get-DeviceSecurityReport -Devices $devices -TimeFrame $TimeFrame
            
            # Export each report
            $exportPathWithoutExtension = [System.IO.Path]::GetDirectoryName($ExportPath) + "\" + [System.IO.Path]::GetFileNameWithoutExtension($ExportPath)
            $extension = [System.IO.Path]::GetExtension($ExportPath)
            
            if ($ExportFormat -eq "Excel") {
                # For Excel, export all reports to different worksheets in the same file
                $basicReport | Export-Excel -Path $ExportPath -AutoSize -TableName "BasicDeviceReport" -WorksheetName "Basic Device Report"
                $detailedReport | Export-Excel -Path $ExportPath -AutoSize -TableName "DetailedDeviceReport" -WorksheetName "Detailed Device Report" -ClearSheet
                $complianceReport | Export-Excel -Path $ExportPath -AutoSize -TableName "DeviceComplianceReport" -WorksheetName "Device Compliance Report" -ClearSheet
                $profileReport | Export-Excel -Path $ExportPath -AutoSize -TableName "DeviceProfileReport" -WorksheetName "Device Profile Report" -ClearSheet
                $appReport | Export-Excel -Path $ExportPath -AutoSize -TableName "DeviceAppReport" -WorksheetName "Device App Report" -ClearSheet
                $securityReport | Export-Excel -Path $ExportPath -AutoSize -TableName "DeviceSecurityReport" -WorksheetName "Device Security Report" -ClearSheet
                
                Write-Log "All reports exported successfully to: $ExportPath"
            }
            else {
                # For other formats, export to separate files
                Export-Report -Data $basicReport -ExportPath "$exportPathWithoutExtension-Basic$extension" -ExportFormat $ExportFormat -ReportTitle "Basic Device Report"
                Export-Report -Data $detailedReport -ExportPath "$exportPathWithoutExtension-Detailed$extension" -ExportFormat $ExportFormat -ReportTitle "Detailed Device Report"
                Export-Report -Data $complianceReport -ExportPath "$exportPathWithoutExtension-Compliance$extension" -ExportFormat $ExportFormat -ReportTitle "Device Compliance Report"
                Export-Report -Data $profileReport -ExportPath "$exportPathWithoutExtension-Profiles$extension" -ExportFormat $ExportFormat -ReportTitle "Device Configuration Profile Report"
                Export-Report -Data $appReport -ExportPath "$exportPathWithoutExtension-Apps$extension" -ExportFormat $ExportFormat -ReportTitle "Device Application Report"
                Export-Report -Data $securityReport -ExportPath "$exportPathWithoutExtension-Security$extension" -ExportFormat $ExportFormat -ReportTitle "Device Security Report"
                
                Write-Log "All reports exported successfully to separate files with base path: $exportPathWithoutExtension"
            }
            
            # Exit early since we've already exported all reports
            exit 0
        }
    }
    
    # Export report
    if ($null -ne $report) {
        $exportResult = Export-Report -Data $report -ExportPath $ExportPath -ExportFormat $ExportFormat -ReportTitle $reportTitle
        
        if ($exportResult) {
            Write-Output "Report exported successfully to: $ExportPath"
        }
        else {
            Write-Output "Failed to export report"
            exit 1
        }
    }
    else {
        Write-Log "No report data generated" -Level Error
        exit 1
    }
    
    # Output success message
    Write-Output "Device report generation completed successfully"
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
