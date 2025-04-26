<#
.SYNOPSIS
    Exports Microsoft Intune device data using Microsoft Graph API.

.DESCRIPTION
    This script exports detailed Microsoft Intune device data using Microsoft Graph API.
    It supports various export options including basic device information, compliance status,
    installed applications, configuration profiles, and security status.
    Results can be exported to CSV, JSON, or Excel formats.

.PARAMETER ExportOptions
    The device data to export (Basic, Compliance, Applications, Configurations, Security, All).

.PARAMETER OutputFormat
    The format of the export file (CSV, JSON, Excel).

.PARAMETER OutputPath
    The path where the export file will be saved.

.PARAMETER FilterByOS
    Filter devices by operating system (Windows, iOS, Android, macOS).

.PARAMETER FilterByOwnership
    Filter devices by ownership type (Corporate, Personal, Unknown).

.PARAMETER FilterByComplianceStatus
    Filter devices by compliance status (Compliant, NonCompliant, Unknown, All).

.PARAMETER FilterByEnrollmentStatus
    Filter devices by enrollment status (Enrolled, NotEnrolled, All).

.PARAMETER FilterByLastSyncTime
    Filter devices by last sync time in days (e.g., 30 for devices that synced in the last 30 days).

.PARAMETER IncludeRetired
    Whether to include retired devices in the export.

.PARAMETER MaxDevices
    Maximum number of devices to export. Default is all devices.

.PARAMETER LogPath
    Path where logs will be stored. Defaults to Windows log directory.

.EXAMPLE
    .\Export-GraphDevices.ps1 -ExportOptions Basic,Compliance -OutputFormat CSV -OutputPath "C:\Exports\DeviceExport.csv"
    Exports basic device information and compliance status to a CSV file.

.EXAMPLE
    .\Export-GraphDevices.ps1 -ExportOptions All -OutputFormat Excel -OutputPath "C:\Exports\DeviceExport.xlsx" -FilterByOS Windows -FilterByComplianceStatus NonCompliant
    Exports all device data for non-compliant Windows devices to an Excel file.

.NOTES
    Author: Michael Witzsche
    Date: April 26, 2025
    Version: 1.1
#>

#Requires -Modules Microsoft.Graph.DeviceManagement, Microsoft.Graph.DeviceManagement.Administration, ImportExcel

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$LogPath = "$env:SystemRoot\Logs\Export-GraphDevices",
    
    [Parameter(Mandatory = $true)]
    [ValidateSet("Basic", "Compliance", "Applications", "Configurations", "Security", "All")]
    [string[]]$ExportOptions,
    
    [Parameter(Mandatory = $true)]
    [ValidateSet("CSV", "JSON", "Excel")]
    [string]$OutputFormat,
    
    [Parameter(Mandatory = $true)]
    [string]$OutputPath,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Windows", "iOS", "Android", "macOS", "")]
    [string]$FilterByOS = "",
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Corporate", "Personal", "Unknown", "")]
    [string]$FilterByOwnership = "",
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Compliant", "NonCompliant", "Unknown", "All")]
    [string]$FilterByComplianceStatus = "All",
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Enrolled", "NotEnrolled", "All")]
    [string]$FilterByEnrollmentStatus = "All",
    
    [Parameter(Mandatory = $false)]
    [int]$FilterByLastSyncTime = 0,
    
    [Parameter(Mandatory = $false)]
    [bool]$IncludeRetired = $false,
    
    [Parameter(Mandatory = $false)]
    [int]$MaxDevices = 0
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
        Connect-MgGraph -Scopes "DeviceManagementManagedDevices.Read.All", "DeviceManagementConfiguration.Read.All", "DeviceManagementApps.Read.All" -ErrorAction Stop
        
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

function Get-FilteredDevices {
    [CmdletBinding()]
    param()
    
    try {
        # Build filter
        $filter = ""
        
        # Filter by OS
        if (-not [string]::IsNullOrEmpty($FilterByOS)) {
            switch ($FilterByOS) {
                "Windows" { $filter = "contains(operatingSystem, 'Windows')" }
                "iOS" { $filter = "contains(operatingSystem, 'iOS')" }
                "Android" { $filter = "contains(operatingSystem, 'Android')" }
                "macOS" { $filter = "contains(operatingSystem, 'macOS')" }
            }
        }
        
        # Filter by ownership
        if (-not [string]::IsNullOrEmpty($FilterByOwnership)) {
            $ownershipFilter = ""
            switch ($FilterByOwnership) {
                "Corporate" { $ownershipFilter = "managedDeviceOwnerType eq 'company'" }
                "Personal" { $ownershipFilter = "managedDeviceOwnerType eq 'personal'" }
                "Unknown" { $ownershipFilter = "managedDeviceOwnerType eq 'unknown'" }
            }
            
            if (-not [string]::IsNullOrEmpty($filter)) {
                $filter += " and $ownershipFilter"
            }
            else {
                $filter = $ownershipFilter
            }
        }
        
        # Filter by compliance status
        if ($FilterByComplianceStatus -ne "All") {
            $complianceFilter = ""
            switch ($FilterByComplianceStatus) {
                "Compliant" { $complianceFilter = "complianceState eq 'compliant'" }
                "NonCompliant" { $complianceFilter = "complianceState eq 'noncompliant'" }
                "Unknown" { $complianceFilter = "complianceState eq 'unknown'" }
            }
            
            if (-not [string]::IsNullOrEmpty($filter)) {
                $filter += " and $complianceFilter"
            }
            else {
                $filter = $complianceFilter
            }
        }
        
        # Filter by enrollment status
        if ($FilterByEnrollmentStatus -ne "All") {
            $enrollmentFilter = ""
            switch ($FilterByEnrollmentStatus) {
                "Enrolled" { $enrollmentFilter = "managementState eq 'managed'" }
                "NotEnrolled" { $enrollmentFilter = "managementState eq 'unmanaged'" }
            }
            
            if (-not [string]::IsNullOrEmpty($filter)) {
                $filter += " and $enrollmentFilter"
            }
            else {
                $filter = $enrollmentFilter
            }
        }
        
        # Filter by last sync time
        if ($FilterByLastSyncTime -gt 0) {
            $syncDate = (Get-Date).AddDays(-$FilterByLastSyncTime).ToString("yyyy-MM-dd")
            $syncFilter = "lastSyncDateTime ge $syncDate"
            
            if (-not [string]::IsNullOrEmpty($filter)) {
                $filter += " and $syncFilter"
            }
            else {
                $filter = $syncFilter
            }
        }
        
        # Exclude retired devices if specified
        if (-not $IncludeRetired) {
            $retiredFilter = "managementState ne 'retired'"
            
            if (-not [string]::IsNullOrEmpty($filter)) {
                $filter += " and $retiredFilter"
            }
            else {
                $filter = $retiredFilter
            }
        }
        
        # Get devices with filter
        Write-Log "Retrieving devices with filter: $filter"
        
        $params = @{
            All = $true
        }
        
        if (-not [string]::IsNullOrEmpty($filter)) {
            $params.Filter = $filter
        }
        
        $devices = Get-MgDeviceManagementManagedDevice @params
        
        # Apply max devices limit if specified
        if ($MaxDevices -gt 0 -and $devices.Count -gt $MaxDevices) {
            Write-Log "Limiting export to $MaxDevices devices"
            $devices = $devices | Select-Object -First $MaxDevices
        }
        
        Write-Log "Retrieved $($devices.Count) devices"
        return $devices
    }
    catch {
        Write-Log "Error retrieving devices: $_" -Level Error
        throw $_
    }
}

function Get-DeviceComplianceStatus {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object[]]$Devices
    )
    
    try {
        Write-Log "Retrieving compliance status for $($Devices.Count) devices"
        
        # Create device compliance information
        $deviceCompliance = @()
        
        foreach ($device in $Devices) {
            # Get compliance policy status
            $complianceStatus = Get-MgDeviceManagementDeviceCompliancePolicyDeviceStateSummary
            
            $deviceCompliance += [PSCustomObject]@{
                DeviceId = $device.Id
                DeviceName = $device.DeviceName
                ComplianceState = $device.ComplianceState
                ComplianceGracePeriodExpirationDateTime = $device.ComplianceGracePeriodExpirationDateTime
                NonCompliantSettingCount = $device.NonCompliantSettingCount
                SecurityPatchLevel = $device.SecurityPatchLevel
                JailBroken = $device.JailBroken
                ManagementAgent = $device.ManagementAgent
                IsEncrypted = $device.IsEncrypted
                IsSupervised = $device.IsSupervised
            }
        }
        
        Write-Log "Compliance status retrieved successfully"
        return $deviceCompliance
    }
    catch {
        Write-Log "Error retrieving device compliance status: $_" -Level Error
        throw $_
    }
}

function Get-DeviceApplications {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object[]]$Devices
    )
    
    try {
        Write-Log "Retrieving installed applications for $($Devices.Count) devices"
        
        # Create device application information
        $deviceApplications = @()
        
        foreach ($device in $Devices) {
            Write-Log "Getting applications for device: $($device.DeviceName)" -Level Information
            
            try {
                # Get installed applications
                $apps = Get-MgDeviceManagementManagedDeviceDetectedApp -ManagedDeviceId $device.Id -ErrorAction SilentlyContinue
                
                if ($null -ne $apps -and $apps.Count -gt 0) {
                    foreach ($app in $apps) {
                        $deviceApplications += [PSCustomObject]@{
                            DeviceId = $device.Id
                            DeviceName = $device.DeviceName
                            AppName = $app.DisplayName
                            AppVersion = $app.Version
                            AppSize = $app.SizeInByte
                            AppPublisher = $app.Publisher
                            DetectedDateTime = $app.DetectedDateTime
                        }
                    }
                }
                else {
                    # Add a record even if no apps are found
                    $deviceApplications += [PSCustomObject]@{
                        DeviceId = $device.Id
                        DeviceName = $device.DeviceName
                        AppName = "No applications detected"
                        AppVersion = ""
                        AppSize = 0
                        AppPublisher = ""
                        DetectedDateTime = ""
                    }
                }
            }
            catch {
                Write-Log "Error retrieving applications for device $($device.DeviceName): $_" -Level Warning
                
                # Add a record for the error
                $deviceApplications += [PSCustomObject]@{
                    DeviceId = $device.Id
                    DeviceName = $device.DeviceName
                    AppName = "Error retrieving applications"
                    AppVersion = ""
                    AppSize = 0
                    AppPublisher = ""
                    DetectedDateTime = ""
                }
            }
        }
        
        Write-Log "Installed applications retrieved successfully"
        return $deviceApplications
    }
    catch {
        Write-Log "Error retrieving device applications: $_" -Level Error
        throw $_
    }
}

function Get-DeviceConfigurations {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object[]]$Devices
    )
    
    try {
        Write-Log "Retrieving configuration profiles for $($Devices.Count) devices"
        
        # Get all configuration profiles
        $configProfiles = Get-MgDeviceManagementDeviceConfiguration
        
        # Create device configuration information
        $deviceConfigurations = @()
        
        foreach ($device in $Devices) {
            Write-Log "Getting configuration profiles for device: $($device.DeviceName)" -Level Information
            
            try {
                # Get device configuration status
                $deviceConfigStatus = @()
                
                foreach ($profile in $configProfiles) {
                    $status = Get-MgDeviceManagementDeviceConfigurationDeviceStatus -DeviceConfigurationId $profile.Id | 
                        Where-Object { $_.DeviceId -eq $device.Id }
                    
                    if ($null -ne $status) {
                        $deviceConfigStatus += [PSCustomObject]@{
                            ProfileId = $profile.Id
                            ProfileName = $profile.DisplayName
                            Status = $status.Status
                            LastReportedDateTime = $status.LastReportedDateTime
                        }
                    }
                }
                
                if ($deviceConfigStatus.Count -gt 0) {
                    foreach ($config in $deviceConfigStatus) {
                        $deviceConfigurations += [PSCustomObject]@{
                            DeviceId = $device.Id
                            DeviceName = $device.DeviceName
                            ProfileName = $config.ProfileName
                            Status = $config.Status
                            LastReportedDateTime = $config.LastReportedDateTime
                        }
                    }
                }
                else {
                    # Add a record even if no configurations are found
                    $deviceConfigurations += [PSCustomObject]@{
                        DeviceId = $device.Id
                        DeviceName = $device.DeviceName
                        ProfileName = "No configuration profiles assigned"
                        Status = ""
                        LastReportedDateTime = ""
                    }
                }
            }
            catch {
                Write-Log "Error retrieving configuration profiles for device $($device.DeviceName): $_" -Level Warning
                
                # Add a record for the error
                $deviceConfigurations += [PSCustomObject]@{
                    DeviceId = $device.Id
                    DeviceName = $device.DeviceName
                    ProfileName = "Error retrieving configuration profiles"
                    Status = ""
                    LastReportedDateTime = ""
                }
            }
        }
        
        Write-Log "Configuration profiles retrieved successfully"
        return $deviceConfigurations
    }
    catch {
        Write-Log "Error retrieving device configurations: $_" -Level Error
        throw $_
    }
}

function Get-DeviceSecurityStatus {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object[]]$Devices
    )
    
    try {
        Write-Log "Retrieving security status for $($Devices.Count) devices"
        
        # Create device security information
        $deviceSecurity = @()
        
        foreach ($device in $Devices) {
            $deviceSecurity += [PSCustomObject]@{
                DeviceId = $device.Id
                DeviceName = $device.DeviceName
                IsEncrypted = $device.IsEncrypted
                JailBroken = $device.JailBroken
                SecurityPatchLevel = $device.SecurityPatchLevel
                AadRegistered = $device.AadRegistered
                EncryptionState = $device.EncryptionState
                AntivirusSignatureStatus = $device.AntivirusSignatureStatus
                AntivirusEnabled = $device.AntivirusEnabled
                FirewallEnabled = $device.FirewallEnabled
                SecureBootEnabled = $device.SecureBootEnabled
                TpmSpecificationVersion = $device.TpmSpecificationVersion
                RequireUserEnrollmentApproval = $device.RequireUserEnrollmentApproval
                ManagedDeviceOwnerType = $device.ManagedDeviceOwnerType
                ManagementState = $device.ManagementState
                LastSyncDateTime = $device.LastSyncDateTime
            }
        }
        
        Write-Log "Security status retrieved successfully"
        return $deviceSecurity
    }
    catch {
        Write-Log "Error retrieving device security status: $_" -Level Error
        throw $_
    }
}

function Format-DeviceData {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object[]]$Devices,
        
        [Parameter(Mandatory = $false)]
        [object[]]$DeviceCompliance = $null,
        
        [Parameter(Mandatory = $false)]
        [object[]]$DeviceApplications = $null,
        
        [Parameter(Mandatory = $false)]
        [object[]]$DeviceConfigurations = $null,
        
        [Parameter(Mandatory = $false)]
        [object[]]$DeviceSecurity = $null
    )
    
    try {
        Write-Log "Formatting device data for export"
        
        # Create formatted device data
        $formattedDevices = @()
        
        foreach ($device in $Devices) {
            $deviceData = [ordered]@{
                DeviceId = $device.Id
                DeviceName = $device.DeviceName
                SerialNumber = $device.SerialNumber
                IMEI = $device.Imei
                Manufacturer = $device.Manufacturer
                Model = $device.Model
                OperatingSystem = $device.OperatingSystem
                OSVersion = $device.OsVersion
                UserPrincipalName = $device.UserPrincipalName
                EmailAddress = $device.EmailAddress
                PhoneNumber = $device.PhoneNumber
                WiFiMacAddress = $device.WiFiMacAddress
                EthernetMacAddress = $device.EthernetMacAddress
                SubscriberCarrier = $device.SubscriberCarrier
                CellularTechnology = $device.CellularTechnology
                EnrolledDateTime = $device.EnrolledDateTime
                LastSyncDateTime = $device.LastSyncDateTime
                ManagedDeviceOwnerType = $device.ManagedDeviceOwnerType
                ManagementState = $device.ManagementState
                DeviceCategory = $device.DeviceCategory
                DeviceType = $device.DeviceType
            }
            
            # Add compliance information if available
            if ($null -ne $DeviceCompliance) {
                $compliance = $DeviceCompliance | Where-Object { $_.DeviceId -eq $device.Id } | Select-Object -First 1
                if ($null -ne $compliance) {
                    $deviceData.ComplianceState = $compliance.ComplianceState
                    $deviceData.ComplianceGracePeriodExpirationDateTime = $compliance.ComplianceGracePeriodExpirationDateTime
                    $deviceData.NonCompliantSettingCount = $compliance.NonCompliantSettingCount
                    $deviceData.SecurityPatchLevel = $compliance.SecurityPatchLevel
                    $deviceData.JailBroken = $compliance.JailBroken
                    $deviceData.ManagementAgent = $compliance.ManagementAgent
                    $deviceData.IsEncrypted = $compliance.IsEncrypted
                    $deviceData.IsSupervised = $compliance.IsSupervised
                }
            }
            
            # Add security information if available
            if ($null -ne $DeviceSecurity) {
                $security = $DeviceSecurity | Where-Object { $_.DeviceId -eq $device.Id } | Select-Object -First 1
                if ($null -ne $security) {
                    $deviceData.IsEncrypted = $security.IsEncrypted
                    $deviceData.JailBroken = $security.JailBroken
                    $deviceData.SecurityPatchLevel = $security.SecurityPatchLevel
                    $deviceData.AadRegistered = $security.AadRegistered
                    $deviceData.EncryptionState = $security.EncryptionState
                    $deviceData.AntivirusSignatureStatus = $security.AntivirusSignatureStatus
                    $deviceData.AntivirusEnabled = $security.AntivirusEnabled
                    $deviceData.FirewallEnabled = $security.FirewallEnabled
                    $deviceData.SecureBootEnabled = $security.SecureBootEnabled
                    $deviceData.TpmSpecificationVersion = $security.TpmSpecificationVersion
                }
            }
            
            $formattedDevices += [PSCustomObject]$deviceData
        }
        
        Write-Log "Device data formatted successfully"
        return $formattedDevices
    }
    catch {
        Write-Log "Error formatting device data: $_" -Level Error
        throw $_
    }
}

function Export-DeviceDataToCSV {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object[]]$DeviceData,
        
        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )
    
    try {
        Write-Log "Exporting device data to CSV: $OutputPath"
        
        # Export to CSV
        $DeviceData | Export-Csv -Path $OutputPath -NoTypeInformation
        
        Write-Log "Device data exported to CSV successfully"
        return $true
    }
    catch {
        Write-Log "Error exporting device data to CSV: $_" -Level Error
        return $false
    }
}

function Export-DeviceDataToJSON {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object[]]$DeviceData,
        
        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )
    
    try {
        Write-Log "Exporting device data to JSON: $OutputPath"
        
        # Export to JSON
        $DeviceData | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath -Encoding utf8
        
        Write-Log "Device data exported to JSON successfully"
        return $true
    }
    catch {
        Write-Log "Error exporting device data to JSON: $_" -Level Error
        return $false
    }
}

function Export-DeviceDataToExcel {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object[]]$DeviceData,
        
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,
        
        [Parameter(Mandatory = $false)]
        [object[]]$DeviceCompliance = $null,
        
        [Parameter(Mandatory = $false)]
        [object[]]$DeviceApplications = $null,
        
        [Parameter(Mandatory = $false)]
        [object[]]$DeviceConfigurations = $null,
        
        [Parameter(Mandatory = $false)]
        [object[]]$DeviceSecurity = $null
    )
    
    try {
        Write-Log "Exporting device data to Excel: $OutputPath"
        
        # Create Excel package
        $excelPackage = New-Object OfficeOpenXml.ExcelPackage
        
        # Create Devices worksheet
        $devicesSheet = $excelPackage.Workbook.Worksheets.Add("Devices")
        
        # Add headers
        $headers = $DeviceData[0].PSObject.Properties.Name
        for ($i = 0; $i -lt $headers.Count; $i++) {
            $devicesSheet.Cells[1, $i + 1].Value = $headers[$i]
        }
        
        # Add data
        for ($row = 0; $row -lt $DeviceData.Count; $row++) {
            for ($col = 0; $col -lt $headers.Count; $col++) {
                $devicesSheet.Cells[$row + 2, $col + 1].Value = $DeviceData[$row].$($headers[$col])
            }
        }
        
        # Add additional worksheets if data is available
        if ($null -ne $DeviceCompliance) {
            $complianceSheet = $excelPackage.Workbook.Worksheets.Add("Compliance")
            
            # Add headers
            $complianceSheet.Cells["A1"].Value = "DeviceName"
            $complianceSheet.Cells["B1"].Value = "ComplianceState"
            $complianceSheet.Cells["C1"].Value = "NonCompliantSettingCount"
            $complianceSheet.Cells["D1"].Value = "SecurityPatchLevel"
            $complianceSheet.Cells["E1"].Value = "JailBroken"
            $complianceSheet.Cells["F1"].Value = "IsEncrypted"
            $complianceSheet.Cells["G1"].Value = "IsSupervised"
            
            # Add data
            for ($row = 0; $row -lt $DeviceCompliance.Count; $row++) {
                $complianceSheet.Cells[$row + 2, 1].Value = $DeviceCompliance[$row].DeviceName
                $complianceSheet.Cells[$row + 2, 2].Value = $DeviceCompliance[$row].ComplianceState
                $complianceSheet.Cells[$row + 2, 3].Value = $DeviceCompliance[$row].NonCompliantSettingCount
                $complianceSheet.Cells[$row + 2, 4].Value = $DeviceCompliance[$row].SecurityPatchLevel
                $complianceSheet.Cells[$row + 2, 5].Value = $DeviceCompliance[$row].JailBroken
                $complianceSheet.Cells[$row + 2, 6].Value = $DeviceCompliance[$row].IsEncrypted
                $complianceSheet.Cells[$row + 2, 7].Value = $DeviceCompliance[$row].IsSupervised
            }
        }
        
        if ($null -ne $DeviceApplications) {
            $appsSheet = $excelPackage.Workbook.Worksheets.Add("Applications")
            
            # Add headers
            $appsSheet.Cells["A1"].Value = "DeviceName"
            $appsSheet.Cells["B1"].Value = "AppName"
            $appsSheet.Cells["C1"].Value = "AppVersion"
            $appsSheet.Cells["D1"].Value = "AppPublisher"
            $appsSheet.Cells["E1"].Value = "AppSize"
            $appsSheet.Cells["F1"].Value = "DetectedDateTime"
            
            # Add data
            for ($row = 0; $row -lt $DeviceApplications.Count; $row++) {
                $appsSheet.Cells[$row + 2, 1].Value = $DeviceApplications[$row].DeviceName
                $appsSheet.Cells[$row + 2, 2].Value = $DeviceApplications[$row].AppName
                $appsSheet.Cells[$row + 2, 3].Value = $DeviceApplications[$row].AppVersion
                $appsSheet.Cells[$row + 2, 4].Value = $DeviceApplications[$row].AppPublisher
                $appsSheet.Cells[$row + 2, 5].Value = $DeviceApplications[$row].AppSize
                $appsSheet.Cells[$row + 2, 6].Value = $DeviceApplications[$row].DetectedDateTime
            }
        }
        
        if ($null -ne $DeviceConfigurations) {
            $configSheet = $excelPackage.Workbook.Worksheets.Add("Configurations")
            
            # Add headers
            $configSheet.Cells["A1"].Value = "DeviceName"
            $configSheet.Cells["B1"].Value = "ProfileName"
            $configSheet.Cells["C1"].Value = "Status"
            $configSheet.Cells["D1"].Value = "LastReportedDateTime"
            
            # Add data
            for ($row = 0; $row -lt $DeviceConfigurations.Count; $row++) {
                $configSheet.Cells[$row + 2, 1].Value = $DeviceConfigurations[$row].DeviceName
                $configSheet.Cells[$row + 2, 2].Value = $DeviceConfigurations[$row].ProfileName
                $configSheet.Cells[$row + 2, 3].Value = $DeviceConfigurations[$row].Status
                $configSheet.Cells[$row + 2, 4].Value = $DeviceConfigurations[$row].LastReportedDateTime
            }
        }
        
        if ($null -ne $DeviceSecurity) {
            $securitySheet = $excelPackage.Workbook.Worksheets.Add("Security")
            
            # Add headers
            $securitySheet.Cells["A1"].Value = "DeviceName"
            $securitySheet.Cells["B1"].Value = "IsEncrypted"
            $securitySheet.Cells["C1"].Value = "EncryptionState"
            $securitySheet.Cells["D1"].Value = "JailBroken"
            $securitySheet.Cells["E1"].Value = "SecurityPatchLevel"
            $securitySheet.Cells["F1"].Value = "AntivirusEnabled"
            $securitySheet.Cells["G1"].Value = "FirewallEnabled"
            $securitySheet.Cells["H1"].Value = "SecureBootEnabled"
            
            # Add data
            for ($row = 0; $row -lt $DeviceSecurity.Count; $row++) {
                $securitySheet.Cells[$row + 2, 1].Value = $DeviceSecurity[$row].DeviceName
                $securitySheet.Cells[$row + 2, 2].Value = $DeviceSecurity[$row].IsEncrypted
                $securitySheet.Cells[$row + 2, 3].Value = $DeviceSecurity[$row].EncryptionState
                $securitySheet.Cells[$row + 2, 4].Value = $DeviceSecurity[$row].JailBroken
                $securitySheet.Cells[$row + 2, 5].Value = $DeviceSecurity[$row].SecurityPatchLevel
                $securitySheet.Cells[$row + 2, 6].Value = $DeviceSecurity[$row].AntivirusEnabled
                $securitySheet.Cells[$row + 2, 7].Value = $DeviceSecurity[$row].FirewallEnabled
                $securitySheet.Cells[$row + 2, 8].Value = $DeviceSecurity[$row].SecureBootEnabled
            }
        }
        
        # Format all worksheets
        foreach ($worksheet in $excelPackage.Workbook.Worksheets) {
            # Format headers
            $headerRange = $worksheet.Dimension.Address -replace "\d+", "1"
            $worksheet.Cells[$headerRange].Style.Font.Bold = $true
            $worksheet.Cells[$headerRange].Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
            $worksheet.Cells[$headerRange].Style.Fill.BackgroundColor.SetColor([System.Drawing.Color]::LightGray)
            
            # Auto-fit columns
            $worksheet.Cells[$worksheet.Dimension.Address].AutoFitColumns()
        }
        
        # Save Excel file
        $excelPackage.SaveAs($OutputPath)
        
        Write-Log "Device data exported to Excel successfully"
        return $true
    }
    catch {
        Write-Log "Error exporting device data to Excel: $_" -Level Error
        return $false
    }
}
#endregion

#region Main Script
try {
    # Script start
    Write-Log "Script started with parameters: ExportOptions=$($ExportOptions -join ','), OutputFormat=$OutputFormat"
    
    # Connect to Microsoft Graph
    $connectedToGraph = Connect-ToMSGraph
    if (-not $connectedToGraph) {
        Write-Log "Cannot proceed without Microsoft Graph connection" -Level Error
        exit 1
    }
    
    # Get devices
    $devices = Get-FilteredDevices
    
    if ($devices.Count -eq 0) {
        Write-Log "No devices found matching the specified filters" -Level Warning
        exit 0
    }
    
    # Initialize variables for additional data
    $deviceCompliance = $null
    $deviceApplications = $null
    $deviceConfigurations = $null
    $deviceSecurity = $null
    
    # Get additional data based on export options
    if ($ExportOptions -contains "All" -or $ExportOptions -contains "Compliance") {
        $deviceCompliance = Get-DeviceComplianceStatus -Devices $devices
    }
    
    if ($ExportOptions -contains "All" -or $ExportOptions -contains "Applications") {
        $deviceApplications = Get-DeviceApplications -Devices $devices
    }
    
    if ($ExportOptions -contains "All" -or $ExportOptions -contains "Configurations") {
        $deviceConfigurations = Get-DeviceConfigurations -Devices $devices
    }
    
    if ($ExportOptions -contains "All" -or $ExportOptions -contains "Security") {
        $deviceSecurity = Get-DeviceSecurityStatus -Devices $devices
    }
    
    # Format device data
    $formattedDevices = Format-DeviceData -Devices $devices -DeviceCompliance $deviceCompliance -DeviceApplications $deviceApplications -DeviceConfigurations $deviceConfigurations -DeviceSecurity $deviceSecurity
    
    # Export data based on output format
    $exportResult = $false
    
    switch ($OutputFormat) {
        "CSV" {
            $exportResult = Export-DeviceDataToCSV -DeviceData $formattedDevices -OutputPath $OutputPath
        }
        "JSON" {
            $exportResult = Export-DeviceDataToJSON -DeviceData $formattedDevices -OutputPath $OutputPath
        }
        "Excel" {
            $exportResult = Export-DeviceDataToExcel -DeviceData $formattedDevices -OutputPath $OutputPath -DeviceCompliance $deviceCompliance -DeviceApplications $deviceApplications -DeviceConfigurations $deviceConfigurations -DeviceSecurity $deviceSecurity
        }
    }
    
    if (-not $exportResult) {
        Write-Log "Failed to export device data" -Level Error
        exit 1
    }
    
    # Output success message
    Write-Output "Device data exported successfully to: $OutputPath"
    Write-Output "Total devices exported: $($devices.Count)"
    
    # Output additional statistics
    if ($null -ne $deviceCompliance) {
        $compliantDevices = ($deviceCompliance | Where-Object { $_.ComplianceState -eq "compliant" }).Count
        Write-Output "Compliant devices: $compliantDevices"
        
        $nonCompliantDevices = ($deviceCompliance | Where-Object { $_.ComplianceState -eq "noncompliant" }).Count
        Write-Output "Non-compliant devices: $nonCompliantDevices"
    }
    
    if ($null -ne $deviceSecurity) {
        $encryptedDevices = ($deviceSecurity | Where-Object { $_.IsEncrypted -eq $true }).Count
        Write-Output "Encrypted devices: $encryptedDevices"
        
        $secureBootDevices = ($deviceSecurity | Where-Object { $_.SecureBootEnabled -eq $true }).Count
        Write-Output "Devices with Secure Boot enabled: $secureBootDevices"
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
