<#
.SYNOPSIS
    Manages data protection with Windows Information Protection (WIP).

.DESCRIPTION
    This script manages Windows Information Protection (WIP) policies for protecting
    corporate data on devices. It supports creating, updating, and removing WIP policies,
    as well as reporting on policy status and compliance.

.PARAMETER Action
    The action to perform (Get, Create, Update, Remove, Report).

.PARAMETER PolicyName
    The name of the WIP policy to manage.

.PARAMETER EnforcementLevel
    The enforcement level for the WIP policy (Off, Silent, Override, Block).

.PARAMETER ProtectedApps
    Array of protected app package family names or file paths.

.PARAMETER ExemptApps
    Array of exempt app package family names or file paths.

.PARAMETER ProtectedDomains
    Array of domains to protect.

.PARAMETER ProtectedNetworkLocations
    Array of network locations to protect.

.PARAMETER DataRecoveryCertificate
    The data recovery certificate to use for the WIP policy.

.PARAMETER TargetGroups
    Array of group IDs to target with the policy.

.PARAMETER ExcludedGroups
    Array of group IDs to exclude from the policy.

.PARAMETER ReportType
    The type of report to generate (Compliance, Status, Violations).

.PARAMETER ExportPath
    The path where the report will be saved.

.PARAMETER ExportFormat
    The format of the export file (CSV, JSON, Excel).

.PARAMETER LogPath
    Path where logs will be stored. Defaults to Windows log directory.

.EXAMPLE
    .\Manage-WindowsInformationProtection.ps1 -Action Create -PolicyName "Corporate WIP Policy" -EnforcementLevel "Block" -ProtectedDomains @("contoso.com", "fabrikam.com") -TargetGroups @("00000000-0000-0000-0000-000000000000")
    Creates a new WIP policy with Block enforcement level.

.EXAMPLE
    .\Manage-WindowsInformationProtection.ps1 -Action Report -ReportType Compliance -ExportPath "C:\Reports\WIPCompliance.csv" -ExportFormat CSV
    Generates a WIP compliance report and exports it to CSV format.

.NOTES
    Author: Michael Witzsche
    Date: April 26, 2025
    Version: 1.0.0
    
    History:
    1.0.0 - Initial release
#>

#Requires -Modules Microsoft.Graph.Intune, Microsoft.Graph.Authentication, ImportExcel

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$LogPath = "$env:SystemRoot\Logs\Manage-WindowsInformationProtection",
    
    [Parameter(Mandatory = $true)]
    [ValidateSet("Get", "Create", "Update", "Remove", "Report")]
    [string]$Action,
    
    [Parameter(Mandatory = $false)]
    [string]$PolicyName = "",
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Off", "Silent", "Override", "Block", "")]
    [string]$EnforcementLevel = "",
    
    [Parameter(Mandatory = $false)]
    [string[]]$ProtectedApps = @(),
    
    [Parameter(Mandatory = $false)]
    [string[]]$ExemptApps = @(),
    
    [Parameter(Mandatory = $false)]
    [string[]]$ProtectedDomains = @(),
    
    [Parameter(Mandatory = $false)]
    [string[]]$ProtectedNetworkLocations = @(),
    
    [Parameter(Mandatory = $false)]
    [string]$DataRecoveryCertificate = "",
    
    [Parameter(Mandatory = $false)]
    [string[]]$TargetGroups = @(),
    
    [Parameter(Mandatory = $false)]
    [string[]]$ExcludedGroups = @(),
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Compliance", "Status", "Violations", "")]
    [string]$ReportType = "",
    
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
            "DeviceManagementApps.ReadWrite.All",
            "DeviceManagementConfiguration.ReadWrite.All",
            "DeviceManagementManagedDevices.ReadWrite.All",
            "Group.Read.All",
            "User.Read.All"
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

function Get-WIPPolicies {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$PolicyName = ""
    )
    
    try {
        Write-Log "Retrieving WIP policies..."
        
        # Get WIP policies
        $uri = "https://graph.microsoft.com/beta/deviceAppManagement/windowsInformationProtectionPolicies"
        $policies = Invoke-MgGraphRequest -Uri $uri -Method GET
        
        if ($null -eq $policies -or $null -eq $policies.value) {
            Write-Log "No WIP policies found" -Level Warning
            return $null
        }
        
        # Filter by policy name if specified
        if (-not [string]::IsNullOrEmpty($PolicyName)) {
            $filteredPolicies = $policies.value | Where-Object { $_.displayName -eq $PolicyName }
            
            if ($null -eq $filteredPolicies -or $filteredPolicies.Count -eq 0) {
                Write-Log "No WIP policy found with name: $PolicyName" -Level Warning
                return $null
            }
            
            return $filteredPolicies
        }
        
        Write-Log "Retrieved $($policies.value.Count) WIP policies"
        return $policies.value
    }
    catch {
        Write-Log "Error retrieving WIP policies: $_" -Level Error
        return $null
    }
}

function Create-WIPPolicy {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$PolicyName,
        
        [Parameter(Mandatory = $true)]
        [string]$EnforcementLevel,
        
        [Parameter(Mandatory = $false)]
        [string[]]$ProtectedApps = @(),
        
        [Parameter(Mandatory = $false)]
        [string[]]$ExemptApps = @(),
        
        [Parameter(Mandatory = $false)]
        [string[]]$ProtectedDomains = @(),
        
        [Parameter(Mandatory = $false)]
        [string[]]$ProtectedNetworkLocations = @(),
        
        [Parameter(Mandatory = $false)]
        [string]$DataRecoveryCertificate = "",
        
        [Parameter(Mandatory = $false)]
        [string[]]$TargetGroups = @()
    )
    
    try {
        Write-Log "Creating WIP policy: $PolicyName..."
        
        # Check if policy already exists
        $existingPolicies = Get-WIPPolicies -PolicyName $PolicyName
        
        if ($null -ne $existingPolicies) {
            Write-Log "WIP policy already exists with name: $PolicyName" -Level Warning
            return $null
        }
        
        # Map enforcement level
        $enforcementValue = switch ($EnforcementLevel) {
            "Off" { "noProtection" }
            "Silent" { "silent" }
            "Override" { "override" }
            "Block" { "block" }
            default { "noProtection" }
        }
        
        # Prepare protected apps
        $protectedAppsList = @()
        foreach ($app in $ProtectedApps) {
            if ($app -match "^[A-Za-z0-9]+\.[A-Za-z0-9\.]+_[a-z0-9]{13}$") {
                # App is a package family name
                $protectedAppsList += @{
                    "packageFamilyName" = $app
                    "denied" = $false
                }
            }
            else {
                # App is a file path
                $protectedAppsList += @{
                    "path" = $app
                    "denied" = $false
                }
            }
        }
        
        # Prepare exempt apps
        $exemptAppsList = @()
        foreach ($app in $ExemptApps) {
            if ($app -match "^[A-Za-z0-9]+\.[A-Za-z0-9\.]+_[a-z0-9]{13}$") {
                # App is a package family name
                $exemptAppsList += @{
                    "packageFamilyName" = $app
                    "denied" = $false
                }
            }
            else {
                # App is a file path
                $exemptAppsList += @{
                    "path" = $app
                    "denied" = $false
                }
            }
        }
        
        # Prepare protected domains
        $protectedDomainsList = @()
        foreach ($domain in $ProtectedDomains) {
            $protectedDomainsList += @{
                "domain" = $domain
                "type" = "enterprise"
            }
        }
        
        # Prepare protected network locations
        $protectedNetworksList = @()
        foreach ($network in $ProtectedNetworkLocations) {
            $protectedNetworksList += @{
                "ipAddressOrFQDN" = $network
                "type" = "enterprise"
            }
        }
        
        # Prepare data recovery certificate
        $dataRecoveryCert = $null
        if (-not [string]::IsNullOrEmpty($DataRecoveryCertificate)) {
            $dataRecoveryCert = @{
                "base64EncodedCertificate" = $DataRecoveryCertificate
                "subjectName" = "Data Recovery Certificate"
            }
        }
        
        # Prepare target groups
        $assignments = @()
        foreach ($groupId in $TargetGroups) {
            $assignments += @{
                "target" = @{
                    "@odata.type" = "#microsoft.graph.groupAssignmentTarget"
                    "groupId" = $groupId
                }
            }
        }
        
        # Create policy body
        $policyBody = @{
            "@odata.type" = "#microsoft.graph.windowsInformationProtectionPolicy"
            "displayName" = $PolicyName
            "description" = "WIP policy created via PowerShell"
            "enforcementLevel" = $enforcementValue
            "enterpriseDomain" = $ProtectedDomains -join ","
            "protectedApps" = $protectedAppsList
            "exemptApps" = $exemptAppsList
            "enterpriseProtectedDomainNames" = $protectedDomainsList
            "enterpriseNetworkDomainNames" = $protectedNetworksList
            "enterpriseIPRanges" = @()
            "enterpriseIPRangesAreAuthoritative" = $false
            "enterpriseProxyServers" = @()
            "enterpriseInternalProxyServers" = @()
            "enterpriseProxyServersAreAuthoritative" = $false
            "neutralDomainResources" = @()
            "iconsVisible" = $true
            "protectionUnderLockConfigRequired" = $true
            "dataRecoveryCertificate" = $dataRecoveryCert
            "revokeOnUnenrollDisabled" = $false
            "rightsManagementServicesTemplateId" = $null
            "azureRightsManagementServicesAllowed" = $true
            "assignments" = $assignments
        }
        
        # Create policy
        $uri = "https://graph.microsoft.com/beta/deviceAppManagement/windowsInformationProtectionPolicies"
        $policy = Invoke-MgGraphRequest -Uri $uri -Method POST -Body ($policyBody | ConvertTo-Json -Depth 10)
        
        Write-Log "WIP policy created successfully: $PolicyName"
        return $policy
    }
    catch {
        Write-Log "Error creating WIP policy: $_" -Level Error
        return $null
    }
}

function Update-WIPPolicy {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$PolicyName,
        
        [Parameter(Mandatory = $false)]
        [string]$EnforcementLevel = "",
        
        [Parameter(Mandatory = $false)]
        [string[]]$ProtectedApps = @(),
        
        [Parameter(Mandatory = $false)]
        [string[]]$ExemptApps = @(),
        
        [Parameter(Mandatory = $false)]
        [string[]]$ProtectedDomains = @(),
        
        [Parameter(Mandatory = $false)]
        [string[]]$ProtectedNetworkLocations = @(),
        
        [Parameter(Mandatory = $false)]
        [string]$DataRecoveryCertificate = "",
        
        [Parameter(Mandatory = $false)]
        [string[]]$TargetGroups = @(),
        
        [Parameter(Mandatory = $false)]
        [string[]]$ExcludedGroups = @()
    )
    
    try {
        Write-Log "Updating WIP policy: $PolicyName..."
        
        # Get existing policy
        $existingPolicies = Get-WIPPolicies -PolicyName $PolicyName
        
        if ($null -eq $existingPolicies) {
            Write-Log "WIP policy not found with name: $PolicyName" -Level Warning
            return $null
        }
        
        $existingPolicy = $existingPolicies[0]
        
        # Map enforcement level
        $enforcementValue = $existingPolicy.enforcementLevel
        if (-not [string]::IsNullOrEmpty($EnforcementLevel)) {
            $enforcementValue = switch ($EnforcementLevel) {
                "Off" { "noProtection" }
                "Silent" { "silent" }
                "Override" { "override" }
                "Block" { "block" }
                default { $existingPolicy.enforcementLevel }
            }
        }
        
        # Prepare protected apps
        $protectedAppsList = $existingPolicy.protectedApps
        if ($ProtectedApps.Count -gt 0) {
            $protectedAppsList = @()
            foreach ($app in $ProtectedApps) {
                if ($app -match "^[A-Za-z0-9]+\.[A-Za-z0-9\.]+_[a-z0-9]{13}$") {
                    # App is a package family name
                    $protectedAppsList += @{
                        "packageFamilyName" = $app
                        "denied" = $false
                    }
                }
                else {
                    # App is a file path
                    $protectedAppsList += @{
                        "path" = $app
                        "denied" = $false
                    }
                }
            }
        }
        
        # Prepare exempt apps
        $exemptAppsList = $existingPolicy.exemptApps
        if ($ExemptApps.Count -gt 0) {
            $exemptAppsList = @()
            foreach ($app in $ExemptApps) {
                if ($app -match "^[A-Za-z0-9]+\.[A-Za-z0-9\.]+_[a-z0-9]{13}$") {
                    # App is a package family name
                    $exemptAppsList += @{
                        "packageFamilyName" = $app
                        "denied" = $false
                    }
                }
                else {
                    # App is a file path
                    $exemptAppsList += @{
                        "path" = $app
                        "denied" = $false
                    }
                }
            }
        }
        
        # Prepare protected domains
        $protectedDomainsList = $existingPolicy.enterpriseProtectedDomainNames
        if ($ProtectedDomains.Count -gt 0) {
            $protectedDomainsList = @()
            foreach ($domain in $ProtectedDomains) {
                $protectedDomainsList += @{
                    "domain" = $domain
                    "type" = "enterprise"
                }
            }
        }
        
        # Prepare protected network locations
        $protectedNetworksList = $existingPolicy.enterpriseNetworkDomainNames
        if ($ProtectedNetworkLocations.Count -gt 0) {
            $protectedNetworksList = @()
            foreach ($network in $ProtectedNetworkLocations) {
                $protectedNetworksList += @{
                    "ipAddressOrFQDN" = $network
                    "type" = "enterprise"
                }
            }
        }
        
        # Prepare data recovery certificate
        $dataRecoveryCert = $existingPolicy.dataRecoveryCertificate
        if (-not [string]::IsNullOrEmpty($DataRecoveryCertificate)) {
            $dataRecoveryCert = @{
                "base64EncodedCertificate" = $DataRecoveryCertificate
                "subjectName" = "Data Recovery Certificate"
            }
        }
        
        # Prepare assignments
        $assignments = $existingPolicy.assignments
        if ($TargetGroups.Count -gt 0 -or $ExcludedGroups.Count -gt 0) {
            $assignments = @()
            
            # Add target groups
            foreach ($groupId in $TargetGroups) {
                $assignments += @{
                    "target" = @{
                        "@odata.type" = "#microsoft.graph.groupAssignmentTarget"
                        "groupId" = $groupId
                    }
                }
            }
            
            # Add excluded groups
            foreach ($groupId in $ExcludedGroups) {
                $assignments += @{
                    "target" = @{
                        "@odata.type" = "#microsoft.graph.exclusionGroupAssignmentTarget"
                        "groupId" = $groupId
                    }
                }
            }
        }
        
        # Update policy body
        $policyBody = @{
            "@odata.type" = "#microsoft.graph.windowsInformationProtectionPolicy"
            "displayName" = $PolicyName
            "description" = "WIP policy updated via PowerShell"
            "enforcementLevel" = $enforcementValue
            "enterpriseDomain" = $ProtectedDomains -join ","
            "protectedApps" = $protectedAppsList
            "exemptApps" = $exemptAppsList
            "enterpriseProtectedDomainNames" = $protectedDomainsList
            "enterpriseNetworkDomainNames" = $protectedNetworksList
            "enterpriseIPRanges" = $existingPolicy.enterpriseIPRanges
            "enterpriseIPRangesAreAuthoritative" = $existingPolicy.enterpriseIPRangesAreAuthoritative
            "enterpriseProxyServers" = $existingPolicy.enterpriseProxyServers
            "enterpriseInternalProxyServers" = $existingPolicy.enterpriseInternalProxyServers
            "enterpriseProxyServersAreAuthoritative" = $existingPolicy.enterpriseProxyServersAreAuthoritative
            "neutralDomainResources" = $existingPolicy.neutralDomainResources
            "iconsVisible" = $existingPolicy.iconsVisible
            "protectionUnderLockConfigRequired" = $existingPolicy.protectionUnderLockConfigRequired
            "dataRecoveryCertificate" = $dataRecoveryCert
            "revokeOnUnenrollDisabled" = $existingPolicy.revokeOnUnenrollDisabled
            "rightsManagementServicesTemplateId" = $existingPolicy.rightsManagementServicesTemplateId
            "azureRightsManagementServicesAllowed" = $existingPolicy.azureRightsManagementServicesAllowed
            "assignments" = $assignments
        }
        
        # Update policy
        $uri = "https://graph.microsoft.com/beta/deviceAppManagement/windowsInformationProtectionPolicies/$($existingPolicy.id)"
        $policy = Invoke-MgGraphRequest -Uri $uri -Method PATCH -Body ($policyBody | ConvertTo-Json -Depth 10)
        
        Write-Log "WIP policy updated successfully: $PolicyName"
        return $policy
    }
    catch {
        Write-Log "Error updating WIP policy: $_" -Level Error
        return $null
    }
}

function Remove-WIPPolicy {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$PolicyName
    )
    
    try {
        Write-Log "Removing WIP policy: $PolicyName..."
        
        # Get existing policy
        $existingPolicies = Get-WIPPolicies -PolicyName $PolicyName
        
        if ($null -eq $existingPolicies) {
            Write-Log "WIP policy not found with name: $PolicyName" -Level Warning
            return $false
        }
        
        $existingPolicy = $existingPolicies[0]
        
        # Remove policy
        $uri = "https://graph.microsoft.com/beta/deviceAppManagement/windowsInformationProtectionPolicies/$($existingPolicy.id)"
        Invoke-MgGraphRequest -Uri $uri -Method DELETE
        
        Write-Log "WIP policy removed successfully: $PolicyName"
        return $true
    }
    catch {
        Write-Log "Error removing WIP policy: $_" -Level Error
        return $false
    }
}

function Get-WIPDeviceStatus {
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Retrieving WIP device status..."
        
        # Get WIP device status
        $uri = "https://graph.microsoft.com/beta/deviceManagement/windowsInformationProtectionDeviceStatuses"
        $deviceStatus = Invoke-MgGraphRequest -Uri $uri -Method GET
        
        if ($null -eq $deviceStatus -or $null -eq $deviceStatus.value) {
            Write-Log "No WIP device status found" -Level Warning
            return $null
        }
        
        # Get device details
        $devices = @()
        foreach ($status in $deviceStatus.value) {
            # Get device details
            $deviceUri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$($status.deviceId)"
            $device = Invoke-MgGraphRequest -Uri $deviceUri -Method GET -ErrorAction SilentlyContinue
            
            $deviceName = "Unknown"
            $deviceOwner = "Unknown"
            
            if ($null -ne $device) {
                $deviceName = $device.deviceName
                $deviceOwner = $device.userPrincipalName
            }
            
            $devices += [PSCustomObject]@{
                DeviceId = $status.deviceId
                DeviceName = $deviceName
                UserPrincipalName = $deviceOwner
                LastCheckInDateTime = $status.lastCheckInDateTime
                Status = $status.status
                PolicyName = $status.policyName
                EnforcementLevel = $status.enforcementLevel
                RequiredAppCount = $status.requiredAppCount
                RequiredAppCountOnWindows10InternalBuilds = $status.requiredAppCountOnWindows10InternalBuilds
                RequiredAppCountNotInStoreOnWindows10InternalBuilds = $status.requiredAppCountNotInStoreOnWindows10InternalBuilds
            }
        }
        
        Write-Log "Retrieved WIP status for $($devices.Count) devices"
        return $devices
    }
    catch {
        Write-Log "Error retrieving WIP device status: $_" -Level Error
        return $null
    }
}

function Get-WIPComplianceReport {
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Generating WIP compliance report..."
        
        # Get WIP policies
        $policies = Get-WIPPolicies
        
        if ($null -eq $policies) {
            Write-Log "No WIP policies found" -Level Warning
            return $null
        }
        
        # Get WIP device status
        $deviceStatus = Get-WIPDeviceStatus
        
        if ($null -eq $deviceStatus) {
            Write-Log "No WIP device status found" -Level Warning
            return $null
        }
        
        # Generate compliance report
        $complianceReport = @()
        
        foreach ($policy in $policies) {
            # Get devices with this policy
            $policyDevices = $deviceStatus | Where-Object { $_.PolicyName -eq $policy.displayName }
            
            # Calculate compliance metrics
            $totalDevices = $policyDevices.Count
            $compliantDevices = ($policyDevices | Where-Object { $_.Status -eq "Compliant" }).Count
            $nonCompliantDevices = $totalDevices - $compliantDevices
            $complianceRate = if ($totalDevices -gt 0) { [math]::Round(($compliantDevices / $totalDevices) * 100, 2) } else { 0 }
            
            $complianceReport += [PSCustomObject]@{
                PolicyName = $policy.displayName
                EnforcementLevel = $policy.enforcementLevel
                TotalDevices = $totalDevices
                CompliantDevices = $compliantDevices
                NonCompliantDevices = $nonCompliantDevices
                ComplianceRate = $complianceRate
                LastUpdated = Get-Date
            }
        }
        
        Write-Log "Generated WIP compliance report for $($policies.Count) policies"
        return $complianceReport
    }
    catch {
        Write-Log "Error generating WIP compliance report: $_" -Level Error
        return $null
    }
}

function Get-WIPViolationsReport {
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Generating WIP violations report..."
        
        # Get WIP policies
        $policies = Get-WIPPolicies
        
        if ($null -eq $policies) {
            Write-Log "No WIP policies found" -Level Warning
            return $null
        }
        
        # Get WIP device status
        $deviceStatus = Get-WIPDeviceStatus
        
        if ($null -eq $deviceStatus) {
            Write-Log "No WIP device status found" -Level Warning
            return $null
        }
        
        # Get WIP protection violations
        $uri = "https://graph.microsoft.com/beta/deviceManagement/windowsInformationProtectionNetworkLearningSummaries"
        $violations = Invoke-MgGraphRequest -Uri $uri -Method GET
        
        if ($null -eq $violations -or $null -eq $violations.value) {
            Write-Log "No WIP violations found" -Level Warning
            return $null
        }
        
        # Generate violations report
        $violationsReport = @()
        
        foreach ($violation in $violations.value) {
            $violationsReport += [PSCustomObject]@{
                URL = $violation.url
                DeviceCount = $violation.deviceCount
                ProcessCount = $violation.processCount
                LastSeenDateTime = $violation.lastSeenDateTime
                ProcessNames = $violation.processNames -join ", "
            }
        }
        
        Write-Log "Generated WIP violations report with $($violationsReport.Count) entries"
        return $violationsReport
    }
    catch {
        Write-Log "Error generating WIP violations report: $_" -Level Error
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
                $Data | Export-Excel -Path $ExportPath -AutoSize -TableName "WIPReport" -WorksheetName "WIP Report"
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
    Write-Log "Script started with parameters: Action=$Action"
    
    # Connect to Microsoft Graph
    $connectedToGraph = Connect-ToMicrosoftGraph
    if (-not $connectedToGraph) {
        Write-Log "Cannot proceed without Microsoft Graph connection" -Level Error
        exit 1
    }
    
    # Process based on action
    switch ($Action) {
        "Get" {
            # Get WIP policies
            $policies = Get-WIPPolicies -PolicyName $PolicyName
            
            if ($null -ne $policies) {
                Write-Output "WIP Policies:"
                $policies | Format-Table -Property displayName, enforcementLevel
                
                # Export report if path is specified
                if (-not [string]::IsNullOrEmpty($ExportPath)) {
                    $exportResult = Export-Report -Data $policies -ExportPath $ExportPath -ExportFormat $ExportFormat
                    
                    if ($exportResult) {
                        Write-Output "WIP policies exported to: $ExportPath"
                    }
                }
            }
            else {
                Write-Output "No WIP policies found"
            }
        }
        "Create" {
            # Validate required parameters
            if ([string]::IsNullOrEmpty($PolicyName)) {
                Write-Log "PolicyName parameter is required for Create action" -Level Error
                exit 1
            }
            
            if ([string]::IsNullOrEmpty($EnforcementLevel)) {
                Write-Log "EnforcementLevel parameter is required for Create action" -Level Error
                exit 1
            }
            
            if ($ProtectedDomains.Count -eq 0) {
                Write-Log "ProtectedDomains parameter is required for Create action" -Level Error
                exit 1
            }
            
            # Create WIP policy
            $policy = Create-WIPPolicy -PolicyName $PolicyName -EnforcementLevel $EnforcementLevel -ProtectedApps $ProtectedApps -ExemptApps $ExemptApps -ProtectedDomains $ProtectedDomains -ProtectedNetworkLocations $ProtectedNetworkLocations -DataRecoveryCertificate $DataRecoveryCertificate -TargetGroups $TargetGroups
            
            if ($null -ne $policy) {
                Write-Output "WIP policy created successfully: $PolicyName"
            }
            else {
                Write-Output "Failed to create WIP policy"
                exit 1
            }
        }
        "Update" {
            # Validate required parameters
            if ([string]::IsNullOrEmpty($PolicyName)) {
                Write-Log "PolicyName parameter is required for Update action" -Level Error
                exit 1
            }
            
            # Update WIP policy
            $policy = Update-WIPPolicy -PolicyName $PolicyName -EnforcementLevel $EnforcementLevel -ProtectedApps $ProtectedApps -ExemptApps $ExemptApps -ProtectedDomains $ProtectedDomains -ProtectedNetworkLocations $ProtectedNetworkLocations -DataRecoveryCertificate $DataRecoveryCertificate -TargetGroups $TargetGroups -ExcludedGroups $ExcludedGroups
            
            if ($null -ne $policy) {
                Write-Output "WIP policy updated successfully: $PolicyName"
            }
            else {
                Write-Output "Failed to update WIP policy"
                exit 1
            }
        }
        "Remove" {
            # Validate required parameters
            if ([string]::IsNullOrEmpty($PolicyName)) {
                Write-Log "PolicyName parameter is required for Remove action" -Level Error
                exit 1
            }
            
            # Remove WIP policy
            $result = Remove-WIPPolicy -PolicyName $PolicyName
            
            if ($result) {
                Write-Output "WIP policy removed successfully: $PolicyName"
            }
            else {
                Write-Output "Failed to remove WIP policy"
                exit 1
            }
        }
        "Report" {
            if ([string]::IsNullOrEmpty($ReportType)) {
                Write-Log "ReportType parameter is required for Report action" -Level Error
                exit 1
            }
            
            switch ($ReportType) {
                "Status" {
                    $deviceStatus = Get-WIPDeviceStatus
                    
                    if ($null -ne $deviceStatus) {
                        Write-Output "WIP Device Status:"
                        $deviceStatus | Format-Table -Property DeviceName, UserPrincipalName, Status, PolicyName, EnforcementLevel
                        
                        # Export report if path is specified
                        if (-not [string]::IsNullOrEmpty($ExportPath)) {
                            $exportResult = Export-Report -Data $deviceStatus -ExportPath $ExportPath -ExportFormat $ExportFormat
                            
                            if ($exportResult) {
                                Write-Output "WIP device status report exported to: $ExportPath"
                            }
                        }
                    }
                    else {
                        Write-Output "No WIP device status found"
                    }
                }
                "Compliance" {
                    $complianceReport = Get-WIPComplianceReport
                    
                    if ($null -ne $complianceReport) {
                        Write-Output "WIP Compliance Report:"
                        $complianceReport | Format-Table -Property PolicyName, EnforcementLevel, TotalDevices, CompliantDevices, NonCompliantDevices, ComplianceRate
                        
                        # Export report if path is specified
                        if (-not [string]::IsNullOrEmpty($ExportPath)) {
                            $exportResult = Export-Report -Data $complianceReport -ExportPath $ExportPath -ExportFormat $ExportFormat
                            
                            if ($exportResult) {
                                Write-Output "WIP compliance report exported to: $ExportPath"
                            }
                        }
                    }
                    else {
                        Write-Output "Failed to generate WIP compliance report"
                    }
                }
                "Violations" {
                    $violationsReport = Get-WIPViolationsReport
                    
                    if ($null -ne $violationsReport) {
                        Write-Output "WIP Violations Report:"
                        $violationsReport | Format-Table -Property URL, DeviceCount, ProcessCount, LastSeenDateTime
                        
                        # Export report if path is specified
                        if (-not [string]::IsNullOrEmpty($ExportPath)) {
                            $exportResult = Export-Report -Data $violationsReport -ExportPath $ExportPath -ExportFormat $ExportFormat
                            
                            if ($exportResult) {
                                Write-Output "WIP violations report exported to: $ExportPath"
                            }
                        }
                    }
                    else {
                        Write-Output "Failed to generate WIP violations report"
                    }
                }
            }
        }
    }
    
    # Output success message
    Write-Output "Windows Information Protection management operation completed successfully"
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
