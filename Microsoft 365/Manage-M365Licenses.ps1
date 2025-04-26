<#
.SYNOPSIS
    Manages Microsoft 365 licenses for users and groups.

.DESCRIPTION
    This script manages Microsoft 365 licenses for users and groups, including
    assigning, removing, and reporting on license usage and availability.
    It supports various license operations and detailed reporting.

.PARAMETER Action
    The action to perform (Get, Assign, Remove, Report).

.PARAMETER UserPrincipalNames
    Array of user principal names to perform the action on.

.PARAMETER GroupIds
    Array of group IDs to perform the action on.

.PARAMETER LicenseSkuIds
    Array of license SKU IDs to assign or remove.

.PARAMETER DisabledPlans
    Array of service plan IDs to disable when assigning licenses.

.PARAMETER ReportType
    The type of report to generate (Usage, Availability, UserLicenses, GroupLicenses).

.PARAMETER ExportPath
    The path where the license report will be saved.

.PARAMETER ExportFormat
    The format of the export file (CSV, JSON, Excel).

.PARAMETER LogPath
    Path where logs will be stored. Defaults to Windows log directory.

.EXAMPLE
    .\Manage-M365Licenses.ps1 -Action Get -ReportType Availability
    Retrieves and displays available licenses in the tenant.

.EXAMPLE
    .\Manage-M365Licenses.ps1 -Action Assign -UserPrincipalNames @("user@contoso.com") -LicenseSkuIds @("contoso:ENTERPRISEPACK")
    Assigns Office 365 E3 license to the specified user.

.EXAMPLE
    .\Manage-M365Licenses.ps1 -Action Report -ReportType Usage -ExportPath "C:\Reports\LicenseUsage.csv" -ExportFormat CSV
    Generates a license usage report and exports it to CSV format.

.NOTES
    Author: Michael Witzsche
    Date: April 26, 2025
    Version: 1.1
#>

#Requires -Modules Microsoft.Graph.Users, Microsoft.Graph.Groups, Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.Authentication, ImportExcel

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$LogPath = "$env:SystemRoot\Logs\Manage-M365Licenses",
    
    [Parameter(Mandatory = $true)]
    [ValidateSet("Get", "Assign", "Remove", "Report")]
    [string]$Action,
    
    [Parameter(Mandatory = $false)]
    [string[]]$UserPrincipalNames = @(),
    
    [Parameter(Mandatory = $false)]
    [string[]]$GroupIds = @(),
    
    [Parameter(Mandatory = $false)]
    [string[]]$LicenseSkuIds = @(),
    
    [Parameter(Mandatory = $false)]
    [string[]]$DisabledPlans = @(),
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Usage", "Availability", "UserLicenses", "GroupLicenses", "")]
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
            "User.Read.All",
            "User.ReadWrite.All",
            "Directory.Read.All",
            "Directory.ReadWrite.All",
            "Group.Read.All",
            "Group.ReadWrite.All",
            "Organization.Read.All"
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

function Get-SubscribedSkus {
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Retrieving subscribed SKUs..."
        
        # Get subscribed SKUs
        $skus = Get-MgSubscribedSku -All
        
        Write-Log "Retrieved $($skus.Count) subscribed SKUs"
        return $skus
    }
    catch {
        Write-Log "Error retrieving subscribed SKUs: $_" -Level Error
        return $null
    }
}

function Get-FriendlyLicenseName {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$SkuPartNumber
    )
    
    # Map of SKU part numbers to friendly names
    $licenseMap = @{
        "AAD_PREMIUM" = "Azure AD Premium P1"
        "AAD_PREMIUM_P2" = "Azure AD Premium P2"
        "ADALLOM_S_O365" = "Office 365 Advanced Security Management"
        "ADALLOM_S_STANDALONE" = "Microsoft Cloud App Security"
        "ATP_ENTERPRISE" = "Exchange Online Advanced Threat Protection"
        "CRMPLAN2" = "Dynamics CRM Online Plan 2"
        "CRMSTANDARD" = "Dynamics CRM Online Professional"
        "DESKLESSPACK" = "Office 365 F1"
        "DESKLESSWOFFPACK" = "Office 365 F3"
        "DEVELOPERPACK" = "Office 365 E3 Developer"
        "DYN365_ENTERPRISE_P1" = "Dynamics 365 Customer Engagement Plan"
        "DYN365_ENTERPRISE_PLAN1" = "Dynamics 365 Plan 1"
        "DYN365_ENTERPRISE_SALES" = "Dynamics 365 for Sales"
        "DYN365_ENTERPRISE_TEAM_MEMBERS" = "Dynamics 365 Team Members"
        "DYN365_FINANCIALS_BUSINESS_SKU" = "Dynamics 365 for Financials"
        "ECAL_SERVICES" = "Enterprise Client Access License Services"
        "EMS" = "Enterprise Mobility + Security E3"
        "EMSPREMIUM" = "Enterprise Mobility + Security E5"
        "ENTERPRISEPACK" = "Office 365 E3"
        "ENTERPRISEPREMIUM" = "Office 365 E5"
        "ENTERPRISEPREMIUM_NOPSTNCONF" = "Office 365 E5 without Audio Conferencing"
        "ENTERPRISEWITHSCAL" = "Office 365 E4"
        "FLOW_FREE" = "Microsoft Flow Free"
        "FLOW_P1" = "Microsoft Flow Plan 1"
        "FLOW_P2" = "Microsoft Flow Plan 2"
        "INTUNE_A" = "Intune"
        "MCOEV" = "Microsoft Phone System"
        "MCOSTANDARD" = "Skype for Business Online Standalone Plan 2"
        "MCOMEETADV" = "Microsoft Teams Audio Conferencing"
        "MCOPSTN1" = "Domestic Calling Plan"
        "MCOPSTN2" = "Domestic and International Calling Plan"
        "MCOPSTNPP" = "Communications Credits"
        "MCOSTANDARD" = "Skype for Business Online Plan 2"
        "MCVOICECONF" = "Skype for Business Online Audio Conferencing"
        "MDM_SALES_COLLABORATION" = "Microsoft Dynamics Marketing Sales Collaboration"
        "MS_TEAMS_IW" = "Microsoft Teams"
        "POWER_BI_ADDON" = "Power BI for Office 365 Add-on"
        "POWER_BI_PRO" = "Power BI Pro"
        "POWER_BI_STANDARD" = "Power BI (free)"
        "POWERAPPS_INDIVIDUAL_USER" = "Microsoft PowerApps Plan 1"
        "POWERAPPS_VIRAL" = "Microsoft PowerApps Plan 2"
        "PROJECTCLIENT" = "Project for Office 365"
        "PROJECTESSENTIALS" = "Project Online Essentials"
        "PROJECTONLINE_PLAN_1" = "Project Online Plan 1"
        "PROJECTONLINE_PLAN_2" = "Project Online Plan 2"
        "PROJECTPREMIUM" = "Project Online Premium"
        "PROJECTPROFESSIONAL" = "Project Online Professional"
        "RIGHTSMANAGEMENT" = "Azure Information Protection Plan 1"
        "RIGHTSMANAGEMENT_ADHOC" = "Rights Management Adhoc"
        "SPB" = "Microsoft 365 Business"
        "SPE_E3" = "Microsoft 365 E3"
        "SPE_E5" = "Microsoft 365 E5"
        "SPE_F1" = "Microsoft 365 F1"
        "SPZA_IW" = "App Connect"
        "STANDARDPACK" = "Office 365 E1"
        "STANDARDWOFFPACK" = "Office 365 E2"
        "STREAM" = "Microsoft Stream"
        "VISIOCLIENT" = "Visio for Office 365"
        "VISIOONLINE_PLAN1" = "Visio Online Plan 1"
        "VISIOONLINE_PLAN2" = "Visio Online Plan 2"
        "WIN10_VDA_E3" = "Windows 10 Enterprise E3"
        "WIN10_VDA_E5" = "Windows 10 Enterprise E5"
    }
    
    if ($licenseMap.ContainsKey($SkuPartNumber)) {
        return $licenseMap[$SkuPartNumber]
    }
    else {
        return $SkuPartNumber
    }
}

function Get-LicenseAvailability {
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Retrieving license availability..."
        
        # Get subscribed SKUs
        $skus = Get-SubscribedSkus
        
        if ($null -eq $skus) {
            Write-Log "Failed to retrieve subscribed SKUs" -Level Error
            return $null
        }
        
        # Create license availability report
        $licenseReport = @()
        
        foreach ($sku in $skus) {
            $friendlyName = Get-FriendlyLicenseName -SkuPartNumber $sku.SkuPartNumber
            
            $licenseReport += [PSCustomObject]@{
                SkuId = $sku.SkuId
                SkuPartNumber = $sku.SkuPartNumber
                FriendlyName = $friendlyName
                Total = $sku.PrepaidUnits.Enabled
                Assigned = $sku.ConsumedUnits
                Available = $sku.PrepaidUnits.Enabled - $sku.ConsumedUnits
                PercentUsed = [math]::Round(($sku.ConsumedUnits / $sku.PrepaidUnits.Enabled) * 100, 2)
            }
        }
        
        Write-Log "License availability report generated successfully"
        return $licenseReport
    }
    catch {
        Write-Log "Error retrieving license availability: $_" -Level Error
        return $null
    }
}

function Get-UserLicenses {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string[]]$UserPrincipalNames = @()
    )
    
    try {
        Write-Log "Retrieving user licenses..."
        
        # Get users
        if ($UserPrincipalNames.Count -gt 0) {
            $users = @()
            foreach ($upn in $UserPrincipalNames) {
                $user = Get-MgUser -UserId $upn -Property "id,displayName,userPrincipalName,assignedLicenses"
                $users += $user
            }
        }
        else {
            $users = Get-MgUser -All -Property "id,displayName,userPrincipalName,assignedLicenses"
        }
        
        if ($null -eq $users) {
            Write-Log "Failed to retrieve users" -Level Error
            return $null
        }
        
        # Get subscribed SKUs for friendly names
        $skus = Get-SubscribedSkus
        
        if ($null -eq $skus) {
            Write-Log "Failed to retrieve subscribed SKUs" -Level Error
            return $null
        }
        
        # Create user license report
        $userLicenseReport = @()
        
        foreach ($user in $users) {
            if ($null -ne $user.AssignedLicenses -and $user.AssignedLicenses.Count -gt 0) {
                foreach ($license in $user.AssignedLicenses) {
                    $sku = $skus | Where-Object { $_.SkuId -eq $license.SkuId }
                    
                    if ($null -ne $sku) {
                        $friendlyName = Get-FriendlyLicenseName -SkuPartNumber $sku.SkuPartNumber
                        
                        $userLicenseReport += [PSCustomObject]@{
                            UserId = $user.Id
                            DisplayName = $user.DisplayName
                            UserPrincipalName = $user.UserPrincipalName
                            LicenseSkuId = $license.SkuId
                            LicenseSkuPartNumber = $sku.SkuPartNumber
                            LicenseFriendlyName = $friendlyName
                            DisabledPlans = $license.DisabledPlans -join ","
                        }
                    }
                }
            }
            else {
                $userLicenseReport += [PSCustomObject]@{
                    UserId = $user.Id
                    DisplayName = $user.DisplayName
                    UserPrincipalName = $user.UserPrincipalName
                    LicenseSkuId = ""
                    LicenseSkuPartNumber = ""
                    LicenseFriendlyName = "No License"
                    DisabledPlans = ""
                }
            }
        }
        
        Write-Log "User license report generated successfully"
        return $userLicenseReport
    }
    catch {
        Write-Log "Error retrieving user licenses: $_" -Level Error
        return $null
    }
}

function Get-GroupLicenses {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string[]]$GroupIds = @()
    )
    
    try {
        Write-Log "Retrieving group licenses..."
        
        # Get groups
        if ($GroupIds.Count -gt 0) {
            $groups = @()
            foreach ($groupId in $GroupIds) {
                $group = Get-MgGroup -GroupId $groupId -Property "id,displayName,assignedLicenses"
                $groups += $group
            }
        }
        else {
            $groups = Get-MgGroup -All -Property "id,displayName,assignedLicenses"
        }
        
        if ($null -eq $groups) {
            Write-Log "Failed to retrieve groups" -Level Error
            return $null
        }
        
        # Get subscribed SKUs for friendly names
        $skus = Get-SubscribedSkus
        
        if ($null -eq $skus) {
            Write-Log "Failed to retrieve subscribed SKUs" -Level Error
            return $null
        }
        
        # Create group license report
        $groupLicenseReport = @()
        
        foreach ($group in $groups) {
            if ($null -ne $group.AssignedLicenses -and $group.AssignedLicenses.Count -gt 0) {
                foreach ($license in $group.AssignedLicenses) {
                    $sku = $skus | Where-Object { $_.SkuId -eq $license.SkuId }
                    
                    if ($null -ne $sku) {
                        $friendlyName = Get-FriendlyLicenseName -SkuPartNumber $sku.SkuPartNumber
                        
                        $groupLicenseReport += [PSCustomObject]@{
                            GroupId = $group.Id
                            DisplayName = $group.DisplayName
                            LicenseSkuId = $license.SkuId
                            LicenseSkuPartNumber = $sku.SkuPartNumber
                            LicenseFriendlyName = $friendlyName
                            DisabledPlans = $license.DisabledPlans -join ","
                        }
                    }
                }
            }
        }
        
        Write-Log "Group license report generated successfully"
        return $groupLicenseReport
    }
    catch {
        Write-Log "Error retrieving group licenses: $_" -Level Error
        return $null
    }
}

function Get-LicenseUsage {
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Retrieving license usage..."
        
        # Get license availability
        $licenseAvailability = Get-LicenseAvailability
        
        if ($null -eq $licenseAvailability) {
            Write-Log "Failed to retrieve license availability" -Level Error
            return $null
        }
        
        # Get user licenses
        $userLicenses = Get-UserLicenses
        
        if ($null -eq $userLicenses) {
            Write-Log "Failed to retrieve user licenses" -Level Error
            return $null
        }
        
        # Create license usage report
        $licenseUsageReport = @()
        
        foreach ($license in $licenseAvailability) {
            $usersWithLicense = $userLicenses | Where-Object { $_.LicenseSkuId -eq $license.SkuId }
            $userCount = ($usersWithLicense | Select-Object -Property UserId -Unique).Count
            
            $licenseUsageReport += [PSCustomObject]@{
                SkuId = $license.SkuId
                SkuPartNumber = $license.SkuPartNumber
                FriendlyName = $license.FriendlyName
                Total = $license.Total
                Assigned = $license.Assigned
                Available = $license.Available
                PercentUsed = $license.PercentUsed
                UserCount = $userCount
            }
        }
        
        Write-Log "License usage report generated successfully"
        return $licenseUsageReport
    }
    catch {
        Write-Log "Error retrieving license usage: $_" -Level Error
        return $null
    }
}

function Assign-UserLicenses {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$UserPrincipalNames,
        
        [Parameter(Mandatory = $true)]
        [string[]]$LicenseSkuIds,
        
        [Parameter(Mandatory = $false)]
        [string[]]$DisabledPlans = @()
    )
    
    try {
        Write-Log "Assigning licenses to users..."
        
        # Get subscribed SKUs for validation
        $skus = Get-SubscribedSkus
        
        if ($null -eq $skus) {
            Write-Log "Failed to retrieve subscribed SKUs" -Level Error
            return $false
        }
        
        # Validate license SKU IDs
        foreach ($licenseSkuId in $LicenseSkuIds) {
            $sku = $skus | Where-Object { $_.SkuId -eq $licenseSkuId }
            
            if ($null -eq $sku) {
                Write-Log "Invalid license SKU ID: $licenseSkuId" -Level Error
                return $false
            }
            
            # Check if there are available licenses
            if ($sku.PrepaidUnits.Enabled - $sku.ConsumedUnits -le 0) {
                $friendlyName = Get-FriendlyLicenseName -SkuPartNumber $sku.SkuPartNumber
                Write-Log "No available licenses for $friendlyName ($licenseSkuId)" -Level Error
                return $false
            }
        }
        
        # Assign licenses to users
        foreach ($upn in $UserPrincipalNames) {
            Write-Log "Assigning licenses to user: $upn..."
            
            # Get user
            $user = Get-MgUser -UserId $upn -ErrorAction SilentlyContinue
            
            if ($null -eq $user) {
                Write-Log "User not found: $upn" -Level Warning
                continue
            }
            
            # Get current licenses
            $currentLicenses = @()
            if ($null -ne $user.AssignedLicenses) {
                $currentLicenses = $user.AssignedLicenses
            }
            
            # Create license assignment
            $addLicenses = @()
            foreach ($licenseSkuId in $LicenseSkuIds) {
                $addLicense = @{
                    SkuId = $licenseSkuId
                    DisabledPlans = $DisabledPlans
                }
                
                $addLicenses += $addLicense
            }
            
            # Update user licenses
            $params = @{
                AddLicenses = $addLicenses
                RemoveLicenses = @()
            }
            
            Set-MgUserLicense -UserId $user.Id -BodyParameter $params
            
            Write-Log "Licenses assigned successfully to user: $upn"
        }
        
        return $true
    }
    catch {
        Write-Log "Error assigning licenses to users: $_" -Level Error
        return $false
    }
}

function Assign-GroupLicenses {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$GroupIds,
        
        [Parameter(Mandatory = $true)]
        [string[]]$LicenseSkuIds,
        
        [Parameter(Mandatory = $false)]
        [string[]]$DisabledPlans = @()
    )
    
    try {
        Write-Log "Assigning licenses to groups..."
        
        # Get subscribed SKUs for validation
        $skus = Get-SubscribedSkus
        
        if ($null -eq $skus) {
            Write-Log "Failed to retrieve subscribed SKUs" -Level Error
            return $false
        }
        
        # Validate license SKU IDs
        foreach ($licenseSkuId in $LicenseSkuIds) {
            $sku = $skus | Where-Object { $_.SkuId -eq $licenseSkuId }
            
            if ($null -eq $sku) {
                Write-Log "Invalid license SKU ID: $licenseSkuId" -Level Error
                return $false
            }
            
            # Check if there are available licenses
            if ($sku.PrepaidUnits.Enabled - $sku.ConsumedUnits -le 0) {
                $friendlyName = Get-FriendlyLicenseName -SkuPartNumber $sku.SkuPartNumber
                Write-Log "No available licenses for $friendlyName ($licenseSkuId)" -Level Error
                return $false
            }
        }
        
        # Assign licenses to groups
        foreach ($groupId in $GroupIds) {
            Write-Log "Assigning licenses to group: $groupId..."
            
            # Get group
            $group = Get-MgGroup -GroupId $groupId -ErrorAction SilentlyContinue
            
            if ($null -eq $group) {
                Write-Log "Group not found: $groupId" -Level Warning
                continue
            }
            
            # Get current licenses
            $currentLicenses = @()
            if ($null -ne $group.AssignedLicenses) {
                $currentLicenses = $group.AssignedLicenses
            }
            
            # Create license assignment
            $addLicenses = @()
            foreach ($licenseSkuId in $LicenseSkuIds) {
                $addLicense = @{
                    SkuId = $licenseSkuId
                    DisabledPlans = $DisabledPlans
                }
                
                $addLicenses += $addLicense
            }
            
            # Update group licenses
            $params = @{
                AddLicenses = $addLicenses
                RemoveLicenses = @()
            }
            
            Set-MgGroupLicense -GroupId $group.Id -BodyParameter $params
            
            Write-Log "Licenses assigned successfully to group: $($group.DisplayName)"
        }
        
        return $true
    }
    catch {
        Write-Log "Error assigning licenses to groups: $_" -Level Error
        return $false
    }
}

function Remove-UserLicenses {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$UserPrincipalNames,
        
        [Parameter(Mandatory = $true)]
        [string[]]$LicenseSkuIds
    )
    
    try {
        Write-Log "Removing licenses from users..."
        
        # Remove licenses from users
        foreach ($upn in $UserPrincipalNames) {
            Write-Log "Removing licenses from user: $upn..."
            
            # Get user
            $user = Get-MgUser -UserId $upn -ErrorAction SilentlyContinue
            
            if ($null -eq $user) {
                Write-Log "User not found: $upn" -Level Warning
                continue
            }
            
            # Update user licenses
            $params = @{
                AddLicenses = @()
                RemoveLicenses = $LicenseSkuIds
            }
            
            Set-MgUserLicense -UserId $user.Id -BodyParameter $params
            
            Write-Log "Licenses removed successfully from user: $upn"
        }
        
        return $true
    }
    catch {
        Write-Log "Error removing licenses from users: $_" -Level Error
        return $false
    }
}

function Remove-GroupLicenses {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$GroupIds,
        
        [Parameter(Mandatory = $true)]
        [string[]]$LicenseSkuIds
    )
    
    try {
        Write-Log "Removing licenses from groups..."
        
        # Remove licenses from groups
        foreach ($groupId in $GroupIds) {
            Write-Log "Removing licenses from group: $groupId..."
            
            # Get group
            $group = Get-MgGroup -GroupId $groupId -ErrorAction SilentlyContinue
            
            if ($null -eq $group) {
                Write-Log "Group not found: $groupId" -Level Warning
                continue
            }
            
            # Update group licenses
            $params = @{
                AddLicenses = @()
                RemoveLicenses = $LicenseSkuIds
            }
            
            Set-MgGroupLicense -GroupId $group.Id -BodyParameter $params
            
            Write-Log "Licenses removed successfully from group: $($group.DisplayName)"
        }
        
        return $true
    }
    catch {
        Write-Log "Error removing licenses from groups: $_" -Level Error
        return $false
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
                $Data | Export-Excel -Path $ExportPath -AutoSize -TableName "LicenseReport" -WorksheetName "License Report"
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
            switch ($ReportType) {
                "Availability" {
                    $licenseAvailability = Get-LicenseAvailability
                    
                    if ($null -ne $licenseAvailability) {
                        Write-Output "License Availability:"
                        $licenseAvailability | Format-Table -Property FriendlyName, Total, Assigned, Available, PercentUsed
                        
                        # Export report if path is specified
                        if (-not [string]::IsNullOrEmpty($ExportPath)) {
                            $exportResult = Export-Report -Data $licenseAvailability -ExportPath $ExportPath -ExportFormat $ExportFormat
                            
                            if ($exportResult) {
                                Write-Output "License availability report exported to: $ExportPath"
                            }
                        }
                    }
                    else {
                        Write-Output "Failed to retrieve license availability"
                    }
                }
                "Usage" {
                    $licenseUsage = Get-LicenseUsage
                    
                    if ($null -ne $licenseUsage) {
                        Write-Output "License Usage:"
                        $licenseUsage | Format-Table -Property FriendlyName, Total, Assigned, Available, PercentUsed, UserCount
                        
                        # Export report if path is specified
                        if (-not [string]::IsNullOrEmpty($ExportPath)) {
                            $exportResult = Export-Report -Data $licenseUsage -ExportPath $ExportPath -ExportFormat $ExportFormat
                            
                            if ($exportResult) {
                                Write-Output "License usage report exported to: $ExportPath"
                            }
                        }
                    }
                    else {
                        Write-Output "Failed to retrieve license usage"
                    }
                }
                "UserLicenses" {
                    $userLicenses = Get-UserLicenses -UserPrincipalNames $UserPrincipalNames
                    
                    if ($null -ne $userLicenses) {
                        Write-Output "User Licenses:"
                        $userLicenses | Format-Table -Property DisplayName, UserPrincipalName, LicenseFriendlyName
                        
                        # Export report if path is specified
                        if (-not [string]::IsNullOrEmpty($ExportPath)) {
                            $exportResult = Export-Report -Data $userLicenses -ExportPath $ExportPath -ExportFormat $ExportFormat
                            
                            if ($exportResult) {
                                Write-Output "User licenses report exported to: $ExportPath"
                            }
                        }
                    }
                    else {
                        Write-Output "Failed to retrieve user licenses"
                    }
                }
                "GroupLicenses" {
                    $groupLicenses = Get-GroupLicenses -GroupIds $GroupIds
                    
                    if ($null -ne $groupLicenses) {
                        Write-Output "Group Licenses:"
                        $groupLicenses | Format-Table -Property DisplayName, LicenseFriendlyName
                        
                        # Export report if path is specified
                        if (-not [string]::IsNullOrEmpty($ExportPath)) {
                            $exportResult = Export-Report -Data $groupLicenses -ExportPath $ExportPath -ExportFormat $ExportFormat
                            
                            if ($exportResult) {
                                Write-Output "Group licenses report exported to: $ExportPath"
                            }
                        }
                    }
                    else {
                        Write-Output "Failed to retrieve group licenses"
                    }
                }
                default {
                    Write-Log "ReportType parameter is required for Get action" -Level Error
                    exit 1
                }
            }
        }
        "Assign" {
            if ($UserPrincipalNames.Count -gt 0) {
                # Assign licenses to users
                $result = Assign-UserLicenses -UserPrincipalNames $UserPrincipalNames -LicenseSkuIds $LicenseSkuIds -DisabledPlans $DisabledPlans
                
                if ($result) {
                    Write-Output "Licenses assigned successfully to users"
                }
                else {
                    Write-Output "Failed to assign licenses to users"
                    exit 1
                }
            }
            elseif ($GroupIds.Count -gt 0) {
                # Assign licenses to groups
                $result = Assign-GroupLicenses -GroupIds $GroupIds -LicenseSkuIds $LicenseSkuIds -DisabledPlans $DisabledPlans
                
                if ($result) {
                    Write-Output "Licenses assigned successfully to groups"
                }
                else {
                    Write-Output "Failed to assign licenses to groups"
                    exit 1
                }
            }
            else {
                Write-Log "Either UserPrincipalNames or GroupIds parameter is required for Assign action" -Level Error
                exit 1
            }
        }
        "Remove" {
            if ($UserPrincipalNames.Count -gt 0) {
                # Remove licenses from users
                $result = Remove-UserLicenses -UserPrincipalNames $UserPrincipalNames -LicenseSkuIds $LicenseSkuIds
                
                if ($result) {
                    Write-Output "Licenses removed successfully from users"
                }
                else {
                    Write-Output "Failed to remove licenses from users"
                    exit 1
                }
            }
            elseif ($GroupIds.Count -gt 0) {
                # Remove licenses from groups
                $result = Remove-GroupLicenses -GroupIds $GroupIds -LicenseSkuIds $LicenseSkuIds
                
                if ($result) {
                    Write-Output "Licenses removed successfully from groups"
                }
                else {
                    Write-Output "Failed to remove licenses from groups"
                    exit 1
                }
            }
            else {
                Write-Log "Either UserPrincipalNames or GroupIds parameter is required for Remove action" -Level Error
                exit 1
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
            
            # Generate and export report
            switch ($ReportType) {
                "Availability" {
                    $licenseAvailability = Get-LicenseAvailability
                    
                    if ($null -ne $licenseAvailability) {
                        $exportResult = Export-Report -Data $licenseAvailability -ExportPath $ExportPath -ExportFormat $ExportFormat
                        
                        if ($exportResult) {
                            Write-Output "License availability report exported to: $ExportPath"
                        }
                        else {
                            Write-Output "Failed to export license availability report"
                            exit 1
                        }
                    }
                    else {
                        Write-Output "Failed to generate license availability report"
                        exit 1
                    }
                }
                "Usage" {
                    $licenseUsage = Get-LicenseUsage
                    
                    if ($null -ne $licenseUsage) {
                        $exportResult = Export-Report -Data $licenseUsage -ExportPath $ExportPath -ExportFormat $ExportFormat
                        
                        if ($exportResult) {
                            Write-Output "License usage report exported to: $ExportPath"
                        }
                        else {
                            Write-Output "Failed to export license usage report"
                            exit 1
                        }
                    }
                    else {
                        Write-Output "Failed to generate license usage report"
                        exit 1
                    }
                }
                "UserLicenses" {
                    $userLicenses = Get-UserLicenses -UserPrincipalNames $UserPrincipalNames
                    
                    if ($null -ne $userLicenses) {
                        $exportResult = Export-Report -Data $userLicenses -ExportPath $ExportPath -ExportFormat $ExportFormat
                        
                        if ($exportResult) {
                            Write-Output "User licenses report exported to: $ExportPath"
                        }
                        else {
                            Write-Output "Failed to export user licenses report"
                            exit 1
                        }
                    }
                    else {
                        Write-Output "Failed to generate user licenses report"
                        exit 1
                    }
                }
                "GroupLicenses" {
                    $groupLicenses = Get-GroupLicenses -GroupIds $GroupIds
                    
                    if ($null -ne $groupLicenses) {
                        $exportResult = Export-Report -Data $groupLicenses -ExportPath $ExportPath -ExportFormat $ExportFormat
                        
                        if ($exportResult) {
                            Write-Output "Group licenses report exported to: $ExportPath"
                        }
                        else {
                            Write-Output "Failed to export group licenses report"
                            exit 1
                        }
                    }
                    else {
                        Write-Output "Failed to generate group licenses report"
                        exit 1
                    }
                }
            }
        }
    }
    
    # Output success message
    Write-Output "Microsoft 365 license management operation completed successfully"
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
