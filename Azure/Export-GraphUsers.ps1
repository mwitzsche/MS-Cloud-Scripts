<#
.SYNOPSIS
    Exports Microsoft 365 user data using Microsoft Graph API.

.DESCRIPTION
    This script exports detailed Microsoft 365 user data using Microsoft Graph API.
    It supports various export options including basic user information, licenses,
    group memberships, roles, and authentication methods.
    Results can be exported to CSV, JSON, or Excel formats.

.PARAMETER ExportOptions
    The user data to export (Basic, Licenses, Groups, Roles, AuthMethods, All).

.PARAMETER OutputFormat
    The format of the export file (CSV, JSON, Excel).

.PARAMETER OutputPath
    The path where the export file will be saved.

.PARAMETER FilterByDepartment
    Filter users by department.

.PARAMETER FilterByJobTitle
    Filter users by job title.

.PARAMETER FilterByLocation
    Filter users by location or office.

.PARAMETER FilterByLicenseType
    Filter users by license type.

.PARAMETER FilterByEnabled
    Filter users by enabled status (Enabled, Disabled, All).

.PARAMETER IncludeGuests
    Whether to include guest users in the export.

.PARAMETER MaxUsers
    Maximum number of users to export. Default is all users.

.PARAMETER LogPath
    Path where logs will be stored. Defaults to Windows log directory.

.EXAMPLE
    .\Export-GraphUsers.ps1 -ExportOptions Basic,Licenses -OutputFormat CSV -OutputPath "C:\Exports\UserExport.csv"
    Exports basic user information and license data to a CSV file.

.EXAMPLE
    .\Export-GraphUsers.ps1 -ExportOptions All -OutputFormat Excel -OutputPath "C:\Exports\UserExport.xlsx" -FilterByDepartment "IT" -FilterByEnabled Enabled
    Exports all user data for enabled users in the IT department to an Excel file.

.NOTES
    Author: Michael Witzsche
    Date: April 26, 2025
    Version: 1.1
#>

#Requires -Modules Microsoft.Graph.Users, Microsoft.Graph.Groups, Microsoft.Graph.Identity.DirectoryManagement, ImportExcel

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$LogPath = "$env:SystemRoot\Logs\Export-GraphUsers",
    
    [Parameter(Mandatory = $true)]
    [ValidateSet("Basic", "Licenses", "Groups", "Roles", "AuthMethods", "All")]
    [string[]]$ExportOptions,
    
    [Parameter(Mandatory = $true)]
    [ValidateSet("CSV", "JSON", "Excel")]
    [string]$OutputFormat,
    
    [Parameter(Mandatory = $true)]
    [string]$OutputPath,
    
    [Parameter(Mandatory = $false)]
    [string]$FilterByDepartment = "",
    
    [Parameter(Mandatory = $false)]
    [string]$FilterByJobTitle = "",
    
    [Parameter(Mandatory = $false)]
    [string]$FilterByLocation = "",
    
    [Parameter(Mandatory = $false)]
    [string]$FilterByLicenseType = "",
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Enabled", "Disabled", "All")]
    [string]$FilterByEnabled = "All",
    
    [Parameter(Mandatory = $false)]
    [bool]$IncludeGuests = $false,
    
    [Parameter(Mandatory = $false)]
    [int]$MaxUsers = 0
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
            $graphUser = Get-MgUser -Top 1 -ErrorAction Stop
            Write-Log "Already connected to Microsoft Graph"
            return $true
        }
        catch {
            # Not connected, proceed with connection
        }
        
        # Connect to Microsoft Graph with required scopes
        Write-Log "Connecting to Microsoft Graph..."
        Connect-MgGraph -Scopes "User.Read.All", "Group.Read.All", "Directory.Read.All", "UserAuthenticationMethod.Read.All" -ErrorAction Stop
        
        # Verify connection
        try {
            $graphUser = Get-MgUser -Top 1 -ErrorAction Stop
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

function Get-FilteredUsers {
    [CmdletBinding()]
    param()
    
    try {
        # Build filter
        $filter = ""
        
        # Filter by enabled status
        if ($FilterByEnabled -eq "Enabled") {
            $filter = "accountEnabled eq true"
        }
        elseif ($FilterByEnabled -eq "Disabled") {
            $filter = "accountEnabled eq false"
        }
        
        # Filter by department
        if (-not [string]::IsNullOrEmpty($FilterByDepartment)) {
            if (-not [string]::IsNullOrEmpty($filter)) {
                $filter += " and "
            }
            $filter += "department eq '$FilterByDepartment'"
        }
        
        # Filter by job title
        if (-not [string]::IsNullOrEmpty($FilterByJobTitle)) {
            if (-not [string]::IsNullOrEmpty($filter)) {
                $filter += " and "
            }
            $filter += "jobTitle eq '$FilterByJobTitle'"
        }
        
        # Filter by location
        if (-not [string]::IsNullOrEmpty($FilterByLocation)) {
            if (-not [string]::IsNullOrEmpty($filter)) {
                $filter += " and "
            }
            $filter += "officeLocation eq '$FilterByLocation'"
        }
        
        # Exclude guest users if specified
        if (-not $IncludeGuests) {
            if (-not [string]::IsNullOrEmpty($filter)) {
                $filter += " and "
            }
            $filter += "userType eq 'Member'"
        }
        
        # Get users with filter
        Write-Log "Retrieving users with filter: $filter"
        
        $params = @{
            All = $true
            Select = @(
                "id", "userPrincipalName", "displayName", "givenName", "surname", 
                "mail", "otherMails", "mobilePhone", "businessPhones", 
                "jobTitle", "department", "officeLocation", "accountEnabled", 
                "userType", "createdDateTime", "assignedLicenses"
            )
        }
        
        if (-not [string]::IsNullOrEmpty($filter)) {
            $params.Filter = $filter
        }
        
        $users = Get-MgUser @params
        
        # Apply license filter if specified
        if (-not [string]::IsNullOrEmpty($FilterByLicenseType)) {
            Write-Log "Filtering users by license type: $FilterByLicenseType"
            
            # Get license SKU ID
            $licenseSkus = Get-MgSubscribedSku
            $targetSku = $licenseSkus | Where-Object { $_.SkuPartNumber -like "*$FilterByLicenseType*" }
            
            if ($null -eq $targetSku) {
                Write-Log "License type not found: $FilterByLicenseType" -Level Warning
                return $users
            }
            
            $targetSkuId = $targetSku.SkuId
            $users = $users | Where-Object { $_.AssignedLicenses.SkuId -contains $targetSkuId }
        }
        
        # Apply max users limit if specified
        if ($MaxUsers -gt 0 -and $users.Count -gt $MaxUsers) {
            Write-Log "Limiting export to $MaxUsers users"
            $users = $users | Select-Object -First $MaxUsers
        }
        
        Write-Log "Retrieved $($users.Count) users"
        return $users
    }
    catch {
        Write-Log "Error retrieving users: $_" -Level Error
        throw $_
    }
}

function Get-UserLicenses {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object[]]$Users
    )
    
    try {
        Write-Log "Retrieving license information for $($Users.Count) users"
        
        # Get all license SKUs
        $licenseSkus = Get-MgSubscribedSku
        
        # Create a lookup table for license SKUs
        $skuLookup = @{}
        foreach ($sku in $licenseSkus) {
            $skuLookup[$sku.SkuId] = $sku.SkuPartNumber
        }
        
        # Create user license information
        $userLicenses = @()
        
        foreach ($user in $Users) {
            $licenses = @()
            
            foreach ($license in $user.AssignedLicenses) {
                $skuName = $skuLookup[$license.SkuId]
                $licenses += $skuName
            }
            
            $userLicenses += [PSCustomObject]@{
                UserId = $user.Id
                UserPrincipalName = $user.UserPrincipalName
                DisplayName = $user.DisplayName
                Licenses = $licenses -join "; "
                LicenseCount = $licenses.Count
            }
        }
        
        Write-Log "License information retrieved successfully"
        return $userLicenses
    }
    catch {
        Write-Log "Error retrieving user licenses: $_" -Level Error
        throw $_
    }
}

function Get-UserGroups {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object[]]$Users
    )
    
    try {
        Write-Log "Retrieving group memberships for $($Users.Count) users"
        
        # Create user group information
        $userGroups = @()
        
        foreach ($user in $Users) {
            Write-Log "Getting groups for user: $($user.UserPrincipalName)" -Level Information
            
            $groups = Get-MgUserMemberOf -UserId $user.Id
            $groupNames = @()
            
            foreach ($group in $groups) {
                if ($group.AdditionalProperties.ContainsKey('displayName')) {
                    $groupNames += $group.AdditionalProperties['displayName']
                }
            }
            
            $userGroups += [PSCustomObject]@{
                UserId = $user.Id
                UserPrincipalName = $user.UserPrincipalName
                DisplayName = $user.DisplayName
                Groups = $groupNames -join "; "
                GroupCount = $groupNames.Count
            }
        }
        
        Write-Log "Group memberships retrieved successfully"
        return $userGroups
    }
    catch {
        Write-Log "Error retrieving user groups: $_" -Level Error
        throw $_
    }
}

function Get-UserRoles {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object[]]$Users
    )
    
    try {
        Write-Log "Retrieving directory roles for $($Users.Count) users"
        
        # Create user role information
        $userRoles = @()
        
        foreach ($user in $Users) {
            Write-Log "Getting roles for user: $($user.UserPrincipalName)" -Level Information
            
            $roles = @()
            $userMemberOf = Get-MgUserMemberOf -UserId $user.Id
            
            foreach ($membership in $userMemberOf) {
                if ($membership.AdditionalProperties.ContainsKey('@odata.type') -and 
                    $membership.AdditionalProperties['@odata.type'] -eq '#microsoft.graph.directoryRole') {
                    $roles += $membership.AdditionalProperties['displayName']
                }
            }
            
            $userRoles += [PSCustomObject]@{
                UserId = $user.Id
                UserPrincipalName = $user.UserPrincipalName
                DisplayName = $user.DisplayName
                Roles = $roles -join "; "
                RoleCount = $roles.Count
            }
        }
        
        Write-Log "Directory roles retrieved successfully"
        return $userRoles
    }
    catch {
        Write-Log "Error retrieving user roles: $_" -Level Error
        throw $_
    }
}

function Get-UserAuthMethods {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object[]]$Users
    )
    
    try {
        Write-Log "Retrieving authentication methods for $($Users.Count) users"
        
        # Create user authentication method information
        $userAuthMethods = @()
        
        foreach ($user in $Users) {
            Write-Log "Getting authentication methods for user: $($user.UserPrincipalName)" -Level Information
            
            $methods = @()
            
            # Get authentication methods
            $authMethods = Get-MgUserAuthenticationMethod -UserId $user.Id
            
            foreach ($method in $authMethods) {
                $methodType = $method.AdditionalProperties['@odata.type']
                
                switch -Wildcard ($methodType) {
                    "*microsoftAuthenticatorAuthenticationMethod" { $methods += "Microsoft Authenticator" }
                    "*phoneAuthenticationMethod" { $methods += "Phone" }
                    "*passwordAuthenticationMethod" { $methods += "Password" }
                    "*fido2AuthenticationMethod" { $methods += "FIDO2 Security Key" }
                    "*windowsHelloForBusinessAuthenticationMethod" { $methods += "Windows Hello" }
                    "*emailAuthenticationMethod" { $methods += "Email" }
                    "*temporaryAccessPassAuthenticationMethod" { $methods += "Temporary Access Pass" }
                    "*softwareOathAuthenticationMethod" { $methods += "Software OATH Token" }
                    default { $methods += $methodType }
                }
            }
            
            $userAuthMethods += [PSCustomObject]@{
                UserId = $user.Id
                UserPrincipalName = $user.UserPrincipalName
                DisplayName = $user.DisplayName
                AuthenticationMethods = $methods -join "; "
                MethodCount = $methods.Count
                MFAEnabled = $methods.Count -gt 1 -or ($methods.Count -eq 1 -and $methods[0] -ne "Password")
            }
        }
        
        Write-Log "Authentication methods retrieved successfully"
        return $userAuthMethods
    }
    catch {
        Write-Log "Error retrieving user authentication methods: $_" -Level Error
        throw $_
    }
}

function Format-UserData {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object[]]$Users,
        
        [Parameter(Mandatory = $false)]
        [object[]]$UserLicenses = $null,
        
        [Parameter(Mandatory = $false)]
        [object[]]$UserGroups = $null,
        
        [Parameter(Mandatory = $false)]
        [object[]]$UserRoles = $null,
        
        [Parameter(Mandatory = $false)]
        [object[]]$UserAuthMethods = $null
    )
    
    try {
        Write-Log "Formatting user data for export"
        
        # Create formatted user data
        $formattedUsers = @()
        
        foreach ($user in $Users) {
            $userData = [ordered]@{
                UserId = $user.Id
                UserPrincipalName = $user.UserPrincipalName
                DisplayName = $user.DisplayName
                FirstName = $user.GivenName
                LastName = $user.Surname
                Email = $user.Mail
                AlternateEmail = ($user.OtherMails -join "; ")
                MobilePhone = $user.MobilePhone
                BusinessPhone = ($user.BusinessPhones -join "; ")
                JobTitle = $user.JobTitle
                Department = $user.Department
                Office = $user.OfficeLocation
                Enabled = $user.AccountEnabled
                UserType = $user.UserType
                CreatedDate = $user.CreatedDateTime
            }
            
            # Add license information if available
            if ($null -ne $UserLicenses) {
                $license = $UserLicenses | Where-Object { $_.UserId -eq $user.Id } | Select-Object -First 1
                if ($null -ne $license) {
                    $userData.Licenses = $license.Licenses
                    $userData.LicenseCount = $license.LicenseCount
                }
            }
            
            # Add group information if available
            if ($null -ne $UserGroups) {
                $group = $UserGroups | Where-Object { $_.UserId -eq $user.Id } | Select-Object -First 1
                if ($null -ne $group) {
                    $userData.Groups = $group.Groups
                    $userData.GroupCount = $group.GroupCount
                }
            }
            
            # Add role information if available
            if ($null -ne $UserRoles) {
                $role = $UserRoles | Where-Object { $_.UserId -eq $user.Id } | Select-Object -First 1
                if ($null -ne $role) {
                    $userData.Roles = $role.Roles
                    $userData.RoleCount = $role.RoleCount
                }
            }
            
            # Add authentication method information if available
            if ($null -ne $UserAuthMethods) {
                $authMethod = $UserAuthMethods | Where-Object { $_.UserId -eq $user.Id } | Select-Object -First 1
                if ($null -ne $authMethod) {
                    $userData.AuthenticationMethods = $authMethod.AuthenticationMethods
                    $userData.MethodCount = $authMethod.MethodCount
                    $userData.MFAEnabled = $authMethod.MFAEnabled
                }
            }
            
            $formattedUsers += [PSCustomObject]$userData
        }
        
        Write-Log "User data formatted successfully"
        return $formattedUsers
    }
    catch {
        Write-Log "Error formatting user data: $_" -Level Error
        throw $_
    }
}

function Export-UserDataToCSV {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object[]]$UserData,
        
        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )
    
    try {
        Write-Log "Exporting user data to CSV: $OutputPath"
        
        # Export to CSV
        $UserData | Export-Csv -Path $OutputPath -NoTypeInformation
        
        Write-Log "User data exported to CSV successfully"
        return $true
    }
    catch {
        Write-Log "Error exporting user data to CSV: $_" -Level Error
        return $false
    }
}

function Export-UserDataToJSON {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object[]]$UserData,
        
        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )
    
    try {
        Write-Log "Exporting user data to JSON: $OutputPath"
        
        # Export to JSON
        $UserData | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath -Encoding utf8
        
        Write-Log "User data exported to JSON successfully"
        return $true
    }
    catch {
        Write-Log "Error exporting user data to JSON: $_" -Level Error
        return $false
    }
}

function Export-UserDataToExcel {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object[]]$UserData,
        
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,
        
        [Parameter(Mandatory = $false)]
        [object[]]$UserLicenses = $null,
        
        [Parameter(Mandatory = $false)]
        [object[]]$UserGroups = $null,
        
        [Parameter(Mandatory = $false)]
        [object[]]$UserRoles = $null,
        
        [Parameter(Mandatory = $false)]
        [object[]]$UserAuthMethods = $null
    )
    
    try {
        Write-Log "Exporting user data to Excel: $OutputPath"
        
        # Create Excel package
        $excelPackage = New-Object OfficeOpenXml.ExcelPackage
        
        # Create Users worksheet
        $usersSheet = $excelPackage.Workbook.Worksheets.Add("Users")
        
        # Add headers
        $headers = $UserData[0].PSObject.Properties.Name
        for ($i = 0; $i -lt $headers.Count; $i++) {
            $usersSheet.Cells[1, $i + 1].Value = $headers[$i]
        }
        
        # Add data
        for ($row = 0; $row -lt $UserData.Count; $row++) {
            for ($col = 0; $col -lt $headers.Count; $col++) {
                $usersSheet.Cells[$row + 2, $col + 1].Value = $UserData[$row].$($headers[$col])
            }
        }
        
        # Add additional worksheets if data is available
        if ($null -ne $UserLicenses) {
            $licenseSheet = $excelPackage.Workbook.Worksheets.Add("Licenses")
            
            # Add headers
            $licenseSheet.Cells["A1"].Value = "UserPrincipalName"
            $licenseSheet.Cells["B1"].Value = "DisplayName"
            $licenseSheet.Cells["C1"].Value = "Licenses"
            $licenseSheet.Cells["D1"].Value = "LicenseCount"
            
            # Add data
            for ($row = 0; $row -lt $UserLicenses.Count; $row++) {
                $licenseSheet.Cells[$row + 2, 1].Value = $UserLicenses[$row].UserPrincipalName
                $licenseSheet.Cells[$row + 2, 2].Value = $UserLicenses[$row].DisplayName
                $licenseSheet.Cells[$row + 2, 3].Value = $UserLicenses[$row].Licenses
                $licenseSheet.Cells[$row + 2, 4].Value = $UserLicenses[$row].LicenseCount
            }
        }
        
        if ($null -ne $UserGroups) {
            $groupSheet = $excelPackage.Workbook.Worksheets.Add("Groups")
            
            # Add headers
            $groupSheet.Cells["A1"].Value = "UserPrincipalName"
            $groupSheet.Cells["B1"].Value = "DisplayName"
            $groupSheet.Cells["C1"].Value = "Groups"
            $groupSheet.Cells["D1"].Value = "GroupCount"
            
            # Add data
            for ($row = 0; $row -lt $UserGroups.Count; $row++) {
                $groupSheet.Cells[$row + 2, 1].Value = $UserGroups[$row].UserPrincipalName
                $groupSheet.Cells[$row + 2, 2].Value = $UserGroups[$row].DisplayName
                $groupSheet.Cells[$row + 2, 3].Value = $UserGroups[$row].Groups
                $groupSheet.Cells[$row + 2, 4].Value = $UserGroups[$row].GroupCount
            }
        }
        
        if ($null -ne $UserRoles) {
            $roleSheet = $excelPackage.Workbook.Worksheets.Add("Roles")
            
            # Add headers
            $roleSheet.Cells["A1"].Value = "UserPrincipalName"
            $roleSheet.Cells["B1"].Value = "DisplayName"
            $roleSheet.Cells["C1"].Value = "Roles"
            $roleSheet.Cells["D1"].Value = "RoleCount"
            
            # Add data
            for ($row = 0; $row -lt $UserRoles.Count; $row++) {
                $roleSheet.Cells[$row + 2, 1].Value = $UserRoles[$row].UserPrincipalName
                $roleSheet.Cells[$row + 2, 2].Value = $UserRoles[$row].DisplayName
                $roleSheet.Cells[$row + 2, 3].Value = $UserRoles[$row].Roles
                $roleSheet.Cells[$row + 2, 4].Value = $UserRoles[$row].RoleCount
            }
        }
        
        if ($null -ne $UserAuthMethods) {
            $authSheet = $excelPackage.Workbook.Worksheets.Add("Authentication")
            
            # Add headers
            $authSheet.Cells["A1"].Value = "UserPrincipalName"
            $authSheet.Cells["B1"].Value = "DisplayName"
            $authSheet.Cells["C1"].Value = "AuthenticationMethods"
            $authSheet.Cells["D1"].Value = "MethodCount"
            $authSheet.Cells["E1"].Value = "MFAEnabled"
            
            # Add data
            for ($row = 0; $row -lt $UserAuthMethods.Count; $row++) {
                $authSheet.Cells[$row + 2, 1].Value = $UserAuthMethods[$row].UserPrincipalName
                $authSheet.Cells[$row + 2, 2].Value = $UserAuthMethods[$row].DisplayName
                $authSheet.Cells[$row + 2, 3].Value = $UserAuthMethods[$row].AuthenticationMethods
                $authSheet.Cells[$row + 2, 4].Value = $UserAuthMethods[$row].MethodCount
                $authSheet.Cells[$row + 2, 5].Value = $UserAuthMethods[$row].MFAEnabled
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
        
        Write-Log "User data exported to Excel successfully"
        return $true
    }
    catch {
        Write-Log "Error exporting user data to Excel: $_" -Level Error
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
    
    # Get users
    $users = Get-FilteredUsers
    
    if ($users.Count -eq 0) {
        Write-Log "No users found matching the specified filters" -Level Warning
        exit 0
    }
    
    # Initialize variables for additional data
    $userLicenses = $null
    $userGroups = $null
    $userRoles = $null
    $userAuthMethods = $null
    
    # Get additional data based on export options
    if ($ExportOptions -contains "All" -or $ExportOptions -contains "Licenses") {
        $userLicenses = Get-UserLicenses -Users $users
    }
    
    if ($ExportOptions -contains "All" -or $ExportOptions -contains "Groups") {
        $userGroups = Get-UserGroups -Users $users
    }
    
    if ($ExportOptions -contains "All" -or $ExportOptions -contains "Roles") {
        $userRoles = Get-UserRoles -Users $users
    }
    
    if ($ExportOptions -contains "All" -or $ExportOptions -contains "AuthMethods") {
        $userAuthMethods = Get-UserAuthMethods -Users $users
    }
    
    # Format user data
    $formattedUsers = Format-UserData -Users $users -UserLicenses $userLicenses -UserGroups $userGroups -UserRoles $userRoles -UserAuthMethods $userAuthMethods
    
    # Export data based on output format
    $exportResult = $false
    
    switch ($OutputFormat) {
        "CSV" {
            $exportResult = Export-UserDataToCSV -UserData $formattedUsers -OutputPath $OutputPath
        }
        "JSON" {
            $exportResult = Export-UserDataToJSON -UserData $formattedUsers -OutputPath $OutputPath
        }
        "Excel" {
            $exportResult = Export-UserDataToExcel -UserData $formattedUsers -OutputPath $OutputPath -UserLicenses $userLicenses -UserGroups $userGroups -UserRoles $userRoles -UserAuthMethods $userAuthMethods
        }
    }
    
    if (-not $exportResult) {
        Write-Log "Failed to export user data" -Level Error
        exit 1
    }
    
    # Output success message
    Write-Output "User data exported successfully to: $OutputPath"
    Write-Output "Total users exported: $($users.Count)"
    
    # Output additional statistics
    if ($null -ne $userLicenses) {
        $licensedUsers = ($userLicenses | Where-Object { $_.LicenseCount -gt 0 }).Count
        Write-Output "Licensed users: $licensedUsers"
    }
    
    if ($null -ne $userAuthMethods) {
        $mfaUsers = ($userAuthMethods | Where-Object { $_.MFAEnabled -eq $true }).Count
        Write-Output "Users with MFA enabled: $mfaUsers"
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
