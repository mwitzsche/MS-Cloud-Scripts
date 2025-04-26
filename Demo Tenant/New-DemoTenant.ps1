<#
.SYNOPSIS
    Creates a fictional company in a new Microsoft 365 trial tenant with departments, users, groups, and license assignments.

.DESCRIPTION
    This script automates the setup of a complete demo environment in a new Microsoft 365 trial tenant.
    It creates organizational departments, fictional users, security groups, and assigns appropriate licenses.
    The script provisions:
    - 15 licenses for Office 365 E5 without Teams
    - 15 trial licenses for Teams Enterprise
    - 15 licenses for Enterprise Mobility + Security E5
    - Departments: IT, Management, HR, Production
    - 15 fictional users distributed across departments
    - Appropriate groups and license assignments

.PARAMETER TenantName
    The name of the fictional company/tenant (e.g., "Contoso")

.PARAMETER TenantDomain
    The domain name for the tenant (e.g., "contoso.onmicrosoft.com")

.PARAMETER GlobalAdminUsername
    The username for the global admin account

.PARAMETER GlobalAdminPassword
    The password for the global admin account

.PARAMETER CountryCode
    The two-letter country code for the tenant and users

.PARAMETER UserPasswordPrefix
    Prefix for generated user passwords (will be combined with a random suffix)

.PARAMETER LogPath
    Path where logs will be stored. Defaults to Windows log directory.

.EXAMPLE
    .\New-DemoTenant.ps1 -TenantName "Contoso" -TenantDomain "contoso.onmicrosoft.com" -GlobalAdminUsername "admin" -GlobalAdminPassword "P@ssw0rd123" -CountryCode "US"
    Creates a new demo tenant for Contoso with the specified admin credentials.

.NOTES
    Author: Michael Witzsche
    Date: April 26, 2025
    Version: 1.0.0
    
    History:
    1.0.0 - Initial release
#>

#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.Users, Microsoft.Graph.Groups, Microsoft.Graph.Users.Actions, Microsoft.Graph.Identity.Governance, Microsoft.Graph.DeviceManagement, AzureAD

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$TenantName,
    
    [Parameter(Mandatory = $true)]
    [string]$TenantDomain,
    
    [Parameter(Mandatory = $true)]
    [string]$GlobalAdminUsername,
    
    [Parameter(Mandatory = $true)]
    [SecureString]$GlobalAdminPassword,
    
    [Parameter(Mandatory = $false)]
    [string]$CountryCode = "US",
    
    [Parameter(Mandatory = $false)]
    [string]$UserPasswordPrefix = "Demo@",
    
    [Parameter(Mandatory = $false)]
    [string]$LogPath = "$env:SystemRoot\Logs\New-DemoTenant"
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
    param (
        [Parameter(Mandatory = $true)]
        [string]$Username,
        
        [Parameter(Mandatory = $true)]
        [SecureString]$Password
    )
    
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
        
        # Create credential object
        $credential = New-Object System.Management.Automation.PSCredential($Username, $Password)
        
        # Connect to Microsoft Graph
        Write-Log "Connecting to Microsoft Graph as $Username..."
        
        # Define required scopes
        $scopes = @(
            "User.ReadWrite.All",
            "Group.ReadWrite.All",
            "Directory.ReadWrite.All",
            "Organization.ReadWrite.All",
            "RoleManagement.ReadWrite.Directory",
            "DeviceManagementApps.ReadWrite.All",
            "DeviceManagementConfiguration.ReadWrite.All",
            "LicenseAssignment.ReadWrite.All"
        )
        
        Connect-MgGraph -Credential $credential -Scopes $scopes -ErrorAction Stop
        
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

function Connect-ToAzureAD {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Username,
        
        [Parameter(Mandatory = $true)]
        [SecureString]$Password
    )
    
    try {
        # Check if already connected
        try {
            $context = Get-AzureADCurrentSessionInfo
            Write-Log "Already connected to Azure AD as $($context.Account)"
            return $true
        }
        catch {
            # Not connected
        }
        
        # Create credential object
        $credential = New-Object System.Management.Automation.PSCredential($Username, $Password)
        
        # Connect to Azure AD
        Write-Log "Connecting to Azure AD as $Username..."
        Connect-AzureAD -Credential $credential -ErrorAction Stop
        
        # Verify connection
        $context = Get-AzureADCurrentSessionInfo
        if ($null -ne $context) {
            Write-Log "Successfully connected to Azure AD as $($context.Account)"
            return $true
        }
        else {
            Write-Log "Failed to verify Azure AD connection" -Level Error
            return $false
        }
    }
    catch {
        Write-Log "Error connecting to Azure AD: $_" -Level Error
        return $false
    }
}

function Get-RandomPassword {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [int]$Length = 8,
        
        [Parameter(Mandatory = $false)]
        [string]$Prefix = ""
    )
    
    # Define character sets
    $lowercase = "abcdefghijklmnopqrstuvwxyz"
    $uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    $numbers = "0123456789"
    $specialChars = "!@#$%^&*()-_=+[]{}|;:,.<>?"
    
    # Ensure at least one character from each set
    $password = $Prefix
    $password += $lowercase[(Get-Random -Maximum $lowercase.Length)]
    $password += $uppercase[(Get-Random -Maximum $uppercase.Length)]
    $password += $numbers[(Get-Random -Maximum $numbers.Length)]
    $password += $specialChars[(Get-Random -Maximum $specialChars.Length)]
    
    # Fill the rest of the password
    $allChars = $lowercase + $uppercase + $numbers + $specialChars
    $remainingLength = $Length - 4
    
    for ($i = 0; $i -lt $remainingLength; $i++) {
        $password += $allChars[(Get-Random -Maximum $allChars.Length)]
    }
    
    # Shuffle the password
    $passwordArray = $password.ToCharArray()
    $shuffledPassword = $passwordArray | Get-Random -Count $passwordArray.Length
    
    return -join $shuffledPassword
}

function New-DemoUser {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$FirstName,
        
        [Parameter(Mandatory = $true)]
        [string]$LastName,
        
        [Parameter(Mandatory = $true)]
        [string]$Department,
        
        [Parameter(Mandatory = $true)]
        [string]$JobTitle,
        
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        
        [Parameter(Mandatory = $true)]
        [string]$Password,
        
        [Parameter(Mandatory = $true)]
        [string]$CountryCode
    )
    
    try {
        # Create UPN and email
        $mailNickname = "$($FirstName.ToLower()).$($LastName.ToLower())"
        $upn = "$mailNickname@$Domain"
        
        # Create password profile
        $passwordProfile = @{
            Password = $Password
            ForceChangePasswordNextSignIn = $false
        }
        
        # Create user
        Write-Log "Creating user: $FirstName $LastName ($upn)..."
        
        $params = @{
            DisplayName = "$FirstName $LastName"
            GivenName = $FirstName
            Surname = $LastName
            UserPrincipalName = $upn
            MailNickname = $mailNickname
            AccountEnabled = $true
            PasswordProfile = $passwordProfile
            Department = $Department
            JobTitle = $JobTitle
            UsageLocation = $CountryCode
        }
        
        $user = New-MgUser -BodyParameter $params
        
        Write-Log "Successfully created user: $FirstName $LastName ($upn) with ID: $($user.Id)"
        
        return $user
    }
    catch {
        Write-Log "Error creating user $FirstName $LastName: $_" -Level Error
        return $null
    }
}

function New-DemoGroup {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$DisplayName,
        
        [Parameter(Mandatory = $true)]
        [string]$Description,
        
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Security", "Microsoft365")]
        [string]$GroupType = "Security",
        
        [Parameter(Mandatory = $false)]
        [bool]$MailEnabled = $false,
        
        [Parameter(Mandatory = $false)]
        [bool]$SecurityEnabled = $true
    )
    
    try {
        # Create mail nickname
        $mailNickname = $DisplayName.Replace(" ", "").ToLower()
        
        # Create group
        Write-Log "Creating group: $DisplayName..."
        
        $params = @{
            DisplayName = $DisplayName
            Description = $Description
            MailNickname = $mailNickname
            MailEnabled = $MailEnabled
            SecurityEnabled = $SecurityEnabled
        }
        
        # Add group type if Microsoft365
        if ($GroupType -eq "Microsoft365") {
            $params.GroupTypes = @("Unified")
            $params.MailEnabled = $true
        }
        
        $group = New-MgGroup -BodyParameter $params
        
        Write-Log "Successfully created group: $DisplayName with ID: $($group.Id)"
        
        return $group
    }
    catch {
        Write-Log "Error creating group $DisplayName: $_" -Level Error
        return $null
    }
}

function Add-UserToGroup {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$UserId,
        
        [Parameter(Mandatory = $true)]
        [string]$GroupId
    )
    
    try {
        # Add user to group
        Write-Log "Adding user $UserId to group $GroupId..."
        
        $params = @{
            "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$UserId"
        }
        
        New-MgGroupMember -GroupId $GroupId -DirectoryObjectId $UserId
        
        Write-Log "Successfully added user $UserId to group $GroupId"
        
        return $true
    }
    catch {
        Write-Log "Error adding user $UserId to group $GroupId: $_" -Level Error
        return $false
    }
}

function Get-LicenseSkuId {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$SkuPartNumber
    )
    
    try {
        # Get available license SKUs
        $skus = Get-MgSubscribedSku
        
        # Find the SKU with the matching part number
        $sku = $skus | Where-Object { $_.SkuPartNumber -eq $SkuPartNumber }
        
        if ($null -eq $sku) {
            Write-Log "License SKU with part number $SkuPartNumber not found" -Level Warning
            return $null
        }
        
        Write-Log "Found license SKU: $SkuPartNumber with ID: $($sku.SkuId)"
        
        return $sku.SkuId
    }
    catch {
        Write-Log "Error getting license SKU ID for $SkuPartNumber: $_" -Level Error
        return $null
    }
}

function Assign-LicenseToUser {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$UserId,
        
        [Parameter(Mandatory = $true)]
        [string]$SkuId,
        
        [Parameter(Mandatory = $false)]
        [string[]]$DisabledPlans = @()
    )
    
    try {
        # Assign license to user
        Write-Log "Assigning license $SkuId to user $UserId..."
        
        # Get current licenses
        $user = Get-MgUser -UserId $UserId -Property AssignedLicenses
        $currentLicenses = $user.AssignedLicenses
        
        # Create new license object
        $license = @{
            SkuId = $SkuId
            DisabledPlans = $DisabledPlans
        }
        
        # Add new license to current licenses
        $licenses = $currentLicenses + $license
        
        # Update user licenses
        Set-MgUserLicense -UserId $UserId -AddLicenses @($license) -RemoveLicenses @()
        
        Write-Log "Successfully assigned license $SkuId to user $UserId"
        
        return $true
    }
    catch {
        Write-Log "Error assigning license $SkuId to user $UserId: $_" -Level Error
        return $false
    }
}

function Get-TeamsServicePlan {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$SkuId
    )
    
    try {
        # Get SKU details
        $sku = Get-MgSubscribedSku -SubscribedSkuId $SkuId
        
        # Find Teams service plan
        $teamsPlans = $sku.ServicePlans | Where-Object { $_.ServicePlanName -like "*TEAMS*" }
        
        if ($null -eq $teamsPlans -or $teamsPlans.Count -eq 0) {
            Write-Log "No Teams service plans found in SKU $SkuId" -Level Warning
            return @()
        }
        
        Write-Log "Found Teams service plans in SKU $SkuId: $($teamsPlans.ServicePlanName -join ', ')"
        
        return $teamsPlans.ServicePlanId
    }
    catch {
        Write-Log "Error getting Teams service plan for SKU $SkuId: $_" -Level Error
        return @()
    }
}
#endregion

#region Main Script
try {
    # Script start
    Write-Log "Script started with parameters: TenantName=$TenantName, TenantDomain=$TenantDomain"
    
    # Connect to Microsoft Graph and Azure AD
    $adminUpn = "$GlobalAdminUsername@$TenantDomain"
    $connectedToGraph = Connect-ToMicrosoftGraph -Username $adminUpn -Password $GlobalAdminPassword
    $connectedToAzureAD = Connect-ToAzureAD -Username $adminUpn -Password $GlobalAdminPassword
    
    if (-not $connectedToGraph -or -not $connectedToAzureAD) {
        Write-Log "Cannot proceed without Microsoft Graph and Azure AD connections" -Level Error
        exit 1
    }
    
    #region Define Demo Data
    # Define departments
    $departments = @(
        @{
            Name = "IT"
            Description = "Information Technology Department"
            Users = 4
        },
        @{
            Name = "Management"
            Description = "Executive Management Team"
            Users = 3
        },
        @{
            Name = "HR"
            Description = "Human Resources Department"
            Users = 3
        },
        @{
            Name = "Production"
            Description = "Production Department"
            Users = 5
        }
    )
    
    # Define fictional users
    $users = @(
        # IT Department
        @{
            FirstName = "John"
            LastName = "Smith"
            Department = "IT"
            JobTitle = "IT Director"
        },
        @{
            FirstName = "Emily"
            LastName = "Johnson"
            Department = "IT"
            JobTitle = "System Administrator"
        },
        @{
            FirstName = "Michael"
            LastName = "Brown"
            Department = "IT"
            JobTitle = "Network Engineer"
        },
        @{
            FirstName = "David"
            LastName = "Wilson"
            Department = "IT"
            JobTitle = "Security Analyst"
        },
        
        # Management Department
        @{
            FirstName = "Sarah"
            LastName = "Davis"
            Department = "Management"
            JobTitle = "CEO"
        },
        @{
            FirstName = "Robert"
            LastName = "Miller"
            Department = "Management"
            JobTitle = "CFO"
        },
        @{
            FirstName = "Jennifer"
            LastName = "Taylor"
            Department = "Management"
            JobTitle = "COO"
        },
        
        # HR Department
        @{
            FirstName = "Lisa"
            LastName = "Anderson"
            Department = "HR"
            JobTitle = "HR Director"
        },
        @{
            FirstName = "Thomas"
            LastName = "Martinez"
            Department = "HR"
            JobTitle = "HR Manager"
        },
        @{
            FirstName = "Jessica"
            LastName = "Garcia"
            Department = "HR"
            JobTitle = "Recruiter"
        },
        
        # Production Department
        @{
            FirstName = "Daniel"
            LastName = "Rodriguez"
            Department = "Production"
            JobTitle = "Production Manager"
        },
        @{
            FirstName = "Christopher"
            LastName = "Lee"
            Department = "Production"
            JobTitle = "Quality Assurance"
        },
        @{
            FirstName = "Matthew"
            LastName = "Walker"
            Department = "Production"
            JobTitle = "Production Supervisor"
        },
        @{
            FirstName = "Amanda"
            LastName = "Hall"
            Department = "Production"
            JobTitle = "Production Planner"
        },
        @{
            FirstName = "James"
            LastName = "Wright"
            Department = "Production"
            JobTitle = "Logistics Coordinator"
        }
    )
    
    # Define license SKUs
    $licenseSkus = @(
        @{
            Name = "Office 365 E5 without Teams"
            SkuPartNumber = "ENTERPRISEPREMIUM_NOPSTNCONF"
            Count = 15
        },
        @{
            Name = "Teams Enterprise Trial"
            SkuPartNumber = "TEAMS_COMMERCIAL_TRIAL"
            Count = 15
        },
        @{
            Name = "Enterprise Mobility + Security E5"
            SkuPartNumber = "EMSPREMIUM"
            Count = 15
        }
    )
    #endregion
    
    #region Create Groups
    Write-Log "Creating department groups..."
    
    $departmentGroups = @{}
    $licenseGroups = @{}
    
    # Create department groups
    foreach ($dept in $departments) {
        $groupName = "$($dept.Name) Department"
        $group = New-DemoGroup -DisplayName $groupName -Description $dept.Description -Domain $TenantDomain
        
        if ($null -ne $group) {
            $departmentGroups[$dept.Name] = $group
        }
    }
    
    # Create license groups
    foreach ($license in $licenseSkus) {
        $groupName = "$($license.Name) Users"
        $group = New-DemoGroup -DisplayName $groupName -Description "Users with $($license.Name) license" -Domain $TenantDomain
        
        if ($null -ne $group) {
            $licenseGroups[$license.SkuPartNumber] = $group
        }
    }
    
    # Create All Users group
    $allUsersGroup = New-DemoGroup -DisplayName "All Users" -Description "All company users" -Domain $TenantDomain
    #endregion
    
    #region Create Users
    Write-Log "Creating users..."
    
    $createdUsers = @()
    
    foreach ($user in $users) {
        # Generate random password
        $password = Get-RandomPassword -Prefix $UserPasswordPrefix
        
        # Create user
        $newUser = New-DemoUser -FirstName $user.FirstName -LastName $user.LastName -Department $user.Department -JobTitle $user.JobTitle -Domain $TenantDomain -Password $password -CountryCode $CountryCode
        
        if ($null -ne $newUser) {
            # Add user properties
            $user.Id = $newUser.Id
            $user.UPN = $newUser.UserPrincipalName
            $user.Password = $password
            
            $createdUsers += $user
            
            # Add user to department group
            if ($departmentGroups.ContainsKey($user.Department)) {
                Add-UserToGroup -UserId $user.Id -GroupId $departmentGroups[$user.Department].Id
            }
            
            # Add user to All Users group
            if ($null -ne $allUsersGroup) {
                Add-UserToGroup -UserId $user.Id -GroupId $allUsersGroup.Id
            }
        }
    }
    #endregion
    
    #region Assign Licenses
    Write-Log "Assigning licenses..."
    
    # Get license SKU IDs
    $licenseSkuIds = @{}
    
    foreach ($license in $licenseSkus) {
        $skuId = Get-LicenseSkuId -SkuPartNumber $license.SkuPartNumber
        
        if ($null -ne $skuId) {
            $licenseSkuIds[$license.SkuPartNumber] = $skuId
        }
    }
    
    # Get Teams service plans for O365 E5
    $teamsPlans = @()
    if ($licenseSkuIds.ContainsKey("ENTERPRISEPREMIUM_NOPSTNCONF")) {
        $teamsPlans = Get-TeamsServicePlan -SkuId $licenseSkuIds["ENTERPRISEPREMIUM_NOPSTNCONF"]
    }
    
    # Assign licenses to users
    foreach ($user in $createdUsers) {
        # Assign Office 365 E5 without Teams
        if ($licenseSkuIds.ContainsKey("ENTERPRISEPREMIUM_NOPSTNCONF")) {
            Assign-LicenseToUser -UserId $user.Id -SkuId $licenseSkuIds["ENTERPRISEPREMIUM_NOPSTNCONF"] -DisabledPlans $teamsPlans
            
            # Add user to license group
            if ($licenseGroups.ContainsKey("ENTERPRISEPREMIUM_NOPSTNCONF")) {
                Add-UserToGroup -UserId $user.Id -GroupId $licenseGroups["ENTERPRISEPREMIUM_NOPSTNCONF"].Id
            }
        }
        
        # Assign Teams Enterprise Trial
        if ($licenseSkuIds.ContainsKey("TEAMS_COMMERCIAL_TRIAL")) {
            Assign-LicenseToUser -UserId $user.Id -SkuId $licenseSkuIds["TEAMS_COMMERCIAL_TRIAL"]
            
            # Add user to license group
            if ($licenseGroups.ContainsKey("TEAMS_COMMERCIAL_TRIAL")) {
                Add-UserToGroup -UserId $user.Id -GroupId $licenseGroups["TEAMS_COMMERCIAL_TRIAL"].Id
            }
        }
        
        # Assign Enterprise Mobility + Security E5
        if ($licenseSkuIds.ContainsKey("EMSPREMIUM")) {
            Assign-LicenseToUser -UserId $user.Id -SkuId $licenseSkuIds["EMSPREMIUM"]
            
            # Add user to license group
            if ($licenseGroups.ContainsKey("EMSPREMIUM")) {
                Add-UserToGroup -UserId $user.Id -GroupId $licenseGroups["EMSPREMIUM"].Id
            }
        }
    }
    #endregion
    
    #region Generate Report
    Write-Log "Generating demo tenant report..."
    
    $reportFile = Join-Path -Path $LogPath -ChildPath "DemoTenantReport.txt"
    
    $report = @"
# $TenantName Demo Tenant Report
Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

## Tenant Information
- Tenant Name: $TenantName
- Tenant Domain: $TenantDomain
- Global Admin: $adminUpn

## Departments
$(foreach ($dept in $departments) {
"- $($dept.Name): $($dept.Description)"
})

## Groups
$(foreach ($key in $departmentGroups.Keys) {
"- $($departmentGroups[$key].DisplayName): $($departmentGroups[$key].Description)"
})
$(foreach ($key in $licenseGroups.Keys) {
"- $($licenseGroups[$key].DisplayName): $($licenseGroups[$key].Description)"
})
- $($allUsersGroup.DisplayName): $($allUsersGroup.Description)

## Users
$(foreach ($user in $createdUsers) {
"- $($user.FirstName) $($user.LastName) ($($user.UPN))
  - Department: $($user.Department)
  - Job Title: $($user.JobTitle)
  - Password: $($user.Password)
"
})

## Licenses
$(foreach ($license in $licenseSkus) {
"- $($license.Name) ($($license.SkuPartNumber)): $($license.Count) licenses"
})

"@
    
    # Save report to file
    $report | Out-File -FilePath $reportFile -Force
    
    Write-Log "Demo tenant report saved to: $reportFile"
    #endregion
    
    # Output success message
    Write-Log "Demo tenant setup completed successfully"
    Write-Output "Demo tenant setup completed successfully. Report saved to: $reportFile"
    
    # Return report file path
    return $reportFile
}
catch {
    Write-Log "Script execution failed: $_" -Level Error
    exit 1
}
finally {
    # Disconnect from Microsoft Graph and Azure AD
    try {
        Disconnect-MgGraph -ErrorAction SilentlyContinue
        Disconnect-AzureAD -ErrorAction SilentlyContinue
    }
    catch {
        # Ignore disconnection errors
    }
    
    Write-Log "Script execution completed"
}
#endregion
