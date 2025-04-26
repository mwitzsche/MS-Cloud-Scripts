# PowerShell Scripts Manual

## Overview

This manual documents a comprehensive collection of PowerShell scripts for managing all aspects of Azure Cloud, Microsoft 365, Entra ID, Intune, and Microsoft Defender. These scripts are designed for Azure administrators, Intune administrators, and security analysts to automate common tasks and generate detailed reports.

**Author:** Michael Witzsche  
**Date:** April 26, 2025  
**Version:** 1.0.0

## Table of Contents

1. [Azure](#azure)
2. [Entra ID](#entra-id)
3. [Intune](#intune)
4. [Microsoft 365](#microsoft-365)
5. [Security](#security)
6. [Data Protection](#data-protection)

## Installation and Requirements

### Prerequisites

- PowerShell 5.1 or PowerShell 7.x
- Required PowerShell modules:
  - Microsoft.Graph.Authentication
  - Microsoft.Graph.Identity.DirectoryManagement
  - Microsoft.Graph.Users
  - Microsoft.Graph.Groups
  - Microsoft.Graph.DeviceManagement
  - Microsoft.Graph.DeviceManagement.Administration
  - Microsoft.Graph.DeviceManagement.Enrollment
  - Microsoft.Graph.Security
  - Microsoft.Graph.Compliance
  - Microsoft.Graph.Teams
  - Microsoft.Graph.Sites
  - ExchangeOnlineManagement
  - Az
  - ImportExcel

### Installation

1. Install required PowerShell modules:

```powershell
# Install Microsoft Graph modules
Install-Module Microsoft.Graph -Force

# Install Azure modules
Install-Module Az -Force

# Install Exchange Online module
Install-Module ExchangeOnlineManagement -Force

# Install ImportExcel module for report export
Install-Module ImportExcel -Force
```

2. Download the scripts to your local machine
3. Ensure execution policy allows running the scripts:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

## Authentication

Most scripts use Microsoft Graph API and require authentication. Scripts are designed to use interactive authentication with a human account running from a desktop to Azure remotely. When running scripts, you'll be prompted to sign in with your Azure AD credentials.

## Azure

Scripts for managing Azure resources and services.

### New-AzureVM.ps1

**Description:** Creates a new virtual machine in Azure with specified configuration.

**Parameters:**
- `ResourceGroupName` - Name of the resource group where the VM will be created
- `VMName` - Name of the virtual machine
- `Location` - Azure region for the VM
- `VMSize` - Size of the VM (e.g., Standard_D2s_v3)
- `ImageName` - OS image to use (e.g., Win2019Datacenter, UbuntuLTS)
- `AdminUsername` - Administrator username
- `AdminPassword` - Administrator password
- `VNetName` - Virtual network name
- `SubnetName` - Subnet name
- `PublicIPName` - Public IP address name
- `NSGName` - Network security group name
- `Tags` - Hashtable of tags to apply to the VM
- `LogPath` - Path where logs will be stored

**Example:**
```powershell
.\New-AzureVM.ps1 -ResourceGroupName "MyResourceGroup" -VMName "MyVM" -Location "eastus" -VMSize "Standard_D2s_v3" -ImageName "Win2019Datacenter" -AdminUsername "azureadmin" -AdminPassword (ConvertTo-SecureString "P@ssw0rd123" -AsPlainText -Force) -VNetName "MyVNet" -SubnetName "default" -PublicIPName "MyPublicIP" -NSGName "MyNSG" -Tags @{Environment="Test"; Department="IT"}
```

### New-AzureVirtualNetwork.ps1

**Description:** Creates a new virtual network in Azure with subnets and network security groups.

**Parameters:**
- `ResourceGroupName` - Name of the resource group
- `VNetName` - Name of the virtual network
- `Location` - Azure region for the VNet
- `AddressPrefix` - Address space for the VNet (e.g., "10.0.0.0/16")
- `Subnets` - Array of subnet configurations
- `CreateNSG` - Whether to create network security groups for each subnet
- `Tags` - Hashtable of tags to apply
- `LogPath` - Path where logs will be stored

**Example:**
```powershell
$subnets = @(
    @{Name="Frontend"; AddressPrefix="10.0.0.0/24"; ServiceEndpoints=@("Microsoft.Storage")},
    @{Name="Backend"; AddressPrefix="10.0.1.0/24"; ServiceEndpoints=@("Microsoft.Sql")}
)
.\New-AzureVirtualNetwork.ps1 -ResourceGroupName "MyResourceGroup" -VNetName "MyVNet" -Location "eastus" -AddressPrefix "10.0.0.0/16" -Subnets $subnets -CreateNSG $true -Tags @{Environment="Production"; Department="IT"}
```

### New-AzureSQLDatabase.ps1

**Description:** Creates a new Azure SQL Database with specified configuration.

**Parameters:**
- `ResourceGroupName` - Name of the resource group
- `ServerName` - Name of the SQL Server
- `DatabaseName` - Name of the database
- `Location` - Azure region for the database
- `Edition` - SQL Database edition (e.g., Basic, Standard, Premium)
- `ServiceObjective` - Performance level (e.g., S0, S1, P1)
- `AdminUsername` - SQL Server admin username
- `AdminPassword` - SQL Server admin password
- `AllowAzureIPs` - Whether to allow Azure services to access the server
- `FirewallRules` - Array of firewall rules to create
- `Tags` - Hashtable of tags to apply
- `LogPath` - Path where logs will be stored

**Example:**
```powershell
$firewallRules = @(
    @{Name="Office"; StartIpAddress="203.0.113.0"; EndIpAddress="203.0.113.255"},
    @{Name="HomeNetwork"; StartIpAddress="198.51.100.0"; EndIpAddress="198.51.100.255"}
)
.\New-AzureSQLDatabase.ps1 -ResourceGroupName "MyResourceGroup" -ServerName "mysqlserver" -DatabaseName "MyDatabase" -Location "eastus" -Edition "Standard" -ServiceObjective "S1" -AdminUsername "sqladmin" -AdminPassword (ConvertTo-SecureString "P@ssw0rd123" -AsPlainText -Force) -AllowAzureIPs $true -FirewallRules $firewallRules -Tags @{Environment="Production"; Department="IT"}
```

## Entra ID

Scripts for managing Entra ID (formerly Azure AD) users, groups, and roles.

### New-AzureADUser.ps1

**Description:** Creates a new user in Entra ID with specified attributes and group memberships.

**Parameters:**
- `DisplayName` - Display name for the user
- `UserPrincipalName` - User principal name (email format)
- `MailNickname` - Mail nickname for the user
- `Password` - Initial password
- `ForceChangePasswordNextSignIn` - Whether to force password change at next sign-in
- `AccountEnabled` - Whether the account should be enabled
- `Department` - User's department
- `JobTitle` - User's job title
- `CompanyName` - User's company name
- `UsageLocation` - Two-letter country code for license assignment
- `GroupIds` - Array of group IDs to add the user to
- `LicenseSkuIds` - Array of license SKU IDs to assign
- `LogPath` - Path where logs will be stored

**Example:**
```powershell
.\New-AzureADUser.ps1 -DisplayName "John Doe" -UserPrincipalName "john.doe@contoso.com" -MailNickname "johndoe" -Password (ConvertTo-SecureString "P@ssw0rd123" -AsPlainText -Force) -ForceChangePasswordNextSignIn $true -AccountEnabled $true -Department "IT" -JobTitle "System Administrator" -CompanyName "Contoso" -UsageLocation "US" -GroupIds @("12345678-1234-1234-1234-123456789012", "87654321-4321-4321-4321-210987654321") -LicenseSkuIds @("f8a1db68-be16-40ed-86d5-cb42ce701560")
```

### New-AzureADGroup.ps1

**Description:** Creates a new security or Microsoft 365 group in Entra ID.

**Parameters:**
- `DisplayName` - Display name for the group
- `MailNickname` - Mail nickname for the group
- `Description` - Description of the group
- `GroupType` - Type of group (Security, Microsoft365)
- `MailEnabled` - Whether the group is mail-enabled
- `SecurityEnabled` - Whether the group is security-enabled
- `Visibility` - Visibility of the group (Private, Public, HiddenMembership)
- `Owners` - Array of user IDs to set as group owners
- `Members` - Array of user IDs to add as group members
- `IsAssignableToRole` - Whether the group can be assigned to an admin role
- `LogPath` - Path where logs will be stored

**Example:**
```powershell
.\New-AzureADGroup.ps1 -DisplayName "IT Department" -MailNickname "itdepartment" -Description "IT Department Security Group" -GroupType "Security" -MailEnabled $false -SecurityEnabled $true -Visibility "Private" -Owners @("12345678-1234-1234-1234-123456789012") -Members @("12345678-1234-1234-1234-123456789012", "87654321-4321-4321-4321-210987654321") -IsAssignableToRole $false
```

### Add-AzureADRoleAssignment.ps1

**Description:** Assigns an Entra ID directory role to a user or group.

**Parameters:**
- `RoleDefinitionName` - Name of the role to assign (e.g., Global Administrator, User Administrator)
- `PrincipalId` - ID of the user or group to assign the role to
- `PrincipalType` - Type of principal (User, Group)
- `LogPath` - Path where logs will be stored

**Example:**
```powershell
.\Add-AzureADRoleAssignment.ps1 -RoleDefinitionName "User Administrator" -PrincipalId "12345678-1234-1234-1234-123456789012" -PrincipalType "User"
```

### Get-UserReport.ps1

**Description:** Generates comprehensive reports about users in Microsoft 365 and Azure environments, including account information, license status, group memberships, role assignments, authentication methods, and activity logs.

**Parameters:**
- `ReportType` - Type of user report to generate (Basic, Detailed, Licenses, Groups, Roles, Auth, Activity, All)
- `Filter` - Hashtable of filters to apply to the report
- `TimeFrame` - Time frame for activity data (Last7Days, Last30Days, Last90Days, LastYear)
- `IncludeGuests` - Whether to include guest users in the report
- `IncludeServiceAccounts` - Whether to include service accounts in the report
- `ExportPath` - Path where the report will be saved
- `ExportFormat` - Format of the export file (CSV, JSON, Excel, HTML)
- `LogPath` - Path where logs will be stored

**Example:**
```powershell
.\Get-UserReport.ps1 -ReportType Licenses -Filter @{Department="IT"} -TimeFrame Last30Days -IncludeGuests $false -IncludeServiceAccounts $false -ExportPath "C:\Reports\UserLicenses.xlsx" -ExportFormat Excel
```

## Intune

Scripts for managing Microsoft Intune devices, applications, and policies.

### New-IntuneConfigurationProfile.ps1

**Description:** Creates a new device configuration profile in Microsoft Intune.

**Parameters:**
- `ProfileName` - Name of the configuration profile
- `Description` - Description of the profile
- `Platform` - Target platform (Windows10, iOS, Android, macOS)
- `ProfileType` - Type of configuration profile
- `Settings` - Hashtable of settings for the profile
- `Assignments` - Array of group IDs to assign the profile to
- `AssignmentType` - Type of assignment (Include, Exclude)
- `LogPath` - Path where logs will be stored

**Example:**
```powershell
$settings = @{
    passwordRequired = $true
    passwordMinimumLength = 8
    passwordRequiredType = "alphanumeric"
    passwordMinutesOfInactivityBeforeLock = 15
}
.\New-IntuneConfigurationProfile.ps1 -ProfileName "Windows 10 Security Baseline" -Description "Security baseline for Windows 10 devices" -Platform "Windows10" -ProfileType "deviceConfiguration" -Settings $settings -Assignments @("12345678-1234-1234-1234-123456789012") -AssignmentType "Include"
```

### New-IntuneApplication.ps1

**Description:** Creates and deploys a new application in Microsoft Intune.

**Parameters:**
- `AppName` - Name of the application
- `Description` - Description of the application
- `Publisher` - Publisher of the application
- `AppType` - Type of application (Win32, iOS, Android, WebApp)
- `FilePath` - Path to the application installation file
- `InstallCommand` - Command to install the application
- `UninstallCommand` - Command to uninstall the application
- `DetectionRules` - Array of detection rules
- `Requirements` - Hashtable of requirements for the application
- `Assignments` - Array of group IDs to assign the application to
- `AssignmentType` - Type of assignment (Required, Available, Uninstall)
- `LogPath` - Path where logs will be stored

**Example:**
```powershell
$detectionRules = @(
    @{
        Type = "File"
        Path = "C:\Program Files\MyApp"
        File = "myapp.exe"
        Existence = $true
    }
)
$requirements = @{
    MinimumOS = "10.0.18363"
    Architecture = "x64"
}
.\New-IntuneApplication.ps1 -AppName "My Application" -Description "Business application" -Publisher "Contoso" -AppType "Win32" -FilePath "C:\Packages\MyApp.intunewin" -InstallCommand "setup.exe /quiet" -UninstallCommand "setup.exe /uninstall /quiet" -DetectionRules $detectionRules -Requirements $requirements -Assignments @("12345678-1234-1234-1234-123456789012") -AssignmentType "Required"
```

### New-IntuneCompliancePolicy.ps1

**Description:** Creates a new device compliance policy in Microsoft Intune.

**Parameters:**
- `PolicyName` - Name of the compliance policy
- `Description` - Description of the policy
- `Platform` - Target platform (Windows10, iOS, Android, macOS)
- `Settings` - Hashtable of compliance settings
- `Assignments` - Array of group IDs to assign the policy to
- `AssignmentType` - Type of assignment (Include, Exclude)
- `LogPath` - Path where logs will be stored

**Example:**
```powershell
$settings = @{
    passwordRequired = $true
    passwordMinimumLength = 8
    secureBootEnabled = $true
    bitLockerEnabled = $true
    antivirusRequired = $true
    antiSpywareRequired = $true
    defenderEnabled = $true
    firewallEnabled = $true
}
.\New-IntuneCompliancePolicy.ps1 -PolicyName "Windows 10 Compliance Policy" -Description "Basic compliance policy for Windows 10 devices" -Platform "Windows10" -Settings $settings -Assignments @("12345678-1234-1234-1234-123456789012") -AssignmentType "Include"
```

### Manage-IntuneDevice.ps1

**Description:** Performs various management actions on Intune-managed devices.

**Parameters:**
- `Action` - Action to perform (Restart, Wipe, Reset, Rename, Sync, Retire, Delete, LocateDevice)
- `DeviceId` - ID of the target device
- `DeviceName` - Name of the target device (alternative to DeviceId)
- `NewDeviceName` - New name for the device (for Rename action)
- `BatchFile` - Path to CSV file for batch operations
- `LogPath` - Path where logs will be stored

**Example:**
```powershell
.\Manage-IntuneDevice.ps1 -Action "Restart" -DeviceId "12345678-1234-1234-1234-123456789012"
```

### Get-DeviceReport.ps1

**Description:** Generates comprehensive reports about devices in Microsoft Intune and Azure AD, including device information, compliance status, configuration profiles, installed applications, and security status.

**Parameters:**
- `ReportType` - Type of device report to generate (Basic, Detailed, Compliance, Profiles, Apps, Security, All)
- `Filter` - Hashtable of filters to apply to the report
- `TimeFrame` - Time frame for activity data (Last7Days, Last30Days, Last90Days, LastYear)
- `IncludePersonal` - Whether to include personal devices in the report
- `IncludeRetired` - Whether to include retired devices in the report
- `ExportPath` - Path where the report will be saved
- `ExportFormat` - Format of the export file (CSV, JSON, Excel, HTML)
- `LogPath` - Path where logs will be stored

**Example:**
```powershell
.\Get-DeviceReport.ps1 -ReportType Compliance -Filter @{OS="Windows"} -TimeFrame Last30Days -IncludePersonal $false -IncludeRetired $false -ExportPath "C:\Reports\WindowsCompliance.xlsx" -ExportFormat Excel
```

## Microsoft 365

Scripts for managing Microsoft 365 services including Exchange Online, SharePoint, Teams, and licenses.

### New-M365User.ps1

**Description:** Creates a new user in Microsoft 365 with specified attributes and license assignments.

**Parameters:**
- `DisplayName` - Display name for the user
- `UserPrincipalName` - User principal name (email format)
- `Password` - Initial password
- `ForceChangePasswordNextSignIn` - Whether to force password change at next sign-in
- `AccountEnabled` - Whether the account should be enabled
- `UsageLocation` - Two-letter country code for license assignment
- `LicenseSkus` - Array of license SKUs to assign
- `CreateMailbox` - Whether to create an Exchange Online mailbox
- `MailboxType` - Type of mailbox to create (User, Shared, Resource)
- `LogPath` - Path where logs will be stored

**Example:**
```powershell
.\New-M365User.ps1 -DisplayName "John Doe" -UserPrincipalName "john.doe@contoso.com" -Password (ConvertTo-SecureString "P@ssw0rd123" -AsPlainText -Force) -ForceChangePasswordNextSignIn $true -AccountEnabled $true -UsageLocation "US" -LicenseSkus @("ENTERPRISEPACK") -CreateMailbox $true -MailboxType "User"
```

### New-M365Group.ps1

**Description:** Creates a new Microsoft 365 group with specified attributes and members.

**Parameters:**
- `DisplayName` - Display name for the group
- `MailNickname` - Mail nickname for the group
- `Description` - Description of the group
- `Visibility` - Visibility of the group (Private, Public)
- `Owners` - Array of user principal names to set as group owners
- `Members` - Array of user principal names to add as group members
- `CreateTeam` - Whether to create a Teams team for the group
- `LogPath` - Path where logs will be stored

**Example:**
```powershell
.\New-M365Group.ps1 -DisplayName "Marketing Team" -MailNickname "marketing" -Description "Marketing department team" -Visibility "Private" -Owners @("john.doe@contoso.com") -Members @("jane.smith@contoso.com", "bob.johnson@contoso.com") -CreateTeam $true
```

### New-SharePointSite.ps1

**Description:** Creates a new SharePoint Online site with specified configuration.

**Parameters:**
- `SiteType` - Type of site to create (TeamSite, CommunicationSite)
- `Title` - Title of the site
- `Url` - URL for the site
- `Description` - Description of the site
- `Owners` - Array of user principal names to set as site owners
- `Members` - Array of user principal names to add as site members
- `Visitors` - Array of user principal names to add as site visitors
- `IsPublic` - Whether the site is public
- `Locale` - Locale ID for the site
- `TimeZone` - Time zone ID for the site
- `LogPath` - Path where logs will be stored

**Example:**
```powershell
.\New-SharePointSite.ps1 -SiteType "TeamSite" -Title "Project X" -Url "https://contoso.sharepoint.com/sites/ProjectX" -Description "Project X collaboration site" -Owners @("john.doe@contoso.com") -Members @("jane.smith@contoso.com", "bob.johnson@contoso.com") -Visitors @() -IsPublic $false -Locale 1033 -TimeZone 10
```

### New-ExchangeMailbox.ps1

**Description:** Creates a new Exchange Online mailbox of specified type.

**Parameters:**
- `MailboxType` - Type of mailbox to create (User, Shared, Room, Equipment)
- `DisplayName` - Display name for the mailbox
- `PrimarySmtpAddress` - Primary SMTP address for the mailbox
- `Alias` - Email alias for the mailbox
- `UserPrincipalName` - User principal name (for user mailboxes)
- `Password` - Initial password (for user mailboxes)
- `RoomCapacity` - Capacity of the room (for room mailboxes)
- `ResourceCapacity` - Capacity of the resource (for equipment mailboxes)
- `AutoAccept` - Whether to automatically accept meeting requests (for room/equipment mailboxes)
- `Delegates` - Array of users to set as delegates (for shared mailboxes)
- `LogPath` - Path where logs will be stored

**Example:**
```powershell
.\New-ExchangeMailbox.ps1 -MailboxType "Shared" -DisplayName "Support Mailbox" -PrimarySmtpAddress "support@contoso.com" -Alias "support" -Delegates @("john.doe@contoso.com", "jane.smith@contoso.com")
```

### New-TeamsTeam.ps1

**Description:** Creates a new Microsoft Teams team with specified channels and settings.

**Parameters:**
- `TeamName` - Name of the team
- `Description` - Description of the team
- `Visibility` - Visibility of the team (Private, Public)
- `Owners` - Array of user principal names to set as team owners
- `Members` - Array of user principal names to add as team members
- `Channels` - Array of channels to create
- `AllowGuestAccess` - Whether to allow guest access
- `AllowCreateUpdateChannels` - Whether to allow members to create and update channels
- `AllowCreatePrivateChannels` - Whether to allow members to create private channels
- `AllowDeleteChannels` - Whether to allow members to delete channels
- `LogPath` - Path where logs will be stored

**Example:**
```powershell
$channels = @(
    @{Name="General"; Description="General channel"},
    @{Name="Announcements"; Description="Team announcements"},
    @{Name="Projects"; Description="Project discussions"}
)
.\New-TeamsTeam.ps1 -TeamName "Marketing Team" -Description "Marketing department team" -Visibility "Private" -Owners @("john.doe@contoso.com") -Members @("jane.smith@contoso.com", "bob.johnson@contoso.com") -Channels $channels -AllowGuestAccess $false -AllowCreateUpdateChannels $true -AllowCreatePrivateChannels $true -AllowDeleteChannels $false
```

### Manage-M365Licenses.ps1

**Description:** Manages Microsoft 365 license assignments for users and groups.

**Parameters:**
- `Action` - Action to perform (Assign, Remove, List, Report)
- `UserPrincipalName` - User principal name to manage licenses for
- `GroupId` - Group ID to manage licenses for
- `LicenseSkus` - Array of license SKUs to assign or remove
- `DisabledPlans` - Array of service plans to disable
- `UsageLocation` - Two-letter country code for license assignment
- `BatchFile` - Path to CSV file for batch operations
- `ExportPath` - Path to export license report
- `LogPath` - Path where logs will be stored

**Example:**
```powershell
.\Manage-M365Licenses.ps1 -Action "Assign" -UserPrincipalName "john.doe@contoso.com" -LicenseSkus @("ENTERPRISEPACK") -DisabledPlans @("SWAY") -UsageLocation "US"
```

### Manage-AzureSubscription.ps1

**Description:** Manages Azure subscriptions including creation, assignment, and reporting.

**Parameters:**
- `Action` - Action to perform (Create, Assign, Remove, List, Report)
- `SubscriptionName` - Name of the subscription
- `SubscriptionId` - ID of the subscription
- `BillingAccount` - Billing account ID
- `BillingProfile` - Billing profile ID
- `InvoiceSection` - Invoice section ID
- `OfferType` - Offer type for the subscription
- `PrincipalId` - ID of the user or group to assign the subscription to
- `RoleDefinitionName` - Role to assign (Owner, Contributor, Reader)
- `ExportPath` - Path to export subscription report
- `LogPath` - Path where logs will be stored

**Example:**
```powershell
.\Manage-AzureSubscription.ps1 -Action "Assign" -SubscriptionId "12345678-1234-1234-1234-123456789012" -PrincipalId "87654321-4321-4321-4321-210987654321" -RoleDefinitionName "Contributor"
```

## Security

Scripts for managing security settings, Microsoft Defender, and security reporting.

### Set-AzureSecurityCenter.ps1

**Description:** Configures Azure Security Center settings and policies.

**Parameters:**
- `SubscriptionId` - ID of the subscription
- `PricingTier` - Pricing tier for Security Center (Free, Standard)
- `AutoProvisioningSettings` - Auto-provisioning settings for the Security Center agent
- `WorkspaceId` - Log Analytics workspace ID for data collection
- `SecurityContacts` - Array of security contacts
- `EnableDefender` - Whether to enable Microsoft Defender for Cloud
- `DefenderPlans` - Array of Defender plans to enable
- `LogPath` - Path where logs will be stored

**Example:**
```powershell
$securityContacts = @(
    @{Email="security@contoso.com"; Phone="+1-555-123-4567"; AlertNotifications=$true; AlertsToAdmins=$true}
)
$defenderPlans = @("VirtualMachines", "SqlServers", "AppServices", "StorageAccounts", "KeyVaults", "Containers")
.\Set-AzureSecurityCenter.ps1 -SubscriptionId "12345678-1234-1234-1234-123456789012" -PricingTier "Standard" -AutoProvisioningSettings "On" -WorkspaceId "87654321-4321-4321-4321-210987654321" -SecurityContacts $securityContacts -EnableDefender $true -DefenderPlans $defenderPlans
```

### Set-M365Security.ps1

**Description:** Configures Microsoft 365 security settings including conditional access policies and security defaults.

**Parameters:**
- `Action` - Action to perform (EnableSecurityDefaults, DisableSecurityDefaults, CreateConditionalAccessPolicy)
- `PolicyName` - Name of the conditional access policy
- `PolicyState` - State of the policy (Enabled, Disabled, EnabledForReportingOnly)
- `IncludeUsers` - Array of users to include in the policy
- `ExcludeUsers` - Array of users to exclude from the policy
- `IncludeGroups` - Array of groups to include in the policy
- `ExcludeGroups` - Array of groups to exclude from the policy
- `IncludeApplications` - Array of applications to include in the policy
- `ExcludeApplications` - Array of applications to exclude from the policy
- `GrantControls` - Array of grant controls for the policy
- `SessionControls` - Array of session controls for the policy
- `LogPath` - Path where logs will be stored

**Example:**
```powershell
$grantControls = @{
    Operator = "OR"
    BuiltInControls = @("mfa", "compliantDevice")
}
.\Set-M365Security.ps1 -Action "CreateConditionalAccessPolicy" -PolicyName "Require MFA for All Users" -PolicyState "Enabled" -IncludeUsers @("All") -ExcludeUsers @("admin@contoso.com") -IncludeApplications @("All") -GrantControls $grantControls
```

### Analyze-DefenderAlertFalsePositives.ps1

**Description:** Analyzes Microsoft Defender alerts to identify potential false positives.

**Parameters:**
- `TimeFrame` - Time frame for alert analysis (Last7Days, Last30Days, Last90Days, LastYear)
- `MinimumAlertCount` - Minimum number of similar alerts to consider for false positive analysis
- `ExcludeAlertTypes` - Array of alert types to exclude from analysis
- `ExportPath` - Path to export false positive report
- `ExportFormat` - Format of the export file (CSV, JSON, Excel, HTML)
- `LogPath` - Path where logs will be stored

**Example:**
```powershell
.\Analyze-DefenderAlertFalsePositives.ps1 -TimeFrame "Last30Days" -MinimumAlertCount 5 -ExportPath "C:\Reports\DefenderFalsePositives.xlsx" -ExportFormat "Excel"
```

### Manage-DefenderIncident.ps1

**Description:** Manages Microsoft Defender incidents including assignment, classification, and comments.

**Parameters:**
- `Action` - Action to perform (Assign, Classify, Comment, Close, List)
- `IncidentId` - ID of the incident
- `AssignedTo` - User to assign the incident to
- `Classification` - Classification of the incident (TruePositive, FalsePositive, Informational)
- `ClassificationReason` - Reason for the classification
- `Comment` - Comment to add to the incident
- `Status` - Status to set for the incident (New, Active, Resolved)
- `ExportPath` - Path to export incident report
- `LogPath` - Path where logs will be stored

**Example:**
```powershell
.\Manage-DefenderIncident.ps1 -Action "Classify" -IncidentId "12345" -Classification "FalsePositive" -ClassificationReason "Legitimate administrative activity" -Comment "Verified with system administrator"
```

### Configure-DefenderXDR.ps1

**Description:** Configures Microsoft Defender XDR settings including advanced features and integrations.

**Parameters:**
- `Action` - Action to perform (ConfigureEDR, ConfigureIdentity, ConfigureOffice365, ConfigureEndpoints, ConfigureIntegrations)
- `SubscriptionId` - ID of the subscription
- `WorkspaceId` - Log Analytics workspace ID
- `EnableAdvancedFeatures` - Whether to enable advanced features
- `EnableAuditLogs` - Whether to enable audit logs
- `EnableAutomaticSampleSubmission` - Whether to enable automatic sample submission
- `EnableCloudDeliveredProtection` - Whether to enable cloud-delivered protection
- `IntegrationType` - Type of integration to configure (SIEM, SOAR, API)
- `IntegrationSettings` - Hashtable of integration settings
- `LogPath` - Path where logs will be stored

**Example:**
```powershell
$integrationSettings = @{
    WorkspaceId = "12345678-1234-1234-1234-123456789012"
    PrimaryKey = "abcdefghijklmnopqrstuvwxyz123456789="
    EventTypes = @("SecurityAlert", "SecurityIncident", "AuditLogs")
}
.\Configure-DefenderXDR.ps1 -Action "ConfigureIntegrations" -IntegrationType "SIEM" -IntegrationSettings $integrationSettings
```

### Generate-DefenderSecurityReport.ps1

**Description:** Generates comprehensive security reports from Microsoft Defender XDR.

**Parameters:**
- `ReportType` - Type of report to generate (Alerts, Incidents, Vulnerabilities, SecureScore, Compliance, ThreatAnalytics, All)
- `TimeFrame` - Time frame for the report (Last7Days, Last30Days, Last90Days, LastYear)
- `Filter` - Hashtable of filters to apply to the report
- `IncludeRemediation` - Whether to include remediation recommendations
- `ExportPath` - Path to export the report
- `ExportFormat` - Format of the export file (CSV, JSON, Excel, HTML)
- `LogPath` - Path where logs will be stored

**Example:**
```powershell
.\Generate-DefenderSecurityReport.ps1 -ReportType "Incidents" -TimeFrame "Last30Days" -Filter @{Severity="High"} -IncludeRemediation $true -ExportPath "C:\Reports\HighSeverityIncidents.xlsx" -ExportFormat "Excel"
```

### Get-SecurityReport.ps1

**Description:** Generates comprehensive security reports for Microsoft Defender and Azure Security Center, including security alerts, incidents, vulnerabilities, secure score, and compliance status.

**Parameters:**
- `ReportType` - Type of security report to generate (Alerts, Incidents, Vulnerabilities, SecureScore, Compliance, All)
- `Filter` - Hashtable of filters to apply to the report
- `TimeFrame` - Time frame for security data (Last7Days, Last30Days, Last90Days, LastYear)
- `IncludeInformational` - Whether to include informational alerts in the report
- `IncludeResolved` - Whether to include resolved items in the report
- `ExportPath` - Path where the report will be saved
- `ExportFormat` - Format of the export file (CSV, JSON, Excel, HTML)
- `LogPath` - Path where logs will be stored

**Example:**
```powershell
.\Get-SecurityReport.ps1 -ReportType Alerts -TimeFrame Last7Days -Filter @{Severity="High"} -IncludeInformational $false -IncludeResolved $false -ExportPath "C:\Reports\SecurityAlerts.xlsx" -ExportFormat Excel
```

### Analyze-ASRRules.ps1

**Description:** Analyzes and reports on Attack Surface Reduction (ASR) rules configuration and events, helping security administrators identify potential false positives and optimize ASR rule deployment.

**Parameters:**
- `ReportType` - Type of ASR report to generate (Configuration, Events, FalsePositives, Recommendations, All)
- `TimeFrame` - Time frame for ASR events data (Last7Days, Last30Days, Last90Days, LastYear)
- `Filter` - Hashtable of filters to apply to the report
- `IncludeAuditEvents` - Whether to include audit mode events in the report
- `GroupByDevice` - Whether to group results by device instead of by rule
- `ExportPath` - Path where the report will be saved
- `ExportFormat` - Format of the export file (CSV, JSON, Excel, HTML)
- `LogPath` - Path where logs will be stored

**Example:**
```powershell
.\Analyze-ASRRules.ps1 -ReportType FalsePositives -TimeFrame Last30Days -ExportPath "C:\Reports\ASRFalsePositives.xlsx" -ExportFormat Excel
```

## Data Protection

Scripts for managing data protection with Microsoft Purview and Windows Information Protection.

### Manage-WindowsInformationProtection.ps1

**Description:** Manages Windows Information Protection (WIP) policies for devices.

**Parameters:**
- `Action` - Action to perform (Create, Update, Remove, List)
- `PolicyName` - Name of the WIP policy
- `Description` - Description of the policy
- `EnforcementLevel` - Enforcement level (Off, Silent, Override, Block)
- `EnterpriseProtectedDomains` - Array of enterprise protected domains
- `EnterpriseIPRanges` - Array of enterprise IP ranges
- `EnterpriseProxyServers` - Array of enterprise proxy servers
- `EnterpriseInternalProxyServers` - Array of enterprise internal proxy servers
- `DataRecoveryCertificate` - Data recovery certificate
- `ProtectedApps` - Array of protected apps
- `ExemptApps` - Array of exempt apps
- `Assignments` - Array of group IDs to assign the policy to
- `LogPath` - Path where logs will be stored

**Example:**
```powershell
$protectedDomains = @("contoso.com", "contoso.net")
$protectedApps = @(
    @{Name="Microsoft Edge"; Path="C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"},
    @{Name="Microsoft Office"; Path="C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"}
)
.\Manage-WindowsInformationProtection.ps1 -Action "Create" -PolicyName "Contoso WIP Policy" -Description "Windows Information Protection policy for Contoso" -EnforcementLevel "Block" -EnterpriseProtectedDomains $protectedDomains -ProtectedApps $protectedApps -Assignments @("12345678-1234-1234-1234-123456789012")
```

### Manage-MicrosoftPurview.ps1

**Description:** Manages Microsoft Purview compliance settings including data classification and retention policies.

**Parameters:**
- `Action` - Action to perform (CreateSensitivityLabel, CreateRetentionPolicy, CreateDLPPolicy, List)
- `Name` - Name of the policy or label
- `Description` - Description of the policy or label
- `ContentType` - Content types the policy applies to (Email, Document, Site)
- `SensitivityLabelSettings` - Hashtable of sensitivity label settings
- `RetentionPolicySettings` - Hashtable of retention policy settings
- `DLPPolicySettings` - Hashtable of DLP policy settings
- `Locations` - Array of locations to apply the policy to
- `ExcludedLocations` - Array of locations to exclude from the policy
- `Priority` - Priority of the policy
- `LogPath` - Path where logs will be stored

**Example:**
```powershell
$sensitivitySettings = @{
    Tooltip = "Contains confidential information"
    Color = "#FF0000"
    Encryption = $true
    EncryptionProtectionType = "Template"
    EncryptionTemplateId = "12345678-1234-1234-1234-123456789012"
    ContentMarkingEnabled = $true
    HeaderText = "Confidential"
    FooterText = "Contoso Confidential"
    WatermarkText = "Confidential"
}
.\Manage-MicrosoftPurview.ps1 -Action "CreateSensitivityLabel" -Name "Confidential" -Description "Label for confidential information" -ContentType @("Email", "Document") -SensitivityLabelSettings $sensitivitySettings
```

### Manage-PurviewInformationProtection.ps1

**Description:** Manages Microsoft Purview Information Protection settings including sensitivity labels, policies, and auto-labeling.

**Parameters:**
- `Action` - Action to perform (CreateLabel, CreatePolicy, CreateAutoLabelingPolicy, List)
- `Name` - Name of the label or policy
- `Description` - Description of the label or policy
- `ParentLabelId` - ID of the parent label (for sub-labels)
- `Tooltip` - Tooltip for the label
- `Color` - Color for the label
- `Sensitivity` - Sensitivity level (Low, Medium, High, Critical)
- `EncryptionEnabled` - Whether encryption is enabled
- `EncryptionSettings` - Hashtable of encryption settings
- `MarkingSettings` - Hashtable of content marking settings
- `ProtectionSettings` - Hashtable of protection settings
- `AutoLabelingSettings` - Hashtable of auto-labeling settings
- `Scope` - Scope of the policy (All, Exchange, SharePoint, OneDrive)
- `Priority` - Priority of the policy
- `LogPath` - Path where logs will be stored

**Example:**
```powershell
$markingSettings = @{
    HeaderEnabled = $true
    HeaderText = "Confidential"
    HeaderFontSize = 12
    HeaderColor = "#FF0000"
    HeaderAlignment = "Center"
    FooterEnabled = $true
    FooterText = "Contoso Confidential"
    FooterFontSize = 12
    FooterColor = "#FF0000"
    FooterAlignment = "Center"
    WatermarkEnabled = $true
    WatermarkText = "Confidential"
    WatermarkFontSize = 40
    WatermarkColor = "#FF0000"
}
.\Manage-PurviewInformationProtection.ps1 -Action "CreateLabel" -Name "Confidential" -Description "Label for confidential information" -Tooltip "Contains confidential information" -Color "#FF0000" -Sensitivity "High" -MarkingSettings $markingSettings
```

## Logging and Error Handling

All scripts include comprehensive error handling and logging capabilities. By default, logs are stored in the Windows log directory, but you can specify a custom log path using the `LogPath` parameter.

Logs include:
- Timestamp
- Log level (Information, Warning, Error)
- Detailed message

Example log entry:
```
[2025-04-26 10:15:30] [Information] Successfully connected to Microsoft Graph as admin@contoso.com
```

## Best Practices

1. **Authentication**: Always use secure authentication methods. Scripts are designed to use interactive authentication with a human account.

2. **Error Handling**: All scripts include comprehensive error handling. Check logs for detailed error information.

3. **Testing**: Always test scripts in a non-production environment before using them in production.

4. **Permissions**: Ensure the account running the scripts has the necessary permissions for the operations being performed.

5. **Secure Storage**: Store scripts in a secure location with appropriate access controls.

6. **Parameter Validation**: All scripts include parameter validation to prevent errors and security issues.

7. **Logging**: Review logs regularly to monitor script execution and troubleshoot issues.

## Support

For issues or questions about these scripts, please contact the author:

**Author:** Michael Witzsche  
**Date:** April 26, 2025  
**Version:** 1.0.0
