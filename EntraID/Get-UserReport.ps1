<#
.SYNOPSIS
    Generates comprehensive user reports from Microsoft 365 and Azure environments.

.DESCRIPTION
    This script generates detailed reports about users in Microsoft 365 and Azure environments,
    including account information, license status, group memberships, role assignments,
    authentication methods, and activity logs. Reports can be filtered by various criteria
    and exported in multiple formats.

.PARAMETER ReportType
    The type of user report to generate (Basic, Detailed, Licenses, Groups, Roles, Auth, Activity, All).

.PARAMETER Filter
    Hashtable of filters to apply to the report (e.g. @{Department="IT"; Country="Germany"}).

.PARAMETER TimeFrame
    The time frame for activity data (Last7Days, Last30Days, Last90Days, LastYear).

.PARAMETER IncludeGuests
    Whether to include guest users in the report.

.PARAMETER IncludeServiceAccounts
    Whether to include service accounts in the report.

.PARAMETER ExportPath
    The path where the report will be saved.

.PARAMETER ExportFormat
    The format of the export file (CSV, JSON, Excel, HTML).

.PARAMETER LogPath
    Path where logs will be stored. Defaults to Windows log directory.

.EXAMPLE
    .\Get-UserReport.ps1 -ReportType Basic -ExportPath "C:\Reports\UserBasicReport.csv" -ExportFormat CSV
    Generates a basic user report and exports it to CSV format.

.EXAMPLE
    .\Get-UserReport.ps1 -ReportType Licenses -Filter @{Department="IT"} -ExportPath "C:\Reports\ITLicenses.xlsx" -ExportFormat Excel
    Generates a license report for IT department users and exports it to Excel format.

.NOTES
    Author: Michael Witzsche
    Date: April 26, 2025
    Version: 1.0.0
    
    History:
    1.0.0 - Initial release
#>

#Requires -Modules Microsoft.Graph.Users, Microsoft.Graph.Groups, Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.Authentication, ImportExcel

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$LogPath = "$env:SystemRoot\Logs\Get-UserReport",
    
    [Parameter(Mandatory = $true)]
    [ValidateSet("Basic", "Detailed", "Licenses", "Groups", "Roles", "Auth", "Activity", "All")]
    [string]$ReportType,
    
    [Parameter(Mandatory = $false)]
    [hashtable]$Filter = @{},
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Last7Days", "Last30Days", "Last90Days", "LastYear")]
    [string]$TimeFrame = "Last30Days",
    
    [Parameter(Mandatory = $false)]
    [bool]$IncludeGuests = $false,
    
    [Parameter(Mandatory = $false)]
    [bool]$IncludeServiceAccounts = $false,
    
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
            "User.Read.All",
            "Group.Read.All",
            "Directory.Read.All",
            "AuditLog.Read.All",
            "Organization.Read.All",
            "UserAuthenticationMethod.Read.All"
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

function Get-FilteredUsers {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [hashtable]$Filter = @{},
        
        [Parameter(Mandatory = $false)]
        [bool]$IncludeGuests = $false,
        
        [Parameter(Mandatory = $false)]
        [bool]$IncludeServiceAccounts = $false
    )
    
    try {
        Write-Log "Retrieving users with applied filters..."
        
        # Build filter string
        $filterStrings = @()
        
        # Add user type filter
        if (-not $IncludeGuests) {
            $filterStrings += "userType eq 'Member'"
        }
        
        # Add service account filter (typically identified by specific naming patterns)
        if (-not $IncludeServiceAccounts) {
            $filterStrings += "not startsWith(displayName, 'svc-')"
            $filterStrings += "not startsWith(displayName, 'sa-')"
            $filterStrings += "not startsWith(displayName, 'service-')"
        }
        
        # Add custom filters
        foreach ($key in $Filter.Keys) {
            $value = $Filter[$key]
            
            # Handle different property types
            switch ($key) {
                "Department" { $filterStrings += "department eq '$value'" }
                "Country" { $filterStrings += "country eq '$value'" }
                "City" { $filterStrings += "city eq '$value'" }
                "JobTitle" { $filterStrings += "jobTitle eq '$value'" }
                "CompanyName" { $filterStrings += "companyName eq '$value'" }
                "AccountEnabled" { $filterStrings += "accountEnabled eq $($value.ToString().ToLower())" }
                "DisplayName" { $filterStrings += "startsWith(displayName, '$value')" }
                "Mail" { $filterStrings += "startsWith(mail, '$value')" }
                "UserPrincipalName" { $filterStrings += "startsWith(userPrincipalName, '$value')" }
                default { $filterStrings += "$key eq '$value'" }
            }
        }
        
        # Combine filter strings
        $filterString = $filterStrings -join " and "
        
        # Get users with filter
        if ([string]::IsNullOrEmpty($filterString)) {
            $users = Get-MgUser -All -Property Id, DisplayName, UserPrincipalName, Mail, JobTitle, Department, 
                                         OfficeLocation, BusinessPhones, MobilePhone, AccountEnabled, 
                                         UserType, CreatedDateTime, Country, City, CompanyName
        }
        else {
            $users = Get-MgUser -Filter $filterString -All -Property Id, DisplayName, UserPrincipalName, Mail, 
                                                            JobTitle, Department, OfficeLocation, BusinessPhones, 
                                                            MobilePhone, AccountEnabled, UserType, CreatedDateTime, 
                                                            Country, City, CompanyName
        }
        
        if ($null -eq $users -or $users.Count -eq 0) {
            Write-Log "No users found with the specified filters" -Level Warning
            return $null
        }
        
        Write-Log "Retrieved $($users.Count) users"
        return $users
    }
    catch {
        Write-Log "Error retrieving users: $_" -Level Error
        return $null
    }
}

function Get-BasicUserReport {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object[]]$Users
    )
    
    try {
        Write-Log "Generating basic user report..."
        
        $report = @()
        
        foreach ($user in $Users) {
            $report += [PSCustomObject]@{
                DisplayName = $user.DisplayName
                UserPrincipalName = $user.UserPrincipalName
                Mail = $user.Mail
                JobTitle = $user.JobTitle
                Department = $user.Department
                AccountEnabled = $user.AccountEnabled
                UserType = $user.UserType
                CreatedDateTime = $user.CreatedDateTime
            }
        }
        
        Write-Log "Generated basic user report with $($report.Count) entries"
        return $report
    }
    catch {
        Write-Log "Error generating basic user report: $_" -Level Error
        return $null
    }
}

function Get-DetailedUserReport {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object[]]$Users
    )
    
    try {
        Write-Log "Generating detailed user report..."
        
        $report = @()
        
        foreach ($user in $Users) {
            # Get additional user details
            $userDetails = Get-MgUser -UserId $user.Id -Property Id, DisplayName, UserPrincipalName, Mail, 
                                                      GivenName, Surname, JobTitle, Department, OfficeLocation, 
                                                      BusinessPhones, MobilePhone, AccountEnabled, UserType, 
                                                      CreatedDateTime, Country, City, CompanyName, 
                                                      StreetAddress, PostalCode, State, UsageLocation, 
                                                      PreferredLanguage, PasswordPolicies, LastPasswordChangeDateTime
            
            # Get manager
            $manager = $null
            try {
                $manager = Get-MgUserManager -UserId $user.Id
            }
            catch {
                # No manager assigned
            }
            
            $report += [PSCustomObject]@{
                DisplayName = $userDetails.DisplayName
                UserPrincipalName = $userDetails.UserPrincipalName
                Mail = $userDetails.Mail
                GivenName = $userDetails.GivenName
                Surname = $userDetails.Surname
                JobTitle = $userDetails.JobTitle
                Department = $userDetails.Department
                OfficeLocation = $userDetails.OfficeLocation
                BusinessPhone = if ($userDetails.BusinessPhones.Count -gt 0) { $userDetails.BusinessPhones[0] } else { "" }
                MobilePhone = $userDetails.MobilePhone
                AccountEnabled = $userDetails.AccountEnabled
                UserType = $userDetails.UserType
                CreatedDateTime = $userDetails.CreatedDateTime
                Country = $userDetails.Country
                City = $userDetails.City
                CompanyName = $userDetails.CompanyName
                StreetAddress = $userDetails.StreetAddress
                PostalCode = $userDetails.PostalCode
                State = $userDetails.State
                UsageLocation = $userDetails.UsageLocation
                PreferredLanguage = $userDetails.PreferredLanguage
                PasswordPolicies = $userDetails.PasswordPolicies
                LastPasswordChangeDateTime = $userDetails.LastPasswordChangeDateTime
                Manager = if ($null -ne $manager) { $manager.AdditionalProperties.displayName } else { "" }
                ManagerEmail = if ($null -ne $manager) { $manager.AdditionalProperties.mail } else { "" }
            }
        }
        
        Write-Log "Generated detailed user report with $($report.Count) entries"
        return $report
    }
    catch {
        Write-Log "Error generating detailed user report: $_" -Level Error
        return $null
    }
}

function Get-UserLicenseReport {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object[]]$Users
    )
    
    try {
        Write-Log "Generating user license report..."
        
        $report = @()
        
        # Get license SKU information
        $skus = Get-MgSubscribedSku
        $skuLookup = @{}
        
        foreach ($sku in $skus) {
            $skuLookup[$sku.SkuId] = $sku.SkuPartNumber
        }
        
        foreach ($user in $Users) {
            # Get user license details
            $userDetails = Get-MgUser -UserId $user.Id -Property Id, DisplayName, UserPrincipalName, Mail, 
                                                      AssignedLicenses, UsageLocation
            
            if ($null -eq $userDetails.AssignedLicenses -or $userDetails.AssignedLicenses.Count -eq 0) {
                # User has no licenses
                $report += [PSCustomObject]@{
                    DisplayName = $userDetails.DisplayName
                    UserPrincipalName = $userDetails.UserPrincipalName
                    Mail = $userDetails.Mail
                    UsageLocation = $userDetails.UsageLocation
                    LicenseName = "No License"
                    LicenseSkuId = ""
                    LicenseSkuPartNumber = ""
                    AssignmentSource = ""
                }
            }
            else {
                # User has licenses
                foreach ($license in $userDetails.AssignedLicenses) {
                    $skuPartNumber = if ($skuLookup.ContainsKey($license.SkuId)) { $skuLookup[$license.SkuId] } else { "Unknown" }
                    
                    $report += [PSCustomObject]@{
                        DisplayName = $userDetails.DisplayName
                        UserPrincipalName = $userDetails.UserPrincipalName
                        Mail = $userDetails.Mail
                        UsageLocation = $userDetails.UsageLocation
                        LicenseName = Get-LicenseDisplayName -SkuPartNumber $skuPartNumber
                        LicenseSkuId = $license.SkuId
                        LicenseSkuPartNumber = $skuPartNumber
                        AssignmentSource = "Direct" # Would need additional logic to determine if group-based
                    }
                }
            }
        }
        
        Write-Log "Generated user license report with $($report.Count) entries"
        return $report
    }
    catch {
        Write-Log "Error generating user license report: $_" -Level Error
        return $null
    }
}

function Get-LicenseDisplayName {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$SkuPartNumber
    )
    
    # Map SKU part numbers to friendly names
    $licenseMap = @{
        "AAD_PREMIUM" = "Azure AD Premium P1"
        "AAD_PREMIUM_P2" = "Azure AD Premium P2"
        "ADALLOM_S_O365" = "Microsoft Defender for Cloud Apps for Office 365"
        "ADALLOM_S_STANDALONE" = "Microsoft Defender for Cloud Apps"
        "ATP_ENTERPRISE" = "Microsoft Defender for Office 365 (Plan 1)"
        "ATP_ENTERPRISE_FACULTY" = "Microsoft Defender for Office 365 (Plan 1) for Faculty"
        "ATP_ENTERPRISE_GOV" = "Microsoft Defender for Office 365 (Plan 1) for Government"
        "CRMSTANDARD" = "Dynamics 365 Customer Engagement Plan"
        "DESKLESSPACK" = "Office 365 F1"
        "DESKLESSWOFFPACK" = "Office 365 F3"
        "DEVELOPERPACK" = "Office 365 E3 Developer"
        "DYN365_ENTERPRISE_PLAN1" = "Dynamics 365 Customer Engagement Plan Enterprise Edition"
        "DYN365_ENTERPRISE_SALES" = "Dynamics 365 for Sales Enterprise Edition"
        "DYN365_ENTERPRISE_TEAM_MEMBERS" = "Dynamics 365 Team Members Enterprise Edition"
        "DYN365_FINANCIALS_BUSINESS_SKU" = "Dynamics 365 for Financials Business Edition"
        "ECAL_SERVICES" = "Enterprise Client Access License Services"
        "EMS" = "Enterprise Mobility + Security E3"
        "EMSPREMIUM" = "Enterprise Mobility + Security E5"
        "ENTERPRISEPACK" = "Office 365 E3"
        "ENTERPRISEPACK_FACULTY" = "Office 365 E3 for Faculty"
        "ENTERPRISEPACK_GOV" = "Office 365 G3 GCC"
        "ENTERPRISEPACK_STUDENT" = "Office 365 E3 for Students"
        "ENTERPRISEPREMIUM" = "Office 365 E5"
        "ENTERPRISEPREMIUM_FACULTY" = "Office 365 E5 for Faculty"
        "ENTERPRISEPREMIUM_GOV" = "Office 365 G5 GCC"
        "ENTERPRISEPREMIUM_STUDENT" = "Office 365 E5 for Students"
        "ENTERPRISEWITHSCAL" = "Office 365 E4"
        "ENTERPRISEWITHSCAL_FACULTY" = "Office 365 E4 for Faculty"
        "ENTERPRISEWITHSCAL_GOV" = "Office 365 G4 GCC"
        "ENTERPRISEWITHSCAL_STUDENT" = "Office 365 E4 for Students"
        "EOP_ENTERPRISE" = "Exchange Online Protection"
        "EOP_ENTERPRISE_FACULTY" = "Exchange Online Protection for Faculty"
        "EQUIVIO_ANALYTICS" = "Office 365 Advanced eDiscovery"
        "ESKLESSWOFFPACK_GOV" = "Office 365 F3 GCC"
        "EXCHANGE_L_STANDARD" = "Exchange Online (Plan 1)"
        "EXCHANGE_S_ARCHIVE_ADDON_GOV" = "Exchange Online Archiving for Government"
        "EXCHANGE_S_DESKLESS" = "Exchange Online Kiosk"
        "EXCHANGE_S_DESKLESS_GOV" = "Exchange Kiosk GCC"
        "EXCHANGE_S_ENTERPRISE" = "Exchange Online (Plan 2)"
        "EXCHANGE_S_ENTERPRISE_GOV" = "Exchange Online (Plan 2) GCC"
        "EXCHANGE_S_STANDARD" = "Exchange Online (Plan 1)"
        "EXCHANGE_S_STANDARD_GOV" = "Exchange Online (Plan 1) GCC"
        "EXCHANGESTANDARD" = "Exchange Online (Plan 1)"
        "EXCHANGESTANDARD_GOV" = "Exchange Online (Plan 1) GCC"
        "FLOW_FREE" = "Microsoft Flow Free"
        "FLOW_P1" = "Microsoft Flow Plan 1"
        "FLOW_P2" = "Microsoft Flow Plan 2"
        "IDENTITY_THREAT_PROTECTION" = "Microsoft 365 E5 Security"
        "INFORMATION_PROTECTION_COMPLIANCE" = "Microsoft 365 E5 Compliance"
        "INTUNE_A" = "Intune for Education"
        "INTUNE_A_VL" = "Intune for Education VL"
        "INTUNE_O365" = "Intune for Office 365"
        "INTUNE_STORAGE" = "Intune Extra Storage"
        "IT_ACADEMY_AD" = "Microsoft Imagine Academy"
        "LITEPACK" = "Office 365 Small Business"
        "LITEPACK_P2" = "Office 365 Small Business Premium"
        "M365_E3_USGOV_DOD" = "Microsoft 365 E3 for US Government DoD"
        "M365_E3_USGOV_GCCHIGH" = "Microsoft 365 E3 for US Government GCC High"
        "M365_E5_SECURITY_COMPLIANCE" = "Microsoft 365 E5 Security + Compliance"
        "M365_E5_USGOV_DOD" = "Microsoft 365 E5 for US Government DoD"
        "M365_E5_USGOV_GCCHIGH" = "Microsoft 365 E5 for US Government GCC High"
        "M365EDU_A1" = "Microsoft 365 A1 for Students"
        "M365EDU_A3_FACULTY" = "Microsoft 365 A3 for Faculty"
        "M365EDU_A3_STUDENT" = "Microsoft 365 A3 for Students"
        "M365EDU_A5_FACULTY" = "Microsoft 365 A5 for Faculty"
        "M365EDU_A5_STUDENT" = "Microsoft 365 A5 for Students"
        "MCOEV" = "Microsoft Teams Phone System"
        "MCOEV_DOD" = "Microsoft Teams Phone System for DoD"
        "MCOEV_FACULTY" = "Microsoft Teams Phone System for Faculty"
        "MCOEV_GOV" = "Microsoft Teams Phone System for GCC"
        "MCOEV_GCCHIGH" = "Microsoft Teams Phone System for GCC High"
        "MCOEV_STUDENT" = "Microsoft Teams Phone System for Students"
        "MCOEVSMB_1" = "Microsoft Teams Phone System for Small and Medium Business"
        "MCOIMP" = "Skype for Business Online (Plan 1)"
        "MCOPSTN1" = "Microsoft Teams Domestic Calling Plan"
        "MCOPSTN2" = "Microsoft Teams Domestic and International Calling Plan"
        "MCOPSTN_DOD" = "Microsoft Teams Calling for DoD"
        "MCOPSTN_GCCHIGH" = "Microsoft Teams Calling for GCC High"
        "MCOSTANDARD" = "Skype for Business Online (Plan 2)"
        "MCOSTANDARD_GOV" = "Skype for Business Online (Plan 2) for GCC"
        "MCOSTANDARD_MIDMARKET" = "Skype for Business Online (Plan 1)"
        "MDE_SMB" = "Microsoft Defender for Endpoint for SMB"
        "MDM_SALES_COLLABORATION" = "Microsoft Dynamics Marketing Sales Collaboration"
        "MDATP_XPLAT" = "Microsoft Defender for Endpoint"
        "MEE_FACULTY" = "Minecraft Education Edition Faculty"
        "MEE_STUDENT" = "Minecraft Education Edition Student"
        "MICROSOFT_BUSINESS_CENTER" = "Microsoft Business Center"
        "MICROSOFT_REMOTE_ASSIST" = "Microsoft Remote Assist"
        "MICROSOFT_STREAM" = "Microsoft Stream"
        "MICROSOFT_STREAM_O365_E3" = "Microsoft Stream for Office 365 E3"
        "MICROSOFT_STREAM_O365_E5" = "Microsoft Stream for Office 365 E5"
        "MS_TEAMS_IW" = "Microsoft Teams"
        "NBPOSTS" = "Dynamics 365 Business Central Essential"
        "NBPROFESSIONALBASEPLAN" = "Dynamics 365 Business Central Premium"
        "O365_BUSINESS" = "Microsoft 365 Apps for Business"
        "O365_BUSINESS_ESSENTIALS" = "Microsoft 365 Business Basic"
        "O365_BUSINESS_PREMIUM" = "Microsoft 365 Business Standard"
        "OFFICE365_MULTIGEO" = "Office 365 Multi-Geo"
        "OFFICESUBSCRIPTION" = "Microsoft 365 Apps for Enterprise"
        "OFFICESUBSCRIPTION_FACULTY" = "Microsoft 365 Apps for Faculty"
        "OFFICESUBSCRIPTION_GOV" = "Microsoft 365 Apps for GCC"
        "OFFICESUBSCRIPTION_STUDENT" = "Microsoft 365 Apps for Students"
        "PLANNERSTANDALONE" = "Planner Standalone"
        "POWER_BI_ADDON" = "Power BI for Office 365 Add-On"
        "POWER_BI_INDIVIDUAL_USER" = "Power BI Individual User"
        "POWER_BI_PRO" = "Power BI Pro"
        "POWER_BI_STANDARD" = "Power BI (free)"
        "POWERAPPS_INDIVIDUAL_USER" = "PowerApps and Logic Flows"
        "POWERAPPS_VIRAL" = "PowerApps Trial"
        "PROJECT_MADEIRA_PREVIEW_IW_SKU" = "Dynamics 365 for Financials for IWs"
        "PROJECTCLIENT" = "Project for Office 365"
        "PROJECTESSENTIALS" = "Project Online Essentials"
        "PROJECTONLINE_PLAN_1" = "Project Online Premium Without Project Client"
        "PROJECTONLINE_PLAN_1_FACULTY" = "Project Online for Faculty Plan 1"
        "PROJECTONLINE_PLAN_1_STUDENT" = "Project Online for Students Plan 1"
        "PROJECTONLINE_PLAN_2" = "Project Online Premium"
        "PROJECTONLINE_PLAN_2_FACULTY" = "Project Online for Faculty Plan 2"
        "PROJECTONLINE_PLAN_2_STUDENT" = "Project Online for Students Plan 2"
        "PROJECTPREMIUM" = "Project Online Premium"
        "PROJECTPROFESSIONAL" = "Project Online Professional"
        "RIGHTSMANAGEMENT" = "Azure Information Protection Plan 1"
        "RIGHTSMANAGEMENT_ADHOC" = "Rights Management Adhoc"
        "RIGHTSMANAGEMENT_STANDARD_FACULTY" = "Azure Information Protection Premium P1 for Faculty"
        "RIGHTSMANAGEMENT_STANDARD_STUDENT" = "Azure Information Protection Premium P1 for Students"
        "RMS_S_ENTERPRISE" = "Azure Information Protection Plan 2"
        "RMS_S_ENTERPRISE_GOV" = "Azure Information Protection Premium P2 for Government"
        "RMS_S_PREMIUM" = "Azure Information Protection Premium P2"
        "RMS_S_PREMIUM2" = "Azure Information Protection Premium P2"
        "SHAREPOINTDESKLESS" = "SharePoint Online Kiosk"
        "SHAREPOINTDESKLESS_GOV" = "SharePoint Online Kiosk GCC"
        "SHAREPOINTENTERPRISE" = "SharePoint Online (Plan 2)"
        "SHAREPOINTENTERPRISE_GOV" = "SharePoint Online (Plan 2) GCC"
        "SHAREPOINTENTERPRISE_MIDMARKET" = "SharePoint Online (Plan 1)"
        "SHAREPOINTLITE" = "SharePoint Online (Plan 1)"
        "SHAREPOINTSTANDARD" = "SharePoint Online (Plan 1)"
        "SHAREPOINTSTORAGE" = "SharePoint Online Storage"
        "SHAREPOINTWAC" = "Office Online"
        "SHAREPOINTWAC_GOV" = "Office Online for GCC"
        "SMB_APPS" = "Business Apps (free)"
        "SMB_BUSINESS" = "Microsoft 365 Apps for Business"
        "SMB_BUSINESS_ESSENTIALS" = "Microsoft 365 Business Basic"
        "SMB_BUSINESS_PREMIUM" = "Microsoft 365 Business Standard"
        "SPB" = "Microsoft 365 Business Premium"
        "SPE_E3" = "Microsoft 365 E3"
        "SPE_E3_USGOV_DOD" = "Microsoft 365 E3 for US Government DoD"
        "SPE_E3_USGOV_GCCHIGH" = "Microsoft 365 E3 for US Government GCC High"
        "SPE_E5" = "Microsoft 365 E5"
        "SPE_E5_NOPSTNCONF" = "Microsoft 365 E5 without Audio Conferencing"
        "SPE_F1" = "Microsoft 365 F3"
        "SPZA" = "App Connect"
        "SPZA_IW" = "App Connect IW"
        "SQL_IS_SSIM" = "Power BI Information Services"
        "STANDARDPACK" = "Office 365 E1"
        "STANDARDPACK_FACULTY" = "Office 365 E1 for Faculty"
        "STANDARDPACK_GOV" = "Office 365 G1 GCC"
        "STANDARDPACK_STUDENT" = "Office 365 E1 for Students"
        "STANDARDWOFFPACK" = "Office 365 E2"
        "STANDARDWOFFPACK_FACULTY" = "Office 365 E2 for Faculty"
        "STANDARDWOFFPACK_GOV" = "Office 365 G2 GCC"
        "STANDARDWOFFPACK_IW_FACULTY" = "Office 365 Education for Faculty"
        "STANDARDWOFFPACK_IW_STUDENT" = "Office 365 Education for Students"
        "STANDARDWOFFPACK_STUDENT" = "Office 365 E2 for Students"
        "STREAM" = "Microsoft Stream Trial"
        "STREAM_O365_E3" = "Microsoft Stream for Office 365 E3"
        "STREAM_O365_E5" = "Microsoft Stream for Office 365 E5"
        "TEAMS_COMMERCIAL_TRIAL" = "Microsoft Teams Commercial Trial"
        "TEAMS_EXPLORATORY" = "Microsoft Teams Exploratory"
        "THREAT_INTELLIGENCE" = "Microsoft Defender for Office 365 (Plan 2)"
        "VISIO_PLAN1_FACULTY" = "Visio Online Plan 1 for Faculty"
        "VISIO_PLAN1_STUDENT" = "Visio Online Plan 1 for Students"
        "VISIOCLIENT" = "Visio Online Plan 2"
        "VISIOONLINE_PLAN1" = "Visio Online Plan 1"
        "WACONEDRIVESTANDARD" = "OneDrive for Business (Plan 1)"
        "WIN10_PRO_ENT_SUB" = "Windows 10 Enterprise E3"
        "WIN10_VDA_E3" = "Windows 10 Enterprise E3"
        "WIN10_VDA_E5" = "Windows 10 Enterprise E5"
        "WINDOWS_STORE" = "Windows Store for Business"
        "YAMMER_ENTERPRISE" = "Yammer Enterprise"
        "YAMMER_MIDSIZE" = "Yammer"
    }
    
    if ($licenseMap.ContainsKey($SkuPartNumber)) {
        return $licenseMap[$SkuPartNumber]
    }
    else {
        return $SkuPartNumber
    }
}

function Get-UserGroupReport {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object[]]$Users
    )
    
    try {
        Write-Log "Generating user group membership report..."
        
        $report = @()
        
        foreach ($user in $Users) {
            # Get user group memberships
            $groups = Get-MgUserMemberOf -UserId $user.Id -All
            
            if ($null -eq $groups -or $groups.Count -eq 0) {
                # User has no group memberships
                $report += [PSCustomObject]@{
                    DisplayName = $user.DisplayName
                    UserPrincipalName = $user.UserPrincipalName
                    Mail = $user.Mail
                    GroupDisplayName = "No Group Memberships"
                    GroupId = ""
                    GroupDescription = ""
                    GroupType = ""
                    GroupVisibility = ""
                    IsAssignableToRole = ""
                    IsDynamic = ""
                }
            }
            else {
                # User has group memberships
                foreach ($group in $groups) {
                    # Only process groups (not roles)
                    if ($group.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.group') {
                        $groupDetails = Get-MgGroup -GroupId $group.Id -Property Id, DisplayName, Description, 
                                                                      GroupTypes, SecurityEnabled, MailEnabled, 
                                                                      Visibility, IsAssignableToRole, MembershipRule
                        
                        $report += [PSCustomObject]@{
                            DisplayName = $user.DisplayName
                            UserPrincipalName = $user.UserPrincipalName
                            Mail = $user.Mail
                            GroupDisplayName = $groupDetails.DisplayName
                            GroupId = $groupDetails.Id
                            GroupDescription = $groupDetails.Description
                            GroupType = if ($groupDetails.SecurityEnabled -and $groupDetails.MailEnabled) { "Mail-enabled security" } 
                                       elseif ($groupDetails.SecurityEnabled) { "Security" } 
                                       elseif ($groupDetails.MailEnabled) { "Distribution" } 
                                       else { "Unknown" }
                            GroupVisibility = $groupDetails.Visibility
                            IsAssignableToRole = $groupDetails.IsAssignableToRole
                            IsDynamic = -not [string]::IsNullOrEmpty($groupDetails.MembershipRule)
                        }
                    }
                }
            }
        }
        
        Write-Log "Generated user group membership report with $($report.Count) entries"
        return $report
    }
    catch {
        Write-Log "Error generating user group membership report: $_" -Level Error
        return $null
    }
}

function Get-UserRoleReport {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object[]]$Users
    )
    
    try {
        Write-Log "Generating user role assignment report..."
        
        $report = @()
        
        foreach ($user in $Users) {
            # Get user role assignments (direct)
            $directRoleAssignments = Get-MgUserDirectoryRole -UserId $user.Id -All -ErrorAction SilentlyContinue
            
            # Get user memberships (groups and roles)
            $memberships = Get-MgUserMemberOf -UserId $user.Id -All
            
            # Filter for role assignments
            $roleAssignments = $memberships | Where-Object { $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.directoryRole' }
            
            if (($null -eq $directRoleAssignments -or $directRoleAssignments.Count -eq 0) -and 
                ($null -eq $roleAssignments -or $roleAssignments.Count -eq 0)) {
                # User has no role assignments
                $report += [PSCustomObject]@{
                    DisplayName = $user.DisplayName
                    UserPrincipalName = $user.UserPrincipalName
                    Mail = $user.Mail
                    RoleDisplayName = "No Role Assignments"
                    RoleId = ""
                    RoleDescription = ""
                    AssignmentType = ""
                    AssignmentSource = ""
                }
            }
            else {
                # Process direct role assignments
                if ($null -ne $directRoleAssignments -and $directRoleAssignments.Count -gt 0) {
                    foreach ($role in $directRoleAssignments) {
                        $report += [PSCustomObject]@{
                            DisplayName = $user.DisplayName
                            UserPrincipalName = $user.UserPrincipalName
                            Mail = $user.Mail
                            RoleDisplayName = $role.DisplayName
                            RoleId = $role.Id
                            RoleDescription = $role.Description
                            AssignmentType = "Direct"
                            AssignmentSource = "User"
                        }
                    }
                }
                
                # Process role assignments through memberships
                if ($null -ne $roleAssignments -and $roleAssignments.Count -gt 0) {
                    foreach ($role in $roleAssignments) {
                        $roleDetails = Get-MgDirectoryRole -DirectoryRoleId $role.Id -Property Id, DisplayName, Description
                        
                        $report += [PSCustomObject]@{
                            DisplayName = $user.DisplayName
                            UserPrincipalName = $user.UserPrincipalName
                            Mail = $user.Mail
                            RoleDisplayName = $roleDetails.DisplayName
                            RoleId = $roleDetails.Id
                            RoleDescription = $roleDetails.Description
                            AssignmentType = "Inherited"
                            AssignmentSource = "Group" # Would need additional logic to determine the exact group
                        }
                    }
                }
            }
        }
        
        Write-Log "Generated user role assignment report with $($report.Count) entries"
        return $report
    }
    catch {
        Write-Log "Error generating user role assignment report: $_" -Level Error
        return $null
    }
}

function Get-UserAuthMethodReport {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object[]]$Users
    )
    
    try {
        Write-Log "Generating user authentication methods report..."
        
        $report = @()
        
        foreach ($user in $Users) {
            # Get user authentication methods
            $authMethods = Get-MgUserAuthenticationMethod -UserId $user.Id -ErrorAction SilentlyContinue
            
            if ($null -eq $authMethods -or $authMethods.Count -eq 0) {
                # User has no authentication methods
                $report += [PSCustomObject]@{
                    DisplayName = $user.DisplayName
                    UserPrincipalName = $user.UserPrincipalName
                    Mail = $user.Mail
                    AuthMethodType = "No Authentication Methods"
                    AuthMethodDetails = ""
                    IsDefault = ""
                }
            }
            else {
                # Process authentication methods
                foreach ($method in $authMethods) {
                    $methodType = $method.AdditionalProperties.'@odata.type'
                    $methodDetails = ""
                    $isDefault = $false
                    
                    switch -Wildcard ($methodType) {
                        "*microsoftAuthenticatorAuthenticationMethod" {
                            $methodType = "Microsoft Authenticator"
                            $methodDetails = "Device: $($method.AdditionalProperties.displayName)"
                            $isDefault = $method.AdditionalProperties.isDefault
                        }
                        "*phoneAuthenticationMethod" {
                            $methodType = "Phone"
                            $methodDetails = "Number: $($method.AdditionalProperties.phoneNumber), Type: $($method.AdditionalProperties.phoneType)"
                            $isDefault = $method.AdditionalProperties.isDefault
                        }
                        "*passwordAuthenticationMethod" {
                            $methodType = "Password"
                            $methodDetails = "Created: $($method.AdditionalProperties.createdDateTime)"
                        }
                        "*fido2AuthenticationMethod" {
                            $methodType = "FIDO2 Security Key"
                            $methodDetails = "Model: $($method.AdditionalProperties.model)"
                        }
                        "*windowsHelloForBusinessAuthenticationMethod" {
                            $methodType = "Windows Hello for Business"
                            $methodDetails = "Device: $($method.AdditionalProperties.displayName)"
                        }
                        "*emailAuthenticationMethod" {
                            $methodType = "Email"
                            $methodDetails = "Email: $($method.AdditionalProperties.emailAddress)"
                        }
                        "*temporaryAccessPassAuthenticationMethod" {
                            $methodType = "Temporary Access Pass"
                            $methodDetails = "Created: $($method.AdditionalProperties.createdDateTime), Expires: $($method.AdditionalProperties.expiresDateTime)"
                        }
                        "*softwareOathAuthenticationMethod" {
                            $methodType = "Software OATH Token"
                            $methodDetails = "Created: $($method.AdditionalProperties.createdDateTime)"
                        }
                        default {
                            $methodType = $methodType -replace '#microsoft.graph.', ''
                            $methodDetails = "Unknown method details"
                        }
                    }
                    
                    $report += [PSCustomObject]@{
                        DisplayName = $user.DisplayName
                        UserPrincipalName = $user.UserPrincipalName
                        Mail = $user.Mail
                        AuthMethodType = $methodType
                        AuthMethodDetails = $methodDetails
                        IsDefault = $isDefault
                    }
                }
            }
        }
        
        Write-Log "Generated user authentication methods report with $($report.Count) entries"
        return $report
    }
    catch {
        Write-Log "Error generating user authentication methods report: $_" -Level Error
        return $null
    }
}

function Get-UserActivityReport {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object[]]$Users,
        
        [Parameter(Mandatory = $false)]
        [string]$TimeFrame = "Last30Days"
    )
    
    try {
        Write-Log "Generating user activity report for time frame: $TimeFrame..."
        
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
        
        foreach ($user in $Users) {
            # Get user sign-in activity
            $signIns = Get-MgAuditLogSignIn -Filter "userId eq '$($user.Id)' and createdDateTime ge $($startDate.ToString('yyyy-MM-ddTHH:mm:ssZ'))" -Top 100
            
            # Get last sign-in
            $lastSignIn = $signIns | Sort-Object CreatedDateTime -Descending | Select-Object -First 1
            
            # Count sign-ins by status
            $successfulSignIns = ($signIns | Where-Object { $_.Status.ErrorCode -eq 0 }).Count
            $failedSignIns = ($signIns | Where-Object { $_.Status.ErrorCode -ne 0 }).Count
            
            # Get user's last password change
            $userDetails = Get-MgUser -UserId $user.Id -Property Id, DisplayName, UserPrincipalName, Mail, LastPasswordChangeDateTime
            
            # Get user's device count
            $devices = Get-MgUserOwnedDevice -UserId $user.Id -All
            $deviceCount = if ($null -ne $devices) { $devices.Count } else { 0 }
            
            $report += [PSCustomObject]@{
                DisplayName = $user.DisplayName
                UserPrincipalName = $user.UserPrincipalName
                Mail = $user.Mail
                LastSignInDateTime = if ($null -ne $lastSignIn) { $lastSignIn.CreatedDateTime } else { $null }
                LastSignInStatus = if ($null -ne $lastSignIn) { if ($lastSignIn.Status.ErrorCode -eq 0) { "Success" } else { "Failure: $($lastSignIn.Status.FailureReason)" } } else { "No sign-ins" }
                LastSignInLocation = if ($null -ne $lastSignIn -and $null -ne $lastSignIn.Location) { "$($lastSignIn.Location.City), $($lastSignIn.Location.CountryOrRegion)" } else { "Unknown" }
                LastSignInDevice = if ($null -ne $lastSignIn) { $lastSignIn.DeviceDetail.DisplayName } else { "Unknown" }
                LastSignInApplication = if ($null -ne $lastSignIn) { $lastSignIn.AppDisplayName } else { "Unknown" }
                SuccessfulSignInsCount = $successfulSignIns
                FailedSignInsCount = $failedSignIns
                LastPasswordChangeDateTime = $userDetails.LastPasswordChangeDateTime
                DeviceCount = $deviceCount
                TimeFrame = $TimeFrame
            }
        }
        
        Write-Log "Generated user activity report with $($report.Count) entries"
        return $report
    }
    catch {
        Write-Log "Error generating user activity report: $_" -Level Error
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
        [string]$ReportTitle = "User Report"
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
                $Data | Export-Excel -Path $ExportPath -AutoSize -TableName "UserReport" -WorksheetName $ReportTitle
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
    
    # Get filtered users
    $users = Get-FilteredUsers -Filter $Filter -IncludeGuests $IncludeGuests -IncludeServiceAccounts $IncludeServiceAccounts
    
    if ($null -eq $users) {
        Write-Log "No users found with the specified filters" -Level Error
        exit 1
    }
    
    Write-Log "Retrieved $($users.Count) users for reporting"
    
    # Generate reports based on report type
    switch ($ReportType) {
        "Basic" {
            $report = Get-BasicUserReport -Users $users
            $reportTitle = "Basic User Report"
        }
        "Detailed" {
            $report = Get-DetailedUserReport -Users $users
            $reportTitle = "Detailed User Report"
        }
        "Licenses" {
            $report = Get-UserLicenseReport -Users $users
            $reportTitle = "User License Report"
        }
        "Groups" {
            $report = Get-UserGroupReport -Users $users
            $reportTitle = "User Group Membership Report"
        }
        "Roles" {
            $report = Get-UserRoleReport -Users $users
            $reportTitle = "User Role Assignment Report"
        }
        "Auth" {
            $report = Get-UserAuthMethodReport -Users $users
            $reportTitle = "User Authentication Methods Report"
        }
        "Activity" {
            $report = Get-UserActivityReport -Users $users -TimeFrame $TimeFrame
            $reportTitle = "User Activity Report"
        }
        "All" {
            # Generate all reports
            $basicReport = Get-BasicUserReport -Users $users
            $detailedReport = Get-DetailedUserReport -Users $users
            $licenseReport = Get-UserLicenseReport -Users $users
            $groupReport = Get-UserGroupReport -Users $users
            $roleReport = Get-UserRoleReport -Users $users
            $authReport = Get-UserAuthMethodReport -Users $users
            $activityReport = Get-UserActivityReport -Users $users -TimeFrame $TimeFrame
            
            # Export each report
            $exportPathWithoutExtension = [System.IO.Path]::GetDirectoryName($ExportPath) + "\" + [System.IO.Path]::GetFileNameWithoutExtension($ExportPath)
            $extension = [System.IO.Path]::GetExtension($ExportPath)
            
            if ($ExportFormat -eq "Excel") {
                # For Excel, export all reports to different worksheets in the same file
                $basicReport | Export-Excel -Path $ExportPath -AutoSize -TableName "BasicUserReport" -WorksheetName "Basic User Report"
                $detailedReport | Export-Excel -Path $ExportPath -AutoSize -TableName "DetailedUserReport" -WorksheetName "Detailed User Report" -ClearSheet
                $licenseReport | Export-Excel -Path $ExportPath -AutoSize -TableName "UserLicenseReport" -WorksheetName "User License Report" -ClearSheet
                $groupReport | Export-Excel -Path $ExportPath -AutoSize -TableName "UserGroupReport" -WorksheetName "User Group Report" -ClearSheet
                $roleReport | Export-Excel -Path $ExportPath -AutoSize -TableName "UserRoleReport" -WorksheetName "User Role Report" -ClearSheet
                $authReport | Export-Excel -Path $ExportPath -AutoSize -TableName "UserAuthReport" -WorksheetName "User Auth Methods Report" -ClearSheet
                $activityReport | Export-Excel -Path $ExportPath -AutoSize -TableName "UserActivityReport" -WorksheetName "User Activity Report" -ClearSheet
                
                Write-Log "All reports exported successfully to: $ExportPath"
            }
            else {
                # For other formats, export to separate files
                Export-Report -Data $basicReport -ExportPath "$exportPathWithoutExtension-Basic$extension" -ExportFormat $ExportFormat -ReportTitle "Basic User Report"
                Export-Report -Data $detailedReport -ExportPath "$exportPathWithoutExtension-Detailed$extension" -ExportFormat $ExportFormat -ReportTitle "Detailed User Report"
                Export-Report -Data $licenseReport -ExportPath "$exportPathWithoutExtension-Licenses$extension" -ExportFormat $ExportFormat -ReportTitle "User License Report"
                Export-Report -Data $groupReport -ExportPath "$exportPathWithoutExtension-Groups$extension" -ExportFormat $ExportFormat -ReportTitle "User Group Membership Report"
                Export-Report -Data $roleReport -ExportPath "$exportPathWithoutExtension-Roles$extension" -ExportFormat $ExportFormat -ReportTitle "User Role Assignment Report"
                Export-Report -Data $authReport -ExportPath "$exportPathWithoutExtension-Auth$extension" -ExportFormat $ExportFormat -ReportTitle "User Authentication Methods Report"
                Export-Report -Data $activityReport -ExportPath "$exportPathWithoutExtension-Activity$extension" -ExportFormat $ExportFormat -ReportTitle "User Activity Report"
                
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
    Write-Output "User report generation completed successfully"
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
