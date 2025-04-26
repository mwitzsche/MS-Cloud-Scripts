# Demo Tenant Setup Script - README

## Overview

The `New-DemoTenant.ps1` script automates the creation of a complete fictional company environment in a Microsoft 365 trial tenant. This script is designed for IT administrators, consultants, and trainers who need to quickly set up a realistic demo environment for testing, training, or demonstration purposes.

## Features

- **Complete Tenant Setup**: Creates a fully functional Microsoft 365 tenant with departments, users, groups, and license assignments
- **Realistic Company Structure**: Establishes a fictional company with IT, Management, HR, and Production departments
- **Comprehensive User Profiles**: Creates 15 fictional users with realistic names, job titles, and department assignments
- **License Management**: Assigns three types of licenses to users:
  - Office 365 E5 without Teams (15 licenses)
  - Teams Enterprise Trial (15 licenses)
  - Enterprise Mobility + Security E5 (15 licenses)
- **Group Organization**: Creates department groups and license groups for easy management
- **Detailed Reporting**: Generates a comprehensive report of all created resources, including user credentials

## Requirements

### PowerShell Modules

The script requires the following PowerShell modules:
- Microsoft.Graph.Authentication
- Microsoft.Graph.Identity.DirectoryManagement
- Microsoft.Graph.Users
- Microsoft.Graph.Groups
- Microsoft.Graph.Users.Actions
- Microsoft.Graph.Identity.Governance
- Microsoft.Graph.DeviceManagement
- AzureAD

You can install these modules using:

```powershell
Install-Module Microsoft.Graph -Force
Install-Module AzureAD -Force
```

### Permissions

The account used to run the script must have Global Administrator permissions in the Microsoft 365 tenant.

### Microsoft 365 Trial Tenant

Before running the script, you need to create a Microsoft 365 trial tenant:

1. Go to [Microsoft 365 Developer Program](https://developer.microsoft.com/en-us/microsoft-365/dev-program)
2. Sign up for a developer account if you don't have one
3. Create a new sandbox/trial tenant
4. Note the tenant domain (e.g., contoso.onmicrosoft.com) and admin credentials

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| TenantName | String | Yes | The name of the fictional company/tenant (e.g., "Contoso") |
| TenantDomain | String | Yes | The domain name for the tenant (e.g., "contoso.onmicrosoft.com") |
| GlobalAdminUsername | String | Yes | The username for the global admin account |
| GlobalAdminPassword | SecureString | Yes | The password for the global admin account |
| CountryCode | String | No | The two-letter country code for the tenant and users (default: "US") |
| UserPasswordPrefix | String | No | Prefix for generated user passwords (default: "Demo@") |
| LogPath | String | No | Path where logs will be stored (default: Windows log directory) |

## Usage

### Basic Usage

```powershell
.\New-DemoTenant.ps1 -TenantName "Contoso" -TenantDomain "contoso.onmicrosoft.com" -GlobalAdminUsername "admin" -GlobalAdminPassword (ConvertTo-SecureString "P@ssw0rd123" -AsPlainText -Force)
```

### Advanced Usage

```powershell
.\New-DemoTenant.ps1 -TenantName "Contoso" -TenantDomain "contoso.onmicrosoft.com" -GlobalAdminUsername "admin" -GlobalAdminPassword (ConvertTo-SecureString "P@ssw0rd123" -AsPlainText -Force) -CountryCode "DE" -UserPasswordPrefix "ContosoDemo@" -LogPath "C:\Logs\DemoTenant"
```

## What Gets Created

### Departments
- IT Department
- Management Department
- HR Department
- Production Department

### Users (15 total)
- **IT Department (4 users)**
  - John Smith (IT Director)
  - Emily Johnson (System Administrator)
  - Michael Brown (Network Engineer)
  - David Wilson (Security Analyst)

- **Management Department (3 users)**
  - Sarah Davis (CEO)
  - Robert Miller (CFO)
  - Jennifer Taylor (COO)

- **HR Department (3 users)**
  - Lisa Anderson (HR Director)
  - Thomas Martinez (HR Manager)
  - Jessica Garcia (Recruiter)

- **Production Department (5 users)**
  - Daniel Rodriguez (Production Manager)
  - Christopher Lee (Quality Assurance)
  - Matthew Walker (Production Supervisor)
  - Amanda Hall (Production Planner)
  - James Wright (Logistics Coordinator)

### Groups
- Department groups (IT Department, Management Department, etc.)
- License groups (Office 365 E5 Users, Teams Enterprise Trial Users, etc.)
- All Users group

### Licenses
- Office 365 E5 without Teams (ENTERPRISEPREMIUM_NOPSTNCONF)
- Teams Enterprise Trial (TEAMS_COMMERCIAL_TRIAL)
- Enterprise Mobility + Security E5 (EMSPREMIUM)

## Output

The script generates a detailed report file in the specified log directory with information about:
- Tenant details
- Created departments
- Created groups
- Created users (including credentials)
- Assigned licenses

This report is valuable for accessing the demo environment after setup.

## Logging

The script creates detailed logs in the specified log directory (or Windows log directory by default). These logs include:
- Connection status
- Resource creation events
- License assignments
- Errors and warnings

## Troubleshooting

### Common Issues

1. **Module Installation Errors**
   - Ensure you're running PowerShell as an administrator
   - Use `Install-Module Microsoft.Graph -Force -AllowClobber` to resolve conflicts

2. **Authentication Errors**
   - Verify the admin credentials are correct
   - Ensure the admin account has Global Administrator permissions

3. **License Assignment Failures**
   - Verify the tenant has the required licenses available
   - Check that the user's UsageLocation is set correctly

### Getting Help

If you encounter issues:
1. Check the log files for detailed error messages
2. Verify all prerequisites are met
3. Run the script with verbose output: `.\New-DemoTenant.ps1 -Verbose [other parameters]`

## Customization

The script can be customized by modifying the following sections:

- **Departments**: Modify the `$departments` array to change department names and user distribution
- **Users**: Edit the `$users` array to change user names, departments, and job titles
- **Licenses**: Adjust the `$licenseSkus` array to change license types and quantities

## Security Considerations

- The script generates and stores passwords in plain text in the report file
- For production use, consider implementing more secure password handling
- Delete the report file or store it securely after use

## Author

**Author:** Michael Witzsche  
**Date:** April 26, 2025  
**Version:** 1.0.0

## License

This script is provided "as is" with no warranties. Use at your own risk.

---

*Note: This script is intended for creating demo environments only and should not be used to configure production tenants without appropriate modifications and security considerations.*
