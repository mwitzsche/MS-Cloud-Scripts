<#
.SYNOPSIS
    Creates a new Microsoft 365 user.

.DESCRIPTION
    This script creates a new user in Microsoft 365 with specified parameters
    including display name, user principal name, password, and license assignment.
    It includes options for enabling or disabling the account and forcing password change.

.PARAMETER DisplayName
    The display name for the new user.

.PARAMETER UserPrincipalName
    The user principal name (UPN) for the new user. This should be in email format.

.PARAMETER Password
    The initial password for the new user.

.PARAMETER Department
    The department the user belongs to.

.PARAMETER JobTitle
    The job title for the user.

.PARAMETER Location
    The office location for the user.

.PARAMETER MobilePhone
    The mobile phone number for the user.

.PARAMETER LicenseSkuId
    The SKU ID of the license to assign to the user (e.g., "contoso:ENTERPRISEPACK").

.PARAMETER UsageLocation
    The two-letter country code for the user's usage location (required for license assignment).

.PARAMETER Enabled
    Whether the user account should be enabled upon creation.

.PARAMETER ForceChangePasswordNextLogin
    Whether the user should be required to change their password at next login.

.PARAMETER LogPath
    Path where logs will be stored. Defaults to Windows log directory.

.EXAMPLE
    .\New-M365User.ps1 -DisplayName "John Doe" -UserPrincipalName "john.doe@contoso.com" -Password "P@ssw0rd123" -Department "IT" -JobTitle "IT Specialist" -Location "New York" -UsageLocation "US" -LicenseSkuId "contoso:ENTERPRISEPACK" -Enabled $true -ForceChangePasswordNextLogin $true
    Creates a new enabled user named John Doe in the IT department with the specified UPN, password, and license, requiring password change at next login.

.NOTES
    Author: Michael Witzsche
    Date: April 26, 2025
    Version: 1.1
#>

#Requires -Modules ExchangeOnlineManagement, Microsoft.Graph.Users, Microsoft.Graph.Identity.DirectoryManagement

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$LogPath = "$env:SystemRoot\Logs\New-M365User",
    
    [Parameter(Mandatory = $true)]
    [string]$DisplayName,
    
    [Parameter(Mandatory = $true)]
    [string]$UserPrincipalName,
    
    [Parameter(Mandatory = $true)]
    [string]$Password,
    
    [Parameter(Mandatory = $false)]
    [string]$Department = "",
    
    [Parameter(Mandatory = $false)]
    [string]$JobTitle = "",
    
    [Parameter(Mandatory = $false)]
    [string]$Location = "",
    
    [Parameter(Mandatory = $false)]
    [string]$MobilePhone = "",
    
    [Parameter(Mandatory = $false)]
    [string]$LicenseSkuId = "",
    
    [Parameter(Mandatory = $false)]
    [string]$UsageLocation = "",
    
    [Parameter(Mandatory = $false)]
    [bool]$Enabled = $true,
    
    [Parameter(Mandatory = $false)]
    [bool]$ForceChangePasswordNextLogin = $true
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
        Connect-MgGraph -Scopes "User.ReadWrite.All", "Directory.ReadWrite.All", "Organization.Read.All" -ErrorAction Stop
        
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

function Connect-ToExchangeOnline {
    [CmdletBinding()]
    param()
    
    try {
        # Check if already connected
        try {
            $mailbox = Get-EXOMailbox -ResultSize 1 -ErrorAction Stop
            Write-Log "Already connected to Exchange Online"
            return $true
        }
        catch {
            # Not connected, proceed with connection
        }
        
        # Connect to Exchange Online
        Write-Log "Connecting to Exchange Online..."
        Connect-ExchangeOnline -ErrorAction Stop
        
        # Verify connection
        try {
            $mailbox = Get-EXOMailbox -ResultSize 1 -ErrorAction Stop
            Write-Log "Successfully connected to Exchange Online"
            return $true
        }
        catch {
            Write-Log "Failed to verify Exchange Online connection" -Level Error
            return $false
        }
    }
    catch {
        Write-Log "Error connecting to Exchange Online: $_" -Level Error
        return $false
    }
}
#endregion

#region Main Script
try {
    # Script start
    Write-Log "Script started with parameters: DisplayName=$DisplayName, UserPrincipalName=$UserPrincipalName, Department=$Department, JobTitle=$JobTitle, Location=$Location"
    
    # Connect to Microsoft Graph
    $connectedToGraph = Connect-ToMSGraph
    if (-not $connectedToGraph) {
        Write-Log "Cannot proceed without Microsoft Graph connection" -Level Error
        exit 1
    }
    
    # Connect to Exchange Online if needed
    $connectedToExchange = $true
    if (-not [string]::IsNullOrEmpty($LicenseSkuId)) {
        $connectedToExchange = Connect-ToExchangeOnline
        if (-not $connectedToExchange) {
            Write-Log "Warning: Could not connect to Exchange Online. Mailbox configuration may be limited." -Level Warning
        }
    }
    
    # Check if user already exists
    Write-Log "Checking if user $UserPrincipalName already exists..."
    try {
        $existingUser = Get-MgUser -Filter "userPrincipalName eq '$UserPrincipalName'" -ErrorAction SilentlyContinue
        if ($null -ne $existingUser) {
            Write-Log "User $UserPrincipalName already exists. Cannot create duplicate user." -Level Error
            exit 1
        }
    }
    catch {
        Write-Log "Error checking for existing user: $_" -Level Warning
        # Continue as this might be a permission issue or transient error
    }
    
    # Create password profile
    $passwordProfile = @{
        Password = $Password
        ForceChangePasswordNextSignIn = $ForceChangePasswordNextLogin
    }
    
    # Create user parameters
    $userParams = @{
        DisplayName = $DisplayName
        UserPrincipalName = $UserPrincipalName
        PasswordProfile = $passwordProfile
        AccountEnabled = $Enabled
        MailNickname = ($UserPrincipalName -split '@')[0]
    }
    
    # Add optional parameters if specified
    if (-not [string]::IsNullOrEmpty($Department)) {
        $userParams.Department = $Department
    }
    
    if (-not [string]::IsNullOrEmpty($JobTitle)) {
        $userParams.JobTitle = $JobTitle
    }
    
    if (-not [string]::IsNullOrEmpty($Location)) {
        $userParams.OfficeLocation = $Location
    }
    
    if (-not [string]::IsNullOrEmpty($MobilePhone)) {
        $userParams.MobilePhone = $MobilePhone
    }
    
    # Set usage location if specified (required for license assignment)
    if (-not [string]::IsNullOrEmpty($UsageLocation)) {
        $userParams.UsageLocation = $UsageLocation
    }
    elseif (-not [string]::IsNullOrEmpty($LicenseSkuId)) {
        Write-Log "UsageLocation is required for license assignment. License will not be assigned." -Level Warning
    }
    
    # Create the user
    try {
        Write-Log "Creating new user $DisplayName with UPN $UserPrincipalName..."
        $newUser = New-MgUser @userParams
        
        Write-Log "User created successfully with ID: $($newUser.Id)"
        
        # Assign license if specified and usage location is set
        if (-not [string]::IsNullOrEmpty($LicenseSkuId) -and -not [string]::IsNullOrEmpty($UsageLocation)) {
            Write-Log "Assigning license $LicenseSkuId to user..."
            
            try {
                # Get license details
                $licenseSkus = Get-MgSubscribedSku -All
                $licenseSku = $licenseSkus | Where-Object { $_.SkuPartNumber -eq $LicenseSkuId -or $_.SkuId -eq $LicenseSkuId }
                
                if ($null -eq $licenseSku) {
                    Write-Log "License SKU $LicenseSkuId not found or not available" -Level Error
                }
                else {
                    # Check if license is available
                    if ($licenseSku.PrepaidUnits.Enabled - $licenseSku.ConsumedUnits -le 0) {
                        Write-Log "No available licenses for SKU $LicenseSkuId" -Level Error
                    }
                    else {
                        # Assign license
                        Set-MgUserLicense -UserId $newUser.Id -AddLicenses @{SkuId = $licenseSku.SkuId} -RemoveLicenses @() -ErrorAction Stop
                        Write-Log "License assigned successfully"
                    }
                }
            }
            catch {
                Write-Log "Failed to assign license: $_" -Level Error
            }
        }
        
        # Configure Exchange mailbox if connected to Exchange Online
        if ($connectedToExchange) {
            Write-Log "Configuring Exchange mailbox settings..."
            
            try {
                # Wait for mailbox to be provisioned
                $mailboxProvisioned = $false
                $retryCount = 0
                $maxRetries = 10
                
                while (-not $mailboxProvisioned -and $retryCount -lt $maxRetries) {
                    try {
                        $mailbox = Get-EXOMailbox -Identity $UserPrincipalName -ErrorAction Stop
                        $mailboxProvisioned = $true
                        Write-Log "Mailbox provisioned successfully"
                    }
                    catch {
                        $retryCount++
                        Write-Log "Waiting for mailbox to be provisioned (attempt $retryCount of $maxRetries)..."
                        Start-Sleep -Seconds 10
                    }
                }
                
                if ($mailboxProvisioned) {
                    # Configure mailbox settings
                    Set-EXOMailbox -Identity $UserPrincipalName -EmailAddresses @{Add="smtp:$($UserPrincipalName.Split('@')[0])@$($UserPrincipalName.Split('@')[1])"} -ErrorAction Stop
                    Write-Log "Mailbox configured successfully"
                }
                else {
                    Write-Log "Mailbox not provisioned after $maxRetries attempts" -Level Warning
                }
            }
            catch {
                Write-Log "Error configuring mailbox: $_" -Level Warning
            }
        }
        
        # Output user details
        Write-Output "User created successfully:"
        Write-Output "  Display Name: $($newUser.DisplayName)"
        Write-Output "  User Principal Name: $($newUser.UserPrincipalName)"
        Write-Output "  Object ID: $($newUser.Id)"
        Write-Output "  Account Enabled: $($newUser.AccountEnabled)"
        
        if (-not [string]::IsNullOrEmpty($Department)) {
            Write-Output "  Department: $Department"
        }
        
        if (-not [string]::IsNullOrEmpty($JobTitle)) {
            Write-Output "  Job Title: $JobTitle"
        }
        
        if (-not [string]::IsNullOrEmpty($LicenseSkuId) -and -not [string]::IsNullOrEmpty($UsageLocation)) {
            Write-Output "  License Assigned: $LicenseSkuId"
        }
        
        return $newUser
    }
    catch {
        Write-Log "Failed to create user: $_" -Level Error
        throw $_
    }
}
catch {
    Write-Log "Script execution failed: $_" -Level Error
    exit 1
}
finally {
    # Disconnect from services
    try {
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
    }
    catch {
        # Ignore disconnection errors
    }
    
    Write-Log "Script execution completed"
}
#endregion
