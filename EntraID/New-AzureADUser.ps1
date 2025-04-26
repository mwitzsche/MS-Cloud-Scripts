<#
.SYNOPSIS
    Creates a new user in Azure Active Directory.

.DESCRIPTION
    This script creates a new user in Azure Active Directory with specified parameters
    including display name, user principal name, password, and department.
    It includes options for enabling or disabling the account and forcing password change.

.PARAMETER DisplayName
    The display name for the new user.

.PARAMETER UserPrincipalName
    The user principal name (UPN) for the new user. This should be in email format.

.PARAMETER Password
    The initial password for the new user.

.PARAMETER Department
    The department the user belongs to.

.PARAMETER Enabled
    Whether the user account should be enabled upon creation.

.PARAMETER ForceChangePasswordNextLogin
    Whether the user should be required to change their password at next login.

.PARAMETER LogPath
    Path where logs will be stored. Defaults to Windows log directory.

.EXAMPLE
    .\New-AzureADUser.ps1 -DisplayName "John Doe" -UserPrincipalName "john.doe@contoso.com" -Password "P@ssw0rd123" -Department "IT" -Enabled $true -ForceChangePasswordNextLogin $true
    Creates a new enabled user named John Doe in the IT department with the specified UPN and password, requiring password change at next login.

.NOTES
    Author: Michael Witzsche
    Date: April 26, 2025
    Version: 1.1
#>

#Requires -Modules Az.Accounts, Az.Resources, Microsoft.Graph.Users

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$LogPath = "$env:SystemRoot\Logs\New-AzureADUser",
    
    [Parameter(Mandatory = $true)]
    [string]$DisplayName,
    
    [Parameter(Mandatory = $true)]
    [string]$UserPrincipalName,
    
    [Parameter(Mandatory = $true)]
    [string]$Password,
    
    [Parameter(Mandatory = $false)]
    [string]$Department = "",
    
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
        Connect-MgGraph -Scopes "User.ReadWrite.All", "Directory.ReadWrite.All" -ErrorAction Stop
        
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

function Connect-ToAzure {
    [CmdletBinding()]
    param()
    
    try {
        # Check if already connected
        $context = Get-AzContext
        if ($null -ne $context) {
            Write-Log "Already connected to Azure as $($context.Account.Id)"
            return $true
        }
        
        # Connect to Azure
        Write-Log "Connecting to Azure..."
        Connect-AzAccount -ErrorAction Stop
        
        # Verify connection
        $context = Get-AzContext
        if ($null -eq $context) {
            Write-Log "Failed to connect to Azure" -Level Error
            return $false
        }
        
        Write-Log "Successfully connected to Azure as $($context.Account.Id)"
        return $true
    }
    catch {
        Write-Log "Error connecting to Azure: $_" -Level Error
        return $false
    }
}
#endregion

#region Main Script
try {
    # Script start
    Write-Log "Script started with parameters: DisplayName=$DisplayName, UserPrincipalName=$UserPrincipalName, Department=$Department, Enabled=$Enabled, ForceChangePasswordNextLogin=$ForceChangePasswordNextLogin"
    
    # Connect to Azure and Microsoft Graph
    $connectedToAzure = Connect-ToAzure
    if (-not $connectedToAzure) {
        Write-Log "Cannot proceed without Azure connection" -Level Error
        exit 1
    }
    
    $connectedToGraph = Connect-ToMSGraph
    if (-not $connectedToGraph) {
        Write-Log "Cannot proceed without Microsoft Graph connection" -Level Error
        exit 1
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
    
    # Add department if specified
    if (-not [string]::IsNullOrEmpty($Department)) {
        $userParams.Department = $Department
    }
    
    # Create the user
    try {
        Write-Log "Creating new user $DisplayName with UPN $UserPrincipalName..."
        $newUser = New-MgUser @userParams
        
        Write-Log "User created successfully with ID: $($newUser.Id)"
        
        # Output user details
        Write-Output "User created successfully:"
        Write-Output "  Display Name: $($newUser.DisplayName)"
        Write-Output "  User Principal Name: $($newUser.UserPrincipalName)"
        Write-Output "  Object ID: $($newUser.Id)"
        Write-Output "  Account Enabled: $($newUser.AccountEnabled)"
        
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
    # No specific cleanup needed
    Write-Log "Script execution completed"
}
#endregion
