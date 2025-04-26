<#
.SYNOPSIS
    Creates a new Azure AD group.

.DESCRIPTION
    This script creates a new Azure Active Directory group with specified parameters
    including display name, description, group type, and membership type.
    It supports both security and Microsoft 365 groups, as well as dynamic and assigned membership types.

.PARAMETER DisplayName
    The display name for the new group.

.PARAMETER Description
    The description for the new group.

.PARAMETER GroupType
    The type of group to create (Security or Microsoft365).

.PARAMETER MembershipType
    The membership type for the group (Assigned or Dynamic).

.PARAMETER MailNickname
    The mail nickname for the group. If not specified, it will be derived from the display name.

.PARAMETER DynamicMembershipRule
    The rule for dynamic membership. Required if MembershipType is Dynamic.

.PARAMETER LogPath
    Path where logs will be stored. Defaults to Windows log directory.

.EXAMPLE
    .\New-AzureADGroup.ps1 -DisplayName "IT Department" -Description "All IT staff" -GroupType Security -MembershipType Assigned
    Creates a new security group with assigned membership for the IT department.

.EXAMPLE
    .\New-AzureADGroup.ps1 -DisplayName "All Windows 10 Devices" -Description "Dynamic group for Windows 10 devices" -GroupType Security -MembershipType Dynamic -DynamicMembershipRule "(device.operatingSystem -eq ""Windows"") and (device.operatingSystemVersion -startsWith ""10"")"
    Creates a new dynamic security group that includes all Windows 10 devices.

.NOTES
    Author: Michael Witzsche
    Date: April 26, 2025
    Version: 1.1
#>

#Requires -Modules Az.Accounts, Microsoft.Graph.Groups

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$LogPath = "$env:SystemRoot\Logs\New-AzureADGroup",
    
    [Parameter(Mandatory = $true)]
    [string]$DisplayName,
    
    [Parameter(Mandatory = $false)]
    [string]$Description = "",
    
    [Parameter(Mandatory = $true)]
    [ValidateSet("Security", "Microsoft365")]
    [string]$GroupType,
    
    [Parameter(Mandatory = $true)]
    [ValidateSet("Assigned", "Dynamic")]
    [string]$MembershipType,
    
    [Parameter(Mandatory = $false)]
    [string]$MailNickname = "",
    
    [Parameter(Mandatory = $false)]
    [string]$DynamicMembershipRule = ""
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
            $graphGroup = Get-MgGroup -Top 1 -ErrorAction Stop
            Write-Log "Already connected to Microsoft Graph"
            return $true
        }
        catch {
            # Not connected, proceed with connection
        }
        
        # Connect to Microsoft Graph with required scopes
        Write-Log "Connecting to Microsoft Graph..."
        Connect-MgGraph -Scopes "Group.ReadWrite.All", "Directory.ReadWrite.All" -ErrorAction Stop
        
        # Verify connection
        try {
            $graphGroup = Get-MgGroup -Top 1 -ErrorAction Stop
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
#endregion

#region Main Script
try {
    # Script start
    Write-Log "Script started with parameters: DisplayName=$DisplayName, GroupType=$GroupType, MembershipType=$MembershipType"
    
    # Connect to Microsoft Graph
    $connectedToGraph = Connect-ToMSGraph
    if (-not $connectedToGraph) {
        Write-Log "Cannot proceed without Microsoft Graph connection" -Level Error
        exit 1
    }
    
    # Validate parameters
    if ($MembershipType -eq "Dynamic" -and [string]::IsNullOrEmpty($DynamicMembershipRule)) {
        Write-Log "DynamicMembershipRule is required when MembershipType is Dynamic" -Level Error
        exit 1
    }
    
    # Generate mail nickname if not provided
    if ([string]::IsNullOrEmpty($MailNickname)) {
        # Remove spaces and special characters
        $MailNickname = $DisplayName -replace '[^a-zA-Z0-9]', ''
        Write-Log "Generated mail nickname: $MailNickname"
    }
    
    # Check if group already exists
    Write-Log "Checking if group $DisplayName already exists..."
    try {
        $existingGroup = Get-MgGroup -Filter "displayName eq '$DisplayName'" -ErrorAction SilentlyContinue
        if ($null -ne $existingGroup) {
            Write-Log "Group $DisplayName already exists. Cannot create duplicate group." -Level Error
            exit 1
        }
    }
    catch {
        Write-Log "Error checking for existing group: $_" -Level Warning
        # Continue as this might be a permission issue or transient error
    }
    
    # Prepare group parameters
    $groupParams = @{
        DisplayName = $DisplayName
        Description = $Description
        MailNickname = $MailNickname
    }
    
    # Set group type
    if ($GroupType -eq "Security") {
        $groupParams.SecurityEnabled = $true
        $groupParams.MailEnabled = $false
        Write-Log "Creating security group"
    }
    else {
        $groupParams.SecurityEnabled = $false
        $groupParams.MailEnabled = $true
        $groupParams.GroupTypes = @("Unified")
        Write-Log "Creating Microsoft 365 group"
    }
    
    # Set membership type
    if ($MembershipType -eq "Dynamic") {
        $groupParams.GroupTypes += "DynamicMembership"
        $groupParams.MembershipRule = $DynamicMembershipRule
        $groupParams.MembershipRuleProcessingState = "On"
        Write-Log "Setting dynamic membership with rule: $DynamicMembershipRule"
    }
    
    # Create the group
    try {
        Write-Log "Creating new group $DisplayName..."
        $newGroup = New-MgGroup @groupParams
        
        Write-Log "Group created successfully with ID: $($newGroup.Id)"
        
        # Output group details
        Write-Output "Group created successfully:"
        Write-Output "  Display Name: $($newGroup.DisplayName)"
        Write-Output "  Description: $($newGroup.Description)"
        Write-Output "  Group Type: $GroupType"
        Write-Output "  Membership Type: $MembershipType"
        Write-Output "  Object ID: $($newGroup.Id)"
        
        return $newGroup
    }
    catch {
        Write-Log "Failed to create group: $_" -Level Error
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
