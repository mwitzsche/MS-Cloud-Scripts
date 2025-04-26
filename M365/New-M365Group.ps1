<#
.SYNOPSIS
    Creates a new Microsoft 365 group.

.DESCRIPTION
    This script creates a new Microsoft 365 group with specified parameters
    including display name, description, owners, members, and visibility settings.
    It supports creating both Microsoft 365 Groups and Teams-enabled groups.

.PARAMETER DisplayName
    The display name for the new group.

.PARAMETER Description
    The description for the new group.

.PARAMETER MailNickname
    The mail nickname for the group. If not specified, it will be derived from the display name.

.PARAMETER Owners
    An array of user principal names (UPNs) to be added as owners of the group.

.PARAMETER Members
    An array of user principal names (UPNs) to be added as members of the group.

.PARAMETER Visibility
    The visibility of the group (Private, Public, or HiddenMembership).

.PARAMETER AllowExternalSenders
    Whether to allow people outside the organization to send emails to the group.

.PARAMETER AutoSubscribeNewMembers
    Whether to automatically subscribe new members to group conversations.

.PARAMETER CreateTeam
    Whether to create a Microsoft Teams team for this group.

.PARAMETER LogPath
    Path where logs will be stored. Defaults to Windows log directory.

.EXAMPLE
    .\New-M365Group.ps1 -DisplayName "Marketing Team" -Description "Group for Marketing department" -Owners @("admin@contoso.com") -Members @("user1@contoso.com", "user2@contoso.com") -Visibility "Private" -CreateTeam $true
    Creates a new private Microsoft 365 group for the Marketing department with the specified owners and members, and creates a Teams team for it.

.NOTES
    Author: Michael Witzsche
    Date: April 26, 2025
    Version: 1.1
#>

#Requires -Modules Microsoft.Graph.Groups, Microsoft.Graph.Users, MicrosoftTeams

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$LogPath = "$env:SystemRoot\Logs\New-M365Group",
    
    [Parameter(Mandatory = $true)]
    [string]$DisplayName,
    
    [Parameter(Mandatory = $false)]
    [string]$Description = "",
    
    [Parameter(Mandatory = $false)]
    [string]$MailNickname = "",
    
    [Parameter(Mandatory = $false)]
    [string[]]$Owners = @(),
    
    [Parameter(Mandatory = $false)]
    [string[]]$Members = @(),
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Private", "Public", "HiddenMembership")]
    [string]$Visibility = "Private",
    
    [Parameter(Mandatory = $false)]
    [bool]$AllowExternalSenders = $false,
    
    [Parameter(Mandatory = $false)]
    [bool]$AutoSubscribeNewMembers = $true,
    
    [Parameter(Mandatory = $false)]
    [bool]$CreateTeam = $false,
    
    [Parameter(Mandatory = $false)]
    [bool]$HideFromAddressLists = $false
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
        Connect-MgGraph -Scopes "Group.ReadWrite.All", "User.ReadWrite.All", "Directory.ReadWrite.All" -ErrorAction Stop
        
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

function Connect-ToMicrosoftTeams {
    [CmdletBinding()]
    param()
    
    try {
        # Check if already connected
        try {
            $team = Get-Team -ErrorAction Stop
            Write-Log "Already connected to Microsoft Teams"
            return $true
        }
        catch {
            # Not connected, proceed with connection
        }
        
        # Connect to Microsoft Teams
        Write-Log "Connecting to Microsoft Teams..."
        Connect-MicrosoftTeams -ErrorAction Stop
        
        # Verify connection
        try {
            $team = Get-Team -ErrorAction Stop
            Write-Log "Successfully connected to Microsoft Teams"
            return $true
        }
        catch {
            Write-Log "Failed to verify Microsoft Teams connection" -Level Error
            return $false
        }
    }
    catch {
        Write-Log "Error connecting to Microsoft Teams: $_" -Level Error
        return $false
    }
}
#endregion

#region Main Script
try {
    # Script start
    Write-Log "Script started with parameters: DisplayName=$DisplayName, Visibility=$Visibility, CreateTeam=$CreateTeam"
    
    # Connect to Microsoft Graph
    $connectedToGraph = Connect-ToMSGraph
    if (-not $connectedToGraph) {
        Write-Log "Cannot proceed without Microsoft Graph connection" -Level Error
        exit 1
    }
    
    # Connect to Microsoft Teams if needed
    if ($CreateTeam) {
        $connectedToTeams = Connect-ToMicrosoftTeams
        if (-not $connectedToTeams) {
            Write-Log "Cannot create Teams team without Microsoft Teams connection" -Level Error
            exit 1
        }
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
    
    # Validate owners and members
    if ($Owners.Count -gt 0) {
        Write-Log "Validating owners..."
        foreach ($owner in $Owners) {
            try {
                $user = Get-MgUser -Filter "userPrincipalName eq '$owner'" -ErrorAction Stop
                if ($null -eq $user) {
                    Write-Log "Owner $owner not found" -Level Warning
                }
            }
            catch {
                Write-Log "Error validating owner $owner: $_" -Level Warning
            }
        }
    }
    
    if ($Members.Count -gt 0) {
        Write-Log "Validating members..."
        foreach ($member in $Members) {
            try {
                $user = Get-MgUser -Filter "userPrincipalName eq '$member'" -ErrorAction Stop
                if ($null -eq $user) {
                    Write-Log "Member $member not found" -Level Warning
                }
            }
            catch {
                Write-Log "Error validating member $member: $_" -Level Warning
            }
        }
    }
    
    # Prepare group parameters
    $groupParams = @{
        DisplayName = $DisplayName
        Description = $Description
        MailEnabled = $true
        MailNickname = $MailNickname
        SecurityEnabled = $false
        GroupTypes = @("Unified")
        Visibility = $Visibility
    }
    
    # Create the group
    try {
        Write-Log "Creating new Microsoft 365 group $DisplayName..."
        $newGroup = New-MgGroup @groupParams
        
        Write-Log "Group created successfully with ID: $($newGroup.Id)"
        
        # Add owners
        if ($Owners.Count -gt 0) {
            Write-Log "Adding owners to the group..."
            foreach ($owner in $Owners) {
                try {
                    $user = Get-MgUser -Filter "userPrincipalName eq '$owner'" -ErrorAction Stop
                    if ($null -ne $user) {
                        New-MgGroupOwnerByRef -GroupId $newGroup.Id -BodyParameter @{
                            "@odata.id" = "https://graph.microsoft.com/v1.0/users/$($user.Id)"
                        } -ErrorAction Stop
                        Write-Log "Added $owner as owner"
                    }
                }
                catch {
                    Write-Log "Failed to add owner $owner: $_" -Level Error
                }
            }
        }
        
        # Add members
        if ($Members.Count -gt 0) {
            Write-Log "Adding members to the group..."
            foreach ($member in $Members) {
                try {
                    $user = Get-MgUser -Filter "userPrincipalName eq '$member'" -ErrorAction Stop
                    if ($null -ne $user) {
                        New-MgGroupMemberByRef -GroupId $newGroup.Id -BodyParameter @{
                            "@odata.id" = "https://graph.microsoft.com/v1.0/users/$($user.Id)"
                        } -ErrorAction Stop
                        Write-Log "Added $member as member"
                    }
                }
                catch {
                    Write-Log "Failed to add member $member: $_" -Level Error
                }
            }
        }
        
        # Configure group settings
        try {
            Write-Log "Configuring group settings..."
            
            $groupSettings = @{
                AllowExternalSenders = $AllowExternalSenders
                AutoSubscribeNewMembers = $AutoSubscribeNewMembers
                HideFromAddressLists = $HideFromAddressLists
            }
            
            Update-MgGroup -GroupId $newGroup.Id -BodyParameter $groupSettings -ErrorAction Stop
            Write-Log "Group settings configured successfully"
        }
        catch {
            Write-Log "Failed to configure group settings: $_" -Level Error
        }
        
        # Create Teams team if requested
        if ($CreateTeam) {
            Write-Log "Creating Microsoft Teams team for the group..."
            
            try {
                # Wait for group to be fully provisioned
                Write-Log "Waiting for group to be fully provisioned before creating team..."
                Start-Sleep -Seconds 30
                
                # Create team
                $team = New-Team -GroupId $newGroup.Id -ErrorAction Stop
                Write-Log "Teams team created successfully with ID: $($team.GroupId)"
            }
            catch {
                Write-Log "Failed to create Teams team: $_" -Level Error
            }
        }
        
        # Output group details
        Write-Output "Microsoft 365 Group created successfully:"
        Write-Output "  Display Name: $($newGroup.DisplayName)"
        Write-Output "  Description: $($newGroup.Description)"
        Write-Output "  Mail Nickname: $($newGroup.MailNickname)"
        Write-Output "  Visibility: $Visibility"
        Write-Output "  Group ID: $($newGroup.Id)"
        
        if ($CreateTeam -and $null -ne $team) {
            Write-Output "  Teams Team Created: Yes"
            Write-Output "  Teams Team ID: $($team.GroupId)"
        }
        
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
    # Disconnect from services
    try {
        Disconnect-MicrosoftTeams -ErrorAction SilentlyContinue
    }
    catch {
        # Ignore disconnection errors
    }
    
    Write-Log "Script execution completed"
}
#endregion
