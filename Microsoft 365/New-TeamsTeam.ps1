<#
.SYNOPSIS
    Creates a new Microsoft Teams team.

.DESCRIPTION
    This script creates a new Microsoft Teams team with specified parameters
    including team name, description, visibility, and owners.
    It supports creating teams from scratch or from existing Microsoft 365 groups.

.PARAMETER TeamName
    The name for the new team.

.PARAMETER Description
    The description for the new team.

.PARAMETER Visibility
    The visibility of the team (Private, Public, or HiddenMembership).

.PARAMETER Owners
    An array of user principal names (UPNs) to be added as owners of the team.

.PARAMETER Members
    An array of user principal names (UPNs) to be added as members of the team.

.PARAMETER AllowGuestAccess
    Whether to allow guest access to the team.

.PARAMETER AllowCreateUpdateChannels
    Whether to allow members to create and update channels.

.PARAMETER AllowCreatePrivateChannels
    Whether to allow members to create private channels.

.PARAMETER AllowDeleteChannels
    Whether to allow members to delete channels.

.PARAMETER ExistingGroupId
    The ID of an existing Microsoft 365 group to create the team from. If specified, a new group will not be created.

.PARAMETER Channels
    An array of channel names to create in the team.

.PARAMETER LogPath
    Path where logs will be stored. Defaults to Windows log directory.

.EXAMPLE
    .\New-TeamsTeam.ps1 -TeamName "Marketing Team" -Description "Team for Marketing department" -Visibility "Private" -Owners @("admin@contoso.com") -Members @("user1@contoso.com", "user2@contoso.com") -Channels @("General", "Campaigns", "Events")
    Creates a new private team for the Marketing department with the specified owners, members, and channels.

.NOTES
    Author: Michael Witzsche
    Date: April 26, 2025
    Version: 1.1
#>

#Requires -Modules MicrosoftTeams, Microsoft.Graph.Groups

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$LogPath = "$env:SystemRoot\Logs\New-TeamsTeam",
    
    [Parameter(Mandatory = $true)]
    [string]$TeamName,
    
    [Parameter(Mandatory = $false)]
    [string]$Description = "",
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Private", "Public", "HiddenMembership")]
    [string]$Visibility = "Private",
    
    [Parameter(Mandatory = $false)]
    [string[]]$Owners = @(),
    
    [Parameter(Mandatory = $false)]
    [string[]]$Members = @(),
    
    [Parameter(Mandatory = $false)]
    [bool]$AllowGuestAccess = $true,
    
    [Parameter(Mandatory = $false)]
    [bool]$AllowCreateUpdateChannels = $true,
    
    [Parameter(Mandatory = $false)]
    [bool]$AllowCreatePrivateChannels = $true,
    
    [Parameter(Mandatory = $false)]
    [bool]$AllowDeleteChannels = $false,
    
    [Parameter(Mandatory = $false)]
    [string]$ExistingGroupId = "",
    
    [Parameter(Mandatory = $false)]
    [string[]]$Channels = @()
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
#endregion

#region Main Script
try {
    # Script start
    Write-Log "Script started with parameters: TeamName=$TeamName, Visibility=$Visibility"
    
    # Connect to Microsoft Teams
    $connectedToTeams = Connect-ToMicrosoftTeams
    if (-not $connectedToTeams) {
        Write-Log "Cannot proceed without Microsoft Teams connection" -Level Error
        exit 1
    }
    
    # Connect to Microsoft Graph for user operations
    $connectedToGraph = Connect-ToMSGraph
    if (-not $connectedToGraph) {
        Write-Log "Cannot proceed without Microsoft Graph connection" -Level Error
        exit 1
    }
    
    # Check if team already exists
    Write-Log "Checking if team $TeamName already exists..."
    $existingTeam = Get-Team | Where-Object { $_.DisplayName -eq $TeamName }
    
    if ($null -ne $existingTeam) {
        Write-Log "Team $TeamName already exists. Cannot create duplicate team." -Level Error
        exit 1
    }
    
    # Validate owners
    if ($Owners.Count -eq 0) {
        Write-Log "No owners specified. At least one owner is required." -Level Error
        exit 1
    }
    
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
    
    # Create the team
    try {
        if ([string]::IsNullOrEmpty($ExistingGroupId)) {
            # Create new team from scratch
            Write-Log "Creating new team $TeamName..."
            
            $newTeamParams = @{
                DisplayName = $TeamName
                Description = $Description
                Visibility = $Visibility
                Owner = $Owners[0]  # First owner
            }
            
            $newTeam = New-Team @newTeamParams
            Write-Log "Team created successfully with ID: $($newTeam.GroupId)"
        }
        else {
            # Create team from existing group
            Write-Log "Creating team from existing group $ExistingGroupId..."
            
            # Verify group exists
            try {
                $group = Get-MgGroup -GroupId $ExistingGroupId -ErrorAction Stop
                if ($null -eq $group) {
                    Write-Log "Group $ExistingGroupId not found" -Level Error
                    exit 1
                }
            }
            catch {
                Write-Log "Error finding group $ExistingGroupId: $_" -Level Error
                exit 1
            }
            
            $newTeam = New-Team -GroupId $ExistingGroupId
            Write-Log "Team created successfully from existing group"
        }
        
        # Add additional owners
        if ($Owners.Count -gt 1) {
            Write-Log "Adding additional owners..."
            
            for ($i = 1; $i -lt $Owners.Count; $i++) {
                try {
                    Add-TeamUser -GroupId $newTeam.GroupId -User $Owners[$i] -Role Owner
                    Write-Log "Added $($Owners[$i]) as owner"
                }
                catch {
                    Write-Log "Failed to add owner $($Owners[$i]): $_" -Level Error
                }
            }
        }
        
        # Add members
        if ($Members.Count -gt 0) {
            Write-Log "Adding members..."
            
            foreach ($member in $Members) {
                try {
                    Add-TeamUser -GroupId $newTeam.GroupId -User $member -Role Member
                    Write-Log "Added $member as member"
                }
                catch {
                    Write-Log "Failed to add member $member: $_" -Level Error
                }
            }
        }
        
        # Configure team settings
        Write-Log "Configuring team settings..."
        
        $teamSettings = @{
            GroupId = $newTeam.GroupId
            AllowGiphy = $true
            GiphyContentRating = "Moderate"
            AllowStickersAndMemes = $true
            AllowCustomMemes = $true
            AllowGuestCreateUpdateChannels = $AllowGuestAccess
            AllowGuestDeleteChannels = $false
            AllowCreateUpdateChannels = $AllowCreateUpdateChannels
            AllowDeleteChannels = $AllowDeleteChannels
            AllowAddRemoveApps = $true
            AllowCreateUpdateRemoveTabs = $true
            AllowCreateUpdateRemoveConnectors = $true
            AllowUserEditMessages = $true
            AllowUserDeleteMessages = $true
            AllowOwnerDeleteMessages = $true
            AllowTeamMentions = $true
            AllowChannelMentions = $true
        }
        
        if ($AllowCreatePrivateChannels) {
            $teamSettings.AllowPrivateChannelCreation = $true
        }
        
        Set-Team @teamSettings
        Write-Log "Team settings configured successfully"
        
        # Create channels
        if ($Channels.Count -gt 0) {
            Write-Log "Creating channels..."
            
            foreach ($channel in $Channels) {
                if ($channel -ne "General") {  # General channel is created by default
                    try {
                        New-TeamChannel -GroupId $newTeam.GroupId -DisplayName $channel
                        Write-Log "Created channel: $channel"
                    }
                    catch {
                        Write-Log "Failed to create channel $channel: $_" -Level Error
                    }
                }
            }
        }
        
        # Output team details
        Write-Output "Microsoft Teams team created successfully:"
        Write-Output "  Name: $TeamName"
        Write-Output "  Description: $Description"
        Write-Output "  Visibility: $Visibility"
        Write-Output "  Group ID: $($newTeam.GroupId)"
        Write-Output "  Owners: $($Owners -join ', ')"
        
        if ($Members.Count -gt 0) {
            Write-Output "  Members: $($Members -join ', ')"
        }
        
        if ($Channels.Count -gt 0) {
            Write-Output "  Channels: General, $($Channels -join ', ')"
        }
        else {
            Write-Output "  Channels: General"
        }
        
        return $newTeam
    }
    catch {
        Write-Log "Failed to create team: $_" -Level Error
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
