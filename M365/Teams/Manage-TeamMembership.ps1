<#
.SYNOPSIS
    Manages Microsoft Teams team membership (owners and members).

.DESCRIPTION
    This script adds or removes owners and members from a specified Microsoft Teams team.
    It requires the Team ID and the User Principal Names (UPNs) of the users to add or remove.

.PARAMETER Action
    The action to perform (AddOwner, RemoveOwner, AddMember, RemoveMember).

.PARAMETER TeamId
    The ID of the target Microsoft Teams team.

.PARAMETER UserPrincipalNames
    An array of user principal names (UPNs) to add or remove.

.PARAMETER LogPath
    Path where logs will be stored. Defaults to Windows log directory.

.EXAMPLE
    .\Manage-TeamMembership.ps1 -Action AddMember -TeamId "12345678-1234-1234-1234-123456789012" -UserPrincipalNames @("user1@contoso.com", "user2@contoso.com")
    Adds user1 and user2 as members to the specified team.

.EXAMPLE
    .\Manage-TeamMembership.ps1 -Action RemoveOwner -TeamId "12345678-1234-1234-1234-123456789012" -UserPrincipalNames @("admin@contoso.com")
    Removes admin@contoso.com as an owner from the specified team.

.NOTES
    Author: Michael Witzsche (Adapted by Gemini)
    Date: April 26, 2025
    Version: 1.0.0

    History:
    1.0.0 - Initial release
#>

#Requires -Modules MicrosoftTeams, Microsoft.Graph.Users, Microsoft.Graph.Authentication

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$LogPath = "$env:SystemRoot\Logs\Manage-TeamMembership",

    [Parameter(Mandatory = $true)]
    [ValidateSet("AddOwner", "RemoveOwner", "AddMember", "RemoveMember")]
    [string]$Action,

    [Parameter(Mandatory = $true)]
    [string]$TeamId,

    [Parameter(Mandatory = $true)]
    [string[]]$UserPrincipalNames
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
            "GroupMember.ReadWrite.All",
            "TeamMember.ReadWrite.All"
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

#endregion

#region Main Script
try {
    # Script start
    Write-Log "Script started with parameters: Action=$Action, TeamId=$TeamId"

    # Connect to Microsoft Teams and Graph
    $connectedToTeams = Connect-ToMicrosoftTeams
    $connectedToGraph = Connect-ToMicrosoftGraph
    if (-not $connectedToTeams -or -not $connectedToGraph) {
        Write-Log "Cannot proceed without Microsoft Teams and Graph connections" -Level Error
        exit 1
    }

    # Get Team Display Name for logging
    $teamName = ""
    try {
        $team = Get-Team -GroupId $TeamId
        $teamName = $team.DisplayName
    }
    catch {
        Write-Log "Could not retrieve team name for ID $TeamId: $_" -Level Warning
        $teamName = $TeamId # Use ID if name lookup fails
    }


    # Perform the action
    foreach ($upn in $UserPrincipalNames) {
        Write-Log "Processing user: $upn for action: $Action on team: $teamName"

        # Validate user exists
        try {
            $user = Get-MgUser -Filter "userPrincipalName eq '$upn'" -ErrorAction Stop
            if ($null -eq $user) {
                Write-Log "User $upn not found, skipping..." -Level Warning
                continue
            }
            $userId = $user.Id
        }
        catch {
            Write-Log "Error validating user $upn: $_, skipping..." -Level Error
            continue
        }

        # Execute action
        try {
            switch ($Action) {
                "AddOwner" {
                    Add-TeamUser -GroupId $TeamId -User $upn -Role Owner
                    Write-Log "Added $upn as owner to team $teamName"
                }
                "RemoveOwner" {
                    Remove-TeamUser -GroupId $TeamId -User $upn -Role Owner
                    Write-Log "Removed $upn as owner from team $teamName"
                }
                "AddMember" {
                    Add-TeamUser -GroupId $TeamId -User $upn -Role Member
                    Write-Log "Added $upn as member to team $teamName"
                }
                "RemoveMember" {
                    Remove-TeamUser -GroupId $TeamId -User $upn -Role Member
                    Write-Log "Removed $upn as member from team $teamName"
                }
            }
            Write-Output "Successfully performed action '$Action' for user '$upn' on team '$teamName'"
        }
        catch {
            Write-Log "Failed to perform action '$Action' for user '$upn' on team '$teamName': $_" -Level Error
            Write-Output "Failed action '$Action' for user '$upn' on team '$teamName'"
        }
    }

    # Output success message
    Write-Output "Team membership management operation completed."
}
catch {
    Write-Log "Script execution failed: $_" -Level Error
    exit 1
}
finally {
    # Disconnect from services if needed
    # Disconnect-MicrosoftTeams -ErrorAction SilentlyContinue
    Write-Log "Script execution completed"
}
#endregion