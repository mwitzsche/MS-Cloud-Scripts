<#
.SYNOPSIS
    Manages Microsoft Teams channels (create, delete, update).

.DESCRIPTION
    This script creates, deletes, or updates channels within a specified Microsoft Teams team.
    It supports creating standard and private channels, setting descriptions, and managing channel settings.

.PARAMETER Action
    The action to perform (Create, Delete, Update).

.PARAMETER TeamId
    The ID of the target Microsoft Teams team.

.PARAMETER ChannelName
    The display name of the channel to manage.

.PARAMETER NewChannelName
    The new display name for the channel (used with Update action).

.PARAMETER Description
    The description for the channel (used with Create or Update action).

.PARAMETER MembershipType
    The membership type for the channel (Standard or Private). Default is Standard.

.PARAMETER IsFavoriteByDefault
    Whether the channel should be favorited by default for team members (used with Create action).

.PARAMETER LogPath
    Path where logs will be stored. Defaults to Windows log directory.

.EXAMPLE
    .\Manage-TeamChannel.ps1 -Action Create -TeamId "12345678-1234-1234-1234-123456789012" -ChannelName "Project Alpha" -Description "Channel for Project Alpha discussions"
    Creates a new standard channel named "Project Alpha" in the specified team.

.EXAMPLE
    .\Manage-TeamChannel.ps1 -Action Delete -TeamId "12345678-1234-1234-1234-123456789012" -ChannelName "Old Project Channel"
    Deletes the channel named "Old Project Channel" from the specified team.

.NOTES
    Author: Michael Witzsche
    Date: April 26, 2025
    Version: 1.0.0

    History:
    1.0.0 - Initial release
#>

#Requires -Modules MicrosoftTeams, Microsoft.Graph.Groups, Microsoft.Graph.Authentication

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$LogPath = "$env:SystemRoot\Logs\Manage-TeamChannel",

    [Parameter(Mandatory = $true)]
    [ValidateSet("Create", "Delete", "Update")]
    [string]$Action,

    [Parameter(Mandatory = $true)]
    [string]$TeamId,

    [Parameter(Mandatory = $true)]
    [string]$ChannelName,

    [Parameter(Mandatory = $false)]
    [string]$NewChannelName = "",

    [Parameter(Mandatory = $false)]
    [string]$Description = "",

    [Parameter(Mandatory = $false)]
    [ValidateSet("Standard", "Private")]
    [string]$MembershipType = "Standard",

    [Parameter(Mandatory = $false)]
    [bool]$IsFavoriteByDefault = $false
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

#endregion

#region Main Script
try {
    # Script start
    Write-Log "Script started with parameters: Action=$Action, TeamId=$TeamId, ChannelName=$ChannelName"

    # Connect to Microsoft Teams
    $connectedToTeams = Connect-ToMicrosoftTeams
    if (-not $connectedToTeams) {
        Write-Log "Cannot proceed without Microsoft Teams connection" -Level Error
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
    try {
        switch ($Action) {
            "Create" {
                Write-Log "Creating channel '$ChannelName' in team '$teamName'..."
                $params = @{
                    GroupId = $TeamId
                    DisplayName = $ChannelName
                    MembershipType = $MembershipType
                }
                if (-not [string]::IsNullOrEmpty($Description)) {
                    $params.Description = $Description
                }
                if ($IsFavoriteByDefault) {
                    $params.IsFavoriteByDefault = $true
                }

                $newChannel = New-TeamChannel @params
                Write-Log "Channel '$ChannelName' created successfully with ID: $($newChannel.Id)"
                Write-Output "Successfully created channel '$ChannelName' in team '$teamName'"
            }
            "Delete" {
                Write-Log "Deleting channel '$ChannelName' from team '$teamName'..."
                Remove-TeamChannel -GroupId $TeamId -DisplayName $ChannelName -Force
                Write-Log "Channel '$ChannelName' deleted successfully"
                Write-Output "Successfully deleted channel '$ChannelName' from team '$teamName'"
            }
            "Update" {
                Write-Log "Updating channel '$ChannelName' in team '$teamName'..."
                $params = @{
                    GroupId = $TeamId
                    CurrentName = $ChannelName
                }
                if (-not [string]::IsNullOrEmpty($NewChannelName)) {
                    $params.NewName = $NewChannelName
                    Write-Log "Setting new name: $NewChannelName"
                }
                 if (-not [string]::IsNullOrEmpty($Description)) {
                    $params.Description = $Description
                    Write-Log "Setting new description: $Description"
                }

                if ($params.Count -gt 2) { # Check if there are updates to apply
                    Set-TeamChannel @params
                    Write-Log "Channel '$ChannelName' updated successfully"
                    Write-Output "Successfully updated channel '$ChannelName' in team '$teamName'"
                } else {
                     Write-Log "No updates specified for channel '$ChannelName'" -Level Warning
                     Write-Output "No updates specified for channel '$ChannelName'"
                }
            }
        }
    }
    catch {
        Write-Log "Failed to perform action '$Action' on channel '$ChannelName' in team '$teamName': $_" -Level Error
        Write-Output "Failed action '$Action' on channel '$ChannelName' in team '$teamName'"
        exit 1
    }

    # Output success message
    Write-Output "Team channel management operation completed."
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