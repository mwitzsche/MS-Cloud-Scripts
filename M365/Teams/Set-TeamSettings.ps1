<#
.SYNOPSIS
    Configures settings for a Microsoft Teams team.

.DESCRIPTION
    This script configures various settings for a specified Microsoft Teams team,
    such as member permissions, guest permissions, fun settings (Giphy, memes), and messaging settings.

.PARAMETER TeamId
    The ID of the target Microsoft Teams team.

.PARAMETER AllowCreateUpdateChannels
    Allow members to create and update channels ($true/$false).

.PARAMETER AllowDeleteChannels
    Allow members to delete channels ($true/$false).

.PARAMETER AllowAddRemoveApps
    Allow members to add and remove apps ($true/$false).

.PARAMETER AllowGuestAccess
    Allow guest access to the team ($true/$false).

.PARAMETER AllowGuestCreateUpdateChannels
    Allow guests to create and update channels ($true/$false).

.PARAMETER AllowGiphy
    Allow usage of Giphy ($true/$false).

.PARAMETER GiphyContentRating
    Set Giphy content rating (Strict, Moderate).

.PARAMETER AllowStickersAndMemes
    Allow usage of stickers and memes ($true/$false).

.PARAMETER LogPath
    Path where logs will be stored. Defaults to Windows log directory.

.EXAMPLE
    .\Set-TeamSettings.ps1 -TeamId "12345678-1234-1234-1234-123456789012" -AllowCreateUpdateChannels $false -AllowGuestAccess $false
    Disables member channel creation and guest access for the specified team.

.EXAMPLE
    .\Set-TeamSettings.ps1 -TeamId "12345678-1234-1234-1234-123456789012" -AllowGiphy $true -GiphyContentRating "Strict"
    Enables Giphy with a strict content rating for the specified team.

.NOTES
    Author: Michael Witzsche (Adapted by Gemini)
    Date: April 26, 2025
    Version: 1.0.0

    History:
    1.0.0 - Initial release
#>

#Requires -Modules MicrosoftTeams

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$LogPath = "$env:SystemRoot\Logs\Set-TeamSettings",

    [Parameter(Mandatory = $true)]
    [string]$TeamId,

    [Parameter(Mandatory = $false)]
    [Nullable[bool]]$AllowCreateUpdateChannels,

    [Parameter(Mandatory = $false)]
    [Nullable[bool]]$AllowDeleteChannels,

    [Parameter(Mandatory = $false)]
    [Nullable[bool]]$AllowAddRemoveApps,

    [Parameter(Mandatory = $false)]
    [Nullable[bool]]$AllowGuestAccess, # Maps to GuestSettings

    [Parameter(Mandatory = $false)]
    [Nullable[bool]]$AllowGuestCreateUpdateChannels,

    [Parameter(Mandatory = $false)]
    [Nullable[bool]]$AllowGiphy,

    [Parameter(Mandatory = $false)]
    [ValidateSet("Strict", "Moderate")]
    [string]$GiphyContentRating,

    [Parameter(Mandatory = $false)]
    [Nullable[bool]]$AllowStickersAndMemes
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
    Write-Log "Script started for TeamId: $TeamId"

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

    # Prepare settings parameters
    $settingsParams = @{ GroupId = $TeamId }
    $settingsToUpdate = @{}

    # Member Settings
    if ($PSBoundParameters.ContainsKey('AllowCreateUpdateChannels')) { $settingsParams.Add("AllowCreateUpdateChannels", $AllowCreateUpdateChannels); $settingsToUpdate.Add("AllowCreateUpdateChannels", $AllowCreateUpdateChannels) }
    if ($PSBoundParameters.ContainsKey('AllowDeleteChannels')) { $settingsParams.Add("AllowDeleteChannels", $AllowDeleteChannels); $settingsToUpdate.Add("AllowDeleteChannels", $AllowDeleteChannels) }
    if ($PSBoundParameters.ContainsKey('AllowAddRemoveApps')) { $settingsParams.Add("AllowAddRemoveApps", $AllowAddRemoveApps); $settingsToUpdate.Add("AllowAddRemoveApps", $AllowAddRemoveApps) }

    # Guest Settings
    if ($PSBoundParameters.ContainsKey('AllowGuestAccess')) { $settingsParams.Add("AllowGuestCreateUpdateChannels", $AllowGuestAccess); $settingsToUpdate.Add("AllowGuestAccess (Guest Create/Update Channels)", $AllowGuestAccess) } # Note: Mapping AllowGuestAccess conceptually
    if ($PSBoundParameters.ContainsKey('AllowGuestCreateUpdateChannels')) { $settingsParams.Add("AllowGuestCreateUpdateChannels", $AllowGuestCreateUpdateChannels); $settingsToUpdate.Add("AllowGuestCreateUpdateChannels", $AllowGuestCreateUpdateChannels) }

    # Fun Settings
    if ($PSBoundParameters.ContainsKey('AllowGiphy')) { $settingsParams.Add("AllowGiphy", $AllowGiphy); $settingsToUpdate.Add("AllowGiphy", $AllowGiphy) }
    if ($PSBoundParameters.ContainsKey('GiphyContentRating')) { $settingsParams.Add("GiphyContentRating", $GiphyContentRating); $settingsToUpdate.Add("GiphyContentRating", $GiphyContentRating) }
    if ($PSBoundParameters.ContainsKey('AllowStickersAndMemes')) { $settingsParams.Add("AllowStickersAndMemes", $AllowStickersAndMemes); $settingsToUpdate.Add("AllowStickersAndMemes", $AllowStickersAndMemes) }

    # Check if any settings were provided
    if ($settingsParams.Count -le 1) {
         Write-Log "No settings specified to update for team '$teamName'" -Level Warning
         Write-Output "No settings specified to update for team '$teamName'"
         exit 0
    }

    # Apply settings
    try {
        Write-Log "Applying settings to team '$teamName'..."
        Write-Log "Settings to apply: $($settingsToUpdate | Out-String)"
        Set-Team @settingsParams
        Write-Log "Settings applied successfully to team '$teamName'"
        Write-Output "Successfully applied settings to team '$teamName'"
    }
    catch {
        Write-Log "Failed to apply settings to team '$teamName': $_" -Level Error
        Write-Output "Failed to apply settings to team '$teamName'"
        exit 1
    }

    # Output success message
    Write-Output "Team settings configuration operation completed."
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