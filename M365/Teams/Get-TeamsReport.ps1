<#
.SYNOPSIS
    Generates comprehensive reports about Microsoft Teams teams and their usage.

.DESCRIPTION
    This script generates detailed reports about Microsoft Teams, including team details,
    membership, channel information, activity, and settings. Reports can be filtered
    by various criteria and exported in multiple formats.

.PARAMETER ReportType
    The type of Teams report to generate (Basic, Membership, Channels, Activity, Settings, All).

.PARAMETER Filter
    Hashtable of filters to apply to the report (e.g. @{Visibility="Private"; Status="Active"}).

.PARAMETER TimeFrame
    The time frame for activity data (Last7Days, Last30Days, Last90Days, LastYear).

.PARAMETER IncludeArchived
    Whether to include archived teams in the report.

.PARAMETER ExportPath
    The path where the report will be saved.

.PARAMETER ExportFormat
    The format of the export file (CSV, JSON, Excel, HTML).

.PARAMETER LogPath
    Path where logs will be stored. Defaults to Windows log directory.

.EXAMPLE
    .\Get-TeamsReport.ps1 -ReportType Membership -ExportPath "C:\Reports\TeamsMembership.csv" -ExportFormat CSV
    Generates a team membership report and exports it to CSV format.

.EXAMPLE
    .\Get-TeamsReport.ps1 -ReportType Activity -TimeFrame Last90Days -Filter @{Visibility="Private"} -ExportPath "C:\Reports\PrivateTeamActivity.xlsx" -ExportFormat Excel
    Generates an activity report for private teams over the last 90 days and exports it to Excel format.

.NOTES
    Author: Michael Witzsche (Adapted by Gemini)
    Date: April 26, 2025
    Version: 1.0.0

    History:
    1.0.0 - Initial release
#>

#Requires -Modules MicrosoftTeams, Microsoft.Graph.Reports, Microsoft.Graph.Groups, Microsoft.Graph.Authentication, ImportExcel

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$LogPath = "$env:SystemRoot\Logs\Get-TeamsReport",

    [Parameter(Mandatory = $true)]
    [ValidateSet("Basic", "Membership", "Channels", "Activity", "Settings", "All")]
    [string]$ReportType,

    [Parameter(Mandatory = $false)]
    [hashtable]$Filter = @{},

    [Parameter(Mandatory = $false)]
    [ValidateSet("Last7Days", "Last30Days", "Last90Days", "LastYear")]
    [string]$TimeFrame = "Last30Days",

    [Parameter(Mandatory = $false)]
    [bool]$IncludeArchived = $false,

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
            "Team.ReadBasic.All",
            "TeamSettings.Read.All",
            "TeamMember.Read.All",
            "Channel.ReadBasic.All",
            "Reports.Read.All",
            "Group.Read.All",
            "Directory.Read.All"
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

function Get-FilteredTeams {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [hashtable]$Filter = @{},

        [Parameter(Mandatory = $false)]
        [bool]$IncludeArchived = $false
    )

    try {
        Write-Log "Retrieving teams with applied filters..."

        # Get all teams
        $teams = Get-MgTeam -All

        if (-not $IncludeArchived) {
            $teams = $teams | Where-Object { $_.IsArchived -eq $false }
        }

        # Apply custom filters
        if ($Filter.Count -gt 0) {
            $filteredTeams = $teams | Where-Object {
                $match = $true
                foreach ($key in $Filter.Keys) {
                    $value = $Filter[$key]
                    if ($_.AdditionalProperties[$key] -notlike "*$value*" -and $_.$key -notlike "*$value*") {
                        $match = $false
                        break
                    }
                }
                $match
            }
            $teams = $filteredTeams
        }

        if ($null -eq $teams -or $teams.Count -eq 0) {
            Write-Log "No teams found with the specified filters" -Level Warning
            return $null
        }

        Write-Log "Retrieved $($teams.Count) teams"
        return $teams
    }
    catch {
        Write-Log "Error retrieving teams: $_" -Level Error
        return $null
    }
}

function Get-BasicTeamReport {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object[]]$Teams
    )

    try {
        Write-Log "Generating basic team report..."

        $report = @()

        foreach ($team in $Teams) {
            $report += [PSCustomObject]@{
                TeamId = $team.Id
                DisplayName = $team.DisplayName
                Description = $team.Description
                Visibility = $team.Visibility
                IsArchived = $team.IsArchived
                CreatedDateTime = $team.CreatedDateTime
                WebUrl = $team.WebUrl
            }
        }

        Write-Log "Generated basic team report with $($report.Count) entries"
        return $report
    }
    catch {
        Write-Log "Error generating basic team report: $_" -Level Error
        return $null
    }
}

function Get-TeamMembershipReport {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object[]]$Teams
    )

    try {
        Write-Log "Generating team membership report..."

        $report = @()

        foreach ($team in $Teams) {
            Write-Log "Getting members for team: $($team.DisplayName)"
            # Get owners
            $owners = Get-MgTeamOwner -TeamId $team.Id
            # Get members
            $members = Get-MgTeamMember -TeamId $team.Id

            $ownerList = ($owners.AdditionalProperties.displayName -join "; ")
            $memberList = ($members.AdditionalProperties.displayName -join "; ")
            $ownerCount = if ($null -ne $owners) { $owners.Count } else { 0 }
            $memberCount = if ($null -ne $members) { $members.Count } else { 0 }

            $report += [PSCustomObject]@{
                TeamId = $team.Id
                DisplayName = $team.DisplayName
                OwnerCount = $ownerCount
                MemberCount = $memberCount
                Owners = $ownerList
                Members = $memberList
            }
        }

        Write-Log "Generated team membership report with $($report.Count) entries"
        return $report
    }
    catch {
        Write-Log "Error generating team membership report: $_" -Level Error
        return $null
    }
}

function Get-TeamChannelReport {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object[]]$Teams
    )

    try {
        Write-Log "Generating team channel report..."

        $report = @()

        foreach ($team in $Teams) {
            Write-Log "Getting channels for team: $($team.DisplayName)"
            # Get channels
            $channels = Get-MgTeamChannel -TeamId $team.Id -All

            if ($null -eq $channels -or $channels.Count -eq 0) {
                $report += [PSCustomObject]@{
                    TeamId = $team.Id
                    DisplayName = $team.DisplayName
                    ChannelName = "No Channels Found (excluding General)"
                    ChannelId = ""
                    ChannelDescription = ""
                    MembershipType = ""
                    ChannelWebUrl = ""
                }
            }
            else {
                foreach ($channel in $channels) {
                     $report += [PSCustomObject]@{
                        TeamId = $team.Id
                        DisplayName = $team.DisplayName
                        ChannelName = $channel.DisplayName
                        ChannelId = $channel.Id
                        ChannelDescription = $channel.Description
                        MembershipType = $channel.MembershipType
                        ChannelWebUrl = $channel.WebUrl
                    }
                }
            }
        }

        Write-Log "Generated team channel report with $($report.Count) entries"
        return $report
    }
    catch {
        Write-Log "Error generating team channel report: $_" -Level Error
        return $null
    }
}

function Get-TeamActivityReport {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object[]]$Teams,

        [Parameter(Mandatory = $false)]
        [string]$TimeFrame = "Last30Days"
    )

    try {
        Write-Log "Generating team activity report for time frame: $TimeFrame..."

        # Calculate date based on time frame
        $reportDate = (Get-Date).AddDays(-1) # Activity reports are usually available for the previous day
        $period = ""

        switch ($TimeFrame) {
            "Last7Days" { $period = "D7" }
            "Last30Days" { $period = "D30" }
            "Last90Days" { $period = "D90" }
            "LastYear" { $period = "D180" } # Max period for this report is 180 days
            default { $period = "D30" }
        }

         Write-Log "Retrieving Teams activity report for period $period"
         # Note: Specific team activity requires iterating or filtering if available via Graph API
         # Get-MgReportTeamActivity is tenant-wide. Need to filter post-retrieval or use other methods for specific team activity.
         # This example focuses on tenant-wide activity, enhance if specific team activity reporting becomes feasible/needed via Graph.

         $activityReportStream = Get-MgReportTeamActivity -Period $period -Format "csv" -OutFile "$LogPath\temp_activity.csv"
         # Need to read and process the CSV report here.

        $activityData = Import-Csv "$LogPath\temp_activity.csv"
        Remove-Item "$LogPath\temp_activity.csv"

        $report = @()
        # Correlate activityData with the $Teams list if needed

        # Example: Show tenant wide activity for now
         foreach ($entry in $activityData) {
             $report += [PSCustomObject]@{
                 ReportRefreshDate = $entry."Report Refresh Date"
                 TeamId = "Tenant-Wide" # Modify if specific team data can be extracted
                 DisplayName = "Tenant-Wide" # Modify if specific team data can be extracted
                 ActiveUsers = $entry."Active Users"
                 ActiveChannels = $entry."Active Channels"
                 Guests = $entry."Guests"
                 Reactions = $entry."Reactions"
                 MeetingsOrganized = $entry."Meetings Organized"
                 PostMessages = $entry."Post Messages"
                 ChannelMessages = $entry."Channel Messages"
                 ReplyMessages = $entry."Reply Messages"
                 UrgentMessages = $entry."Urgent Messages"
                 ReportPeriod = $entry."Report Period"
             }
         }


        Write-Log "Generated team activity report with $($report.Count) entries"
        return $report
    }
    catch {
        Write-Log "Error generating team activity report: $_" -Level Error
        return $null
    }
}


function Get-TeamSettingsReport {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object[]]$Teams
    )

    try {
        Write-Log "Generating team settings report..."

        $report = @()

        foreach ($team in $Teams) {
            Write-Log "Getting settings for team: $($team.DisplayName)"
            try {
                $settings = Get-MgTeam -TeamId $team.Id -Property MemberSettings,MessagingSettings,FunSettings,GuestSettings

                $report += [PSCustomObject]@{
                    TeamId = $team.Id
                    DisplayName = $team.DisplayName
                    AllowCreateUpdateChannels = $settings.MemberSettings.AllowCreateUpdateChannels
                    AllowDeleteChannels = $settings.MemberSettings.AllowDeleteChannels
                    AllowAddRemoveApps = $settings.MemberSettings.AllowAddRemoveApps
                    AllowCreateUpdateRemoveTabs = $settings.MemberSettings.AllowCreateUpdateRemoveTabs
                    AllowCreateUpdateRemoveConnectors = $settings.MemberSettings.AllowCreateUpdateRemoveConnectors
                    AllowUserEditMessages = $settings.MessagingSettings.AllowUserEditMessages
                    AllowUserDeleteMessages = $settings.MessagingSettings.AllowUserDeleteMessages
                    AllowOwnerDeleteMessages = $settings.MessagingSettings.AllowOwnerDeleteMessages
                    AllowTeamMentions = $settings.MessagingSettings.AllowTeamMentions
                    AllowChannelMentions = $settings.MessagingSettings.AllowChannelMentions
                    AllowGiphy = $settings.FunSettings.AllowGiphy
                    GiphyContentRating = $settings.FunSettings.GiphyContentRating
                    AllowStickersAndMemes = $settings.FunSettings.AllowStickersAndMemes
                    AllowCustomMemes = $settings.FunSettings.AllowCustomMemes
                    AllowGuestsToCreateUpdateChannels = $settings.GuestSettings.AllowCreateUpdateChannels
                    AllowGuestsToDeleteChannels = $settings.GuestSettings.AllowDeleteChannels
                }
            }
            catch {
                 Write-Log "Error getting settings for team $($team.DisplayName): $_" -Level Warning
                 $report += [PSCustomObject]@{
                    TeamId = $team.Id
                    DisplayName = $team.DisplayName
                    AllowCreateUpdateChannels = "Error"
                    # Fill other fields with "Error" or appropriate placeholder
                 }
            }
        }

        Write-Log "Generated team settings report with $($report.Count) entries"
        return $report
    }
    catch {
        Write-Log "Error generating team settings report: $_" -Level Error
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
        [string]$ReportTitle = "Teams Report"
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
                $Data | Export-Excel -Path $ExportPath -AutoSize -TableName "TeamsReport" -WorksheetName $ReportTitle
            }
            "HTML" {
                $htmlHeader = @"
<!DOCTYPE html>
<html>
<head>
    <title>$ReportTitle</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #464775; } /* Teams Purple */
        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
        th { background-color: #464775; color: white; text-align: left; padding: 8px; }
        td { border: 1px solid #ddd; padding: 8px; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        tr:hover { background-color: #e1e1e1; }
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

    # Get filtered teams
    $teams = Get-FilteredTeams -Filter $Filter -IncludeArchived $IncludeArchived

    if ($null -eq $teams) {
        Write-Log "No teams found with the specified filters" -Level Error
        exit 1
    }

    Write-Log "Retrieved $($teams.Count) teams for reporting"

    # Generate reports based on report type
    switch ($ReportType) {
        "Basic" {
            $report = Get-BasicTeamReport -Teams $teams
            $reportTitle = "Basic Teams Report"
        }
        "Membership" {
            $report = Get-TeamMembershipReport -Teams $teams
            $reportTitle = "Teams Membership Report"
        }
        "Channels" {
            $report = Get-TeamChannelReport -Teams $teams
            $reportTitle = "Teams Channel Report"
        }
        "Activity" {
            $report = Get-TeamActivityReport -Teams $teams -TimeFrame $TimeFrame
            $reportTitle = "Teams Activity Report"
        }
        "Settings" {
            $report = Get-TeamSettingsReport -Teams $teams
            $reportTitle = "Teams Settings Report"
        }
        "All" {
            # Generate all reports
            $basicReport = Get-BasicTeamReport -Teams $teams
            $membershipReport = Get-TeamMembershipReport -Teams $teams
            $channelReport = Get-TeamChannelReport -Teams $teams
            $activityReport = Get-TeamActivityReport -Teams $teams -TimeFrame $TimeFrame
            $settingsReport = Get-TeamSettingsReport -Teams $teams

            # Export each report
            $exportPathWithoutExtension = [System.IO.Path]::GetDirectoryName($ExportPath) + "\" + [System.IO.Path]::GetFileNameWithoutExtension($ExportPath)
            $extension = [System.IO.Path]::GetExtension($ExportPath)

            if ($ExportFormat -eq "Excel") {
                # For Excel, export all reports to different worksheets in the same file
                $basicReport | Export-Excel -Path $ExportPath -AutoSize -TableName "BasicReport" -WorksheetName "Basic Teams Report"
                $membershipReport | Export-Excel -Path $ExportPath -AutoSize -TableName "MembershipReport" -WorksheetName "Membership Report" -ClearSheet
                $channelReport | Export-Excel -Path $ExportPath -AutoSize -TableName "ChannelReport" -WorksheetName "Channel Report" -ClearSheet
                $activityReport | Export-Excel -Path $ExportPath -AutoSize -TableName "ActivityReport" -WorksheetName "Activity Report" -ClearSheet
                $settingsReport | Export-Excel -Path $ExportPath -AutoSize -TableName "SettingsReport" -WorksheetName "Settings Report" -ClearSheet

                Write-Log "All reports exported successfully to: $ExportPath"
            }
            else {
                # For other formats, export to separate files
                Export-Report -Data $basicReport -ExportPath "$exportPathWithoutExtension-Basic$extension" -ExportFormat $ExportFormat -ReportTitle "Basic Teams Report"
                Export-Report -Data $membershipReport -ExportPath "$exportPathWithoutExtension-Membership$extension" -ExportFormat $ExportFormat -ReportTitle "Teams Membership Report"
                Export-Report -Data $channelReport -ExportPath "$exportPathWithoutExtension-Channels$extension" -ExportFormat $ExportFormat -ReportTitle "Teams Channel Report"
                Export-Report -Data $activityReport -ExportPath "$exportPathWithoutExtension-Activity$extension" -ExportFormat $ExportFormat -ReportTitle "Teams Activity Report"
                Export-Report -Data $settingsReport -ExportPath "$exportPathWithoutExtension-Settings$extension" -ExportFormat $ExportFormat -ReportTitle "Teams Settings Report"

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
    Write-Output "Teams report generation completed successfully"
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