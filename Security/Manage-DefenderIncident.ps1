<#
.SYNOPSIS
    Manages Microsoft Defender XDR incidents.

.DESCRIPTION
    This script provides comprehensive management capabilities for Microsoft Defender XDR incidents
    including retrieving incident details, updating status, assigning owners, adding comments,
    and generating reports on incident metrics.

.PARAMETER Action
    The action to perform on incidents (Get, Update, Assign, Comment, Report).

.PARAMETER IncidentId
    The ID of the incident to manage. Required for single incident operations.

.PARAMETER Status
    The new status to set for the incident (New, InProgress, Resolved).

.PARAMETER Classification
    The classification for resolving an incident (TruePositive, FalsePositive, Informational).

.PARAMETER AssignedTo
    The user principal name of the person to assign the incident to.

.PARAMETER Comment
    The comment to add to the incident.

.PARAMETER DaysToAnalyze
    The number of days of incident history to analyze for reporting.

.PARAMETER OutputPath
    The path where the report will be saved.

.PARAMETER FilterBySeverity
    Filter incidents by severity (Low, Medium, High, Critical).

.PARAMETER FilterByStatus
    Filter incidents by status (New, InProgress, Resolved).

.PARAMETER LogPath
    Path where logs will be stored. Defaults to Windows log directory.

.EXAMPLE
    .\Manage-DefenderIncident.ps1 -Action Get -IncidentId "12345"
    Retrieves detailed information about the specified incident.

.EXAMPLE
    .\Manage-DefenderIncident.ps1 -Action Update -IncidentId "12345" -Status "Resolved" -Classification "FalsePositive"
    Updates the specified incident to resolved status with a false positive classification.

.EXAMPLE
    .\Manage-DefenderIncident.ps1 -Action Report -DaysToAnalyze 30 -OutputPath "C:\Reports\IncidentReport.csv"
    Generates a report of all incidents from the past 30 days and saves it to the specified path.

.NOTES
    Author: Michael Witzsche
    Date: April 26, 2025
    Version: 1.1
#>

#Requires -Modules Microsoft.Graph.Security

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$LogPath = "$env:SystemRoot\Logs\Manage-DefenderIncident",
    
    [Parameter(Mandatory = $true)]
    [ValidateSet("Get", "Update", "Assign", "Comment", "Report")]
    [string]$Action,
    
    [Parameter(Mandatory = $false)]
    [string]$IncidentId = "",
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("New", "InProgress", "Resolved")]
    [string]$Status = "",
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("TruePositive", "FalsePositive", "Informational", "")]
    [string]$Classification = "",
    
    [Parameter(Mandatory = $false)]
    [string]$AssignedTo = "",
    
    [Parameter(Mandatory = $false)]
    [string]$Comment = "",
    
    [Parameter(Mandatory = $false)]
    [int]$DaysToAnalyze = 30,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "$env:USERPROFILE\Desktop\DefenderXDR_Incident_Report_$(Get-Date -Format 'yyyyMMdd').csv",
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Low", "Medium", "High", "Critical", "")]
    [string]$FilterBySeverity = "",
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("New", "InProgress", "Resolved", "")]
    [string]$FilterByStatus = ""
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
            $graphIncident = Get-MgSecurityIncident -Top 1 -ErrorAction Stop
            Write-Log "Already connected to Microsoft Graph"
            return $true
        }
        catch {
            # Not connected, proceed with connection
        }
        
        # Connect to Microsoft Graph with required scopes
        Write-Log "Connecting to Microsoft Graph..."
        Connect-MgGraph -Scopes "SecurityIncident.Read.All", "SecurityIncident.ReadWrite.All" -ErrorAction Stop
        
        # Verify connection
        try {
            $graphIncident = Get-MgSecurityIncident -Top 1 -ErrorAction Stop
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

function Format-IncidentDetails {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Incident
    )
    
    # Create a custom object with the incident details
    $incidentDetails = [PSCustomObject]@{
        IncidentId = $Incident.Id
        Title = $Incident.Title
        Description = $Incident.Description
        Severity = $Incident.Severity
        Status = $Incident.Status
        Classification = $Incident.Classification
        AssignedTo = $Incident.AssignedTo
        CreatedDateTime = $Incident.CreatedDateTime
        LastUpdateDateTime = $Incident.LastUpdateDateTime
        AlertCount = $Incident.AlertsCount
        Comments = $Incident.Comments | ForEach-Object { "$($_.CreatedBy.User.DisplayName) ($($_.CreatedDateTime)): $($_.Comment)" } -join "`n"
        Tags = $Incident.Tags -join ", "
    }
    
    return $incidentDetails
}

function Export-IncidentDetails {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object[]]$Incidents,
        
        [Parameter(Mandatory = $true)]
        [string]$ExportPath
    )
    
    try {
        # Create an array to hold the formatted incident details
        $incidentDetailsList = @()
        
        # Format each incident
        foreach ($incident in $Incidents) {
            $incidentDetails = Format-IncidentDetails -Incident $incident
            $incidentDetailsList += $incidentDetails
        }
        
        # Export to CSV
        $incidentDetailsList | Export-Csv -Path $ExportPath -NoTypeInformation
        Write-Log "Exported incident details to: $ExportPath"
        
        return $true
    }
    catch {
        Write-Log "Error exporting incident details: $_" -Level Error
        return $false
    }
}

function Get-IncidentMetrics {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object[]]$Incidents
    )
    
    # Calculate metrics
    $totalIncidents = $Incidents.Count
    $bySeverity = $Incidents | Group-Object -Property Severity | Select-Object Name, Count
    $byStatus = $Incidents | Group-Object -Property Status | Select-Object Name, Count
    $byClassification = $Incidents | Where-Object { $_.Status -eq "Resolved" } | Group-Object -Property Classification | Select-Object Name, Count
    
    # Calculate average time to resolve
    $resolvedIncidents = $Incidents | Where-Object { $_.Status -eq "Resolved" }
    $avgTimeToResolve = if ($resolvedIncidents.Count -gt 0) {
        $totalHours = 0
        foreach ($incident in $resolvedIncidents) {
            $created = [DateTime]$incident.CreatedDateTime
            $resolved = [DateTime]$incident.LastUpdateDateTime
            $totalHours += ($resolved - $created).TotalHours
        }
        [math]::Round($totalHours / $resolvedIncidents.Count, 2)
    } else { 0 }
    
    # Calculate metrics by day
    $byDay = $Incidents | Group-Object -Property { ([DateTime]$_.CreatedDateTime).ToString("yyyy-MM-dd") } | 
        Select-Object @{Name="Date"; Expression={$_.Name}}, @{Name="Count"; Expression={$_.Count}} |
        Sort-Object -Property Date
    
    # Return metrics
    $metrics = [PSCustomObject]@{
        TotalIncidents = $totalIncidents
        BySeverity = $bySeverity
        ByStatus = $byStatus
        ByClassification = $byClassification
        AverageTimeToResolveHours = $avgTimeToResolve
        IncidentsByDay = $byDay
    }
    
    return $metrics
}
#endregion

#region Main Script
try {
    # Script start
    Write-Log "Script started with parameters: Action=$Action, IncidentId=$IncidentId"
    
    # Connect to Microsoft Graph
    $connectedToGraph = Connect-ToMSGraph
    if (-not $connectedToGraph) {
        Write-Log "Cannot proceed without Microsoft Graph connection" -Level Error
        exit 1
    }
    
    # Validate parameters based on action
    switch ($Action) {
        "Get" {
            if ([string]::IsNullOrEmpty($IncidentId) -and [string]::IsNullOrEmpty($FilterBySeverity) -and [string]::IsNullOrEmpty($FilterByStatus)) {
                Write-Log "Either IncidentId or filter parameters must be provided for Get action" -Level Error
                exit 1
            }
        }
        "Update" {
            if ([string]::IsNullOrEmpty($IncidentId)) {
                Write-Log "IncidentId is required for Update action" -Level Error
                exit 1
            }
            if ([string]::IsNullOrEmpty($Status) -and [string]::IsNullOrEmpty($Classification)) {
                Write-Log "Either Status or Classification must be provided for Update action" -Level Error
                exit 1
            }
            if ($Status -eq "Resolved" -and [string]::IsNullOrEmpty($Classification)) {
                Write-Log "Classification is required when resolving an incident" -Level Error
                exit 1
            }
        }
        "Assign" {
            if ([string]::IsNullOrEmpty($IncidentId) -or [string]::IsNullOrEmpty($AssignedTo)) {
                Write-Log "IncidentId and AssignedTo are required for Assign action" -Level Error
                exit 1
            }
        }
        "Comment" {
            if ([string]::IsNullOrEmpty($IncidentId) -or [string]::IsNullOrEmpty($Comment)) {
                Write-Log "IncidentId and Comment are required for Comment action" -Level Error
                exit 1
            }
        }
        "Report" {
            # No additional validation needed
        }
    }
    
    # Perform the action
    switch ($Action) {
        "Get" {
            if (-not [string]::IsNullOrEmpty($IncidentId)) {
                # Get a single incident
                try {
                    $incident = Get-MgSecurityIncident -IncidentId $IncidentId -ErrorAction Stop
                    
                    if ($null -eq $incident) {
                        Write-Log "Incident not found: $IncidentId" -Level Error
                        exit 1
                    }
                    
                    # Format and display incident details
                    $incidentDetails = Format-IncidentDetails -Incident $incident
                    
                    # Output incident details
                    Write-Output "Incident Details:"
                    $incidentDetails | Format-List
                    
                    # Export to file if specified
                    if (-not [string]::IsNullOrEmpty($OutputPath)) {
                        Export-IncidentDetails -Incidents @($incident) -ExportPath $OutputPath
                    }
                }
                catch {
                    Write-Log "Error retrieving incident: $_" -Level Error
                    exit 1
                }
            }
            else {
                # Get multiple incidents based on filters
                try {
                    # Calculate date range
                    $startDate = (Get-Date).AddDays(-$DaysToAnalyze)
                    $filter = "createdDateTime ge $($startDate.ToString('yyyy-MM-ddT00:00:00Z'))"
                    
                    # Add severity filter if specified
                    if (-not [string]::IsNullOrEmpty($FilterBySeverity)) {
                        $filter += " and severity eq '$FilterBySeverity'"
                    }
                    
                    # Add status filter if specified
                    if (-not [string]::IsNullOrEmpty($FilterByStatus)) {
                        $filter += " and status eq '$FilterByStatus'"
                    }
                    
                    Write-Log "Retrieving incidents with filter: $filter"
                    $incidents = Get-MgSecurityIncident -All -Filter $filter
                    
                    if ($null -eq $incidents -or $incidents.Count -eq 0) {
                        Write-Log "No incidents found matching the specified filters" -Level Warning
                        exit 0
                    }
                    
                    Write-Log "Found $($incidents.Count) incidents matching the specified filters"
                    
                    # Export to file if specified
                    if (-not [string]::IsNullOrEmpty($OutputPath)) {
                        Export-IncidentDetails -Incidents $incidents -ExportPath $OutputPath
                        Write-Output "Exported $($incidents.Count) incidents to $OutputPath"
                    }
                    else {
                        # Display summary of incidents
                        Write-Output "Incident Summary:"
                        $incidents | Select-Object Id, Title, Severity, Status, CreatedDateTime | Format-Table -AutoSize
                    }
                }
                catch {
                    Write-Log "Error retrieving incidents: $_" -Level Error
                    exit 1
                }
            }
        }
        "Update" {
            try {
                # Get the incident
                $incident = Get-MgSecurityIncident -IncidentId $IncidentId -ErrorAction Stop
                
                if ($null -eq $incident) {
                    Write-Log "Incident not found: $IncidentId" -Level Error
                    exit 1
                }
                
                # Prepare update parameters
                $updateParams = @{}
                
                if (-not [string]::IsNullOrEmpty($Status)) {
                    $updateParams.Status = $Status
                }
                
                if (-not [string]::IsNullOrEmpty($Classification)) {
                    $updateParams.Classification = $Classification
                }
                
                # Update the incident
                Write-Log "Updating incident $IncidentId: Status=$Status, Classification=$Classification"
                Update-MgSecurityIncident -IncidentId $IncidentId -BodyParameter $updateParams
                
                Write-Log "Incident updated successfully"
                Write-Output "Incident $IncidentId updated successfully"
                
                # Get updated incident details
                $updatedIncident = Get-MgSecurityIncident -IncidentId $IncidentId
                $incidentDetails = Format-IncidentDetails -Incident $updatedIncident
                
                # Output updated incident details
                Write-Output "Updated Incident Details:"
                $incidentDetails | Format-List
            }
            catch {
                Write-Log "Error updating incident: $_" -Level Error
                exit 1
            }
        }
        "Assign" {
            try {
                # Get the incident
                $incident = Get-MgSecurityIncident -IncidentId $IncidentId -ErrorAction Stop
                
                if ($null -eq $incident) {
                    Write-Log "Incident not found: $IncidentId" -Level Error
                    exit 1
                }
                
                # Update the incident
                Write-Log "Assigning incident $IncidentId to $AssignedTo"
                Update-MgSecurityIncident -IncidentId $IncidentId -BodyParameter @{
                    AssignedTo = $AssignedTo
                }
                
                Write-Log "Incident assigned successfully"
                Write-Output "Incident $IncidentId assigned to $AssignedTo successfully"
                
                # Get updated incident details
                $updatedIncident = Get-MgSecurityIncident -IncidentId $IncidentId
                $incidentDetails = Format-IncidentDetails -Incident $updatedIncident
                
                # Output updated incident details
                Write-Output "Updated Incident Details:"
                $incidentDetails | Format-List
            }
            catch {
                Write-Log "Error assigning incident: $_" -Level Error
                exit 1
            }
        }
        "Comment" {
            try {
                # Get the incident
                $incident = Get-MgSecurityIncident -IncidentId $IncidentId -ErrorAction Stop
                
                if ($null -eq $incident) {
                    Write-Log "Incident not found: $IncidentId" -Level Error
                    exit 1
                }
                
                # Add comment to the incident
                Write-Log "Adding comment to incident $IncidentId"
                New-MgSecurityIncidentComment -IncidentId $IncidentId -BodyParameter @{
                    Comment = $Comment
                }
                
                Write-Log "Comment added successfully"
                Write-Output "Comment added to incident $IncidentId successfully"
                
                # Get updated incident details
                $updatedIncident = Get-MgSecurityIncident -IncidentId $IncidentId
                $incidentDetails = Format-IncidentDetails -Incident $updatedIncident
                
                # Output updated incident details
                Write-Output "Updated Incident Details:"
                $incidentDetails | Format-List
            }
            catch {
                Write-Log "Error adding comment to incident: $_" -Level Error
                exit 1
            }
        }
        "Report" {
            try {
                # Calculate date range
                $startDate = (Get-Date).AddDays(-$DaysToAnalyze)
                $filter = "createdDateTime ge $($startDate.ToString('yyyy-MM-ddT00:00:00Z'))"
                
                Write-Log "Retrieving incidents for report with filter: $filter"
                $incidents = Get-MgSecurityIncident -All -Filter $filter
                
                if ($null -eq $incidents -or $incidents.Count -eq 0) {
                    Write-Log "No incidents found in the specified date range" -Level Warning
                    exit 0
                }
                
                Write-Log "Retrieved $($incidents.Count) incidents for report"
                
                # Calculate metrics
                $metrics = Get-IncidentMetrics -Incidents $incidents
                
                # Export incident details to CSV
                Export-IncidentDetails -Incidents $incidents -ExportPath $OutputPath
                
                # Display report
                Write-Output "Incident Report for the Past $DaysToAnalyze Days:"
                Write-Output "  Total Incidents: $($metrics.TotalIncidents)"
                Write-Output "  Average Time to Resolve: $($metrics.AverageTimeToResolveHours) hours"
                
                Write-Output "`nIncidents by Severity:"
                $metrics.BySeverity | Format-Table -AutoSize
                
                Write-Output "Incidents by Status:"
                $metrics.ByStatus | Format-Table -AutoSize
                
                if ($metrics.ByClassification.Count -gt 0) {
                    Write-Output "Resolved Incidents by Classification:"
                    $metrics.ByClassification | Format-Table -AutoSize
                }
                
                Write-Output "Incidents by Day:"
                $metrics.IncidentsByDay | Format-Table -AutoSize
                
                Write-Output "`nDetailed incident data exported to: $OutputPath"
            }
            catch {
                Write-Log "Error generating report: $_" -Level Error
                exit 1
            }
        }
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
