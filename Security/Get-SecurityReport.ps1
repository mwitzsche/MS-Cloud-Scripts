<#
.SYNOPSIS
    Generates comprehensive security reports for Microsoft Defender and Azure Security Center.

.DESCRIPTION
    This script generates detailed security reports for Microsoft Defender and Azure Security Center,
    including security alerts, incidents, vulnerabilities, secure score, and compliance status.
    Reports can be filtered by various criteria and exported in multiple formats.

.PARAMETER ReportType
    The type of security report to generate (Alerts, Incidents, Vulnerabilities, SecureScore, Compliance, All).

.PARAMETER Filter
    Hashtable of filters to apply to the report (e.g. @{Severity="High"; Status="New"}).

.PARAMETER TimeFrame
    The time frame for security data (Last7Days, Last30Days, Last90Days, LastYear).

.PARAMETER IncludeInformational
    Whether to include informational alerts in the report.

.PARAMETER IncludeResolved
    Whether to include resolved items in the report.

.PARAMETER ExportPath
    The path where the report will be saved.

.PARAMETER ExportFormat
    The format of the export file (CSV, JSON, Excel, HTML).

.PARAMETER LogPath
    Path where logs will be stored. Defaults to Windows log directory.

.EXAMPLE
    .\Get-SecurityReport.ps1 -ReportType Alerts -TimeFrame Last7Days -ExportPath "C:\Reports\SecurityAlerts.csv" -ExportFormat CSV
    Generates a security alerts report for the last 7 days and exports it to CSV format.

.EXAMPLE
    .\Get-SecurityReport.ps1 -ReportType SecureScore -ExportPath "C:\Reports\SecureScore.xlsx" -ExportFormat Excel
    Generates a secure score report and exports it to Excel format.

.NOTES
    Author: Michael Witzsche
    Date: April 26, 2025
    Version: 1.0.0
    
    History:
    1.0.0 - Initial release
#>

#Requires -Modules Microsoft.Graph.Security, Microsoft.Graph.DeviceManagement, Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.Authentication, ImportExcel

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$LogPath = "$env:SystemRoot\Logs\Get-SecurityReport",
    
    [Parameter(Mandatory = $true)]
    [ValidateSet("Alerts", "Incidents", "Vulnerabilities", "SecureScore", "Compliance", "All")]
    [string]$ReportType,
    
    [Parameter(Mandatory = $false)]
    [hashtable]$Filter = @{},
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Last7Days", "Last30Days", "Last90Days", "LastYear")]
    [string]$TimeFrame = "Last30Days",
    
    [Parameter(Mandatory = $false)]
    [bool]$IncludeInformational = $false,
    
    [Parameter(Mandatory = $false)]
    [bool]$IncludeResolved = $false,
    
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
            "SecurityEvents.Read.All",
            "SecurityIncident.Read.All",
            "SecurityAlert.Read.All",
            "SecurityActions.Read.All",
            "Directory.Read.All",
            "DeviceManagementConfiguration.Read.All"
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

function Get-TimeFrameFilter {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$TimeFrame
    )
    
    # Calculate date range based on time frame
    $endDate = Get-Date
    $startDate = $endDate
    
    switch ($TimeFrame) {
        "Last7Days" {
            $startDate = $endDate.AddDays(-7)
        }
        "Last30Days" {
            $startDate = $endDate.AddDays(-30)
        }
        "Last90Days" {
            $startDate = $endDate.AddDays(-90)
        }
        "LastYear" {
            $startDate = $endDate.AddDays(-365)
        }
    }
    
    return @{
        StartDate = $startDate
        EndDate = $endDate
        StartDateString = $startDate.ToString("yyyy-MM-ddTHH:mm:ssZ")
        EndDateString = $endDate.ToString("yyyy-MM-ddTHH:mm:ssZ")
    }
}

function Get-SecurityAlertsReport {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [hashtable]$Filter = @{},
        
        [Parameter(Mandatory = $false)]
        [string]$TimeFrame = "Last30Days",
        
        [Parameter(Mandatory = $false)]
        [bool]$IncludeInformational = $false,
        
        [Parameter(Mandatory = $false)]
        [bool]$IncludeResolved = $false
    )
    
    try {
        Write-Log "Generating security alerts report for time frame: $TimeFrame..."
        
        # Get time frame filter
        $timeFrameFilter = Get-TimeFrameFilter -TimeFrame $TimeFrame
        
        # Build filter string
        $filterStrings = @()
        
        # Add time frame filter
        $filterStrings += "createdDateTime ge $($timeFrameFilter.StartDateString)"
        
        # Add severity filter if not including informational
        if (-not $IncludeInformational) {
            $filterStrings += "severity ne 'Informational' and severity ne 'Low'"
        }
        
        # Add status filter if not including resolved
        if (-not $IncludeResolved) {
            $filterStrings += "status ne 'Resolved'"
        }
        
        # Add custom filters
        foreach ($key in $Filter.Keys) {
            $value = $Filter[$key]
            
            # Handle different property types
            switch ($key) {
                "Severity" { $filterStrings += "severity eq '$value'" }
                "Status" { $filterStrings += "status eq '$value'" }
                "Category" { $filterStrings += "category eq '$value'" }
                "Title" { $filterStrings += "contains(title, '$value')" }
                "UserPrincipalName" { $filterStrings += "contains(userStates/any(u:u/userPrincipalName), '$value')" }
                "HostName" { $filterStrings += "contains(hostStates/any(h:h/netBiosName), '$value')" }
                default { $filterStrings += "contains($key, '$value')" }
            }
        }
        
        # Combine filter strings
        $filterString = $filterStrings -join " and "
        
        # Get security alerts with filter
        $alerts = Get-MgSecurityAlert -Filter $filterString -All
        
        if ($null -eq $alerts -or $alerts.Count -eq 0) {
            Write-Log "No security alerts found with the specified filters" -Level Warning
            return $null
        }
        
        Write-Log "Retrieved $($alerts.Count) security alerts"
        
        # Create report
        $report = @()
        
        foreach ($alert in $alerts) {
            # Extract user information
            $userInfo = if ($alert.UserStates.Count -gt 0) {
                ($alert.UserStates | ForEach-Object {
                    "$($_.UserPrincipalName) ($($_.AccountName))"
                }) -join "; "
            } else { "N/A" }
            
            # Extract host information
            $hostInfo = if ($alert.HostStates.Count -gt 0) {
                ($alert.HostStates | ForEach-Object {
                    "$($_.NetBiosName) ($($_.PrivateIpAddress))"
                }) -join "; "
            } else { "N/A" }
            
            # Extract file information
            $fileInfo = if ($alert.FileStates.Count -gt 0) {
                ($alert.FileStates | ForEach-Object {
                    "$($_.Name) ($($_.Path))"
                }) -join "; "
            } else { "N/A" }
            
            $report += [PSCustomObject]@{
                AlertId = $alert.Id
                Title = $alert.Title
                Category = $alert.Category
                Severity = $alert.Severity
                Status = $alert.Status
                CreatedDateTime = $alert.CreatedDateTime
                LastModifiedDateTime = $alert.LastModifiedDateTime
                Provider = $alert.ProviderName
                VendorInformation = $alert.VendorInformation.Provider
                Description = $alert.Description
                Users = $userInfo
                Hosts = $hostInfo
                Files = $fileInfo
                RecommendedActions = $alert.RecommendedActions -join "; "
                TimeFrame = $TimeFrame
            }
        }
        
        Write-Log "Generated security alerts report with $($report.Count) entries"
        return $report
    }
    catch {
        Write-Log "Error generating security alerts report: $_" -Level Error
        return $null
    }
}

function Get-SecurityIncidentsReport {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [hashtable]$Filter = @{},
        
        [Parameter(Mandatory = $false)]
        [string]$TimeFrame = "Last30Days",
        
        [Parameter(Mandatory = $false)]
        [bool]$IncludeResolved = $false
    )
    
    try {
        Write-Log "Generating security incidents report for time frame: $TimeFrame..."
        
        # Get time frame filter
        $timeFrameFilter = Get-TimeFrameFilter -TimeFrame $TimeFrame
        
        # Build filter string
        $filterStrings = @()
        
        # Add time frame filter
        $filterStrings += "createdDateTime ge $($timeFrameFilter.StartDateString)"
        
        # Add status filter if not including resolved
        if (-not $IncludeResolved) {
            $filterStrings += "status ne 'Resolved'"
        }
        
        # Add custom filters
        foreach ($key in $Filter.Keys) {
            $value = $Filter[$key]
            
            # Handle different property types
            switch ($key) {
                "Severity" { $filterStrings += "severity eq '$value'" }
                "Status" { $filterStrings += "status eq '$value'" }
                "Classification" { $filterStrings += "classification eq '$value'" }
                "Title" { $filterStrings += "contains(title, '$value')" }
                default { $filterStrings += "contains($key, '$value')" }
            }
        }
        
        # Combine filter strings
        $filterString = $filterStrings -join " and "
        
        # Get security incidents with filter
        $incidents = Get-MgSecurityIncident -Filter $filterString -All
        
        if ($null -eq $incidents -or $incidents.Count -eq 0) {
            Write-Log "No security incidents found with the specified filters" -Level Warning
            return $null
        }
        
        Write-Log "Retrieved $($incidents.Count) security incidents"
        
        # Create report
        $report = @()
        
        foreach ($incident in $incidents) {
            # Get alerts for this incident
            $alertsCount = 0
            try {
                $incidentAlerts = Get-MgSecurityIncidentAlert -SecurityIncidentId $incident.Id
                $alertsCount = $incidentAlerts.Count
            }
            catch {
                # No alerts or error retrieving alerts
            }
            
            $report += [PSCustomObject]@{
                IncidentId = $incident.Id
                Title = $incident.Title
                Severity = $incident.Severity
                Status = $incident.Status
                Classification = $incident.Classification
                ClassificationReason = $incident.ClassificationReason
                AssignedTo = $incident.AssignedTo
                CreatedDateTime = $incident.CreatedDateTime
                LastModifiedDateTime = $incident.LastModifiedDateTime
                AlertsCount = $alertsCount
                Comments = $incident.Comments -join "; "
                Tags = $incident.Tags -join "; "
                TimeFrame = $TimeFrame
            }
        }
        
        Write-Log "Generated security incidents report with $($report.Count) entries"
        return $report
    }
    catch {
        Write-Log "Error generating security incidents report: $_" -Level Error
        return $null
    }
}

function Get-VulnerabilitiesReport {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [hashtable]$Filter = @{},
        
        [Parameter(Mandatory = $false)]
        [bool]$IncludeInformational = $false,
        
        [Parameter(Mandatory = $false)]
        [bool]$IncludeResolved = $false
    )
    
    try {
        Write-Log "Generating vulnerabilities report..."
        
        # Get vulnerability assessments
        $vulnerabilities = Get-MgDeviceManagementDetectedApp -All | Where-Object { $_.DetectionSource -eq "SecurityAssessment" }
        
        if ($null -eq $vulnerabilities -or $vulnerabilities.Count -eq 0) {
            Write-Log "No vulnerabilities found with the specified filters" -Level Warning
            return $null
        }
        
        # Filter vulnerabilities
        if (-not $IncludeInformational) {
            $vulnerabilities = $vulnerabilities | Where-Object { $_.SecurityRisk -ne "Low" }
        }
        
        if (-not $IncludeResolved) {
            $vulnerabilities = $vulnerabilities | Where-Object { $_.ResolvedDateTime -eq $null }
        }
        
        # Apply custom filters
        foreach ($key in $Filter.Keys) {
            $value = $Filter[$key]
            
            # Handle different property types
            switch ($key) {
                "SecurityRisk" { $vulnerabilities = $vulnerabilities | Where-Object { $_.SecurityRisk -eq $value } }
                "DeviceName" { $vulnerabilities = $vulnerabilities | Where-Object { $_.DeviceName -like "*$value*" } }
                "DisplayName" { $vulnerabilities = $vulnerabilities | Where-Object { $_.DisplayName -like "*$value*" } }
                default { $vulnerabilities = $vulnerabilities | Where-Object { $_.$key -like "*$value*" } }
            }
        }
        
        if ($null -eq $vulnerabilities -or $vulnerabilities.Count -eq 0) {
            Write-Log "No vulnerabilities found after applying filters" -Level Warning
            return $null
        }
        
        Write-Log "Retrieved $($vulnerabilities.Count) vulnerabilities"
        
        # Create report
        $report = @()
        
        foreach ($vulnerability in $vulnerabilities) {
            $report += [PSCustomObject]@{
                DisplayName = $vulnerability.DisplayName
                Version = $vulnerability.Version
                SecurityRisk = $vulnerability.SecurityRisk
                DeviceName = $vulnerability.DeviceName
                DeviceId = $vulnerability.DeviceId
                DetectionSource = $vulnerability.DetectionSource
                Publisher = $vulnerability.Publisher
                DetectedDateTime = $vulnerability.DetectedDateTime
                ResolvedDateTime = $vulnerability.ResolvedDateTime
                SizeInByte = $vulnerability.SizeInByte
                Platform = $vulnerability.Platform
            }
        }
        
        Write-Log "Generated vulnerabilities report with $($report.Count) entries"
        return $report
    }
    catch {
        Write-Log "Error generating vulnerabilities report: $_" -Level Error
        return $null
    }
}

function Get-SecureScoreReport {
    [CmdletBinding()]
    param ()
    
    try {
        Write-Log "Generating secure score report..."
        
        # Get secure scores
        $secureScores = Get-MgSecuritySecureScore -Top 10 -OrderBy "createdDateTime DESC"
        
        if ($null -eq $secureScores -or $secureScores.Count -eq 0) {
            Write-Log "No secure scores found" -Level Warning
            return $null
        }
        
        # Get latest secure score
        $latestScore = $secureScores[0]
        
        # Get secure score control profiles
        $controlProfiles = Get-MgSecuritySecureScoreControlProfile -All
        
        if ($null -eq $controlProfiles -or $controlProfiles.Count -eq 0) {
            Write-Log "No secure score control profiles found" -Level Warning
            return $null
        }
        
        # Create report
        $report = @()
        
        # Add overall score
        $report += [PSCustomObject]@{
            ControlName = "Overall Secure Score"
            ControlCategory = "Summary"
            CurrentScore = $latestScore.CurrentScore
            MaxScore = $latestScore.MaxScore
            PercentageScore = [math]::Round(($latestScore.CurrentScore / $latestScore.MaxScore) * 100, 2)
            ScoreDate = $latestScore.CreatedDateTime
            ImplementationStatus = "N/A"
            Description = "Overall Microsoft Secure Score"
            RecommendedActions = "Review individual controls below"
        }
        
        # Add control scores
        foreach ($controlProfile in $controlProfiles) {
            # Get control score from latest secure score
            $controlScore = $latestScore.ControlScores | Where-Object { $_.ControlName -eq $controlProfile.ControlName }
            
            if ($null -ne $controlScore) {
                $implementationStatus = if ($controlScore.Score -eq 0) {
                    "Not Implemented"
                } elseif ($controlScore.Score -lt $controlProfile.MaxScore) {
                    "Partially Implemented"
                } else {
                    "Fully Implemented"
                }
                
                $report += [PSCustomObject]@{
                    ControlName = $controlProfile.Title
                    ControlCategory = $controlProfile.ControlCategory
                    CurrentScore = $controlScore.Score
                    MaxScore = $controlProfile.MaxScore
                    PercentageScore = if ($controlProfile.MaxScore -gt 0) { [math]::Round(($controlScore.Score / $controlProfile.MaxScore) * 100, 2) } else { 0 }
                    ScoreDate = $latestScore.CreatedDateTime
                    ImplementationStatus = $implementationStatus
                    Description = $controlProfile.Description
                    RecommendedActions = $controlProfile.RecommendedActions -join "; "
                }
            }
        }
        
        Write-Log "Generated secure score report with $($report.Count) entries"
        return $report
    }
    catch {
        Write-Log "Error generating secure score report: $_" -Level Error
        return $null
    }
}

function Get-ComplianceReport {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$TimeFrame = "Last30Days"
    )
    
    try {
        Write-Log "Generating compliance report for time frame: $TimeFrame..."
        
        # Get time frame filter
        $timeFrameFilter = Get-TimeFrameFilter -TimeFrame $TimeFrame
        
        # Get compliance policies
        $compliancePolicies = Get-MgDeviceManagementDeviceCompliancePolicy -All
        
        if ($null -eq $compliancePolicies -or $compliancePolicies.Count -eq 0) {
            Write-Log "No compliance policies found" -Level Warning
            return $null
        }
        
        # Create report
        $report = @()
        
        foreach ($policy in $compliancePolicies) {
            # Get policy status overview
            $policyStatusOverview = Get-MgDeviceManagementDeviceCompliancePolicyDeviceStateSummary -DeviceCompliancePolicyId $policy.Id
            
            # Get device status details
            $deviceStatuses = Get-MgDeviceManagementDeviceCompliancePolicyDeviceStatus -DeviceCompliancePolicyId $policy.Id -All
            
            # Calculate compliance percentages
            $totalDevices = $policyStatusOverview.DeviceCount
            $compliantDevices = $policyStatusOverview.CompliantDeviceCount
            $nonCompliantDevices = $policyStatusOverview.NonCompliantDeviceCount
            $errorDevices = $policyStatusOverview.ErrorDeviceCount
            $conflictDevices = $policyStatusOverview.ConflictDeviceCount
            
            $compliantPercentage = if ($totalDevices -gt 0) { [math]::Round(($compliantDevices / $totalDevices) * 100, 2) } else { 0 }
            $nonCompliantPercentage = if ($totalDevices -gt 0) { [math]::Round(($nonCompliantDevices / $totalDevices) * 100, 2) } else { 0 }
            $errorPercentage = if ($totalDevices -gt 0) { [math]::Round(($errorDevices / $totalDevices) * 100, 2) } else { 0 }
            $conflictPercentage = if ($totalDevices -gt 0) { [math]::Round(($conflictDevices / $totalDevices) * 100, 2) } else { 0 }
            
            # Get recent non-compliant devices
            $recentNonCompliantDevices = $deviceStatuses | 
                Where-Object { $_.Status -eq "NonCompliant" -and $_.LastReportedDateTime -ge $timeFrameFilter.StartDate } |
                Sort-Object LastReportedDateTime -Descending |
                Select-Object -First 5
            
            $recentNonCompliantDevicesList = if ($recentNonCompliantDevices.Count -gt 0) {
                ($recentNonCompliantDevices | ForEach-Object {
                    "$($_.DeviceDisplayName) (Last reported: $($_.LastReportedDateTime))"
                }) -join "; "
            } else { "None" }
            
            $report += [PSCustomObject]@{
                PolicyName = $policy.DisplayName
                PolicyDescription = $policy.Description
                PolicyType = $policy.AdditionalProperties.'@odata.type'
                TotalDevices = $totalDevices
                CompliantDevices = $compliantDevices
                CompliantPercentage = $compliantPercentage
                NonCompliantDevices = $nonCompliantDevices
                NonCompliantPercentage = $nonCompliantPercentage
                ErrorDevices = $errorDevices
                ErrorPercentage = $errorPercentage
                ConflictDevices = $conflictDevices
                ConflictPercentage = $conflictPercentage
                RecentNonCompliantDevices = $recentNonCompliantDevicesList
                CreatedDateTime = $policy.CreatedDateTime
                LastModifiedDateTime = $policy.LastModifiedDateTime
                TimeFrame = $TimeFrame
            }
        }
        
        Write-Log "Generated compliance report with $($report.Count) entries"
        return $report
    }
    catch {
        Write-Log "Error generating compliance report: $_" -Level Error
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
        [string]$ReportTitle = "Security Report"
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
                $Data | Export-Excel -Path $ExportPath -AutoSize -TableName "SecurityReport" -WorksheetName $ReportTitle
            }
            "HTML" {
                $htmlHeader = @"
<!DOCTYPE html>
<html>
<head>
    <title>$ReportTitle</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #0078D4; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
        th { background-color: #0078D4; color: white; text-align: left; padding: 8px; }
        td { border: 1px solid #ddd; padding: 8px; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        tr:hover { background-color: #ddd; }
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
    
    # Generate reports based on report type
    switch ($ReportType) {
        "Alerts" {
            $report = Get-SecurityAlertsReport -Filter $Filter -TimeFrame $TimeFrame -IncludeInformational $IncludeInformational -IncludeResolved $IncludeResolved
            $reportTitle = "Security Alerts Report"
        }
        "Incidents" {
            $report = Get-SecurityIncidentsReport -Filter $Filter -TimeFrame $TimeFrame -IncludeResolved $IncludeResolved
            $reportTitle = "Security Incidents Report"
        }
        "Vulnerabilities" {
            $report = Get-VulnerabilitiesReport -Filter $Filter -IncludeInformational $IncludeInformational -IncludeResolved $IncludeResolved
            $reportTitle = "Vulnerabilities Report"
        }
        "SecureScore" {
            $report = Get-SecureScoreReport
            $reportTitle = "Secure Score Report"
        }
        "Compliance" {
            $report = Get-ComplianceReport -TimeFrame $TimeFrame
            $reportTitle = "Compliance Report"
        }
        "All" {
            # Generate all reports
            $alertsReport = Get-SecurityAlertsReport -Filter $Filter -TimeFrame $TimeFrame -IncludeInformational $IncludeInformational -IncludeResolved $IncludeResolved
            $incidentsReport = Get-SecurityIncidentsReport -Filter $Filter -TimeFrame $TimeFrame -IncludeResolved $IncludeResolved
            $vulnerabilitiesReport = Get-VulnerabilitiesReport -Filter $Filter -IncludeInformational $IncludeInformational -IncludeResolved $IncludeResolved
            $secureScoreReport = Get-SecureScoreReport
            $complianceReport = Get-ComplianceReport -TimeFrame $TimeFrame
            
            # Export each report
            $exportPathWithoutExtension = [System.IO.Path]::GetDirectoryName($ExportPath) + "\" + [System.IO.Path]::GetFileNameWithoutExtension($ExportPath)
            $extension = [System.IO.Path]::GetExtension($ExportPath)
            
            if ($ExportFormat -eq "Excel") {
                # For Excel, export all reports to different worksheets in the same file
                $alertsReport | Export-Excel -Path $ExportPath -AutoSize -TableName "SecurityAlertsReport" -WorksheetName "Security Alerts Report"
                $incidentsReport | Export-Excel -Path $ExportPath -AutoSize -TableName "SecurityIncidentsReport" -WorksheetName "Security Incidents Report" -ClearSheet
                $vulnerabilitiesReport | Export-Excel -Path $ExportPath -AutoSize -TableName "VulnerabilitiesReport" -WorksheetName "Vulnerabilities Report" -ClearSheet
                $secureScoreReport | Export-Excel -Path $ExportPath -AutoSize -TableName "SecureScoreReport" -WorksheetName "Secure Score Report" -ClearSheet
                $complianceReport | Export-Excel -Path $ExportPath -AutoSize -TableName "ComplianceReport" -WorksheetName "Compliance Report" -ClearSheet
                
                Write-Log "All reports exported successfully to: $ExportPath"
            }
            else {
                # For other formats, export to separate files
                Export-Report -Data $alertsReport -ExportPath "$exportPathWithoutExtension-Alerts$extension" -ExportFormat $ExportFormat -ReportTitle "Security Alerts Report"
                Export-Report -Data $incidentsReport -ExportPath "$exportPathWithoutExtension-Incidents$extension" -ExportFormat $ExportFormat -ReportTitle "Security Incidents Report"
                Export-Report -Data $vulnerabilitiesReport -ExportPath "$exportPathWithoutExtension-Vulnerabilities$extension" -ExportFormat $ExportFormat -ReportTitle "Vulnerabilities Report"
                Export-Report -Data $secureScoreReport -ExportPath "$exportPathWithoutExtension-SecureScore$extension" -ExportFormat $ExportFormat -ReportTitle "Secure Score Report"
                Export-Report -Data $complianceReport -ExportPath "$exportPathWithoutExtension-Compliance$extension" -ExportFormat $ExportFormat -ReportTitle "Compliance Report"
                
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
    Write-Output "Security report generation completed successfully"
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
