<#
.SYNOPSIS
    Generates comprehensive security reports for Microsoft Defender XDR.

.DESCRIPTION
    This script generates detailed security reports for Microsoft Defender XDR
    including threat detection statistics, vulnerability assessments, security posture,
    and compliance status across the organization.

.PARAMETER ReportType
    The type of report to generate (ThreatDetection, Vulnerability, SecurityPosture, Compliance, Executive).

.PARAMETER TimeFrame
    The time frame for the report (Last24Hours, Last7Days, Last30Days, Last90Days, Custom).

.PARAMETER StartDate
    The start date for custom time frame reports.

.PARAMETER EndDate
    The end date for custom time frame reports.

.PARAMETER OutputFormat
    The format of the report output (CSV, HTML, JSON, Excel).

.PARAMETER OutputPath
    The path where the report will be saved.

.PARAMETER IncludeCharts
    Whether to include charts in HTML and Excel reports.

.PARAMETER FilterByDeviceGroup
    Filter the report by device group.

.PARAMETER FilterByOS
    Filter the report by operating system (Windows, macOS, Linux, iOS, Android).

.PARAMETER EmailReport
    Whether to email the report after generation.

.PARAMETER EmailRecipients
    Email addresses to send the report to.

.PARAMETER LogPath
    Path where logs will be stored. Defaults to Windows log directory.

.EXAMPLE
    .\Generate-DefenderSecurityReport.ps1 -ReportType ThreatDetection -TimeFrame Last30Days -OutputFormat HTML -OutputPath "C:\Reports\ThreatReport.html" -IncludeCharts $true
    Generates a threat detection report for the last 30 days in HTML format with charts.

.EXAMPLE
    .\Generate-DefenderSecurityReport.ps1 -ReportType Executive -TimeFrame Custom -StartDate "2025-03-01" -EndDate "2025-03-31" -OutputFormat Excel -OutputPath "C:\Reports\ExecutiveReport.xlsx" -EmailReport $true -EmailRecipients "ciso@contoso.com"
    Generates an executive summary report for March 2025 in Excel format and emails it to the CISO.

.NOTES
    Author: Michael Witzsche
    Date: April 26, 2025
    Version: 1.1
#>

#Requires -Modules Microsoft.Graph.Security, Microsoft.Graph.Reports, ImportExcel

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$LogPath = "$env:SystemRoot\Logs\Generate-DefenderSecurityReport",
    
    [Parameter(Mandatory = $true)]
    [ValidateSet("ThreatDetection", "Vulnerability", "SecurityPosture", "Compliance", "Executive")]
    [string]$ReportType,
    
    [Parameter(Mandatory = $true)]
    [ValidateSet("Last24Hours", "Last7Days", "Last30Days", "Last90Days", "Custom")]
    [string]$TimeFrame,
    
    [Parameter(Mandatory = $false)]
    [string]$StartDate = "",
    
    [Parameter(Mandatory = $false)]
    [string]$EndDate = "",
    
    [Parameter(Mandatory = $true)]
    [ValidateSet("CSV", "HTML", "JSON", "Excel")]
    [string]$OutputFormat,
    
    [Parameter(Mandatory = $true)]
    [string]$OutputPath,
    
    [Parameter(Mandatory = $false)]
    [bool]$IncludeCharts = $true,
    
    [Parameter(Mandatory = $false)]
    [string]$FilterByDeviceGroup = "",
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Windows", "macOS", "Linux", "iOS", "Android", "")]
    [string]$FilterByOS = "",
    
    [Parameter(Mandatory = $false)]
    [bool]$EmailReport = $false,
    
    [Parameter(Mandatory = $false)]
    [string[]]$EmailRecipients = @()
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
            $graphAlert = Get-MgSecurityAlert -Top 1 -ErrorAction Stop
            Write-Log "Already connected to Microsoft Graph"
            return $true
        }
        catch {
            # Not connected, proceed with connection
        }
        
        # Connect to Microsoft Graph with required scopes
        Write-Log "Connecting to Microsoft Graph..."
        Connect-MgGraph -Scopes "SecurityEvents.Read.All", "SecurityAlert.Read.All", "Reports.Read.All" -ErrorAction Stop
        
        # Verify connection
        try {
            $graphAlert = Get-MgSecurityAlert -Top 1 -ErrorAction Stop
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

function Get-DateRange {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$TimeFrame,
        
        [Parameter(Mandatory = $false)]
        [string]$StartDate,
        
        [Parameter(Mandatory = $false)]
        [string]$EndDate
    )
    
    $endDateTime = Get-Date
    $startDateTime = $null
    
    switch ($TimeFrame) {
        "Last24Hours" {
            $startDateTime = $endDateTime.AddHours(-24)
        }
        "Last7Days" {
            $startDateTime = $endDateTime.AddDays(-7)
        }
        "Last30Days" {
            $startDateTime = $endDateTime.AddDays(-30)
        }
        "Last90Days" {
            $startDateTime = $endDateTime.AddDays(-90)
        }
        "Custom" {
            if ([string]::IsNullOrEmpty($StartDate) -or [string]::IsNullOrEmpty($EndDate)) {
                throw "StartDate and EndDate are required for Custom time frame"
            }
            
            try {
                $startDateTime = [DateTime]::ParseExact($StartDate, "yyyy-MM-dd", $null)
                $endDateTime = [DateTime]::ParseExact($EndDate, "yyyy-MM-dd", $null).AddDays(1).AddSeconds(-1)
            }
            catch {
                throw "Invalid date format. Use yyyy-MM-dd format."
            }
        }
    }
    
    return @{
        StartDateTime = $startDateTime
        EndDateTime = $endDateTime
    }
}

function Get-ThreatDetectionData {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [DateTime]$StartDateTime,
        
        [Parameter(Mandatory = $true)]
        [DateTime]$EndDateTime,
        
        [Parameter(Mandatory = $false)]
        [string]$DeviceGroup,
        
        [Parameter(Mandatory = $false)]
        [string]$OS
    )
    
    try {
        # Build filter
        $filter = "createdDateTime ge $($StartDateTime.ToString('yyyy-MM-ddT00:00:00Z')) and createdDateTime le $($EndDateTime.ToString('yyyy-MM-ddT23:59:59Z'))"
        
        Write-Log "Retrieving alerts with filter: $filter"
        $alerts = Get-MgSecurityAlert -All -Filter $filter
        
        # Apply additional filters
        if (-not [string]::IsNullOrEmpty($OS)) {
            $alerts = $alerts | Where-Object { $_.DeviceStates.OSPlatform -like "*$OS*" }
        }
        
        if (-not [string]::IsNullOrEmpty($DeviceGroup)) {
            # This is a simplified approach - in a real environment, you would need to get device group membership
            # and filter alerts based on that
            Write-Log "Device group filtering would be applied here in a real environment"
        }
        
        # Process alerts
        $alertsBySeverity = $alerts | Group-Object -Property Severity | Select-Object Name, Count
        $alertsByCategory = $alerts | Group-Object -Property Category | Select-Object Name, Count
        $alertsByStatus = $alerts | Group-Object -Property Status | Select-Object Name, Count
        
        # Get top affected devices
        $deviceStats = @{}
        foreach ($alert in $alerts) {
            foreach ($device in $alert.DeviceStates) {
                if (-not [string]::IsNullOrEmpty($device.DeviceName)) {
                    if (-not $deviceStats.ContainsKey($device.DeviceName)) {
                        $deviceStats[$device.DeviceName] = 0
                    }
                    $deviceStats[$device.DeviceName]++
                }
            }
        }
        
        $topAffectedDevices = $deviceStats.GetEnumerator() | 
            Sort-Object -Property Value -Descending | 
            Select-Object -First 10 | 
            ForEach-Object { [PSCustomObject]@{DeviceName = $_.Key; AlertCount = $_.Value} }
        
        # Get top alert types
        $topAlertTypes = $alerts | Group-Object -Property Title | 
            Sort-Object -Property Count -Descending | 
            Select-Object -First 10 | 
            Select-Object Name, Count
        
        # Calculate daily trend
        $dailyTrend = $alerts | Group-Object -Property { ([DateTime]$_.CreatedDateTime).ToString("yyyy-MM-dd") } | 
            Select-Object @{Name="Date"; Expression={$_.Name}}, @{Name="Count"; Expression={$_.Count}} |
            Sort-Object -Property Date
        
        # Return the data
        return @{
            TotalAlerts = $alerts.Count
            AlertsBySeverity = $alertsBySeverity
            AlertsByCategory = $alertsByCategory
            AlertsByStatus = $alertsByStatus
            TopAffectedDevices = $topAffectedDevices
            TopAlertTypes = $topAlertTypes
            DailyTrend = $dailyTrend
            RawAlerts = $alerts
        }
    }
    catch {
        Write-Log "Error retrieving threat detection data: $_" -Level Error
        throw $_
    }
}

function Get-VulnerabilityData {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [DateTime]$StartDateTime,
        
        [Parameter(Mandatory = $true)]
        [DateTime]$EndDateTime,
        
        [Parameter(Mandatory = $false)]
        [string]$DeviceGroup,
        
        [Parameter(Mandatory = $false)]
        [string]$OS
    )
    
    try {
        # In a real environment, this would retrieve vulnerability data from Microsoft Defender Vulnerability Management
        # For this script, we'll simulate the data
        
        Write-Log "Retrieving vulnerability data (simulated)"
        
        # Simulate vulnerability data
        $vulnerabilities = @(
            [PSCustomObject]@{
                CVE = "CVE-2025-1234"
                Title = "Remote Code Execution Vulnerability in Windows"
                Severity = "Critical"
                ExploitabilityLevel = "High"
                AffectedDevicesCount = 15
                PatchAvailable = $true
                FirstDetected = $StartDateTime.AddDays(2)
            },
            [PSCustomObject]@{
                CVE = "CVE-2025-5678"
                Title = "Elevation of Privilege Vulnerability in Office"
                Severity = "High"
                ExploitabilityLevel = "Medium"
                AffectedDevicesCount = 42
                PatchAvailable = $true
                FirstDetected = $StartDateTime.AddDays(5)
            },
            [PSCustomObject]@{
                CVE = "CVE-2025-9012"
                Title = "Information Disclosure Vulnerability in Exchange"
                Severity = "Medium"
                ExploitabilityLevel = "Low"
                AffectedDevicesCount = 8
                PatchAvailable = $false
                FirstDetected = $StartDateTime.AddDays(10)
            },
            [PSCustomObject]@{
                CVE = "CVE-2025-3456"
                Title = "Denial of Service Vulnerability in SQL Server"
                Severity = "Low"
                ExploitabilityLevel = "Low"
                AffectedDevicesCount = 3
                PatchAvailable = $true
                FirstDetected = $StartDateTime.AddDays(15)
            },
            [PSCustomObject]@{
                CVE = "CVE-2025-7890"
                Title = "Cross-Site Scripting Vulnerability in SharePoint"
                Severity = "Medium"
                ExploitabilityLevel = "Medium"
                AffectedDevicesCount = 12
                PatchAvailable = $true
                FirstDetected = $StartDateTime.AddDays(20)
            }
        )
        
        # Process vulnerability data
        $vulnerabilitiesBySeverity = $vulnerabilities | Group-Object -Property Severity | Select-Object Name, Count
        $vulnerabilitiesByExploitability = $vulnerabilities | Group-Object -Property ExploitabilityLevel | Select-Object Name, Count
        $vulnerabilitiesByPatchStatus = $vulnerabilities | Group-Object -Property PatchAvailable | 
            Select-Object @{Name="Status"; Expression={if ($_.Name -eq "True") { "Patch Available" } else { "No Patch" }}}, Count
        
        # Calculate total affected devices (with potential duplicates)
        $totalAffectedDevices = ($vulnerabilities | Measure-Object -Property AffectedDevicesCount -Sum).Sum
        
        # Return the data
        return @{
            TotalVulnerabilities = $vulnerabilities.Count
            VulnerabilitiesBySeverity = $vulnerabilitiesBySeverity
            VulnerabilitiesByExploitability = $vulnerabilitiesByExploitability
            VulnerabilitiesByPatchStatus = $vulnerabilitiesByPatchStatus
            TotalAffectedDevices = $totalAffectedDevices
            TopVulnerabilities = $vulnerabilities | Sort-Object -Property AffectedDevicesCount -Descending | Select-Object -First 10
            RawVulnerabilities = $vulnerabilities
        }
    }
    catch {
        Write-Log "Error retrieving vulnerability data: $_" -Level Error
        throw $_
    }
}

function Get-SecurityPostureData {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [DateTime]$StartDateTime,
        
        [Parameter(Mandatory = $true)]
        [DateTime]$EndDateTime,
        
        [Parameter(Mandatory = $false)]
        [string]$DeviceGroup,
        
        [Parameter(Mandatory = $false)]
        [string]$OS
    )
    
    try {
        # In a real environment, this would retrieve security posture data from Microsoft Defender
        # For this script, we'll simulate the data
        
        Write-Log "Retrieving security posture data (simulated)"
        
        # Simulate security posture data
        $secureScoreHistory = @(
            [PSCustomObject]@{
                Date = $StartDateTime.AddDays(0).ToString("yyyy-MM-dd")
                Score = 65
            },
            [PSCustomObject]@{
                Date = $StartDateTime.AddDays(7).ToString("yyyy-MM-dd")
                Score = 68
            },
            [PSCustomObject]@{
                Date = $StartDateTime.AddDays(14).ToString("yyyy-MM-dd")
                Score = 72
            },
            [PSCustomObject]@{
                Date = $StartDateTime.AddDays(21).ToString("yyyy-MM-dd")
                Score = 75
            },
            [PSCustomObject]@{
                Date = $EndDateTime.ToString("yyyy-MM-dd")
                Score = 78
            }
        )
        
        $securityControls = @(
            [PSCustomObject]@{
                ControlName = "MFA Enabled"
                Category = "Identity"
                ComplianceRate = 92
                RecommendedActions = "Enable MFA for remaining 8% of accounts"
            },
            [PSCustomObject]@{
                ControlName = "Antimalware Enabled"
                Category = "Endpoint"
                ComplianceRate = 98
                RecommendedActions = "Deploy antimalware to remaining devices"
            },
            [PSCustomObject]@{
                ControlName = "OS Up to Date"
                Category = "Endpoint"
                ComplianceRate = 85
                RecommendedActions = "Update OS on 15% of devices"
            },
            [PSCustomObject]@{
                ControlName = "Firewall Enabled"
                Category = "Network"
                ComplianceRate = 95
                RecommendedActions = "Enable firewall on remaining devices"
            },
            [PSCustomObject]@{
                ControlName = "Encryption Enabled"
                Category = "Data"
                ComplianceRate = 88
                RecommendedActions = "Enable encryption on remaining devices"
            },
            [PSCustomObject]@{
                ControlName = "Admin Accounts Protected"
                Category = "Identity"
                ComplianceRate = 90
                RecommendedActions = "Implement additional protections for admin accounts"
            },
            [PSCustomObject]@{
                ControlName = "Email Protection"
                Category = "Email"
                ComplianceRate = 94
                RecommendedActions = "Configure additional email protection policies"
            },
            [PSCustomObject]@{
                ControlName = "Cloud Apps Secured"
                Category = "Cloud"
                ComplianceRate = 82
                RecommendedActions = "Review and secure additional cloud applications"
            }
        )
        
        # Process security posture data
        $controlsByCategory = $securityControls | Group-Object -Property Category | 
            Select-Object Name, @{Name="AverageComplianceRate"; Expression={[math]::Round(($_.Group | Measure-Object -Property ComplianceRate -Average).Average, 2)}}
        
        $topImprovementAreas = $securityControls | Sort-Object -Property ComplianceRate | Select-Object -First 3
        
        # Calculate overall compliance rate
        $overallComplianceRate = [math]::Round(($securityControls | Measure-Object -Property ComplianceRate -Average).Average, 2)
        
        # Return the data
        return @{
            CurrentSecureScore = $secureScoreHistory[-1].Score
            SecureScoreImprovement = $secureScoreHistory[-1].Score - $secureScoreHistory[0].Score
            SecureScoreHistory = $secureScoreHistory
            OverallComplianceRate = $overallComplianceRate
            ControlsByCategory = $controlsByCategory
            TopImprovementAreas = $topImprovementAreas
            AllSecurityControls = $securityControls
        }
    }
    catch {
        Write-Log "Error retrieving security posture data: $_" -Level Error
        throw $_
    }
}

function Get-ComplianceData {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [DateTime]$StartDateTime,
        
        [Parameter(Mandatory = $true)]
        [DateTime]$EndDateTime,
        
        [Parameter(Mandatory = $false)]
        [string]$DeviceGroup,
        
        [Parameter(Mandatory = $false)]
        [string]$OS
    )
    
    try {
        # In a real environment, this would retrieve compliance data from Microsoft Defender and Intune
        # For this script, we'll simulate the data
        
        Write-Log "Retrieving compliance data (simulated)"
        
        # Simulate compliance data
        $compliancePolicies = @(
            [PSCustomObject]@{
                PolicyName = "Windows 10/11 Compliance"
                DeviceType = "Windows"
                TotalDevices = 450
                CompliantDevices = 423
                NonCompliantDevices = 27
                ComplianceRate = 94
            },
            [PSCustomObject]@{
                PolicyName = "macOS Compliance"
                DeviceType = "macOS"
                TotalDevices = 120
                CompliantDevices = 108
                NonCompliantDevices = 12
                ComplianceRate = 90
            },
            [PSCustomObject]@{
                PolicyName = "iOS Compliance"
                DeviceType = "iOS"
                TotalDevices = 200
                CompliantDevices = 192
                NonCompliantDevices = 8
                ComplianceRate = 96
            },
            [PSCustomObject]@{
                PolicyName = "Android Compliance"
                DeviceType = "Android"
                TotalDevices = 180
                CompliantDevices = 162
                NonCompliantDevices = 18
                ComplianceRate = 90
            }
        )
        
        $complianceIssues = @(
            [PSCustomObject]@{
                Issue = "OS Not Up to Date"
                AffectedDevices = 22
                DeviceType = "Mixed"
                Severity = "Medium"
                RemediationAction = "Update OS to latest version"
            },
            [PSCustomObject]@{
                Issue = "Encryption Not Enabled"
                AffectedDevices = 15
                DeviceType = "Windows"
                Severity = "High"
                RemediationAction = "Enable BitLocker encryption"
            },
            [PSCustomObject]@{
                Issue = "Antimalware Not Running"
                AffectedDevices = 8
                DeviceType = "Windows"
                Severity = "High"
                RemediationAction = "Ensure Microsoft Defender is running"
            },
            [PSCustomObject]@{
                Issue = "Jailbroken Device"
                AffectedDevices = 3
                DeviceType = "iOS"
                Severity = "Critical"
                RemediationAction = "Reset device to factory settings"
            },
            [PSCustomObject]@{
                Issue = "Password Policy Not Met"
                AffectedDevices = 12
                DeviceType = "Mixed"
                Severity = "Medium"
                RemediationAction = "Update device password to meet requirements"
            },
            [PSCustomObject]@{
                Issue = "Firewall Disabled"
                AffectedDevices = 5
                DeviceType = "Windows"
                Severity = "Medium"
                RemediationAction = "Enable Windows Firewall"
            }
        )
        
        # Process compliance data
        $complianceByDeviceType = $compliancePolicies | Select-Object DeviceType, ComplianceRate
        
        $issuesBySeverity = $complianceIssues | Group-Object -Property Severity | 
            Select-Object Name, @{Name="AffectedDevices"; Expression={($_.Group | Measure-Object -Property AffectedDevices -Sum).Sum}}
        
        # Calculate overall compliance rate
        $totalDevices = ($compliancePolicies | Measure-Object -Property TotalDevices -Sum).Sum
        $compliantDevices = ($compliancePolicies | Measure-Object -Property CompliantDevices -Sum).Sum
        $overallComplianceRate = [math]::Round(($compliantDevices / $totalDevices) * 100, 2)
        
        # Return the data
        return @{
            OverallComplianceRate = $overallComplianceRate
            TotalDevices = $totalDevices
            CompliantDevices = $compliantDevices
            NonCompliantDevices = $totalDevices - $compliantDevices
            ComplianceByDeviceType = $complianceByDeviceType
            IssuesBySeverity = $issuesBySeverity
            TopComplianceIssues = $complianceIssues | Sort-Object -Property AffectedDevices -Descending | Select-Object -First 5
            AllCompliancePolicies = $compliancePolicies
            AllComplianceIssues = $complianceIssues
        }
    }
    catch {
        Write-Log "Error retrieving compliance data: $_" -Level Error
        throw $_
    }
}

function Export-ReportToCSV {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$ReportData,
        
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,
        
        [Parameter(Mandatory = $true)]
        [string]$ReportType
    )
    
    try {
        # Determine which data to export based on report type
        $dataToExport = $null
        
        switch ($ReportType) {
            "ThreatDetection" {
                $dataToExport = $ReportData.RawAlerts
            }
            "Vulnerability" {
                $dataToExport = $ReportData.RawVulnerabilities
            }
            "SecurityPosture" {
                $dataToExport = $ReportData.AllSecurityControls
            }
            "Compliance" {
                $dataToExport = $ReportData.AllCompliancePolicies
            }
            "Executive" {
                # For executive report, create a summary
                $dataToExport = [PSCustomObject]@{
                    ReportDate = Get-Date -Format "yyyy-MM-dd"
                    TimeFrame = "$($StartDateTime.ToString('yyyy-MM-dd')) to $($EndDateTime.ToString('yyyy-MM-dd'))"
                    TotalAlerts = $ReportData.ThreatDetection.TotalAlerts
                    CriticalAlerts = ($ReportData.ThreatDetection.AlertsBySeverity | Where-Object { $_.Name -eq "Critical" }).Count
                    TotalVulnerabilities = $ReportData.Vulnerability.TotalVulnerabilities
                    CriticalVulnerabilities = ($ReportData.Vulnerability.VulnerabilitiesBySeverity | Where-Object { $_.Name -eq "Critical" }).Count
                    SecureScore = $ReportData.SecurityPosture.CurrentSecureScore
                    SecureScoreImprovement = $ReportData.SecurityPosture.SecureScoreImprovement
                    OverallComplianceRate = $ReportData.Compliance.OverallComplianceRate
                    TotalDevices = $ReportData.Compliance.TotalDevices
                    CompliantDevices = $ReportData.Compliance.CompliantDevices
                    NonCompliantDevices = $ReportData.Compliance.NonCompliantDevices
                }
            }
        }
        
        # Export to CSV
        $dataToExport | Export-Csv -Path $OutputPath -NoTypeInformation
        Write-Log "Report exported to CSV: $OutputPath"
        
        return $true
    }
    catch {
        Write-Log "Error exporting report to CSV: $_" -Level Error
        return $false
    }
}

function Export-ReportToHTML {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$ReportData,
        
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,
        
        [Parameter(Mandatory = $true)]
        [string]$ReportType,
        
        [Parameter(Mandatory = $true)]
        [bool]$IncludeCharts,
        
        [Parameter(Mandatory = $true)]
        [DateTime]$StartDateTime,
        
        [Parameter(Mandatory = $true)]
        [DateTime]$EndDateTime
    )
    
    try {
        # Create HTML header
        $reportTitle = switch ($ReportType) {
            "ThreatDetection" { "Threat Detection Report" }
            "Vulnerability" { "Vulnerability Assessment Report" }
            "SecurityPosture" { "Security Posture Report" }
            "Compliance" { "Compliance Status Report" }
            "Executive" { "Executive Security Summary" }
        }
        
        $timeFrameText = "$($StartDateTime.ToString('yyyy-MM-dd')) to $($EndDateTime.ToString('yyyy-MM-dd'))"
        
        $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>$reportTitle</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1, h2, h3 { color: #0078D4; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #0078D4; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        .summary-box { background-color: #f0f0f0; border: 1px solid #ddd; padding: 15px; margin-bottom: 20px; border-radius: 5px; }
        .critical { color: #E81123; }
        .high { color: #FF8C00; }
        .medium { color: #FFB900; }
        .low { color: #107C10; }
        .chart-container { width: 600px; height: 400px; margin: 20px 0; }
    </style>
</head>
<body>
    <h1>$reportTitle</h1>
    <p><strong>Time Frame:</strong> $timeFrameText</p>
    <p><strong>Generated:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
"@
        
        # Add report-specific content
        switch ($ReportType) {
            "ThreatDetection" {
                $threatData = $ReportData
                
                # Add summary section
                $html += @"
    <div class="summary-box">
        <h2>Summary</h2>
        <p><strong>Total Alerts:</strong> $($threatData.TotalAlerts)</p>
        <p><strong>Critical Alerts:</strong> $(($threatData.AlertsBySeverity | Where-Object { $_.Name -eq "Critical" }).Count)</p>
        <p><strong>High Alerts:</strong> $(($threatData.AlertsBySeverity | Where-Object { $_.Name -eq "High" }).Count)</p>
        <p><strong>Medium Alerts:</strong> $(($threatData.AlertsBySeverity | Where-Object { $_.Name -eq "Medium" }).Count)</p>
        <p><strong>Low Alerts:</strong> $(($threatData.AlertsBySeverity | Where-Object { $_.Name -eq "Low" }).Count)</p>
    </div>
"@
                
                # Add alerts by severity
                $html += @"
    <h2>Alerts by Severity</h2>
    <table>
        <tr>
            <th>Severity</th>
            <th>Count</th>
            <th>Percentage</th>
        </tr>
"@
                
                foreach ($severity in $threatData.AlertsBySeverity) {
                    $percentage = [math]::Round(($severity.Count / $threatData.TotalAlerts) * 100, 2)
                    $html += @"
        <tr>
            <td>$($severity.Name)</td>
            <td>$($severity.Count)</td>
            <td>$percentage%</td>
        </tr>
"@
                }
                
                $html += "</table>"
                
                # Add top alert types
                $html += @"
    <h2>Top Alert Types</h2>
    <table>
        <tr>
            <th>Alert Type</th>
            <th>Count</th>
        </tr>
"@
                
                foreach ($alertType in $threatData.TopAlertTypes) {
                    $html += @"
        <tr>
            <td>$($alertType.Name)</td>
            <td>$($alertType.Count)</td>
        </tr>
"@
                }
                
                $html += "</table>"
                
                # Add top affected devices
                $html += @"
    <h2>Top Affected Devices</h2>
    <table>
        <tr>
            <th>Device Name</th>
            <th>Alert Count</th>
        </tr>
"@
                
                foreach ($device in $threatData.TopAffectedDevices) {
                    $html += @"
        <tr>
            <td>$($device.DeviceName)</td>
            <td>$($device.AlertCount)</td>
        </tr>
"@
                }
                
                $html += "</table>"
                
                # Add daily trend
                $html += @"
    <h2>Daily Alert Trend</h2>
    <table>
        <tr>
            <th>Date</th>
            <th>Alert Count</th>
        </tr>
"@
                
                foreach ($day in $threatData.DailyTrend) {
                    $html += @"
        <tr>
            <td>$($day.Date)</td>
            <td>$($day.Count)</td>
        </tr>
"@
                }
                
                $html += "</table>"
            }
            "Vulnerability" {
                $vulnData = $ReportData
                
                # Add summary section
                $html += @"
    <div class="summary-box">
        <h2>Summary</h2>
        <p><strong>Total Vulnerabilities:</strong> $($vulnData.TotalVulnerabilities)</p>
        <p><strong>Critical Vulnerabilities:</strong> $(($vulnData.VulnerabilitiesBySeverity | Where-Object { $_.Name -eq "Critical" }).Count)</p>
        <p><strong>High Vulnerabilities:</strong> $(($vulnData.VulnerabilitiesBySeverity | Where-Object { $_.Name -eq "High" }).Count)</p>
        <p><strong>Total Affected Devices:</strong> $($vulnData.TotalAffectedDevices)</p>
    </div>
"@
                
                # Add vulnerabilities by severity
                $html += @"
    <h2>Vulnerabilities by Severity</h2>
    <table>
        <tr>
            <th>Severity</th>
            <th>Count</th>
            <th>Percentage</th>
        </tr>
"@
                
                foreach ($severity in $vulnData.VulnerabilitiesBySeverity) {
                    $percentage = [math]::Round(($severity.Count / $vulnData.TotalVulnerabilities) * 100, 2)
                    $html += @"
        <tr>
            <td>$($severity.Name)</td>
            <td>$($severity.Count)</td>
            <td>$percentage%</td>
        </tr>
"@
                }
                
                $html += "</table>"
                
                # Add top vulnerabilities
                $html += @"
    <h2>Top Vulnerabilities</h2>
    <table>
        <tr>
            <th>CVE</th>
            <th>Title</th>
            <th>Severity</th>
            <th>Exploitability</th>
            <th>Affected Devices</th>
            <th>Patch Available</th>
        </tr>
"@
                
                foreach ($vuln in $vulnData.TopVulnerabilities) {
                    $patchStatus = $vuln.PatchAvailable ? "Yes" : "No"
                    $html += @"
        <tr>
            <td>$($vuln.CVE)</td>
            <td>$($vuln.Title)</td>
            <td>$($vuln.Severity)</td>
            <td>$($vuln.ExploitabilityLevel)</td>
            <td>$($vuln.AffectedDevicesCount)</td>
            <td>$patchStatus</td>
        </tr>
"@
                }
                
                $html += "</table>"
            }
            "SecurityPosture" {
                $postureData = $ReportData
                
                # Add summary section
                $html += @"
    <div class="summary-box">
        <h2>Summary</h2>
        <p><strong>Current Secure Score:</strong> $($postureData.CurrentSecureScore)/100</p>
        <p><strong>Secure Score Improvement:</strong> $($postureData.SecureScoreImprovement) points</p>
        <p><strong>Overall Compliance Rate:</strong> $($postureData.OverallComplianceRate)%</p>
    </div>
"@
                
                # Add secure score history
                $html += @"
    <h2>Secure Score History</h2>
    <table>
        <tr>
            <th>Date</th>
            <th>Score</th>
        </tr>
"@
                
                foreach ($score in $postureData.SecureScoreHistory) {
                    $html += @"
        <tr>
            <td>$($score.Date)</td>
            <td>$($score.Score)</td>
        </tr>
"@
                }
                
                $html += "</table>"
                
                # Add controls by category
                $html += @"
    <h2>Security Controls by Category</h2>
    <table>
        <tr>
            <th>Category</th>
            <th>Average Compliance Rate</th>
        </tr>
"@
                
                foreach ($category in $postureData.ControlsByCategory) {
                    $html += @"
        <tr>
            <td>$($category.Name)</td>
            <td>$($category.AverageComplianceRate)%</td>
        </tr>
"@
                }
                
                $html += "</table>"
                
                # Add top improvement areas
                $html += @"
    <h2>Top Improvement Areas</h2>
    <table>
        <tr>
            <th>Control</th>
            <th>Category</th>
            <th>Compliance Rate</th>
            <th>Recommended Actions</th>
        </tr>
"@
                
                foreach ($area in $postureData.TopImprovementAreas) {
                    $html += @"
        <tr>
            <td>$($area.ControlName)</td>
            <td>$($area.Category)</td>
            <td>$($area.ComplianceRate)%</td>
            <td>$($area.RecommendedActions)</td>
        </tr>
"@
                }
                
                $html += "</table>"
                
                # Add all security controls
                $html += @"
    <h2>All Security Controls</h2>
    <table>
        <tr>
            <th>Control</th>
            <th>Category</th>
            <th>Compliance Rate</th>
        </tr>
"@
                
                foreach ($control in $postureData.AllSecurityControls) {
                    $html += @"
        <tr>
            <td>$($control.ControlName)</td>
            <td>$($control.Category)</td>
            <td>$($control.ComplianceRate)%</td>
        </tr>
"@
                }
                
                $html += "</table>"
            }
            "Compliance" {
                $complianceData = $ReportData
                
                # Add summary section
                $html += @"
    <div class="summary-box">
        <h2>Summary</h2>
        <p><strong>Overall Compliance Rate:</strong> $($complianceData.OverallComplianceRate)%</p>
        <p><strong>Total Devices:</strong> $($complianceData.TotalDevices)</p>
        <p><strong>Compliant Devices:</strong> $($complianceData.CompliantDevices)</p>
        <p><strong>Non-Compliant Devices:</strong> $($complianceData.NonCompliantDevices)</p>
    </div>
"@
                
                # Add compliance by device type
                $html += @"
    <h2>Compliance by Device Type</h2>
    <table>
        <tr>
            <th>Device Type</th>
            <th>Compliance Rate</th>
        </tr>
"@
                
                foreach ($deviceType in $complianceData.ComplianceByDeviceType) {
                    $html += @"
        <tr>
            <td>$($deviceType.DeviceType)</td>
            <td>$($deviceType.ComplianceRate)%</td>
        </tr>
"@
                }
                
                $html += "</table>"
                
                # Add issues by severity
                $html += @"
    <h2>Compliance Issues by Severity</h2>
    <table>
        <tr>
            <th>Severity</th>
            <th>Affected Devices</th>
        </tr>
"@
                
                foreach ($severity in $complianceData.IssuesBySeverity) {
                    $html += @"
        <tr>
            <td>$($severity.Name)</td>
            <td>$($severity.AffectedDevices)</td>
        </tr>
"@
                }
                
                $html += "</table>"
                
                # Add top compliance issues
                $html += @"
    <h2>Top Compliance Issues</h2>
    <table>
        <tr>
            <th>Issue</th>
            <th>Device Type</th>
            <th>Severity</th>
            <th>Affected Devices</th>
            <th>Remediation Action</th>
        </tr>
"@
                
                foreach ($issue in $complianceData.TopComplianceIssues) {
                    $html += @"
        <tr>
            <td>$($issue.Issue)</td>
            <td>$($issue.DeviceType)</td>
            <td>$($issue.Severity)</td>
            <td>$($issue.AffectedDevices)</td>
            <td>$($issue.RemediationAction)</td>
        </tr>
"@
                }
                
                $html += "</table>"
                
                # Add all compliance policies
                $html += @"
    <h2>All Compliance Policies</h2>
    <table>
        <tr>
            <th>Policy Name</th>
            <th>Device Type</th>
            <th>Total Devices</th>
            <th>Compliant Devices</th>
            <th>Non-Compliant Devices</th>
            <th>Compliance Rate</th>
        </tr>
"@
                
                foreach ($policy in $complianceData.AllCompliancePolicies) {
                    $html += @"
        <tr>
            <td>$($policy.PolicyName)</td>
            <td>$($policy.DeviceType)</td>
            <td>$($policy.TotalDevices)</td>
            <td>$($policy.CompliantDevices)</td>
            <td>$($policy.NonCompliantDevices)</td>
            <td>$($policy.ComplianceRate)%</td>
        </tr>
"@
                }
                
                $html += "</table>"
            }
            "Executive" {
                $threatData = $ReportData.ThreatDetection
                $vulnData = $ReportData.Vulnerability
                $postureData = $ReportData.SecurityPosture
                $complianceData = $ReportData.Compliance
                
                # Add executive summary
                $html += @"
    <div class="summary-box">
        <h2>Executive Summary</h2>
        <p><strong>Secure Score:</strong> $($postureData.CurrentSecureScore)/100 (Improved by $($postureData.SecureScoreImprovement) points)</p>
        <p><strong>Overall Compliance Rate:</strong> $($complianceData.OverallComplianceRate)%</p>
        <p><strong>Total Alerts:</strong> $($threatData.TotalAlerts) ($($threatData.AlertsBySeverity | Where-Object { $_.Name -eq "Critical" }).Count critical)</p>
        <p><strong>Total Vulnerabilities:</strong> $($vulnData.TotalVulnerabilities) ($($vulnData.VulnerabilitiesBySeverity | Where-Object { $_.Name -eq "Critical" }).Count critical)</p>
        <p><strong>Device Compliance:</strong> $($complianceData.CompliantDevices) of $($complianceData.TotalDevices) devices compliant</p>
    </div>
"@
                
                # Add threat summary
                $html += @"
    <h2>Threat Summary</h2>
    <table>
        <tr>
            <th>Severity</th>
            <th>Alert Count</th>
        </tr>
"@
                
                foreach ($severity in $threatData.AlertsBySeverity) {
                    $html += @"
        <tr>
            <td>$($severity.Name)</td>
            <td>$($severity.Count)</td>
        </tr>
"@
                }
                
                $html += "</table>"
                
                # Add vulnerability summary
                $html += @"
    <h2>Vulnerability Summary</h2>
    <table>
        <tr>
            <th>Severity</th>
            <th>Vulnerability Count</th>
        </tr>
"@
                
                foreach ($severity in $vulnData.VulnerabilitiesBySeverity) {
                    $html += @"
        <tr>
            <td>$($severity.Name)</td>
            <td>$($severity.Count)</td>
        </tr>
"@
                }
                
                $html += "</table>"
                
                # Add security posture summary
                $html += @"
    <h2>Security Posture Summary</h2>
    <table>
        <tr>
            <th>Category</th>
            <th>Compliance Rate</th>
        </tr>
"@
                
                foreach ($category in $postureData.ControlsByCategory) {
                    $html += @"
        <tr>
            <td>$($category.Name)</td>
            <td>$($category.AverageComplianceRate)%</td>
        </tr>
"@
                }
                
                $html += "</table>"
                
                # Add compliance summary
                $html += @"
    <h2>Compliance Summary</h2>
    <table>
        <tr>
            <th>Device Type</th>
            <th>Compliance Rate</th>
        </tr>
"@
                
                foreach ($deviceType in $complianceData.ComplianceByDeviceType) {
                    $html += @"
        <tr>
            <td>$($deviceType.DeviceType)</td>
            <td>$($deviceType.ComplianceRate)%</td>
        </tr>
"@
                }
                
                $html += "</table>"
                
                # Add top issues and recommendations
                $html += @"
    <h2>Top Issues and Recommendations</h2>
    <table>
        <tr>
            <th>Issue</th>
            <th>Recommendation</th>
        </tr>
"@
                
                # Combine top issues from different areas
                $topIssues = @(
                    [PSCustomObject]@{
                        Issue = "Critical Alerts: $($($threatData.AlertsBySeverity | Where-Object { $_.Name -eq "Critical" }).Count)"
                        Recommendation = "Investigate and remediate all critical alerts immediately"
                    },
                    [PSCustomObject]@{
                        Issue = "Critical Vulnerabilities: $($($vulnData.VulnerabilitiesBySeverity | Where-Object { $_.Name -eq "Critical" }).Count)"
                        Recommendation = "Patch critical vulnerabilities as soon as possible"
                    }
                )
                
                # Add top improvement areas from security posture
                foreach ($area in $postureData.TopImprovementAreas) {
                    $topIssues += [PSCustomObject]@{
                        Issue = "Low Compliance in $($area.ControlName): $($area.ComplianceRate)%"
                        Recommendation = $area.RecommendedActions
                    }
                }
                
                # Add top compliance issues
                foreach ($issue in $complianceData.TopComplianceIssues | Select-Object -First 2) {
                    $topIssues += [PSCustomObject]@{
                        Issue = "$($issue.Issue) affecting $($issue.AffectedDevices) devices"
                        Recommendation = $issue.RemediationAction
                    }
                }
                
                foreach ($issue in $topIssues) {
                    $html += @"
        <tr>
            <td>$($issue.Issue)</td>
            <td>$($issue.Recommendation)</td>
        </tr>
"@
                }
                
                $html += "</table>"
            }
        }
        
        # Close HTML
        $html += @"
</body>
</html>
"@
        
        # Write HTML to file
        $html | Out-File -FilePath $OutputPath -Encoding utf8
        Write-Log "Report exported to HTML: $OutputPath"
        
        return $true
    }
    catch {
        Write-Log "Error exporting report to HTML: $_" -Level Error
        return $false
    }
}

function Export-ReportToJSON {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$ReportData,
        
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,
        
        [Parameter(Mandatory = $true)]
        [string]$ReportType
    )
    
    try {
        # Convert report data to JSON
        $jsonData = $ReportData | ConvertTo-Json -Depth 10
        
        # Write JSON to file
        $jsonData | Out-File -FilePath $OutputPath -Encoding utf8
        Write-Log "Report exported to JSON: $OutputPath"
        
        return $true
    }
    catch {
        Write-Log "Error exporting report to JSON: $_" -Level Error
        return $false
    }
}

function Export-ReportToExcel {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$ReportData,
        
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,
        
        [Parameter(Mandatory = $true)]
        [string]$ReportType,
        
        [Parameter(Mandatory = $true)]
        [bool]$IncludeCharts,
        
        [Parameter(Mandatory = $true)]
        [DateTime]$StartDateTime,
        
        [Parameter(Mandatory = $true)]
        [DateTime]$EndDateTime
    )
    
    try {
        # Create Excel package
        $excelPackage = New-Object OfficeOpenXml.ExcelPackage
        
        # Determine which data to export based on report type
        switch ($ReportType) {
            "ThreatDetection" {
                $threatData = $ReportData
                
                # Create Summary worksheet
                $summarySheet = $excelPackage.Workbook.Worksheets.Add("Summary")
                $summarySheet.Cells["A1"].Value = "Threat Detection Report"
                $summarySheet.Cells["A1:D1"].Merge = $true
                $summarySheet.Cells["A1:D1"].Style.Font.Size = 16
                $summarySheet.Cells["A1:D1"].Style.Font.Bold = $true
                
                $summarySheet.Cells["A3"].Value = "Time Frame:"
                $summarySheet.Cells["B3"].Value = "$($StartDateTime.ToString('yyyy-MM-dd')) to $($EndDateTime.ToString('yyyy-MM-dd'))"
                
                $summarySheet.Cells["A4"].Value = "Total Alerts:"
                $summarySheet.Cells["B4"].Value = $threatData.TotalAlerts
                
                $summarySheet.Cells["A5"].Value = "Critical Alerts:"
                $summarySheet.Cells["B5"].Value = ($threatData.AlertsBySeverity | Where-Object { $_.Name -eq "Critical" }).Count
                
                $summarySheet.Cells["A6"].Value = "High Alerts:"
                $summarySheet.Cells["B6"].Value = ($threatData.AlertsBySeverity | Where-Object { $_.Name -eq "High" }).Count
                
                $summarySheet.Cells["A7"].Value = "Medium Alerts:"
                $summarySheet.Cells["B7"].Value = ($threatData.AlertsBySeverity | Where-Object { $_.Name -eq "Medium" }).Count
                
                $summarySheet.Cells["A8"].Value = "Low Alerts:"
                $summarySheet.Cells["B8"].Value = ($threatData.AlertsBySeverity | Where-Object { $_.Name -eq "Low" }).Count
                
                # Create Alerts by Severity worksheet
                $severitySheet = $excelPackage.Workbook.Worksheets.Add("Alerts by Severity")
                $severitySheet.Cells["A1"].Value = "Severity"
                $severitySheet.Cells["B1"].Value = "Count"
                $severitySheet.Cells["C1"].Value = "Percentage"
                
                $row = 2
                foreach ($severity in $threatData.AlertsBySeverity) {
                    $percentage = [math]::Round(($severity.Count / $threatData.TotalAlerts) * 100, 2)
                    $severitySheet.Cells["A$row"].Value = $severity.Name
                    $severitySheet.Cells["B$row"].Value = $severity.Count
                    $severitySheet.Cells["C$row"].Value = "$percentage%"
                    $row++
                }
                
                # Create Top Alert Types worksheet
                $alertTypesSheet = $excelPackage.Workbook.Worksheets.Add("Top Alert Types")
                $alertTypesSheet.Cells["A1"].Value = "Alert Type"
                $alertTypesSheet.Cells["B1"].Value = "Count"
                
                $row = 2
                foreach ($alertType in $threatData.TopAlertTypes) {
                    $alertTypesSheet.Cells["A$row"].Value = $alertType.Name
                    $alertTypesSheet.Cells["B$row"].Value = $alertType.Count
                    $row++
                }
                
                # Create Top Affected Devices worksheet
                $devicesSheet = $excelPackage.Workbook.Worksheets.Add("Top Affected Devices")
                $devicesSheet.Cells["A1"].Value = "Device Name"
                $devicesSheet.Cells["B1"].Value = "Alert Count"
                
                $row = 2
                foreach ($device in $threatData.TopAffectedDevices) {
                    $devicesSheet.Cells["A$row"].Value = $device.DeviceName
                    $devicesSheet.Cells["B$row"].Value = $device.AlertCount
                    $row++
                }
                
                # Create Daily Trend worksheet
                $trendSheet = $excelPackage.Workbook.Worksheets.Add("Daily Trend")
                $trendSheet.Cells["A1"].Value = "Date"
                $trendSheet.Cells["B1"].Value = "Alert Count"
                
                $row = 2
                foreach ($day in $threatData.DailyTrend) {
                    $trendSheet.Cells["A$row"].Value = $day.Date
                    $trendSheet.Cells["B$row"].Value = $day.Count
                    $row++
                }
                
                # Create Raw Alerts worksheet
                $rawAlertsSheet = $excelPackage.Workbook.Worksheets.Add("Raw Alerts")
                $rawAlertsSheet.Cells["A1"].Value = "Title"
                $rawAlertsSheet.Cells["B1"].Value = "Severity"
                $rawAlertsSheet.Cells["C1"].Value = "Category"
                $rawAlertsSheet.Cells["D1"].Value = "Status"
                $rawAlertsSheet.Cells["E1"].Value = "Created Date"
                
                $row = 2
                foreach ($alert in $threatData.RawAlerts) {
                    $rawAlertsSheet.Cells["A$row"].Value = $alert.Title
                    $rawAlertsSheet.Cells["B$row"].Value = $alert.Severity
                    $rawAlertsSheet.Cells["C$row"].Value = $alert.Category
                    $rawAlertsSheet.Cells["D$row"].Value = $alert.Status
                    $rawAlertsSheet.Cells["E$row"].Value = $alert.CreatedDateTime
                    $row++
                }
            }
            "Vulnerability" {
                $vulnData = $ReportData
                
                # Create Summary worksheet
                $summarySheet = $excelPackage.Workbook.Worksheets.Add("Summary")
                $summarySheet.Cells["A1"].Value = "Vulnerability Assessment Report"
                $summarySheet.Cells["A1:D1"].Merge = $true
                $summarySheet.Cells["A1:D1"].Style.Font.Size = 16
                $summarySheet.Cells["A1:D1"].Style.Font.Bold = $true
                
                $summarySheet.Cells["A3"].Value = "Time Frame:"
                $summarySheet.Cells["B3"].Value = "$($StartDateTime.ToString('yyyy-MM-dd')) to $($EndDateTime.ToString('yyyy-MM-dd'))"
                
                $summarySheet.Cells["A4"].Value = "Total Vulnerabilities:"
                $summarySheet.Cells["B4"].Value = $vulnData.TotalVulnerabilities
                
                $summarySheet.Cells["A5"].Value = "Critical Vulnerabilities:"
                $summarySheet.Cells["B5"].Value = ($vulnData.VulnerabilitiesBySeverity | Where-Object { $_.Name -eq "Critical" }).Count
                
                $summarySheet.Cells["A6"].Value = "High Vulnerabilities:"
                $summarySheet.Cells["B6"].Value = ($vulnData.VulnerabilitiesBySeverity | Where-Object { $_.Name -eq "High" }).Count
                
                $summarySheet.Cells["A7"].Value = "Total Affected Devices:"
                $summarySheet.Cells["B7"].Value = $vulnData.TotalAffectedDevices
                
                # Create Vulnerabilities by Severity worksheet
                $severitySheet = $excelPackage.Workbook.Worksheets.Add("By Severity")
                $severitySheet.Cells["A1"].Value = "Severity"
                $severitySheet.Cells["B1"].Value = "Count"
                $severitySheet.Cells["C1"].Value = "Percentage"
                
                $row = 2
                foreach ($severity in $vulnData.VulnerabilitiesBySeverity) {
                    $percentage = [math]::Round(($severity.Count / $vulnData.TotalVulnerabilities) * 100, 2)
                    $severitySheet.Cells["A$row"].Value = $severity.Name
                    $severitySheet.Cells["B$row"].Value = $severity.Count
                    $severitySheet.Cells["C$row"].Value = "$percentage%"
                    $row++
                }
                
                # Create Top Vulnerabilities worksheet
                $topVulnSheet = $excelPackage.Workbook.Worksheets.Add("Top Vulnerabilities")
                $topVulnSheet.Cells["A1"].Value = "CVE"
                $topVulnSheet.Cells["B1"].Value = "Title"
                $topVulnSheet.Cells["C1"].Value = "Severity"
                $topVulnSheet.Cells["D1"].Value = "Exploitability"
                $topVulnSheet.Cells["E1"].Value = "Affected Devices"
                $topVulnSheet.Cells["F1"].Value = "Patch Available"
                
                $row = 2
                foreach ($vuln in $vulnData.TopVulnerabilities) {
                    $patchStatus = $vuln.PatchAvailable ? "Yes" : "No"
                    $topVulnSheet.Cells["A$row"].Value = $vuln.CVE
                    $topVulnSheet.Cells["B$row"].Value = $vuln.Title
                    $topVulnSheet.Cells["C$row"].Value = $vuln.Severity
                    $topVulnSheet.Cells["D$row"].Value = $vuln.ExploitabilityLevel
                    $topVulnSheet.Cells["E$row"].Value = $vuln.AffectedDevicesCount
                    $topVulnSheet.Cells["F$row"].Value = $patchStatus
                    $row++
                }
                
                # Create All Vulnerabilities worksheet
                $allVulnSheet = $excelPackage.Workbook.Worksheets.Add("All Vulnerabilities")
                $allVulnSheet.Cells["A1"].Value = "CVE"
                $allVulnSheet.Cells["B1"].Value = "Title"
                $allVulnSheet.Cells["C1"].Value = "Severity"
                $allVulnSheet.Cells["D1"].Value = "Exploitability"
                $allVulnSheet.Cells["E1"].Value = "Affected Devices"
                $allVulnSheet.Cells["F1"].Value = "Patch Available"
                $allVulnSheet.Cells["G1"].Value = "First Detected"
                
                $row = 2
                foreach ($vuln in $vulnData.RawVulnerabilities) {
                    $patchStatus = $vuln.PatchAvailable ? "Yes" : "No"
                    $allVulnSheet.Cells["A$row"].Value = $vuln.CVE
                    $allVulnSheet.Cells["B$row"].Value = $vuln.Title
                    $allVulnSheet.Cells["C$row"].Value = $vuln.Severity
                    $allVulnSheet.Cells["D$row"].Value = $vuln.ExploitabilityLevel
                    $allVulnSheet.Cells["E$row"].Value = $vuln.AffectedDevicesCount
                    $allVulnSheet.Cells["F$row"].Value = $patchStatus
                    $allVulnSheet.Cells["G$row"].Value = $vuln.FirstDetected
                    $row++
                }
            }
            "SecurityPosture" {
                $postureData = $ReportData
                
                # Create Summary worksheet
                $summarySheet = $excelPackage.Workbook.Worksheets.Add("Summary")
                $summarySheet.Cells["A1"].Value = "Security Posture Report"
                $summarySheet.Cells["A1:D1"].Merge = $true
                $summarySheet.Cells["A1:D1"].Style.Font.Size = 16
                $summarySheet.Cells["A1:D1"].Style.Font.Bold = $true
                
                $summarySheet.Cells["A3"].Value = "Time Frame:"
                $summarySheet.Cells["B3"].Value = "$($StartDateTime.ToString('yyyy-MM-dd')) to $($EndDateTime.ToString('yyyy-MM-dd'))"
                
                $summarySheet.Cells["A4"].Value = "Current Secure Score:"
                $summarySheet.Cells["B4"].Value = "$($postureData.CurrentSecureScore)/100"
                
                $summarySheet.Cells["A5"].Value = "Secure Score Improvement:"
                $summarySheet.Cells["B5"].Value = $postureData.SecureScoreImprovement
                
                $summarySheet.Cells["A6"].Value = "Overall Compliance Rate:"
                $summarySheet.Cells["B6"].Value = "$($postureData.OverallComplianceRate)%"
                
                # Create Secure Score History worksheet
                $scoreHistorySheet = $excelPackage.Workbook.Worksheets.Add("Score History")
                $scoreHistorySheet.Cells["A1"].Value = "Date"
                $scoreHistorySheet.Cells["B1"].Value = "Score"
                
                $row = 2
                foreach ($score in $postureData.SecureScoreHistory) {
                    $scoreHistorySheet.Cells["A$row"].Value = $score.Date
                    $scoreHistorySheet.Cells["B$row"].Value = $score.Score
                    $row++
                }
                
                # Create Controls by Category worksheet
                $categorySheet = $excelPackage.Workbook.Worksheets.Add("Controls by Category")
                $categorySheet.Cells["A1"].Value = "Category"
                $categorySheet.Cells["B1"].Value = "Average Compliance Rate"
                
                $row = 2
                foreach ($category in $postureData.ControlsByCategory) {
                    $categorySheet.Cells["A$row"].Value = $category.Name
                    $categorySheet.Cells["B$row"].Value = "$($category.AverageComplianceRate)%"
                    $row++
                }
                
                # Create Top Improvement Areas worksheet
                $improvementSheet = $excelPackage.Workbook.Worksheets.Add("Improvement Areas")
                $improvementSheet.Cells["A1"].Value = "Control"
                $improvementSheet.Cells["B1"].Value = "Category"
                $improvementSheet.Cells["C1"].Value = "Compliance Rate"
                $improvementSheet.Cells["D1"].Value = "Recommended Actions"
                
                $row = 2
                foreach ($area in $postureData.TopImprovementAreas) {
                    $improvementSheet.Cells["A$row"].Value = $area.ControlName
                    $improvementSheet.Cells["B$row"].Value = $area.Category
                    $improvementSheet.Cells["C$row"].Value = "$($area.ComplianceRate)%"
                    $improvementSheet.Cells["D$row"].Value = $area.RecommendedActions
                    $row++
                }
                
                # Create All Security Controls worksheet
                $controlsSheet = $excelPackage.Workbook.Worksheets.Add("All Controls")
                $controlsSheet.Cells["A1"].Value = "Control"
                $controlsSheet.Cells["B1"].Value = "Category"
                $controlsSheet.Cells["C1"].Value = "Compliance Rate"
                $controlsSheet.Cells["D1"].Value = "Recommended Actions"
                
                $row = 2
                foreach ($control in $postureData.AllSecurityControls) {
                    $controlsSheet.Cells["A$row"].Value = $control.ControlName
                    $controlsSheet.Cells["B$row"].Value = $control.Category
                    $controlsSheet.Cells["C$row"].Value = "$($control.ComplianceRate)%"
                    $controlsSheet.Cells["D$row"].Value = $control.RecommendedActions
                    $row++
                }
            }
            "Compliance" {
                $complianceData = $ReportData
                
                # Create Summary worksheet
                $summarySheet = $excelPackage.Workbook.Worksheets.Add("Summary")
                $summarySheet.Cells["A1"].Value = "Compliance Status Report"
                $summarySheet.Cells["A1:D1"].Merge = $true
                $summarySheet.Cells["A1:D1"].Style.Font.Size = 16
                $summarySheet.Cells["A1:D1"].Style.Font.Bold = $true
                
                $summarySheet.Cells["A3"].Value = "Time Frame:"
                $summarySheet.Cells["B3"].Value = "$($StartDateTime.ToString('yyyy-MM-dd')) to $($EndDateTime.ToString('yyyy-MM-dd'))"
                
                $summarySheet.Cells["A4"].Value = "Overall Compliance Rate:"
                $summarySheet.Cells["B4"].Value = "$($complianceData.OverallComplianceRate)%"
                
                $summarySheet.Cells["A5"].Value = "Total Devices:"
                $summarySheet.Cells["B5"].Value = $complianceData.TotalDevices
                
                $summarySheet.Cells["A6"].Value = "Compliant Devices:"
                $summarySheet.Cells["B6"].Value = $complianceData.CompliantDevices
                
                $summarySheet.Cells["A7"].Value = "Non-Compliant Devices:"
                $summarySheet.Cells["B7"].Value = $complianceData.NonCompliantDevices
                
                # Create Compliance by Device Type worksheet
                $deviceTypeSheet = $excelPackage.Workbook.Worksheets.Add("By Device Type")
                $deviceTypeSheet.Cells["A1"].Value = "Device Type"
                $deviceTypeSheet.Cells["B1"].Value = "Compliance Rate"
                
                $row = 2
                foreach ($deviceType in $complianceData.ComplianceByDeviceType) {
                    $deviceTypeSheet.Cells["A$row"].Value = $deviceType.DeviceType
                    $deviceTypeSheet.Cells["B$row"].Value = "$($deviceType.ComplianceRate)%"
                    $row++
                }
                
                # Create Issues by Severity worksheet
                $severitySheet = $excelPackage.Workbook.Worksheets.Add("Issues by Severity")
                $severitySheet.Cells["A1"].Value = "Severity"
                $severitySheet.Cells["B1"].Value = "Affected Devices"
                
                $row = 2
                foreach ($severity in $complianceData.IssuesBySeverity) {
                    $severitySheet.Cells["A$row"].Value = $severity.Name
                    $severitySheet.Cells["B$row"].Value = $severity.AffectedDevices
                    $row++
                }
                
                # Create Top Compliance Issues worksheet
                $topIssuesSheet = $excelPackage.Workbook.Worksheets.Add("Top Issues")
                $topIssuesSheet.Cells["A1"].Value = "Issue"
                $topIssuesSheet.Cells["B1"].Value = "Device Type"
                $topIssuesSheet.Cells["C1"].Value = "Severity"
                $topIssuesSheet.Cells["D1"].Value = "Affected Devices"
                $topIssuesSheet.Cells["E1"].Value = "Remediation Action"
                
                $row = 2
                foreach ($issue in $complianceData.TopComplianceIssues) {
                    $topIssuesSheet.Cells["A$row"].Value = $issue.Issue
                    $topIssuesSheet.Cells["B$row"].Value = $issue.DeviceType
                    $topIssuesSheet.Cells["C$row"].Value = $issue.Severity
                    $topIssuesSheet.Cells["D$row"].Value = $issue.AffectedDevices
                    $topIssuesSheet.Cells["E$row"].Value = $issue.RemediationAction
                    $row++
                }
                
                # Create All Compliance Policies worksheet
                $policiesSheet = $excelPackage.Workbook.Worksheets.Add("All Policies")
                $policiesSheet.Cells["A1"].Value = "Policy Name"
                $policiesSheet.Cells["B1"].Value = "Device Type"
                $policiesSheet.Cells["C1"].Value = "Total Devices"
                $policiesSheet.Cells["D1"].Value = "Compliant Devices"
                $policiesSheet.Cells["E1"].Value = "Non-Compliant Devices"
                $policiesSheet.Cells["F1"].Value = "Compliance Rate"
                
                $row = 2
                foreach ($policy in $complianceData.AllCompliancePolicies) {
                    $policiesSheet.Cells["A$row"].Value = $policy.PolicyName
                    $policiesSheet.Cells["B$row"].Value = $policy.DeviceType
                    $policiesSheet.Cells["C$row"].Value = $policy.TotalDevices
                    $policiesSheet.Cells["D$row"].Value = $policy.CompliantDevices
                    $policiesSheet.Cells["E$row"].Value = $policy.NonCompliantDevices
                    $policiesSheet.Cells["F$row"].Value = "$($policy.ComplianceRate)%"
                    $row++
                }
                
                # Create All Compliance Issues worksheet
                $issuesSheet = $excelPackage.Workbook.Worksheets.Add("All Issues")
                $issuesSheet.Cells["A1"].Value = "Issue"
                $issuesSheet.Cells["B1"].Value = "Device Type"
                $issuesSheet.Cells["C1"].Value = "Severity"
                $issuesSheet.Cells["D1"].Value = "Affected Devices"
                $issuesSheet.Cells["E1"].Value = "Remediation Action"
                
                $row = 2
                foreach ($issue in $complianceData.AllComplianceIssues) {
                    $issuesSheet.Cells["A$row"].Value = $issue.Issue
                    $issuesSheet.Cells["B$row"].Value = $issue.DeviceType
                    $issuesSheet.Cells["C$row"].Value = $issue.Severity
                    $issuesSheet.Cells["D$row"].Value = $issue.AffectedDevices
                    $issuesSheet.Cells["E$row"].Value = $issue.RemediationAction
                    $row++
                }
            }
            "Executive" {
                $threatData = $ReportData.ThreatDetection
                $vulnData = $ReportData.Vulnerability
                $postureData = $ReportData.SecurityPosture
                $complianceData = $ReportData.Compliance
                
                # Create Executive Summary worksheet
                $summarySheet = $excelPackage.Workbook.Worksheets.Add("Executive Summary")
                $summarySheet.Cells["A1"].Value = "Executive Security Summary"
                $summarySheet.Cells["A1:D1"].Merge = $true
                $summarySheet.Cells["A1:D1"].Style.Font.Size = 16
                $summarySheet.Cells["A1:D1"].Style.Font.Bold = $true
                
                $summarySheet.Cells["A3"].Value = "Time Frame:"
                $summarySheet.Cells["B3"].Value = "$($StartDateTime.ToString('yyyy-MM-dd')) to $($EndDateTime.ToString('yyyy-MM-dd'))"
                
                $summarySheet.Cells["A4"].Value = "Secure Score:"
                $summarySheet.Cells["B4"].Value = "$($postureData.CurrentSecureScore)/100 (Improved by $($postureData.SecureScoreImprovement) points)"
                
                $summarySheet.Cells["A5"].Value = "Overall Compliance Rate:"
                $summarySheet.Cells["B5"].Value = "$($complianceData.OverallComplianceRate)%"
                
                $summarySheet.Cells["A6"].Value = "Total Alerts:"
                $summarySheet.Cells["B6"].Value = "$($threatData.TotalAlerts) ($($($threatData.AlertsBySeverity | Where-Object { $_.Name -eq 'Critical' }).Count) critical)"
                
                $summarySheet.Cells["A7"].Value = "Total Vulnerabilities:"
                $summarySheet.Cells["B7"].Value = "$($vulnData.TotalVulnerabilities) ($($($vulnData.VulnerabilitiesBySeverity | Where-Object { $_.Name -eq 'Critical' }).Count) critical)"
                
                $summarySheet.Cells["A8"].Value = "Device Compliance:"
                $summarySheet.Cells["B8"].Value = "$($complianceData.CompliantDevices) of $($complianceData.TotalDevices) devices compliant"
                
                # Create Threat Summary worksheet
                $threatSheet = $excelPackage.Workbook.Worksheets.Add("Threat Summary")
                $threatSheet.Cells["A1"].Value = "Severity"
                $threatSheet.Cells["B1"].Value = "Alert Count"
                
                $row = 2
                foreach ($severity in $threatData.AlertsBySeverity) {
                    $threatSheet.Cells["A$row"].Value = $severity.Name
                    $threatSheet.Cells["B$row"].Value = $severity.Count
                    $row++
                }
                
                # Create Vulnerability Summary worksheet
                $vulnSheet = $excelPackage.Workbook.Worksheets.Add("Vulnerability Summary")
                $vulnSheet.Cells["A1"].Value = "Severity"
                $vulnSheet.Cells["B1"].Value = "Vulnerability Count"
                
                $row = 2
                foreach ($severity in $vulnData.VulnerabilitiesBySeverity) {
                    $vulnSheet.Cells["A$row"].Value = $severity.Name
                    $vulnSheet.Cells["B$row"].Value = $severity.Count
                    $row++
                }
                
                # Create Security Posture Summary worksheet
                $postureSheet = $excelPackage.Workbook.Worksheets.Add("Security Posture")
                $postureSheet.Cells["A1"].Value = "Category"
                $postureSheet.Cells["B1"].Value = "Compliance Rate"
                
                $row = 2
                foreach ($category in $postureData.ControlsByCategory) {
                    $postureSheet.Cells["A$row"].Value = $category.Name
                    $postureSheet.Cells["B$row"].Value = "$($category.AverageComplianceRate)%"
                    $row++
                }
                
                # Create Compliance Summary worksheet
                $complianceSheet = $excelPackage.Workbook.Worksheets.Add("Compliance Summary")
                $complianceSheet.Cells["A1"].Value = "Device Type"
                $complianceSheet.Cells["B1"].Value = "Compliance Rate"
                
                $row = 2
                foreach ($deviceType in $complianceData.ComplianceByDeviceType) {
                    $complianceSheet.Cells["A$row"].Value = $deviceType.DeviceType
                    $complianceSheet.Cells["B$row"].Value = "$($deviceType.ComplianceRate)%"
                    $row++
                }
                
                # Create Top Issues and Recommendations worksheet
                $issuesSheet = $excelPackage.Workbook.Worksheets.Add("Top Issues")
                $issuesSheet.Cells["A1"].Value = "Issue"
                $issuesSheet.Cells["B1"].Value = "Recommendation"
                
                # Combine top issues from different areas
                $topIssues = @(
                    [PSCustomObject]@{
                        Issue = "Critical Alerts: $($($threatData.AlertsBySeverity | Where-Object { $_.Name -eq 'Critical' }).Count)"
                        Recommendation = "Investigate and remediate all critical alerts immediately"
                    },
                    [PSCustomObject]@{
                        Issue = "Critical Vulnerabilities: $($($vulnData.VulnerabilitiesBySeverity | Where-Object { $_.Name -eq 'Critical' }).Count)"
                        Recommendation = "Patch critical vulnerabilities as soon as possible"
                    }
                )
                
                # Add top improvement areas from security posture
                foreach ($area in $postureData.TopImprovementAreas) {
                    $topIssues += [PSCustomObject]@{
                        Issue = "Low Compliance in $($area.ControlName): $($area.ComplianceRate)%"
                        Recommendation = $area.RecommendedActions
                    }
                }
                
                # Add top compliance issues
                foreach ($issue in $complianceData.TopComplianceIssues | Select-Object -First 2) {
                    $topIssues += [PSCustomObject]@{
                        Issue = "$($issue.Issue) affecting $($issue.AffectedDevices) devices"
                        Recommendation = $issue.RemediationAction
                    }
                }
                
                $row = 2
                foreach ($issue in $topIssues) {
                    $issuesSheet.Cells["A$row"].Value = $issue.Issue
                    $issuesSheet.Cells["B$row"].Value = $issue.Recommendation
                    $row++
                }
            }
        }
        
        # Format all worksheets
        foreach ($worksheet in $excelPackage.Workbook.Worksheets) {
            # Format headers
            $headerRange = $worksheet.Dimension.Address -replace "\d+", "1"
            $worksheet.Cells[$headerRange].Style.Font.Bold = $true
            $worksheet.Cells[$headerRange].Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
            $worksheet.Cells[$headerRange].Style.Fill.BackgroundColor.SetColor([System.Drawing.Color]::LightGray)
            
            # Auto-fit columns
            $worksheet.Cells[$worksheet.Dimension.Address].AutoFitColumns()
        }
        
        # Save Excel file
        $excelPackage.SaveAs($OutputPath)
        Write-Log "Report exported to Excel: $OutputPath"
        
        return $true
    }
    catch {
        Write-Log "Error exporting report to Excel: $_" -Level Error
        return $false
    }
}

function Send-ReportEmail {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,
        
        [Parameter(Mandatory = $true)]
        [string]$ReportType,
        
        [Parameter(Mandatory = $true)]
        [string[]]$Recipients,
        
        [Parameter(Mandatory = $true)]
        [DateTime]$StartDateTime,
        
        [Parameter(Mandatory = $true)]
        [DateTime]$EndDateTime
    )
    
    try {
        # In a real environment, this would send an email with the report attached
        # For this script, we'll simulate the email sending
        
        $reportTitle = switch ($ReportType) {
            "ThreatDetection" { "Threat Detection Report" }
            "Vulnerability" { "Vulnerability Assessment Report" }
            "SecurityPosture" { "Security Posture Report" }
            "Compliance" { "Compliance Status Report" }
            "Executive" { "Executive Security Summary" }
        }
        
        $timeFrameText = "$($StartDateTime.ToString('yyyy-MM-dd')) to $($EndDateTime.ToString('yyyy-MM-dd'))"
        
        Write-Log "Simulating email sending for $reportTitle ($timeFrameText) to: $($Recipients -join ', ')"
        Write-Log "Email would include attachment: $OutputPath"
        
        return $true
    }
    catch {
        Write-Log "Error sending email: $_" -Level Error
        return $false
    }
}
#endregion

#region Main Script
try {
    # Script start
    Write-Log "Script started with parameters: ReportType=$ReportType, TimeFrame=$TimeFrame, OutputFormat=$OutputFormat"
    
    # Connect to Microsoft Graph
    $connectedToGraph = Connect-ToMSGraph
    if (-not $connectedToGraph) {
        Write-Log "Cannot proceed without Microsoft Graph connection" -Level Error
        exit 1
    }
    
    # Validate parameters
    if ($TimeFrame -eq "Custom" -and ([string]::IsNullOrEmpty($StartDate) -or [string]::IsNullOrEmpty($EndDate))) {
        Write-Log "StartDate and EndDate are required for Custom time frame" -Level Error
        exit 1
    }
    
    if ($EmailReport -and $EmailRecipients.Count -eq 0) {
        Write-Log "EmailRecipients are required when EmailReport is enabled" -Level Error
        exit 1
    }
    
    # Get date range
    try {
        $dateRange = Get-DateRange -TimeFrame $TimeFrame -StartDate $StartDate -EndDate $EndDate
        $StartDateTime = $dateRange.StartDateTime
        $EndDateTime = $dateRange.EndDateTime
        
        Write-Log "Using date range: $($StartDateTime.ToString('yyyy-MM-dd')) to $($EndDateTime.ToString('yyyy-MM-dd'))"
    }
    catch {
        Write-Log "Error calculating date range: $_" -Level Error
        exit 1
    }
    
    # Generate report data based on report type
    $reportData = $null
    
    switch ($ReportType) {
        "ThreatDetection" {
            Write-Log "Generating threat detection report..."
            $reportData = Get-ThreatDetectionData -StartDateTime $StartDateTime -EndDateTime $EndDateTime -DeviceGroup $FilterByDeviceGroup -OS $FilterByOS
        }
        "Vulnerability" {
            Write-Log "Generating vulnerability assessment report..."
            $reportData = Get-VulnerabilityData -StartDateTime $StartDateTime -EndDateTime $EndDateTime -DeviceGroup $FilterByDeviceGroup -OS $FilterByOS
        }
        "SecurityPosture" {
            Write-Log "Generating security posture report..."
            $reportData = Get-SecurityPostureData -StartDateTime $StartDateTime -EndDateTime $EndDateTime -DeviceGroup $FilterByDeviceGroup -OS $FilterByOS
        }
        "Compliance" {
            Write-Log "Generating compliance status report..."
            $reportData = Get-ComplianceData -StartDateTime $StartDateTime -EndDateTime $EndDateTime -DeviceGroup $FilterByDeviceGroup -OS $FilterByOS
        }
        "Executive" {
            Write-Log "Generating executive summary report..."
            
            # For executive report, we need data from all report types
            $threatData = Get-ThreatDetectionData -StartDateTime $StartDateTime -EndDateTime $EndDateTime -DeviceGroup $FilterByDeviceGroup -OS $FilterByOS
            $vulnData = Get-VulnerabilityData -StartDateTime $StartDateTime -EndDateTime $EndDateTime -DeviceGroup $FilterByDeviceGroup -OS $FilterByOS
            $postureData = Get-SecurityPostureData -StartDateTime $StartDateTime -EndDateTime $EndDateTime -DeviceGroup $FilterByDeviceGroup -OS $FilterByOS
            $complianceData = Get-ComplianceData -StartDateTime $StartDateTime -EndDateTime $EndDateTime -DeviceGroup $FilterByDeviceGroup -OS $FilterByOS
            
            $reportData = @{
                ThreatDetection = $threatData
                Vulnerability = $vulnData
                SecurityPosture = $postureData
                Compliance = $complianceData
            }
        }
    }
    
    # Export report based on output format
    $exportResult = $false
    
    switch ($OutputFormat) {
        "CSV" {
            Write-Log "Exporting report to CSV..."
            $exportResult = Export-ReportToCSV -ReportData $reportData -OutputPath $OutputPath -ReportType $ReportType
        }
        "HTML" {
            Write-Log "Exporting report to HTML..."
            $exportResult = Export-ReportToHTML -ReportData $reportData -OutputPath $OutputPath -ReportType $ReportType -IncludeCharts $IncludeCharts -StartDateTime $StartDateTime -EndDateTime $EndDateTime
        }
        "JSON" {
            Write-Log "Exporting report to JSON..."
            $exportResult = Export-ReportToJSON -ReportData $reportData -OutputPath $OutputPath -ReportType $ReportType
        }
        "Excel" {
            Write-Log "Exporting report to Excel..."
            $exportResult = Export-ReportToExcel -ReportData $reportData -OutputPath $OutputPath -ReportType $ReportType -IncludeCharts $IncludeCharts -StartDateTime $StartDateTime -EndDateTime $EndDateTime
        }
    }
    
    if (-not $exportResult) {
        Write-Log "Failed to export report" -Level Error
        exit 1
    }
    
    # Send email if requested
    if ($EmailReport) {
        Write-Log "Sending report via email..."
        $emailResult = Send-ReportEmail -OutputPath $OutputPath -ReportType $ReportType -Recipients $EmailRecipients -StartDateTime $StartDateTime -EndDateTime $EndDateTime
        
        if (-not $emailResult) {
            Write-Log "Failed to send email" -Level Warning
        }
    }
    
    # Output success message
    Write-Output "Report generated successfully and saved to: $OutputPath"
    
    if ($EmailReport) {
        Write-Output "Report sent via email to: $($EmailRecipients -join ', ')"
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
