<#
.SYNOPSIS
    Analyzes Microsoft Defender XDR alerts for false positives.

.DESCRIPTION
    This script identifies alerts with high false positive rates in Microsoft Defender XDR
    and generates a report with recommendations for alert tuning.
    It analyzes historical alert data to identify patterns and suggest optimization strategies.

.PARAMETER DaysToAnalyze
    The number of days of alert history to analyze.

.PARAMETER FalsePositiveThreshold
    The percentage threshold above which an alert is considered to have a high false positive rate.

.PARAMETER OutputPath
    The path where the report will be saved.

.PARAMETER IncludeRecommendations
    Whether to include tuning recommendations in the report.

.PARAMETER DetailedAnalysis
    Whether to perform a more detailed analysis of alert patterns.

.PARAMETER LogPath
    Path where logs will be stored. Defaults to Windows log directory.

.EXAMPLE
    .\Analyze-DefenderAlertFalsePositives.ps1 -DaysToAnalyze 30 -FalsePositiveThreshold 80 -OutputPath "C:\Reports\FalsePositiveReport.csv" -IncludeRecommendations $true
    Analyzes alerts from the past 30 days, identifies those with a false positive rate above 80%, and generates a report with recommendations.

.NOTES
    Author: Michael Witzsche
    Date: April 26, 2025
    Version: 1.1
#>

#Requires -Modules Microsoft.Graph.Security

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$LogPath = "$env:SystemRoot\Logs\Analyze-DefenderAlertFalsePositives",
    
    [Parameter(Mandatory = $false)]
    [int]$DaysToAnalyze = 30,
    
    [Parameter(Mandatory = $false)]
    [int]$FalsePositiveThreshold = 80,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "$env:USERPROFILE\Desktop\DefenderXDR_FalsePositive_Report_$(Get-Date -Format 'yyyyMMdd').csv",
    
    [Parameter(Mandatory = $false)]
    [bool]$IncludeRecommendations = $true,
    
    [Parameter(Mandatory = $false)]
    [bool]$DetailedAnalysis = $false
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
        Connect-MgGraph -Scopes "SecurityEvents.Read.All", "SecurityAlert.Read.All" -ErrorAction Stop
        
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

function Get-AlertRecommendation {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$AlertType,
        
        [Parameter(Mandatory = $true)]
        [double]$FalsePositiveRate,
        
        [Parameter(Mandatory = $true)]
        [int]$TotalCount,
        
        [Parameter(Mandatory = $true)]
        [int]$FalsePositiveCount
    )
    
    # Define common recommendations based on alert type patterns
    $recommendations = @{
        "Suspicious PowerShell" = "Consider creating exclusions for legitimate PowerShell scripts used in your environment. Review and whitelist administrative scripts."
        "Network connection" = "Review and whitelist legitimate network connections to trusted business applications and services."
        "Suspicious process" = "Analyze the process execution patterns and create exclusions for legitimate business applications."
        "Suspicious file" = "Implement file hash exclusions for legitimate files that are being flagged."
        "Registry modification" = "Create exclusions for legitimate software that modifies registry keys as part of normal operation."
        "Unusual login" = "Refine the baseline for normal login behavior in your environment. Consider adjusting the sensitivity level."
        "Malware detected" = "Verify if the detected malware is a legitimate business tool being misclassified. Consider submitting false positives to Microsoft."
    }
    
    # Default recommendation if no specific match
    $recommendation = "Review alert patterns and consider creating custom exclusions based on legitimate business activities."
    
    # Check for matches in the alert type
    foreach ($key in $recommendations.Keys) {
        if ($AlertType -like "*$key*") {
            $recommendation = $recommendations[$key]
            break
        }
    }
    
    # Add severity-based recommendations
    if ($FalsePositiveRate -gt 95) {
        $recommendation += " Consider disabling this alert type if it provides no value to your security operations."
    }
    elseif ($FalsePositiveRate -gt 85) {
        $recommendation += " Significantly increase the threshold or specificity of detection rules."
    }
    elseif ($FalsePositiveRate -gt 70) {
        $recommendation += " Adjust detection sensitivity or create more specific exclusions."
    }
    
    # Add volume-based recommendations
    if ($TotalCount -gt 100 -and $FalsePositiveRate -gt 70) {
        $recommendation += " High-volume alert with high false positive rate - prioritize tuning to reduce analyst fatigue."
    }
    
    return $recommendation
}
#endregion

#region Main Script
try {
    # Script start
    Write-Log "Script started with parameters: DaysToAnalyze=$DaysToAnalyze, FalsePositiveThreshold=$FalsePositiveThreshold"
    
    # Connect to Microsoft Graph
    $connectedToGraph = Connect-ToMSGraph
    if (-not $connectedToGraph) {
        Write-Log "Cannot proceed without Microsoft Graph connection" -Level Error
        exit 1
    }
    
    # Calculate date range
    $startDate = (Get-Date).AddDays(-$DaysToAnalyze)
    $endDate = Get-Date
    
    Write-Log "Analyzing alerts from $($startDate.ToString('yyyy-MM-dd')) to $($endDate.ToString('yyyy-MM-dd'))"
    
    # Get alerts within the date range
    try {
        $filter = "createdDateTime ge $($startDate.ToString('yyyy-MM-ddT00:00:00Z')) and createdDateTime le $($endDate.ToString('yyyy-MM-ddT23:59:59Z'))"
        Write-Log "Retrieving alerts with filter: $filter"
        
        $alerts = Get-MgSecurityAlert -All -Filter $filter
        
        if ($null -eq $alerts -or $alerts.Count -eq 0) {
            Write-Log "No alerts found in the specified date range" -Level Warning
            exit 0
        }
        
        Write-Log "Retrieved $($alerts.Count) alerts"
    }
    catch {
        Write-Log "Error retrieving alerts: $_" -Level Error
        exit 1
    }
    
    # Group alerts by title and analyze
    Write-Log "Grouping and analyzing alerts..."
    
    $alertStats = $alerts | Group-Object -Property Title | ForEach-Object {
        $alertType = $_.Name
        $totalCount = $_.Count
        $resolvedAsFalsePositive = ($_.Group | Where-Object { $_.Status -eq "Resolved" -and $_.Classification -eq "FalsePositive" }).Count
        $resolvedAsTruePositive = ($_.Group | Where-Object { $_.Status -eq "Resolved" -and $_.Classification -eq "TruePositive" }).Count
        $unresolved = $totalCount - $resolvedAsFalsePositive - $resolvedAsTruePositive
        
        # Calculate false positive rate (only for alerts that have been classified)
        $classifiedCount = $resolvedAsFalsePositive + $resolvedAsTruePositive
        $falsePositiveRate = if ($classifiedCount -gt 0) { [math]::Round(($resolvedAsFalsePositive / $classifiedCount) * 100, 2) } else { 0 }
        
        # Create alert statistics object
        $alertStat = [PSCustomObject]@{
            AlertType = $alertType
            TotalCount = $totalCount
            FalsePositiveCount = $resolvedAsFalsePositive
            TruePositiveCount = $resolvedAsTruePositive
            UnresolvedCount = $unresolved
            FalsePositiveRate = $falsePositiveRate
            Severity = ($_.Group | Select-Object -First 1).Severity
            Category = ($_.Group | Select-Object -First 1).Category
        }
        
        # Add recommendation if requested
        if ($IncludeRecommendations) {
            $alertStat | Add-Member -MemberType NoteProperty -Name "Recommendation" -Value (Get-AlertRecommendation -AlertType $alertType -FalsePositiveRate $falsePositiveRate -TotalCount $totalCount -FalsePositiveCount $resolvedAsFalsePositive)
        }
        
        # Add detailed analysis if requested
        if ($DetailedAnalysis) {
            # Get common entities in false positives
            $falsePositives = $_.Group | Where-Object { $_.Status -eq "Resolved" -and $_.Classification -eq "FalsePositive" }
            
            if ($falsePositives.Count -gt 0) {
                # Extract common hosts
                $commonHosts = $falsePositives.HostStates | Group-Object -Property NetBiosName | 
                    Where-Object { $_.Count -gt 1 } | 
                    Select-Object -Property @{Name="HostName"; Expression={$_.Name}}, Count
                
                # Extract common users
                $commonUsers = $falsePositives.UserStates | Group-Object -Property UserPrincipalName | 
                    Where-Object { $_.Count -gt 1 } | 
                    Select-Object -Property @{Name="UserPrincipalName"; Expression={$_.Name}}, Count
                
                # Add to alert statistics
                $alertStat | Add-Member -MemberType NoteProperty -Name "CommonHosts" -Value ($commonHosts | ConvertTo-Json -Compress)
                $alertStat | Add-Member -MemberType NoteProperty -Name "CommonUsers" -Value ($commonUsers | ConvertTo-Json -Compress)
            }
        }
        
        return $alertStat
    }
    
    # Filter alerts with high false positive rate
    $highFalsePositiveAlerts = $alertStats | Where-Object { $_.FalsePositiveRate -ge $FalsePositiveThreshold } | Sort-Object -Property FalsePositiveRate -Descending
    
    # Generate report
    if ($highFalsePositiveAlerts.Count -gt 0) {
        Write-Log "Found $($highFalsePositiveAlerts.Count) alert types with false positive rate >= $FalsePositiveThreshold%"
        
        # Export to CSV
        $highFalsePositiveAlerts | Export-Csv -Path $OutputPath -NoTypeInformation
        Write-Log "Report exported to: $OutputPath"
        
        # Display results
        Write-Output "Alerts with high false positive rate (>= $FalsePositiveThreshold%):"
        $highFalsePositiveAlerts | Format-Table -Property AlertType, TotalCount, FalsePositiveCount, FalsePositiveRate, Severity -AutoSize
        
        # Display recommendations
        if ($IncludeRecommendations) {
            Write-Output "`nRecommendations for alert tuning:"
            foreach ($alert in $highFalsePositiveAlerts) {
                Write-Output "- $($alert.AlertType) (False Positive Rate: $($alert.FalsePositiveRate)%):"
                Write-Output "  $($alert.Recommendation)"
            }
        }
    }
    else {
        Write-Log "No alerts found with false positive rate >= $FalsePositiveThreshold%"
        Write-Output "No alerts found with false positive rate >= $FalsePositiveThreshold%"
    }
    
    # Provide summary statistics
    $totalAlerts = $alerts.Count
    $totalFalsePositives = ($alerts | Where-Object { $_.Status -eq "Resolved" -and $_.Classification -eq "FalsePositive" }).Count
    $totalTruePositives = ($alerts | Where-Object { $_.Status -eq "Resolved" -and $_.Classification -eq "TruePositive" }).Count
    $totalUnresolved = $totalAlerts - $totalFalsePositives - $totalTruePositives
    
    $overallFalsePositiveRate = if (($totalFalsePositives + $totalTruePositives) -gt 0) {
        [math]::Round(($totalFalsePositives / ($totalFalsePositives + $totalTruePositives)) * 100, 2)
    } else { 0 }
    
    Write-Output "`nOverall Alert Statistics for the Past $DaysToAnalyze Days:"
    Write-Output "  Total Alerts: $totalAlerts"
    Write-Output "  False Positives: $totalFalsePositives"
    Write-Output "  True Positives: $totalTruePositives"
    Write-Output "  Unresolved: $totalUnresolved"
    Write-Output "  Overall False Positive Rate: $overallFalsePositiveRate%"
    
    Write-Log "Analysis completed successfully"
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
