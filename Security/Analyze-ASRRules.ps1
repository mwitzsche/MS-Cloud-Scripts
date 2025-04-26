<#
.SYNOPSIS
    Analyzes and reports on Attack Surface Reduction (ASR) rules configuration and events.

.DESCRIPTION
    This script analyzes Attack Surface Reduction (ASR) rules configuration across the organization,
    reports on rule status, exceptions, and triggered events. It helps security administrators
    identify potential false positives and optimize ASR rule deployment.

.PARAMETER ReportType
    The type of ASR report to generate (Configuration, Events, FalsePositives, Recommendations, All).

.PARAMETER TimeFrame
    The time frame for ASR events data (Last7Days, Last30Days, Last90Days, LastYear).

.PARAMETER Filter
    Hashtable of filters to apply to the report (e.g. @{RuleName="Block Office applications from creating executable content"}).

.PARAMETER IncludeAuditEvents
    Whether to include audit mode events in the report.

.PARAMETER GroupByDevice
    Whether to group results by device instead of by rule.

.PARAMETER ExportPath
    The path where the report will be saved.

.PARAMETER ExportFormat
    The format of the export file (CSV, JSON, Excel, HTML).

.PARAMETER LogPath
    Path where logs will be stored. Defaults to Windows log directory.

.EXAMPLE
    .\Analyze-ASRRules.ps1 -ReportType Configuration -ExportPath "C:\Reports\ASRConfiguration.csv" -ExportFormat CSV
    Generates an ASR rules configuration report and exports it to CSV format.

.EXAMPLE
    .\Analyze-ASRRules.ps1 -ReportType FalsePositives -TimeFrame Last30Days -ExportPath "C:\Reports\ASRFalsePositives.xlsx" -ExportFormat Excel
    Generates an ASR false positives report for the last 30 days and exports it to Excel format.

.NOTES
    Author: Michael Witzsche
    Date: April 26, 2025
    Version: 1.0.0
    
    History:
    1.0.0 - Initial release
#>

#Requires -Modules Microsoft.Graph.DeviceManagement, Microsoft.Graph.Security, Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.Authentication, ImportExcel

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$LogPath = "$env:SystemRoot\Logs\Analyze-ASRRules",
    
    [Parameter(Mandatory = $true)]
    [ValidateSet("Configuration", "Events", "FalsePositives", "Recommendations", "All")]
    [string]$ReportType,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Last7Days", "Last30Days", "Last90Days", "LastYear")]
    [string]$TimeFrame = "Last30Days",
    
    [Parameter(Mandatory = $false)]
    [hashtable]$Filter = @{},
    
    [Parameter(Mandatory = $false)]
    [bool]$IncludeAuditEvents = $true,
    
    [Parameter(Mandatory = $false)]
    [bool]$GroupByDevice = $false,
    
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
            "DeviceManagementConfiguration.Read.All",
            "DeviceManagementManagedDevices.Read.All",
            "SecurityEvents.Read.All",
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

function Get-ASRRuleInfo {
    [CmdletBinding()]
    param()
    
    # Define ASR rules with their GUIDs and descriptions
    $asrRules = @(
        @{
            Name = "Block executable content from email client and webmail"
            Id = "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550"
            Description = "This rule blocks executable files from being run or launched from an email seen in either Microsoft Outlook or webmail (such as Gmail.com or Outlook.com)."
            SupportedOS = "Windows 10, Windows 11"
            RecommendedState = "Enabled"
            Impact = "Low"
        },
        @{
            Name = "Block all Office applications from creating child processes"
            Id = "D4F940AB-401B-4EFC-AADC-AD5F3C50688A"
            Description = "This rule blocks Office apps from creating child processes. Office apps include Word, Excel, PowerPoint, OneNote, and Access."
            SupportedOS = "Windows 10, Windows 11"
            RecommendedState = "Enabled"
            Impact = "Medium"
        },
        @{
            Name = "Block Office applications from creating executable content"
            Id = "3B576869-A4EC-4529-8536-B80A7769E899"
            Description = "This rule blocks Office apps from creating executable content. Office apps include Word, Excel, PowerPoint, OneNote, and Access."
            SupportedOS = "Windows 10, Windows 11"
            RecommendedState = "Enabled"
            Impact = "Low"
        },
        @{
            Name = "Block Office applications from injecting code into other processes"
            Id = "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84"
            Description = "This rule blocks code injection attempts from Office apps into other processes. Office apps include Word, Excel, PowerPoint, OneNote, and Access."
            SupportedOS = "Windows 10, Windows 11"
            RecommendedState = "Enabled"
            Impact = "Low"
        },
        @{
            Name = "Block JavaScript or VBScript from launching downloaded executable content"
            Id = "D3E037E1-3EB8-44C8-A917-57927947596D"
            Description = "This rule helps prevent JavaScript and VBScript scripts from launching downloaded executable content."
            SupportedOS = "Windows 10, Windows 11"
            RecommendedState = "Enabled"
            Impact = "Low"
        },
        @{
            Name = "Block execution of potentially obfuscated scripts"
            Id = "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC"
            Description = "This rule detects suspicious properties within obfuscated scripts."
            SupportedOS = "Windows 10, Windows 11"
            RecommendedState = "Enabled"
            Impact = "Medium"
        },
        @{
            Name = "Block Win32 API calls from Office macros"
            Id = "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B"
            Description = "This rule blocks Win32 API calls from Office macros."
            SupportedOS = "Windows 10, Windows 11"
            RecommendedState = "Enabled"
            Impact = "Medium"
        },
        @{
            Name = "Block executable files from running unless they meet a prevalence, age, or trusted list criterion"
            Id = "01443614-CD74-433A-B99E-2ECDC07BFC25"
            Description = "This rule blocks executable files from running unless they meet a prevalence, age, or trusted list criterion."
            SupportedOS = "Windows 10, Windows 11"
            RecommendedState = "Audit"
            Impact = "High"
        },
        @{
            Name = "Block credential stealing from the Windows local security authority subsystem"
            Id = "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2"
            Description = "This rule helps prevent credential stealing by blocking suspicious programs from accessing the LSASS process."
            SupportedOS = "Windows 10, Windows 11"
            RecommendedState = "Enabled"
            Impact = "Low"
        },
        @{
            Name = "Block process creations originating from PSExec and WMI commands"
            Id = "D1E49AAC-8F56-4280-B9BA-993A6D77406C"
            Description = "This rule blocks processes created through PsExec and WMI from running."
            SupportedOS = "Windows 10, Windows 11"
            RecommendedState = "Audit"
            Impact = "Medium"
        },
        @{
            Name = "Block untrusted and unsigned processes that run from USB"
            Id = "B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4"
            Description = "This rule blocks untrusted and unsigned processes that run from USB removable drives."
            SupportedOS = "Windows 10, Windows 11"
            RecommendedState = "Enabled"
            Impact = "Low"
        },
        @{
            Name = "Block Office communication application from creating child processes"
            Id = "26190899-1602-49E8-8B27-EB1D0A1CE869"
            Description = "This rule blocks Office communication apps from creating child processes. Communication apps include Microsoft Teams, Skype for Business, and Microsoft Lync."
            SupportedOS = "Windows 10 1709 or later, Windows 11"
            RecommendedState = "Enabled"
            Impact = "Low"
        },
        @{
            Name = "Block Adobe Reader from creating child processes"
            Id = "7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C"
            Description = "This rule blocks Adobe Reader from creating child processes."
            SupportedOS = "Windows 10 1709 or later, Windows 11"
            RecommendedState = "Enabled"
            Impact = "Low"
        },
        @{
            Name = "Block persistence through WMI event subscription"
            Id = "E6DB77E5-3DF2-4CF1-B95A-636979351E5B"
            Description = "This rule prevents malware from abusing WMI to attain persistence on a device."
            SupportedOS = "Windows 10 1903 or later, Windows 11"
            RecommendedState = "Enabled"
            Impact = "Low"
        },
        @{
            Name = "Block abuse of exploited vulnerable signed drivers"
            Id = "56A863A9-875E-4185-98A7-B882C64B5CE5"
            Description = "This rule prevents applications from writing to protected kernel memory locations."
            SupportedOS = "Windows 10 1709 or later, Windows 11"
            RecommendedState = "Enabled"
            Impact = "Low"
        },
        @{
            Name = "Use advanced protection against ransomware"
            Id = "C1DB55AB-C21A-4637-BB3F-A12568109D35"
            Description = "This rule provides an extra layer of protection against ransomware."
            SupportedOS = "Windows 10 1803 or later, Windows 11"
            RecommendedState = "Enabled"
            Impact = "Medium"
        }
    )
    
    return $asrRules
}

function Get-ASRConfigurationReport {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [hashtable]$Filter = @{}
    )
    
    try {
        Write-Log "Generating ASR rules configuration report..."
        
        # Get ASR rule information
        $asrRules = Get-ASRRuleInfo
        
        # Get ASR configuration policies
        $asrPolicies = Get-MgDeviceManagementConfigurationPolicy -All | Where-Object { 
            $_.TemplateReference.TemplateId -eq "e8c053d6-9f95-42b1-a7f1-ebfd71c67a4b" -or # Endpoint security Attack surface reduction
            $_.TemplateReference.TemplateId -eq "0e237410-1367-4844-bd7f-15fb0f08943b"     # Device configuration profile with ASR settings
        }
        
        if ($null -eq $asrPolicies -or $asrPolicies.Count -eq 0) {
            Write-Log "No ASR configuration policies found" -Level Warning
            return $null
        }
        
        Write-Log "Retrieved $($asrPolicies.Count) ASR configuration policies"
        
        # Create report
        $report = @()
        
        foreach ($rule in $asrRules) {
            # Apply custom filters
            if ($Filter.ContainsKey("RuleName") -and $rule.Name -notlike "*$($Filter.RuleName)*") {
                continue
            }
            
            if ($Filter.ContainsKey("RuleId") -and $rule.Id -ne $Filter.RuleId) {
                continue
            }
            
            # Count policy configurations for this rule
            $enabledCount = 0
            $auditCount = 0
            $disabledCount = 0
            $notConfiguredCount = 0
            $policiesConfiguring = @()
            
            foreach ($policy in $asrPolicies) {
                # Get policy settings
                $policySettings = Get-MgDeviceManagementConfigurationPolicySetting -DeviceManagementConfigurationPolicyId $policy.Id
                
                # Check if policy configures this rule
                $ruleSetting = $policySettings | Where-Object { 
                    $_.SettingInstance.AdditionalProperties.simpleSettingValue.value -eq $rule.Id -or
                    $_.SettingInstance.AdditionalProperties.simpleSettingCollectionValue.values -contains $rule.Id
                }
                
                if ($null -ne $ruleSetting) {
                    $ruleState = "Not Configured"
                    
                    # Determine rule state
                    if ($ruleSetting.SettingInstance.AdditionalProperties.simpleSettingValue.value -eq $rule.Id) {
                        # Individual rule setting
                        $stateSettingId = $ruleSetting.SettingInstance.AdditionalProperties.settingDefinitionId -replace "AsrRuleIds", "AsrRuleStates"
                        $stateSetting = $policySettings | Where-Object { 
                            $_.SettingInstance.AdditionalProperties.settingDefinitionId -eq $stateSettingId 
                        }
                        
                        if ($null -ne $stateSetting) {
                            $stateValue = $stateSetting.SettingInstance.AdditionalProperties.simpleSettingValue.value
                            switch ($stateValue) {
                                "0" { $ruleState = "Disabled"; $disabledCount++ }
                                "1" { $ruleState = "Enabled"; $enabledCount++ }
                                "2" { $ruleState = "Audit"; $auditCount++ }
                                default { $ruleState = "Not Configured"; $notConfiguredCount++ }
                            }
                        }
                    }
                    elseif ($ruleSetting.SettingInstance.AdditionalProperties.simpleSettingCollectionValue.values -contains $rule.Id) {
                        # Collection of rules
                        $collectionType = $ruleSetting.SettingInstance.AdditionalProperties.settingDefinitionId
                        
                        if ($collectionType -like "*Enabled*") {
                            $ruleState = "Enabled"
                            $enabledCount++
                        }
                        elseif ($collectionType -like "*Audit*") {
                            $ruleState = "Audit"
                            $auditCount++
                        }
                        elseif ($collectionType -like "*Disabled*") {
                            $ruleState = "Disabled"
                            $disabledCount++
                        }
                        else {
                            $ruleState = "Not Configured"
                            $notConfiguredCount++
                        }
                    }
                    
                    # Add policy to list
                    $policiesConfiguring += [PSCustomObject]@{
                        PolicyName = $policy.Name
                        PolicyId = $policy.Id
                        State = $ruleState
                    }
                }
                else {
                    $notConfiguredCount++
                }
            }
            
            # Get exceptions for this rule
            $exceptions = @()
            foreach ($policy in $asrPolicies) {
                $policySettings = Get-MgDeviceManagementConfigurationPolicySetting -DeviceManagementConfigurationPolicyId $policy.Id
                
                $exceptionSetting = $policySettings | Where-Object { 
                    $_.SettingInstance.AdditionalProperties.settingDefinitionId -like "*AsrRuleExclusions*" -and
                    $_.SettingInstance.AdditionalProperties.simpleSettingValue.value -eq $rule.Id
                }
                
                if ($null -ne $exceptionSetting) {
                    $exceptionPaths = $policySettings | Where-Object { 
                        $_.SettingInstance.AdditionalProperties.settingDefinitionId -like "*AsrRuleExclusionPaths*" 
                    }
                    
                    if ($null -ne $exceptionPaths) {
                        $paths = $exceptionPaths.SettingInstance.AdditionalProperties.stringCollectionSettingValue.values
                        
                        $exceptions += [PSCustomObject]@{
                            PolicyName = $policy.Name
                            PolicyId = $policy.Id
                            Paths = $paths -join "; "
                        }
                    }
                }
            }
            
            # Determine overall state
            $overallState = "Not Configured"
            if ($enabledCount -gt 0) {
                $overallState = "Enabled"
            }
            elseif ($auditCount -gt 0) {
                $overallState = "Audit"
            }
            elseif ($disabledCount -gt 0) {
                $overallState = "Disabled"
            }
            
            # Format policies configuring this rule
            $policiesConfiguringText = ($policiesConfiguring | ForEach-Object {
                "$($_.PolicyName) ($($_.State))"
            }) -join "; "
            
            # Format exceptions
            $exceptionsText = ($exceptions | ForEach-Object {
                "$($_.PolicyName): $($_.Paths)"
            }) -join "; "
            
            if ([string]::IsNullOrEmpty($exceptionsText)) {
                $exceptionsText = "None"
            }
            
            # Add to report
            $report += [PSCustomObject]@{
                RuleName = $rule.Name
                RuleId = $rule.Id
                Description = $rule.Description
                SupportedOS = $rule.SupportedOS
                RecommendedState = $rule.RecommendedState
                Impact = $rule.Impact
                CurrentState = $overallState
                EnabledPolicies = $enabledCount
                AuditPolicies = $auditCount
                DisabledPolicies = $disabledCount
                NotConfiguredPolicies = $notConfiguredCount
                PoliciesConfiguring = $policiesConfiguringText
                Exceptions = $exceptionsText
                AlignedWithRecommendation = ($overallState -eq $rule.RecommendedState)
            }
        }
        
        # Apply additional filters
        if ($Filter.ContainsKey("CurrentState")) {
            $report = $report | Where-Object { $_.CurrentState -eq $Filter.CurrentState }
        }
        
        if ($Filter.ContainsKey("AlignedWithRecommendation")) {
            $report = $report | Where-Object { $_.AlignedWithRecommendation -eq [bool]::Parse($Filter.AlignedWithRecommendation) }
        }
        
        Write-Log "Generated ASR configuration report with $($report.Count) entries"
        return $report
    }
    catch {
        Write-Log "Error generating ASR configuration report: $_" -Level Error
        return $null
    }
}

function Get-ASREventsReport {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [hashtable]$Filter = @{},
        
        [Parameter(Mandatory = $false)]
        [string]$TimeFrame = "Last30Days",
        
        [Parameter(Mandatory = $false)]
        [bool]$IncludeAuditEvents = $true,
        
        [Parameter(Mandatory = $false)]
        [bool]$GroupByDevice = $false
    )
    
    try {
        Write-Log "Generating ASR events report for time frame: $TimeFrame..."
        
        # Get time frame filter
        $timeFrameFilter = Get-TimeFrameFilter -TimeFrame $TimeFrame
        
        # Get ASR rule information
        $asrRules = Get-ASRRuleInfo
        
        # Create lookup dictionary for rule names
        $ruleNameLookup = @{}
        foreach ($rule in $asrRules) {
            $ruleNameLookup[$rule.Id] = $rule.Name
        }
        
        # Build filter string for security events
        $filterStrings = @()
        
        # Add time frame filter
        $filterStrings += "createdDateTime ge $($timeFrameFilter.StartDateString)"
        
        # Add category filter for ASR events
        $filterStrings += "category eq 'AttackSurfaceReductionRule'"
        
        # Add custom filters
        if ($Filter.ContainsKey("RuleName") -or $Filter.ContainsKey("RuleId")) {
            $ruleIdFilter = ""
            
            if ($Filter.ContainsKey("RuleId")) {
                $ruleIdFilter = $Filter.RuleId
            }
            elseif ($Filter.ContainsKey("RuleName")) {
                $matchingRule = $asrRules | Where-Object { $_.Name -like "*$($Filter.RuleName)*" } | Select-Object -First 1
                if ($null -ne $matchingRule) {
                    $ruleIdFilter = $matchingRule.Id
                }
            }
            
            if (-not [string]::IsNullOrEmpty($ruleIdFilter)) {
                $filterStrings += "properties/ruleId eq '$ruleIdFilter'"
            }
        }
        
        if ($Filter.ContainsKey("DeviceName")) {
            $filterStrings += "contains(deviceName, '$($Filter.DeviceName)')"
        }
        
        if ($Filter.ContainsKey("UserName")) {
            $filterStrings += "contains(userPrincipalName, '$($Filter.UserName)')"
        }
        
        if (-not $IncludeAuditEvents) {
            $filterStrings += "properties/actionType ne 'Audit'"
        }
        
        # Combine filter strings
        $filterString = $filterStrings -join " and "
        
        # Get security events with filter
        $events = Get-MgSecurityAlert -Filter $filterString -All
        
        if ($null -eq $events -or $events.Count -eq 0) {
            Write-Log "No ASR events found with the specified filters" -Level Warning
            return $null
        }
        
        Write-Log "Retrieved $($events.Count) ASR events"
        
        # Create report
        $report = @()
        
        foreach ($event in $events) {
            # Extract event properties
            $ruleId = $event.AdditionalProperties.properties.ruleId
            $ruleName = if ($ruleNameLookup.ContainsKey($ruleId)) { $ruleNameLookup[$ruleId] } else { "Unknown Rule" }
            $actionType = $event.AdditionalProperties.properties.actionType
            $processName = $event.AdditionalProperties.properties.processName
            $processPath = $event.AdditionalProperties.properties.processPath
            
            # Add to report
            $reportEntry = [PSCustomObject]@{
                EventId = $event.Id
                RuleId = $ruleId
                RuleName = $ruleName
                ActionType = $actionType
                ProcessName = $processName
                ProcessPath = $processPath
                DeviceName = $event.DeviceName
                UserName = $event.UserPrincipalName
                Timestamp = $event.CreatedDateTime
                TimeFrame = $TimeFrame
            }
            
            $report += $reportEntry
        }
        
        # Group by device if requested
        if ($GroupByDevice) {
            $groupedReport = @()
            $deviceGroups = $report | Group-Object -Property DeviceName
            
            foreach ($deviceGroup in $deviceGroups) {
                $deviceName = $deviceGroup.Name
                $deviceEvents = $deviceGroup.Group
                
                # Group events by rule
                $ruleGroups = $deviceEvents | Group-Object -Property RuleId, RuleName, ActionType
                
                foreach ($ruleGroup in $ruleGroups) {
                    $ruleParts = $ruleGroup.Name -split ", "
                    $ruleId = $ruleParts[0]
                    $ruleName = $ruleParts[1]
                    $actionType = $ruleParts[2]
                    $eventCount = $ruleGroup.Count
                    
                    # Get most recent event
                    $mostRecentEvent = $ruleGroup.Group | Sort-Object -Property Timestamp -Descending | Select-Object -First 1
                    
                    # Get unique processes
                    $uniqueProcesses = ($ruleGroup.Group | Select-Object -Property ProcessName, ProcessPath -Unique | ForEach-Object {
                        "$($_.ProcessName) ($($_.ProcessPath))"
                    }) -join "; "
                    
                    $groupedReport += [PSCustomObject]@{
                        DeviceName = $deviceName
                        RuleId = $ruleId
                        RuleName = $ruleName
                        ActionType = $actionType
                        EventCount = $eventCount
                        UniqueProcesses = $uniqueProcesses
                        MostRecentTimestamp = $mostRecentEvent.Timestamp
                        TimeFrame = $TimeFrame
                    }
                }
            }
            
            $report = $groupedReport
        }
        
        Write-Log "Generated ASR events report with $($report.Count) entries"
        return $report
    }
    catch {
        Write-Log "Error generating ASR events report: $_" -Level Error
        return $null
    }
}

function Get-ASRFalsePositivesReport {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [hashtable]$Filter = @{},
        
        [Parameter(Mandatory = $false)]
        [string]$TimeFrame = "Last30Days"
    )
    
    try {
        Write-Log "Generating ASR false positives report for time frame: $TimeFrame..."
        
        # Get ASR events
        $eventsReport = Get-ASREventsReport -Filter $Filter -TimeFrame $TimeFrame -IncludeAuditEvents $true -GroupByDevice $false
        
        if ($null -eq $eventsReport -or $eventsReport.Count -eq 0) {
            Write-Log "No ASR events found for false positive analysis" -Level Warning
            return $null
        }
        
        # Get ASR configuration
        $configReport = Get-ASRConfigurationReport -Filter $Filter
        
        if ($null -eq $configReport -or $configReport.Count -eq 0) {
            Write-Log "No ASR configuration found for false positive analysis" -Level Warning
            return $null
        }
        
        # Create lookup dictionary for rule configurations
        $ruleConfigLookup = @{}
        foreach ($config in $configReport) {
            $ruleConfigLookup[$config.RuleId] = $config
        }
        
        # Group events by rule, process, and action type
        $eventGroups = $eventsReport | Group-Object -Property RuleId, ProcessName, ProcessPath, ActionType
        
        # Create report
        $report = @()
        
        foreach ($group in $eventGroups) {
            $groupParts = $group.Name -split ", "
            $ruleId = $groupParts[0]
            $processName = $groupParts[1]
            $processPath = $groupParts[2]
            $actionType = $groupParts[3]
            $eventCount = $group.Count
            
            # Get unique devices affected
            $uniqueDevices = ($group.Group | Select-Object -Property DeviceName -Unique).Count
            
            # Get unique users affected
            $uniqueUsers = ($group.Group | Where-Object { -not [string]::IsNullOrEmpty($_.UserName) } | Select-Object -Property UserName -Unique).Count
            
            # Get most recent event
            $mostRecentEvent = $group.Group | Sort-Object -Property Timestamp -Descending | Select-Object -First 1
            
            # Get rule configuration
            $ruleConfig = $ruleConfigLookup[$ruleId]
            $ruleName = if ($null -ne $ruleConfig) { $ruleConfig.RuleName } else { "Unknown Rule" }
            $ruleDescription = if ($null -ne $ruleConfig) { $ruleConfig.Description } else { "" }
            $currentState = if ($null -ne $ruleConfig) { $ruleConfig.CurrentState } else { "Unknown" }
            $exceptions = if ($null -ne $ruleConfig) { $ruleConfig.Exceptions } else { "None" }
            
            # Determine if this is likely a false positive
            $isFalsePositive = $false
            $falsePositiveReason = ""
            
            # Check for common false positive indicators
            if ($processPath -like "*\Program Files\*" -or $processPath -like "*\Program Files (x86)\*") {
                $isFalsePositive = $true
                $falsePositiveReason = "Legitimate application path"
            }
            elseif ($processPath -like "*\Windows\*") {
                $isFalsePositive = $true
                $falsePositiveReason = "Windows system path"
            }
            elseif ($eventCount -gt 10 -and $uniqueDevices -gt 5) {
                $isFalsePositive = $true
                $falsePositiveReason = "High frequency across multiple devices"
            }
            
            # Only include likely false positives in the report
            if ($isFalsePositive) {
                $report += [PSCustomObject]@{
                    RuleId = $ruleId
                    RuleName = $ruleName
                    RuleDescription = $ruleDescription
                    ProcessName = $processName
                    ProcessPath = $processPath
                    ActionType = $actionType
                    EventCount = $eventCount
                    UniqueDevices = $uniqueDevices
                    UniqueUsers = $uniqueUsers
                    MostRecentTimestamp = $mostRecentEvent.Timestamp
                    CurrentRuleState = $currentState
                    CurrentExceptions = $exceptions
                    FalsePositiveReason = $falsePositiveReason
                    RecommendedAction = "Add exception for '$processPath'"
                    TimeFrame = $TimeFrame
                }
            }
        }
        
        # Sort by event count descending
        $report = $report | Sort-Object -Property EventCount -Descending
        
        Write-Log "Generated ASR false positives report with $($report.Count) entries"
        return $report
    }
    catch {
        Write-Log "Error generating ASR false positives report: $_" -Level Error
        return $null
    }
}

function Get-ASRRecommendationsReport {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [hashtable]$Filter = @{},
        
        [Parameter(Mandatory = $false)]
        [string]$TimeFrame = "Last30Days"
    )
    
    try {
        Write-Log "Generating ASR recommendations report..."
        
        # Get ASR configuration
        $configReport = Get-ASRConfigurationReport -Filter $Filter
        
        if ($null -eq $configReport -or $configReport.Count -eq 0) {
            Write-Log "No ASR configuration found for recommendations analysis" -Level Warning
            return $null
        }
        
        # Get ASR events
        $eventsReport = Get-ASREventsReport -Filter $Filter -TimeFrame $TimeFrame -IncludeAuditEvents $true -GroupByDevice $true
        
        # Create lookup dictionary for rule events
        $ruleEventsLookup = @{}
        if ($null -ne $eventsReport) {
            foreach ($event in $eventsReport) {
                if (-not $ruleEventsLookup.ContainsKey($event.RuleId)) {
                    $ruleEventsLookup[$event.RuleId] = @()
                }
                
                $ruleEventsLookup[$event.RuleId] += $event
            }
        }
        
        # Get false positives
        $falsePositivesReport = Get-ASRFalsePositivesReport -Filter $Filter -TimeFrame $TimeFrame
        
        # Create lookup dictionary for rule false positives
        $ruleFalsePositivesLookup = @{}
        if ($null -ne $falsePositivesReport) {
            foreach ($falsePositive in $falsePositivesReport) {
                if (-not $ruleFalsePositivesLookup.ContainsKey($falsePositive.RuleId)) {
                    $ruleFalsePositivesLookup[$falsePositive.RuleId] = @()
                }
                
                $ruleFalsePositivesLookup[$falsePositive.RuleId] += $falsePositive
            }
        }
        
        # Create report
        $report = @()
        
        foreach ($config in $configReport) {
            # Get events for this rule
            $ruleEvents = if ($ruleEventsLookup.ContainsKey($config.RuleId)) { $ruleEventsLookup[$config.RuleId] } else { @() }
            
            # Get false positives for this rule
            $ruleFalsePositives = if ($ruleFalsePositivesLookup.ContainsKey($config.RuleId)) { $ruleFalsePositivesLookup[$config.RuleId] } else { @() }
            
            # Count events by action type
            $blockEvents = ($ruleEvents | Where-Object { $_.ActionType -eq "Block" }).Count
            $auditEvents = ($ruleEvents | Where-Object { $_.ActionType -eq "Audit" }).Count
            
            # Count unique devices with events
            $uniqueDevices = if ($ruleEvents.Count -gt 0) { ($ruleEvents | Select-Object -Property DeviceName -Unique).Count } else { 0 }
            
            # Determine recommendation
            $recommendation = ""
            $justification = ""
            
            if ($config.CurrentState -eq "Not Configured") {
                # Rule is not configured
                if ($config.RecommendedState -eq "Enabled") {
                    $recommendation = "Enable in Audit mode"
                    $justification = "Rule is recommended to be enabled but is not configured"
                }
                elseif ($config.RecommendedState -eq "Audit") {
                    $recommendation = "Enable in Audit mode"
                    $justification = "Rule is recommended to be in audit mode but is not configured"
                }
            }
            elseif ($config.CurrentState -eq "Audit") {
                # Rule is in audit mode
                if ($config.RecommendedState -eq "Enabled" -and $auditEvents -eq 0) {
                    $recommendation = "Enable in Block mode"
                    $justification = "Rule is recommended to be enabled and no audit events were detected"
                }
                elseif ($config.RecommendedState -eq "Enabled" -and $auditEvents -gt 0 -and $ruleFalsePositives.Count -eq 0) {
                    $recommendation = "Enable in Block mode with exceptions"
                    $justification = "Rule is recommended to be enabled and audit events were detected, but no false positives identified"
                }
                elseif ($config.RecommendedState -eq "Enabled" -and $ruleFalsePositives.Count -gt 0) {
                    $recommendation = "Add exceptions for false positives before enabling"
                    $justification = "Rule is recommended to be enabled but false positives were identified"
                }
            }
            elseif ($config.CurrentState -eq "Enabled") {
                # Rule is enabled
                if ($config.RecommendedState -eq "Audit" -or $config.RecommendedState -eq "Disabled") {
                    $recommendation = "Consider changing to Audit mode"
                    $justification = "Rule is currently enabled but recommended to be in $($config.RecommendedState) mode"
                }
                elseif ($blockEvents -gt 0 -and $ruleFalsePositives.Count -gt 0) {
                    $recommendation = "Add exceptions for false positives"
                    $justification = "Rule is blocking legitimate applications"
                }
                else {
                    $recommendation = "No changes needed"
                    $justification = "Rule is correctly configured and functioning as expected"
                }
            }
            elseif ($config.CurrentState -eq "Disabled") {
                # Rule is disabled
                if ($config.RecommendedState -eq "Enabled" -or $config.RecommendedState -eq "Audit") {
                    $recommendation = "Enable in Audit mode"
                    $justification = "Rule is disabled but recommended to be in $($config.RecommendedState) mode"
                }
                else {
                    $recommendation = "No changes needed"
                    $justification = "Rule is correctly configured as disabled"
                }
            }
            
            # Format false positives
            $falsePositivesText = if ($ruleFalsePositives.Count -gt 0) {
                ($ruleFalsePositives | ForEach-Object {
                    "$($_.ProcessPath) ($($_.EventCount) events)"
                }) -join "; "
            }
            else {
                "None detected"
            }
            
            # Format recommended exceptions
            $recommendedExceptionsText = if ($ruleFalsePositives.Count -gt 0) {
                ($ruleFalsePositives | ForEach-Object {
                    $_.ProcessPath
                }) -join "; "
            }
            else {
                "None"
            }
            
            $report += [PSCustomObject]@{
                RuleName = $config.RuleName
                RuleId = $config.RuleId
                Description = $config.Description
                RecommendedState = $config.RecommendedState
                CurrentState = $config.CurrentState
                Impact = $config.Impact
                BlockEvents = $blockEvents
                AuditEvents = $auditEvents
                UniqueDevices = $uniqueDevices
                CurrentExceptions = $config.Exceptions
                DetectedFalsePositives = $falsePositivesText
                Recommendation = $recommendation
                Justification = $justification
                RecommendedExceptions = $recommendedExceptionsText
                TimeFrame = $TimeFrame
            }
        }
        
        # Sort by recommendation priority
        $report = $report | Sort-Object -Property @{Expression = {
            switch ($_.Recommendation) {
                "Add exceptions for false positives" { 1 }
                "Enable in Block mode with exceptions" { 2 }
                "Enable in Block mode" { 3 }
                "Enable in Audit mode" { 4 }
                "Add exceptions for false positives before enabling" { 5 }
                "Consider changing to Audit mode" { 6 }
                "No changes needed" { 7 }
                default { 8 }
            }
        }}
        
        Write-Log "Generated ASR recommendations report with $($report.Count) entries"
        return $report
    }
    catch {
        Write-Log "Error generating ASR recommendations report: $_" -Level Error
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
        [string]$ReportTitle = "ASR Report"
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
                $Data | Export-Excel -Path $ExportPath -AutoSize -TableName "ASRReport" -WorksheetName $ReportTitle
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
        "Configuration" {
            $report = Get-ASRConfigurationReport -Filter $Filter
            $reportTitle = "ASR Configuration Report"
        }
        "Events" {
            $report = Get-ASREventsReport -Filter $Filter -TimeFrame $TimeFrame -IncludeAuditEvents $IncludeAuditEvents -GroupByDevice $GroupByDevice
            $reportTitle = "ASR Events Report"
        }
        "FalsePositives" {
            $report = Get-ASRFalsePositivesReport -Filter $Filter -TimeFrame $TimeFrame
            $reportTitle = "ASR False Positives Report"
        }
        "Recommendations" {
            $report = Get-ASRRecommendationsReport -Filter $Filter -TimeFrame $TimeFrame
            $reportTitle = "ASR Recommendations Report"
        }
        "All" {
            # Generate all reports
            $configReport = Get-ASRConfigurationReport -Filter $Filter
            $eventsReport = Get-ASREventsReport -Filter $Filter -TimeFrame $TimeFrame -IncludeAuditEvents $IncludeAuditEvents -GroupByDevice $GroupByDevice
            $falsePositivesReport = Get-ASRFalsePositivesReport -Filter $Filter -TimeFrame $TimeFrame
            $recommendationsReport = Get-ASRRecommendationsReport -Filter $Filter -TimeFrame $TimeFrame
            
            # Export each report
            $exportPathWithoutExtension = [System.IO.Path]::GetDirectoryName($ExportPath) + "\" + [System.IO.Path]::GetFileNameWithoutExtension($ExportPath)
            $extension = [System.IO.Path]::GetExtension($ExportPath)
            
            if ($ExportFormat -eq "Excel") {
                # For Excel, export all reports to different worksheets in the same file
                $configReport | Export-Excel -Path $ExportPath -AutoSize -TableName "ASRConfigurationReport" -WorksheetName "ASR Configuration Report"
                $eventsReport | Export-Excel -Path $ExportPath -AutoSize -TableName "ASREventsReport" -WorksheetName "ASR Events Report" -ClearSheet
                $falsePositivesReport | Export-Excel -Path $ExportPath -AutoSize -TableName "ASRFalsePositivesReport" -WorksheetName "ASR False Positives Report" -ClearSheet
                $recommendationsReport | Export-Excel -Path $ExportPath -AutoSize -TableName "ASRRecommendationsReport" -WorksheetName "ASR Recommendations Report" -ClearSheet
                
                Write-Log "All reports exported successfully to: $ExportPath"
            }
            else {
                # For other formats, export to separate files
                Export-Report -Data $configReport -ExportPath "$exportPathWithoutExtension-Configuration$extension" -ExportFormat $ExportFormat -ReportTitle "ASR Configuration Report"
                Export-Report -Data $eventsReport -ExportPath "$exportPathWithoutExtension-Events$extension" -ExportFormat $ExportFormat -ReportTitle "ASR Events Report"
                Export-Report -Data $falsePositivesReport -ExportPath "$exportPathWithoutExtension-FalsePositives$extension" -ExportFormat $ExportFormat -ReportTitle "ASR False Positives Report"
                Export-Report -Data $recommendationsReport -ExportPath "$exportPathWithoutExtension-Recommendations$extension" -ExportFormat $ExportFormat -ReportTitle "ASR Recommendations Report"
                
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
    Write-Output "ASR analysis completed successfully"
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
