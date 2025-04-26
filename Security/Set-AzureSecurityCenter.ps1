<#
.SYNOPSIS
    Configures and manages Azure Security Center settings.

.DESCRIPTION
    This script configures and manages Azure Security Center (Microsoft Defender for Cloud) settings
    including security policies, threat protection, just-in-time VM access, and security recommendations.
    It supports various security configurations and compliance standards.

.PARAMETER ResourceGroupName
    The name of the resource group to configure security for. If not specified, configures at subscription level.

.PARAMETER SubscriptionId
    The ID of the subscription to configure security for. If not specified, uses the current subscription.

.PARAMETER Action
    The action to perform (Get, Enable, Disable, Configure).

.PARAMETER SecurityComponent
    The security component to configure (SecurityPolicy, ThreatProtection, JitAccess, Recommendations, Compliance, All).

.PARAMETER StandardName
    The compliance standard to configure (PCI-DSS, ISO-27001, SOC-TSP, NIST-SP-800-53, CIS).

.PARAMETER EnableDefenderPlans
    Array of Defender plans to enable (VirtualMachines, SqlServers, AppServices, StorageAccounts, KeyVaults, KubernetesService, ContainerRegistry, Dns).

.PARAMETER JitVmIds
    Array of VM resource IDs to configure just-in-time access for.

.PARAMETER JitPorts
    Array of ports to configure for just-in-time access.

.PARAMETER JitRequestor
    The requestor IP address for just-in-time access.

.PARAMETER JitMaxRequestHours
    The maximum number of hours for just-in-time access requests.

.PARAMETER ExportPath
    The path where the security assessment report will be saved.

.PARAMETER LogPath
    Path where logs will be stored. Defaults to Windows log directory.

.EXAMPLE
    .\Set-AzureSecurityCenter.ps1 -Action Enable -SecurityComponent ThreatProtection -EnableDefenderPlans @("VirtualMachines", "SqlServers", "KeyVaults")
    Enables Microsoft Defender for VMs, SQL Servers, and Key Vaults.

.EXAMPLE
    .\Set-AzureSecurityCenter.ps1 -Action Configure -SecurityComponent Compliance -StandardName "PCI-DSS"
    Configures the PCI-DSS compliance standard in Security Center.

.EXAMPLE
    .\Set-AzureSecurityCenter.ps1 -Action Configure -SecurityComponent JitAccess -JitVmIds @("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/myRG/providers/Microsoft.Compute/virtualMachines/myVM") -JitPorts @(22, 3389) -JitMaxRequestHours 3
    Configures just-in-time access for the specified VM with SSH and RDP ports.

.NOTES
    Author: Michael Witzsche
    Date: April 26, 2025
    Version: 1.1
#>

#Requires -Modules Az.Security, Az.Accounts, Az.Resources

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$LogPath = "$env:SystemRoot\Logs\Set-AzureSecurityCenter",
    
    [Parameter(Mandatory = $false)]
    [string]$ResourceGroupName = "",
    
    [Parameter(Mandatory = $false)]
    [string]$SubscriptionId = "",
    
    [Parameter(Mandatory = $true)]
    [ValidateSet("Get", "Enable", "Disable", "Configure")]
    [string]$Action,
    
    [Parameter(Mandatory = $true)]
    [ValidateSet("SecurityPolicy", "ThreatProtection", "JitAccess", "Recommendations", "Compliance", "All")]
    [string]$SecurityComponent,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("PCI-DSS", "ISO-27001", "SOC-TSP", "NIST-SP-800-53", "CIS", "")]
    [string]$StandardName = "",
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("VirtualMachines", "SqlServers", "AppServices", "StorageAccounts", "KeyVaults", "KubernetesService", "ContainerRegistry", "Dns")]
    [string[]]$EnableDefenderPlans = @(),
    
    [Parameter(Mandatory = $false)]
    [string[]]$JitVmIds = @(),
    
    [Parameter(Mandatory = $false)]
    [int[]]$JitPorts = @(22, 3389),
    
    [Parameter(Mandatory = $false)]
    [string]$JitRequestor = "*",
    
    [Parameter(Mandatory = $false)]
    [int]$JitMaxRequestHours = 3,
    
    [Parameter(Mandatory = $false)]
    [string]$ExportPath = ""
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

function Connect-ToAzure {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$SubscriptionId = ""
    )
    
    try {
        # Check if already connected
        $context = Get-AzContext
        if ($null -ne $context) {
            Write-Log "Already connected to Azure as $($context.Account.Id) in subscription $($context.Subscription.Name)"
            
            # Switch subscription if specified
            if (-not [string]::IsNullOrEmpty($SubscriptionId) -and $context.Subscription.Id -ne $SubscriptionId) {
                Write-Log "Switching to subscription $SubscriptionId..."
                Set-AzContext -SubscriptionId $SubscriptionId | Out-Null
                $context = Get-AzContext
                Write-Log "Switched to subscription $($context.Subscription.Name)"
            }
            
            return $true
        }
        
        # Connect to Azure
        Write-Log "Connecting to Azure..."
        Connect-AzAccount -ErrorAction Stop | Out-Null
        
        # Switch subscription if specified
        if (-not [string]::IsNullOrEmpty($SubscriptionId)) {
            Write-Log "Switching to subscription $SubscriptionId..."
            Set-AzContext -SubscriptionId $SubscriptionId | Out-Null
        }
        
        # Verify connection
        $context = Get-AzContext
        if ($null -ne $context) {
            Write-Log "Successfully connected to Azure as $($context.Account.Id) in subscription $($context.Subscription.Name)"
            return $true
        }
        else {
            Write-Log "Failed to verify Azure connection" -Level Error
            return $false
        }
    }
    catch {
        Write-Log "Error connecting to Azure: $_" -Level Error
        return $false
    }
}

function Get-SecurityPolicies {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$ResourceGroupName = ""
    )
    
    try {
        Write-Log "Retrieving security policies..."
        
        if ([string]::IsNullOrEmpty($ResourceGroupName)) {
            # Get subscription-level policies
            $policies = Get-AzSecurityPolicy
        }
        else {
            # Get resource group-level policies
            $policies = Get-AzSecurityPolicy | Where-Object { $_.ResourceGroupName -eq $ResourceGroupName }
        }
        
        Write-Log "Retrieved $($policies.Count) security policies"
        return $policies
    }
    catch {
        Write-Log "Error retrieving security policies: $_" -Level Error
        return $null
    }
}

function Set-SecurityPolicy {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Action,
        
        [Parameter(Mandatory = $false)]
        [string]$ResourceGroupName = "",
        
        [Parameter(Mandatory = $false)]
        [string]$StandardName = ""
    )
    
    try {
        # Get current security policy
        $policyName = "default"
        $policies = Get-SecurityPolicies -ResourceGroupName $ResourceGroupName
        
        if ($null -eq $policies -or $policies.Count -eq 0) {
            Write-Log "No security policies found" -Level Warning
            return $false
        }
        
        $policy = $policies | Where-Object { $_.Name -eq $policyName } | Select-Object -First 1
        
        if ($null -eq $policy) {
            Write-Log "Default security policy not found" -Level Warning
            return $false
        }
        
        # Configure policy based on action
        switch ($Action) {
            "Enable" {
                Write-Log "Enabling security policy..."
                
                # Enable all policy settings
                $parameters = @{
                    Name = $policyName
                    PolicyLevel = "Subscription"
                }
                
                if (-not [string]::IsNullOrEmpty($ResourceGroupName)) {
                    $parameters.ResourceGroupName = $ResourceGroupName
                }
                
                Set-AzSecurityPolicy @parameters -PolicyEffect "On" | Out-Null
                Write-Log "Security policy enabled successfully"
            }
            "Disable" {
                Write-Log "Disabling security policy..."
                
                # Disable all policy settings
                $parameters = @{
                    Name = $policyName
                    PolicyLevel = "Subscription"
                }
                
                if (-not [string]::IsNullOrEmpty($ResourceGroupName)) {
                    $parameters.ResourceGroupName = $ResourceGroupName
                }
                
                Set-AzSecurityPolicy @parameters -PolicyEffect "Off" | Out-Null
                Write-Log "Security policy disabled successfully"
            }
            "Configure" {
                if ([string]::IsNullOrEmpty($StandardName)) {
                    Write-Log "StandardName parameter is required for Configure action" -Level Error
                    return $false
                }
                
                Write-Log "Configuring security policy for standard: $StandardName..."
                
                # Configure policy for specific compliance standard
                $parameters = @{
                    Name = $policyName
                    PolicyLevel = "Subscription"
                }
                
                if (-not [string]::IsNullOrEmpty($ResourceGroupName)) {
                    $parameters.ResourceGroupName = $ResourceGroupName
                }
                
                # Set policy parameters based on standard
                switch ($StandardName) {
                    "PCI-DSS" {
                        $parameters.StandardName = "PCI_DSS_3.2.1"
                    }
                    "ISO-27001" {
                        $parameters.StandardName = "ISO_27001"
                    }
                    "SOC-TSP" {
                        $parameters.StandardName = "SOC_TSP"
                    }
                    "NIST-SP-800-53" {
                        $parameters.StandardName = "NIST_SP_800_53_R4"
                    }
                    "CIS" {
                        $parameters.StandardName = "CIS_CONTROLS_7.1"
                    }
                }
                
                Set-AzSecurityPolicy @parameters -PolicyEffect "On" | Out-Null
                Write-Log "Security policy configured successfully for standard: $StandardName"
            }
        }
        
        return $true
    }
    catch {
        Write-Log "Error configuring security policy: $_" -Level Error
        return $false
    }
}

function Get-ThreatProtectionSettings {
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Retrieving threat protection settings..."
        
        # Get pricing settings for all resource types
        $pricingSettings = Get-AzSecurityPricing
        
        Write-Log "Retrieved threat protection settings for $($pricingSettings.Count) resource types"
        return $pricingSettings
    }
    catch {
        Write-Log "Error retrieving threat protection settings: $_" -Level Error
        return $null
    }
}

function Set-ThreatProtection {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Action,
        
        [Parameter(Mandatory = $false)]
        [string[]]$DefenderPlans = @()
    )
    
    try {
        # Map of resource types to pricing names
        $resourceTypeMap = @{
            "VirtualMachines" = "VirtualMachines"
            "SqlServers" = "SqlServers"
            "AppServices" = "AppServices"
            "StorageAccounts" = "StorageAccounts"
            "KeyVaults" = "KeyVaults"
            "KubernetesService" = "KubernetesService"
            "ContainerRegistry" = "ContainerRegistry"
            "Dns" = "Dns"
        }
        
        # Get current pricing settings
        $pricingSettings = Get-ThreatProtectionSettings
        
        if ($null -eq $pricingSettings) {
            Write-Log "Failed to retrieve current threat protection settings" -Level Error
            return $false
        }
        
        # Configure pricing settings based on action
        switch ($Action) {
            "Enable" {
                # If no specific plans are specified, enable all
                if ($DefenderPlans.Count -eq 0) {
                    $DefenderPlans = $resourceTypeMap.Keys
                }
                
                foreach ($plan in $DefenderPlans) {
                    if (-not $resourceTypeMap.ContainsKey($plan)) {
                        Write-Log "Invalid Defender plan: $plan" -Level Warning
                        continue
                    }
                    
                    $pricingName = $resourceTypeMap[$plan]
                    Write-Log "Enabling Microsoft Defender for $plan..."
                    
                    Set-AzSecurityPricing -Name $pricingName -PricingTier "Standard" | Out-Null
                }
                
                Write-Log "Threat protection enabled successfully for specified plans"
            }
            "Disable" {
                # If no specific plans are specified, disable all
                if ($DefenderPlans.Count -eq 0) {
                    $DefenderPlans = $resourceTypeMap.Keys
                }
                
                foreach ($plan in $DefenderPlans) {
                    if (-not $resourceTypeMap.ContainsKey($plan)) {
                        Write-Log "Invalid Defender plan: $plan" -Level Warning
                        continue
                    }
                    
                    $pricingName = $resourceTypeMap[$plan]
                    Write-Log "Disabling Microsoft Defender for $plan..."
                    
                    Set-AzSecurityPricing -Name $pricingName -PricingTier "Free" | Out-Null
                }
                
                Write-Log "Threat protection disabled successfully for specified plans"
            }
            "Get" {
                # Display current settings
                $pricingSettings | ForEach-Object {
                    Write-Output "Resource Type: $($_.Name), Pricing Tier: $($_.PricingTier)"
                }
            }
        }
        
        return $true
    }
    catch {
        Write-Log "Error configuring threat protection: $_" -Level Error
        return $false
    }
}

function Get-JitAccessPolicies {
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Retrieving just-in-time access policies..."
        
        # Get JIT access policies
        $jitPolicies = Get-AzJitNetworkAccessPolicy
        
        Write-Log "Retrieved $($jitPolicies.Count) just-in-time access policies"
        return $jitPolicies
    }
    catch {
        Write-Log "Error retrieving just-in-time access policies: $_" -Level Error
        return $null
    }
}

function Set-JitAccess {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Action,
        
        [Parameter(Mandatory = $false)]
        [string[]]$VmIds = @(),
        
        [Parameter(Mandatory = $false)]
        [int[]]$Ports = @(22, 3389),
        
        [Parameter(Mandatory = $false)]
        [string]$Requestor = "*",
        
        [Parameter(Mandatory = $false)]
        [int]$MaxRequestHours = 3
    )
    
    try {
        # Validate parameters
        if ($VmIds.Count -eq 0 -and $Action -ne "Get") {
            Write-Log "VM IDs are required for $Action action" -Level Error
            return $false
        }
        
        # Configure JIT access based on action
        switch ($Action) {
            "Enable" {
                foreach ($vmId in $VmIds) {
                    Write-Log "Enabling just-in-time access for VM: $vmId..."
                    
                    # Create JIT policy configuration
                    $jitPolicy = @{
                        VirtualMachines = @(
                            @{
                                Id = $vmId
                                Ports = @()
                            }
                        )
                    }
                    
                    # Add port configurations
                    foreach ($port in $Ports) {
                        $portConfig = @{
                            Number = $port
                            Protocol = "*"
                            AllowedSourceAddressPrefix = @($Requestor)
                            MaxRequestAccessDuration = "PT${MaxRequestHours}H"
                        }
                        
                        $jitPolicy.VirtualMachines[0].Ports += $portConfig
                    }
                    
                    # Get resource group name from VM ID
                    $rgName = ($vmId -split "/")[4]
                    
                    # Create JIT policy
                    Set-AzJitNetworkAccessPolicy -ResourceGroupName $rgName -Location (Get-AzResourceGroup -Name $rgName).Location -Name "default" -Kind "Basic" -VirtualMachine $jitPolicy.VirtualMachines | Out-Null
                }
                
                Write-Log "Just-in-time access enabled successfully for specified VMs"
            }
            "Disable" {
                foreach ($vmId in $VmIds) {
                    Write-Log "Disabling just-in-time access for VM: $vmId..."
                    
                    # Get resource group name from VM ID
                    $rgName = ($vmId -split "/")[4]
                    
                    # Get JIT policies
                    $jitPolicies = Get-AzJitNetworkAccessPolicy | Where-Object { $_.ResourceGroupName -eq $rgName }
                    
                    foreach ($policy in $jitPolicies) {
                        # Check if policy contains the VM
                        $vmInPolicy = $policy.VirtualMachines | Where-Object { $_.Id -eq $vmId }
                        
                        if ($null -ne $vmInPolicy) {
                            # Remove the VM from the policy
                            $policy.VirtualMachines = $policy.VirtualMachines | Where-Object { $_.Id -ne $vmId }
                            
                            # Update the policy if there are still VMs in it, otherwise remove it
                            if ($policy.VirtualMachines.Count -gt 0) {
                                Set-AzJitNetworkAccessPolicy -ResourceGroupName $rgName -Location $policy.Location -Name $policy.Name -Kind $policy.Kind -VirtualMachine $policy.VirtualMachines | Out-Null
                            }
                            else {
                                Remove-AzJitNetworkAccessPolicy -ResourceGroupName $rgName -Name $policy.Name -Force | Out-Null
                            }
                        }
                    }
                }
                
                Write-Log "Just-in-time access disabled successfully for specified VMs"
            }
            "Get" {
                # Get and display JIT policies
                $jitPolicies = Get-JitAccessPolicies
                
                if ($null -eq $jitPolicies -or $jitPolicies.Count -eq 0) {
                    Write-Output "No just-in-time access policies found"
                }
                else {
                    foreach ($policy in $jitPolicies) {
                        Write-Output "Policy: $($policy.Name), Resource Group: $($policy.ResourceGroupName)"
                        
                        foreach ($vm in $policy.VirtualMachines) {
                            Write-Output "  VM: $($vm.Id)"
                            
                            foreach ($port in $vm.Ports) {
                                Write-Output "    Port: $($port.Number), Protocol: $($port.Protocol), Max Duration: $($port.MaxRequestAccessDuration)"
                                Write-Output "    Allowed Source: $($port.AllowedSourceAddressPrefix -join ', ')"
                            }
                        }
                    }
                }
            }
        }
        
        return $true
    }
    catch {
        Write-Log "Error configuring just-in-time access: $_" -Level Error
        return $false
    }
}

function Get-SecurityRecommendations {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$ResourceGroupName = ""
    )
    
    try {
        Write-Log "Retrieving security recommendations..."
        
        # Get security tasks (recommendations)
        $tasks = Get-AzSecurityTask
        
        # Filter by resource group if specified
        if (-not [string]::IsNullOrEmpty($ResourceGroupName)) {
            $tasks = $tasks | Where-Object { $_.ResourceId -like "*resourceGroups/$ResourceGroupName*" }
        }
        
        Write-Log "Retrieved $($tasks.Count) security recommendations"
        return $tasks
    }
    catch {
        Write-Log "Error retrieving security recommendations: $_" -Level Error
        return $null
    }
}

function Export-SecurityAssessment {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ExportPath,
        
        [Parameter(Mandatory = $false)]
        [string]$ResourceGroupName = ""
    )
    
    try {
        Write-Log "Generating security assessment report..."
        
        # Get security data
        $policies = Get-SecurityPolicies -ResourceGroupName $ResourceGroupName
        $pricingSettings = Get-ThreatProtectionSettings
        $jitPolicies = Get-JitAccessPolicies
        $recommendations = Get-SecurityRecommendations -ResourceGroupName $ResourceGroupName
        
        # Create report content
        $report = @"
# Azure Security Center Assessment Report
Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

## Security Policies
"@
        
        if ($null -ne $policies -and $policies.Count -gt 0) {
            foreach ($policy in $policies) {
                $report += @"

### Policy: $($policy.Name)
- Resource Group: $($policy.ResourceGroupName)
- Policy Level: $($policy.PolicyLevel)
- Policy Effect: $($policy.PolicyEffect)
"@
            }
        }
        else {
            $report += @"

No security policies found.
"@
        }
        
        $report += @"

## Threat Protection Settings
"@
        
        if ($null -ne $pricingSettings -and $pricingSettings.Count -gt 0) {
            foreach ($setting in $pricingSettings) {
                $report += @"

### Resource Type: $($setting.Name)
- Pricing Tier: $($setting.PricingTier)
"@
            }
        }
        else {
            $report += @"

No threat protection settings found.
"@
        }
        
        $report += @"

## Just-in-Time Access Policies
"@
        
        if ($null -ne $jitPolicies -and $jitPolicies.Count -gt 0) {
            foreach ($policy in $jitPolicies) {
                $report += @"

### Policy: $($policy.Name)
- Resource Group: $($policy.ResourceGroupName)
"@
                
                foreach ($vm in $policy.VirtualMachines) {
                    $vmName = ($vm.Id -split "/")[-1]
                    $report += @"

#### VM: $vmName
"@
                    
                    foreach ($port in $vm.Ports) {
                        $report += @"
- Port: $($port.Number), Protocol: $($port.Protocol), Max Duration: $($port.MaxRequestAccessDuration)
- Allowed Source: $($port.AllowedSourceAddressPrefix -join ', ')
"@
                    }
                }
            }
        }
        else {
            $report += @"

No just-in-time access policies found.
"@
        }
        
        $report += @"

## Security Recommendations
"@
        
        if ($null -ne $recommendations -and $recommendations.Count -gt 0) {
            # Group recommendations by severity
            $highRecommendations = $recommendations | Where-Object { $_.RecommendationSeverity -eq "High" }
            $mediumRecommendations = $recommendations | Where-Object { $_.RecommendationSeverity -eq "Medium" }
            $lowRecommendations = $recommendations | Where-Object { $_.RecommendationSeverity -eq "Low" }
            
            $report += @"

### High Severity Recommendations
"@
            
            if ($null -ne $highRecommendations -and $highRecommendations.Count -gt 0) {
                foreach ($rec in $highRecommendations) {
                    $resourceName = ($rec.ResourceId -split "/")[-1]
                    $report += @"

- **$($rec.RecommendationName)**
  - Resource: $resourceName
  - State: $($rec.State)
  - Description: $($rec.RecommendationText)
"@
                }
            }
            else {
                $report += @"

No high severity recommendations found.
"@
            }
            
            $report += @"

### Medium Severity Recommendations
"@
            
            if ($null -ne $mediumRecommendations -and $mediumRecommendations.Count -gt 0) {
                foreach ($rec in $mediumRecommendations) {
                    $resourceName = ($rec.ResourceId -split "/")[-1]
                    $report += @"

- **$($rec.RecommendationName)**
  - Resource: $resourceName
  - State: $($rec.State)
  - Description: $($rec.RecommendationText)
"@
                }
            }
            else {
                $report += @"

No medium severity recommendations found.
"@
            }
            
            $report += @"

### Low Severity Recommendations
"@
            
            if ($null -ne $lowRecommendations -and $lowRecommendations.Count -gt 0) {
                foreach ($rec in $lowRecommendations) {
                    $resourceName = ($rec.ResourceId -split "/")[-1]
                    $report += @"

- **$($rec.RecommendationName)**
  - Resource: $resourceName
  - State: $($rec.State)
  - Description: $($rec.RecommendationText)
"@
                }
            }
            else {
                $report += @"

No low severity recommendations found.
"@
            }
        }
        else {
            $report += @"

No security recommendations found.
"@
        }
        
        $report += @"

## Summary
- Total Policies: $($policies.Count)
- Total Defender Plans: $($pricingSettings.Count)
- Total JIT Policies: $($jitPolicies.Count)
- Total Recommendations: $($recommendations.Count)
  - High Severity: $($highRecommendations.Count)
  - Medium Severity: $($mediumRecommendations.Count)
  - Low Severity: $($lowRecommendations.Count)
"@
        
        # Write report to file
        $report | Out-File -FilePath $ExportPath -Encoding utf8
        
        Write-Log "Security assessment report generated successfully: $ExportPath"
        return $true
    }
    catch {
        Write-Log "Error generating security assessment report: $_" -Level Error
        return $false
    }
}
#endregion

#region Main Script
try {
    # Script start
    Write-Log "Script started with parameters: Action=$Action, SecurityComponent=$SecurityComponent"
    
    # Connect to Azure
    $connectedToAzure = Connect-ToAzure -SubscriptionId $SubscriptionId
    if (-not $connectedToAzure) {
        Write-Log "Cannot proceed without Azure connection" -Level Error
        exit 1
    }
    
    # Process based on security component and action
    switch ($SecurityComponent) {
        "SecurityPolicy" {
            switch ($Action) {
                "Get" {
                    $policies = Get-SecurityPolicies -ResourceGroupName $ResourceGroupName
                    
                    if ($null -ne $policies -and $policies.Count -gt 0) {
                        Write-Output "Security Policies:"
                        $policies | Format-Table -Property Name, PolicyLevel, PolicyEffect, ResourceGroupName
                    }
                    else {
                        Write-Output "No security policies found"
                    }
                }
                "Enable" {
                    $result = Set-SecurityPolicy -Action "Enable" -ResourceGroupName $ResourceGroupName
                    
                    if (-not $result) {
                        Write-Log "Failed to enable security policy" -Level Error
                        exit 1
                    }
                }
                "Disable" {
                    $result = Set-SecurityPolicy -Action "Disable" -ResourceGroupName $ResourceGroupName
                    
                    if (-not $result) {
                        Write-Log "Failed to disable security policy" -Level Error
                        exit 1
                    }
                }
                "Configure" {
                    if ([string]::IsNullOrEmpty($StandardName)) {
                        Write-Log "StandardName parameter is required for Configure action" -Level Error
                        exit 1
                    }
                    
                    $result = Set-SecurityPolicy -Action "Configure" -ResourceGroupName $ResourceGroupName -StandardName $StandardName
                    
                    if (-not $result) {
                        Write-Log "Failed to configure security policy" -Level Error
                        exit 1
                    }
                }
            }
        }
        "ThreatProtection" {
            switch ($Action) {
                "Get" {
                    $pricingSettings = Get-ThreatProtectionSettings
                    
                    if ($null -ne $pricingSettings -and $pricingSettings.Count -gt 0) {
                        Write-Output "Threat Protection Settings:"
                        $pricingSettings | Format-Table -Property Name, PricingTier
                    }
                    else {
                        Write-Output "No threat protection settings found"
                    }
                }
                "Enable" {
                    $result = Set-ThreatProtection -Action "Enable" -DefenderPlans $EnableDefenderPlans
                    
                    if (-not $result) {
                        Write-Log "Failed to enable threat protection" -Level Error
                        exit 1
                    }
                }
                "Disable" {
                    $result = Set-ThreatProtection -Action "Disable" -DefenderPlans $EnableDefenderPlans
                    
                    if (-not $result) {
                        Write-Log "Failed to disable threat protection" -Level Error
                        exit 1
                    }
                }
            }
        }
        "JitAccess" {
            switch ($Action) {
                "Get" {
                    Set-JitAccess -Action "Get"
                }
                "Enable" {
                    if ($JitVmIds.Count -eq 0) {
                        Write-Log "JitVmIds parameter is required for Enable action" -Level Error
                        exit 1
                    }
                    
                    $result = Set-JitAccess -Action "Enable" -VmIds $JitVmIds -Ports $JitPorts -Requestor $JitRequestor -MaxRequestHours $JitMaxRequestHours
                    
                    if (-not $result) {
                        Write-Log "Failed to enable just-in-time access" -Level Error
                        exit 1
                    }
                }
                "Disable" {
                    if ($JitVmIds.Count -eq 0) {
                        Write-Log "JitVmIds parameter is required for Disable action" -Level Error
                        exit 1
                    }
                    
                    $result = Set-JitAccess -Action "Disable" -VmIds $JitVmIds
                    
                    if (-not $result) {
                        Write-Log "Failed to disable just-in-time access" -Level Error
                        exit 1
                    }
                }
            }
        }
        "Recommendations" {
            switch ($Action) {
                "Get" {
                    $recommendations = Get-SecurityRecommendations -ResourceGroupName $ResourceGroupName
                    
                    if ($null -ne $recommendations -and $recommendations.Count -gt 0) {
                        Write-Output "Security Recommendations:"
                        $recommendations | Format-Table -Property RecommendationName, RecommendationSeverity, State
                    }
                    else {
                        Write-Output "No security recommendations found"
                    }
                }
            }
        }
        "Compliance" {
            switch ($Action) {
                "Configure" {
                    if ([string]::IsNullOrEmpty($StandardName)) {
                        Write-Log "StandardName parameter is required for Configure action" -Level Error
                        exit 1
                    }
                    
                    $result = Set-SecurityPolicy -Action "Configure" -ResourceGroupName $ResourceGroupName -StandardName $StandardName
                    
                    if (-not $result) {
                        Write-Log "Failed to configure compliance standard" -Level Error
                        exit 1
                    }
                }
            }
        }
        "All" {
            switch ($Action) {
                "Get" {
                    if ([string]::IsNullOrEmpty($ExportPath)) {
                        Write-Log "ExportPath parameter is required for Get action on All components" -Level Error
                        exit 1
                    }
                    
                    $result = Export-SecurityAssessment -ExportPath $ExportPath -ResourceGroupName $ResourceGroupName
                    
                    if (-not $result) {
                        Write-Log "Failed to generate security assessment report" -Level Error
                        exit 1
                    }
                    
                    Write-Output "Security assessment report generated: $ExportPath"
                }
                "Enable" {
                    # Enable security policy
                    $policyResult = Set-SecurityPolicy -Action "Enable" -ResourceGroupName $ResourceGroupName
                    
                    if (-not $policyResult) {
                        Write-Log "Failed to enable security policy" -Level Warning
                    }
                    
                    # Enable threat protection
                    $threatResult = Set-ThreatProtection -Action "Enable" -DefenderPlans $EnableDefenderPlans
                    
                    if (-not $threatResult) {
                        Write-Log "Failed to enable threat protection" -Level Warning
                    }
                    
                    # Enable JIT access if VMs are specified
                    if ($JitVmIds.Count -gt 0) {
                        $jitResult = Set-JitAccess -Action "Enable" -VmIds $JitVmIds -Ports $JitPorts -Requestor $JitRequestor -MaxRequestHours $JitMaxRequestHours
                        
                        if (-not $jitResult) {
                            Write-Log "Failed to enable just-in-time access" -Level Warning
                        }
                    }
                    
                    Write-Output "Security components enabled successfully"
                }
                "Disable" {
                    # Disable security policy
                    $policyResult = Set-SecurityPolicy -Action "Disable" -ResourceGroupName $ResourceGroupName
                    
                    if (-not $policyResult) {
                        Write-Log "Failed to disable security policy" -Level Warning
                    }
                    
                    # Disable threat protection
                    $threatResult = Set-ThreatProtection -Action "Disable" -DefenderPlans $EnableDefenderPlans
                    
                    if (-not $threatResult) {
                        Write-Log "Failed to disable threat protection" -Level Warning
                    }
                    
                    # Disable JIT access if VMs are specified
                    if ($JitVmIds.Count -gt 0) {
                        $jitResult = Set-JitAccess -Action "Disable" -VmIds $JitVmIds
                        
                        if (-not $jitResult) {
                            Write-Log "Failed to disable just-in-time access" -Level Warning
                        }
                    }
                    
                    Write-Output "Security components disabled successfully"
                }
                "Configure" {
                    if ([string]::IsNullOrEmpty($StandardName)) {
                        Write-Log "StandardName parameter is required for Configure action" -Level Error
                        exit 1
                    }
                    
                    # Configure security policy for compliance standard
                    $policyResult = Set-SecurityPolicy -Action "Configure" -ResourceGroupName $ResourceGroupName -StandardName $StandardName
                    
                    if (-not $policyResult) {
                        Write-Log "Failed to configure security policy" -Level Warning
                    }
                    
                    # Enable threat protection
                    $threatResult = Set-ThreatProtection -Action "Enable" -DefenderPlans $EnableDefenderPlans
                    
                    if (-not $threatResult) {
                        Write-Log "Failed to enable threat protection" -Level Warning
                    }
                    
                    # Enable JIT access if VMs are specified
                    if ($JitVmIds.Count -gt 0) {
                        $jitResult = Set-JitAccess -Action "Enable" -VmIds $JitVmIds -Ports $JitPorts -Requestor $JitRequestor -MaxRequestHours $JitMaxRequestHours
                        
                        if (-not $jitResult) {
                            Write-Log "Failed to enable just-in-time access" -Level Warning
                        }
                    }
                    
                    Write-Output "Security components configured successfully for standard: $StandardName"
                }
            }
        }
    }
    
    # Output success message
    Write-Output "Azure Security Center operation completed successfully"
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
