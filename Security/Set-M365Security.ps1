<#
.SYNOPSIS
    Configures and manages Microsoft 365 Security settings.

.DESCRIPTION
    This script configures and manages Microsoft 365 Security settings including
    Conditional Access policies, Identity Protection, MFA, and Security Defaults.
    It supports various security configurations and compliance requirements.

.PARAMETER Action
    The action to perform (Get, Enable, Disable, Configure).

.PARAMETER SecurityComponent
    The security component to configure (ConditionalAccess, IdentityProtection, MFA, SecurityDefaults, All).

.PARAMETER PolicyName
    The name of the policy to create or modify.

.PARAMETER PolicyType
    The type of Conditional Access policy to create (BlockCountries, RequireMFA, BlockLegacyAuth, RequireCompliantDevice).

.PARAMETER TargetGroups
    Array of group IDs to target with the policy.

.PARAMETER ExcludedGroups
    Array of group IDs to exclude from the policy.

.PARAMETER TargetCountries
    Array of country codes to target with the policy (for BlockCountries policy type).

.PARAMETER TargetApplications
    Array of application IDs to target with the policy.

.PARAMETER ExcludedApplications
    Array of application IDs to exclude from the policy.

.PARAMETER RiskLevel
    The risk level to target with the policy (Low, Medium, High).

.PARAMETER BlockLegacyAuth
    Whether to block legacy authentication protocols.

.PARAMETER RequireCompliantDevice
    Whether to require a compliant device.

.PARAMETER RequireMFA
    Whether to require multi-factor authentication.

.PARAMETER ExportPath
    The path where the security assessment report will be saved.

.PARAMETER LogPath
    Path where logs will be stored. Defaults to Windows log directory.

.EXAMPLE
    .\Set-M365Security.ps1 -Action Enable -SecurityComponent MFA -TargetGroups @("00000000-0000-0000-0000-000000000000")
    Enables MFA for the specified group.

.EXAMPLE
    .\Set-M365Security.ps1 -Action Configure -SecurityComponent ConditionalAccess -PolicyName "Block High Risk Countries" -PolicyType BlockCountries -TargetCountries @("RU", "CN", "IR")
    Creates a Conditional Access policy to block access from high-risk countries.

.EXAMPLE
    .\Set-M365Security.ps1 -Action Get -SecurityComponent All -ExportPath "C:\Reports\M365SecurityReport.md"
    Generates a comprehensive security assessment report for Microsoft 365.

.NOTES
    Author: Michael Witzsche
    Date: April 26, 2025
    Version: 1.1
#>

#Requires -Modules Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Authentication, Microsoft.Graph.Users

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$LogPath = "$env:SystemRoot\Logs\Set-M365Security",
    
    [Parameter(Mandatory = $true)]
    [ValidateSet("Get", "Enable", "Disable", "Configure")]
    [string]$Action,
    
    [Parameter(Mandatory = $true)]
    [ValidateSet("ConditionalAccess", "IdentityProtection", "MFA", "SecurityDefaults", "All")]
    [string]$SecurityComponent,
    
    [Parameter(Mandatory = $false)]
    [string]$PolicyName = "",
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("BlockCountries", "RequireMFA", "BlockLegacyAuth", "RequireCompliantDevice", "")]
    [string]$PolicyType = "",
    
    [Parameter(Mandatory = $false)]
    [string[]]$TargetGroups = @(),
    
    [Parameter(Mandatory = $false)]
    [string[]]$ExcludedGroups = @(),
    
    [Parameter(Mandatory = $false)]
    [string[]]$TargetCountries = @(),
    
    [Parameter(Mandatory = $false)]
    [string[]]$TargetApplications = @(),
    
    [Parameter(Mandatory = $false)]
    [string[]]$ExcludedApplications = @(),
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Low", "Medium", "High", "")]
    [string]$RiskLevel = "",
    
    [Parameter(Mandatory = $false)]
    [bool]$BlockLegacyAuth = $false,
    
    [Parameter(Mandatory = $false)]
    [bool]$RequireCompliantDevice = $false,
    
    [Parameter(Mandatory = $false)]
    [bool]$RequireMFA = $false,
    
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
            "Policy.Read.All",
            "Policy.ReadWrite.ConditionalAccess",
            "Directory.Read.All",
            "Directory.ReadWrite.All",
            "User.Read.All",
            "User.ReadWrite.All",
            "Application.Read.All",
            "IdentityRiskyUser.Read.All",
            "IdentityRiskyUser.ReadWrite.All"
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

function Get-ConditionalAccessPolicies {
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Retrieving Conditional Access policies..."
        
        # Get Conditional Access policies
        $policies = Get-MgIdentityConditionalAccessPolicy
        
        Write-Log "Retrieved $($policies.Count) Conditional Access policies"
        return $policies
    }
    catch {
        Write-Log "Error retrieving Conditional Access policies: $_" -Level Error
        return $null
    }
}

function New-ConditionalAccessPolicy {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$PolicyName,
        
        [Parameter(Mandatory = $true)]
        [string]$PolicyType,
        
        [Parameter(Mandatory = $false)]
        [string[]]$TargetGroups = @(),
        
        [Parameter(Mandatory = $false)]
        [string[]]$ExcludedGroups = @(),
        
        [Parameter(Mandatory = $false)]
        [string[]]$TargetCountries = @(),
        
        [Parameter(Mandatory = $false)]
        [string[]]$TargetApplications = @(),
        
        [Parameter(Mandatory = $false)]
        [string[]]$ExcludedApplications = @(),
        
        [Parameter(Mandatory = $false)]
        [string]$RiskLevel = ""
    )
    
    try {
        Write-Log "Creating Conditional Access policy: $PolicyName (Type: $PolicyType)..."
        
        # Check if policy already exists
        $existingPolicies = Get-MgIdentityConditionalAccessPolicy
        $existingPolicy = $existingPolicies | Where-Object { $_.DisplayName -eq $PolicyName }
        
        if ($null -ne $existingPolicy) {
            Write-Log "Conditional Access policy '$PolicyName' already exists" -Level Warning
            return $existingPolicy
        }
        
        # Create policy parameters based on policy type
        $policyParams = @{
            DisplayName = $PolicyName
            State = "enabled"
            Conditions = @{
                Applications = @{
                    IncludeApplications = @()
                    ExcludeApplications = @()
                }
                Users = @{
                    IncludeUsers = @()
                    ExcludeUsers = @()
                    IncludeGroups = @()
                    ExcludeGroups = @()
                }
                Locations = @{
                    IncludeLocations = @()
                    ExcludeLocations = @()
                }
                ClientAppTypes = @("all")
            }
            GrantControls = @{
                Operator = "OR"
                BuiltInControls = @()
            }
        }
        
        # Configure target groups
        if ($TargetGroups.Count -gt 0) {
            $policyParams.Conditions.Users.IncludeGroups = $TargetGroups
        }
        else {
            $policyParams.Conditions.Users.IncludeUsers = @("All")
        }
        
        # Configure excluded groups
        if ($ExcludedGroups.Count -gt 0) {
            $policyParams.Conditions.Users.ExcludeGroups = $ExcludedGroups
        }
        
        # Configure target applications
        if ($TargetApplications.Count -gt 0) {
            $policyParams.Conditions.Applications.IncludeApplications = $TargetApplications
        }
        else {
            $policyParams.Conditions.Applications.IncludeApplications = @("All")
        }
        
        # Configure excluded applications
        if ($ExcludedApplications.Count -gt 0) {
            $policyParams.Conditions.Applications.ExcludeApplications = $ExcludedApplications
        }
        
        # Configure policy based on type
        switch ($PolicyType) {
            "BlockCountries" {
                if ($TargetCountries.Count -eq 0) {
                    Write-Log "TargetCountries parameter is required for BlockCountries policy type" -Level Error
                    return $null
                }
                
                # Configure locations
                $policyParams.Conditions.Locations.IncludeLocations = $TargetCountries
                
                # Configure grant controls
                $policyParams.GrantControls.BuiltInControls = @("block")
            }
            "RequireMFA" {
                # Configure grant controls
                $policyParams.GrantControls.BuiltInControls = @("mfa")
            }
            "BlockLegacyAuth" {
                # Configure client app types
                $policyParams.Conditions.ClientAppTypes = @("exchangeActiveSync", "other")
                
                # Configure grant controls
                $policyParams.GrantControls.BuiltInControls = @("block")
            }
            "RequireCompliantDevice" {
                # Configure grant controls
                $policyParams.GrantControls.BuiltInControls = @("compliantDevice")
            }
        }
        
        # Add risk level if specified
        if (-not [string]::IsNullOrEmpty($RiskLevel)) {
            $policyParams.Conditions.UserRiskLevels = @()
            
            switch ($RiskLevel) {
                "Low" {
                    $policyParams.Conditions.UserRiskLevels = @("low", "medium", "high")
                }
                "Medium" {
                    $policyParams.Conditions.UserRiskLevels = @("medium", "high")
                }
                "High" {
                    $policyParams.Conditions.UserRiskLevels = @("high")
                }
            }
        }
        
        # Create policy
        $policy = New-MgIdentityConditionalAccessPolicy -BodyParameter $policyParams
        
        Write-Log "Conditional Access policy '$PolicyName' created successfully"
        return $policy
    }
    catch {
        Write-Log "Error creating Conditional Access policy: $_" -Level Error
        return $null
    }
}

function Remove-ConditionalAccessPolicy {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$PolicyName
    )
    
    try {
        Write-Log "Removing Conditional Access policy: $PolicyName..."
        
        # Find policy by name
        $policies = Get-MgIdentityConditionalAccessPolicy
        $policy = $policies | Where-Object { $_.DisplayName -eq $PolicyName }
        
        if ($null -eq $policy) {
            Write-Log "Conditional Access policy '$PolicyName' not found" -Level Warning
            return $false
        }
        
        # Remove policy
        Remove-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $policy.Id
        
        Write-Log "Conditional Access policy '$PolicyName' removed successfully"
        return $true
    }
    catch {
        Write-Log "Error removing Conditional Access policy: $_" -Level Error
        return $false
    }
}

function Get-IdentityProtectionPolicies {
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Retrieving Identity Protection policies..."
        
        # Get Identity Protection policies
        $signInRiskPolicy = Get-MgIdentityProtectionRiskyUserHistoryItem -Filter "riskLevel eq 'high'"
        $userRiskPolicy = Get-MgIdentityProtectionRiskyUser -Filter "riskLevel eq 'high'"
        
        $policies = @{
            SignInRiskPolicy = $signInRiskPolicy
            UserRiskPolicy = $userRiskPolicy
        }
        
        Write-Log "Retrieved Identity Protection policies"
        return $policies
    }
    catch {
        Write-Log "Error retrieving Identity Protection policies: $_" -Level Error
        return $null
    }
}

function Get-RiskyUsers {
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Retrieving risky users..."
        
        # Get risky users
        $riskyUsers = Get-MgIdentityProtectionRiskyUser
        
        Write-Log "Retrieved $($riskyUsers.Count) risky users"
        return $riskyUsers
    }
    catch {
        Write-Log "Error retrieving risky users: $_" -Level Error
        return $null
    }
}

function Confirm-RiskyUser {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$UserId,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet("Verified", "Dismissed")]
        [string]$RiskState
    )
    
    try {
        Write-Log "Confirming risky user $UserId as $RiskState..."
        
        # Confirm risky user
        $params = @{
            RiskState = $RiskState
        }
        
        Update-MgIdentityProtectionRiskyUser -RiskyUserId $UserId -BodyParameter $params
        
        Write-Log "Risky user $UserId confirmed as $RiskState successfully"
        return $true
    }
    catch {
        Write-Log "Error confirming risky user: $_" -Level Error
        return $false
    }
}

function Get-MFAStatus {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string[]]$UserIds = @()
    )
    
    try {
        Write-Log "Retrieving MFA status..."
        
        # Get users
        if ($UserIds.Count -gt 0) {
            $users = @()
            foreach ($userId in $UserIds) {
                $user = Get-MgUser -UserId $userId
                $users += $user
            }
        }
        else {
            $users = Get-MgUser -All
        }
        
        # Get MFA status for each user
        $mfaStatus = @()
        foreach ($user in $users) {
            $authMethods = Get-MgUserAuthenticationMethod -UserId $user.Id
            
            $hasMfa = $false
            foreach ($method in $authMethods) {
                if ($method.AdditionalProperties["@odata.type"] -ne "#microsoft.graph.passwordAuthenticationMethod") {
                    $hasMfa = $true
                    break
                }
            }
            
            $mfaStatus += [PSCustomObject]@{
                UserId = $user.Id
                UserPrincipalName = $user.UserPrincipalName
                DisplayName = $user.DisplayName
                MFAEnabled = $hasMfa
                AuthenticationMethods = $authMethods.Count
            }
        }
        
        Write-Log "Retrieved MFA status for $($mfaStatus.Count) users"
        return $mfaStatus
    }
    catch {
        Write-Log "Error retrieving MFA status: $_" -Level Error
        return $null
    }
}

function Enable-MFA {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$UserIds
    )
    
    try {
        Write-Log "Enabling MFA for users..."
        
        # Create Conditional Access policy to require MFA
        $policyName = "Require MFA for All Users"
        $policy = New-ConditionalAccessPolicy -PolicyName $policyName -PolicyType "RequireMFA" -TargetGroups $UserIds
        
        if ($null -eq $policy) {
            Write-Log "Failed to create Conditional Access policy to require MFA" -Level Error
            return $false
        }
        
        Write-Log "MFA enabled successfully for users"
        return $true
    }
    catch {
        Write-Log "Error enabling MFA: $_" -Level Error
        return $false
    }
}

function Get-SecurityDefaultsStatus {
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Retrieving Security Defaults status..."
        
        # Get Security Defaults policy
        $policy = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy
        
        Write-Log "Retrieved Security Defaults status: $($policy.IsEnabled)"
        return $policy
    }
    catch {
        Write-Log "Error retrieving Security Defaults status: $_" -Level Error
        return $null
    }
}

function Set-SecurityDefaults {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [bool]$Enabled
    )
    
    try {
        Write-Log "Setting Security Defaults to $Enabled..."
        
        # Set Security Defaults policy
        $params = @{
            IsEnabled = $Enabled
        }
        
        Update-MgPolicyIdentitySecurityDefaultEnforcementPolicy -BodyParameter $params
        
        Write-Log "Security Defaults set to $Enabled successfully"
        return $true
    }
    catch {
        Write-Log "Error setting Security Defaults: $_" -Level Error
        return $false
    }
}

function Export-SecurityAssessment {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ExportPath
    )
    
    try {
        Write-Log "Generating security assessment report..."
        
        # Get security data
        $conditionalAccessPolicies = Get-ConditionalAccessPolicies
        $identityProtectionPolicies = Get-IdentityProtectionPolicies
        $riskyUsers = Get-RiskyUsers
        $mfaStatus = Get-MFAStatus
        $securityDefaultsStatus = Get-SecurityDefaultsStatus
        
        # Create report content
        $report = @"
# Microsoft 365 Security Assessment Report
Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

## Conditional Access Policies
"@
        
        if ($null -ne $conditionalAccessPolicies -and $conditionalAccessPolicies.Count -gt 0) {
            foreach ($policy in $conditionalAccessPolicies) {
                $report += @"

### Policy: $($policy.DisplayName)
- State: $($policy.State)
- Created: $($policy.CreatedDateTime)
- Modified: $($policy.ModifiedDateTime)
"@
                
                if ($null -ne $policy.Conditions.Users.IncludeUsers) {
                    $report += @"

#### Target Users:
- $($policy.Conditions.Users.IncludeUsers -join ", ")
"@
                }
                
                if ($null -ne $policy.Conditions.Users.IncludeGroups -and $policy.Conditions.Users.IncludeGroups.Count -gt 0) {
                    $report += @"

#### Target Groups:
- $($policy.Conditions.Users.IncludeGroups -join ", ")
"@
                }
                
                if ($null -ne $policy.Conditions.Applications.IncludeApplications) {
                    $report += @"

#### Target Applications:
- $($policy.Conditions.Applications.IncludeApplications -join ", ")
"@
                }
                
                if ($null -ne $policy.Conditions.Locations.IncludeLocations -and $policy.Conditions.Locations.IncludeLocations.Count -gt 0) {
                    $report += @"

#### Target Locations:
- $($policy.Conditions.Locations.IncludeLocations -join ", ")
"@
                }
                
                if ($null -ne $policy.GrantControls.BuiltInControls) {
                    $report += @"

#### Grant Controls:
- $($policy.GrantControls.BuiltInControls -join ", ")
"@
                }
            }
        }
        else {
            $report += @"

No Conditional Access policies found.
"@
        }
        
        $report += @"

## Identity Protection
"@
        
        if ($null -ne $riskyUsers -and $riskyUsers.Count -gt 0) {
            $report += @"

### Risky Users
"@
            
            # Group users by risk level
            $highRiskUsers = $riskyUsers | Where-Object { $_.RiskLevel -eq "high" }
            $mediumRiskUsers = $riskyUsers | Where-Object { $_.RiskLevel -eq "medium" }
            $lowRiskUsers = $riskyUsers | Where-Object { $_.RiskLevel -eq "low" }
            
            $report += @"

#### High Risk Users: $($highRiskUsers.Count)
"@
            
            if ($highRiskUsers.Count -gt 0) {
                foreach ($user in $highRiskUsers) {
                    $report += @"
- $($user.UserDisplayName) ($($user.UserPrincipalName))
  - Risk State: $($user.RiskState)
  - Risk Detail: $($user.RiskDetail)
  - Last Updated: $($user.RiskLastUpdatedDateTime)
"@
                }
            }
            
            $report += @"

#### Medium Risk Users: $($mediumRiskUsers.Count)
"@
            
            if ($mediumRiskUsers.Count -gt 0) {
                foreach ($user in $mediumRiskUsers) {
                    $report += @"
- $($user.UserDisplayName) ($($user.UserPrincipalName))
  - Risk State: $($user.RiskState)
  - Risk Detail: $($user.RiskDetail)
  - Last Updated: $($user.RiskLastUpdatedDateTime)
"@
                }
            }
            
            $report += @"

#### Low Risk Users: $($lowRiskUsers.Count)
"@
            
            if ($lowRiskUsers.Count -gt 0) {
                foreach ($user in $lowRiskUsers) {
                    $report += @"
- $($user.UserDisplayName) ($($user.UserPrincipalName))
  - Risk State: $($user.RiskState)
  - Risk Detail: $($user.RiskDetail)
  - Last Updated: $($user.RiskLastUpdatedDateTime)
"@
                }
            }
        }
        else {
            $report += @"

No risky users found.
"@
        }
        
        $report += @"

## Multi-Factor Authentication
"@
        
        if ($null -ne $mfaStatus -and $mfaStatus.Count -gt 0) {
            # Calculate MFA statistics
            $totalUsers = $mfaStatus.Count
            $mfaEnabledUsers = ($mfaStatus | Where-Object { $_.MFAEnabled -eq $true }).Count
            $mfaPercentage = [math]::Round(($mfaEnabledUsers / $totalUsers) * 100, 2)
            
            $report += @"

### MFA Status Summary
- Total Users: $totalUsers
- MFA Enabled Users: $mfaEnabledUsers
- MFA Adoption Rate: $mfaPercentage%

### Users Without MFA
"@
            
            $usersWithoutMFA = $mfaStatus | Where-Object { $_.MFAEnabled -eq $false }
            
            if ($usersWithoutMFA.Count -gt 0) {
                foreach ($user in $usersWithoutMFA) {
                    $report += @"
- $($user.DisplayName) ($($user.UserPrincipalName))
"@
                }
            }
            else {
                $report += @"
All users have MFA enabled.
"@
            }
        }
        else {
            $report += @"

Failed to retrieve MFA status.
"@
        }
        
        $report += @"

## Security Defaults
"@
        
        if ($null -ne $securityDefaultsStatus) {
            $report += @"

- Status: $($securityDefaultsStatus.IsEnabled ? "Enabled" : "Disabled")
"@
        }
        else {
            $report += @"

Failed to retrieve Security Defaults status.
"@
        }
        
        $report += @"

## Summary
- Conditional Access Policies: $($conditionalAccessPolicies.Count)
- Risky Users: $($riskyUsers.Count)
- MFA Adoption Rate: $mfaPercentage%
- Security Defaults: $($securityDefaultsStatus.IsEnabled ? "Enabled" : "Disabled")
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
    
    # Connect to Microsoft Graph
    $connectedToGraph = Connect-ToMicrosoftGraph
    if (-not $connectedToGraph) {
        Write-Log "Cannot proceed without Microsoft Graph connection" -Level Error
        exit 1
    }
    
    # Process based on security component and action
    switch ($SecurityComponent) {
        "ConditionalAccess" {
            switch ($Action) {
                "Get" {
                    $policies = Get-ConditionalAccessPolicies
                    
                    if ($null -ne $policies -and $policies.Count -gt 0) {
                        Write-Output "Conditional Access Policies:"
                        $policies | Format-Table -Property DisplayName, State, CreatedDateTime
                    }
                    else {
                        Write-Output "No Conditional Access policies found"
                    }
                }
                "Enable" {
                    if ([string]::IsNullOrEmpty($PolicyName)) {
                        Write-Log "PolicyName parameter is required for Enable action" -Level Error
                        exit 1
                    }
                    
                    # Find policy by name
                    $policies = Get-ConditionalAccessPolicies
                    $policy = $policies | Where-Object { $_.DisplayName -eq $PolicyName }
                    
                    if ($null -eq $policy) {
                        Write-Log "Conditional Access policy '$PolicyName' not found" -Level Error
                        exit 1
                    }
                    
                    # Enable policy
                    $params = @{
                        State = "enabled"
                    }
                    
                    Update-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $policy.Id -BodyParameter $params
                    
                    Write-Output "Conditional Access policy '$PolicyName' enabled successfully"
                }
                "Disable" {
                    if ([string]::IsNullOrEmpty($PolicyName)) {
                        Write-Log "PolicyName parameter is required for Disable action" -Level Error
                        exit 1
                    }
                    
                    # Find policy by name
                    $policies = Get-ConditionalAccessPolicies
                    $policy = $policies | Where-Object { $_.DisplayName -eq $PolicyName }
                    
                    if ($null -eq $policy) {
                        Write-Log "Conditional Access policy '$PolicyName' not found" -Level Error
                        exit 1
                    }
                    
                    # Disable policy
                    $params = @{
                        State = "disabled"
                    }
                    
                    Update-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $policy.Id -BodyParameter $params
                    
                    Write-Output "Conditional Access policy '$PolicyName' disabled successfully"
                }
                "Configure" {
                    if ([string]::IsNullOrEmpty($PolicyName)) {
                        Write-Log "PolicyName parameter is required for Configure action" -Level Error
                        exit 1
                    }
                    
                    if ([string]::IsNullOrEmpty($PolicyType)) {
                        Write-Log "PolicyType parameter is required for Configure action" -Level Error
                        exit 1
                    }
                    
                    # Create policy
                    $policy = New-ConditionalAccessPolicy -PolicyName $PolicyName -PolicyType $PolicyType -TargetGroups $TargetGroups -ExcludedGroups $ExcludedGroups -TargetCountries $TargetCountries -TargetApplications $TargetApplications -ExcludedApplications $ExcludedApplications -RiskLevel $RiskLevel
                    
                    if ($null -eq $policy) {
                        Write-Log "Failed to create Conditional Access policy" -Level Error
                        exit 1
                    }
                    
                    Write-Output "Conditional Access policy '$PolicyName' created successfully"
                }
            }
        }
        "IdentityProtection" {
            switch ($Action) {
                "Get" {
                    $riskyUsers = Get-RiskyUsers
                    
                    if ($null -ne $riskyUsers -and $riskyUsers.Count -gt 0) {
                        Write-Output "Risky Users:"
                        $riskyUsers | Format-Table -Property UserDisplayName, UserPrincipalName, RiskLevel, RiskState
                    }
                    else {
                        Write-Output "No risky users found"
                    }
                }
                "Configure" {
                    if ([string]::IsNullOrEmpty($PolicyName)) {
                        Write-Log "PolicyName parameter is required for Configure action" -Level Error
                        exit 1
                    }
                    
                    if ([string]::IsNullOrEmpty($RiskLevel)) {
                        Write-Log "RiskLevel parameter is required for Configure action" -Level Error
                        exit 1
                    }
                    
                    # Create Conditional Access policy for risky users
                    $policy = New-ConditionalAccessPolicy -PolicyName $PolicyName -PolicyType "RequireMFA" -TargetGroups $TargetGroups -RiskLevel $RiskLevel
                    
                    if ($null -eq $policy) {
                        Write-Log "Failed to create Identity Protection policy" -Level Error
                        exit 1
                    }
                    
                    Write-Output "Identity Protection policy '$PolicyName' created successfully"
                }
            }
        }
        "MFA" {
            switch ($Action) {
                "Get" {
                    $mfaStatus = Get-MFAStatus -UserIds $TargetGroups
                    
                    if ($null -ne $mfaStatus -and $mfaStatus.Count -gt 0) {
                        Write-Output "MFA Status:"
                        $mfaStatus | Format-Table -Property UserPrincipalName, DisplayName, MFAEnabled, AuthenticationMethods
                    }
                    else {
                        Write-Output "Failed to retrieve MFA status"
                    }
                }
                "Enable" {
                    if ($TargetGroups.Count -eq 0) {
                        Write-Log "TargetGroups parameter is required for Enable action" -Level Error
                        exit 1
                    }
                    
                    $result = Enable-MFA -UserIds $TargetGroups
                    
                    if (-not $result) {
                        Write-Log "Failed to enable MFA" -Level Error
                        exit 1
                    }
                    
                    Write-Output "MFA enabled successfully for specified users"
                }
                "Configure" {
                    if ([string]::IsNullOrEmpty($PolicyName)) {
                        Write-Log "PolicyName parameter is required for Configure action" -Level Error
                        exit 1
                    }
                    
                    # Create Conditional Access policy to require MFA
                    $policy = New-ConditionalAccessPolicy -PolicyName $PolicyName -PolicyType "RequireMFA" -TargetGroups $TargetGroups -ExcludedGroups $ExcludedGroups -TargetApplications $TargetApplications -ExcludedApplications $ExcludedApplications
                    
                    if ($null -eq $policy) {
                        Write-Log "Failed to create MFA policy" -Level Error
                        exit 1
                    }
                    
                    Write-Output "MFA policy '$PolicyName' created successfully"
                }
            }
        }
        "SecurityDefaults" {
            switch ($Action) {
                "Get" {
                    $securityDefaultsStatus = Get-SecurityDefaultsStatus
                    
                    if ($null -ne $securityDefaultsStatus) {
                        Write-Output "Security Defaults Status: $($securityDefaultsStatus.IsEnabled ? 'Enabled' : 'Disabled')"
                    }
                    else {
                        Write-Output "Failed to retrieve Security Defaults status"
                    }
                }
                "Enable" {
                    $result = Set-SecurityDefaults -Enabled $true
                    
                    if (-not $result) {
                        Write-Log "Failed to enable Security Defaults" -Level Error
                        exit 1
                    }
                    
                    Write-Output "Security Defaults enabled successfully"
                }
                "Disable" {
                    $result = Set-SecurityDefaults -Enabled $false
                    
                    if (-not $result) {
                        Write-Log "Failed to disable Security Defaults" -Level Error
                        exit 1
                    }
                    
                    Write-Output "Security Defaults disabled successfully"
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
                    
                    $result = Export-SecurityAssessment -ExportPath $ExportPath
                    
                    if (-not $result) {
                        Write-Log "Failed to generate security assessment report" -Level Error
                        exit 1
                    }
                    
                    Write-Output "Security assessment report generated: $ExportPath"
                }
                "Enable" {
                    # Enable Security Defaults
                    $securityDefaultsResult = Set-SecurityDefaults -Enabled $true
                    
                    if (-not $securityDefaultsResult) {
                        Write-Log "Failed to enable Security Defaults" -Level Warning
                    }
                    
                    # Create MFA policy if target groups are specified
                    if ($TargetGroups.Count -gt 0) {
                        $mfaResult = Enable-MFA -UserIds $TargetGroups
                        
                        if (-not $mfaResult) {
                            Write-Log "Failed to enable MFA" -Level Warning
                        }
                    }
                    
                    # Create block legacy auth policy
                    if ($BlockLegacyAuth) {
                        $legacyAuthPolicy = New-ConditionalAccessPolicy -PolicyName "Block Legacy Authentication" -PolicyType "BlockLegacyAuth"
                        
                        if ($null -eq $legacyAuthPolicy) {
                            Write-Log "Failed to create policy to block legacy authentication" -Level Warning
                        }
                    }
                    
                    # Create require compliant device policy
                    if ($RequireCompliantDevice) {
                        $compliantDevicePolicy = New-ConditionalAccessPolicy -PolicyName "Require Compliant Device" -PolicyType "RequireCompliantDevice" -TargetGroups $TargetGroups
                        
                        if ($null -eq $compliantDevicePolicy) {
                            Write-Log "Failed to create policy to require compliant device" -Level Warning
                        }
                    }
                    
                    Write-Output "Security components enabled successfully"
                }
                "Disable" {
                    # Disable Security Defaults
                    $securityDefaultsResult = Set-SecurityDefaults -Enabled $false
                    
                    if (-not $securityDefaultsResult) {
                        Write-Log "Failed to disable Security Defaults" -Level Warning
                    }
                    
                    # Remove MFA policy if it exists
                    $mfaPolicyName = "Require MFA for All Users"
                    $mfaResult = Remove-ConditionalAccessPolicy -PolicyName $mfaPolicyName
                    
                    if (-not $mfaResult) {
                        Write-Log "Failed to remove MFA policy" -Level Warning
                    }
                    
                    # Remove block legacy auth policy if it exists
                    $legacyAuthPolicyName = "Block Legacy Authentication"
                    $legacyAuthResult = Remove-ConditionalAccessPolicy -PolicyName $legacyAuthPolicyName
                    
                    if (-not $legacyAuthResult) {
                        Write-Log "Failed to remove legacy authentication policy" -Level Warning
                    }
                    
                    # Remove require compliant device policy if it exists
                    $compliantDevicePolicyName = "Require Compliant Device"
                    $compliantDeviceResult = Remove-ConditionalAccessPolicy -PolicyName $compliantDevicePolicyName
                    
                    if (-not $compliantDeviceResult) {
                        Write-Log "Failed to remove compliant device policy" -Level Warning
                    }
                    
                    Write-Output "Security components disabled successfully"
                }
                "Configure" {
                    if ([string]::IsNullOrEmpty($PolicyName)) {
                        Write-Log "PolicyName parameter is required for Configure action" -Level Error
                        exit 1
                    }
                    
                    # Configure security based on parameters
                    $securityPolicies = @()
                    
                    # Configure MFA if required
                    if ($RequireMFA) {
                        $mfaPolicy = New-ConditionalAccessPolicy -PolicyName "$PolicyName - Require MFA" -PolicyType "RequireMFA" -TargetGroups $TargetGroups -ExcludedGroups $ExcludedGroups -TargetApplications $TargetApplications -ExcludedApplications $ExcludedApplications
                        
                        if ($null -ne $mfaPolicy) {
                            $securityPolicies += "MFA"
                        }
                    }
                    
                    # Configure block legacy auth if required
                    if ($BlockLegacyAuth) {
                        $legacyAuthPolicy = New-ConditionalAccessPolicy -PolicyName "$PolicyName - Block Legacy Auth" -PolicyType "BlockLegacyAuth" -TargetGroups $TargetGroups -ExcludedGroups $ExcludedGroups
                        
                        if ($null -ne $legacyAuthPolicy) {
                            $securityPolicies += "Block Legacy Auth"
                        }
                    }
                    
                    # Configure require compliant device if required
                    if ($RequireCompliantDevice) {
                        $compliantDevicePolicy = New-ConditionalAccessPolicy -PolicyName "$PolicyName - Require Compliant Device" -PolicyType "RequireCompliantDevice" -TargetGroups $TargetGroups -ExcludedGroups $ExcludedGroups -TargetApplications $TargetApplications -ExcludedApplications $ExcludedApplications
                        
                        if ($null -ne $compliantDevicePolicy) {
                            $securityPolicies += "Require Compliant Device"
                        }
                    }
                    
                    # Configure block countries if specified
                    if ($TargetCountries.Count -gt 0) {
                        $countriesPolicy = New-ConditionalAccessPolicy -PolicyName "$PolicyName - Block Countries" -PolicyType "BlockCountries" -TargetGroups $TargetGroups -ExcludedGroups $ExcludedGroups -TargetCountries $TargetCountries
                        
                        if ($null -ne $countriesPolicy) {
                            $securityPolicies += "Block Countries"
                        }
                    }
                    
                    Write-Output "Security components configured successfully: $($securityPolicies -join ", ")"
                }
            }
        }
    }
    
    # Output success message
    Write-Output "Microsoft 365 Security operation completed successfully"
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
