<#
.SYNOPSIS
    Assigns an Azure AD role to a user or service principal.

.DESCRIPTION
    This script assigns an Azure AD role to a user or service principal in Azure Active Directory.
    It supports both built-in and custom roles and provides options for scope (directory, subscription, resource group, or resource).

.PARAMETER PrincipalId
    The object ID of the user or service principal to assign the role to.

.PARAMETER PrincipalType
    The type of principal (User or ServicePrincipal).

.PARAMETER RoleName
    The name of the role to assign (e.g., "Global Administrator", "Contributor").

.PARAMETER ScopeType
    The type of scope for the role assignment (Directory, Subscription, ResourceGroup, or Resource).

.PARAMETER SubscriptionId
    The subscription ID when scope type is Subscription, ResourceGroup, or Resource.

.PARAMETER ResourceGroupName
    The resource group name when scope type is ResourceGroup or Resource.

.PARAMETER ResourceName
    The resource name when scope type is Resource.

.PARAMETER ResourceType
    The resource type when scope type is Resource (e.g., "Microsoft.Compute/virtualMachines").

.PARAMETER LogPath
    Path where logs will be stored. Defaults to Windows log directory.

.EXAMPLE
    .\Add-AzureADRoleAssignment.ps1 -PrincipalId "12345678-1234-1234-1234-123456789012" -PrincipalType User -RoleName "Global Administrator" -ScopeType Directory
    Assigns the Global Administrator role at directory level to the specified user.

.EXAMPLE
    .\Add-AzureADRoleAssignment.ps1 -PrincipalId "12345678-1234-1234-1234-123456789012" -PrincipalType User -RoleName "Contributor" -ScopeType Subscription -SubscriptionId "87654321-4321-4321-4321-210987654321"
    Assigns the Contributor role at subscription level to the specified user.

.NOTES
    Author: Michael Witzsche
    Date: April 26, 2025
    Version: 1.1
#>

#Requires -Modules Az.Accounts, Az.Resources, Microsoft.Graph.Identity.DirectoryManagement

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$LogPath = "$env:SystemRoot\Logs\Add-AzureADRoleAssignment",
    
    [Parameter(Mandatory = $true)]
    [string]$PrincipalId,
    
    [Parameter(Mandatory = $true)]
    [ValidateSet("User", "ServicePrincipal")]
    [string]$PrincipalType,
    
    [Parameter(Mandatory = $true)]
    [string]$RoleName,
    
    [Parameter(Mandatory = $true)]
    [ValidateSet("Directory", "Subscription", "ResourceGroup", "Resource")]
    [string]$ScopeType,
    
    [Parameter(Mandatory = $false)]
    [string]$SubscriptionId,
    
    [Parameter(Mandatory = $false)]
    [string]$ResourceGroupName,
    
    [Parameter(Mandatory = $false)]
    [string]$ResourceName,
    
    [Parameter(Mandatory = $false)]
    [string]$ResourceType
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
    param()
    
    try {
        # Check if already connected
        $context = Get-AzContext
        if ($null -ne $context) {
            Write-Log "Already connected to Azure as $($context.Account.Id)"
            return $true
        }
        
        # Connect to Azure
        Write-Log "Connecting to Azure..."
        Connect-AzAccount -ErrorAction Stop
        
        # Verify connection
        $context = Get-AzContext
        if ($null -eq $context) {
            Write-Log "Failed to connect to Azure" -Level Error
            return $false
        }
        
        Write-Log "Successfully connected to Azure as $($context.Account.Id)"
        return $true
    }
    catch {
        Write-Log "Error connecting to Azure: $_" -Level Error
        return $false
    }
}

function Connect-ToMSGraph {
    [CmdletBinding()]
    param()
    
    try {
        # Check if already connected
        try {
            $graphUser = Get-MgUser -Top 1 -ErrorAction Stop
            Write-Log "Already connected to Microsoft Graph"
            return $true
        }
        catch {
            # Not connected, proceed with connection
        }
        
        # Connect to Microsoft Graph with required scopes
        Write-Log "Connecting to Microsoft Graph..."
        Connect-MgGraph -Scopes "RoleManagement.ReadWrite.Directory", "Directory.ReadWrite.All" -ErrorAction Stop
        
        # Verify connection
        try {
            $graphUser = Get-MgUser -Top 1 -ErrorAction Stop
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

function Get-ScopeString {
    [CmdletBinding()]
    param()
    
    switch ($ScopeType) {
        "Directory" {
            return "/"
        }
        "Subscription" {
            if ([string]::IsNullOrEmpty($SubscriptionId)) {
                throw "SubscriptionId is required for Subscription scope"
            }
            return "/subscriptions/$SubscriptionId"
        }
        "ResourceGroup" {
            if ([string]::IsNullOrEmpty($SubscriptionId) -or [string]::IsNullOrEmpty($ResourceGroupName)) {
                throw "SubscriptionId and ResourceGroupName are required for ResourceGroup scope"
            }
            return "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName"
        }
        "Resource" {
            if ([string]::IsNullOrEmpty($SubscriptionId) -or [string]::IsNullOrEmpty($ResourceGroupName) -or 
                [string]::IsNullOrEmpty($ResourceName) -or [string]::IsNullOrEmpty($ResourceType)) {
                throw "SubscriptionId, ResourceGroupName, ResourceName, and ResourceType are required for Resource scope"
            }
            return "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/$ResourceType/$ResourceName"
        }
        default {
            throw "Invalid ScopeType: $ScopeType"
        }
    }
}
#endregion

#region Main Script
try {
    # Script start
    Write-Log "Script started with parameters: PrincipalId=$PrincipalId, PrincipalType=$PrincipalType, RoleName=$RoleName, ScopeType=$ScopeType"
    
    # Connect to Azure
    $connectedToAzure = Connect-ToAzure
    if (-not $connectedToAzure) {
        Write-Log "Cannot proceed without Azure connection" -Level Error
        exit 1
    }
    
    # Connect to Microsoft Graph if needed for directory roles
    if ($ScopeType -eq "Directory") {
        $connectedToGraph = Connect-ToMSGraph
        if (-not $connectedToGraph) {
            Write-Log "Cannot proceed without Microsoft Graph connection for directory roles" -Level Error
            exit 1
        }
    }
    
    # Validate principal exists
    Write-Log "Validating principal $PrincipalId exists..."
    try {
        if ($PrincipalType -eq "User") {
            $principal = Get-AzADUser -ObjectId $PrincipalId -ErrorAction Stop
            if ($null -eq $principal) {
                Write-Log "User with ID $PrincipalId not found" -Level Error
                exit 1
            }
            Write-Log "Found user: $($principal.DisplayName)"
        }
        else {
            $principal = Get-AzADServicePrincipal -ObjectId $PrincipalId -ErrorAction Stop
            if ($null -eq $principal) {
                Write-Log "Service Principal with ID $PrincipalId not found" -Level Error
                exit 1
            }
            Write-Log "Found service principal: $($principal.DisplayName)"
        }
    }
    catch {
        Write-Log "Error validating principal: $_" -Level Error
        exit 1
    }
    
    # Handle directory roles differently than RBAC roles
    if ($ScopeType -eq "Directory") {
        try {
            # Get directory role
            Write-Log "Getting directory role: $RoleName"
            $role = Get-MgDirectoryRole -Filter "DisplayName eq '$RoleName'" -ErrorAction Stop
            
            if ($null -eq $role) {
                # Role might not be activated yet, try to activate it
                Write-Log "Role not found, attempting to activate it..."
                $roleTemplate = Get-MgDirectoryRoleTemplate -Filter "DisplayName eq '$RoleName'" -ErrorAction Stop
                
                if ($null -eq $roleTemplate) {
                    Write-Log "Directory role template '$RoleName' not found" -Level Error
                    exit 1
                }
                
                $role = New-MgDirectoryRole -RoleTemplateId $roleTemplate.Id -ErrorAction Stop
                Write-Log "Activated directory role: $RoleName"
            }
            
            # Check if principal is already a member
            $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -ErrorAction Stop
            $isMember = $members | Where-Object { $_.Id -eq $PrincipalId }
            
            if ($null -ne $isMember) {
                Write-Log "Principal is already a member of the '$RoleName' role" -Level Warning
                return
            }
            
            # Add member to role
            Write-Log "Adding principal to directory role: $RoleName"
            New-MgDirectoryRoleMemberByRef -DirectoryRoleId $role.Id -BodyParameter @{
                "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$PrincipalId"
            } -ErrorAction Stop
            
            Write-Log "Successfully assigned directory role '$RoleName' to principal"
        }
        catch {
            Write-Log "Error assigning directory role: $_" -Level Error
            exit 1
        }
    }
    else {
        try {
            # Get scope string
            $scope = Get-ScopeString
            Write-Log "Using scope: $scope"
            
            # Set subscription context if needed
            if ($ScopeType -ne "Directory" -and -not [string]::IsNullOrEmpty($SubscriptionId)) {
                Write-Log "Setting subscription context to: $SubscriptionId"
                Set-AzContext -Subscription $SubscriptionId -ErrorAction Stop | Out-Null
            }
            
            # Get role definition
            Write-Log "Getting role definition: $RoleName"
            $roleDefinition = Get-AzRoleDefinition -Name $RoleName -ErrorAction Stop
            
            if ($null -eq $roleDefinition) {
                Write-Log "Role definition '$RoleName' not found" -Level Error
                exit 1
            }
            
            # Check if assignment already exists
            $existingAssignment = Get-AzRoleAssignment -ObjectId $PrincipalId -RoleDefinitionName $RoleName -Scope $scope -ErrorAction SilentlyContinue
            
            if ($null -ne $existingAssignment) {
                Write-Log "Role assignment already exists" -Level Warning
                return
            }
            
            # Create role assignment
            Write-Log "Creating role assignment..."
            $assignment = New-AzRoleAssignment -ObjectId $PrincipalId -RoleDefinitionName $RoleName -Scope $scope -ErrorAction Stop
            
            Write-Log "Successfully created role assignment with ID: $($assignment.RoleAssignmentId)"
            
            # Output assignment details
            Write-Output "Role assignment created successfully:"
            Write-Output "  Principal: $($principal.DisplayName)"
            Write-Output "  Role: $RoleName"
            Write-Output "  Scope: $scope"
            Write-Output "  Assignment ID: $($assignment.RoleAssignmentId)"
        }
        catch {
            Write-Log "Error creating role assignment: $_" -Level Error
            exit 1
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
