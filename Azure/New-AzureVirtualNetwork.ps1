<#
.SYNOPSIS
    Creates a new Azure Virtual Network.

.DESCRIPTION
    This script creates a new Azure Virtual Network with specified parameters
    including resource group, location, address space, and subnets.
    It supports creating multiple subnets with different address prefixes and network security groups.

.PARAMETER ResourceGroupName
    The name of the resource group where the virtual network will be created.

.PARAMETER VNetName
    The name of the virtual network to create.

.PARAMETER Location
    The Azure region where the virtual network will be created.

.PARAMETER AddressPrefix
    The address space for the virtual network in CIDR notation (e.g., "10.0.0.0/16").

.PARAMETER Subnets
    An array of subnet configurations. Each subnet should be a hashtable with Name and AddressPrefix keys.
    Example: @(@{Name="Frontend"; AddressPrefix="10.0.1.0/24"}, @{Name="Backend"; AddressPrefix="10.0.2.0/24"})

.PARAMETER Tags
    Optional tags to apply to the virtual network.

.PARAMETER EnableDdosProtection
    Whether to enable DDoS protection for the virtual network.

.PARAMETER LogPath
    Path where logs will be stored. Defaults to Windows log directory.

.EXAMPLE
    .\New-AzureVirtualNetwork.ps1 -ResourceGroupName "MyResourceGroup" -VNetName "MyVNet" -Location "eastus" -AddressPrefix "10.0.0.0/16" -Subnets @(@{Name="Frontend"; AddressPrefix="10.0.1.0/24"}, @{Name="Backend"; AddressPrefix="10.0.2.0/24"})
    Creates a new virtual network with two subnets.

.NOTES
    Author: Michael Witzsche
    Date: April 26, 2025
    Version: 1.1
#>

#Requires -Modules Az.Accounts, Az.Network, Az.Resources

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$LogPath = "$env:SystemRoot\Logs\New-AzureVirtualNetwork",
    
    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,
    
    [Parameter(Mandatory = $true)]
    [string]$VNetName,
    
    [Parameter(Mandatory = $true)]
    [string]$Location,
    
    [Parameter(Mandatory = $true)]
    [string]$AddressPrefix,
    
    [Parameter(Mandatory = $true)]
    [array]$Subnets,
    
    [Parameter(Mandatory = $false)]
    [hashtable]$Tags = @{},
    
    [Parameter(Mandatory = $false)]
    [bool]$EnableDdosProtection = $false
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
#endregion

#region Main Script
try {
    # Script start
    Write-Log "Script started with parameters: ResourceGroupName=$ResourceGroupName, VNetName=$VNetName, Location=$Location, AddressPrefix=$AddressPrefix"
    
    # Connect to Azure
    $connectedToAzure = Connect-ToAzure
    if (-not $connectedToAzure) {
        Write-Log "Cannot proceed without Azure connection" -Level Error
        exit 1
    }
    
    # Check if resource group exists, create if not
    Write-Log "Checking if resource group $ResourceGroupName exists..."
    $resourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
    if ($null -eq $resourceGroup) {
        Write-Log "Resource group $ResourceGroupName does not exist. Creating..."
        $resourceGroup = New-AzResourceGroup -Name $ResourceGroupName -Location $Location
        Write-Log "Resource group created successfully"
    }
    
    # Check if virtual network already exists
    Write-Log "Checking if virtual network $VNetName already exists..."
    $existingVNet = Get-AzVirtualNetwork -Name $VNetName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
    if ($null -ne $existingVNet) {
        Write-Log "Virtual network $VNetName already exists in resource group $ResourceGroupName." -Level Warning
        
        # Ask if user wants to update the existing VNet
        $updateVNet = Read-Host "Do you want to update the existing virtual network? (Y/N)"
        if ($updateVNet -ne "Y" -and $updateVNet -ne "y") {
            Write-Log "Operation cancelled by user" -Level Warning
            exit 0
        }
        
        Write-Log "Proceeding with update of existing virtual network"
    }
    
    # Create subnet configurations
    Write-Log "Creating subnet configurations..."
    $subnetConfigs = @()
    
    foreach ($subnet in $Subnets) {
        if (-not $subnet.ContainsKey("Name") -or -not $subnet.ContainsKey("AddressPrefix")) {
            Write-Log "Invalid subnet configuration. Each subnet must have Name and AddressPrefix keys." -Level Error
            exit 1
        }
        
        Write-Log "Creating subnet configuration for $($subnet.Name) with address prefix $($subnet.AddressPrefix)"
        $subnetConfig = New-AzVirtualNetworkSubnetConfig -Name $subnet.Name -AddressPrefix $subnet.AddressPrefix
        $subnetConfigs += $subnetConfig
    }
    
    # Create or update virtual network
    if ($null -eq $existingVNet) {
        # Create new virtual network
        Write-Log "Creating new virtual network $VNetName..."
        $vnet = New-AzVirtualNetwork -ResourceGroupName $ResourceGroupName -Name $VNetName -Location $Location -AddressPrefix $AddressPrefix -Subnet $subnetConfigs -Tag $Tags -EnableDdosProtection:$EnableDdosProtection
        Write-Log "Virtual network created successfully"
    }
    else {
        # Update existing virtual network
        Write-Log "Updating existing virtual network $VNetName..."
        
        # Update address space
        $existingVNet.AddressSpace.AddressPrefixes = @($AddressPrefix)
        
        # Update subnets
        foreach ($subnet in $Subnets) {
            $existingSubnet = $existingVNet.Subnets | Where-Object { $_.Name -eq $subnet.Name }
            
            if ($null -eq $existingSubnet) {
                # Add new subnet
                Write-Log "Adding new subnet $($subnet.Name)..."
                Add-AzVirtualNetworkSubnetConfig -Name $subnet.Name -AddressPrefix $subnet.AddressPrefix -VirtualNetwork $existingVNet | Out-Null
            }
            else {
                # Update existing subnet
                Write-Log "Updating existing subnet $($subnet.Name)..."
                Set-AzVirtualNetworkSubnetConfig -Name $subnet.Name -AddressPrefix $subnet.AddressPrefix -VirtualNetwork $existingVNet | Out-Null
            }
        }
        
        # Update tags
        $existingVNet.Tag = $Tags
        
        # Update DDoS protection
        $existingVNet.EnableDdosProtection = $EnableDdosProtection
        
        # Apply changes
        $vnet = $existingVNet | Set-AzVirtualNetwork
        Write-Log "Virtual network updated successfully"
    }
    
    # Output virtual network details
    Write-Output "Virtual network details:"
    Write-Output "  Name: $($vnet.Name)"
    Write-Output "  Resource Group: $ResourceGroupName"
    Write-Output "  Location: $($vnet.Location)"
    Write-Output "  Address Space: $($vnet.AddressSpace.AddressPrefixes -join ', ')"
    Write-Output "  Subnets:"
    foreach ($subnet in $vnet.Subnets) {
        Write-Output "    - $($subnet.Name): $($subnet.AddressPrefix)"
    }
    Write-Output "  DDoS Protection Enabled: $($vnet.EnableDdosProtection)"
    
    return $vnet
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
