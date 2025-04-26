<#
.SYNOPSIS
    Creates a new Azure Virtual Machine.

.DESCRIPTION
    This script creates a new Azure Virtual Machine with specified parameters
    including resource group, location, size, OS type, and networking configuration.
    It supports both Windows and Linux VMs with various configuration options.

.PARAMETER ResourceGroupName
    The name of the resource group where the VM will be created.

.PARAMETER VMName
    The name of the virtual machine to create.

.PARAMETER Location
    The Azure region where the VM will be created.

.PARAMETER VMSize
    The size of the virtual machine (e.g., "Standard_D2s_v3").

.PARAMETER OSType
    The operating system type (Windows or Linux).

.PARAMETER AdminUsername
    The administrator username for the VM.

.PARAMETER AdminPassword
    The administrator password for the VM.

.PARAMETER VirtualNetworkName
    The name of the virtual network to use. If it doesn't exist, it will be created.

.PARAMETER SubnetName
    The name of the subnet to use. If it doesn't exist, it will be created.

.PARAMETER PublicIPAddressName
    The name of the public IP address to create. If not specified, no public IP will be assigned.

.PARAMETER OpenPorts
    The ports to open in the network security group (e.g., 80, 443, 3389, 22).

.PARAMETER LogPath
    Path where logs will be stored. Defaults to Windows log directory.

.EXAMPLE
    .\New-AzureVM.ps1 -ResourceGroupName "MyResourceGroup" -VMName "MyVM" -Location "eastus" -VMSize "Standard_D2s_v3" -OSType "Windows" -AdminUsername "adminuser" -AdminPassword "P@ssw0rd123" -VirtualNetworkName "MyVNet" -SubnetName "default" -PublicIPAddressName "MyVMPublicIP" -OpenPorts 3389,80,443
    Creates a new Windows VM with the specified configuration.

.NOTES
    Author: Michael Witzsche
    Date: April 26, 2025
    Version: 1.1
#>

#Requires -Modules Az.Accounts, Az.Compute, Az.Network, Az.Resources

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$LogPath = "$env:SystemRoot\Logs\New-AzureVM",
    
    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,
    
    [Parameter(Mandatory = $true)]
    [string]$VMName,
    
    [Parameter(Mandatory = $true)]
    [string]$Location,
    
    [Parameter(Mandatory = $true)]
    [string]$VMSize,
    
    [Parameter(Mandatory = $true)]
    [ValidateSet("Windows", "Linux")]
    [string]$OSType,
    
    [Parameter(Mandatory = $true)]
    [string]$AdminUsername,
    
    [Parameter(Mandatory = $true)]
    [string]$AdminPassword,
    
    [Parameter(Mandatory = $true)]
    [string]$VirtualNetworkName,
    
    [Parameter(Mandatory = $true)]
    [string]$SubnetName,
    
    [Parameter(Mandatory = $false)]
    [string]$PublicIPAddressName = "",
    
    [Parameter(Mandatory = $false)]
    [int[]]$OpenPorts = @()
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
    Write-Log "Script started with parameters: ResourceGroupName=$ResourceGroupName, VMName=$VMName, Location=$Location, OSType=$OSType"
    
    # Connect to Azure
    $connectedToAzure = Connect-ToAzure
    if (-not $connectedToAzure) {
        Write-Log "Cannot proceed without Azure connection" -Level Error
        exit 1
    }
    
    # Create secure credentials
    $securePassword = ConvertTo-SecureString $AdminPassword -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential ($AdminUsername, $securePassword)
    
    # Check if resource group exists, create if not
    Write-Log "Checking if resource group $ResourceGroupName exists..."
    $resourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
    if ($null -eq $resourceGroup) {
        Write-Log "Resource group $ResourceGroupName does not exist. Creating..."
        $resourceGroup = New-AzResourceGroup -Name $ResourceGroupName -Location $Location
        Write-Log "Resource group created successfully"
    }
    
    # Check if VM already exists
    Write-Log "Checking if VM $VMName already exists..."
    $existingVM = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $VMName -ErrorAction SilentlyContinue
    if ($null -ne $existingVM) {
        Write-Log "VM $VMName already exists in resource group $ResourceGroupName. Cannot create duplicate VM." -Level Error
        exit 1
    }
    
    # Check if virtual network exists, create if not
    Write-Log "Checking if virtual network $VirtualNetworkName exists..."
    $vnet = Get-AzVirtualNetwork -Name $VirtualNetworkName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
    if ($null -eq $vnet) {
        Write-Log "Virtual network $VirtualNetworkName does not exist. Creating..."
        $subnetConfig = New-AzVirtualNetworkSubnetConfig -Name $SubnetName -AddressPrefix "10.0.0.0/24"
        $vnet = New-AzVirtualNetwork -ResourceGroupName $ResourceGroupName -Name $VirtualNetworkName -Location $Location -AddressPrefix "10.0.0.0/16" -Subnet $subnetConfig
        Write-Log "Virtual network created successfully"
    }
    
    # Get subnet
    $subnet = Get-AzVirtualNetworkSubnetConfig -Name $SubnetName -VirtualNetwork $vnet -ErrorAction SilentlyContinue
    if ($null -eq $subnet) {
        Write-Log "Subnet $SubnetName does not exist in virtual network $VirtualNetworkName. Creating..."
        $subnet = Add-AzVirtualNetworkSubnetConfig -Name $SubnetName -VirtualNetwork $vnet -AddressPrefix "10.0.1.0/24"
        $vnet | Set-AzVirtualNetwork | Out-Null
        $vnet = Get-AzVirtualNetwork -Name $VirtualNetworkName -ResourceGroupName $ResourceGroupName
        $subnet = Get-AzVirtualNetworkSubnetConfig -Name $SubnetName -VirtualNetwork $vnet
        Write-Log "Subnet created successfully"
    }
    
    # Create network interface configuration
    Write-Log "Creating network interface configuration..."
    $nicName = "$VMName-nic"
    $nic = $null
    
    # Create public IP if specified
    if (-not [string]::IsNullOrEmpty($PublicIPAddressName)) {
        Write-Log "Creating public IP address $PublicIPAddressName..."
        $publicIP = New-AzPublicIpAddress -ResourceGroupName $ResourceGroupName -Name $PublicIPAddressName -Location $Location -AllocationMethod Dynamic
        
        # Create network security group if open ports specified
        if ($OpenPorts.Count -gt 0) {
            Write-Log "Creating network security group with open ports: $($OpenPorts -join ', ')..."
            $nsgName = "$VMName-nsg"
            $nsg = New-AzNetworkSecurityGroup -ResourceGroupName $ResourceGroupName -Name $nsgName -Location $Location
            
            # Add rules for each port
            $priority = 1000
            foreach ($port in $OpenPorts) {
                $ruleName = "Allow-$port"
                Write-Log "Adding NSG rule for port $port..."
                $nsg | Add-AzNetworkSecurityRuleConfig -Name $ruleName -Protocol Tcp -Direction Inbound -Priority $priority -SourceAddressPrefix * -SourcePortRange * -DestinationAddressPrefix * -DestinationPortRange $port -Access Allow | Set-AzNetworkSecurityGroup | Out-Null
                $priority += 10
            }
            
            # Create NIC with public IP and NSG
            $nic = New-AzNetworkInterface -ResourceGroupName $ResourceGroupName -Name $nicName -Location $Location -SubnetId $subnet.Id -PublicIpAddressId $publicIP.Id -NetworkSecurityGroupId $nsg.Id
        }
        else {
            # Create NIC with public IP but no NSG
            $nic = New-AzNetworkInterface -ResourceGroupName $ResourceGroupName -Name $nicName -Location $Location -SubnetId $subnet.Id -PublicIpAddressId $publicIP.Id
        }
    }
    else {
        # Create NIC without public IP
        $nic = New-AzNetworkInterface -ResourceGroupName $ResourceGroupName -Name $nicName -Location $Location -SubnetId $subnet.Id
    }
    
    Write-Log "Network interface created successfully"
    
    # Create VM configuration
    Write-Log "Creating VM configuration..."
    $vmConfig = New-AzVMConfig -VMName $VMName -VMSize $VMSize
    
    # Add NIC to VM configuration
    $vmConfig = Add-AzVMNetworkInterface -VM $vmConfig -Id $nic.Id
    
    # Configure OS based on type
    if ($OSType -eq "Windows") {
        Write-Log "Configuring Windows OS..."
        $vmConfig = Set-AzVMOperatingSystem -VM $vmConfig -Windows -ComputerName $VMName -Credential $credential -ProvisionVMAgent -EnableAutoUpdate
        $vmConfig = Set-AzVMSourceImage -VM $vmConfig -PublisherName "MicrosoftWindowsServer" -Offer "WindowsServer" -Skus "2019-Datacenter" -Version "latest"
    }
    else {
        Write-Log "Configuring Linux OS..."
        $vmConfig = Set-AzVMOperatingSystem -VM $vmConfig -Linux -ComputerName $VMName -Credential $credential
        $vmConfig = Set-AzVMSourceImage -VM $vmConfig -PublisherName "Canonical" -Offer "UbuntuServer" -Skus "18.04-LTS" -Version "latest"
    }
    
    # Add OS disk
    $osDiskName = "$VMName-osdisk"
    $vmConfig = Set-AzVMOSDisk -VM $vmConfig -Name $osDiskName -CreateOption FromImage
    
    # Create the VM
    Write-Log "Creating VM $VMName..."
    try {
        $newVM = New-AzVM -ResourceGroupName $ResourceGroupName -Location $Location -VM $vmConfig
        
        Write-Log "VM created successfully"
        
        # Get VM details
        $vm = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $VMName
        
        # Get public IP if applicable
        $publicIPAddress = ""
        if (-not [string]::IsNullOrEmpty($PublicIPAddressName)) {
            $publicIP = Get-AzPublicIpAddress -ResourceGroupName $ResourceGroupName -Name $PublicIPAddressName
            $publicIPAddress = $publicIP.IpAddress
        }
        
        # Output VM details
        Write-Output "VM created successfully:"
        Write-Output "  Name: $VMName"
        Write-Output "  Resource Group: $ResourceGroupName"
        Write-Output "  Location: $Location"
        Write-Output "  Size: $VMSize"
        Write-Output "  OS Type: $OSType"
        if (-not [string]::IsNullOrEmpty($publicIPAddress)) {
            Write-Output "  Public IP: $publicIPAddress"
        }
        
        return $vm
    }
    catch {
        Write-Log "Failed to create VM: $_" -Level Error
        throw $_
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
