<#
.SYNOPSIS
    Creates and configures an Azure SQL Database and Server.

.DESCRIPTION
    This script creates and configures an Azure SQL Database and Server with specified parameters
    including resource group, location, performance tier, security settings, and backup configuration.
    It supports various SQL Database configurations and security options.

.PARAMETER ResourceGroupName
    The name of the resource group where the SQL Server and Database will be created.

.PARAMETER Location
    The Azure region where the SQL Server and Database will be deployed.

.PARAMETER ServerName
    The name of the SQL Server to create.

.PARAMETER DatabaseName
    The name of the SQL Database to create.

.PARAMETER AdminUsername
    The administrator username for the SQL Server.

.PARAMETER AdminPassword
    The administrator password for the SQL Server.

.PARAMETER Edition
    The edition of the SQL Database (Basic, Standard, Premium, GeneralPurpose, BusinessCritical, Hyperscale).

.PARAMETER ServiceObjective
    The performance level of the SQL Database (e.g., Basic, S0, P1, GP_Gen5_2, BC_Gen5_2).

.PARAMETER MaxSizeGB
    The maximum size of the SQL Database in GB.

.PARAMETER AllowAzureIPs
    Whether to allow Azure services to access the SQL Server.

.PARAMETER AllowedIPAddresses
    Array of IP addresses or ranges to allow access to the SQL Server.

.PARAMETER EnableAudit
    Whether to enable auditing for the SQL Server.

.PARAMETER AuditRetentionDays
    The number of days to retain audit logs.

.PARAMETER EnableThreatDetection
    Whether to enable Advanced Threat Protection.

.PARAMETER EnableTransparentDataEncryption
    Whether to enable Transparent Data Encryption.

.PARAMETER EnableGeoBackup
    Whether to enable geo-redundant backups.

.PARAMETER BackupRetentionDays
    The number of days to retain backups.

.PARAMETER Tags
    Hashtable of tags to apply to the SQL Server and Database.

.PARAMETER LogPath
    Path where logs will be stored. Defaults to Windows log directory.

.EXAMPLE
    .\New-AzureSQLDatabase.ps1 -ResourceGroupName "MyRG" -Location "eastus" -ServerName "mysqlserver" -DatabaseName "mydb" -AdminUsername "sqladmin" -AdminPassword "P@ssw0rd123!" -Edition "Standard" -ServiceObjective "S1" -MaxSizeGB 50 -AllowAzureIPs $true -AllowedIPAddresses @("203.0.113.0/24", "198.51.100.10")
    Creates a Standard S1 SQL Database with firewall rules to allow specific IP addresses.

.EXAMPLE
    .\New-AzureSQLDatabase.ps1 -ResourceGroupName "MyRG" -Location "westeurope" -ServerName "mysqlserver" -DatabaseName "mydb" -AdminUsername "sqladmin" -AdminPassword "P@ssw0rd123!" -Edition "GeneralPurpose" -ServiceObjective "GP_Gen5_2" -MaxSizeGB 100 -EnableAudit $true -EnableThreatDetection $true -EnableTransparentDataEncryption $true -EnableGeoBackup $true
    Creates a General Purpose SQL Database with enhanced security features and geo-redundant backups.

.NOTES
    Author: Michael Witzsche
    Date: April 26, 2025
    Version: 1.1
#>

#Requires -Modules Az.Sql, Az.Resources

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$LogPath = "$env:SystemRoot\Logs\New-AzureSQLDatabase",
    
    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,
    
    [Parameter(Mandatory = $true)]
    [string]$Location,
    
    [Parameter(Mandatory = $true)]
    [string]$ServerName,
    
    [Parameter(Mandatory = $true)]
    [string]$DatabaseName,
    
    [Parameter(Mandatory = $true)]
    [string]$AdminUsername,
    
    [Parameter(Mandatory = $true)]
    [string]$AdminPassword,
    
    [Parameter(Mandatory = $true)]
    [ValidateSet("Basic", "Standard", "Premium", "GeneralPurpose", "BusinessCritical", "Hyperscale")]
    [string]$Edition,
    
    [Parameter(Mandatory = $true)]
    [string]$ServiceObjective,
    
    [Parameter(Mandatory = $false)]
    [int]$MaxSizeGB = 32,
    
    [Parameter(Mandatory = $false)]
    [bool]$AllowAzureIPs = $false,
    
    [Parameter(Mandatory = $false)]
    [string[]]$AllowedIPAddresses = @(),
    
    [Parameter(Mandatory = $false)]
    [bool]$EnableAudit = $false,
    
    [Parameter(Mandatory = $false)]
    [int]$AuditRetentionDays = 90,
    
    [Parameter(Mandatory = $false)]
    [bool]$EnableThreatDetection = $false,
    
    [Parameter(Mandatory = $false)]
    [bool]$EnableTransparentDataEncryption = $true,
    
    [Parameter(Mandatory = $false)]
    [bool]$EnableGeoBackup = $false,
    
    [Parameter(Mandatory = $false)]
    [int]$BackupRetentionDays = 7,
    
    [Parameter(Mandatory = $false)]
    [hashtable]$Tags = @{}
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
            Write-Log "Already connected to Azure as $($context.Account.Id) in subscription $($context.Subscription.Name)"
            return $true
        }
        
        # Connect to Azure
        Write-Log "Connecting to Azure..."
        Connect-AzAccount -ErrorAction Stop
        
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

function New-ResourceGroupIfNotExists {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ResourceGroupName,
        
        [Parameter(Mandatory = $true)]
        [string]$Location
    )
    
    try {
        # Check if resource group exists
        $resourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
        
        if ($null -eq $resourceGroup) {
            # Create resource group
            Write-Log "Creating resource group $ResourceGroupName in $Location..."
            $resourceGroup = New-AzResourceGroup -Name $ResourceGroupName -Location $Location
            Write-Log "Resource group $ResourceGroupName created successfully"
        }
        else {
            Write-Log "Resource group $ResourceGroupName already exists"
        }
        
        return $resourceGroup
    }
    catch {
        Write-Log "Error creating resource group: $_" -Level Error
        throw $_
    }
}

function New-SQLServer {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ResourceGroupName,
        
        [Parameter(Mandatory = $true)]
        [string]$Location,
        
        [Parameter(Mandatory = $true)]
        [string]$ServerName,
        
        [Parameter(Mandatory = $true)]
        [string]$AdminUsername,
        
        [Parameter(Mandatory = $true)]
        [string]$AdminPassword,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Tags = @{}
    )
    
    try {
        # Check if SQL Server exists
        $server = Get-AzSqlServer -ResourceGroupName $ResourceGroupName -ServerName $ServerName -ErrorAction SilentlyContinue
        
        if ($null -eq $server) {
            # Create secure password
            $securePassword = ConvertTo-SecureString $AdminPassword -AsPlainText -Force
            $credential = New-Object System.Management.Automation.PSCredential ($AdminUsername, $securePassword)
            
            # Create SQL Server
            Write-Log "Creating SQL Server $ServerName in $Location..."
            $serverParams = @{
                ResourceGroupName = $ResourceGroupName
                Location = $Location
                ServerName = $ServerName
                SqlAdministratorCredentials = $credential
                ServerVersion = "12.0"
            }
            
            # Add tags if specified
            if ($Tags.Count -gt 0) {
                $serverParams.Tag = $Tags
            }
            
            $server = New-AzSqlServer @serverParams
            Write-Log "SQL Server $ServerName created successfully"
        }
        else {
            Write-Log "SQL Server $ServerName already exists"
        }
        
        return $server
    }
    catch {
        Write-Log "Error creating SQL Server: $_" -Level Error
        throw $_
    }
}

function Set-SQLServerFirewallRules {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ResourceGroupName,
        
        [Parameter(Mandatory = $true)]
        [string]$ServerName,
        
        [Parameter(Mandatory = $false)]
        [bool]$AllowAzureIPs = $false,
        
        [Parameter(Mandatory = $false)]
        [string[]]$AllowedIPAddresses = @()
    )
    
    try {
        # Allow Azure services if specified
        if ($AllowAzureIPs) {
            Write-Log "Allowing Azure services to access SQL Server..."
            New-AzSqlServerFirewallRule -ResourceGroupName $ResourceGroupName -ServerName $ServerName -AllowAllAzureIPs | Out-Null
        }
        
        # Add firewall rules for allowed IP addresses
        foreach ($ip in $AllowedIPAddresses) {
            $ruleName = "Rule_$($ip.Replace('/', '_').Replace('.', '_'))"
            
            # Check if IP contains a subnet mask
            if ($ip -match "/") {
                # Convert CIDR notation to start and end IP addresses
                $network, $mask = $ip -split "/"
                $networkIP = [System.Net.IPAddress]::Parse($network)
                $maskIP = [System.Net.IPAddress]::Parse((Convert-CIDRToSubnetMask $mask))
                $networkAddressInt = ConvertIPToInt $networkIP
                $maskInt = ConvertIPToInt $maskIP
                
                $startIPInt = $networkAddressInt -band $maskInt
                $endIPInt = $startIPInt -bor (-bnot $maskInt -band [uint32]0xFFFFFFFF)
                
                $startIP = ConvertIntToIP $startIPInt
                $endIP = ConvertIntToIP $endIPInt
            }
            else {
                # Single IP address
                $startIP = $ip
                $endIP = $ip
            }
            
            Write-Log "Adding firewall rule for IP range: $startIP - $endIP..."
            New-AzSqlServerFirewallRule -ResourceGroupName $ResourceGroupName -ServerName $ServerName -FirewallRuleName $ruleName -StartIpAddress $startIP -EndIpAddress $endIP | Out-Null
        }
        
        Write-Log "SQL Server firewall rules configured successfully"
        return $true
    }
    catch {
        Write-Log "Error configuring SQL Server firewall rules: $_" -Level Error
        return $false
    }
}

function Convert-CIDRToSubnetMask {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [int]$MaskBits
    )
    
    $mask = [UInt32]([Math]::Pow(2, $MaskBits) - 1) * [Math]::Pow(2, (32 - $MaskBits))
    $bytes = [BitConverter]::GetBytes([UInt32]$mask)
    [Array]::Reverse($bytes)
    return [IPAddress](New-Object System.Net.IPAddress(,$bytes))
}

function ConvertIPToInt {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.Net.IPAddress]$IP
    )
    
    $bytes = $IP.GetAddressBytes()
    [Array]::Reverse($bytes)
    return [BitConverter]::ToUInt32($bytes, 0)
}

function ConvertIntToIP {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [uint32]$Int
    )
    
    $bytes = [BitConverter]::GetBytes($Int)
    [Array]::Reverse($bytes)
    return [IPAddress](New-Object System.Net.IPAddress(,$bytes))
}

function New-SQLDatabase {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ResourceGroupName,
        
        [Parameter(Mandatory = $true)]
        [string]$ServerName,
        
        [Parameter(Mandatory = $true)]
        [string]$DatabaseName,
        
        [Parameter(Mandatory = $true)]
        [string]$Edition,
        
        [Parameter(Mandatory = $true)]
        [string]$ServiceObjective,
        
        [Parameter(Mandatory = $false)]
        [int]$MaxSizeGB = 32,
        
        [Parameter(Mandatory = $false)]
        [bool]$EnableGeoBackup = $false,
        
        [Parameter(Mandatory = $false)]
        [int]$BackupRetentionDays = 7,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Tags = @{}
    )
    
    try {
        # Check if database exists
        $database = Get-AzSqlDatabase -ResourceGroupName $ResourceGroupName -ServerName $ServerName -DatabaseName $DatabaseName -ErrorAction SilentlyContinue
        
        if ($null -eq $database) {
            # Create database
            Write-Log "Creating SQL Database $DatabaseName with edition $Edition and service objective $ServiceObjective..."
            
            $databaseParams = @{
                ResourceGroupName = $ResourceGroupName
                ServerName = $ServerName
                DatabaseName = $DatabaseName
                Edition = $Edition
                RequestedServiceObjectiveName = $ServiceObjective
            }
            
            # Add max size if specified
            if ($MaxSizeGB -gt 0) {
                $databaseParams.MaxSizeBytes = $MaxSizeGB * 1024 * 1024 * 1024
            }
            
            # Add geo-backup if specified
            if ($EnableGeoBackup) {
                $databaseParams.GeoBackupEnabled = $true
            }
            
            # Add backup retention if specified
            if ($BackupRetentionDays -gt 0) {
                $databaseParams.BackupRetentionDays = $BackupRetentionDays
            }
            
            # Add tags if specified
            if ($Tags.Count -gt 0) {
                $databaseParams.Tag = $Tags
            }
            
            $database = New-AzSqlDatabase @databaseParams
            Write-Log "SQL Database $DatabaseName created successfully"
        }
        else {
            Write-Log "SQL Database $DatabaseName already exists"
        }
        
        return $database
    }
    catch {
        Write-Log "Error creating SQL Database: $_" -Level Error
        throw $_
    }
}

function Set-SQLDatabaseSecurity {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ResourceGroupName,
        
        [Parameter(Mandatory = $true)]
        [string]$ServerName,
        
        [Parameter(Mandatory = $true)]
        [string]$DatabaseName,
        
        [Parameter(Mandatory = $false)]
        [bool]$EnableAudit = $false,
        
        [Parameter(Mandatory = $false)]
        [int]$AuditRetentionDays = 90,
        
        [Parameter(Mandatory = $false)]
        [bool]$EnableThreatDetection = $false,
        
        [Parameter(Mandatory = $false)]
        [bool]$EnableTransparentDataEncryption = $true
    )
    
    try {
        # Enable auditing if specified
        if ($EnableAudit) {
            Write-Log "Enabling SQL Database auditing..."
            
            # Create storage account for audit logs if needed
            $storageAccountName = "sqlaudit$((New-Guid).ToString().Substring(0, 8))"
            $storageAccount = New-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $storageAccountName -Location (Get-AzResourceGroup -Name $ResourceGroupName).Location -SkuName Standard_LRS -Kind StorageV2
            
            # Enable server auditing
            Set-AzSqlServerAudit -ResourceGroupName $ResourceGroupName -ServerName $ServerName -StorageAccountResourceId $storageAccount.Id -RetentionInDays $AuditRetentionDays -BlobStorageTargetState Enabled | Out-Null
            
            # Enable database auditing
            Set-AzSqlDatabaseAudit -ResourceGroupName $ResourceGroupName -ServerName $ServerName -DatabaseName $DatabaseName -StorageAccountResourceId $storageAccount.Id -RetentionInDays $AuditRetentionDays -BlobStorageTargetState Enabled | Out-Null
            
            Write-Log "SQL Database auditing enabled successfully"
        }
        
        # Enable threat detection if specified
        if ($EnableThreatDetection) {
            Write-Log "Enabling SQL Database Advanced Threat Protection..."
            
            # Enable server threat detection
            Enable-AzSqlServerAdvancedThreatProtection -ResourceGroupName $ResourceGroupName -ServerName $ServerName | Out-Null
            
            # Enable database threat detection
            Enable-AzSqlDatabaseAdvancedThreatProtection -ResourceGroupName $ResourceGroupName -ServerName $ServerName -DatabaseName $DatabaseName | Out-Null
            
            Write-Log "SQL Database Advanced Threat Protection enabled successfully"
        }
        
        # Enable transparent data encryption if specified
        if ($EnableTransparentDataEncryption) {
            Write-Log "Enabling SQL Database Transparent Data Encryption..."
            
            Set-AzSqlDatabaseTransparentDataEncryption -ResourceGroupName $ResourceGroupName -ServerName $ServerName -DatabaseName $DatabaseName -State Enabled | Out-Null
            
            Write-Log "SQL Database Transparent Data Encryption enabled successfully"
        }
        
        return $true
    }
    catch {
        Write-Log "Error configuring SQL Database security: $_" -Level Error
        return $false
    }
}
#endregion

#region Main Script
try {
    # Script start
    Write-Log "Script started with parameters: ResourceGroupName=$ResourceGroupName, ServerName=$ServerName, DatabaseName=$DatabaseName, Edition=$Edition"
    
    # Connect to Azure
    $connectedToAzure = Connect-ToAzure
    if (-not $connectedToAzure) {
        Write-Log "Cannot proceed without Azure connection" -Level Error
        exit 1
    }
    
    # Create resource group if not exists
    $resourceGroup = New-ResourceGroupIfNotExists -ResourceGroupName $ResourceGroupName -Location $Location
    
    # Create SQL Server
    $server = New-SQLServer -ResourceGroupName $ResourceGroupName -Location $Location -ServerName $ServerName -AdminUsername $AdminUsername -AdminPassword $AdminPassword -Tags $Tags
    
    # Configure SQL Server firewall rules
    $firewallResult = Set-SQLServerFirewallRules -ResourceGroupName $ResourceGroupName -ServerName $ServerName -AllowAzureIPs $AllowAzureIPs -AllowedIPAddresses $AllowedIPAddresses
    
    if (-not $firewallResult) {
        Write-Log "Failed to configure SQL Server firewall rules" -Level Warning
    }
    
    # Create SQL Database
    $database = New-SQLDatabase -ResourceGroupName $ResourceGroupName -ServerName $ServerName -DatabaseName $DatabaseName -Edition $Edition -ServiceObjective $ServiceObjective -MaxSizeGB $MaxSizeGB -EnableGeoBackup $EnableGeoBackup -BackupRetentionDays $BackupRetentionDays -Tags $Tags
    
    # Configure SQL Database security
    $securityResult = Set-SQLDatabaseSecurity -ResourceGroupName $ResourceGroupName -ServerName $ServerName -DatabaseName $DatabaseName -EnableAudit $EnableAudit -AuditRetentionDays $AuditRetentionDays -EnableThreatDetection $EnableThreatDetection -EnableTransparentDataEncryption $EnableTransparentDataEncryption
    
    if (-not $securityResult) {
        Write-Log "Failed to configure SQL Database security" -Level Warning
    }
    
    # Get connection string
    $connectionString = "Server=tcp:$ServerName.database.windows.net,1433;Initial Catalog=$DatabaseName;Persist Security Info=False;User ID=$AdminUsername;Password=$AdminPassword;MultipleActiveResultSets=False;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;"
    
    # Output success message
    Write-Output "SQL Server $ServerName and Database $DatabaseName created successfully in resource group $ResourceGroupName"
    Write-Output "Server FQDN: $ServerName.database.windows.net"
    Write-Output "Database Edition: $Edition"
    Write-Output "Service Objective: $ServiceObjective"
    Write-Output "Max Size: $MaxSizeGB GB"
    
    if ($EnableGeoBackup) {
        Write-Output "Geo-Backup: Enabled"
        Write-Output "Backup Retention: $BackupRetentionDays days"
    }
    
    if ($EnableAudit) {
        Write-Output "Auditing: Enabled"
        Write-Output "Audit Retention: $AuditRetentionDays days"
    }
    
    if ($EnableThreatDetection) {
        Write-Output "Advanced Threat Protection: Enabled"
    }
    
    if ($EnableTransparentDataEncryption) {
        Write-Output "Transparent Data Encryption: Enabled"
    }
    
    Write-Output "Connection String: $connectionString"
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
