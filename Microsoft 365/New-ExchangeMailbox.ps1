<#
.SYNOPSIS
    Creates a new Exchange Online mailbox.

.DESCRIPTION
    This script creates a new Exchange Online mailbox with specified parameters
    including display name, email address, mailbox type, and various mailbox settings.
    It supports creating user mailboxes, shared mailboxes, and resource mailboxes.

.PARAMETER DisplayName
    The display name for the new mailbox.

.PARAMETER EmailAddress
    The primary email address for the new mailbox.

.PARAMETER MailboxType
    The type of mailbox to create (UserMailbox, SharedMailbox, RoomMailbox, EquipmentMailbox).

.PARAMETER Password
    The password for the user mailbox. Required for UserMailbox type.

.PARAMETER FirstName
    The first name for the user mailbox.

.PARAMETER LastName
    The last name for the user mailbox.

.PARAMETER Department
    The department for the user mailbox.

.PARAMETER Location
    The location for the user or resource mailbox.

.PARAMETER Capacity
    The capacity for room mailboxes.

.PARAMETER AutoAccept
    Whether to automatically accept meeting requests for resource mailboxes.

.PARAMETER HiddenFromAddressList
    Whether to hide the mailbox from the address list.

.PARAMETER ForwardingAddress
    The email address to forward messages to.

.PARAMETER LogPath
    Path where logs will be stored. Defaults to Windows log directory.

.EXAMPLE
    .\New-ExchangeMailbox.ps1 -DisplayName "John Doe" -EmailAddress "john.doe@contoso.com" -MailboxType "UserMailbox" -Password "P@ssw0rd123" -FirstName "John" -LastName "Doe" -Department "IT"
    Creates a new user mailbox for John Doe in the IT department.

.EXAMPLE
    .\New-ExchangeMailbox.ps1 -DisplayName "IT Support" -EmailAddress "itsupport@contoso.com" -MailboxType "SharedMailbox"
    Creates a new shared mailbox for IT Support.

.NOTES
    Author: Michael Witzsche
    Date: April 26, 2025
    Version: 1.1
#>

#Requires -Modules ExchangeOnlineManagement

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$LogPath = "$env:SystemRoot\Logs\New-ExchangeMailbox",
    
    [Parameter(Mandatory = $true)]
    [string]$DisplayName,
    
    [Parameter(Mandatory = $true)]
    [string]$EmailAddress,
    
    [Parameter(Mandatory = $true)]
    [ValidateSet("UserMailbox", "SharedMailbox", "RoomMailbox", "EquipmentMailbox")]
    [string]$MailboxType,
    
    [Parameter(Mandatory = $false)]
    [string]$Password = "",
    
    [Parameter(Mandatory = $false)]
    [string]$FirstName = "",
    
    [Parameter(Mandatory = $false)]
    [string]$LastName = "",
    
    [Parameter(Mandatory = $false)]
    [string]$Department = "",
    
    [Parameter(Mandatory = $false)]
    [string]$Location = "",
    
    [Parameter(Mandatory = $false)]
    [int]$Capacity = 0,
    
    [Parameter(Mandatory = $false)]
    [bool]$AutoAccept = $true,
    
    [Parameter(Mandatory = $false)]
    [bool]$HiddenFromAddressList = $false,
    
    [Parameter(Mandatory = $false)]
    [string]$ForwardingAddress = ""
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

function Connect-ToExchangeOnline {
    [CmdletBinding()]
    param()
    
    try {
        # Check if already connected
        try {
            $mailbox = Get-EXOMailbox -ResultSize 1 -ErrorAction Stop
            Write-Log "Already connected to Exchange Online"
            return $true
        }
        catch {
            # Not connected, proceed with connection
        }
        
        # Connect to Exchange Online
        Write-Log "Connecting to Exchange Online..."
        Connect-ExchangeOnline -ErrorAction Stop
        
        # Verify connection
        try {
            $mailbox = Get-EXOMailbox -ResultSize 1 -ErrorAction Stop
            Write-Log "Successfully connected to Exchange Online"
            return $true
        }
        catch {
            Write-Log "Failed to verify Exchange Online connection" -Level Error
            return $false
        }
    }
    catch {
        Write-Log "Error connecting to Exchange Online: $_" -Level Error
        return $false
    }
}
#endregion

#region Main Script
try {
    # Script start
    Write-Log "Script started with parameters: DisplayName=$DisplayName, EmailAddress=$EmailAddress, MailboxType=$MailboxType"
    
    # Validate parameters
    if ($MailboxType -eq "UserMailbox" -and [string]::IsNullOrEmpty($Password)) {
        Write-Log "Password is required for user mailboxes" -Level Error
        exit 1
    }
    
    # Connect to Exchange Online
    $connectedToExchange = Connect-ToExchangeOnline
    if (-not $connectedToExchange) {
        Write-Log "Cannot proceed without Exchange Online connection" -Level Error
        exit 1
    }
    
    # Check if mailbox already exists
    Write-Log "Checking if mailbox $EmailAddress already exists..."
    try {
        $existingMailbox = Get-EXOMailbox -Identity $EmailAddress -ErrorAction SilentlyContinue
        if ($null -ne $existingMailbox) {
            Write-Log "Mailbox $EmailAddress already exists. Cannot create duplicate mailbox." -Level Error
            exit 1
        }
    }
    catch {
        # Mailbox doesn't exist, which is what we want
        Write-Log "Mailbox does not exist, proceeding with creation"
    }
    
    # Create the mailbox based on type
    try {
        switch ($MailboxType) {
            "UserMailbox" {
                Write-Log "Creating new user mailbox for $DisplayName..."
                
                # Create secure password
                $securePassword = ConvertTo-SecureString -String $Password -AsPlainText -Force
                
                # Create user parameters
                $userParams = @{
                    Name = $DisplayName
                    DisplayName = $DisplayName
                    PrimarySmtpAddress = $EmailAddress
                    Password = $securePassword
                    ResetPasswordOnNextLogon = $true
                }
                
                # Add optional parameters if specified
                if (-not [string]::IsNullOrEmpty($FirstName)) {
                    $userParams.FirstName = $FirstName
                }
                
                if (-not [string]::IsNullOrEmpty($LastName)) {
                    $userParams.LastName = $LastName
                }
                
                if (-not [string]::IsNullOrEmpty($Department)) {
                    $userParams.Department = $Department
                }
                
                if (-not [string]::IsNullOrEmpty($Location)) {
                    $userParams.Office = $Location
                }
                
                # Create the user mailbox
                $newMailbox = New-Mailbox @userParams
                Write-Log "User mailbox created successfully"
            }
            "SharedMailbox" {
                Write-Log "Creating new shared mailbox for $DisplayName..."
                
                # Create the shared mailbox
                $newMailbox = New-Mailbox -Shared -Name $DisplayName -DisplayName $DisplayName -PrimarySmtpAddress $EmailAddress
                Write-Log "Shared mailbox created successfully"
            }
            "RoomMailbox" {
                Write-Log "Creating new room mailbox for $DisplayName..."
                
                # Create the room mailbox
                $newMailbox = New-Mailbox -Room -Name $DisplayName -DisplayName $DisplayName -PrimarySmtpAddress $EmailAddress
                Write-Log "Room mailbox created successfully"
                
                # Configure room mailbox settings
                if (-not [string]::IsNullOrEmpty($Location)) {
                    Set-Mailbox -Identity $EmailAddress -Office $Location
                    Write-Log "Room location set to $Location"
                }
                
                if ($Capacity -gt 0) {
                    Set-Mailbox -Identity $EmailAddress -ResourceCapacity $Capacity
                    Write-Log "Room capacity set to $Capacity"
                }
                
                # Configure calendar processing
                Set-CalendarProcessing -Identity $EmailAddress -AutomateProcessing $AutoAccept ? "AutoAccept" : "AutoUpdate"
                Write-Log "Calendar processing configured"
            }
            "EquipmentMailbox" {
                Write-Log "Creating new equipment mailbox for $DisplayName..."
                
                # Create the equipment mailbox
                $newMailbox = New-Mailbox -Equipment -Name $DisplayName -DisplayName $DisplayName -PrimarySmtpAddress $EmailAddress
                Write-Log "Equipment mailbox created successfully"
                
                # Configure calendar processing
                Set-CalendarProcessing -Identity $EmailAddress -AutomateProcessing $AutoAccept ? "AutoAccept" : "AutoUpdate"
                Write-Log "Calendar processing configured"
            }
        }
        
        # Configure additional mailbox settings
        Write-Log "Configuring additional mailbox settings..."
        
        # Set hidden from address list if specified
        if ($HiddenFromAddressList) {
            Set-Mailbox -Identity $EmailAddress -HiddenFromAddressListsEnabled $true
            Write-Log "Mailbox hidden from address list"
        }
        
        # Set forwarding address if specified
        if (-not [string]::IsNullOrEmpty($ForwardingAddress)) {
            Set-Mailbox -Identity $EmailAddress -ForwardingAddress $ForwardingAddress -DeliverToMailboxAndForward $true
            Write-Log "Forwarding configured to $ForwardingAddress"
        }
        
        # Output mailbox details
        Write-Output "Mailbox created successfully:"
        Write-Output "  Display Name: $DisplayName"
        Write-Output "  Email Address: $EmailAddress"
        Write-Output "  Mailbox Type: $MailboxType"
        
        if ($MailboxType -eq "UserMailbox") {
            if (-not [string]::IsNullOrEmpty($FirstName) -and -not [string]::IsNullOrEmpty($LastName)) {
                Write-Output "  Name: $FirstName $LastName"
            }
            if (-not [string]::IsNullOrEmpty($Department)) {
                Write-Output "  Department: $Department"
            }
        }
        
        if ($MailboxType -eq "RoomMailbox" -and $Capacity -gt 0) {
            Write-Output "  Capacity: $Capacity"
        }
        
        if (-not [string]::IsNullOrEmpty($Location)) {
            Write-Output "  Location: $Location"
        }
        
        if ($HiddenFromAddressList) {
            Write-Output "  Hidden from Address List: Yes"
        }
        
        if (-not [string]::IsNullOrEmpty($ForwardingAddress)) {
            Write-Output "  Forwarding to: $ForwardingAddress"
        }
        
        return $newMailbox
    }
    catch {
        Write-Log "Failed to create mailbox: $_" -Level Error
        throw $_
    }
}
catch {
    Write-Log "Script execution failed: $_" -Level Error
    exit 1
}
finally {
    # Disconnect from Exchange Online
    try {
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
    }
    catch {
        # Ignore disconnection errors
    }
    
    Write-Log "Script execution completed"
}
#endregion
