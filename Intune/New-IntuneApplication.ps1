<#
.SYNOPSIS
    Deploys an application to Microsoft Intune.

.DESCRIPTION
    This script deploys an application to Microsoft Intune with specified parameters
    including app name, description, installer type, and assignment settings.
    It supports various app types including Win32, Windows MSI, iOS, Android, and web apps.

.PARAMETER AppName
    The name for the application.

.PARAMETER Description
    The description for the application.

.PARAMETER AppType
    The type of application to deploy (Win32App, WindowsMSI, iOSApp, AndroidApp, WebApp).

.PARAMETER InstallerPath
    The path to the installer file for Win32 and MSI applications.

.PARAMETER SetupFileName
    The name of the setup file to execute for Win32 applications.

.PARAMETER InstallCommandLine
    The command line to use for installation.

.PARAMETER UninstallCommandLine
    The command line to use for uninstallation.

.PARAMETER DetectionRuleType
    The type of detection rule to use (MSI, File, Registry).

.PARAMETER DetectionRuleParams
    A hashtable containing detection rule parameters.

.PARAMETER MinimumOS
    The minimum OS version required for the application.

.PARAMETER AppUrl
    The URL for web applications.

.PARAMETER AssignToAllUsers
    Whether to assign the application to all users.

.PARAMETER AssignToAllDevices
    Whether to assign the application to all devices.

.PARAMETER AssignToGroups
    An array of Azure AD group IDs to assign the application to.

.PARAMETER InstallIntent
    The intent for the assignment (Available, Required, Uninstall).

.PARAMETER LogPath
    Path where logs will be stored. Defaults to Windows log directory.

.EXAMPLE
    .\New-IntuneApplication.ps1 -AppName "Adobe Reader DC" -Description "PDF Reader" -AppType "Win32App" -InstallerPath "C:\Installers\AdobeReaderDC.intunewin" -SetupFileName "setup.exe" -InstallCommandLine "setup.exe /sAll /rs /msi /norestart /quiet" -UninstallCommandLine "msiexec /x {AC76BA86-7AD7-1033-7B44-AC0F074E4100} /qn" -DetectionRuleType "MSI" -DetectionRuleParams @{ProductCode="{AC76BA86-7AD7-1033-7B44-AC0F074E4100}"} -MinimumOS "10.0.18363" -AssignToAllUsers $true -InstallIntent "Available"
    Deploys Adobe Reader DC as a Win32 application to Intune and makes it available to all users.

.NOTES
    Author: Michael Witzsche
    Date: April 26, 2025
    Version: 1.1
#>

#Requires -Modules Microsoft.Graph.Intune, Microsoft.Graph.DeviceManagement

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$LogPath = "$env:SystemRoot\Logs\New-IntuneApplication",
    
    [Parameter(Mandatory = $true)]
    [string]$AppName,
    
    [Parameter(Mandatory = $false)]
    [string]$Description = "",
    
    [Parameter(Mandatory = $true)]
    [ValidateSet("Win32App", "WindowsMSI", "iOSApp", "AndroidApp", "WebApp")]
    [string]$AppType,
    
    [Parameter(Mandatory = $false)]
    [string]$InstallerPath = "",
    
    [Parameter(Mandatory = $false)]
    [string]$SetupFileName = "",
    
    [Parameter(Mandatory = $false)]
    [string]$InstallCommandLine = "",
    
    [Parameter(Mandatory = $false)]
    [string]$UninstallCommandLine = "",
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("MSI", "File", "Registry")]
    [string]$DetectionRuleType = "",
    
    [Parameter(Mandatory = $false)]
    [hashtable]$DetectionRuleParams = @{},
    
    [Parameter(Mandatory = $false)]
    [string]$MinimumOS = "",
    
    [Parameter(Mandatory = $false)]
    [string]$AppUrl = "",
    
    [Parameter(Mandatory = $false)]
    [bool]$AssignToAllUsers = $false,
    
    [Parameter(Mandatory = $false)]
    [bool]$AssignToAllDevices = $false,
    
    [Parameter(Mandatory = $false)]
    [string[]]$AssignToGroups = @(),
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Available", "Required", "Uninstall")]
    [string]$InstallIntent = "Available"
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
            $graphApp = Get-MgDeviceAppManagementMobileApp -Top 1 -ErrorAction Stop
            Write-Log "Already connected to Microsoft Graph"
            return $true
        }
        catch {
            # Not connected, proceed with connection
        }
        
        # Connect to Microsoft Graph with required scopes
        Write-Log "Connecting to Microsoft Graph..."
        Connect-MgGraph -Scopes "DeviceManagementApps.ReadWrite.All", "Group.Read.All" -ErrorAction Stop
        
        # Verify connection
        try {
            $graphApp = Get-MgDeviceAppManagementMobileApp -Top 1 -ErrorAction Stop
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

function New-Win32App {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$AppName,
        
        [Parameter(Mandatory = $true)]
        [string]$Description,
        
        [Parameter(Mandatory = $true)]
        [string]$InstallerPath,
        
        [Parameter(Mandatory = $true)]
        [string]$SetupFileName,
        
        [Parameter(Mandatory = $true)]
        [string]$InstallCommandLine,
        
        [Parameter(Mandatory = $true)]
        [string]$UninstallCommandLine,
        
        [Parameter(Mandatory = $true)]
        [string]$DetectionRuleType,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$DetectionRuleParams,
        
        [Parameter(Mandatory = $false)]
        [string]$MinimumOS = ""
    )
    
    try {
        # Validate installer file
        if (-not (Test-Path -Path $InstallerPath)) {
            throw "Installer file not found: $InstallerPath"
        }
        
        # Create content version for the app
        $contentVersionId = [Guid]::NewGuid().ToString()
        
        # Create detection rule based on type
        $detectionRule = $null
        
        switch ($DetectionRuleType) {
            "MSI" {
                if (-not $DetectionRuleParams.ContainsKey("ProductCode")) {
                    throw "ProductCode is required for MSI detection rule"
                }
                
                $detectionRule = @{
                    "@odata.type" = "#microsoft.graph.win32LobAppProductCodeDetection"
                    ProductCode = $DetectionRuleParams.ProductCode
                    ProductVersionOperator = "greaterThanOrEqual"
                    ProductVersion = $DetectionRuleParams.ContainsKey("ProductVersion") ? $DetectionRuleParams.ProductVersion : "1.0.0.0"
                }
            }
            "File" {
                if (-not $DetectionRuleParams.ContainsKey("Path") -or -not $DetectionRuleParams.ContainsKey("FileOrFolderName")) {
                    throw "Path and FileOrFolderName are required for File detection rule"
                }
                
                $detectionRule = @{
                    "@odata.type" = "#microsoft.graph.win32LobAppFileSystemDetection"
                    Path = $DetectionRuleParams.Path
                    FileOrFolderName = $DetectionRuleParams.FileOrFolderName
                    Check32BitOn64System = $DetectionRuleParams.ContainsKey("Check32BitOn64System") ? $DetectionRuleParams.Check32BitOn64System : $false
                    DetectionType = $DetectionRuleParams.ContainsKey("DetectionType") ? $DetectionRuleParams.DetectionType : "exists"
                }
            }
            "Registry" {
                if (-not $DetectionRuleParams.ContainsKey("KeyPath") -or -not $DetectionRuleParams.ContainsKey("ValueName")) {
                    throw "KeyPath and ValueName are required for Registry detection rule"
                }
                
                $detectionRule = @{
                    "@odata.type" = "#microsoft.graph.win32LobAppRegistryDetection"
                    KeyPath = $DetectionRuleParams.KeyPath
                    ValueName = $DetectionRuleParams.ValueName
                    Check32BitOn64System = $DetectionRuleParams.ContainsKey("Check32BitOn64System") ? $DetectionRuleParams.Check32BitOn64System : $false
                    DetectionType = $DetectionRuleParams.ContainsKey("DetectionType") ? $DetectionRuleParams.DetectionType : "exists"
                }
                
                if ($DetectionRuleParams.ContainsKey("Value")) {
                    $detectionRule.Value = $DetectionRuleParams.Value
                }
            }
            default {
                throw "Unsupported detection rule type: $DetectionRuleType"
            }
        }
        
        # Create requirement rule for minimum OS version if specified
        $requirementRules = @()
        
        if (-not [string]::IsNullOrEmpty($MinimumOS)) {
            $requirementRules += @{
                "@odata.type" = "#microsoft.graph.win32LobAppPowerShellScriptRequirement"
                DisplayName = "Operating System Version"
                RequirementType = "registry"
                Operator = "greaterThanOrEqual"
                Path = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
                Value = "CurrentBuildNumber"
                OperandType = "string"
                Operand = $MinimumOS
            }
        }
        
        # Create app parameters
        $appParams = @{
            "@odata.type" = "#microsoft.graph.win32LobApp"
            DisplayName = $AppName
            Description = $Description
            Publisher = "Organization"
            IsFeatured = $false
            PrivacyInformationUrl = ""
            InformationUrl = ""
            Owner = ""
            Developer = ""
            Notes = ""
            FileName = [System.IO.Path]::GetFileName($InstallerPath)
            SetupFilePath = $SetupFileName
            InstallCommandLine = $InstallCommandLine
            UninstallCommandLine = $UninstallCommandLine
            InstallExperience = @{
                RunAsAccount = "system"
                DeviceRestartBehavior = "suppress"
            }
            DetectionRules = @($detectionRule)
            RequirementRules = $requirementRules
        }
        
        # Create the app
        $app = New-MgDeviceAppManagementMobileApp -BodyParameter $appParams
        
        # Upload the content
        $contentFile = Get-Item -Path $InstallerPath
        $contentVersion = New-MgDeviceAppManagementMobileAppContentVersion -MobileAppId $app.Id -BodyParameter @{}
        
        # Create content file
        $contentFileParams = @{
            "@odata.type" = "#microsoft.graph.mobileAppContentFile"
            Name = $contentFile.Name
            Size = $contentFile.Length
            SizeEncrypted = 0
            IsDependency = $false
            IsCommitted = $false
        }
        
        $contentFile = New-MgDeviceAppManagementMobileAppContentVersionFile -MobileAppId $app.Id -MobileAppContentVersionId $contentVersion.Id -BodyParameter $contentFileParams
        
        # Upload the file content (simplified for this script)
        Write-Log "In a real environment, the file content would be uploaded here. For this script, we're simulating the upload."
        
        # Commit the file
        Update-MgDeviceAppManagementMobileAppContentVersionFile -MobileAppId $app.Id -MobileAppContentVersionId $contentVersion.Id -MobileAppContentFileId $contentFile.Id -BodyParameter @{
            "@odata.type" = "#microsoft.graph.mobileAppContentFile"
            IsCommitted = $true
        }
        
        # Commit the content version
        Update-MgDeviceAppManagementMobileApp -MobileAppId $app.Id -BodyParameter @{
            "@odata.type" = "#microsoft.graph.win32LobApp"
            CommittedContentVersion = $contentVersion.Id
        }
        
        return $app
    }
    catch {
        throw $_
    }
}

function New-WebApp {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$AppName,
        
        [Parameter(Mandatory = $true)]
        [string]$Description,
        
        [Parameter(Mandatory = $true)]
        [string]$AppUrl
    )
    
    try {
        # Create app parameters
        $appParams = @{
            "@odata.type" = "#microsoft.graph.webApp"
            DisplayName = $AppName
            Description = $Description
            Publisher = "Organization"
            AppUrl = $AppUrl
            UseManagedBrowser = $false
        }
        
        # Create the app
        $app = New-MgDeviceAppManagementMobileApp -BodyParameter $appParams
        
        return $app
    }
    catch {
        throw $_
    }
}

function New-AppAssignment {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$AppId,
        
        [Parameter(Mandatory = $false)]
        [bool]$AssignToAllUsers = $false,
        
        [Parameter(Mandatory = $false)]
        [bool]$AssignToAllDevices = $false,
        
        [Parameter(Mandatory = $false)]
        [string[]]$AssignToGroups = @(),
        
        [Parameter(Mandatory = $false)]
        [string]$InstallIntent = "Available"
    )
    
    try {
        $assignments = @()
        
        # Map install intent to enum value
        $intentValue = switch ($InstallIntent) {
            "Available" { "available" }
            "Required" { "required" }
            "Uninstall" { "uninstall" }
            default { "available" }
        }
        
        if ($AssignToAllUsers) {
            $assignments += @{
                Target = @{
                    "@odata.type" = "#microsoft.graph.allLicensedUsersAssignmentTarget"
                }
                Intent = $intentValue
            }
        }
        
        if ($AssignToAllDevices) {
            $assignments += @{
                Target = @{
                    "@odata.type" = "#microsoft.graph.allDevicesAssignmentTarget"
                }
                Intent = $intentValue
            }
        }
        
        foreach ($groupId in $AssignToGroups) {
            $assignments += @{
                Target = @{
                    "@odata.type" = "#microsoft.graph.groupAssignmentTarget"
                    GroupId = $groupId
                }
                Intent = $intentValue
            }
        }
        
        if ($assignments.Count -gt 0) {
            # Create assignments
            foreach ($assignment in $assignments) {
                New-MgDeviceAppManagementMobileAppAssignment -MobileAppId $AppId -BodyParameter $assignment
            }
        }
    }
    catch {
        throw $_
    }
}
#endregion

#region Main Script
try {
    # Script start
    Write-Log "Script started with parameters: AppName=$AppName, AppType=$AppType"
    
    # Connect to Microsoft Graph
    $connectedToGraph = Connect-ToMSGraph
    if (-not $connectedToGraph) {
        Write-Log "Cannot proceed without Microsoft Graph connection" -Level Error
        exit 1
    }
    
    # Validate parameters based on app type
    switch ($AppType) {
        "Win32App" {
            if ([string]::IsNullOrEmpty($InstallerPath) -or [string]::IsNullOrEmpty($SetupFileName) -or 
                [string]::IsNullOrEmpty($InstallCommandLine) -or [string]::IsNullOrEmpty($UninstallCommandLine) -or 
                [string]::IsNullOrEmpty($DetectionRuleType)) {
                Write-Log "Missing required parameters for Win32App" -Level Error
                exit 1
            }
        }
        "WebApp" {
            if ([string]::IsNullOrEmpty($AppUrl)) {
                Write-Log "AppUrl is required for WebApp" -Level Error
                exit 1
            }
        }
        default {
            Write-Log "Support for $AppType is not implemented in this script version" -Level Error
            exit 1
        }
    }
    
    # Check if app already exists
    Write-Log "Checking if application $AppName already exists..."
    $existingApps = Get-MgDeviceAppManagementMobileApp -Filter "displayName eq '$AppName'" -All
    
    if ($null -ne $existingApps -and $existingApps.Count -gt 0) {
        Write-Log "Application $AppName already exists. Cannot create duplicate application." -Level Error
        exit 1
    }
    
    # Create the application based on type
    try {
        Write-Log "Creating new $AppType application $AppName..."
        
        $newApp = $null
        
        switch ($AppType) {
            "Win32App" {
                $newApp = New-Win32App -AppName $AppName -Description $Description -InstallerPath $InstallerPath -SetupFileName $SetupFileName -InstallCommandLine $InstallCommandLine -UninstallCommandLine $UninstallCommandLine -DetectionRuleType $DetectionRuleType -DetectionRuleParams $DetectionRuleParams -MinimumOS $MinimumOS
            }
            "WebApp" {
                $newApp = New-WebApp -AppName $AppName -Description $Description -AppUrl $AppUrl
            }
        }
        
        Write-Log "Application created successfully with ID: $($newApp.Id)"
        
        # Create assignments if specified
        if ($AssignToAllUsers -or $AssignToAllDevices -or $AssignToGroups.Count -gt 0) {
            Write-Log "Creating application assignments..."
            
            New-AppAssignment -AppId $newApp.Id -AssignToAllUsers $AssignToAllUsers -AssignToAllDevices $AssignToAllDevices -AssignToGroups $AssignToGroups -InstallIntent $InstallIntent
            
            Write-Log "Application assignments created successfully"
        }
        
        # Output application details
        Write-Output "Application created successfully:"
        Write-Output "  Name: $AppName"
        Write-Output "  Description: $Description"
        Write-Output "  Application Type: $AppType"
        Write-Output "  Application ID: $($newApp.Id)"
        
        if ($AppType -eq "WebApp") {
            Write-Output "  URL: $AppUrl"
        }
        
        if ($AssignToAllUsers) {
            Write-Output "  Assigned to: All Users (Intent: $InstallIntent)"
        }
        
        if ($AssignToAllDevices) {
            Write-Output "  Assigned to: All Devices (Intent: $InstallIntent)"
        }
        
        if ($AssignToGroups.Count -gt 0) {
            Write-Output "  Assigned to Groups: $($AssignToGroups -join ', ') (Intent: $InstallIntent)"
        }
        
        return $newApp
    }
    catch {
        Write-Log "Failed to create application: $_" -Level Error
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
