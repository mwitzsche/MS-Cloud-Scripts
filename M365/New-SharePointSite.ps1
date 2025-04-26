<#
.SYNOPSIS
    Creates a new SharePoint Online site.

.DESCRIPTION
    This script creates a new SharePoint Online site with specified parameters
    including site title, URL, template, time zone, and owner.
    It supports creating both team sites and communication sites.

.PARAMETER SiteTitle
    The title for the new SharePoint site.

.PARAMETER SiteUrl
    The relative URL for the new site (e.g., "sites/Marketing").

.PARAMETER SiteTemplate
    The template to use for the new site (TeamSite or CommunicationSite).

.PARAMETER Description
    The description for the new site.

.PARAMETER TimeZoneId
    The time zone ID for the site. Default is 13 (Eastern Time).

.PARAMETER Owner
    The user principal name of the site owner.

.PARAMETER SharingCapability
    The external sharing capability for the site (Disabled, ExternalUserSharingOnly, ExternalUserAndGuestSharing, ExistingExternalUserSharingOnly).

.PARAMETER StorageQuota
    The storage quota for the site in MB.

.PARAMETER ResourceQuota
    The resource quota for the site.

.PARAMETER HubSiteUrl
    The URL of the hub site to associate this site with.

.PARAMETER LogPath
    Path where logs will be stored. Defaults to Windows log directory.

.EXAMPLE
    .\New-SharePointSite.ps1 -SiteTitle "Marketing Team" -SiteUrl "sites/Marketing" -SiteTemplate "TeamSite" -Description "Site for Marketing department" -Owner "admin@contoso.com" -SharingCapability "ExternalUserAndGuestSharing"
    Creates a new team site for the Marketing department with the specified settings.

.NOTES
    Author: Michael Witzsche
    Date: April 26, 2025
    Version: 1.1
#>

#Requires -Modules PnP.PowerShell, Microsoft.Online.SharePoint.PowerShell

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$LogPath = "$env:SystemRoot\Logs\New-SharePointSite",
    
    [Parameter(Mandatory = $true)]
    [string]$SiteTitle,
    
    [Parameter(Mandatory = $true)]
    [string]$SiteUrl,
    
    [Parameter(Mandatory = $true)]
    [ValidateSet("TeamSite", "CommunicationSite")]
    [string]$SiteTemplate,
    
    [Parameter(Mandatory = $false)]
    [string]$Description = "",
    
    [Parameter(Mandatory = $false)]
    [int]$TimeZoneId = 13,
    
    [Parameter(Mandatory = $true)]
    [string]$Owner,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Disabled", "ExternalUserSharingOnly", "ExternalUserAndGuestSharing", "ExistingExternalUserSharingOnly")]
    [string]$SharingCapability = "ExternalUserAndGuestSharing",
    
    [Parameter(Mandatory = $false)]
    [int]$StorageQuota = 1024,
    
    [Parameter(Mandatory = $false)]
    [double]$ResourceQuota = 0,
    
    [Parameter(Mandatory = $false)]
    [string]$HubSiteUrl = ""
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

function Connect-ToSharePointOnline {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$AdminUrl
    )
    
    try {
        # Check if already connected to PnP
        try {
            $site = Get-PnPTenantSite -Limit 1 -ErrorAction Stop
            Write-Log "Already connected to SharePoint Online with PnP"
            return $true
        }
        catch {
            # Not connected, proceed with connection
        }
        
        # Connect to SharePoint Online with PnP
        Write-Log "Connecting to SharePoint Online with PnP..."
        Connect-PnPOnline -Url $AdminUrl -Interactive -ErrorAction Stop
        
        # Verify connection
        try {
            $site = Get-PnPTenantSite -Limit 1 -ErrorAction Stop
            Write-Log "Successfully connected to SharePoint Online with PnP"
            return $true
        }
        catch {
            Write-Log "Failed to verify SharePoint Online connection with PnP" -Level Error
            return $false
        }
    }
    catch {
        Write-Log "Error connecting to SharePoint Online with PnP: $_" -Level Error
        return $false
    }
}
#endregion

#region Main Script
try {
    # Script start
    Write-Log "Script started with parameters: SiteTitle=$SiteTitle, SiteUrl=$SiteUrl, SiteTemplate=$SiteTemplate"
    
    # Extract tenant name from owner's email
    $tenantName = ($Owner -split '@')[1].Split('.')[0]
    $adminUrl = "https://$tenantName-admin.sharepoint.com"
    
    # Connect to SharePoint Online
    $connectedToSharePoint = Connect-ToSharePointOnline -AdminUrl $adminUrl
    if (-not $connectedToSharePoint) {
        Write-Log "Cannot proceed without SharePoint Online connection" -Level Error
        exit 1
    }
    
    # Check if site already exists
    Write-Log "Checking if site $SiteUrl already exists..."
    try {
        $fullSiteUrl = "https://$tenantName.sharepoint.com/$SiteUrl"
        $existingSite = Get-PnPTenantSite -Url $fullSiteUrl -ErrorAction SilentlyContinue
        
        if ($null -ne $existingSite) {
            Write-Log "Site $fullSiteUrl already exists. Cannot create duplicate site." -Level Error
            exit 1
        }
    }
    catch {
        # Site doesn't exist, which is what we want
        Write-Log "Site does not exist, proceeding with creation"
    }
    
    # Create the site
    try {
        Write-Log "Creating new SharePoint site $SiteTitle at $SiteUrl..."
        
        if ($SiteTemplate -eq "TeamSite") {
            # Create team site
            $newSite = New-PnPTenantSite `
                -Title $SiteTitle `
                -Url $fullSiteUrl `
                -Owner $Owner `
                -TimeZone $TimeZoneId `
                -Template "STS#3" `
                -StorageQuota $StorageQuota `
                -ResourceQuota $ResourceQuota `
                -Wait
            
            Write-Log "Team site created successfully"
        }
        else {
            # Create communication site
            $newSite = New-PnPSite `
                -Type CommunicationSite `
                -Title $SiteTitle `
                -Url $fullSiteUrl `
                -Description $Description `
                -Owner $Owner
            
            Write-Log "Communication site created successfully"
        }
        
        # Wait for site to be fully provisioned
        Write-Log "Waiting for site to be fully provisioned..."
        Start-Sleep -Seconds 30
        
        # Set site description if not already set
        if ($SiteTemplate -eq "TeamSite" -and -not [string]::IsNullOrEmpty($Description)) {
            Write-Log "Setting site description..."
            
            try {
                Connect-PnPOnline -Url $fullSiteUrl -Interactive -ErrorAction Stop
                Set-PnPWeb -Description $Description -ErrorAction Stop
                Write-Log "Site description set successfully"
            }
            catch {
                Write-Log "Failed to set site description: $_" -Level Warning
            }
        }
        
        # Set sharing capability
        Write-Log "Setting sharing capability to $SharingCapability..."
        
        try {
            Set-PnPTenantSite -Url $fullSiteUrl -SharingCapability $SharingCapability -ErrorAction Stop
            Write-Log "Sharing capability set successfully"
        }
        catch {
            Write-Log "Failed to set sharing capability: $_" -Level Warning
        }
        
        # Associate with hub site if specified
        if (-not [string]::IsNullOrEmpty($HubSiteUrl)) {
            Write-Log "Associating site with hub site $HubSiteUrl..."
            
            try {
                $hubSiteFullUrl = "https://$tenantName.sharepoint.com/$HubSiteUrl"
                $hubSite = Get-PnPHubSite -Identity $hubSiteFullUrl -ErrorAction Stop
                
                if ($null -ne $hubSite) {
                    Add-PnPHubSiteAssociation -Site $fullSiteUrl -HubSite $hubSiteFullUrl -ErrorAction Stop
                    Write-Log "Site associated with hub site successfully"
                }
                else {
                    Write-Log "Hub site $HubSiteUrl not found" -Level Warning
                }
            }
            catch {
                Write-Log "Failed to associate site with hub site: $_" -Level Warning
            }
        }
        
        # Output site details
        Write-Output "SharePoint site created successfully:"
        Write-Output "  Title: $SiteTitle"
        Write-Output "  URL: $fullSiteUrl"
        Write-Output "  Template: $SiteTemplate"
        Write-Output "  Owner: $Owner"
        Write-Output "  Sharing Capability: $SharingCapability"
        
        if (-not [string]::IsNullOrEmpty($HubSiteUrl)) {
            Write-Output "  Hub Site: $HubSiteUrl"
        }
    }
    catch {
        Write-Log "Failed to create SharePoint site: $_" -Level Error
        throw $_
    }
}
catch {
    Write-Log "Script execution failed: $_" -Level Error
    exit 1
}
finally {
    # Disconnect from SharePoint Online
    try {
        Disconnect-PnPOnline -ErrorAction SilentlyContinue
    }
    catch {
        # Ignore disconnection errors
    }
    
    Write-Log "Script execution completed"
}
#endregion
