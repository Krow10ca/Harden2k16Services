<#
.SYNOPSIS
	Harden a Windows Server 2016 Desktop Experience server
.DESCRIPTION
	This script executes several functions to harden a Windows Server 2016 Desktop Experience server. The changes made are based on the best practices
	laid out by Microsoft in their security baselines. Additional changes were incorporated from the CIS hardening guides and the Digital Boundary Group
	Hardening Windows Networks course. Yes, I know a script like this probably exists on the Internet, but where's the fun in that?
.PARAMETER MemberServer
    Specifies the server the script is running on is a Member server only.
.PARAMETER DomainController
	Specifies the server the script is running on is a Domain Controller and avoids certain changes.
.PARAMETER PrintServer
	Specifies the server the script is running on is a Print Server and avoids certain changes.
.PARAMETER Log
    Specifies that changes should be logged.
.PARAMETER LogFile
    Specifies the name of the log file. If not specified, a default name of <HOSTNAME>_HardenServices_<DATE>.log is used.
.PARAMETER Undo
    Specifies the script should undo previous changes. Requires UndoLogFile parameter.
.PARAMETER UndoLogFile
    Specifies the undo log file used to revert previous changes.
.EXAMPLE
	.\Harden2k16Services.ps1
	Shows the help screen
.EXAMPLE
	.\Harden2k16Services.ps1 -MemberServer
	Runs the script and makes changes for regular member servers
.EXAMPLE
	.\Harden2k16Services.ps1 -DomainController
	Runs the script without making changes that negatively affect Domain Controllers
.EXAMPLE
	.\Harden2k16Services.ps1 -PrintServer
	Runs the script without making changes that negatively affect Print Servers
.EXAMPLE
    .\Harden2k16Services.ps1 -MemberServer -Log
    Runs the script and makes changes for regular member servers and logs changes
.EXAMPLE
    .\Harden2k16Services.ps1 -Undo -UndoLogFile <undo_log>
    Runs the script and uses the specified undo log file to revert previous changes
.NOTES
	Script:		Harden2k16Services_v6.ps1
	Author:		Mike Daniels
	
	Changelog
        0.6     Major rewrite to remove unnecessary functions, streamlining of service disabling function.
        0.5     Added logging capability and undo method based on output log file. Refined the script to update variable names to
                be more descriptive and removed unnecessary variables in function calls.
		0.4		Made script more foolproof by requiring command line switch to make changes.
		0.3		Updated services list to remove services needed by SharePoint servers (NetTcpPortSharing, Net.Tcp Port Sharing Service)
		0.2		Address services that can only be disabled via registry.
		0.1		Initial version of the script that checks Windows services, stops them, and sets the startup type to disabled.
.LINK
	https://blogs.technet.microsoft.com/secguide/2017/05/29/guidance-on-disabling-system-services-on-windows-server-2016-with-desktop-experience/
.LINK
	https://www.cisecurity.org/cis-benchmarks/
.LINK
	https://digitalboundary.net/hardening-windows-networks.html
#>

[CmdletBinding()]

Param(
	[switch]$MemberServer = $false,
	[switch]$DomainController = $false,
	[switch]$PrintServer = $false,
    [switch]$Log = $false,
    [string]$LogFile = $env:computername + "_ServiceHardening_" + (Get-Date).ToString('dd-MM-yy') + ".log",
    [switch]$Undo = $false,
    [string]$UndoLogFile = $null
)

function Stop-RunningService {
	<#
	.SYNOPSIS
	Stop a running service
	.DESCRIPTION
	Stop a running service
	#>

    If ((Get-Service -Name $ServiceName | Select-Object Status).Status -eq "Running")
	{
		#Attempt to stop service
		Try {
			Write-Verbose "Stopping service $ServiceName."
			Stop-Service -Name $ServiceName -ErrorAction Stop
		}
		Catch {
			Write-Verbose "Could not stop service $ServiceName."
		}
	}
	Else
	{
		Write-Verbose "$ServiceName was already stopped."
	}
}

function Set-ServiceStartType {
	<#
	.SYNOPSIS
	Set service startup state via registry
	.DESCRIPTION
	Set service startup state to specified value via registry; not all services can set startup type using Set-Service
    .PARAMETER StartType
    Start type for service (boot, system, automatic, manual, disabled)
	#>
	
	Param(
        [string]$StartType        
	)

    If ($StartType.ToUpper() -eq "BOOT") { $StartValue = 0 }
    ElseIf ($StartType.ToUpper() -eq "SYSTEM") { $StartValue = 1 }
    ElseIf ($StartType.ToUpper() -eq "AUTOMATIC") { $StartValue = 2 }
    ElseIf ($StartType.ToUpper() -eq "MANUAL") { $StartValue = 3 }
    ElseIf ($StartType.ToUpper() -eq "DISABLED") { $StartValue = 4 }
    Else
    {
        Write-Verbose "Invalid startup type specified, $StartType. No changes made."
        Return
    }

    If ((Get-Service -Name $ServiceName | Select-Object StartType).StartType -ne $StartType)
    {
		#Attempt to set service startup to disabled
		Try {
			Write-Verbose "Setting service $ServiceName startup to $StartType($StartValue) via registry."
			Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName" -Name "Start" -value $StartValue
		}
		Catch {
			Write-Verbose "Could not set service $ServiceName startup to $StartType($StartValue) via registry."
		}
	}
	Else
	{
		Write-Verbose "$ServiceName service startup was already set to $StartType($StartValue)."
	}
}

function Write-ScriptLog {
    <#
    .SYNOPSIS
    Write log entry to file
    .DESCRIPTION
    Write log entry to file containing service name, original startup type, and new startup type
    #>

    $LogTime = (Get-Date -format s)
    
    If (Test-Path ($LogFile))
    {
        Write-Verbose "Append log entry to existing log file"
        Write-Output $LogTime","$ServiceName","$OriginalStartType","$NewStartType | Out-File $LogFile -Append
    }
    Else
    {
        # Start new log file
        Write-Verbose "Start new log file and append log entry"
        Write-Output "DateString,ServiceName,StartTypeBeforeChange,StartTypeAfterChange" | Out-File $LogFile
        Write-Output $LogTime","$ServiceName","$OriginalStartType","$NewStartType | Out-File $LogFile -Append
    }
}

function Undo-ServiceHardening {
    <#
    .SYNOPSIS
    Read in log file and revert changes to service startup type
    .DESCRIPTION
    This function reads the provided log file and reverts the changes to the startup type for each service in the log
    #>

    Write-Verbose "Check undo log file exists and execute undo actions"
    If (Test-Path ($UndoLogFile))
    {
        $UndoLogEntries = Import-Csv $UndoLogFile
        ForEach ($UndoLogEntry in $UndoLogEntries)
        {
            #Get old service start type and service name from undo log file
            $StartTypeBeforeChange = $UndoLogEntry.StartTypeBeforeChange
            $ServiceName = $UndoLogEntry.ServiceName

            $OriginalStartType=(Get-Service -Name $ServiceName | Select-Object StartType).StartType
            Set-ServiceStartType -StartType $StartTypeBeforeChange
            $NewStartType=(Get-Service -Name $ServiceName | Select-Object StartType).StartType
            If ($Log) { Write-ScriptLog }
        }
    }
    Else
    {
        Write-Host "Specified undo log file was not found."
    }
}

function Disable-Services {
    <#
    .SYNOPSIS
    Disable services
    .DESCRIPTION
    This function disables services as per Microsoft's guidance for Windows Server 2016 Desktop Experience
    #>

    #Define arrays for services that should be disabled. Separate arrays are created for common services, non-print server only services, and non-print server and non-DC server services
    
    #Common Services (includes services that should already be disabled)
    [Array]$CommonServiceNames = "AxInstSV","tzautoupdate","bthserv","Browser","dmwappushservice","MapsBroker","lfsvc","SharedAccess","lltdsvc","wlidsvc","AppVClient","NcbService","CscService","PhoneSvc","PcaSvc","QWAVE","RmSvc","RemoteAccess","SensorDataService","SensrSvc","SensorService","ShellHWDetection","SCardSvr","ScDeviceEnum","SSDPSRV","WiaRpc","TabletInputService","upnphost","UevAgentService","WalletService","Audiosrv","AudioEndpointBuilder","FrameServer","stisvc","wisvc","icssvc","WpnService","WSearch","XblAuthManager","XblGameSave","CDPUserSvc","PimIndexMaintenanceSvc","NgcSvc","NgcCtnrSvc","OneSyncSvc","UnistoreSvc","UserDataSvc","WpnUserService"
    [Array]$CommonServiceDescriptions = "ActiveX Installer (AxInstSV)","Auto Time Zone Updater","Bluetooth Support Service","Computer Browser","dmwappushsvc","Downloaded Maps Manager","Geolocation Service","Internet Connection Sharing (ICS)","Link-Layer Topology Discovery Mapper","Microsoft Account Sign-in Assistant","Microsoft App-V Client","Network Connection Broker","Offline Files","Phone Service","Program Compatibility Assistant Service","Quality Windows Audio Video Experience","Radio Management Service","Routing and Remote Access","Sensor Data Service","Sensor Monitoring Service","Sensor Service","Shell Hardware Detection","Smart Card","Smart Card Device Enumeration Service","SSDP Discovery","Still Image Acquisition Events","Touch Keyboard and Handwriting Panel Service","UPnP Device Host","User Experience Virtualization Service","WalletService","Windows Audio","Windows Audio Endpoint Builder","Windows Camera Frame Server","Windows Image Acquisition (WIA)","Windows Insider Service","Windows Mobile Hotspot Service","Windows Push Notifications System Service","Windows Search","Xbox Live Auth Manager","Xbox Live Game Save","CDPUserSvc","Contact Data","Microsoft Passport","Microsoft Passport Container","Sync Host","User Data Storage","User Data Access","Windows Push Notifications User Service"
    
    #Services to be disabled on non-Print Servers
    [Array]$PrintServerServiceNames = "PrintNotify"
    [Array]$PrintServerServiceDescriptions = "Printer Extensions and Notifications"
    
    #Services to be disabled on servers that are not DCs or Print Servers
    [Array]$DCorPrintServerServiceNames = "Spooler"
    [Array]$DCorPrintServerServiceDescriptions = "Print Spooler"
    
    #Check and disable common services
    If ($MemberServer -eq $true -or $DomainController -eq $true -or $PrintServer -eq $true)
    {
    	Write-Verbose "Disable common services"
    	ForEach ($ServiceName in $CommonServiceNames) {
            $OriginalStartType=(Get-Service -Name $ServiceName | Select-Object StartType).StartType
            Stop-RunningService
            Set-ServiceStartType -StartType DISABLED
            $NewStartType=(Get-Service -Name $ServiceName | Select-Object StartType).StartType
            If ($Log) { Write-ScriptLog }
        }
    }

    #Check and disable additional services on servers that are not Print Servers
    If ($PrintServer -eq $false -and ($MemberServer -eq $true -or $DomainController -eq $true))
    {
    	Write-Verbose "Disable additional services on non-print servers"
    	ForEach ($ServiceName in $PrintServerServiceNames) {
            $OriginalStartType=(Get-Service -Name $ServiceName | Select-Object StartType).StartType
            Stop-RunningService
            Set-ServiceStartType -StartType DISABLED
            $NewStartType=(Get-Service -Name $ServiceName | Select-Object StartType).StartType
            If ($Log) { Write-ScriptLog }
        }
    }
    
    #Check and disable additional services on servers that are not Print Servers or Domain Controllers
    If ($DomainController -eq $false -and $PrintServer -eq $false -and $MemberServer -eq $true)
    {
    	Write-Verbose "Disable additional services on non-print servers and non-DC servers"
    	ForEach ($ServiceName in $DCorPrintServerServiceNames) {
            $OriginalStartType=(Get-Service -Name $ServiceName | Select-Object StartType).StartType
     	    Stop-RunningService
            Set-ServiceStartType -StartType DISABLED
            $NewStartType=(Get-Service -Name $ServiceName | Select-Object StartType).StartType
            If ($Log) { Write-ScriptLog }
        }
    }
}

#If no switches defined, show usage
If (!$MemberServer -and !$DomainController -and !$PrintServer -and !$Undo)
{
    Write-Verbose "Show script usage"
    $ScriptName = $MyInvocation.MyCommand.Name
    Write-Output "At least one command line switch must be enabled."
	Write-Host "Usage Examples:"
    Write-Host $ScriptName "-MemberServer [-Log] [-LogFile <log_filename>]"
    Write-Host $ScriptName "-DomainController [-Log] [-LogFile <log_filename>]"
    Write-Host $ScriptName "-PrintServer [-Log] [-LogFile <log_filename>]"
    Write-Host $ScriptName "-Undo -UndoLogFile <undo_log_filename>"
	Break
}

# If undo is specified but no undo log file is provided, show usage
If ($Undo -and !$UndoLogFile)
{
    Write-Verbose "Show undo usage"
    $ScriptName = $MyInvocation.MyCommand.Name
    Write-Output "Undo feature requires an input log."
    Write-Host "Usage Example:"
    Write-Host $ScriptName "-Undo -UndoLogFile <undo_log_filename>"
    Break
}

# If undo is specified and undo log file is specified, execute undo
If ($Undo -and $UndoLogFile)
{
    Write-Verbose "Starting undo of previous changes from $UndoLogFile"
    Undo-ServiceHardening
    Break
}

# If MemberServer, DomainController, or PrintServer switches activated, disable services
If ($MemberServer -eq $true -or $DomainController -eq $true -or $PrintServer -eq $true)
{
    Write-Verbose "Start disabling services."
    Disable-Services
    Break
}
