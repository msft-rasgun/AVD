# **************************************************************************************************
# This sample script is not supported under any Microsoft standard support program or service. 
# The sample script is provided AS IS without warranty of any kind. Microsoft further disclaims 
# all implied warranties including, without limitation, any implied warranties of merchantability 
# or of fitness for a particular purpose. The entire risk arising out of the use or performance 
# of the sample scripts and documentation remains with you. In no event shall Microsoft, its authors, 
# Or anyone else involved in the creation, production, or delivery of the scripts be liable for 
# any damages whatsoever (including, without limitation, damages for loss of business profits, 
# business interruption, loss of business information, or other pecuniary loss) arising out of 
# the use of or inability to use the sample scripts or documentation, even if Microsoft has been 
# advised of the possibility of such damages.
# **************************************************************************************************
#

function Write-Log {
    # Note: this is required to support param such as ErrorAction
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [switch]$Err,

        [switch]$Warn
    )

    [string]$MessageTimeStamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $Message = "[$($MyInvocation.ScriptLineNumber)] $Message"
    [string]$WriteMessage = "$MessageTimeStamp $Message"

    if ($Err) {
        Write-Error $WriteMessage
        $Message = "ERROR: $Message"
    }
    elseif ($Warn) {
        Write-Warning $WriteMessage
        $Message = "WARN: $Message"
    }
    else {
        Write-Output $WriteMessage
    }
}

Write-Log "Start script AIBCustomiser_GeneralizeConfigMgrAgent v0.1"

If (-not (Get-Service ccmexec -ErrorAction SilentlyContinue)){
    Write-Log "ConfigMgr Agent service doesn't exist, nothing to generalize"
    exit 0
}

while ((Get-Service ccmexec).Status -ne 'Stopped'){
    Write-Log "ConfigMgr Agent service not stopped. Try to stop and check again"
    Stop-Service ccmexec
    Start-Sleep -Seconds 5
}
Write-Log "Configuration Manager Agent service is stopped"

Write-Log "Remove self-signed certificates from SMS store"
Get-ChildItem -Path Cert:\LocalMachine\SMS\ | Remove-Item

If (Test-Path C:\Windows\SMSCFG.ini){
    Write-Log "Remove smscfg.ini from C:\Windows"
    Remove-Item -Path C:\Windows\SMSCFG.ini -Force
}

Write-Log "Remove inventory history from WMI"
Get-WmiObject -Namespace root\ccm\invagt -Query "Select * from InventoryActionStatus where InventoryActionID like '{00000%'" | Remove-WmiObject

Write-Log "End script"