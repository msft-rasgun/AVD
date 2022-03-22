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
#        Write-Error $WriteMessage
        $WriteMessage = "ERROR: $WriteMessage"
        Write-Output $WriteMessage
    }
    elseif ($Warn) {
#        Write-Warning $WriteMessage
        $WriteMessage = "WARN: $WriteMessage"
        Write-Output $WriteMessage
    }
    else {
        Write-Output $WriteMessage
    }
}

Write-Log "Start script AIBCustomiser_WaitForTS v0.1"

while (-not (Get-Service ccmexec -ErrorAction SilentlyContinue)){
    Write-Log "ConfigMgr Agent service doesn't exist. Wait 30 seconds and try again"
    Start-Sleep -seconds 30
}

while ((Get-Service ccmexec).Status -ne 'Running'){
    Write-Log "ConfigMgr Agent service not running. Wait 30 seconds and try again"
    Start-Sleep -seconds 30
}

Write-Log "Configuration Manager Agent service is running"

while (-not (Test-Path C:\Windows\CCM\Logs\smsts.log)){
    Write-Log "C:\Windows\CCM\Logs\smsts.log not found. Wait 30 seconds and try again"
    Start-Sleep -Seconds 30
}
Write-Log "C:\Windows\CCM\Logs\smsts.log found"

while (-not (Test-Path 'HKLM:\SOFTWARE\Microsoft\SMS\Mobile Client\Software Distribution\Execution History\System\DH100026')){
    Write-Log "Execution history not found in registry. Wait 30 seconds and try again"
    Start-Sleep -Seconds 30
}
$RegKeys = Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\SMS\Mobile Client\Software Distribution\Execution History\System\DH100026'
foreach ($RegKey in $RegKeys){
    If ((get-itemproperty $regkey.pspath)._State -eq "Success"){
        Write-Log "Found Success state in execution history in regstry"
    }
    else{
        Write-Log "Execution history not success: $((get-itemproperty $regkey.pspath)._State)" -Err
        While (!(Test-Path C:\dummy.txt)){
            Write-Log "Stop script execution for troubleshooting"
            start-sleep -Seconds 60
        }
        Write-Log "dump smsts.log"
        Get-Content C:\Windows\CCM\Logs\smsts.log
        Write-Log "dump Remove-AppxProvisionedPackages.log"
        Get-Content C:\Windows\CCM\Logs\Remove-AppxProvisionedPackages.log
        Write-Log "Stop script execution for troubleshooting"
        Start-Sleep -Seconds 7200
        exit 1
    }
}

Write-Log "End script"