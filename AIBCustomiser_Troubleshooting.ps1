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

Write-Log "Start script AIBCustomiser_Troubleshooting v0.1"

while (!(Test-Path C:\dummy.txt)){
    Write-Log "C:\dummy.txt not found, wait 30 sec"
    Start-Sleep -Seconds 30
}
Write-Log "Found C:\dummy.txt file, removing it"
Remove-Item C:\dummy.txt -Force

Write-Log "End script"