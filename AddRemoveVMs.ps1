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

<#
.SYNOPSIS
    Runbook script to add and remove session hosts as part of deployment of a new image

.DESCRIPTION
    This script is based on version 0.1.38 of the official autoscaling solution provided by Microsoft. Solution and script links below:
        https://docs.microsoft.com/en-us/azure/virtual-desktop/set-up-scaling-script
        https://github.com/Azure/RDS-Templates/blob/master/wvd-templates/wvd-scaling-script/ARM_based/basicScale.ps1

    The script will find session hosts not running the desired image and delete them if they don't have any user sessions.
    If there's any user sessions running, it will put the session host in drain mode.

    The script can only handle images that are part of a shared image gallery.

    Requires the following modules to be imported in the automation account
        Az.Accounts
        Az.Compute
        Az.DesktopVirtualization
        Az.KeyVault
        Az.Network
        Az.Resources
        OMSIngestionAPI


.INPUTS
    Script is designed to run as part of a runbook, triggered by a logic app calling the webhook
    The script will handle the following input parameters
    Required
        ResourceGroupName                       [Resource group name where the hostpool resides and where VMs will be created]
		HostPoolName                            [Name of the hostpool where we want to perform the scaling]
		TimeDifference                          [Time difference to UTC to calculate peak/off-peak and write log entries in local time]
		ImageID                                 [The ID of the image definition]
		ImageVersion                            [The version of the image definition]
        MinimumNumberOfVMs                      [Specify minimum number of VMs that are required running the new image]
        vmLocation                              [Azure region to deploy VMs in]
        virtualNetworkResourceGroupName         [Virtual network resource group name that contains the virtual network and subnet for deploying VMs]
        existingVnetName                        [Virtual network name for deploying VMs]
        existingSubnetName                      [Subnet name for deploying VMs]
        domain                                  [Specify FQDN of Active Directory domain to join new VMs to]
        ouPath                                  [Specify the OU path to create computer objects in]
        KeyVaultName                            [Specify the Azure Key Vault that contains the secrets]

    Optional
	    LogAnalyticsWorkspaceId                 [WorkspaceID for logging]
        LogAnalyticsPrimaryKey                  [Primary key to access the log analytics workspace. Required if LogAnalyticsWorkspaceId is set]
        ConnectionAssetName                     [Automation account name. If not set, default value "AzureRunAsConnection" is being used]
        EnvironmentName                         [Specifies the Azure environment. If not set, default value "AzureCloud" is being used]
	    MaintenanceTagName                      [Session hosts with this maintenance tag will be ignored by the script]
        SkipAuth                                [If enabled, the script will assume that all the authentication is already done in current or parent scope before calling this script]
        StatusCheckTimeOut                      [Specify time in seconds to wait for jobs to finish. Default value 3600 (1hr)]
        KeyVaultSecretNameJoinDomainAccount     [Secret name that contains the join domain account name. Default: <HostpoolName>-JoinDomainAccount]
	    KeyVaultSecretNameJoinDomainPassword    [Secret name that contains the join domain password. Default: <HostpoolName>-JoinDomainPassword]
	    KeyVaultSecretNameLocalAdminAccount     [Secret name that contains the local administrator account name. Default: <HostpoolName>-LocalAdminAccount]
	    KeyVaultSecretNameLocalAdminPassword    [Secret name that contains the local administrator password. Default: <HostpoolName>-LocalAdminPassword]

    
.NOTES
    v0.1.0 Initial draft - 2021-10-01
#>
[CmdletBinding(SupportsShouldProcess)]
param (
	[Parameter(mandatory = $false)]
	$WebHookData,

	# Note: optional for simulating user sessions
	[System.Nullable[int]]$OverrideNUserSessions
)
try {
	[version]$Version = '0.1.0'
	#region set err action preference, extract & validate input rqt params

	# Setting ErrorActionPreference to stop script execution when error occurs
	$ErrorActionPreference = 'Stop'
	# Note: this is to force cast in case it's not of the desired type. Specifying this type inside before the param inside param () doesn't work because it still accepts other types and doesn't cast it to this type
	$WebHookData = [PSCustomObject]$WebHookData

	function Get-PSObjectPropVal {
		param (
			$Obj,
			[string]$Key,
			$Default = $null
		)
		$Prop = $Obj.PSObject.Properties[$Key]
		if ($Prop) {
			return $Prop.Value
		}
		return $Default
	}

	# If runbook was called from Webhook, WebhookData and its RequestBody will not be null
	if (!$WebHookData -or [string]::IsNullOrWhiteSpace((Get-PSObjectPropVal -Obj $WebHookData -Key 'RequestBody'))) {
		throw 'Runbook was not started from Webhook (WebHookData or its RequestBody is empty)'
	}

	# Collect Input converted from JSON request body of Webhook
	$RqtParams = ConvertFrom-Json -InputObject $WebHookData.RequestBody

	if (!$RqtParams) {
		throw 'RequestBody of WebHookData is empty'
	}

	[string[]]$RequiredStrParams = @(
		'ResourceGroupName'
		'HostPoolName'
		'TimeDifference'
		'ImageID'
		'ImageVersion'
        'vmLocation'
        'virtualNetworkResourceGroupName'
        'existingVnetName'
        'existingSubnetName'
        'domain'
        'ouPath'
        'KeyVaultName'
    )
	[string[]]$RequiredParams = @('MinimumNumberOfVMs')
	[string[]]$InvalidParams = @($RequiredStrParams | Where-Object { [string]::IsNullOrWhiteSpace((Get-PSObjectPropVal -Obj $RqtParams -Key $_)) })
	[string[]]$InvalidParams += @($RequiredParams | Where-Object { $null -eq (Get-PSObjectPropVal -Obj $RqtParams -Key $_) })
    # Ensure that MinimumNumberOfVMs is a positive number
    If ($RqtParams.MinimumNumberOfVMs -lt 1){
        [string[]]$InvalidParams += "vmInitialNumber"
    }
	if ($InvalidParams) {
		throw "Invalid values for the following $($InvalidParams.Count) params: $($InvalidParams -join ', ')"
	}
	[string]$LogAnalyticsWorkspaceId = Get-PSObjectPropVal -Obj $RqtParams -Key 'LogAnalyticsWorkspaceId'
	[string]$LogAnalyticsPrimaryKey = Get-PSObjectPropVal -Obj $RqtParams -Key 'LogAnalyticsPrimaryKey'
	[string]$ConnectionAssetName = Get-PSObjectPropVal -Obj $RqtParams -Key 'ConnectionAssetName'
	[string]$EnvironmentName = Get-PSObjectPropVal -Obj $RqtParams -Key 'EnvironmentName'
	[string]$MaintenanceTagName = Get-PSObjectPropVal -Obj $RqtParams -Key 'MaintenanceTagName'
	[int]$StatusCheckTimeOut = Get-PSObjectPropVal -Obj $RqtParams -Key 'StatusCheckTimeOut' -Default (60 * 60) # 1 hr
    [bool]$SkipAuth = !!(Get-PSObjectPropVal -Obj $RqtParams -Key 'SkipAuth')
	[string]$TimeDifference = $RqtParams.TimeDifference
	[string]$ResourceGroupName = $RqtParams.ResourceGroupName
	[string]$HostPoolName = $RqtParams.HostPoolName
	[string]$ImageID = $RqtParams.ImageID
	[string]$ImageVersion = $RqtParams.ImageVersion
	[string]$vmLocation = $RqtParams.vmLocation
	[string]$virtualNetworkResourceGroupName = $RqtParams.virtualNetworkResourceGroupName
	[string]$existingVnetName = $RqtParams.existingVnetName
	[string]$existingSubnetName = $RqtParams.existingSubnetName
	[string]$domain = $RqtParams.domain
	[string]$ouPath = $RqtParams.ouPath
	[string]$KeyVaultName = $RqtParams.KeyVaultName
	[string]$KeyVaultSecretNameJoinDomainAccount = $RqtParams.KeyVaultSecretNameJoinDomainAccount
	[string]$KeyVaultSecretNameJoinDomainPassword = $RqtParams.KeyVaultSecretNameJoinDomainPassword
	[string]$KeyVaultSecretNameLocalAdminAccount = $RqtParams.KeyVaultSecretNameLocalAdminAccount
	[string]$KeyVaultSecretNameLocalAdminPassword = $RqtParams.KeyVaultSecretNameLocalAdminPassword
    [int]$MinimumNumberOfVMs = $RqtParams.MinimumNumberOfVMs

    # Set default values if not supplied
    if ([string]::IsNullOrWhiteSpace($ConnectionAssetName)) {
		$ConnectionAssetName = 'AzureRunAsConnection'
	}
	if ([string]::IsNullOrWhiteSpace($EnvironmentName)) {
		$EnvironmentName = 'AzureCloud'
	}
	if ([string]::IsNullOrWhiteSpace($KeyVaultSecretNameJoinDomainAccount)) {
		$KeyVaultSecretNameJoinDomainAccount = "$($HostPoolName)-JoinDomainAccount"
	}
	if ([string]::IsNullOrWhiteSpace($KeyVaultSecretNameJoinDomainPassword)) {
		$KeyVaultSecretNameJoinDomainPassword = "$($HostPoolName)-JoinDomainPassword"
	}
	if ([string]::IsNullOrWhiteSpace($KeyVaultSecretNameLocalAdminAccount)) {
		$KeyVaultSecretNameLocalAdminAccount = "$($HostPoolName)-LocalAdminAccount"
	}
	if ([string]::IsNullOrWhiteSpace($KeyVaultSecretNameLocalAdminPassword)) {
		$KeyVaultSecretNameLocalAdminPassword = "$($HostPoolName)-LocalAdminPassword"
	}

   	# Note: time diff can be '#' or '#:#', so it is appended with ':0' in case its just '#' and so the result will have at least 2 items (hrs and min)
	[string[]]$TimeDiffHrsMin = "$($TimeDifference):0".Split(':')

	#endregion

	#region helper/common functions, set exec policies, set TLS 1.2 security protocol, log rqt params

	# Function to return local time converted from UTC
	function Get-LocalDateTime {
		return (Get-Date).ToUniversalTime().AddHours($TimeDiffHrsMin[0]).AddMinutes($TimeDiffHrsMin[1])
	}

	function Write-Log {
		# Note: this is required to support param such as ErrorAction
		[CmdletBinding()]
		param (
			[Parameter(Mandatory = $true)]
			[string]$Message,

			[switch]$Err,

			[switch]$Warn
		)

		[string]$MessageTimeStamp = (Get-LocalDateTime).ToString('yyyy-MM-dd HH:mm:ss')
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
			
		if (!$LogAnalyticsWorkspaceId -or !$LogAnalyticsPrimaryKey) {
			return
		}

		try {
			$body_obj = @{
				'hostpoolName' = $HostPoolName
				'logmessage'   = $Message
				'TimeStamp'    = $MessageTimeStamp
			}
			$json_body = ConvertTo-Json -Compress $body_obj
			
			$PostResult = Send-OMSAPIIngestionFile -customerId $LogAnalyticsWorkspaceId -sharedKey $LogAnalyticsPrimaryKey -Body $json_body -logType 'AVD_AddRemoveSessionHosts' -TimeStampField 'TimeStamp' -EnvironmentName $EnvironmentName
			if ($PostResult -ine 'Accepted') {
				throw "Error posting to OMS: $PostResult"
			}
		}
		catch {
			Write-Warning "$MessageTimeStamp Some error occurred while logging to log analytics workspace: $($PSItem | Format-List -Force | Out-String)"
		}
	}

	# Function to wait for background jobs
	function Wait-ForJobs {
		param ([array]$Jobs = @())

		Write-Log "Wait for $($Jobs.Count) jobs"
		$StartTime = Get-Date
		[string]$StatusInfo = ''
		while ($true) {
			if ((Get-Date).Subtract($StartTime).TotalSeconds -ge $StatusCheckTimeOut) {
				throw "Jobs status check timed out. Taking more than $StatusCheckTimeOut seconds. $StatusInfo"
			}
			$StatusInfo = "[Check jobs status] Total: $($Jobs.Count), $(($Jobs | Group-Object State | ForEach-Object { "$($_.Name): $($_.Count)" }) -join ', ')"
			Write-Log $StatusInfo
			if (!($Jobs | Where-Object { $_.State -ieq 'Running' })) {
				break
			}
			Start-Sleep -Seconds 30
		}

		[array]$IncompleteJobs = @($Jobs | Where-Object { $_.State -ine 'Completed' })
		if ($IncompleteJobs) {
			throw "$($IncompleteJobs.Count)/$($Jobs.Count) jobs did not complete successfully: $($IncompleteJobs | Format-List -Force | Out-String)"
		}
	}

	function Get-SessionHostName {
		param (
			[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
			$SessionHost
		)
		return $SessionHost.Name.Split('/')[-1]
	}

	function TryUpdateSessionHostDrainMode {
		[CmdletBinding(SupportsShouldProcess)]
		param (
			[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
			[hashtable]$VM,

			[switch]$AllowNewSession
		)
		Begin { }
		Process {
			$SessionHost = $VM.SessionHost
			if ($SessionHost.AllowNewSession -eq $AllowNewSession) {
				return
			}
			
			[string]$SessionHostName = $VM.SessionHostName
			Write-Log "Update session host '$SessionHostName' to set allow new sessions to $AllowNewSession"
			if ($PSCmdlet.ShouldProcess($SessionHostName, "Update session host to set allow new sessions to $AllowNewSession")) {
				try {
					$SessionHost = $VM.SessionHost = Update-AzWvdSessionHost -ResourceGroupName $ResourceGroupName -HostPoolName $HostPoolName -Name $SessionHostName -AllowNewSession:$AllowNewSession
					if ($SessionHost.AllowNewSession -ne $AllowNewSession) {
						throw $SessionHost
					}
				}
				catch {
					Write-Log -Warn "Failed to update the session host '$SessionHostName' to set allow new sessions to $($AllowNewSession): $($PSItem | Format-List -Force | Out-String)"
				}
			}
		}
		End { }
	}

	Set-ExecutionPolicy -ExecutionPolicy Undefined -Scope Process -Force -Confirm:$false
	if (!$SkipAuth) {
		# Note: this requires admin priviledges
		Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope LocalMachine -Force -Confirm:$false
	}

	# Note: https://stackoverflow.com/questions/41674518/powershell-setting-security-protocol-to-tls-1-2
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

	Write-Log "Request params: $($RqtParams | Format-List -Force | Out-String)"

	if ($LogAnalyticsWorkspaceId -and $LogAnalyticsPrimaryKey) {
		Write-Log "Log analytics is enabled"
	}

	#endregion


	#region azure auth, ctx

	if (!$SkipAuth) {
		# Collect the credentials from Azure Automation Account Assets
		Write-Log "Get auto connection from asset: '$ConnectionAssetName'"
		$ConnectionAsset = Get-AutomationConnection -Name $ConnectionAssetName
		
		# Azure auth
		$AzContext = $null
		try {
			$AzAuth = Connect-AzAccount -ApplicationId $ConnectionAsset.ApplicationId -CertificateThumbprint $ConnectionAsset.CertificateThumbprint -TenantId $ConnectionAsset.TenantId -SubscriptionId $ConnectionAsset.SubscriptionId -EnvironmentName $EnvironmentName -ServicePrincipal
			if (!$AzAuth -or !$AzAuth.Context) {
				throw $AzAuth
			}
			$AzContext = $AzAuth.Context
		}
		catch {
			throw [System.Exception]::new('Failed to authenticate Azure with application ID, tenant ID, subscription ID', $PSItem.Exception)
		}
		Write-Log "Successfully authenticated with Azure using service principal: $($AzContext | Format-List -Force | Out-String)"

		# Set Azure context with subscription, tenant
		if ($AzContext.Tenant.Id -ine $ConnectionAsset.TenantId -or $AzContext.Subscription.Id -ine $ConnectionAsset.SubscriptionId) {
			if ($PSCmdlet.ShouldProcess((@($ConnectionAsset.TenantId, $ConnectionAsset.SubscriptionId) -join ', '), 'Set Azure context with tenant ID, subscription ID')) {
				try {
					$AzContext = Set-AzContext -TenantId $ConnectionAsset.TenantId -SubscriptionId $ConnectionAsset.SubscriptionId
					if (!$AzContext -or $AzContext.Tenant.Id -ine $ConnectionAsset.TenantId -or $AzContext.Subscription.Id -ine $ConnectionAsset.SubscriptionId) {
						throw $AzContext
					}
				}
				catch {
					throw [System.Exception]::new('Failed to set Azure context with tenant ID, subscription ID', $PSItem.Exception)
				}
				Write-Log "Successfully set the Azure context with the tenant ID, subscription ID: $($AzContext | Format-List -Force | Out-String)"
			}
		}
	}

	#endregion


	#region validate host pool, validate / update HostPool load balancer type, ensure there is at least 1 session host, get num of user sessions

	# Validate and get HostPool info
	$HostPool = $null
	try {
		Write-Log "Get Hostpool info of '$HostPoolName' in resource group '$ResourceGroupName'"
		$HostPool = Get-AzWvdHostPool -ResourceGroupName $ResourceGroupName -Name $HostPoolName
		if (!$HostPool) {
			throw $HostPool
		}
	}
	catch {
		throw [System.Exception]::new("Failed to get Hostpool info of '$HostPoolName' in resource group '$ResourceGroupName'. Ensure that you have entered the correct values", $PSItem.Exception)
	}

	# Ensure HostPool load balancer type is not persistent
	if ($HostPool.LoadBalancerType -ieq 'Persistent') {
		throw "HostPool '$HostPoolName' is configured with 'Persistent' load balancer type. Script only supports these load balancer types: BreadthFirst, DepthFirst"
	}

	Write-Log 'Get all session hosts'
	$SessionHosts = @(Get-AzWvdSessionHost -ResourceGroupName $ResourceGroupName -HostPoolName $HostPoolName)

	Write-Log "HostPool info: $($HostPool | Format-List -Force | Out-String)"
	Write-Log "Number of session hosts in the HostPool: $($SessionHosts.Count)"

	#endregion
	
    #region get all session hosts, VMs & user sessions info and compute workload

	# Object that contains all session host objects, VM instance objects except the ones that are under maintenance
	$VMs = @{ }

	# Populate all session hosts objects
	foreach ($SessionHost in $SessionHosts) {
		[string]$SessionHostName = Get-SessionHostName -SessionHost $SessionHost
		$VMs.Add($SessionHostName.Split('.')[0].ToLower(), @{ 'SessionHostName' = $SessionHostName; 'SessionHost' = $SessionHost; 'Instance' = $null })
	}
	
	Write-Log 'Get all VMs, check session host status and get usage info'
	foreach ($VMInstance in (Get-AzVM -Status)) {
		if (!$VMs.ContainsKey($VMInstance.Name.ToLower())) {
			# This VM is not a WVD session host
			continue
		}
		[string]$VMName = $VMInstance.Name.ToLower()
		if ($VMInstance.Tags.Keys -contains $MaintenanceTagName) {
			Write-Log "VM '$VMName' is in maintenance and will be ignored"
			$VMs.Remove($VMName)
			continue
		}

		$VM = $VMs[$VMName]
		$SessionHost = $VM.SessionHost
		if ((Get-PSObjectPropVal -Obj $SessionHost -Key 'VirtualMachineId') -and $VMInstance.VmId -ine $SessionHost.VirtualMachineId) {
			# This VM is not a WVD session host
			continue
		}
		if ($VM.Instance) {
			throw "More than 1 VM found in Azure with same session host name '$($VM.SessionHostName)' (This is not supported): $($VMInstance | Format-List -Force | Out-String)$($VM.Instance | Format-List -Force | Out-String)"
		}

		$VM.Instance = $VMInstance

		Write-Log "Session host: '$($VM.SessionHostName)', power state: '$($VMInstance.PowerState)', status: '$($SessionHost.Status)', update state: '$($SessionHost.UpdateState)', sessions: $($SessionHost.Session), allow new session: $($SessionHost.AllowNewSession)"

	}


    # Make sure VM instance was found in Azure for every session host
	[int]$nVMsWithoutInstance = @($VMs.Values | Where-Object { !$_.Instance }).Count
	if ($nVMsWithoutInstance) {
		throw "There are $nVMsWithoutInstance/$($VMs.Count) session hosts whose VM instance was not found in Azure"
	}

	#endregion



	#region determine which VMs to delete if any

    $VMsWithCorrectImage = @{}
    $VMsToPutInDrainMode = @{}
    $VMsToRemove = @{}

    foreach ($VM in $VMs.Values){
        Write-Log "SessionHostName = $($VM.SessionHostName)"
#        Write-Log "ImageID = $($VM.Instance.StorageProfile.ImageReference.Id)"
#        Write-Log "ImageVersion = $($VM.Instance.StorageProfile.ImageReference.ExactVersion)"
#        Write-Log "AllowNewSession = $($VM.SessionHost.AllowNewSession)"
#        Write-Log "Power state = $($VM.Instance.PowerState)"
#        Write-Log "Status = $($VM.SessionHost.Status)"
#        Write-Log "Update state = $($VM.SessionHost.UpdateState)"
        If ($($VM.Instance.StorageProfile.ImageReference.Id) -notin ($ImageID, "$ImageID/versions/$ImageVersion") -OR $($VM.Instance.StorageProfile.ImageReference.ExactVersion) -ne $ImageVersion){
            Write-Log "Not correct image"
#            write-log "ImageID: [$($VM.Instance.StorageProfile.ImageReference.Id)] Expected [$ImageID]"
#            write-log "ImageVer: [$($VM.Instance.StorageProfile.ImageReference.ExactVersion)] Expected [$ImageVersion]"
            If ($($VM.SessionHost.Session) -eq 0){
                Write-Log "Session host doesn't have any sessions. Delete VM"
                $VMsToRemove.Add($VM.SessionHostName, $VM)
            }
            else{
                Write-Log "Session host have sessions: $($VM.SessionHost.Session). Put in drain mode"
                $VMsToPutInDrainMode.Add($VM.SessionHostName, $VM)
            }
        }
        else {
            Write-Log "Correct Image, ensure drain mode off"
            If ($($VM.SessionHost.AllowNewSession) -eq $false){
                TryUpdateSessionHostDrainMode -VM $VM -AllowNewSession:$true 
            }
            $VMsWithCorrectImage.Add($VM.SessionHostName, $VM)
        }
    }

	#endregion

    Write-Log "VMs to remove: $($VMsToRemove.Keys -join ', ')"
    Write-Log "VMs to drain: $($VMsToPutInDrainMode.Keys -join ', ')"
    Write-Log "VMs with correct image: $($VMsWithCorrectImage.Keys -join ', ')"

	#region start any session hosts if need to

	# Check if we need to add any VMs
    # check if already have the minimum number of VMs
    If ($VMsWithCorrectImage.Count -ge $MinimumNumberOfVMs){
        Write-Log "Have enough VMs with correct image. No need to add additional VMs"
    }
    Else{
        Write-Log "Not enough VMs with correct image. Have $($VMsWithCorrectImage.Count), need $MinimumNumberOfVMs"
        # Array that contains jobs of adding session hosts
		[array]$AddVMjobs = @()

        ######### REMOVE VALUES LATER, JUST FOR TESTING ###########
        $TemplateURI = "https://rasgunavd.blob.core.windows.net/files/template.json"
        $QueryString = "?sp=r&st=2021-09-29T05:23:50Z&se=2021-12-31T12:23:50Z&spr=https&sv=2020-08-04&sr=b&sig=e4JkQMBpk5H%2BdF5XGv%2B%2F8rHSh3IpFXFU4G5rlhI0GnI%3D"

        # Fill variables for template deployment
        $AddVMParams = @{}

        # Get values from Key Vault
        $AddVMParams.Add("administratorAccountUsername", (Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $KeyVaultSecretNameJoinDomainAccount -AsPlainText))
        $AddVMParams.Add("administratorAccountPassword", ((Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $KeyVaultSecretNameJoinDomainPassword -AsPlainText) | ConvertTo-SecureString -AsPlainText -Force))
        $AddVMParams.Add("vmAdministratorAccountUsername", (Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $KeyVaultSecretNameLocalAdminAccount -AsPlainText))
        $AddVMParams.Add("vmAdministratorAccountPassword", ((Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $KeyVaultSecretNameLocalAdminPassword -AsPlainText) | ConvertTo-SecureString -AsPlainText -Force))

        # Get hostpool registration token, generate new if it doesn't exists
        $regToken = Get-AzWvdHostPoolRegistrationToken -HostPoolName $HostPoolName -ResourceGroupName $ResourceGroupName
        If (!$regToken.Token){
            Write-Log "No registration token found, generate new"
            $regToken = New-AzWvdRegistrationInfo -ResourceGroupName $ResourceGroupName -HostPoolName $HostPoolName -ExpirationTime $((get-date).ToUniversalTime().AddDays(1).ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ'))
        }
        If ($regToken){
            $AddVMParams.Add("hostpoolToken", ($regToken.Token | ConvertTo-SecureString -AsPlainText -Force))
        }
        else {
            throw "Unable to get or generate registration token for hostpool"
        }

        # Get values from the hostpool
        $hostpoolTemplate = $HostPool.VMTemplate | ConvertFrom-Json
        If ($hostpoolTemplate){
            $AddVMParams.Add("vmNamePrefix", $hostpoolTemplate.namePrefix)
            $AddVMParams.Add("vmSize", $hostpoolTemplate.vmSize.id)
            $AddVMParams.Add("vmDiskType", $hostpoolTemplate.osDiskType)
            $AddVMParams.Add("vmUseManagedDisks", [bool]$hostpoolTemplate.UseManagedDisks)    
        }
        else{
            throw "unable to read hostpool template to get name prefix, size and disk type"
        }

        # Find where we are up to for numbering
        $TempArray = @()
        $VMs.Keys | where-object{$TempArray += [int]$_.SubString($_.LastIndexOf('-')+1)}
        $AddVMParams.Add("vmInitialNumber", [int](($TempArray | Measure-Object -Maximum).Maximum + 1))

        # Set the rest of the required parameters
        $AddVMParams.Add("vmLocation", $vmLocation)
        $AddVMParams.Add("virtualNetworkResourceGroupName", $virtualNetworkResourceGroupName)
        $AddVMParams.Add("existingVnetName", $existingVnetName)
        $AddVMParams.Add("existingSubnetName", $existingSubnetName)
        $AddVMParams.Add("domain", $domain)
        $AddVMParams.Add("ouPath", $ouPath)
        $AddVMParams.Add("vmNumberOfInstances", [int]($MinimumNumberOfVMs - $VMsWithCorrectImage.Count))
        $AddVMParams.Add("vmCustomImageSourceId", "$ImageID/versions/$ImageVersion")
        $AddVMParams.Add("vmResourceGroup", $ResourceGroupName)
        $AddVMParams.Add("vmImageType", "CustomImage")
        $AddVMParams.Add("deploymentId", ((New-Guid).Guid))
        $AddVMParams.Add("hostpoolName", $HostPoolName)

        $AddVMParams

        # Validate parameters
        # Ensure variables from KeyVault not empty
        $ParametersFromKeyVault = @('administratorAccountUsername','administratorAccountPassword','vmAdministratorAccountUsername','vmAdministratorAccountPassword')
        [string[]]$InvalidParams = @($ParametersFromKeyVault | Where-Object { [string]::IsNullOrWhiteSpace($AddVMParams["$_"]) })

        # Ensure image version exists
        If (!(Get-AzGalleryImageVersion -ResourceId $AddVMParams.vmCustomImageSourceId -ErrorAction Continue)){
            [string[]]$InvalidParams += "vmCustomImageSourceId"
        }

        # Ensure that the numbering is a positive number
        If ($AddVMParams.vmInitialNumber -lt 1){
            [string[]]$InvalidParams += "vmInitialNumber"
        }

        # Ensure the resource group containing the virtual network exists
        If (!(Get-AzResourceGroup -Name $AddVMParams.virtualNetworkResourceGroupName -ErrorAction Continue)){
            [string[]]$InvalidParams += "virtualNetworkResourceGroupName"            
        }

        # Ensure the virtual network exists
        $vnet = Get-AzVirtualNetwork -ResourceGroupName $AddVMParams.virtualNetworkResourceGroupName -Name $AddVMParams.existingVnetName -ErrorAction Continue
        If (!($vnet)){
            [string[]]$InvalidParams += "existingVnetName"
        }
        If (!($vnet.Subnets.Name -eq $AddVMParams.existingSubnetName)){
            [string[]]$InvalidParams += "existingSubnetName"
        }

        # Ensure the Azure region exists
        If ($AddVMParams.vmLocation -notin (Get-AzLocation).Location){
            [string[]]$InvalidParams += "vmLocation"
        }
        if ($InvalidParams) {
            throw "Invalid values for the following $($InvalidParams.Count) params: $($InvalidParams -join ', ')"
        }
    
        $AddVMjobs += New-AzResourceGroupDeployment -ResourceGroupName $ResourceGroupName -TemplateURI $TemplateURI -QueryString $QueryString -TemplateParameterObject $AddVMParams -AsJob

		# Wait for those jobs to add the session hosts
		Wait-ForJobs $AddVMjobs

        # Add additional checks to ensure HP is healthy / can service users
        # Healthy:
        #   VM.ProvisioningState = Succeeded
        #   VM.ImageReference.Id = $AddVMParams.vmCustomImageSourceId
        #   VM.PowerState = VM Running
        #   SessionHost.AllowNewSession = $true
        #   SessionHost.AgentVersion = Max(AgentVersion)
        #   SessionHost.Status = Available

        While ($true){
            # Get all session hosts
            $SessionHosts = @(Get-AzWvdSessionHost -ResourceGroupName $ResourceGroupName -HostPoolName $HostPoolName)

            # Get all VMs
            $VMs = Get-AzVM -Status

            Foreach ($SessionHost in $SessionHosts){
                If ($SessionHost.AllowNewSession -and $SessionHost.Status -eq 'Available'){
                    # Check if the session host found have the VM properties we are looking for
                    Write-Log "Checking VM: ProvisioningState: $(($VMs | where-object {$_.Id -eq $SessionHost.ResourceId}).ProvisioningState) - PowerState: $(($VMs | where-object {$_.Id -eq $SessionHost.ResourceId}).PowerState) - Image: $(($VMs | where-object {$_.Id -eq $SessionHost.ResourceId}).StorageProfile.ImageReference.Id)"
                    If ($VMs | where-object {$_.Id -eq $SessionHost.ResourceId -and $_.ProvisioningState -eq "Succeeded" -and $_.PowerState -eq "VM running" -and $_.StorageProfile.ImageReference.Id -eq $AddVMParams.vmCustomImageSourceId}){
                        Write-Log "Found at least one VM in desired state, continue"
                        $FoundVM = $true
                        break
                    }
                }
            }
            If ($FoundVM){
                break
            }
            Write-Log "No VMs found in desired state. Wait"
            start-sleep -Seconds 30
        }
        

    
    
		Write-Log 'All AddVM jobs completed'
    }

	# Check if we need to put any VMs in drain mode
	if ($VMsToPutInDrainMode.Count -gt 0) {
        Foreach ($VM in $VMsToPutInDrainMode.Values){
            TryUpdateSessionHostDrainMode -VM $VM -AllowNewSession:$false 
        }

		Write-Log 'Done putting VMs in drain mode'
    }

   	# Check if we need to remove any VMs
	if ($VMsToRemove.Count -gt 0) {
        [array]$RemoveVMjobs = @()
        foreach ($VM in $VMsToRemove.Values){
            # Array that contains jobs of removing virtual machines

            # Check that no sessions have been made since last check
            If ((Get-AzWvdSessionHost -ResourceGroupName $ResourceGroupName -HostPoolName $HostPoolName -Name $VM.SessionHostName).Session -gt 0){
                Write-Log "Someone logged in, don't remove"
            }
            else{
                Write-Log "Removing SessionHost: $($VM.Instance.Name)"
                # Note Remove-AzWvdSessionHost doesn't support -AsJob parameter
                Remove-AzWvdSessionHost -ResourceGroupName $ResourceGroupName -HostPoolName $HostPoolName -Name $VM.SessionHostName
    
                Write-Log "Removing VM: $($VM.Instance.Name)"
                $RemoveVMjobs += Remove-AzVM -ResourceGroupName $ResourceGroupName -Name $VM.Instance.Name -Force -AsJob    
            }

        }

		# Wait for those jobs to remove the virtual machines
		Wait-ForJobs $RemoveVMjobs
		Write-Log 'All Remove VM jobs completed'
    }


    Write-Log 'End'

    #endregion

}
catch {
	$ErrContainer = $PSItem
	# $ErrContainer = $_

	[string]$ErrMsg = $ErrContainer | Format-List -Force | Out-String
	$ErrMsg += "Version: $Version`n"

	if (Get-Command 'Write-Log' -ErrorAction:SilentlyContinue) {
		Write-Log -Err $ErrMsg -ErrorAction:Continue
	}
	else {
		Write-Error $ErrMsg -ErrorAction:Continue
	}

	# $ErrMsg += ($WebHookData | Format-List -Force | Out-String)

	throw [System.Exception]::new($ErrMsg, $ErrContainer.Exception)
}