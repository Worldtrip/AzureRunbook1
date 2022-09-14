#Get the date and create a log file
$date = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fffffff"
$logFile = "C:\temp\CadCorp\AzureImport"+ $(get-date -f "yyyyMMdd-HHmmss")+".txt"
#Define a logging function
function WriteMessage([string]$message,[string]$logFile)
	{
    Out-File -Filepath $logFile -InputObject $message -Append
	}

#########################################################################
#### Only need to install these following two modules once on the machine:
#########################################################################

#### see https://docs.microsoft.com/en-us/powershell/azure/active-directory/install-adv2?view=azureadps-2.0
#Install-Module AzureAD

####Download this PowerShell module and extract it to module path (See instructions on https://github.com/RamblingCookieMonster/PSSQLite)
#Install-Module PSSQLite

$time = Get-Date
$UKtime = [String]::Format("{0:HH:mm:ss}", $time)
Writemessage "* $UKtime *" $logfile

#Get the parameters from settings.json
Writemessage "Reading settings json file..." $logfile
try {
#$config = Get-Content -Path $PSScriptRoot\settings.json -Raw | ConvertFrom-Json
$config = Get-Content -Path .\settings.json -Raw | ConvertFrom-Json
} catch {
Writemessage $error[0] $logfile
}
$WebMapDataSource = $config.Connection_Parameters.WebMapDatabase
$tennantId = $config.Connection_Parameters.tenant
$azureuserFilter = $config.Connection_Parameters.UserFilter
$groupFilter = $config.Connection_Parameters.GroupFilter
$groupFilterAZ = $config.Connection_Parameters.GroupFilterAZ
$password = $config.Connection_Parameters.Password
$user = $config.Connection_Parameters.User
$password = $config.Connection_Parameters.Password

#Check the supplied WebMap sqlite database path exists
if (Test-Path $WebMapDataSource)
{


# connect to the azure ad, there are many methods of connecting, but we'll keep it simple here
#########################################################################
#### see https://docs.microsoft.com/en-us/powershell/module/azuread/connect-azuread?view=azureadps-2.0
#########################################################################
# we'll supply the user id and password of the Azure AD we want the users from 

$SecPass = ConvertTo-SecureString $password -AsPlainText -Force
#$Cred = New-Object System.Management.Automation.PSCredential ($user, $SecPass)
$Cred = New-Object System.Management.Automation.PSCredential ($user)
try{ connect-azuread -Credential $cred } catch { WriteMessage "Could not connect to the Azure AD." $logFile throw $_ stop }

#Get the array of AD users
#$azureusers = Get-AzureADUser -Filter $azureuserFilter

#########################################################################
#### see https://docs.microsoft.com/en-us/powershell/module/azuread/get-azureaduser?view=azureadps-2.0
#########################################################################
#Get the Azure AD users array
WriteMessage "Getting Azure AD users..." $logFile
try{
#### NEW
#$azureusers = Get-AzureADUser -All $true -Filter $azureuserFilter
$targetGroups = Get-AzureADGroup -Filter $groupFilter
foreach ($targetGroup in $targetGroups) {
    Write-Host("Reading in members of Azure AD group "+$targetGroup.DisplayName)
    $azureusers += Get-AzureADGroupMember -ObjectId $targetGroup.ObjectId -All $true
    }
}
catch 
{
WriteMessage "Could not obtain Azure AD users." $logFile
WriteMessage $_ $logFile
}

#Get the ApplicationId from WebMap security_Applications table
WriteMessage "Getting Application ID..." $logFile
$security_application_query = "SELECT * FROM security_Applications"
try
{
$applications = Invoke-SqliteQuery -DataSource $WebMapDataSource -Query $security_application_query -ErrorAction Stop
}
catch
{
WriteMessage "Could not obtain Application ID. Statement: $security_application_query" $logFile
WriteMessage $error[0] $logFile
}

#Get the Azure AD groups array
WriteMessage "Getting Azure AD groups..." $logFile
try{
$azuregroups = Get-AzureADGroup -All $true -Filter $groupFilter

}catch{
WriteMessage "Could not obtain Azure AD groups." $logFile
WriteMessage $_ $logFile
}

#Get the list of current Web Map users from security_users
WriteMessage "Getting WebMap users..." $logFile
$wmquery = "SELECT * FROM security_Users"
try{
$wmusers = Invoke-SqliteQuery -DataSource $WebMapDataSource -Query $wmquery -ErrorAction Stop
}
catch
{
WriteMessage "Could not obtain list of current WebMap users. Statement: $wmquery" $logFile
WriteMessage $error[0].InvocationInfo.PositionMessage $logFile
}

#Get the list of current Web Map roles from security_Roles
WriteMessage "Getting WebMap groups..." $logFile
$wmrolequery = "SELECT * FROM security_Roles"
try{
$wmroles = Invoke-SqliteQuery -DataSource $WebMapDataSource -Query $wmrolequery -ErrorAction Stop
}
catch
{
WriteMessage "Could not obtain list of current WebMap users. Statement: $wmquery" $logFile
WriteMessage $error[0].InvocationInfo.PositionMessage $logFile
}

#Build User ID and Name arrays from WebMap, we'll use these to compare against Azure values
$wmuserIDs = [System.Collections.Generic.List[PSObject]]::new()
$wmusernames = [System.Collections.Generic.List[PSObject]]::new()
foreach ($wmuser in $wmusers){
$wmuserObj = new-object PSObject
$wmusernameObj = new-object PSObject
$wmuserObj | add-member -membertype NoteProperty -name "Id" -value $wmuser.UserId
$wmusernameObj | add-member -membertype NoteProperty -name "Name" -value $wmuser.UserName
$wmuserObj = [GUID]$wmuserObj.'Id'
$wmuserIDs.add($wmuserObj)
$wmusernames.add($wmusernameObj)
}


if($azuregroups -ne $null -and $azuregroups.Length -gt 0){
    #Scan through the array and build a list of group IDs
    $azuregroupIDs = [System.Collections.Generic.List[PSObject]]::new()
    WriteMessage "Comparing groups..." $logFile
    foreach ($azuregroup in $azuregroups){
        $groupIDObj = new-object PSObject
        $groupIDObj | add-member -membertype NoteProperty -name "Group" -value $azuregroup.ObjectID
        $groupIDObj = [GUID]$groupIDObj.'Group'
        $azuregroupIDs.add($groupIDObj)
        $azuregroupname = $azuregroup.DisplayName
        $azuregroupdescription = $azuregroup.Description

        #Check the Azure group exists in WebMap 
        $wmgroupquery = "SELECT security_Roles.RoleId, security_Roles.RoleName, security_Roles.Description FROM security_Roles WHERE security_Roles.RoleId=@azuregroup"
        try{
        $groupincommon = Invoke-SqliteQuery -DataSource $WebMapDataSource -Query $wmgroupquery -ErrorAction Stop -SqlParameters @{
        azuregroup=[GUID]$azuregroup.ObjectId
        }
        }
        catch 
        {
        WriteMessage "Could not select group record from WebMap database. Statement: $wmgroupquery" $logFile
        WriteMessage $error[0] $logFile
        }
         #If query returns a value, then group exists
           if ($groupincommon -ne $null){
               #Compare group names are the same, if not then update
               if ($groupincommon.RoleName -ne $azuregroupname) {
                   $groupnameupdatequery = "UPDATE security_Roles SET RoleName=@newgroupname, LoweredRoleName=@newloweredgroupname WHERE RoleId=@newgroupid"
                   try{
                   Invoke-SqliteQuery -DataSource $WebMapDataSource -Query $groupnameupdatequery -ErrorAction Stop -SqlParameters @{
                   newgroupname = $azuregroupname
                   newloweredgroupname = $azuregroupname.ToLower()
                   newgroupid=[GUID]$azuregroup.ObjectId  
                   }
                   WriteMessage "Updating group name: '$($groupincommon.RoleName)' to: '$azuregroupname'"  $logFile
                   }
                   catch 
                   {
                    WriteMessage "Could not update role name. Statement: $groupnameupdatequery" $logFile
                    WriteMessage $error[0] $logFile
                   }
                } 
                  #Compare group descriptions are the same, if not then update
               if ($groupincommon.Description -ne $azuregroupdescription) {
                   $groupdescupdatequery = "UPDATE security_Roles SET Description=@newgroupdesc WHERE RoleId=@newgroupid"
                   try{
                   Invoke-SqliteQuery -DataSource $WebMapDataSource -Query $groupdescupdatequery -ErrorAction Stop -SqlParameters @{
                   newgroupdesc = $azuregroupdescription
                   newgroupid=[GUID]$azuregroup.ObjectId  
                   }
                   WriteMessage "Updating group description: '$($groupincommon.Description)' to: '$azuregroupdescription'"  $logFile
                   }
                   catch 
                   {
                    WriteMessage "Could not update role name. Statement: $groupnameupdatequery" $logFile
                    WriteMessage $error[0] $logFile
                   }
                }
                } 
           Else{   #Then the Azure group doesn't already exists in the WebMap database            
                   #Check group DisplayName already exists to avoid breaking UNIQUE constraint
                   $wmgroupquery = "SELECT * FROM security_Roles WHERE security_Roles.RoleName=@azuregroupname"
                   $commongroupname = Invoke-SqliteQuery -DataSource $WebMapDataSource -Query $wmgroupquery -ErrorAction Stop -SqlParameters @{
                   azuregroupname=$azuregroupname
                   }
                   #If the query is null, then group doesn't exist so add it
                   if ($commongroupname -eq $null){               
                       #Add new group to security_Roles table
                       $queryroles = "INSERT INTO main.security_Roles (ApplicationId, RoleId, RoleName, LoweredRoleName, Description) VALUES (@applicationid, @roleid, @webmaprole,@loweredwebmaprole,@desc)"
                       try{
                       Invoke-SqliteQuery -DataSource $WebMapDataSource -Query $queryroles -ErrorAction Stop -SqlParameters @{
                       applicationid = $applications.ApplicationId
                       webmaprole =  $azuregroupname
                       roleid = [GUID]$azuregroup.ObjectID
                       loweredwebmaprole =  $azuregroupname.ToLower()
                       desc = $azuregroupdescription
                       }
                       WriteMessage "Adding Azure AD group: $($azuregroup.DisplayName)'"  $logFile
                       }
                       catch 
                       {
                       WriteMessage "Could not insert new group in security_Roles table of WebMap database. Statement: $queryroles" $logFile
                       WriteMessage $error[0] $logFile
                       }
                    }              


}
}
}

#Get User ID values from Azure $azureusers array built in line 37
if ($azureusers -ne $null -and $azureusers.Length -gt 0){
   $AzureuserIDs = [System.Collections.Generic.List[PSObject]]::new()
   WriteMessage "Comparing users..." $logFile
    #Loop through each Azure user and build a list 
    foreach ($azureuser in $azureusers){
        if ($azureuser.AccountEnabled) {
            $AzureuserObj = new-object PSObject 
            $AzureuserObj | add-member -membertype NoteProperty -name "Azure" -value $azureuser.ObjectID
            $AzureuserObj = [GUID]$AzureuserObj.'Azure'
            $AzureUserIDs.Add($AzureuserObj)
            $azurename = $azureuser.DisplayName
            $azureuseremail = $azureuser.Mail

            #Check the Azure AD user exists in WebMap 
            $wmquery = "SELECT security_Users.UserId, security_Users.UserName, security_Membership.Email FROM security_Users INNER JOIN security_Membership ON security_Users.UserId=security_Membership.UserId WHERE security_Users.UserId=@azureuser"
            try{
                $userincommon = Invoke-SqliteQuery -DataSource $WebMapDataSource -Query $wmquery -ErrorAction Stop -SqlParameters @{
                azureuser=[GUID]$azureuser.ObjectId
                }
    
            }
            catch {
                WriteMessage "Could not select user record from WebMap database. Statement: $wmquery" $logFile
                WriteMessage $error[0] $logFile
                }
     
            #If query returns a value, then user exists
            if ($userincommon -ne $null){
               #Compare names are the same, if not then update
               if ($userincommon.UserName -ne $azurename) {
                   $usernameupdatequery = "UPDATE security_Users SET UserName=@newusername, LoweredUserName=@newloweredusername WHERE UserId=@azureuser"
                   try{
                   Invoke-SqliteQuery -DataSource $WebMapDataSource -Query $usernameupdatequery -ErrorAction Stop -SqlParameters @{
                   newusername = $azurename
                   newloweredusername = $azurename.ToLower()
                   azureuser=[GUID]$azureuser.ObjectId  
                   }
                   WriteMessage "Updating user name: '$($userincommon.UserName)' to: '$azurename'"  $logFile
                   }
                   catch 
                   {
                    WriteMessage "Could not update user name. Statement: $usernameupdatequery" $logFile
                    WriteMessage $error[0] $logFile
                   }
               } 
       
               #Compare emails are the same, if not then update
               if ($userincommon.Email -ne $azureuseremail) {
                   #Some emmail values could be null
                   if ($azureuseremail -ne $null){
                       $newemail = $azureuseremail                    
                       } else{
                       $newemail = ''
                       }
                   $emailupdatequery = "UPDATE security_Membership SET Email=@newemail, LoweredEmail=@newloweredemail WHERE UserId=@azureuser"
                   try{
                   Invoke-SqliteQuery -DataSource $WebMapDataSource -Query $emailupdatequery -ErrorAction Stop -SqlParameters @{
                   newemail = $newemail
                   newloweredemail = $newemail.ToLower()
                   azureuser=[GUID]$azureuser.ObjectId  
                   }
                   WriteMessage "Updating email address: '$($userincommon.Email)' to: '$azureuseremail'"  $logFile
                   }
                   catch
                   {
                    WriteMessage "Could not update email address. Statement: $emailupdatequery" $logFile
                    WriteMessage $error[0] $logFile
                   }
               }
       
           } Else{   #Then the Azure user doesn't already exists in the WebMap database
              
                   #Check user DisplayName already exists to avoid breaking UNIQUE constraint
                   $wmuserquery = "SELECT * FROM security_Users WHERE security_Users.UserName=@azurename"
                   $commonusername = Invoke-SqliteQuery -DataSource $WebMapDataSource -Query $wmuserquery -ErrorAction Stop -SqlParameters @{
                   azurename=$azurename
                   }
                   #If null, then go ahead and add new user
                   if ($commonusername -eq $null){
               
                       #Add new user to security_Users table
                       $queryusers = "INSERT INTO main.security_Users (ApplicationId, UserId, UserName, LoweredUserName,LastActivityDate) VALUES (@applicationid, @userid, @webmapuser,@loweredwebmapuser,@lastactivedate)"
                       try{
                       Invoke-SqliteQuery -DataSource $WebMapDataSource -Query $queryusers -ErrorAction Stop -SqlParameters @{
                       applicationid = $applications.ApplicationId
                       webmapuser = $azureuser.DisplayName
                       userid = [GUID]$azureuser.ObjectID
                       loweredwebmapuser = $azureuser.DisplayName.ToLower()
                       lastactivedate = $date
                       }
                       WriteMessage "Adding Azure AD user: '$azurename'"  $logFile
                       Write-Host("Adding Azure AD user: '$azurename'")
                       }
                       catch 
                       {
                       WriteMessage "Could not insert new user in security_Users table of WebMap database. Statement: $queryusers" $logFile
                       Write-Host ("Could not insert new user in security_Users table of WebMap database. Statement: $queryusers")
                       WriteMessage $error[0] $logFile
                       }
                       #Add new user to security_Membership table
                       $querymembership = "INSERT INTO main.security_Membership (ApplicationId, UserId, SecurityStamp, PasswordHash,Email,LoweredEmail,IsApproved,IsLockedOut,CreateDate,LastLoginDate,LastPasswordChangedDate,LastLockoutDate,FailedPasswordAttemptCount,FailedPasswordAttemptWindowStart,FailedPasswordAnswerAttemptCount,FailedPasswordAnswerAttemptWindowStart,Comment) VALUES (@applicationid, @userid, @securitystamp,@passwordhash,@email,@loweredemail,0,0,'0001-01-01 00:00:00','0001-01-01 00:00:00','0001-01-01 00:00:00','0001-01-01 00:00:00',0,'0001-01-01 00:00:00',0,'0001-01-01 00:00:00',@comment)"
                       try{
                       Invoke-SqliteQuery -DataSource $WebMapDataSource -Query $querymembership -ErrorAction Stop -SqlParameters @{
                       applicationid = $applications.ApplicationId
                       userid = [GUID]$azureuser.ObjectID
                       securitystamp = New-Guid
                       passwordhash = 'AD User'
                       email = $azureuser.UserPrincipalName
                       loweredemail = $azureuser.UserPrincipalName.ToLower()
                       comment = 'AD User'
                       }
                       }
                       catch 
                       {
                       WriteMessage "Could not insert new user in security_Membership table of WebMap database. Statement: $querymembership" $logFile
                       WriteMessage $error[0] $logFile
                       }
                       $UserNameToAdd = $commonusername.UserName
                    }              
           }
        }
    }
}

#When all users have been either updated or added we need to check for removed users
WriteMessage "Checking for removed users..." $logFile
foreach ($wmuserID in $wmuserIDs){
     if ($AzureUserIDs -notcontains $wmuserID){

        try{
        #If not in Azure Ad, select the user (to get name) and remove from 5 tables:

        #Get the user name:
        $wmusertodeletequery = "SELECT security_Users.UserName FROM security_Users WHERE security_Users.UserId=@wmusertodelete"
        $wmnonexistinguser = Invoke-SqliteQuery -DataSource $WebMapDataSource -Query $wmusertodeletequery -ErrorAction Stop -SqlParameters @{
        wmusertodelete=$wmuserID
        }
        $UserNameToDelete = $wmnonexistinguser.UserName
        WriteMessage "Deleting '$UserNameToDelete' from WebMap users." $logFile

        #Delete the user from MapUsers:
        $wmusertodeletequery = "DELETE FROM MapUsers WHERE MapUsers.UserId=@wmusertodelete"
        Invoke-SqliteQuery -DataSource $WebMapDataSource -Query $wmusertodeletequery -ErrorAction Stop -SqlParameters @{
        wmusertodelete=$wmuserID
        }
         #Delete the user from UserAddIns:
        $wmusertodeletequery = "DELETE FROM UserAddIns WHERE UserAddIns.UserId=@wmusertodelete"
        Invoke-SqliteQuery -DataSource $WebMapDataSource -Query $wmusertodeletequery -ErrorAction Stop -SqlParameters @{
        wmusertodelete=$wmuserID
        }
         #Delete the user from security_UsersInRoles:
        $wmusertodeletequery = "DELETE FROM security_UsersInRoles WHERE security_UsersInRoles.UserId=@wmusertodelete"
        Invoke-SqliteQuery -DataSource $WebMapDataSource -Query $wmusertodeletequery -ErrorAction Stop -SqlParameters @{
        wmusertodelete=$wmuserID
        }
         #Delete the user from security_Membership:
        $wmusertodeletequery = "DELETE FROM security_Membership WHERE security_Membership.UserId=@wmusertodelete"
        Invoke-SqliteQuery -DataSource $WebMapDataSource -Query $wmusertodeletequery -ErrorAction Stop -SqlParameters @{
        wmusertodelete=$wmuserID
        }
         #Delete the user from security_Users:
        $wmusertodeletequery = "DELETE FROM security_Users WHERE security_Users.UserId=@wmusertodelete"
        Invoke-SqliteQuery -DataSource $WebMapDataSource -Query $wmusertodeletequery -ErrorAction Stop -SqlParameters @{
        wmusertodelete=$wmuserID
        }
        } catch{
        WriteMessage "Could not delete user from WebMap database. Statement: $wmusertodeletequery" $logFile
        WriteMessage $error[0] $logFile
        }
        }      
}

WriteMessage "Checking for removed groups..." $logFile
foreach ($wmrole in $wmroles){
     if ($azuregroupIDs -notcontains $wmrole.RoleId){

        try{
        #If not in Azure Ad, select the role (to get name) and remove:

        #Get the role name:
        $wmroletodeletequery = "SELECT security_Roles.RoleName FROM security_Roles WHERE security_Roles.RoleId=@wmusertodelete"
        $wmnonexistingrole = Invoke-SqliteQuery -DataSource $WebMapDataSource -Query $wmroletodeletequery -ErrorAction Stop -SqlParameters @{
        wmusertodelete=$wmrole.RoleID
        }
        $RoleNameToDelete = $wmnonexistingrole.RoleName
        WriteMessage "Deleting '$RoleNameToDelete' from WebMap roles." $logFile

        #Delete the role:
        $wmroletodeletequery = "DELETE FROM security_Roles WHERE security_Roles.RoleId=@wmroletodelete"
        Invoke-SqliteQuery -DataSource $WebMapDataSource -Query $wmroletodeletequery -ErrorAction Stop -SqlParameters @{
        wmroletodelete=$wmrole.RoleID
        }
        } catch{
        WriteMessage "Could not delete role from WebMap database. Statement: $wmroletodeletequery" $logFile
        WriteMessage $error[0] $logFile
        }
        }      
}

} else {
WriteMessage "WebMap database not found."
}
WriteMessage "Finished." $logfile
$time = Get-Date
$UKtime = [String]::Format("{0:HH:mm:ss}", $time)
Writemessage "* $UKtime *" $logfile
