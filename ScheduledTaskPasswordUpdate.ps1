#This function was taken directly from here: https://www.powershellgallery.com/packages/WFTools/0.1.39/Content/Test-Credential.ps1
function Test-Credential { 
    <#
    .SYNOPSIS
        Takes a PSCredential object and validates it

    .DESCRIPTION
        Takes a PSCredential object and validates it against a domain or local machine

        Borrows from a variety of sources online, don't recall which - apologies!

    .PARAMETER Credential
        A PScredential object with the username/password you wish to test. Typically this is generated using the Get-Credential cmdlet. Accepts pipeline input.

    .PARAMETER Context
        An optional parameter specifying what type of credential this is. Possible values are 'Domain','Machine',and 'ApplicationDirectory.' The default is 'Domain.'

    .PARAMETER ComputerName
        If Context is machine, test local credential against this computer.

    .PARAMETER Domain
        If context is domain (default), test local credential against this domain. Default is current user's

    .OUTPUTS
        A boolean, indicating whether the credentials were successfully validated.

    .EXAMPLE
        #I provide my AD account credentials
        $cred = get-credential

        #Test credential for an active directory account
        Test-Credential $cred

    .EXAMPLE
        #I provide local credentials here
        $cred = get-credential

        #Test credential for a local account
        Test-Credential -ComputerName SomeComputer -Credential $cred

    .EXAMPLE
        #I provide my AD account credentials for domain2
        $cred = get-credential

        #Test credential for an active directory account
        Test-Credential -Credential $cred -Domain domain2.com

    .FUNCTIONALITY
        Active Directory

    #>
    [cmdletbinding(DefaultParameterSetName = 'Domain')]
    param(
        [parameter(ValueFromPipeline=$true)]
        [System.Management.Automation.PSCredential]$Credential = $( Get-Credential -Message "Please provide credentials to test" ),

        [validateset('Domain','Machine', 'ApplicationDirectory')]
        [string]$Context = 'Domain',
        
        [parameter(ParameterSetName = 'Machine')]
        [string]$ComputerName,

        [parameter(ParameterSetName = 'Domain')]
        [string]$Domain = $null
    )
    Begin
    {
        Write-Verbose "ParameterSetName: $($PSCmdlet.ParameterSetName)`nPSBoundParameters: $($PSBoundParameters | Out-String)"
        Try
        {
            Add-Type -AssemblyName System.DirectoryServices.AccountManagement
        }
        Catch
        {
            Throw "Could not load assembly: $_"
        }
        
        #create principal context with appropriate context from param. If either comp or domain is null, thread's user's domain or local machine are used
        if ($Context -eq 'ApplicationDirectory' )
        {
            #Name=$null works for machine/domain, not applicationdirectory
            $DS = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::$Context)
        }
        elseif ($PSCmdlet.ParameterSetName -eq 'Domain')
        {
            $Context = $PSCmdlet.ParameterSetName
            $DS = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::$Context, $Domain)
        }
        elseif ($PSCmdlet.ParameterSetName -eq 'Machine')
        {
            $Context = $PSCmdlet.ParameterSetName
            $DS = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::$Context, $ComputerName)
        }

    }
    Process
    {
        #Validate provided credential
        $DS.ValidateCredentials($Credential.UserName, $Credential.GetNetworkCredential().password)
    }
    End
    {
        $DS.Dispose()
    }
}

#Source helper function for testing credentials. Needed if function is not provided above but rather specified in an alternate file in working directory.
#. .\Test-Credential.ps1

#Import Active Directory Module. (Requires prior installation. See here: https://www.varonis.com/blog/powershell-active-directory-module)
Try { Import-Module -Name ActiveDirectory -ErrorAction SilentlyContinue } Catch {}

write-output "`n"
write-output "`t`t`t   *#*# Scheduled Task Password Update *#*#"
write-output "`n** This script will attempt to update passwords for all scheduled tasks running under the provided username. **"
write-output "`n"

#Clear/Reset all variables
$comps = $compsInput = $compsFilePath = $readFileOrManualEntryOrAllNodes = $outputMode = 
$defaultOutFileName = $userPassedOutputFileName = $null
Try { $results.clear() } Catch {}
Try { $errors.clear() } Catch {}
$inputCancelled = $false
$localMachineOnly = $false

#Initialize object for list of comps
$comps = New-Object System.Collections.Generic.List[System.Object]

#Initialize object for list of results and errors
$results = New-Object System.Collections.Generic.List[System.Object]
$errors = New-Object System.Collections.Generic.List[System.Object]

#Determine On Which Nodes to Update Scheduled Task Passwords
##First, How Will Node List Be Provided...
do {
    $readFileOrManualEntryOrAllNodes = read-host -prompt "Node Selection: Read Input From File (1) or Manual Entry (2) or All Nodes (3) [Default = Localhost Only ; q = Quit]"
    If ($readFileOrManualEntryOrAllNodes -eq 'Q') { Exit }
    If (!$readFileOrManualEntryOrAllNodes) { 
        $localMachineOnly = $true
        $comps.Add($ENV:Computername)
    }
} 
while ($readFileOrManualEntryOrAllNodes -ne 1 -and $readFileOrManualEntryOrAllNodes -ne 2 -and 
       $readFileOrManualEntryOrAllNodes -ne 3 -and $localMachineOnly -eq $false)

##If inputting nodes as a text file...
If ($readFileOrManualEntryOrAllNodes -eq 1) {
    do {
        $compsFilePath = read-host -prompt "Hostname Input File"
        If ($compsFilePath -eq 'Q') { Exit }
        if (![string]::IsNullOrEmpty($compsFilePath) -and $compsFilePath -ne "Q") { 
            $fileNotFound = $(!$(test-path $compsFilePath -PathType Leaf))
            if ($fileNotFound) { write-output "`n`tFile '$compsFilePath' Not Found or Path Specified is a Directory!`n" }
        }
        if($fileNotFound) {
            write-output "`n** Remember To Enter Fully Qualified Filenames If Files Are Not In Current Directory **" 
            write-output "`n`tFile must contain one hostname per line.`n"
        }
    }
    while (([string]::IsNullOrEmpty($compsFilePath) -or $fileNotFound) -and 
            $compsFilePath -ne "B" -and $compsFilePath -ne "Q")
    $comps = Get-Content $compsFilePath -ErrorAction Stop
}

##Else if inputting nodes manually...
Elseif ($readFileOrManualEntryOrAllNodes -eq 2) {
    $compCount = 0
    write-output "`n`nEnter 'f' once finished. Minimum 1 entry. (Enter 'q' to exit.)`n"
    do {
        $compsInput = read-host -prompt "Hostname ($($compCount + 1))"
        If ($compsInput -eq 'Q') { Exit }
        if ($compsInput -ne "F" -and ![string]::IsNullOrEmpty($compsInput)) {
            if ($compsInput -eq 'localhost') { $compsInput = $ENV:Computername }
            $comps.Add($compsInput)
            $compCount++
            }
    }
    while (($compsInput -ne "F") -or ($compCount -lt 1))
}
##Else if all domain nodes...
Elseif ($readFileOrManualEntryOrAllNodes -eq 3) {
    Get-ADObject -LDAPFilter "(objectClass=computer)" | 
    #Where-Object { $_.Name -notlike "PCNVS*" -and $_.Name -notlike "DEVVS*" -and $_.Name -notlike "PCNVC*" } | 
    Select-Object Name | sort-object name | Set-Variable -Name compsTemp
    #Get-ADObject -SearchBase "OU=L30_PCN,OU=Assets,DC=wmgpcn,DC=local" -LDAPFilter "(objectClass=computer)" | 
    #Where-Object { $_.Name -notlike "PCNVS*" -and $_.Name -notlike "DEVVS*" -and $_.Name -notlike "PCNVC*" } | 
    #Select-Object Name | Set-Variable -Name compsTemp
    $compsTemp | ForEach-Object { $comps.Add($_.Name) }
}

#Determine if updates are only requested for the local machine...
If ($comps.Count -eq 1 -and $comps[0] -eq $ENV:Computername) { $localMachineOnly = $true }

#Determine Output Mode
do { 
    $outputMode = read-host -prompt "`nSave To File (1), Console Output (2), or Both (3) [Default=2]"
    if (!$outputMode) { $outputMode = 2 }
}
while ($outputMode -ne 1 -and $outputMode -ne 2 -and $outputMode -ne 3 -and
        $outputMode -ne "Q" -and $outputMode -ne "B")
if ($outputMode -eq "Q") { exit }

#If output is to include a file...
$defaultOutFileName = "TaskSchedulerCredentialUpdateOut-$(Get-Date -Format MMddyyyy_HHmmss).csv"

if ($outputMode -eq 1 -or $outputMode -eq 3) {
                
    Write-Output "`n* To save to any directory other than the current, enter fully qualified path name. *"
    Write-Output   "*              Leave this entry blank to use the default file name of               *"
    Write-Output   "*             '$defaultOutFileName',               *"
    Write-Output   "*                which will save to the current working directory.                  *"
    Write-Output   "*                                                                                   *"
    Write-Output   "*  THE '.csv' EXTENSION WILL BE APPENDED AUTOMATICALLY TO THE FILENAME SPECIFIED.   *`n"

    Do { 
        $fileName = read-host -prompt "Save As [Default=$defaultOutFileName]" 

        If ($fileName -and $fileName -eq "Q") { exit }

        $pathIsValid = $true
        $overwriteConfirmed = "Y"

        If (![string]::IsNullOrEmpty($fileName)) {

            $fileName += ".csv"
                                        
            $pathIsValid = Test-Path -Path $fileName -IsValid

            If ($pathIsValid) {
                        
                $fileAlreadyExists = Test-Path -Path $fileName

                If ($fileAlreadyExists) {

                    Do {

                        $overWriteConfirmed = Read-Host -prompt "File '$fileName' Already Exists. Overwrite (Y) or Cancel (N)"       
                        if ($overWriteConfirmed -eq "Q") { exit }
                        if ($overWriteConfirmed -eq "N") { $userPassedOutputFileName = $false }

                    } While ($overWriteConfirmed -ne "Y" -and $overWriteConfirmed -ne "N" -and $overWriteConfirmed -ne "B")
                }
            }

            Else { 
                Write-Output "* Path is not valid. Try again. ('b' to return to main, 'q' to quit.) *"
                $userPassedOutputFileName = $false
            }
        }
        Else { $fileName = $defaultOutFileName }
    }
    while (!$pathIsValid -or $overWriteConfirmed -eq "N")
}

If (!$localMachineOnly) {
    #Get Credential for Remote Connectivity:
    Do {
        $Credential = Get-Credential -Message "Input Credentials for Remote Connectivity.`r`n`r`nClick Cancel to Quit." -ErrorAction SilentlyContinue
        If ($Credential) {
        #Test for valid credentials
            $validRemotingCred = Test-Credential -Credential $Credential
            If (!$validRemotingCred) {
                $wshell = New-Object -ComObject Wscript.Shell
                $wshell.Popup("Invalid Credentials. Please Try Again.",0,"Invalid Credentials",0x0) >$null
            }
        }
        Else { Write-Output "`nUser cancelled credential input. Exiting..." ; Exit }
    }
    While (!$validRemotingCred)
}

#Get Credential for Task Scheduler Updates:
Do {
    If (!$localMachineOnly) {
        $TaskCredentialPromptMessage =  "Input username and new password for scheduled task(s) update. " +
                                        "Do NOT enter domain or machine qualified name. Input base username only. " +
                                        "The script will attempt to find tasks for the username provided both " +
                                        "with and without the caller's current domain qualifier. Local " +
                                        "machine qualifiers will also be attempted automatically, so do " +
                                        "NOT include a machine qualified username for local accounts. " +

                                        "`r`n`r`nException 1: If the target tasks are those running under " +
                                        "a user who is a member of an alternate domain [i.e. a domain " +
                                        "different than that of the user who is calling this script], a " +
                                        "domain qualifier can be used (e.g. myalternatedomain\username)." +
                                     
                                        "`r`n`r`nException 2: If the Powershell Active Directory Module " +
                                        "is not installed on the machine from which this script is called, " +
                                        "a domain qualifier can be used. However, note that in this case " +
                                        "if the username does not contain a domain qualifier for any given " +
                                        "target task configuration, the script will need to be run a 2nd time " + 
                                        "WITHOUT the domain qualifier [provided for the username] to update " + 
                                        "any such remaining tasks." +

                                        "`r`n`r`nMAKE SURE TO RUN POWERSHELL AS ADMINISTRATOR IF UPDATING TASKS ON " +
                                        "LOCALHOST. EXIT AND RERUN SCRIPT AS ADMINISTRATOR IF APPLICABLE" +
                                     
                                        "`r`n`r`nClick Cancel to quit."
    }
    Else {
        $TaskCredentialPromptMessage =  "Input username and new password for scheduled task(s) update. " +
                                        "Do NOT enter domain or machine qualified name. Input base username only. " +
                                        "The script will attempt to find tasks for the username provided both " +
                                        "with and without the caller's current domain qualifier. Local " +
                                        "machine qualifiers will also be attempted automatically, so do " +
                                        "NOT include a machine qualified username for local accounts. " +

                                        "`r`n`r`nMAKE SURE TO RUN POWERSHELL AS ADMINISTRATOR. EXIT AND RERUN IF " +
                                        "NECESSARY." +

                                        "`r`n`r`nClick Cancel to quit."
    }
    $TaskCredential = Get-Credential -Message $TaskCredentialPromptMessage -ErrorAction SilentlyContinue
    If ($TaskCredential) {
        #Test for valid credentials...
        ##Try domain account credential check...
        Try { $validTaskScheduleCred = Test-Credential -Credential $TaskCredential -ErrorAction SilentlyContinue }
        ##If that doesn't work, try local account check...
        Catch { $validTaskScheduleCred = Test-Credential -Credential $TaskCredential -ComputerName $ENV:Computername }
        If (!$inputCancelled -and !$validTaskScheduleCred) {
            $wshell = New-Object -ComObject Wscript.Shell
            $wshell.Popup("Invalid Credentials. Please Try Again.",0,"Invalid Credentials",0x0) >$null
        }
    }
    Else { Write-Output "`nUser cancelled task credential input. Exiting..." ; Exit }
}
While (!$validTaskScheduleCred)

#Determines current domain, needed in some cases for qualifying the username for scheduled tasks (see below). (Requires AD PS Module installation. See here: https://www.varonis.com/blog/powershell-active-directory-module)
Try { $domainObject = Get-ADDomain -Current LoggedOnUser -ErrorAction SilentlyContinue } Catch {}
If ($domainObject) { $currentDomain = $domainObject.Name }

Write-Output "`nPlease Wait. Processing..."

#For requests including remote machine(s)...
If (!$localMachineOnly) {
    #Developer's Note: Could alternatively use -CimSession parameter to Get-ScheduledTask and Set-ScheduledTask commands in place of Invoke-Command...
    $comps | ForEach-Object { 
        $thisComp = $_
        $thisResult = Invoke-Command -ComputerName $thisComp -Credential $Credential -ScriptBlock { 
            $userName = $args[0].Username
            $domainQualifiedUsername = "$($args[1])\$userName"                        #For domain accounts
            $machineQualifiedUsername = "$thisComp\$($TaskCredential.UserName)"       #For local accounts
            $passwd = ($args[0]).GetNetworkCredential().Password
            
            #Depending on the configuration of task scheduler...
            ##For domain accounts...
            ###Sometimes we need to use the non-domain/non-machine qualified username...
            $tasks1 = Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskPath -eq '\' -and $_.Principal.UserID -eq $userName }
            ###Sometimes we need to use the domain qualified username...
            $tasks2 = Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskPath -eq '\' -and $_.Principal.UserID -eq $domainQualifiedUsername }
            ##For local accounts...
            $tasks3 = Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskPath -eq '\' -and $_.Principal.UserID -eq $machineQualifiedUsername }

            #Process Updates...
            $tasks1 | ForEach-Object { Set-ScheduledTask -TaskName $_.TaskName -User $userName -Password $passwd }
            $tasks2 | ForEach-Object { Set-ScheduledTask -TaskName $_.TaskName -User $domainQualifiedUsername -Password $passwd } 
            $tasks3 | ForEach-Object { Set-ScheduledTask -TaskName $_.TaskName -User $machineQualifiedUsername -Password $passwd } 
            #If ($tasks1) { $tasks1 | Set-ScheduledTask -User $userName -Password $passwd } # This doesn't work on monthly triggered tasks...?
            #If ($tasks2) { $tasks2 | Set-ScheduledTask -User $domainQualifiedUsername -Password -passwd } # This doesn't work on monthly triggered tasks...?
            #If ($tasks3) { $tasks3 | Set-ScheduledTask -User $machineQualifiedUsername -Password -passwd } # This doesn't work on monthly triggered tasks...?

        } -ArgumentList $TaskCredential, $currentDomain -ErrorVariable errmsg 2>$null
        If($thisResult) { $thisResult | ForEach-Object { $results.Add($_) } }
        If($errmsg) { $errmsg | ForEach-Object { $errors.Add([PSCustomObject]@{'Hostname' = $thisComp ; 'Exception' = $_.Exception.Message } ) } }
        If(!$thisResult -and !$errmsg) { $errors.Add( [PSCustomObject]@{ 'Hostname' = $thisComp; 'Exception' = "No tasks found for '$($TaskCredential.Username)' on $thisComp" } ) } 
    }
}
#For localhost only requests...
Else {
    #Sometimes we need to use the non-domain qualified username...
    $tasks1 = Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskPath -eq '\' -and $_.Principal.UserID -eq $TaskCredential.UserName }
    #Sometimes we need to use the domain qualified username...
    $tasks2 = Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskPath -eq '\' -and $_.Principal.UserID -eq "$currentDomain\$($TaskCredential.UserName)" }
    #Try computer name qualifier also (only applies to localhost only requests)...
    $tasks3 = Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskPath -eq '\' -and $_.Principal.UserID -eq "$ENV:Computername\$($TaskCredential.UserName)" }
        
    #Process Updates...
    $tasks1 | ForEach-Object { 
        Try { Set-ScheduledTask -TaskName $_.TaskName -User $TaskCredential.UserName -Password $TaskCredential.GetNetworkCredential().Password -ErrorAction Stop -OutVariable +results >$null }
        Catch { $errors.Add( [PSCustomObject]@{ 'Hostname' = $ENV:Computername; 'Exception' = $_.Exception.Message } ) }
    }
    $tasks2 | ForEach-Object { 
        Try { Set-ScheduledTask -TaskName $_.TaskName -User "$currentDomain\$($TaskCredential.UserName)" -Password $TaskCredential.GetNetworkCredential().Password -ErrorAction Stop -OutVariable +results >$null }
        Catch { $errors.Add( [PSCustomObject]@{ 'Hostname' = $ENV:Computername; 'Exception' = $_.Exception.Message } ) }
    }
    $tasks3 | ForEach-Object { 
        Try { Set-ScheduledTask -TaskName $_.TaskName -User "$ENV:Computername\$($TaskCredential.UserName)" -Password $TaskCredential.GetNetworkCredential().Password -ErrorAction Stop -OutVariable +results >$null }
        Catch { $errors.Add( [PSCustomObject]@{ 'Hostname' = $ENV:Computername; 'Exception' = $_.Exception.Message } ) }
    }

    #Add PSComputerName Property to $results
    $results | Add-Member -Name PSComputerName -MemberType NoteProperty -Value $ENV:Computername -Force

    If(!$results -and !$errors) { $errors.Add( [PSCustomObject]@{ 'Hostname' = $thisComp; 'Exception' = "No tasks found for '$($TaskCredential.Username)' on $thisComp" } ) } 
}

If ($results -and ($outputMode -eq 2 -or $outputMode -eq 3)) {
    Write-Output "`n`n*Task Credentials Updated for '$($TaskCredential.Username)' on the Following Machines/Tasks:"
    $results | Format-Table -AutoSize @{n = 'Hostname' ; e = { $_.PSComputerName }}, @{n = 'Task Name' ; e = { $_.TaskName }}
}

If ($errors -and ($outputMode -eq 2 -or $outputMode -eq 3)) {
    Write-Output "`n**Errors Attempting to Update Task Credentials for '$($TaskCredential.Username)' on the Following Machines:"
    $errors | Format-Table -AutoSize Hostname, @{n = 'Exception' ; e = { $_.Exception }}
}

If ($outputMode -eq 1 -or $outputMode -eq 3 -and $results) {
    $outputString = "** Task Credentials Updated for '$($TaskCredential.Username)' on the Following Machines/Tasks:  **"
    Add-Content -Path $fileName -Value $outputString
    $results | Select-Object @{n = 'Hostname' ; e = { $_.PSComputerName }}, @{n = 'Task Name' ; e = { $_.TaskName }} |
               Sort-Object "Hostname" | ConvertTo-CSV -NoTypeInformation | Add-Content -Path $fileName
}
If ($outputMode -eq 1 -or $outputMode -eq 3 -and $errors) {
    $outputString = "`r`n** Errors: **"
    Add-Content -Path $fileName -Value $outputString
    $errors | Select-Object @{ n = 'Hostname' ; e = {$_.Hostname}},
                            @{ n = 'Exception' ; e = {$_.Exception}} |
              Sort-Object "Hostname" | ConvertTo-CSV -NoTypeInformation | Add-Content -Path $fileName
}
    
# References
# https://serverfault.com/questions/1043188/update-task-scheduler-job-password-on-multiple-machines
# https://devblogs.microsoft.com/scripting/powertip-use-powershell-to-display-pop-up-window/
# https://www.powershellgallery.com/packages/WFTools/0.1.39/Content/Test-Credential.ps1
# https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-addomain?view=windowsserver2022-ps
# https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/set-scheduledtask?view=windowsserver2022-ps
# https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/get-scheduledtask?view=windowsserver2022-ps
# https://stackoverflow.com/questions/36200749/how-do-you-add-more-property-values-to-a-custom-object
# https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/add-member?view=powershell-7.3