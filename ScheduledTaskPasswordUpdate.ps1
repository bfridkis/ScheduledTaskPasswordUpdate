#Source helper function for testing credentials
. \\pcngas01\installs\Scripts\ScheduledTaskPasswordUpdate\Test-Credential.ps1

#Import Active Directory Module. (Requires prior installation. See here: https://www.varonis.com/blog/powershell-active-directory-module)
Import-Module -Name ActiveDirectory

write-output "`n"
write-output "`t`t`t   *#*# Scheduled Task Password Update *#*#"
write-output "\`n** This script will attempt to update passwords for all scheduled tasks running under the provided username. **"
write-output "`n"

#Clear all variables
$comps = $compsInput = $compsFilePath = $readFileOrManualEntryOrAllNodes = $outputMode = $defaultOutFileName = $userPassedOutputFileName = $null
Try { $results.clear() } Catch {}
Try { $errors.clear() } Catch {}

#Initialize object for list of comps
$comps = New-Object System.Collections.Generic.List[System.Object]

#Initialize object for list of results and errors
$results = New-Object System.Collections.Generic.List[System.Object]
$errors = New-Object System.Collections.Generic.List[System.Object]

#Determine On Which Nodes to Update Scheduled Task Passwords
##First, How Will Node List Be Provided...
do {
    $readFileOrManualEntryOrAllNodes = read-host -prompt "Node Selection: Read Input From File (1) or Manual Entry (2) or All Nodes (3) [Default = Manual Entry]"
    If ($readFileOrManualEntryOrAllNodes -eq 'Q') { Exit }
    If (!$readFileOrManualEntryOrAllNodes) { $readFileOrManualEntryOrAllNodes = 2 }
} 
while ($readFileOrManualEntryOrAllNodes -ne 1 -and $readFileOrManualEntryOrAllNodes -ne 2 -and $readFileOrManualEntryOrAllNodes -ne 3)

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
    $compsInput = "TRUE"
}

#Determine Output Mode
do { 
    $outputMode = read-host -prompt "`nSave To File (1), Console Output (2), or Both (3) [Default=3]"
    if (!$outputMode) { $outputMode = 3 }
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

#Get Credential for Remote Connectivity:
Do {
    $Credential = Get-Credential -Message "Input Credentials for Remote Connectivity"
    $validRemotingCred = Test-Credential -Credential $Credential
    If (!$validRemotingCred) {
        $wshell = New-Object -ComObject Wscript.Shell
        $wshell.Popup("Invalid Credentials. Please Try Again.",0,"Invalid Credentials",0x0) >$null
    }
}
While (!$validRemotingCred)

#Get Credential for Task Scheduler Updates:
Do {
    $TaskCredential = Get-Credential -Message "Input username and new password for scheduled task(s) update. (Do NOT enter domain qualified name. Input base username only.)"
    $validTaskScheduleCred = Test-Credential -Credential $TaskCredential
    If (!$validTaskScheduleCred) {
        $wshell = New-Object -ComObject Wscript.Shell
        $wshell.Popup("Invalid Credentials. Please Try Again.",0,"Invalid Credentials",0x0) >$null
    }
}
While (!$validTaskScheduleCred)

#Determines current domain, needed in some cases for qualifying the username for scheduled tasks (see below).
$currentDomain = (Get-ADDomain -Current LoggedOnUser).Name

Write-Output "`nPlease Wait. Processing..."

$comps | ForEach-Object { 
    $thisComp = $_
    $thisResult = Invoke-Command -ComputerName $thisComp -Credential $Credential -ScriptBlock { 
        $userName = $args[0].Username
        $domainQualifiedUsername = "$($args[1])\$userName"
        $passwd = ($args[0]).GetNetworkCredential().Password
        
        #Sometimes we need to use the non-domain qualified username...
        $tasks1 = Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskPath -eq '\' -and $_.Principal.UserID -eq $userName }
        #Sometimes we need to use the domain qualified username...
        $tasks2 = Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskPath -eq '\' -and $_.Principal.UserID -eq $domainQualifiedUsername }
        
        #Process Updates...
        $tasks1 | ForEach-Object { Set-ScheduledTask -TaskName $_.TaskName -User $userName -Password $passwd }
        $tasks2 | ForEach-Object { Set-ScheduledTask -TaskName $_.TaskName -User $domainQualifiedUsername -Password $passwd } 
        #If ($tasks1) { $tasks1 | Set-ScheduledTask -User $userName -Password ($args[0]).GetNetworkCredential().Password } # This doesn't work on monthly triggered tasks...?
        #If ($tasks2) { $tasks2 | Set-ScheduledTask -User $domainQualifiedUsername -Password ($args[0]).GetNetworkCredential().Password } # This doesn't work on monthly triggered tasks...?

    } -ArgumentList $TaskCredential, $currentDomain -ErrorVariable errmsg 2>$null
    If($thisResult) { $thisResult | ForEach-Object { $results.Add($_) } }
    If($errmsg) { $errmsg | ForEach-Object { $errors.Add([PSCustomObject]@{'Hostname' = $thisComp ; 'Exception' = $_.Exception.Message } ) } }
    If(!$thisResult -and !$errmsg) { $errors.Add( [PSCustomObject]@{ 'Hostname' = $thisComp; 'Exception' = "No tasks found for '$($TaskCredential.Username)' on $thisComp" } ) } 
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