$TaskCredential = Get-Credential -Message "Input username and new password for scheduled task(s) update."
Get-ScheduledTask | Where-Object { $_.Principal.UserId -eq $TaskCredential.UserName } | Set-ScheduledTask -User $TaskCredential.UserName -Password $TaskCredential.GetNetworkCredential().Password

# Reference
# https://serverfault.com/questions/1043188/update-task-scheduler-job-password-on-multiple-machines