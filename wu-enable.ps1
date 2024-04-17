<#
.SYNOPSIS
This script performs various actions to disable the SCCM client, block SCCM servers in the HOSTS file, reset Group Policy Objects, modify Windows Update settings, and schedule the script to run periodically.

.DESCRIPTION
The script first checks if the SCCM client is installed and uninstalls it silently if found. It then modifies the HOSTS file to block SCCM servers by adding entries for loopback IP addresses. Next, it resets Group Policy Objects by removing relevant registry keys and folders. After that, it sets a registry key to enable Windows Update. Finally, it schedules the script to run every 15 minutes and on startup using the Task Scheduler.

.PARAMETER None

.EXAMPLE
.\wu-enable.ps1
Runs the script to perform the actions described above.

.NOTES
Author: Mike Fara
Date: 2024.04.16
Version: 1.0
#>

# Uninstall SCCM Client silently
$SCCMClientUninstall = "C:\Windows\ccmsetup\ccmsetup.exe"
if (Test-Path $SCCMClientUninstall) {
    Invoke-Expression "$SCCMClientUninstall /uninstall /quiet /norestart"
    Write-Host "SCCM Client has been uninstalled silently."
} else {
    Write-Host "SCCM Client is not installed or the path is incorrect."
}

# Modify HOSTS file to block SCCM Servers
$hostsPath = "$env:windir\System32\drivers\etc\hosts"
$hostsContent = Get-Content -Path $hostsPath
$hostsEntries = @(
    "127.0.0.1 wmcsccm02.mydomain.com",
    "127.0.0.1 wmcsccm03.mydomain.com",
    "127.0.0.1 wmcsccm02",
    "127.0.0.2 wmcsccm03"
)

foreach ($entry in $hostsEntries) {
    if ($hostsContent -notcontains $entry) {
        Add-Content -Path $hostsPath -Value $entry
    }
}

Write-Host "SCCM servers have been blocked in the HOSTS file."

# Reset Group Policy Objects
try {
    if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft") { Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft" -Recurse -Force }
    if (Test-Path "$env:SystemRoot\System32\GroupPolicyUsers") { Remove-Item "$env:SystemRoot\System32\GroupPolicyUsers" -Recurse -Force }
    if (Test-Path "$env:SystemRoot\System32\GroupPolicy") { Remove-Item "$env:SystemRoot\System32\GroupPolicy" -Recurse -Force }
    if (Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies") { Remove-Item "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies" -Recurse -Force }
    if (Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects") { Remove-Item "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects" -Recurse -Force }
    if (Test-Path "HKCU:\SOFTWARE\Policies\Microsoft") { Remove-Item "HKCU:\SOFTWARE\Policies\Microsoft" -Recurse -Force }
} catch {
    Write-Host "Error resetting Group Policy Objects: $_"
}

# Set registry key for Windows Update
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
$registryKey = "DoNotConnectToWindowsUpdateInternetLocations"

If (-Not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force
}
Set-ItemProperty -Path $registryPath -Name $registryKey -Value 0

# Output to verify Windows Update setting change
Write-Host "DoNotConnectToWindowsUpdateInternetLocations: $((Get-ItemProperty -Path $registryPath).$registryKey)"

# Schedule this script to run every 15 minutes and on startup
$ScriptPath = "c:\temp\enable-wu.ps1"
$TaskName = "RunWUEnableScript"
$TaskDescription = "Runs a PowerShell script every 15 minutes to ensure Windows Update is enabled and SCCM is blocked."
$TaskFolderPath = "\"

# Check if the task already exists
if (-not (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)) {
    $nextMinute = (Get-Date).AddMinutes(1)
    $trigger = New-ScheduledTaskTrigger -Once -At $nextMinute -RepetitionInterval (New-TimeSpan -Minutes 15)
    $action = New-ScheduledTaskAction -Execute "C:\Program Files\PowerShell\7\pwsh.exe" -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$ScriptPath`""
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -DontStopOnIdleEnd -StartWhenAvailable
    $task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings
    Register-ScheduledTask -TaskName $TaskName -TaskPath "\" -InputObject $task

    Write-Host "Scheduled task created successfully and will run every 15 minutes and on startup."
} else {
    Write-Host "Scheduled task already exists. No action taken."
}

# Disable Group Policy Client Service
Set-Service -Name gpsvc -StartupType Disabled
Stop-Service -Name gpsvc -Force
Write-Host "Group Policy Client Service has been disabled and stopped."