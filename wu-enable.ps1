param(
    [Parameter(Mandatory=$false)]
    [switch]$undo
)
$SCCMServers = @(
    "wmcsccm02.wcmc.com",
    "wmcsccm03.wcmc.com",
    "wmcsccm02",
    "wmcsccm03"
)
$ScriptRoot = "c:\temp\wu-enable"
$ScriptName = Split-Path -Path $PSCommandPath -Leaf
$ScriptPath = "$ScriptRoot\$ScriptName"
function AdminCheck {
    if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        # Check if the script is running in Visual Studio Code
        if ($host.Name -eq "Visual Studio Code Host") {
            Write-Host "Please restart Visual Studio Code with administrative privileges to run this script."
            exit
        }
        # The script is not running with administrative privileges, so relaunch it with administrative privileges
        # Create a new process start info
        $startInfo = New-Object System.Diagnostics.ProcessStartInfo
        # Set the file name to PowerShell
        $startInfo.FileName = if ($PSVersionTable.PSVersion.Major -ge 7) { "pwsh" } else { "powershell" }
        # Set the arguments to the script path
        $startInfo.Arguments = "-Command {& '" + $script:MyInvocation.MyCommand.Path + "'}"
        # Set the verb to run as
        $startInfo.Verb = "runas"
        # Start the new process
        [System.Diagnostics.Process]::Start($startInfo)
        # Exit the current script
        exit
    }
}
    function ManagePowerShellInstallation {
        # Check if PowerShell 7 is installed
        if (-not (Test-Path "C:\Program Files\PowerShell\7\pwsh.exe")) {
            # PowerShell 7 is not installed, so install it
            Write-Host "PowerShell 7 is not installed. Installing..."
            # Get the latest release from the GitHub API
            $latestRelease = Invoke-RestMethod -Uri "https://api.github.com/repos/PowerShell/PowerShell/releases/latest"
            # Get the download URL of the MSI installer for x64 systems
            $downloadUrl = $latestRelease.assets | Where-Object { $_.name -like "*-win-x64.msi" } | Select-Object -ExpandProperty browser_download_url
            # Download the installer
            Invoke-WebRequest -Uri $downloadUrl -OutFile "$env:TEMP\PowerShell-7-win-x64.msi"
            # Run the installer
            Start-Process -FilePath "$env:TEMP\PowerShell-7-win-x64.msi" -Args "/quiet" -Wait
            Write-Host "PowerShell 7 installed successfully."
        } else {
            # PowerShell 7 is installed, so check if it needs to be updated
            # Get the version of PowerShell 7
            $currentVersion = & "C:\Program Files\PowerShell\7\pwsh.exe" -Command { $PSVersionTable.PSVersion }
            # Get the latest release from the GitHub API
            $latestRelease = Invoke-RestMethod -Uri "https://api.github.com/repos/PowerShell/PowerShell/releases/latest"
            $latestVersion = [Version]$latestRelease.tag_name.Replace('v', '')
            if ($currentVersion -lt $latestVersion) {
                # PowerShell 7 is out of date, so update it
                Write-Host "PowerShell 7 is out of date. Updating..."
                # Get the download URL of the MSI installer for x64 systems
                $downloadUrl = $latestRelease.assets | Where-Object { $_.name -like "*-win-x64.msi" } | Select-Object -ExpandProperty browser_download_url
                # Create a job to download and install the update
                $job = Start-Job -ScriptBlock {
                    Invoke-WebRequest -Uri $using:downloadUrl -OutFile "$env:TEMP\PowerShell-7-win-x64.msi"
                    Start-Process -FilePath "$env:TEMP\PowerShell-7-win-x64.msi" -Args "/quiet" -Wait
                }
                # Wait for the job to complete
                $null = Receive-Job -Job $job -Wait
                # Remove the job
                Remove-Job -Job $job
                Write-Host "PowerShell 7 updated successfully."
            } else {
                # PowerShell 7 is up to date
                Write-Host "PowerShell 7 is up to date."
            }
        }
    }

function ScheduleScript ($undo) {
    # Schedule this script to run every 15 minutes and on startup
    $TaskName = "RunWUEnableScript"
    if (Test-Path "C:\Program Files\PowerShell\7\pwsh.exe") {
        $powershellPath = "C:\Program Files\PowerShell\7\pwsh.exe"
        $powerShellVersion = "7"
        } else {
        $powershellPath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        $powerShellVersion = "5.1"
        }
    if (-not $undo) {
        # Check if the task already exists
        if (-not (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)) {
            $nextMinute = (Get-Date).AddMinutes(1)
            $trigger = New-ScheduledTaskTrigger -Once -At $nextMinute -RepetitionInterval (New-TimeSpan -Minutes 15)            
            $action = New-ScheduledTaskAction -Execute $powershellPath -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$ScriptPath`""
            $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
            $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -DontStopOnIdleEnd -StartWhenAvailable
            $task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings
            Register-ScheduledTask -TaskName $TaskName -TaskPath "\" -InputObject $task

            Write-Host "Scheduled task created successfully and will run every 15 minutes and on startup."
        } else {
            Write-Host "Scheduled task already exists. No action taken."
        }
    } else {
        # Code to unschedule the script
        if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        }
    }
}

function BlockSCCM ($undo) {
    $SCCMClientUninstall = "C:\Windows\ccmsetup\ccmsetup.exe"
    $hostsPath = "$env:windir\System32\drivers\etc\hosts"
    $hostsContent = Get-Content -Path $hostsPath
    $hostsEntries = $SCCMServers | ForEach-Object {
        "127.0.0.1 $_"
        }
        if (-not $undo) {
    if (Test-Path $SCCMClientUninstall) {
        Invoke-Expression "$SCCMClientUninstall /uninstall /quiet /norestart"
        Write-Host "SCCM Client has been uninstalled silently."
    } else {
        Write-Host "SCCM Client is not installed or the path is incorrect."
    }

    foreach ($entry in $hostsEntries) {
        $hostsContent = Get-Content -Path $hostsPath
        if ($hostsContent -notcontains $entry) {
            Add-Content -Path $hostsPath -Value $entry
        } else {
            Write-Output "Entry '$entry' already exists in the HOSTS file. Skipping..."
        }
    }
    Write-Host "SCCM servers have been blocked in the HOSTS file."
} else {
    foreach ($entry in $hostsEntries) {
        if ($hostsContent -contains $entry) {
            $hostsContent = $hostsContent | Where-Object { $_ -ne $entry }
        }
    }
    if ((Get-Content -Path $hostsPath) -ne $hostsContent) {
        $hostsContent | Set-Content -Path $hostsPath
        Write-Host "SCCM servers have been unblocked in the HOSTS file."
        }
    }
}
function ResetGroupPolicyObjects ($undo){
    if (-not $undo) {
    try {
        if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft") { Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft" -Recurse -Force }
        if (Test-Path "$env:SystemRoot\System32\GroupPolicyUsers") { Remove-Item "$env:SystemRoot\System32\GroupPolicyUsers" -Recurse -Force }
        if (Test-Path "$env:SystemRoot\System32\GroupPolicy") { Remove-Item "$env:SystemRoot\System32\GroupPolicy" -Recurse -Force }
        if (Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies") { Remove-Item "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies" -Recurse -Force }
        if (Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects") { Remove-Item "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects" -Recurse -Force }
        if (Test-Path "HKCU:\SOFTWARE\Policies\Microsoft") { Remove-Item "HKCU:\SOFTWARE\Policies\Microsoft" -Recurse -Force }
        Write-Host "Group Policy Objects have been reset."
    } catch {
        Write-Host "Error resetting Group Policy Objects: $_"
    }
    } else {
        Write-Host "Group Policy Objects will not be reset."
    }
}
function EnableWindowsUpdate ($undo) {
    if (-not $undo) {
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"

    if (-Not (Test-Path $registryPath)) {
        New-Item -Path $registryPath -Force
    }

    Set-ItemProperty -Path $registryPath -Name "DoNotConnectToWindowsUpdateInternetLocations" -Value 0
    Write-Host "Windows Update settings have been configured to connect to Windows Update servers."
} else {
    if (Test-Path $registryPath) {
        Remove-Item -Path $registryPath -Recurse -Force
        Write-Host "Windows Update settings have been reset."
    }
    }
}
function DisableGroupPolicyService($undo) {
    if (-not $undo) {
    Set-Service -Name gpsvc -StartupType Disabled
    Stop-Service -Name gpsvc -Force
    Write-Host "Group Policy Client Service has been disabled and stopped."
} else {
    # Code to enable Group Policy Client Service
    if ((Get-Service -Name gpsvc).StartType -eq 'Disabled') {
        Set-Service -Name gpsvc -StartupType Automatic
        Start-Service -Name gpsvc
        Write-Host "Group Policy Client Service has been enabled and started."
    }
}
}
function ForceGroupPolicyUpdate($undo) {
if (-not $undo) {
    Write-Host "Group Policy update will not be forced."
} else { 
    Invoke-Expression "gpupdate /force"
    Write-Host "Group Policy update has been started in the background."
}
}
    # Main logic
    AdminCheck
    ManagePowerShellInstallation
    ScheduleScript($undo)
    BlockSCCM($undo)
    ResetGroupPolicyObjects($undo)
    EnableWindowsUpdate($undo)
    DisableGroupPolicyService($undo)
    ForceGroupPolicyUpdate($undo)