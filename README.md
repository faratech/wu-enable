# SCCM Escape Kit

"For work environments where SCCM is still in use and completely mismanaged!"

In some environments, the management of SCCM (System Center Configuration Manager) can become mismanaged or encounter issues, leading to problems with Windows Update settings. This can result in a lack of control over the update process, which can be problematic for system administrators.

The SCCM Escape Kit is a PowerShell script designed to address these issues and help regain control over Windows Update settings. It performs a series of actions to disable the SCCM client, block SCCM servers, reset Group Policy Objects (GPOs), manage PowerShell 7 installation, and schedule the script to run periodically.

Disabling GPOs is necessary in this context because SCCM failures can sometimes lead to out-of-control group policies in legacy Active Directory (AD) environments. Group policies are a powerful tool used to manage and enforce settings across a network. However, when SCCM is mismanaged or fails, it can result in conflicting or incorrect group policies being applied to systems. By resetting the GPOs, the script helps ensure that the Windows Update settings are properly managed and controlled.

By using the SCCM Escape Kit, system administrators can regain control over their Windows Update settings and mitigate the impact of SCCM mismanagement or failures. It provides a systematic approach to address the issues caused by SCCM and helps maintain a stable and controlled environment for Windows updates.

## Features

- **Manage PowerShell 7 Installation**: The script checks if PowerShell 7 is installed. If not, it installs it. If it is installed, it checks if it's up to date and updates it if necessary.

- **Schedule Script**: The script is scheduled to run every 15 minutes and on startup using the Task Scheduler.

- **Block SCCM**: The script checks if the SCCM client is installed and uninstalls it if found. It then modifies the HOSTS file to block SCCM servers by adding entries for loopback IP addresses.

- **Reset Group Policy Objects**: The script resets Group Policy Objects by removing relevant registry keys and folders.

- **Enable Windows Update**: The script sets a registry key to enable Windows Update.

- **Disable Group Policy Service**: The script disables the Group Policy Client Service.

- **Force Group Policy Update**: The script forces a Group Policy update.

## Why SCCM Escape Kit?

In some work environments, SCCM is used to manage Windows Update settings. However, when SCCM is mismanaged, it can prevent you from receiving important updates or cause other issues. The SCCM Escape Kit is designed to help you regain control over your Windows Update settings by disabling SCCM and resetting Group Policy Objects.

## Usage

Run the script in PowerShell with administrative privileges:

```powershell
.\wu-enable.ps1
```

To uninstall or undo the changes made by the script, pass the `-uninstall` switch:

```powershell
.\wu-enable.ps1 -uninstall
```

## Notes

- The script must be run as the SYSTEM user to disable the Group Policy Client Service.
- The script must be run on a system that is part of a domain to force a Group Policy update.
- The script must be run with administrative privileges to perform most of its actions.

## Author

Mike Fara