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
#>
