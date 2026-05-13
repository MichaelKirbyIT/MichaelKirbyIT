<#
.SYNOPSIS
    This PowerShell script ensures that the maximum size of the Windows Application event log is at least 32768 KB (32 MB).

.NOTES
    Author          : Michael Kirby
    LinkedIn        : https://www.linkedin.com/in/wmkirby/
    GitHub          : https://github.com/MichaelKirbyIT
    Date Created    : 2026-05-13
    Last Modified   : 2026-05-13
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-AU-000500
    Documentation   : https://stigaview.com/products/win11/v2r7/WN11-AU-000500/

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\__remediation_template(STIG-ID-WN11-AU-000500).ps1 
#>

# Define the Registry Path and Value
$registryPath = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application"
$name = "MaxSize"
$value = 32768 # This is 0x00008000 in hex

# 1. Check if the path exists; if not, create it
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
    Write-Host "Created missing registry path: $registryPath" -ForegroundColor Yellow
}

# 2. Set the MaxSize value to 32768 (REG_DWORD)
Set-ItemProperty -Path $registryPath -Name $name -Value $value -Type DWord

# 3. Verify the change
$currentValue = Get-ItemProperty -Path $registryPath -Name $name
Write-Host "Success: $registryPath\$name is now set to $($currentValue.MaxSize) KB." -ForegroundColor Cyan
