# Check-SenseHttpClient

## How to use this script
**Step1**: Download this script to your computer: https://raw.githubusercontent.com/yangsa666/mde-tools/main/Check-SenseNetTrace.ps1

> **NOTE**
> 
> - If you're blocked by execution policy, you can change the execution policy via this PowerShell command `Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser`. This requires admin privilege.
>
> - Ensure you have installed `Wireshark` on your device. And you need to add `Wireshark folder path` in the environment PATHs if it was not added.
> to verify this, you can run `tshark --version` in PowerShell terminal.
> To add the environment PATH, you can refer to this internet article: https://helpdeskgeek.com/windows-10/add-windows-path-environment-variable/


**Step2**: Open Powershell to locate the folder where the script is.

- For Windows, you can open Powershell directly. 

- For Mac, you need to install Powershell first, please refer to this doc for installation: https://docs.microsoft.com/en-us/powershell/scripting/install/installing-powershell-core-on-macos?view=powershell-7

**Step3**: Run `.\Check-SenseNetTrace.ps1 -NetTracePath "{path_of_your_nettrace.pcapng}" -ProxyAddress "{the_proxy_address}"`

**For example**: 
## Has proxy configured
`.\Check-SenseNetTrace.ps1 -NetTracePath "C:\Temp\NetTrace.pcapng" -ProxyAddress "10.0.0.101"`

`.\Check-SenseNetTrace.ps1 -NetTracePath "C:\Temp\NetTrace.pcapng" -ProxyAddress "proxy.domain.local"`

## Direct connection without proxy
`.\Check-SenseNetTrace.ps1 -NetTracePath "C:\Temp\NetTrace.pcapng"`