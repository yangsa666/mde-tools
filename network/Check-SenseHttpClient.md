# Check-SenseHttpClient

## How to use this script
**Step1**: Download this script to your computer: https://raw.githubusercontent.com/yangsa666/mde-tools/main/Check-SenseHttpClient.ps1

> **NOTE**
> 
> If you're blocked by execution policy, you can change the execution policy via this PowerShell command `Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser`. This requires admin privilege. 

**Step2**: Open Powershell to locate the folder where the script is.

- For Windows, you can open Powershell directly. 

- For Mac, you need to install Powershell first, please refer to this doc for installation: https://docs.microsoft.com/en-us/powershell/scripting/install/installing-powershell-core-on-macos?view=powershell-7

**Step3**: Run `.\Check-SenseHttpClient.ps1 -FullSenseFMTTxtFilePath {path of fullsenseclient-!FMT.txt}`

**For example**: `.\Check-SenseHttpClient.ps1 -FullSenseFMTTxtFilePath "C:\Temp\fullsenseclient-!FMT.txt"`
