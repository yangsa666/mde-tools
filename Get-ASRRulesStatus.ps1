
$RuleGUIDShort = @{ 
    "01443614-cd74-433a-b99e-2ecdc07bfc25" = "BlockUntrustedExecFiles"
    "26190899-1602-49e8-8b27-eb1d0a1ce869" = "BlockCommunicationCreateChildProc"
    "33ddedf1-c6e0-47cb-833e-de6133960387" = "BlockSafeModeRebootRule"
    "3b576869-a4ec-4529-8536-b80a7769e899" = "BlockCreatExecuContent"
    "56a863a9-875e-4185-98a7-b882c64b5ce5" = "BlockVulnerableDriverRule"
    "5beb7efe-fd9a-4556-801d-275e5ffc04cc" = "BlockObfuscatedScriptExec"
    "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84" = "BlockInjection"
    "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" = "BlockAdobeCreateChildProc"
    "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b" = "BlockWin32FromMacro"
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" = "BlockReadFromLSASS"
    "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" = "BlockUnsignedProcFromUSB"
    "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" = "BlockExecFromEmail"
    "c1db55ab-c21a-4637-bb3f-a12568109d35" = "ProtectAgainstRansomware"
    "d1e49aac-8f56-4280-b9ba-993a6d77406c" = "BlockPSExecAndWMI"
    "d3e037e1-3eb8-44c8-a917-57927947596d" = "BlockJavaOrVBSScriptLaunchFromDownload"
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a" = "BlockCreateChildProc"
    "e6db77e5-3df2-4cf1-b95a-636979351e5b" = "BlockWmiInstallScriptRule"
}

$RuleNameShort = @{ 
    "BlockUntrustedExecFiles"                = "01443614-cd74-433a-b99e-2ecdc07bfc25"
    "BlockCommunicationCreateChildProc"      = "26190899-1602-49e8-8b27-eb1d0a1ce869"
    "BlockSafeModeRebootRule"                = "33ddedf1-c6e0-47cb-833e-de6133960387"
    "BlockCreatExecuContent"                 = "3b576869-a4ec-4529-8536-b80a7769e899"
    "BlockVulnerableDriverRule"              = "56a863a9-875e-4185-98a7-b882c64b5ce5"
    "BlockObfuscatedScriptExec"              = "5beb7efe-fd9a-4556-801d-275e5ffc04cc"
    "BlockInjection"                         = "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84"
    "BlockAdobeCreateChildProc"              = "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c"
    "BlockWin32FromMacro"                    = "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b"
    "BlockReadFromLSASS"                     = "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"
    "BlockUnsignedProcFromUSB"               = "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4"
    "BlockExecFromEmail"                     = "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550"
    "ProtectAgainstRansomware"               = "c1db55ab-c21a-4637-bb3f-a12568109d35"
    "BlockPSExecAndWMI"                      = "d1e49aac-8f56-4280-b9ba-993a6d77406c"
    "BlockJavaOrVBSScriptLaunchFromDownload" = "d3e037e1-3eb8-44c8-a917-57927947596d"
    "BlockCreateChildProc"                   = "d4f940ab-401b-4efc-aadc-ad5f3c50688a"
    "BlockWmiInstallScriptRule"              = "e6db77e5-3df2-4cf1-b95a-636979351e5b"
}
    
$RuleGUIDLong = @{
    "01443614-cd74-433a-b99e-2ecdc07bfc25" = "Block executable files from running unless they meet a prevalence, age, or trusted list criterion"
    "26190899-1602-49e8-8b27-eb1d0a1ce869" = "Block Office communication application from creating child processes"
    "33ddedf1-c6e0-47cb-833e-de6133960387" = "Block rebooting machine in Safe Mode"
    "3b576869-a4ec-4529-8536-b80a7769e899" = "Block Office applications from creating executable content"
    "56a863a9-875e-4185-98a7-b882c64b5ce5" = "Block abuse of exploited vulnerable signed drivers"
    "5beb7efe-fd9a-4556-801d-275e5ffc04cc" = "Block execution of potentially obfuscated scripts"
    "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84" = "Block Office applications from injecting code into other processes"
    "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" = "Block Adobe Reader from creating child processes"
    "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b" = "Block Win32 API calls from Office macros"
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" = "Block credential stealing from the Windows local security authority subsystem (lsass.exe)"
    "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" = "Block untrusted and unsigned processes that run from USB"
    "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" = "Block executable content from email client and webmail"
    "c1db55ab-c21a-4637-bb3f-a12568109d35" = "Use advanced protection against ransomware"
    "d1e49aac-8f56-4280-b9ba-993a6d77406c" = "Block process creations originating from PSExec and WMI commands"
    "d3e037e1-3eb8-44c8-a917-57927947596d" = "Block JavaScript or VBScript from launching downloaded executable content"
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a" = "Block all Office applications from creating child processes"
    "e6db77e5-3df2-4cf1-b95a-636979351e5b" = "Block persistence through WMI event subscription - File and folder exclusions not supported."
}
    
$ActionCode = @{
    0 = "Disabled" 
    1 = "Enabled" 
    2 = "Audit" 
}
    
$ASR_Ids = (Get-MpPreference).AttackSurfaceReductionRules_Ids
$ASR_Actions = (Get-MpPreference).AttackSurfaceReductionRules_Actions
    
for ($i = 0; $i -lt $ASR_Ids.Count; $i++) {
    Write-Host ("{0,-40} {1,10}" -f $RuleGUIDShort[$($ASR_Ids[$i])], $ActionCode[[int32]($ASR_Actions[$i])] )
    #Write-Host ("{0,-100} {1,10}" -f $RuleGUIDLong[$($ASR_Ids[$i])], $ActionCode[[int32]($ASR_Actions[$i])] )
}

#Add-MpPreference -AttackSurfaceReductionRules_Ids $RuleNameShort["BlockWin32FromMacro"] -AttackSurfaceReductionRules_Actions Enabled
#Add-MpPreference -AttackSurfaceReductionRules_Ids $RuleNameShort["BlockCreateChildProc"] -AttackSurfaceReductionRules_Actions Enabled    
