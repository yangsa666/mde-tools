## Copyright (c) Microsoft Corporation. All rights reserved.

<#
.SYNOPSIS
This cmdlet collects a performance investigation recording of Microsoft
Defender Antivirus.

.DESCRIPTION
This cmdlet collects a performance investigation recording of Microsoft
Defender Antivirus. These performance recordings contain information logged
by both operating system providers and Microsoft Defender Antivirus providers
and can be analyzed after collection using Windows Performance Analyzer, or 
the Get-MpPerformanceReport cmdlet.

This cmdlet requires elevated administrator privileges.

Performance investigation recordings can help a performance analyst develop
insights into problematic files and workloads that could cause performance
degradation of Microsoft Defender Antivirus.

These performance recordings are not intended to provide suggestions on
exclusions. Exclusions can reduce the level of protection on your endpoints.
Exclusions, if any, should be defined with caution.

.EXAMPLE
# Collect interactively a performance recording and save it to '.\Interactive.etl'.
New-DefenderPerformanceRecording -FileMode -RecordTo:.\Interactive.etl

.EXAMPLE
# Collect interactively a performance recording and save it to '.\Interactive.etl', along with support files cab at '.\Interactive.MpSupportFiles.cab'.
New-DefenderPerformanceRecording -FileMode -RecordTo:.\Interactive.etl -GetSupportFilesCab

.EXAMPLE
# Collect a performance recording for 30 seconds and save it to '.\Timed-30s.etl'.
New-DefenderPerformanceRecording -FileMode -RecordTo:.\Timed-5min.etl -Seconds:30

.EXAMPLE
# Collect a performance recording for 30 seconds and save it to '.\Timed-30s.etl', along with support files cab at '.\Timed-30s.MpSupportFiles.cab'.
New-DefenderPerformanceRecording -FileMode -RecordTo:.\Timed-5min.etl -Seconds:30 -GetSupportFilesCab

.EXAMPLE
# Collect a performance recording for 5 minutes and save it to '.\Timed-5min.etl'.
New-DefenderPerformanceRecording -FileMode -RecordTo:.\Timed-5min.etl -Minutes:5

.EXAMPLE
# Collect a performance recording for 5 minutes and save it to '.\Timed-5min.etl', along with support files cab at '.\Timed-5min.MpSupportFiles.cab'.
New-DefenderPerformanceRecording -FileMode -RecordTo:.\Timed-5min.etl -Minutes:5 -GetSupportFilesCab

.EXAMPLE
# Collect a flight-recorder performance recording when CPU usage in Defender service exceeds 80% over 60s and save it to '.\HighCpuUsage-Exceeding-80pct-over-60s.etl'.
New-DefenderPerformanceRecording -RecordTo:.\HighCpuUsage-Exceeding-80pct-over-60s.etl -HighCpuUsage -ExceedingCpuUsagePercent:80 -OverSeconds:60

.EXAMPLE
# Collect a flight-recorder performance recording when CPU usage in Defender service exceeds 80% over 60s and save it to '.\HighCpuUsage-Exceeding-80pct-over-60s.etl', along with support files cab at '.\HighCpuUsage-Exceeding-80pct-over-60s.MpSupportFiles.cab'.
New-DefenderPerformanceRecording -RecordTo:.\HighCpuUsage-Exceeding-80pct-over-60s.etl -HighCpuUsage -ExceedingCpuUsagePercent:80 -OverSeconds:60 -GetSupportFilesCab

.EXAMPLE
# Collect a flight-recorder performance recording with heap when private memory usage in Defender service exceeds 1GB with 20MB growth over 10s and save it to '.\HighMemoryUsage-Exceeding-1GB-and-20MB-growth-over-10s.etl'.
New-DefenderPerformanceRecording -RecordTo:.\HighMemoryUsage-Exceeding-1GB-and-20MB-growth-over-10s.etl -HighMemoryUsage -ExceedingPrivateBytes:1GB -ExceedingPrivateBytesGrowth:20MB -PollingIntervalSeconds:10 -Categories:'Heap'

.EXAMPLE
# Collect a flight-recorder performance recording with heap when private memory usage in Defender service exceeds 1GB with 20MB growth over 10s and save it to '.\HighMemoryUsage-Exceeding-1GB-and-20MB-growth-over-10s.etl', along with support files cab at '.\HighMemoryUsage-Exceeding-1024MB-and-20MB-growth-over-10s.MpSupportFiles.cab'.
New-DefenderPerformanceRecording -RecordTo:.\HighMemoryUsage-Exceeding-1GB-and-20MB-growth-over-10s.etl -HighMemoryUsage -ExceedingPrivateBytes:1GB -ExceedingPrivateBytesGrowth:20MB -PollingIntervalSeconds:10 -Categories:'Heap' -GetSupportFilesCab

.EXAMPLE
# Collect a performance recording for a Quick Scan (not honoring the configured CPU throttling policy) and save it to '.\QuickScan.etl'.
New-DefenderPerformanceRecording -FileMode -RecordTo:.\QuickScan.etl -Scan -ScanType:QuickScan

.EXAMPLE
# Collect a performance recording for a Quick Scan (not honoring the configured CPU throttling policy) and save it to '.\QuickScan.etl', along with support files cab at '.\QuickScan.MpSupportFiles.cab'.
New-DefenderPerformanceRecording -FileMode -RecordTo:.\QuickScan.etl -Scan -ScanType:QuickScan -GetSupportFilesCab

.EXAMPLE
# Collect a performance recording for a Quick Scan honoring the configured CPU throttling policy and save it to '.\QuickScan-CpuThrottling.etl'.
New-DefenderPerformanceRecording -FileMode -RecordTo:.\QuickScan-CpuThrottling.etl -Scan -ScanType:QuickScan -CpuThrottling

.EXAMPLE
# Collect a performance recording for a Quick Scan honoring the configured CPU throttling policy and save it to '.\QuickScan-CpuThrottling.etl', along with support files cab at '.\QuickScan-CpuThrottling.MpSupportFiles.cab'.
New-DefenderPerformanceRecording -FileMode -RecordTo:.\QuickScan-CpuThrottling.etl -Scan -ScanType:QuickScan -CpuThrottling -GetSupportFilesCab

.EXAMPLE
# Collect a performance recording for a SignatureUpdate and save it to '.\SignatureUpdate.etl'.
New-DefenderPerformanceRecording -FileMode -RecordTo:.\SignatureUpdate.etl -SignatureUpdate

.EXAMPLE
# Collect a performance recording for a SignatureUpdate and save it to '.\SignatureUpdate.etl', along with support files cab at '.\SignatureUpdate.MpSupportFiles.cab'.
New-DefenderPerformanceRecording -FileMode -RecordTo:.\SignatureUpdate.etl -SignatureUpdate -GetSupportFilesCab

.EXAMPLE
# Collect a performance recording for a SignatureUpdate from Microsoft Malware Protection Center and save it to '.\SignatureUpdate-MMPC.etl'.
New-DefenderPerformanceRecording -FileMode -RecordTo:.\SignatureUpdate-MMPC.etl -SignatureUpdate -MMPC

.EXAMPLE
# Collect a performance recording for a SignatureUpdate from Microsoft Malware Protection Center and save it to '.\SignatureUpdate-MMPC.etl', along with support files cab at '.\SignatureUpdate-MMPC.MpSupportFiles.cab'.
New-DefenderPerformanceRecording -FileMode -RecordTo:.\SignatureUpdate-MMPC.etl -SignatureUpdate -MMPC -GetSupportFilesCab

.EXAMPLE
# Collect a performance recording for a SignatureUpdate from the configured file share and save it to '.\SignatureUpdate-UNC.etl'.
New-DefenderPerformanceRecording -FileMode -RecordTo:.\SignatureUpdate-UNC.etl -SignatureUpdate -UNC

.EXAMPLE
# Collect a performance recording for a SignatureUpdate from the configured file share and save it to '.\SignatureUpdate-UNC.etl', along with support files cab at '.\SignatureUpdate-UNC.MpSupportFiles.cab'.
New-DefenderPerformanceRecording -FileMode -RecordTo:.\SignatureUpdate-UNC.etl -SignatureUpdate -UNC -GetSupportFilesCab

.EXAMPLE
# Collect a performance recording for a SignatureUpdate from '\\server\share' and save it to '.\SignatureUpdate-CustomUNC.etl'.
New-DefenderPerformanceRecording -FileMode -RecordTo:.\SignatureUpdate-CustomUNC.etl -SignatureUpdate -UNC -Path:\\server\share

.EXAMPLE
# Collect a performance recording for a SignatureUpdate from '\\server\share' and save it to '.\SignatureUpdate-CustomUNC.etl', along with support files cab at '.\SignatureUpdate-CustomUNC.MpSupportFiles.cab'.
New-DefenderPerformanceRecording -FileMode -RecordTo:.\SignatureUpdate-CustomUNC.etl -SignatureUpdate -UNC -Path:\\server\share -GetSupportFilesCab

.EXAMPLE
# Collect a performance recording for a custom workload and save it to '.\CustomWorkload.etl'.
New-DefenderPerformanceRecording -FileMode -RecordTo:.\CustomWorkload.etl -Workload:{ Start-Sleep -Seconds:5 }

.EXAMPLE
# Collect a performance recording for a custom workload and save it to '.\CustomWorkload.etl', along with support files cab at '.\CustomWorkload.MpSupportFiles.cab'.
New-DefenderPerformanceRecording -FileMode -RecordTo:.\CustomWorkload.etl -Workload:{ Start-Sleep -Seconds:5 } -GetSupportFilesCab

.EXAMPLE
# Start a performance recording that must be stopped using 'wpr -stop recording.etl' or cancelled using 'wpr -cancel'.
New-DefenderPerformanceRecording -FileMode -OpenEnded

#>

[CmdletBinding(DefaultParameterSetName='Interactive')]
param(
    [Parameter(Mandatory = $false, HelpMessage = 'Collect in-file performance recording')]
    # Collect in-file performance recording.  Default: in-memory.
    [switch]$FileMode,

    [Parameter(Mandatory=$false, HelpMessage = 'Location where to save performance recording', ParameterSetName='Interactive')]
    [Parameter(Mandatory=$false, HelpMessage = 'Location where to save performance recording', ParameterSetName='TimedSeconds')]
    [Parameter(Mandatory=$false, HelpMessage = 'Location where to save performance recording', ParameterSetName='TimedMinutes')]
    [Parameter(Mandatory=$false, HelpMessage = 'Location where to save performance recording', ParameterSetName='HighCpuUsage')]
    [Parameter(Mandatory=$false, HelpMessage = 'Location where to save performance recording', ParameterSetName='HighMemoryUsage')]
    [Parameter(Mandatory=$false, HelpMessage = 'Location where to save performance recording', ParameterSetName='Scan')]
    [Parameter(Mandatory=$false, HelpMessage = 'Location where to save performance recording', ParameterSetName='SignatureUpdate')]
    [Parameter(Mandatory=$false, HelpMessage = 'Location where to save performance recording', ParameterSetName='SignatureUpdateUnc')]
    [Parameter(Mandatory=$false, HelpMessage = 'Location where to save performance recording', ParameterSetName='CustomWorkload')]
    ## Note: Not ParameterSetName='OpenEnded' because it doesn't stop the performance recording.
    # Specifies the location where to save the Microsoft Defender Antivirus
    # performance recording.
    [ValidateScript({
        if (Test-Path -LiteralPath $_ -PathType Container) {
            throw "The path '$_' points to an existing directory; expected a path to the '.etl' file to be generated."
        }
        if ($_.EndsWith('.etl')) {
            $true
        } else {
            throw "The path '$_' does not end in '.etl'; expected a path that ends in '.etl'."
        }
    })]
    [ValidateNotNullOrEmpty()]
    [string]$RecordTo,


    [Parameter(
        Mandatory = $false,
        ParameterSetName = 'Interactive',
        HelpMessage = 'Collect a performance recording in interactive mode'
        )]
    # Collect a performance recording in interactive mode.
    [switch]$Interative,


    [Parameter(
        Mandatory = $false,
        ParameterSetName = 'TimedSeconds',
        HelpMessage = 'Collect a performance recording for a specified duration'
        )]
    [Parameter(
        Mandatory = $false,
        ParameterSetName = 'TimedMinutes',
        HelpMessage = 'Collect a performance recording for a specified duration'
        )]
    # Collect a performance recording for a specified duration.
    [switch]$Timed,

    [Parameter(
        Mandatory = $true,
        ParameterSetName = 'TimedSeconds',
        HelpMessage = 'Duration of the performance recording in seconds'
        )]
    # Collect a performance recording for the specified number of seconds.
    [ValidateRange(0, 72 * 60 * 60)]
    [int]$Seconds,

    [Parameter(
        Mandatory = $true,
        ParameterSetName = 'TimedMinutes',
        HelpMessage = 'Duration of the performance recording in minutes'
        )]
    # Collect a performance recording for the specified number of minutes.
    [ValidateRange(0, 72 * 60)]
    [int]$Minutes,


    [Parameter(
        Mandatory = $true,
        ParameterSetName = 'HighCpuUsage',
        HelpMessage = 'Collect a performance recording when Defender CPU usage over time window exceeds threshold'
        )]
    # Collect a performance recording when Defender CPU usage over time window exceeds threshold.
    [switch]$HighCpuUsage,

    [Parameter(
        Mandatory = $true,
        ParameterSetName = 'HighCpuUsage',
        HelpMessage = 'Defender CPU usage percent over time window that should trigger collection of performance recording'
        )]
    # The Defender CPU usage percent over time window that should trigger collection of performance recording.
    [ValidateRange(0, 100)]
    [int]$ExceedingCpuUsagePercent = 80,

    [Parameter(
        Mandatory = $true,
        ParameterSetName = 'HighCpuUsage',
        HelpMessage = 'Time window duration in seconds'
        )]
    # Time window duration in seconds
    [ValidateRange(0, 15 * 60)]
    [int]$OverSeconds = 10,


    [Parameter(
        Mandatory = $true,
        ParameterSetName = 'HighMemoryUsage',
        HelpMessage = 'Duration in seconds'
        )]
    # Collect a performance recording when Defender memory usage and growth exceeds thresholds.
    [switch]$HighMemoryUsage,

    [Parameter(
        Mandatory = $true,
        ParameterSetName = 'HighMemoryUsage',
        HelpMessage = 'Defender private bytes usage necessary to trigger collection of performance recording'
        )]
    # The Defender private bytes usage over time window that should trigger collection of performance recording.
    [ValidateRange(200MB, 16GB)]
    [long]$ExceedingPrivateBytes = 2GB,

    [Parameter(
        Mandatory = $true,
        ParameterSetName = 'HighMemoryUsage',
        HelpMessage = 'Defender private bytes growth over window necessary to trigger collection of performance recording'
        )]
    # The Defender private bytes growth over window that should trigger collection of performance recording.
    [ValidateRange(10MB, 1GB)]
    [long]$ExceedingPrivateBytesGrowth = 100MB,

    [Parameter(
        Mandatory = $true,
        ParameterSetName = 'HighMemoryUsage',
        HelpMessage = 'Polling interval in seconds'
        )]
    # Polling interval in seconds
    [ValidateRange(0, 5 * 60)]
    [int]$PollingIntervalSeconds = 10,


    [Parameter(
        Mandatory = $false,
        ParameterSetName = 'HighCpuUsage',
        HelpMessage = 'Initial time windows to skip'
        )]
    [Parameter(
        Mandatory = $false,
        ParameterSetName = 'HighMemoryUsage',
        HelpMessage = 'Initial intervals to skip'
        )]
    # Initial intervals to skip
    [ValidateRange(0, 100)]
    [int]$InitialIntervalsToSkip = 0,


    [Parameter(
        Mandatory = $true,
        ParameterSetName = 'Scan',
        HelpMessage = 'Collect a performance recording around a newly initiated scan'
        )]
    # Collect a performance recording around a newly initiated scan.
    [switch]$Scan,

    [Parameter(
        Mandatory = $true,
        ParameterSetName = 'Scan',
        HelpMessage = 'Type of scan'
        )]
    # Type of scan to initiate.  Default: 'Default'.
    [ValidateSet('Default', 'QuickScan', 'FullScan')]
    [string]$ScanType,

    [Parameter(
        Mandatory = $false,
        ParameterSetName = 'Scan',
        HelpMessage = 'Ensure that the scan obeys CPU throttling as defined in the policy'
        )]
    # Ensure that the scan obeys the CPU throttling as defined in the policy. See '(Get-MpPreference).ScanAvgCPULoadFactor'.
    [switch]$CpuThrottling,

    [Parameter(
        Mandatory = $false,
        ParameterSetName = 'Scan',
        HelpMessage = 'Scan timeout in days'
        )]
    # Scan timeout in days.  Default: 7 days for FullScan and 1 day for QuickScan.
    [ValidateRange(1, 30)]
    [int]$TimeoutDays = $null,


    [Parameter(
        Mandatory = $true,
        ParameterSetName = 'SignatureUpdate',
        HelpMessage = 'Collect a performance recording for a signature update'
        )]
    [Parameter(
        Mandatory = $true,
        ParameterSetName = 'SignatureUpdateUnc',
        HelpMessage = 'Perform update directly from UNC file share'
        )]
    # Collect a performance recording for a signature update (aka. definitions update, Defender security intelligence update).
    [switch]$SignatureUpdate,

    [Parameter(
        Mandatory = $false,
        ParameterSetName = 'SignatureUpdate',
        HelpMessage = 'Perform update directly from Microsoft Malware Protection Center'
        )]
    # Perform update directly from Microsoft Malware Protection Center.
    [switch]$MMPC,

    [Parameter(
        Mandatory = $true,
        ParameterSetName = 'SignatureUpdateUnc',
        HelpMessage = 'Perform update directly from preconfigured UNC file share'
        )]
    # Perform update directly from UNC file share.  Uses preconfigured UNC file share by default.
    [switch]$UNC,

    [Parameter(
        Mandatory = $false,
        ParameterSetName = 'SignatureUpdateUnc',
        HelpMessage = 'A custom UNC file share to use for the signture update'
        )]
    [ValidateScript({
        if ([string]::IsNullOrEmpty($_) -or (Test-Path -LiteralPath:$_ -PathType:Container)) {
            $true
        } else {
            throw "The specified UNC file share path does not exist: $_"
        }
    })]
    # A custom UNC file share to use for the signture update.
    [string]$Path,


    [Parameter(
        Mandatory = $true,
        ParameterSetName = 'CustomWorkload',
        HelpMessage = 'Collect a performance recording for a script block workload'
        )]
    [ValidateNotNull()]
    # Collect a performance recording for a script block workload.
    [scriptblock]$CustomWorkload,


    [Parameter(
        Mandatory = $true,
        ParameterSetName = 'OpenEnded',
        HelpMessage = 'Collect an open ended performance recording'
        )]
    # Start an open ended performance recording that must be stopped using 'wpr -stop recording.etl' or cancelled using 'wpr -cancel'.
    [switch]$OpenEnded,


    [Parameter(Mandatory=$false, HelpMessage = 'Collect Defender support files cab', ParameterSetName='Interactive')]
    [Parameter(Mandatory=$false, HelpMessage = 'Collect Defender support files cab', ParameterSetName='TimedSeconds')]
    [Parameter(Mandatory=$false, HelpMessage = 'Collect Defender support files cab', ParameterSetName='TimedMinutes')]
    [Parameter(Mandatory=$false, HelpMessage = 'Collect Defender support files cab', ParameterSetName='HighCpuUsage')]
    [Parameter(Mandatory=$false, HelpMessage = 'Collect Defender support files cab', ParameterSetName='HighMemoryUsage')]
    [Parameter(Mandatory=$false, HelpMessage = 'Collect Defender support files cab', ParameterSetName='Scan')]
    [Parameter(Mandatory=$false, HelpMessage = 'Collect Defender support files cab', ParameterSetName='SignatureUpdate')]
    [Parameter(Mandatory=$false, HelpMessage = 'Collect Defender support files cab', ParameterSetName='SignatureUpdateUnc')]
    [Parameter(Mandatory=$false, HelpMessage = 'Collect Defender support files cab', ParameterSetName='CustomWorkload')]
    ## Note: Not ParameterSetName='OpenEnded' because it doesn't collect the support files cab.
    # Collect Defender support files cab.
    [switch]$GetSupportFilesCab,

    [Parameter(Mandatory=$false, HelpMessage = 'Collect Defender support files cab', ParameterSetName='HighCpuUsage')]
    [Parameter(Mandatory=$false, HelpMessage = 'Collect Defender support files cab', ParameterSetName='HighMemoryUsage')]
    # Collect Defender support files cab.
    [switch]$Monitor,

    [Parameter(Mandatory = $false, HelpMessage = 'Additional instrumentation categories to collect')]
    # Additional instrumentation categories to collect.
    # Zero or more of: 'Heap', 'DNS', 'SMB', 'TcpIp', 'FullTcpIp', 'Network', 'WinInet', 'WinHttp', 'Pool', 'AMSI', 'AntimalwareCommonUtils'.
    [ValidateSet('Heap', 'DNS', 'SMB', 'TcpIp', 'FullTcpIp', 'Network', 'WinInet', 'WinHttp', 'Pool', 'AMSI', 'AntimalwareCommonUtils')]
    [ValidateNotNull()]
    [string[]]$Categories = @(),

    [Parameter(Mandatory = $false, HelpMessage = 'Collect light performance recording')]
    # Collect light performance recording.  Default: verbose.
    [switch]$Light,

    [Parameter(Mandatory = $false, HelpMessage = 'Location for recording temporary files')]
    # Location for recording temporary files.
    [string]$RecordTempTo,

    [Parameter(Mandatory = $false, HelpMessage = 'WPR instance name')]
    # WPR instance name.
    [string]$InstanceName,

    # Optional argument to specifiy a different tool for recording traces. Default is wpr.exe.
    [Parameter(Mandatory=$false)]
    [string]$WPRPath = $null
)

Set-StrictMode -Version:Latest
$ErrorActionPreference = 'Stop'

$ScriptPSCmdlet = $PSCmdlet

[string]$PlatformPath = (Get-ItemProperty -Path:'HKLM:\Software\Microsoft\Windows Defender' -Name:'InstallLocation' -ErrorAction:Stop).InstallLocation
[string]$mpCmdRunCommand = "${PlatformPath}MpCmdRun.exe"


$capitalizedRecordingType = if ($FileMode.IsPresent) { 'Recording' } else { 'Flight-recording' }

function RunWorkload {
    switch ($ScriptPSCmdlet.ParameterSetName) {
        'TimedSeconds' {
            Write-Host "`n`n   $capitalizedRecordingType for $Seconds seconds... " -NoNewline
        
            Start-Sleep -Seconds:$Seconds

            Write-Host "ok." -NoNewline
        }
    
        'TimedMinutes' {
            Write-Host "`n`n   $capitalizedRecordingType for $Minutes minutes... " -NoNewline

            Start-Sleep -Seconds:($Minutes * 60)

            Write-Host "ok." -NoNewline
        }

        'HighCpuUsage' {
            Write-Host "`n`n   $capitalizedRecordingType until Defender service CPU usage exceeds ${ExceedingCpuUsagePercent}% over $OverSeconds seconds...`n"

            $numberOfLogicalProcessors = $(Get-CimInstance –ClassName Win32_Processor).NumberOfLogicalProcessors
            $ExceedingCpuUsagePercentTimesNumberOfLogicalProcessors = $ExceedingCpuUsagePercent * $numberOfLogicalProcessors
            
            $Context = @{ Skip = $InitialIntervalsToSkip }

            Get-Counter -Counter:'\Process(MsMpEng)\% Processor Time' -SampleInterval:$OverSeconds -Continuous 2> $null | Where-Object {

                if ($Context.Skip -le 0) {
                    $CurrentValue = $_.CounterSamples.CookedValue

                    if ($Monitor.IsPresent) {
                        Write-Host "`r   Defender service CPU usage: $(($CurrentValue/$numberOfLogicalProcessors).ToString('f2'))% over $OverSeconds seconds  " -NoNewline
                    }

                    $detection = ($CurrentValue -ge $ExceedingCpuUsagePercentTimesNumberOfLogicalProcessors)

                    if ($detection) {
                        if ($Monitor.IsPresent) {
                            Write-Host ''
                        }

                        $Message = "High CPU usage of Defender service detected: $(($CurrentValue / $numberOfLogicalProcessors).ToString('f2'))% over $OverSeconds seconds at $($_.Timestamp)"

                        Write-Host "`n   $Message." -NoNewline
                        LogMarker -Message:$Message
                    }
                } else {
                    $Context.Skip--
                    $detection = $false
                }

                return $detection

            } | Select-Object -First 1 | Out-Null

            Write-Host ''
        }

        'HighMemoryUsage' {
            Write-Host "`n`n   $capitalizedRecordingType until Defender service private bytes exceeds $($ExceedingPrivateBytes / 1MB)MB with $($ExceedingPrivateBytesGrowth / 1MB)MB growth over $PollingIntervalSeconds seconds...`n"

            $Context = @{ PreviousValue = $null; Skip = $InitialIntervalsToSkip }

            Get-Counter -Counter:'\Process(MsMpEng)\Private Bytes' -SampleInterval:$PollingIntervalSeconds -Continuous 2> $null | Where-Object {
                $CurrentValue = $_.CounterSamples.CookedValue
                $PreviousValue = $Context.PreviousValue

                if ($Context.Skip -le 0) {
                    if ($null -ne $PreviousValue) {
                        $Growth = $CurrentValue - $PreviousValue

                        if ($Monitor.IsPresent) {
                            Write-Host "`r   Defender service private usage $(($CurrentValue / 1MB).ToString('f2'))MB with $(($Growth / 1MB).ToString('f2'))MB growth over $PollingIntervalSeconds seconds        " -NoNewline
                        }

                        $detection = ($Growth -ge $ExceedingPrivateBytesGrowth) -and ($CurrentValue -gt $ExceedingPrivateBytes)

                        if ($detection) {
                            if ($Monitor.IsPresent) {
                                Write-Host ''
                            }

                            $Message = "High memory usage of Defender service detected: Private $(($CurrentValue / 1MB).ToString('f2'))MB with $(($Growth / 1MB).ToString('f2'))MB growth over $PollingIntervalSeconds seconds at $($_.Timestamp)"

                            Write-Host "`n   $Message." -NoNewline
                            LogMarker -Message:$Message
                        }
                    } else {
                        $detection = $false
                    }
                } else {
                    $Context.Skip--
                    $detection = $false
                }
            
                $Context.PreviousValue = $CurrentValue

                return $detection
            } | Select-Object -First 1 | Out-Null

            Write-Host ''
        }
        
        'Scan' {
            [string]$description = ''
            [string]$additionalDescription = ''
            [int]$scanTypeCode = 0

            switch ($ScanType) {
                'Default' {
                    $scanTypeCode = 0
                    $description = 'default scan'
                }
                'QuickScan' {
                    $scanTypeCode = 1
                    $description = 'quick scan'
                }
                'FullScan' {
                    $scanTypeCode = 2
                    $description = 'full scan'
                }
            }
    
            $mpCmdRunOptions = @()
    
            if ($CpuThrottling.IsPresent) {
                $mpCmdRunOptions += '-CpuThrottling'
                $additionalDescription += ' with CPU throttling'
            }
    
            if ($TimeoutDays -ne 0) {
                $mpCmdRunOptions += '-TimeoutDays'
                $mpCmdRunOptions += $TimeoutDays
                $additionalDescription += ' with timeout of ' + $TimeoutDays + ' days'
            }
            
            Write-Host "`n`n   $capitalizedRecordingType a Defender $description$additionalDescription...`n"
    
            & $mpCmdRunCommand -Scan -ScanType $scanTypeCode @mpCmdRunOptions -ReturnHR

            Write-Host "`n   Defender $description complete.`n`n"
        }
    
        'SignatureUpdate' {
            [string]$description = 'signature update'
            [string]$additionalDescription = ''
    
            $mpCmdRunOptions = @()
    
            if ($MMPC.IsPresent) {
                $mpCmdRunOptions += '-MMPC'
                $additionalDescription += ' from Microsoft Malware Protection Center'
            }
    
            Write-Host "`n`n   $capitalizedRecordingType a Defender $description$additionalDescription...`n"
    
            & $mpCmdRunCommand -SignatureUpdate @mpCmdRunOptions
    
            Write-Host "`n   Defender $description complete.`n`n"
        }
    
        'SignatureUpdateUnc' {
            [string]$description = 'signature update'
            [string]$additionalDescription = ''

            $mpCmdRunOptions = @()
    
            if (-not [string]::IsNullOrEmpty($Path)) {
                $mpCmdRunOptions += '-Path'
                $mpCmdRunOptions += $Path
                $additionalDescription += " from file share '$Path'"
            } else {
                $additionalDescription += " from preconfigured file share"
            }

            Write-Host "`n`n   $capitalizedRecordingType a Defender $description$additionalDescription...`n"
    
            & $mpCmdRunCommand -SignatureUpdate -UNC @mpCmdRunOptions

            Write-Host "`n   Defender $description complete.`n`n"
        }

        'CustomWorkload' {
            Write-Host "`n`n   $capitalizedRecordingType a custom workload...`n"

            & $CustomWorkload

            Write-Host "`n   Custom workload complete.`n`n"
        }
    
        'OpenEnded' { return }
    }
}

function GetWorkloadName {
    switch ($ScriptPSCmdlet.ParameterSetName) {
        'Interactive' {
            'Interactive'
        }

        'TimedSeconds' {
            "Timed-${Seconds}s"
        }
    
        'TimedMinutes' {
            "Timed-${Minutes}min"
        }
    
        'HighCpuUsage' {
            "HighCpuUsage-Exceeding-${ExceedingCpuUsagePercent}pct-over-${OverSeconds}s"
        }

        'HighMemoryUsage' {
            "HighMemoryUsage-Exceeding-${ExceedingPrivateBytes}-and-${ExceedingPrivateBytesGrowth}-growth-over-${PollingIntervalSeconds}s"
        }
        
        'Scan' {

            $name = $ScanType
    
            if ($CpuThrottling.IsPresent) {
                $name += '-CpuThrottling'
            }
    
            if ($TimeoutDays -ne 0) {
                $name += "-Timeout-${TimeoutDays}Days"
            }
            
            $name
        }
    
        'SignatureUpdate' {
    
            $name = 'SignatureUpdate'
    
            if ($MMPC.IsPresent) {
                $name += '-MMPC'
            }
    
            $name
        }
    
        'SignatureUpdateUnc' {
    
            if ([string]::IsNullOrEmpty($Path)) {
                $name = 'SignatureUpdate-UNC'
            } else {
                $name = 'SignatureUpdate-CustomUNC'
            }
    
            $name
        }

        'CustomWorkload' {
            'CustomWorkload'
        }

        default {
            Write-Error 'Invalid workload type'
        }
    }
}


function StartPerformanceRecording {

    $HeapProcessName = 'MsMpEng'

    if ($Categories -contains 'Heap') {
        $HeapProcessId = @((Get-Process -Name:$HeapProcessName -ErrorAction:Stop).Id)
    } else {
        $HeapProcessId = @(0)
    }

    $tempFile = New-TemporaryFile -ErrorAction:Stop

    try {

        $(Get-DefenderWPRProfile -HeapProcessId:$HeapProcessId) | Out-File -Encoding:'utf8' -FilePath:$tempFile.FullName -ErrorAction:Stop

        $wprOptions = @()

        if ($FileMode.IsPresent) {
            $wprOptions += '-filemode'
        }

        if (-not [string]::IsNullOrEmpty($RecordTempTo)) {
            $wprOptions += @('-recordtempto', $RecordTempTo)
        }

        if (-not [string]::IsNullOrEmpty($InstanceName)) {
            $wprOptions += @('-instancename', $InstanceName)
        }

        & $wprCommand -start "$($tempFile.FullName)!WD$(if ($Categories -contains 'Heap') {'Heap'} else {''}).$(if ($Light.IsPresent) {'Light'} else {'Verbose'})" @wprOptions *> $null | Out-Null
        $wprCommandExitCode = $LASTEXITCODE

    } catch {
        throw
    } finally {
        $tempFile.Delete()
    }

    $wprCommandExitCode
}


function LogMarker {
    param(
        [Parameter(Mandatory)]
        [string[]]$Message
    )

    & $wprCommand -marker @Message *> $null | Out-Null
    $wprCommandExitCode = $LASTEXITCODE

    $wprCommandExitCode
}


function StopPerformanceRecording {
    $wprOptions = @()

    if (-not [string]::IsNullOrEmpty($InstanceName)) {
        $wprOptions += @('-instancename',$InstanceName)
    }

    & $wprCommand -stop $RecordTo @wprOptions *> $null | Out-Null
    $wprCommandExitCode = $LASTEXITCODE

    $wprCommandExitCode
}


function Get-DefenderWPRProfile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, HelpMessage = 'Process id of process for which to collect the heap trace')]
        [ValidateCount(1, 2)]
        [int[]]$HeapProcessId
    )

    $HeapProcessIdElements = [string]::Join("`n", ($HeapProcessId | ForEach-Object { "<HeapProcessId Value=`"$_`" />" }))

    [xml]$wprp = [xml]@"
<?xml version="1.0" encoding="utf-8" standalone='yes'?>

<WindowsPerformanceRecorder Version="1.0" Author="Microsoft Defender for Endpoint" Team="Microsoft Defender for Endpoint" Comments="Microsoft Defender for Endpoint performance tracing" Company="Microsoft Corporation" Copyright="Microsoft Corporation">
    <Profiles>

        <!-- System Collectors -->

        <SystemCollector Id="SystemCollector_WDSystemCollectorInFile" Base="" Name="WPR System Collector" Realtime="false">
            <!-- SystemCollector_WPRSystemCollectorInFile -->
            <BufferSize Value="128" />
            <BuffersPerCpu Value="16" />
        </SystemCollector>

        <SystemCollector Id="SystemCollector_WDSystemCollectorInFileLarge" Base="" Name="WPR System Collector" Realtime="false">
            <!-- Base: SystemCollector_WPRSystemCollectorInFileLarge -->
            <BufferSize Value="128" />
            <BuffersPerCpu Value="48" />
            <StackCaching BucketCount="100" CacheSize="1024" />
        </SystemCollector>

        <SystemCollector Id="SystemCollector_WDSystemCollectorInMemory" Base="" Name="WPR System Collector" Realtime="false">
            <!-- Base: SystemCollector_WPRSystemCollectorInMemory -->
            <BufferSize Value="128" />
            <Buffers Value="5" PercentageOfTotalMemory="true" MaximumBufferSpace="1024" />
        </SystemCollector>

        <SystemCollector Id="SystemCollector_WDSystemCollectorInMemoryLarge" Base="" Name="WPR System Collector" Realtime="false">
            <!-- Base: SystemCollector_WPRSystemCollectorInMemory -->
            <BufferSize Value="128" />
            <Buffers Value="5" PercentageOfTotalMemory="true" MaximumBufferSpace="2048" />
        </SystemCollector>

        <!-- Event Collectors -->

        <EventCollector Id="EventCollector_WDEventCollectorInFile" Base="" Name="WPR Event Collector" Private="false" ProcessPrivate="false" Secure="false" Realtime="false">
            <!-- Base: EventCollector_WPREventCollectorInFile -->
            <BufferSize Value="128" />
            <BuffersPerCpu Value="16" />
        </EventCollector>

        <EventCollector Id="EventCollector_WDEventCollectorInFileLarge" Base="" Name="WPR Event Collector" Private="false" ProcessPrivate="false" Secure="false" Realtime="false">
            <!-- Base: EventCollector_WPREventCollectorInFileLarge -->
            <BufferSize Value="128" />
            <BuffersPerCpu Value="48" />
        </EventCollector>

        <EventCollector Id="EventCollector_WDEventCollectorInMemory" Base="" Name="WPR Event Collector" Private="false" ProcessPrivate="false" Secure="false" Realtime="false">
            <!-- Base: EventCollector_WPREventCollectorInMemoryMedium -->
            <BufferSize Value="128" />
            <Buffers Value="3" PercentageOfTotalMemory="true" MaximumBufferSpace="512" />
        </EventCollector>

        <EventCollector Id="EventCollector_WDEventCollectorInMemoryLarge" Base="" Name="WPR Event Collector" Private="false" ProcessPrivate="false" Secure="false" Realtime="false">
            <!-- Base: EventCollector_WPREventCollectorInMemoryLarge -->
            <BufferSize Value="128" />
            <Buffers Value="5" PercentageOfTotalMemory="true" MaximumBufferSpace="1024" />
        </EventCollector>

        <!-- Heap Collectors -->

        <HeapEventCollector Id="HeapCollector_WDHeapEventCollectorInFile" Name="WPR Heap Collector" Secure="true" Realtime="false">
            <!-- Base: HeapCollector_WPRHeapCollector -->
            <BufferSize Value="128" />
            <BuffersPerCpu Value="48" MaximumBufferSpace="384" />
        </HeapEventCollector>

        <HeapEventCollector Id="HeapCollector_WDHeapEventCollectorInMemory" Name="WPR Heap Collector" Secure="true" Realtime="false">
            <!-- Base: HeapCollector_WPRHeapCollector -->
            <BufferSize Value="128" />
            <Buffers Value="5" PercentageOfTotalMemory="true" MaximumBufferSpace="1024" />
        </HeapEventCollector>

        <!-- System Providers -->

        <SystemProvider Id="SystemProvider_WD_Light">
            <Keywords>
                <Keyword Value="CpuConfig" />
                <Keyword Value="Loader" />
                <Keyword Value="ProcessThread" />
                <Keyword Value="HardFaults" />
                <Keyword Value="DiskIO" />
                <Keyword Value="CSwitch" />
                <Keyword Value="ProcessCounter" />
            </Keywords>
        </SystemProvider>

        <SystemProvider Id="SystemProvider_WD_Verbose" Base="SystemProvider_WD_Light">
            <Keywords Operation="Add">
                <Keyword Value="ReadyThread" />
                <Keyword Value="FileIO" />
                <Keyword Value="FileIOInit" />
                <Keyword Value="SampledProfile" />
                <Keyword Value="MemoryInfo" />
                <Keyword Value="MemoryInfoWS" />
                <Keyword Value="Interrupt" />
                <Keyword Value="DPC" />
                <Keyword Value="WDFInterrupt" />
                <Keyword Value="WDFDPC" />
                <Keyword Value="Registry" />
                <Keyword Value="VirtualAllocation" />
                <Keyword Value="VAMap" />
                <Keyword Value="Pool" cfg-any="Pool" />
                <Keyword Value="NetworkTrace" cfg-any="Network TcpIp FullTcpIp" />
                <!-- Additional keywords that enhance Wait Analysis -->
                <Keyword Value="KernelQueue" />
                <Keyword Value="SynchronizationObjects" />
            </Keywords>
            <Stacks>
                <Stack Value="SampledProfile" />
                <Stack Value="CSwitch" />
                <Stack Value="ReadyThread" />
                <Stack Value="FileCreate" />
                <Stack Value="FileClose" />
                <Stack Value="ProcessCreate" />
                <Stack Value="ThreadDCEnd" />
                <Stack Value="VirtualAllocation" />
                <Stack Value="VirtualFree" />
                <Stack Value="MapFile" />
                <Stack Value="UnMapFile" />
                <Stack Value="PoolAllocation" cfg-any="Pool" />
                <Stack Value="PoolAllocationSession" cfg-any="Pool" />
                <Stack Value="PoolFree" cfg-any="Pool" />
                <Stack Value="PoolFreeSession" cfg-any="Pool" />
                <!-- Additional stacks that enhance Wait Analysis -->
                <Stack Value="ThreadCreate" />
                <Stack Value="ThreadPoolCallbackStart" />
                <Stack Value="ThreadPoolCallbackEnqueue" />
                <Stack Value="ThreadPoolCallbackDequeue" />
                <Stack Value="ThreadPoolCallbackStop" />
                <Stack Value="KernelQueueEnqueue" />
                <Stack Value="KernelQueueDequeue" />
            </Stacks>
        </SystemProvider>

        <SystemProvider Id="SystemProvider_WDHeap_Light" Base="SystemProvider_WD_Light" />

        <SystemProvider Id="SystemProvider_WDHeap_Verbose" Base="SystemProvider_WDHeap_Light">
            <Stacks Operation="Add">
                <Stack Value="HeapAllocation" />
                <Stack Value="HeapReallocation" />
                <Stack Value="HeapFree" />
            </Stacks>
        </SystemProvider>

        <!-- Responsiveness Providers -->

        <EventProvider Id="EventProvider_DWMWin32k" Base="" Name="e7ef96be-969f-414f-97d7-3ddb7b558ccc" NonPagedMemory="true">
            <Keywords>
                <Keyword Value="0x2000" />
            </Keywords>
        </EventProvider>

        <EventProvider Id="EventProvider_DWMWin32k_CaptureState" Base="" Name="e7ef96be-969f-414f-97d7-3ddb7b558ccc" NonPagedMemory="true" CaptureStateOnly="true">
            <CaptureStateOnSave>
                <Keyword Value="0x80000" />
            </CaptureStateOnSave>
        </EventProvider>

        <EventProvider Id="EventProvider_Microsoft-Windows-Win32k_Focus" Name="Microsoft-Windows-Win32k" NonPagedMemory="true">
            <Keywords>
                <Keyword Value="0x00002000" /> <!-- Focus -->
            </Keywords>
        </EventProvider>

        <EventProvider Id="EventProvider_Microsoft-Windows-Win32k_CaptureState" Name="Microsoft-Windows-Win32k" NonPagedMemory="true" CaptureStateOnly="true">
            <CaptureStateOnSave>
                <Keyword Value="0x00080000" /> <!-- ThreadRundown -->
            </CaptureStateOnSave>
        </EventProvider>

        <EventProvider Id="EventProvider_Microsoft-Windows-COMRuntime" Name="Microsoft-Windows-COMRuntime">
            <Keywords>
                <Keyword Value="0x00000001" /> <!-- CliModalLoop -->
                <Keyword Value="0x00000002" /> <!-- ComCallWaitAnalysis -->
            </Keywords>
        </EventProvider>

        <!-- Microsoft Defender for Endpoint providers -->
        <!-- Microsoft-Antimalware-Common-Utils: keep guid as name is not registered on all machines -->
        <EventProvider Id="EventProvider_AM_CommonUtils" Name="10a186d1-4315-4a66-8bd6-369214864ffe" Stack="true" cfg-any="AntimalwareCommonUtils" />
        <EventProvider Id="EventProvider_AM_CommonUtils_With_Stacks" Base="EventProvider_AM_CommonUtils" Name="10a186d1-4315-4a66-8bd6-369214864ffe" Stack="true" cfg-any="AntimalwareCommonUtils" />
        <!-- Microsoft-Antimalware-Engine: keep guid as name is not registered on all machines -->
        <EventProvider Id="EventProvider_AM_Engine" Name="0a002690-3839-4e3a-b3b6-96d8df868d99">
            <Keywords>
                <Keyword Value="0x00000000FFFFFFFF" /> <!-- exclude capture state and reserved keywords from runtime keywords -->
            </Keywords>
        </EventProvider>
        <EventProvider Id="EventProvider_AM_Engine_With_StartRundown" Base="EventProvider_AM_Engine" Name="0a002690-3839-4e3a-b3b6-96d8df868d99">
            <CaptureStateOnStart>
                <Keyword Value="0x0000040000000000" /> <!-- StartRundown -->
            </CaptureStateOnStart>
        </EventProvider>
        <EventProvider Id="EventProvider_AM_Engine_With_EndRundown" Base="EventProvider_AM_Engine" Name="0a002690-3839-4e3a-b3b6-96d8df868d99">
            <CaptureStateOnSave>
                <Keyword Value="0x0000080000000000" /> <!-- EndRundown -->
            </CaptureStateOnSave>
        </EventProvider>
        <EventProvider Id="EventProvider_AM_Engine_With_Stacks" Base="EventProvider_AM_Engine" Name="0a002690-3839-4e3a-b3b6-96d8df868d99" Stack="true" />
        <EventProvider Id="EventProvider_AM_Engine_With_Stacks_StartRundown" Base="EventProvider_AM_Engine_With_StartRundown" Name="0a002690-3839-4e3a-b3b6-96d8df868d99" Stack="true" />
        <EventProvider Id="EventProvider_AM_Engine_With_Stacks_EndRundown" Base="EventProvider_AM_Engine_With_EndRundown" Name="0a002690-3839-4e3a-b3b6-96d8df868d99" Stack="true" />
        <!-- Platform providers -->
        <EventProvider Id="EventProvider_AM_Service" Name="Microsoft-Antimalware-Service">
            <Keywords>
                <Keyword Value="0x00000000FFFFFFFF" /> <!-- exclude capture state and reserved keywords from runtime keywords -->
            </Keywords>
        </EventProvider>
        <EventProvider Id="EventProvider_AM_Service_With_StartRundown" Base="EventProvider_AM_Service" Name="Microsoft-Antimalware-Service">
            <CaptureStateOnStart>
                <Keyword Value="0x0000040000000000" /> <!-- StartRundown -->
            </CaptureStateOnStart>
        </EventProvider>
        <EventProvider Id="EventProvider_AM_Service_With_EndRundown" Base="EventProvider_AM_Service" Name="Microsoft-Antimalware-Service">
            <CaptureStateOnSave>
                <Keyword Value="0x0000080000000000" /> <!-- EndRundown -->
            </CaptureStateOnSave>
        </EventProvider>
        <EventProvider Id="EventProvider_AM_Service_With_Stacks" Base="EventProvider_AM_Service" Name="Microsoft-Antimalware-Service" Stack="true" />
        <EventProvider Id="EventProvider_AM_Service_With_Stacks_StartRundown" Base="EventProvider_AM_Service_With_StartRundown" Name="Microsoft-Antimalware-Service" Stack="true" />
        <EventProvider Id="EventProvider_AM_Service_With_Stacks_EndRundown" Base="EventProvider_AM_Service_With_EndRundown" Name="Microsoft-Antimalware-Service" Stack="true" />
        
        <EventProvider Id="EventProvider_AM_RTP" Name="Microsoft-Antimalware-RTP" />
        <EventProvider Id="EventProvider_AM_Filter" Name="Microsoft-Antimalware-AMFilter" />
        <EventProvider Id="EventProvider_AM_Filter_With_Stacks" Name="Microsoft-Antimalware-AMFilter" Stack="true" />
        <EventProvider Id="EventProvider_AM_Protection" Name="Microsoft-Antimalware-Protection" />

        <EventProvider Id="EventProvider_AMSI" Name="Microsoft-Antimalware-Scan-Interface" cfg-any="AMSI" />
        <EventProvider Id="EventProvider_AMSI_UAC" Name="Microsoft-Antimalware-UacScan" cfg-any="AMSI" />

        <!-- Microsoft-Antimalware-Engine-DynamicSymbols & Microsoft-Antimalware-Engine-DynamicSymbolsRundown -->
        <EventProvider Id="EventProvider_Microsoft-Antimalware-Engine-DynamicSymbols" Name="e00ad681-35f9-4afc-950d-7ba36eefcfa5" Level="5"> <!-- Level 5: Verbose -->
            <Keywords>
                <Keyword Value="0x08" /> <!-- Loader: Module events -->
                <Keyword Value="0x10" /> <!-- JIT: Method events -->
            </Keywords>
        </EventProvider>

        <EventProvider Id="EventProvider_Microsoft-Antimalware-Engine-DynamicSymbolsRundown_CaptureState_StartRundown" Name="12137356-423b-4351-87d1-b6178dc73328" Level="5" CaptureStateOnly="true">
            <CaptureStateOnStart>
                <Keyword Value="0x08" /> <!-- Loader: Module events -->
                <Keyword Value="0x10" /> <!-- JIT: Method events -->
                <Keyword Value="0x40" /> <!-- Start Rundown -->
            </CaptureStateOnStart>
        </EventProvider>

        <EventProvider Id="EventProvider_Microsoft-Antimalware-Engine-DynamicSymbolsRundown_CaptureState_EndRundown" Name="12137356-423b-4351-87d1-b6178dc73328" Level="5" CaptureStateOnly="true">
            <CaptureStateOnSave>
                <Keyword Value="0x08" /> <!-- Loader: Module events -->
                <Keyword Value="0x10" /> <!-- JIT: Method events -->
                <Keyword Value="0x100" /> <!-- End Rundown -->
            </CaptureStateOnSave>
        </EventProvider>

        <!-- manifested Process lifetime provider -->
        <EventProvider Id="EventProvider_Windows_Kernel_Process" Name="Microsoft-Windows-Kernel-Process" />

        <!-- AXE provider -->
        <EventProvider Id="EventProvider_Windows_AssessmentExecutionEngine" Name="Microsoft-Windows-AssessmentExecutionEngine" />

        <!-- Network Providers -->
        <EventProvider Id="EventProvider_Microsoft_Windows_NCSI" Name="Microsoft-Windows-NCSI" cfg-any="Network" />

        <EventProvider Id="EventProvider_Microsoft_Windows_WLAN_AutoConfig" Name="Microsoft-Windows-WLAN-AutoConfig" cfg-any="Network">
            <Keywords>
                <Keyword Value="0x200" /> <!-- WlanConnect -->
            </Keywords>
        </EventProvider>

        <EventProvider Id="EventProvider_Microsoft_Windows_TCPIP" Name="Microsoft-Windows-TCPIP" cfg-any="Network TcpIp FullTcpIp">
            <Keywords cfg-none="FullTcpIp">
                <Keyword Value="0x80" /> <!--TcpipDiagnosis -->
            </Keywords>
        </EventProvider>

        <EventProvider Id="EventProvider_Microsoft_Windows_WinInet" Name="Microsoft-Windows-WinInet" cfg-any="WinInet" />
        <EventProvider Id="EventProvider_Microsoft_Windows_WinHttp" Name="Microsoft-Windows-WinHttp" cfg-any="WinHttp" />
        
        <!-- DNS -->
        <EventProvider Id="EventProvider_Microsoft_Windows_DNS_Client" Name="Microsoft-Windows-DNS-Client" cfg-any="Network DNS" />

        <!-- SMB -->
        <EventProvider Id="EventProvider_Microsoft_Windows_SMBClient" Name="Microsoft-Windows-SMBClient" cfg-any="Network SMB">
            <Keywords>
                <Keyword Value="0x001" /> <!-- Smb_Perf -->
                <Keyword Value="0x002" /> <!-- Networking_Perf -->
                <Keyword Value="0x004" /> <!-- Smb_Info -->
                <Keyword Value="0x008" /> <!-- InfoCache_Info -->
                <Keyword Value="0x010" /> <!-- Smb_TFO -->
                <Keyword Value="0x020" /> <!-- Smb_MultiChannel -->
                <Keyword Value="0x040" /> <!-- Smb_Connectivity -->
                <Keyword Value="0x080" /> <!-- Smb_Authentication -->
                <Keyword Value="0x100" /> <!-- Smb_Authorization -->
                <Keyword Value="0x200" /> <!-- Smb_Security -->
            </Keywords>
        </EventProvider>

        <!-- Additional providers that enhance Wait Analysis -->
        <EventProvider Id="EventProvider_ThreadPool" Name="c861d0e2-a2c1-4d36-9f9c-970bab943a12" />
        <EventProvider Id="EventProvider_Microsoft-Windows-RPC" Name="Microsoft-Windows-RPC" Level="4" Stack="true" />
        <EventProvider Id="EventProvider_Microsoft-Windows-RPCSS" Name="Microsoft-Windows-RPCSS" Level="4" Stack="true" />
        <EventProvider Id="EventProvider_Microsoft-Windows-Networking-Correlation" Name="Microsoft-Windows-Networking-Correlation" cfg-any="Network" />
        <EventProvider Id="EventProviderClass_PerfTrack" Name="PerfTrack" Level="4" NonPagedMemory="true" />
        <EventProvider Id="EventProvider_Microsoft-Windows-Win32k_MessagePump" Name="Microsoft-Windows-Win32k" Stack="true">
            <Keywords>
                <Keyword Value="0x400000" /> <!-- MessagePump -->
            </Keywords>
        </EventProvider>

        <!-- Base providers -->
        <EventProvider Id="EventProvider_WPR_Status" Name="36b6f488-aad7-48c2-afe3-d4ec2c8b46fa">
            <Keywords>
                <Keyword Value="0x10000" /> <!-- Perf Status -->
            </Keywords>
        </EventProvider>

        <EventProvider Id="EventProvider_Microsoft_Windows_Performance_Recorder_Context" Name="b7a19fcd-15ba-41ba-a3d7-dc352d5f79ba" NonPagedMemory="true" Strict="true" />

        <EventProvider Id="EventProvider_PerfTrack" Name="PerfTrack" NonPagedMemory="true" Level="4" />

        <EventProvider Id="EventProvider_Microsoft-Windows-Kernel-EventTracing" Name="b675ec37-bdb6-4648-bc92-f3fdc74d3ca2" Level="15" NonPagedMemory="true">
            <Keywords>
                <Keyword Value="0x040" /> <!-- Lost Event -->
            </Keywords>
        </EventProvider>

        <!-- Heap Event Providers -->

        <HeapEventProvider Id="HeapProvider_WDHeap" cfg-any="Heap">
            <HeapProcessIds>
                $HeapProcessIdElements
            </HeapProcessIds>
        </HeapEventProvider>

        <!-- Profiles -->
        <Profile Id="BaseProfile.Light" Name="BaseProfile" Description="BaseProfile" DetailLevel="Light" Base="" LoggingMode="File" Internal="true">
            <Collectors>
                <EventCollectorId Value="EventCollector_WDEventCollectorInFile">
                    <EventProviders>
                        <EventProviderId Value="EventProvider_WPR_Status" />
                        <EventProviderId Value="EventProvider_Microsoft_Windows_Performance_Recorder_Context" />
                        <EventProviderId Value="EventProvider_PerfTrack" />
                        <EventProviderId Value="EventProvider_Microsoft-Windows-ProcessStateManager" />
                        <EventProviderId Value="EventProvider_Microsoft-Windows-BrokerInfrastructure" />
                        <EventProviderId Value="EventProvider_Microsoft-Windows-Kernel-EventTracing" />
                    </EventProviders>
                </EventCollectorId>
            </Collectors>
            <TraceMergeProperties>
                <TraceMergeProperty Id="BaseLightTraceMergeProperties" Name="BaseTraceMergeProperties" Base="">
                    <DeletePreMergedTraceFiles Value="true" />
                    <FileCompression Value="true" />
                    <CustomEvents>
                        <CustomEvent Value="ImageId" />
                        <CustomEvent Value="BuildInfo" />
                        <CustomEvent Value="VolumeMapping" />
                        <CustomEvent Value="EventMetadata" />
                        <CustomEvent Value="PerfTrackMetadata" />
                        <CustomEvent Value="WinSAT" />
                        <CustomEvent Value="NetworkInterface" />
                    </CustomEvents>
                </TraceMergeProperty>
            </TraceMergeProperties>
        </Profile>

        <Profile Id="WD.Light.File" Base="BaseProfile.Light" LoggingMode="File" Name="WD" DetailLevel="Light" Description="Microsoft Defender for Endpoint analysis">
            <Collectors Operation="Add">
                <SystemCollectorId Value="SystemCollector_WDSystemCollectorInFile">
                    <SystemProviderId Value="SystemProvider_WD_Light" />
                </SystemCollectorId>
                <EventCollectorId Value="EventCollector_WDEventCollectorInFile">
                    <EventProviders Operation="Add">
                        <EventProviderId Value="EventProvider_AM_CommonUtils" cfg-any="AntimalwareCommonUtils" />
                        <EventProviderId Value="EventProvider_AM_Engine_With_StartRundown" />
                        <EventProviderId Value="EventProvider_AM_Service_With_StartRundown" />
                        <EventProviderId Value="EventProvider_AM_RTP" />
                        <EventProviderId Value="EventProvider_AM_Filter" />
                        <EventProviderId Value="EventProvider_AM_Protection" />
                        <EventProviderId Value="EventProvider_AMSI" cfg-any="AMSI" />
                        <EventProviderId Value="EventProvider_AMSI_UAC" cfg-any="AMSI" />
                        <EventProviderId Value="EventProvider_DWMWin32k" />
                        <EventProviderId Value="EventProvider_DWMWin32k_CaptureState" />
                        <EventProviderId Value="EventProvider_Microsoft-Windows-Win32k_Focus" />
                        <EventProviderId Value="EventProvider_Microsoft-Windows-Win32k_CaptureState" />
                        <EventProviderId Value="EventProvider_Windows_Kernel_Process" />

                        <EventProviderId Value="EventProvider_Windows_AssessmentExecutionEngine" />

                        <!-- Network -->
                        <EventProviderId Value="EventProvider_Microsoft_Windows_NCSI" cfg-any="Network" />
                        <EventProviderId Value="EventProvider_Microsoft_Windows_WLAN_AutoConfig" cfg-any="Network" />
                        <EventProviderId Value="EventProvider_Microsoft_Windows_TCPIP" cfg-any="Network" />

                        <EventProviderId Value="EventProvider_Microsoft_Windows_WinInet" cfg-any="WinInet" />
                        <EventProviderId Value="EventProvider_Microsoft_Windows_WinHttp" cfg-any="WinHttp" />

                        <!-- DNS -->
                        <EventProviderId Value="EventProvider_Microsoft_Windows_DNS_Client" cfg-any="Network DNS" />

                        <!-- Microsoft-Antimalware-Engine-DynamicSymbols & Microsoft-Antimalware-Engine-DynamicSymbolsRundown -->
                        <EventProviderId Value="EventProvider_Microsoft-Antimalware-Engine-DynamicSymbols" />
                        <EventProviderId Value="EventProvider_Microsoft-Antimalware-Engine-DynamicSymbolsRundown_CaptureState_StartRundown" />
                    </EventProviders>
                </EventCollectorId>
            </Collectors>
        </Profile>

        <Profile Id="WDHeap.Light.File" Base="WD.Light.File" LoggingMode="File" Name="WDHeap" DetailLevel="Light" Description="Microsoft Defender for Endpoint heap analysis" cfg-any="Heap">
            <Collectors Operation="Add">
                <SystemCollectorId Value="SystemCollector_WDSystemCollectorInFile">
                    <SystemProviderId Value="SystemProvider_WDHeap_Light" />
                </SystemCollectorId>
                <HeapEventCollectorId Value="HeapCollector_WDHeapEventCollectorInFile">
                    <HeapEventProviders>
                        <HeapEventProviderId Value="HeapProvider_WDHeap" />
                    </HeapEventProviders>
                </HeapEventCollectorId>
            </Collectors>
        </Profile>

        <Profile Id="WD.Light.Memory" Base="BaseProfile.Light" LoggingMode="Memory" Name="WD" DetailLevel="Light" Description="Microsoft Defender for Endpoint analysis">
            <Collectors Operation="Add">
                <SystemCollectorId Value="SystemCollector_WDSystemCollectorInMemory">
                    <SystemProviderId Value="SystemProvider_WD_Light" />
                </SystemCollectorId>
                <EventCollectorId Value="EventCollector_WDEventCollectorInMemory">
                    <EventProviders Operation="Add">
                        <EventProviderId Value="EventProvider_AM_CommonUtils" cfg-any="AntimalwareCommonUtils" />
                        <EventProviderId Value="EventProvider_AM_Engine_With_EndRundown" />
                        <EventProviderId Value="EventProvider_AM_Service_With_EndRundown" />
                        <EventProviderId Value="EventProvider_AM_RTP" />
                        <EventProviderId Value="EventProvider_AM_Filter" />
                        <EventProviderId Value="EventProvider_AM_Protection" />
                        <EventProviderId Value="EventProvider_AMSI" cfg-any="AMSI" />
                        <EventProviderId Value="EventProvider_AMSI_UAC" cfg-any="AMSI" />
                        <EventProviderId Value="EventProvider_DWMWin32k" />
                        <EventProviderId Value="EventProvider_DWMWin32k_CaptureState" />
                        <EventProviderId Value="EventProvider_Microsoft-Windows-Win32k_Focus" />
                        <EventProviderId Value="EventProvider_Microsoft-Windows-Win32k_CaptureState" />
                        <EventProviderId Value="EventProvider_Windows_Kernel_Process" />

                        <EventProviderId Value="EventProvider_Windows_AssessmentExecutionEngine" />

                        <!-- Network -->
                        <EventProviderId Value="EventProvider_Microsoft_Windows_NCSI" cfg-any="Network" />
                        <EventProviderId Value="EventProvider_Microsoft_Windows_WLAN_AutoConfig" cfg-any="Network" />
                        <EventProviderId Value="EventProvider_Microsoft_Windows_TCPIP" cfg-any="Network" />

                        <EventProviderId Value="EventProvider_Microsoft_Windows_WinInet" cfg-any="WinInet" />
                        <EventProviderId Value="EventProvider_Microsoft_Windows_WinHttp" cfg-any="WinHttp" />

                        <!-- DNS -->
                        <EventProviderId Value="EventProvider_Microsoft_Windows_DNS_Client" cfg-any="Network DNS" />

                        <!-- Microsoft-Antimalware-Engine-DynamicSymbols & Microsoft-Antimalware-Engine-DynamicSymbolsRundown -->
                        <EventProviderId Value="EventProvider_Microsoft-Antimalware-Engine-DynamicSymbols" />
                        <EventProviderId Value="EventProvider_Microsoft-Antimalware-Engine-DynamicSymbolsRundown_CaptureState_EndRundown" />
                    </EventProviders>
                </EventCollectorId>
            </Collectors>
        </Profile>

        <Profile Id="WDHeap.Light.Memory" Base="WD.Light.Memory" LoggingMode="Memory" Name="WDHeap" DetailLevel="Light" Description="Microsoft Defender for Endpoint heap analysis" cfg-any="Heap">
            <Collectors Operation="Add">
                <SystemCollectorId Value="SystemCollector_WDSystemCollectorInMemory">
                    <SystemProviderId Value="SystemProvider_WDHeap_Light" />
                </SystemCollectorId>
                <HeapEventCollectorId Value="HeapCollector_WDHeapEventCollectorInMemory">
                    <HeapEventProviders>
                        <HeapEventProviderId Value="HeapProvider_WDHeap" />
                    </HeapEventProviders>
                </HeapEventCollectorId>
            </Collectors>
        </Profile>

        <Profile Id="WD.Verbose.File" Base="BaseProfile.Light" LoggingMode="File" Name="WD" DetailLevel="Verbose" Description="Microsoft Defender for Endpoint analysis">
            <Collectors Operation="Add">
                <SystemCollectorId Value="SystemCollector_WDSystemCollectorInFileLarge">
                    <SystemProviderId Value="SystemProvider_WD_Verbose" />
                </SystemCollectorId>
                <EventCollectorId Value="EventCollector_WDEventCollectorInFileLarge">
                    <EventProviders Operation="Add">
                        <EventProviderId Value="EventProvider_AM_CommonUtils_With_Stacks" cfg-any="AntimalwareCommonUtils" />
                        <EventProviderId Value="EventProvider_AM_Engine_With_Stacks_StartRundown" />
                        <EventProviderId Value="EventProvider_AM_Service_With_Stacks_StartRundown" />
                        <EventProviderId Value="EventProvider_AM_RTP" />
                        <EventProviderId Value="EventProvider_AM_Filter_With_Stacks" />
                        <EventProviderId Value="EventProvider_AM_Protection" />
                        <EventProviderId Value="EventProvider_AMSI" cfg-any="AMSI" />
                        <EventProviderId Value="EventProvider_AMSI_UAC" cfg-any="AMSI" />
                        <EventProviderId Value="EventProvider_DWMWin32k" />
                        <EventProviderId Value="EventProvider_DWMWin32k_CaptureState" />
                        <EventProviderId Value="EventProvider_Microsoft-Windows-Win32k_Focus" />
                        <EventProviderId Value="EventProvider_Microsoft-Windows-Win32k_CaptureState" />
                        <EventProviderId Value="EventProvider_Microsoft-Windows-COMRuntime" />
                        <EventProviderId Value="EventProvider_Windows_Kernel_Process" />

                        <EventProviderId Value="EventProvider_Windows_AssessmentExecutionEngine" />

                        <!-- Network -->
                        <EventProviderId Value="EventProvider_Microsoft_Windows_NCSI" cfg-any="Network" />
                        <EventProviderId Value="EventProvider_Microsoft_Windows_WLAN_AutoConfig" cfg-any="Network" />
                        <EventProviderId Value="EventProvider_Microsoft_Windows_TCPIP" cfg-any="Network" />

                        <EventProviderId Value="EventProvider_Microsoft_Windows_WinInet" cfg-any="WinInet" />
                        <EventProviderId Value="EventProvider_Microsoft_Windows_WinHttp" cfg-any="WinHttp" />

                        <!-- DNS -->
                        <EventProviderId Value="EventProvider_Microsoft_Windows_DNS_Client" cfg-any="Network DNS" />

                        <!-- Additional providers that enhance Wait Analysis -->
                        <EventProviderId Value="EventProvider_ThreadPool" />
                        <EventProviderId Value="EventProvider_Microsoft-Windows-RPC" />
                        <EventProviderId Value="EventProvider_Microsoft-Windows-RPCSS" />
                        <EventProviderId Value="EventProvider_Microsoft-Windows-Networking-Correlation" cfg-any="Network" />
                        <EventProviderId Value="EventProviderClass_PerfTrack" />
                        <EventProviderId Value="EventProvider_Microsoft-Windows-Win32k_MessagePump" />

                        <!-- SMB -->
                        <EventProviderId Value="EventProvider_Microsoft_Windows_SMBClient" cfg-any="Network SMB" />

                        <!-- Microsoft-Antimalware-Engine-DynamicSymbols & Microsoft-Antimalware-Engine-DynamicSymbolsRundown -->
                        <EventProviderId Value="EventProvider_Microsoft-Antimalware-Engine-DynamicSymbols" />
                        <EventProviderId Value="EventProvider_Microsoft-Antimalware-Engine-DynamicSymbolsRundown_CaptureState_StartRundown" />
                    </EventProviders>
                </EventCollectorId>
            </Collectors>
        </Profile>

        <Profile Id="WDHeap.Verbose.File" Base="WD.Verbose.File" LoggingMode="File" Name="WDHeap" DetailLevel="Verbose" Description="Microsoft Defender for Endpoint heap analysis" cfg-any="Heap">
            <Collectors Operation="Add">
                <SystemCollectorId Value="SystemCollector_WDSystemCollectorInFileLarge">
                    <SystemProviderId Value="SystemProvider_WDHeap_Verbose" />
                </SystemCollectorId>
                <HeapEventCollectorId Value="HeapCollector_WDHeapEventCollectorInFile">
                    <HeapEventProviders>
                        <HeapEventProviderId Value="HeapProvider_WDHeap" />
                    </HeapEventProviders>
                </HeapEventCollectorId>
            </Collectors>
        </Profile>

        <Profile Id="WD.Verbose.Memory" Base="BaseProfile.Light" LoggingMode="Memory" Name="WD" DetailLevel="Verbose" Description="Microsoft Defender for Endpoint analysis">
            <Collectors Operation="Add">
                <SystemCollectorId Value="SystemCollector_WDSystemCollectorInMemoryLarge">
                    <SystemProviderId Value="SystemProvider_WD_Verbose" />
                </SystemCollectorId>
                <EventCollectorId Value="EventCollector_WDEventCollectorInMemoryLarge">
                    <EventProviders Operation="Add">
                        <EventProviderId Value="EventProvider_AM_CommonUtils_With_Stacks" cfg-any="AntimalwareCommonUtils" />
                        <EventProviderId Value="EventProvider_AM_Engine_With_Stacks_EndRundown" />
                        <EventProviderId Value="EventProvider_AM_Service_With_Stacks_EndRundown" />
                        <EventProviderId Value="EventProvider_AM_RTP" />
                        <EventProviderId Value="EventProvider_AM_Filter_With_Stacks" />
                        <EventProviderId Value="EventProvider_AM_Protection" />
                        <EventProviderId Value="EventProvider_AMSI" cfg-any="AMSI" />
                        <EventProviderId Value="EventProvider_AMSI_UAC" cfg-any="AMSI" />
                        <EventProviderId Value="EventProvider_DWMWin32k" />
                        <EventProviderId Value="EventProvider_DWMWin32k_CaptureState" />
                        <EventProviderId Value="EventProvider_Microsoft-Windows-Win32k_Focus" />
                        <EventProviderId Value="EventProvider_Microsoft-Windows-Win32k_CaptureState" />
                        <EventProviderId Value="EventProvider_Microsoft-Windows-COMRuntime" />
                        <EventProviderId Value="EventProvider_Windows_Kernel_Process" />

                        <EventProviderId Value="EventProvider_Windows_AssessmentExecutionEngine" />

                        <!-- Network -->
                        <EventProviderId Value="EventProvider_Microsoft_Windows_NCSI" cfg-any="Network" />
                        <EventProviderId Value="EventProvider_Microsoft_Windows_WLAN_AutoConfig" cfg-any="Network" />
                        <EventProviderId Value="EventProvider_Microsoft_Windows_TCPIP" cfg-any="Network" />

                        <EventProviderId Value="EventProvider_Microsoft_Windows_WinInet" cfg-any="WinInet" />
                        <EventProviderId Value="EventProvider_Microsoft_Windows_WinHttp" cfg-any="WinHttp" />

                        <!-- DNS -->
                        <EventProviderId Value="EventProvider_Microsoft_Windows_DNS_Client" cfg-any="Network DNS" />

                        <!-- Additional providers that enhance Wait Analysis -->
                        <EventProviderId Value="EventProvider_ThreadPool" />
                        <EventProviderId Value="EventProvider_Microsoft-Windows-RPC" />
                        <EventProviderId Value="EventProvider_Microsoft-Windows-RPCSS" />
                        <EventProviderId Value="EventProvider_Microsoft-Windows-Networking-Correlation" cfg-any="Network" />
                        <EventProviderId Value="EventProviderClass_PerfTrack" />
                        <EventProviderId Value="EventProvider_Microsoft-Windows-Win32k_MessagePump" />

                        <!-- SMB -->
                        <EventProviderId Value="EventProvider_Microsoft_Windows_SMBClient" cfg-any="Network SMB" />

                        <!-- Microsoft-Antimalware-Engine-DynamicSymbols & Microsoft-Antimalware-Engine-DynamicSymbolsRundown -->
                        <EventProviderId Value="EventProvider_Microsoft-Antimalware-Engine-DynamicSymbols" />
                        <EventProviderId Value="EventProvider_Microsoft-Antimalware-Engine-DynamicSymbolsRundown_CaptureState_EndRundown" />
                    </EventProviders>
                </EventCollectorId>
            </Collectors>
        </Profile>

        <Profile Id="WDHeap.Verbose.Memory" Base="WD.Verbose.Memory" LoggingMode="Memory" Name="WDHeap" DetailLevel="Verbose" Description="Microsoft Defender for Endpoint heap analysis" cfg-any="Heap">
            <Collectors Operation="Add">
                <SystemCollectorId Value="SystemCollector_WDSystemCollectorInMemoryLarge">
                    <SystemProviderId Value="SystemProvider_WDHeap_Verbose" />
                </SystemCollectorId>
                <HeapEventCollectorId Value="HeapCollector_WDHeapEventCollectorInMemory">
                    <HeapEventProviders>
                        <HeapEventProviderId Value="HeapProvider_WDHeap" />
                    </HeapEventProviders>
                </HeapEventCollectorId>
            </Collectors>
        </Profile>

    </Profiles>

    <TraceMergeProperties>
        <TraceMergeProperty Id="Default" Name="Default" Base="">
            <DeletePreMergedTraceFiles Value="true" />
            <FileCompression Value="true" />
            <CustomEvents>
                <CustomEvent Value="ImageId" />
                <CustomEvent Value="BuildInfo" />
                <CustomEvent Value="VolumeMapping" />
                <CustomEvent Value="EventMetadata" />
                <CustomEvent Value="PerfTrackMetadata" />
                <CustomEvent Value="WinSAT" />
                <CustomEvent Value="NetworkInterface" />
            </CustomEvents>
        </TraceMergeProperty>
    </TraceMergeProperties>

</WindowsPerformanceRecorder>
"@

    # Transform <BuffersPerCpu Value="..." [MaximumBufferSpace="..."] [MaximumPercentOfTotalMemory="..."] /> into <Buffers Value="..." />

    Write-Verbose 'Machine Parameters'

    [int]$numberOfLogicalProcessors = [System.Environment]::ProcessorCount
    [long]$totalMemory = $(Get-CimInstance –ClassName Win32_ComputerSystem -Verbose:$false).TotalPhysicalMemory
    Write-Verbose "  NumberOfLogicalProcessors: $numberOfLogicalProcessors"
    Write-Verbose ('  TotalMemory: {0:f2}GB' -f ($totalMemory/1GB))

    Write-Verbose 'Preprocess: BuffersPerCpu'

    $wprp.SelectNodes('//BuffersPerCpu') | ForEach-Object {

        Write-Verbose "  Value: $($_.Value)"

        $numberOfBuffers = [int]([double]$_.Value * [double]$numberOfLogicalProcessors)

        Write-Verbose "  Buffers: $numberOfBuffers"

        if ($_.Attributes.GetNamedItem('MaximumBufferSpace')) {
            Write-Verbose "    MaximumBufferSpace: $($_.MaximumBufferSpace) [MB]"
            Write-Verbose "    BufferSize: $($_.ParentNode.BufferSize.Value) [kB]"
            $numberOfBuffersLimit = [int]([int]$_.MaximumBufferSpace * [int]1024 / [int]$_.ParentNode.BufferSize.Value) # MaximumBufferSpace is in MB, BufferSize.Value is in kB.
            Write-Verbose "    Buffers: $numberOfBuffersLimit"
            $numberOfBuffers = [Math]::Min($numberOfBuffers, $numberOfBuffersLimit)
        }
        
        if ($_.Attributes.GetNamedItem('MaximumPercentOfTotalMemory')) {
            Write-Verbose "    MaximumPercentOfTotalMemory: $($_.MaximumPercentOfTotalMemory) [%]"
            Write-Verbose "    BufferSize: $($_.ParentNode.BufferSize.Value) [kB]"
            $numberOfBuffersLimit = [int]([long]$totalMemory * [int]$_.MaximumPercentOfTotalMemory / [int]100 / ([int]$_.Parent.BufferSize.Value * [int]1024)) # totalMemory is in B, BufferSize.Value is in kB.
            $numberOfBuffers = [Math]::Min($numberOfBuffers, $numberOfBuffersLimit)
            Write-Verbose "    Buffers: $numberOfBuffersLimit"
        }

        Write-Verbose "  Buffers: $numberOfBuffers"

        $buffers = $_.OwnerDocument.CreateElement('Buffers')
        $buffers.SetAttribute('Value', $numberOfBuffers.ToString())
        [void]$_.ParentNode.ReplaceChild($buffers, $_)
    }

    Write-Verbose 'Preprocess: @cfg-any'
    # Preprocess <... cfg-any="..." />

    $wprp.SelectNodes('//*[@cfg-any]') | ForEach-Object {

        $tags = $_.'cfg-any'.Split(' ').Where({$_ -ne ''})

        $any = $false
        foreach ($tag in $tags)
        {
            if ($Categories -contains $tag) {
                $any = $true
                break;
            }
        }

        if ($any) {
            [void]$_.Attributes.RemoveNamedItem('cfg-any')
        } else {
            [void]$_.ParentNode.RemoveChild($_)
        }
    }

    Write-Verbose 'Preprocess: @cfg-none'

    # Preprocess <... cfg-none="..." />

    $wprp.SelectNodes('//*[@cfg-none]') | ForEach-Object {

        $tags = $_.'cfg-none'.Split(' ').Where({$_ -ne ''})

        $any = $false
        foreach ($tag in $tags)
        {
            if ($Categories -contains $tag) {
                $any = $true
                break;
            }
        }

        if (-not $any) {
            [void]$_.Attributes.RemoveNamedItem('cfg-none')
        } else {
            [void]$_.ParentNode.RemoveChild($_)
        }
    }

    # # Human readable XML
    # $verboseParameter = $ScriptPSCmdlet.MyInvocation.BoundParameters["Verbose"]
    # if (($null -ne $verboseParameter) -and $verboseParameter.IsPresent) {
    #     Write-Verbose ([System.Xml.Linq.XElement]::Parse($wprp.OuterXml).ToString())
    # }

    # Compact XML
    $wprp.OuterXml
}

# Set an automatic filename if not specified

function GetTimestamp {
    Get-Date -Format o -AsUTC | ForEach-Object { $_ -replace '[-T:.]', '_' -replace 'Z','' }
}


if ([string]::IsNullOrEmpty($RecordTo)) {

    $RecordTo = "$(GetWorkloadName)-$(GetTimestamp).etl"
}


#
# Main
#

[bool]$interactiveMode = ($PSCmdlet.ParameterSetName -eq 'Interactive')

# Hosts
[string]$powerShellHostConsole = 'ConsoleHost'
[string]$powerShellHostISE = 'Windows PowerShell ISE Host'
[string]$powerShellHostRemote = 'ServerRemoteHost'

if ($interactiveMode -and ($Host.Name -notin @($powerShellHostConsole, $powerShellHostISE, $powerShellHostRemote))) {
    $ex = New-Object System.Management.Automation.ItemNotFoundException 'Cmdlet supported only on local PowerShell console, Windows PowerShell ISE and remote PowerShell console.'
    $category = [System.Management.Automation.ErrorCategory]::NotImplemented
    $errRecord = New-Object System.Management.Automation.ErrorRecord $ex,'NotImplemented',$category,$Host.Name
    $psCmdlet.WriteError($errRecord)
    return
}


if (-not (Test-Path -LiteralPath:$RecordTo -IsValid)) {
    $ex = New-Object System.Management.Automation.ItemNotFoundException "Cannot record Microsoft Defender Antivirus performance recording to path '$RecordTo' because the location does not exist."
    $category = [System.Management.Automation.ErrorCategory]::InvalidArgument
    $errRecord = New-Object System.Management.Automation.ErrorRecord $ex,'InvalidPath',$category,$RecordTo
    $psCmdlet.WriteError($errRecord)
    return
}

# Resolve any relative paths
$RecordTo = $psCmdlet.SessionState.Path.GetUnresolvedProviderPathFromPSPath($RecordTo)

# Dependencies: WPR Version

# If user provides a valid string as $WPRPath, honor that request.
[string]$wprCommand = $WPRPath

try 
{
    if (!$wprCommand) {
        $wprCommand = "wpr.exe"
        $wprs = @(Get-Command -All "wpr" 2> $null)

        if ($wprs -and ($wprs.Length -ne 0)) {
            $latestVersion = [System.Version]"0.0.0.0"

            $wprs | ForEach-Object {
                $currentVersion = $_.Version
                $currentFullPath = $_.Source
                $currentVersionString = $currentVersion.ToString()
                Write-Host "Found $currentVersionString at $currentFullPath"

                if ($currentVersion -gt $latestVersion) {
                    $latestVersion = $currentVersion
                    $wprCommand = $currentFullPath
                }
            }
        }
    }
}
catch
{
    # Fallback to the old ways in case we encounter an error (ex: version string format change).
    $wprCommand = "wpr.exe"
}

#
# Test dependency presence
#
if (-not (Get-Command $wprCommand -ErrorAction:SilentlyContinue)) {
    $ex = New-Object System.Management.Automation.ItemNotFoundException "Cannot find dependency command '$wprCommand' because it does not exist."
    $category = [System.Management.Automation.ErrorCategory]::ObjectNotFound
    $errRecord = New-Object System.Management.Automation.ErrorRecord $ex,'PathNotFound',$category,$wprCommand
    $psCmdlet.WriteError($errRecord)
    return
}

Write-Host "`nUsing $wprCommand version $((Get-Command $wprCommand).FileVersionInfo.FileVersion)`n"    

# Exclude versions that have known bugs or are not supported any more.
[int]$wprFileVersion = ((Get-Command $wprCommand).Version.Major) -as [int]
if ($wprFileVersion -le 6) {
    $ex = New-Object System.Management.Automation.PSNotSupportedException "You are using an older and unsupported version of '$wprCommand'. Please download and install Windows ADK:`r`nhttps://docs.microsoft.com/en-us/windows-hardware/get-started/adk-install`r`nand try again."
    $category = [System.Management.Automation.ErrorCategory]::NotInstalled
    $errRecord = New-Object System.Management.Automation.ErrorRecord $ex,'NotSupported',$category,$wprCommand
    $psCmdlet.WriteError($errRecord)
    return
}

function CancelPerformanceRecording {
    Write-Host "`n`nCancelling Microsoft Defender Antivirus performance recording... " -NoNewline

    $wprOptions = @()

    if (-not [string]::IsNullOrEmpty($InstanceName)) {
        $wprOptions += @('-instancename',$InstanceName)
    }

    & $wprCommand -cancel @wprOptions
    $wprCommandExitCode = $LASTEXITCODE

    switch ($wprCommandExitCode) {
        0 {}
        0xc5583000 {
            Write-Error "Cannot cancel performance recording because currently Windows Performance Recorder is not recording."
            return
        }
        default {
            Write-Error ("Cannot cancel performance recording: 0x{0:x08}." -f $wprCommandExitCode)
            return
        }
    }

    Write-Host "ok.`n`nRecording has been cancelled."
}

#
# Ensure Ctrl-C doesn't abort the app without cleanup
#

# - local PowerShell consoles: use [Console]::TreatControlCAsInput; cleanup performed and output preserved
# - PowerShell ISE: use try { ... } catch { throw } finally; cleanup performed and output preserved
# - remote PowerShell: use try { ... } catch { throw } finally; cleanup performed but output truncated

[bool]$canTreatControlCAsInput = $interactiveMode -and ($Host.Name -eq $powerShellHostConsole)
$savedControlCAsInput = $null

$shouldCancelRecordingOnTerminatingError = $false

try
{
    if ($canTreatControlCAsInput) {
        $savedControlCAsInput = [Console]::TreatControlCAsInput
        [Console]::TreatControlCAsInput = $true
    }

    #
    # Start recording
    #

    Write-Host "Starting Microsoft Defender Antivirus performance recording$(if($FileMode) {''} else {' in flight-recorder mode'})... " -NoNewline

    $shouldCancelRecordingOnTerminatingError = $true

    $wprCommandExitCode = StartPerformanceRecording

    switch ($wprCommandExitCode) {
        0 {}
        0xc5583001 {
            $shouldCancelRecordingOnTerminatingError = $false
            Write-Error "Cannot start performance recording because Windows Performance Recorder is already recording."
            return
        }
        0x80070008 {
            $shouldCancelRecordingOnTerminatingError = $false
            Write-Error "Cannot start performance recording because the device does not currently have enough memory available for the necessary buffer space. Close some applications and retry after more memory is available."
            return
        }
        default {
            $shouldCancelRecordingOnTerminatingError = $false
            Write-Error ("Cannot start performance recording: 0x{0:x08}." -f $wprCommandExitCode)
            return
        }
    }

    Write-Host "ok.`n`n$capitalizedRecordingType has started." -NoNewline

    if ($interactiveMode) {
        $stopPrompt = "`n`n=> Reproduce the scenario that is impacting the performance on your device.`n`n   Press <ENTER> to stop and save recording or <Ctrl-C> to cancel recording"

        if ($canTreatControlCAsInput) {
            Write-Host "${stopPrompt}: "

            do {
                $key = [Console]::ReadKey($true)
                if (($key.Modifiers -eq [ConsoleModifiers]::Control) -and (($key.Key -eq [ConsoleKey]::C))) {

                    CancelPerformanceRecording

                    $shouldCancelRecordingOnTerminatingError = $false

                    #
                    # Restore Ctrl-C behavior
                    #

                    [Console]::TreatControlCAsInput = $savedControlCAsInput

                    return
                }

            } while (($key.Modifiers -band ([ConsoleModifiers]::Alt -bor [ConsoleModifiers]::Control -bor [ConsoleModifiers]::Shift)) -or ($key.Key -ne [ConsoleKey]::Enter))

        } else {
            Read-Host -Prompt:$stopPrompt
        }
    } else {
        & RunWorkload
    }

    if ($ScriptPSCmdlet.ParameterSetName -ne 'OpenEnded') {

        #
        # Stop recording
        #

        Write-Host "`n`nStopping Microsoft Defender Antivirus performance recording...`n"

        $wprCommandExitCode = StopPerformanceRecording

        switch ($wprCommandExitCode) {
            0 {
                $shouldCancelRecordingOnTerminatingError = $false
            }
            0xc5583000 {
                $shouldCancelRecordingOnTerminatingError = $false
                Write-Error "Cannot stop performance recording because Windows Performance Recorder is not recording a trace."
                return
            }
            default {
                Write-Error ("Cannot stop performance recording: 0x{0:x08}." -f $wprCommandExitCode)
                return
            }
        }

        Write-Host "`nRecording has been saved to '$RecordTo'."

        Write-Host `
'
The performance analyzer provides insight into problematic files that could
cause performance degradation of Microsoft Defender Antivirus. This tool is
provided "AS IS", and is not intended to provide suggestions on exclusions.
Exclusions can reduce the level of protection on your endpoints. Exclusions,
if any, should be defined with caution.
'
        Write-Host `
'
The trace you have just captured may contain personally identifiable information,
including but not necessarily limited to paths to files accessed, paths to
registry accessed and process names. Exact information depends on the events that
were logged. Please be aware of this when sharing this trace with other people.
'

        if ($GetSupportFilesCab.IsPresent) {

            Write-Host "`n`nCollecting Microsoft Defender Antivirus support files cab... " -NoNewline

            & $mpCmdRunCommand -GetFiles *> $null | Out-Null

            $RecordSupportCabTo = $RecordTo -replace '\.etl$','.MpSupportFiles.cab'

            Copy-Item -Force -LiteralPath:"$PlatformPath\..\..\Support\MpSupportFiles.cab" -Destination:$RecordSupportCabTo

            Write-Host "ok.`n`nSupport files cab has been saved to '$RecordSupportCabTo'."

        }
    }

} catch {
    throw
} finally {
    if ($shouldCancelRecordingOnTerminatingError) {
        CancelPerformanceRecording
    }

    if ($null -ne $savedControlCAsInput) {
        #
        # Restore Ctrl-C behavior
        #

        [Console]::TreatControlCAsInput = $savedControlCAsInput
    }
}
