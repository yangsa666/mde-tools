# Collecting the appropriate data
In a scenario where a customer is unable to repro at will but the issue reoccurs over 1 or a few days:  

## Use (currently experimental) New-DefenderPerformanceRecording.ps1 script to collect automatically a flight-recording mode heap trace when a certain private memory threshold and private memory growth over polling interval threshold are met.  


   * Use the automated collector at \\azrwu2tehpv19cx\tools\New-DefenderPerformanceRecording.ps1 with a command line like:  

```
.\New-DefenderPerformanceRecording.ps1 -RecordTo:C:\Data\HighMemoryUsage-Exceeding-3GB-and-40MB-growth-over-10s.etl -HighMemoryUsage -ExceedingPrivateBytes:3GB -ExceedingPrivateBytesGrowth:40MB -PollingIntervalSeconds:10 -Categories:'Heap' -GetSupportFilesCab
```

The command will run an in-memory (flight recorder mode) Defender heap trace at command start time and automatically collect it (along with a support files cab) when the specified high memory usage conditions occur.  The collected trace will provide coverage in recent Defender heap allocations, CPU usage, Defender activities, file activities at the time the trigger conditions are met.

_Notes and Caveats:_
1. Trace can be cancelled by pressing Ctrl-C.
2. No trace will be collected if the specified conditions are not met, but trace will continue running in-memory in the background until cancelled or a reboot occurs.
3. While providing great insight into Defender allocations and their correlations with Defender and system activities, Defender heap traces tend to be heavy, so be mindful of the potential impact on the workload running on the machine.  Don’t leave such traces running unless necessary for a repro.
4. Coverage duration back in time from when the conditions occur will be variable, depending on total memory on the machine, number of logical processors and Defender, system and workload intensity.  It could range from tens of seconds to minutes. 
5. The ExceedingPrivateBytesGrowth parameter requires experimentation.  Too low a value will trigger collections on random transient activities.  Too aggressive a value will not allow collection on slower gradual regressions.
6. A slow gradual regression will be hard to identify because it could be lost in a sea of transient activities that are nonetheless longer than the period covered by the (not overwritten) collected trace tail and either partially or completely spanning it.

* If experimenting locally with the automated collector, the script can render to the console the current Private Bytes and Private Bytes Growth metrics at each performance counter sample (every PollingIntervalSeconds) by adding to the command line above the parameter -Monitor:

```
.\New-DefenderPerformanceRecording.ps1 -RecordTo:C:\Data\HighMemoryUsage-Exceeding-3GB-and-40MB-growth-over-10s.etl -HighMemoryUsage -ExceedingPrivateBytes:3GB -ExceedingPrivateBytesGrowth:40MB -PollingIntervalSeconds:10 -Categories:'Heap' -GetSupportFilesCab -Monitor
```