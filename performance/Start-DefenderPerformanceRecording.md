# Collecting the appropriate data

The preferred dataset for diagnosing performance issues in Defender is a WPR trace. WPR.exe is built into the most recent version of Windows. If the customer is running a version of Windows that does NOT have WPR.exe built in, they will need to download and install the [Windows Performance Toolkit](https://learn.microsoft.com/en-us/windows-hardware/test/wpt/)- a part of the Windows Assessment and Deployment Kit (ADK).  

WPR traces collected with the scripts listed below include more comprehensive and advanced instrumentation than the default,legacy x-perf based commands- which makes them more actionable for the Defender team. In particular, beside Defender Heap instrumentation, such traces also include all instrumentation necessary for Defender troubleshooting of general performance issues.  

Here are the two ways (further elaborated above) on how to collect heap traces for WPR:

**Directed Repro: Collecting an In-file Defender Heap Trace with WPR (Most common)**  
1. Download locally the Start-DefenderPerformanceRecording.ps1 script.
2. Start an in-file performance recording by running the following command from an admin PowerShell:
```
Start-DefenderPerformanceRecording.ps1 -Heap -FileMode
```
3. Repro over 10-15min the conditions that determine the significant Defender memory growth experienced previously.
4. Once the performance issue repro is complete, save the in-progress performance recording by running from an admin PowerShell:
```
wpr -stop wdheap.etl
```  
**Flight Data Recorder: Collecting an In-memory Defender Heap Trace with WPR** 
  
1. Download locally the Start-DefenderPerformanceRecording.ps1 script.
2. Start in-memory performance recording by running the following command from an admin PowerShell:
```
Start-DefenderPerformanceRecording.ps1 -Heap (This command will need to be repeated if the machine is rebooted before a repro occurs.)
```
3. Continue your work, keeping an eye on whether a repro of the significant Defender memory growth experienced previously occurs again.
4. Once the performance issue reproes, save ASAP the in-progress in-memory performance recording by running from an admin PowerShell:
```
wpr -stop wdheap.etl
```
The resulting wdheap.etl should be provided to the Defender team for review and analysis to help determine the cause of the leak. 