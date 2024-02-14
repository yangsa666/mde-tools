param(
    [Parameter(Mandatory = $false, HelpMessage = 'Collect in-file performance recording')]
    # Collect in-file performance recording.  Default: in-memory.
    [switch]$FileMode,

    [Parameter(Mandatory = $false, HelpMessage = 'Collect light performance recording')]
    # Collect light performance recording.  Default: verbose.
    [switch]$Light,

    [Parameter(Mandatory = $false, HelpMessage = 'Collect heap performance recording')]
    # Collect heap performance recording.
    [switch]$Heap,

    [Parameter(Mandatory = $false, HelpMessage = 'Location for recording temporary files')]
    # Location for recording temporary files.
    [string]$RecordTempTo,

    [Parameter(Mandatory = $false, HelpMessage = 'WPR instance name')]
    # WPR instance name.
    [string]$InstanceName
)

function Get-DefenderHeapWPRProfile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, HelpMessage = 'Process id of process for which to collect the heap trace')]
        [ValidateCount(1, 2)]
        [int[]]$HeapProcessId
    )

    $HeapProcessIdElements = [string]::Join("`n", ($HeapProcessId | ForEach-Object { "<HeapProcessId Value=`"$_`" />" }))

@"
<?xml version="1.0" encoding="utf-8" standalone='yes'?>

<WindowsPerformanceRecorder Version="1.0" Author="Microsoft Defender for Endpoint" Team="Microsoft Defender for Endpoint" Comments="Microsoft Defender for Endpoint performance tracing" Company="Microsoft Corporation" Copyright="Microsoft Corporation">
    <Profiles>

        <!-- System Collectors -->

        <SystemCollector Id="SystemCollector_WDSystemCollectorInFile" Base="" Name="WPR System Collector" Realtime="false">
            <!-- SystemCollector_WPRSystemCollectorInFile -->
            <BufferSize Value="1024" />
            <Buffers Value="20" />
        </SystemCollector>

        <SystemCollector Id="SystemCollector_WDSystemCollectorInFileLarge" Base="" Name="WPR System Collector" Realtime="false">
            <!-- Base: SystemCollector_WPRSystemCollectorInFileLarge -->
            <BufferSize Value="1024" />
            <Buffers Value="64" />
            <StackCaching BucketCount="100" CacheSize="1024" />
        </SystemCollector>

        <SystemCollector Id="SystemCollector_WDSystemCollectorInMemory" Base="" Name="WPR System Collector" Realtime="false">
            <!-- Base: SystemCollector_WPRSystemCollectorInMemory -->
            <BufferSize Value="1024" />
            <Buffers Value="5" PercentageOfTotalMemory="true" MaximumBufferSpace="1024" /> <!-- Add MaximumBufferSpace -->
        </SystemCollector>

        <SystemCollector Id="SystemCollector_WDSystemCollectorInMemoryLarge" Base="" Name="WPR System Collector" Realtime="false">
            <!-- Base: SystemCollector_WPRSystemCollectorInMemory -->
            <BufferSize Value="1024" />
            <Buffers Value="5" PercentageOfTotalMemory="true" MaximumBufferSpace="2048" /> <!-- Add MaximumBufferSpace -->
        </SystemCollector>

        <!-- Event Collectors -->

        <EventCollector Id="EventCollector_WDEventCollectorInFile" Base="" Name="WPR Event Collector" Private="false" ProcessPrivate="false" Secure="false" Realtime="false">
            <!-- Base: EventCollector_WPREventCollectorInFile -->
            <BufferSize Value="1024" />
            <Buffers Value="20" />
        </EventCollector>

        <EventCollector Id="EventCollector_WDEventCollectorInFileLarge" Base="" Name="WPR Event Collector" Private="false" ProcessPrivate="false" Secure="false" Realtime="false">
            <!-- Base: EventCollector_WPREventCollectorInFileLarge -->
            <BufferSize Value="1024" />
            <Buffers Value="64" />
        </EventCollector>

        <EventCollector Id="EventCollector_WDEventCollectorInMemory" Base="" Name="WPR Event Collector" Private="false" ProcessPrivate="false" Secure="false" Realtime="false">
            <!-- Base: EventCollector_WPREventCollectorInMemoryMedium -->
            <BufferSize Value="1024" />
            <Buffers Value="3" PercentageOfTotalMemory="true" MaximumBufferSpace="512" /> <!-- Add MaximumBufferSpace -->
        </EventCollector>

        <EventCollector Id="EventCollector_WDEventCollectorInMemoryLarge" Base="" Name="WPR Event Collector" Private="false" ProcessPrivate="false" Secure="false" Realtime="false">
            <!-- Base: EventCollector_WPREventCollectorInMemoryLarge -->
            <BufferSize Value="1024" />
            <Buffers Value="5" PercentageOfTotalMemory="true" MaximumBufferSpace="1024" /> <!-- Add MaximumBufferSpace -->
        </EventCollector>

        <!-- Heap Collectors -->

        <HeapEventCollector Id="HeapCollector_WDHeapEventCollectorInFile" Name="WPR Heap Collector" Secure="true" Realtime="false">
            <!-- Base: HeapCollector_WPRHeapCollector -->
            <BufferSize Value="1024" />
            <Buffers Value="256" /> <!-- Default: 64 -->
        </HeapEventCollector>

        <HeapEventCollector Id="HeapCollector_WDHeapEventCollectorInMemory" Name="WPR Heap Collector" Secure="true" Realtime="false">
            <!-- Base: HeapCollector_WPRHeapCollector -->
            <BufferSize Value="1024" />
            <Buffers Value="256" /> <!-- Default: 64 -->
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
        <EventProvider Id="EventProvider_AM_Service" Name="Microsoft-Antimalware-Service" />
        <EventProvider Id="EventProvider_AM_RTP" Name="Microsoft-Antimalware-RTP" />
        <EventProvider Id="EventProvider_AM_Filter" Name="Microsoft-Antimalware-AMFilter" />
        <EventProvider Id="EventProvider_AM_Filter_With_Stacks" Name="Microsoft-Antimalware-AMFilter" Stack="true" />
        <EventProvider Id="EventProvider_AM_Protection" Name="Microsoft-Antimalware-Protection" />

        <!-- Microsoft-Antimalware-Engine-DynamicSymbols & Microsoft-Antimalware-Engine-DynamicSymbolsRundown -->
        <EventProvider Id="EventProvider_Microsoft-Antimalware-Engine-DynamicSymbols" Name="e00ad681-35f9-4afc-950d-7ba36eefcfa5" Level="5">
            <!-- Level 5: Verbose -->
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
        <EventProvider Id="EventProvider_Microsoft_Windows_NCSI" Name="Microsoft-Windows-NCSI" />

        <EventProvider Id="EventProvider_Microsoft_Windows_WLAN_AutoConfig" Name="Microsoft-Windows-WLAN-AutoConfig">
            <Keywords>
                <Keyword Value="0x200" /> <!-- WlanConnect -->
            </Keywords>
        </EventProvider>

        <EventProvider Id="EventProvider_Microsoft_Windows_TCPIP" Name="Microsoft-Windows-TCPIP">
            <Keywords>
                <Keyword Value="0x80" /> <!--TcpipDiagnosis -->
            </Keywords>
        </EventProvider>

        <!-- SMB -->
        <EventProvider Id="EventProvider_Microsoft_Windows_SMBClient" Name="Microsoft-Windows-SMBClient">
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
        <EventProvider Id="EventProvider_Microsoft-Windows-Networking-Correlation" Name="Microsoft-Windows-Networking-Correlation" />
        <EventProvider Id="EventProviderClass_PerfTrack" Name="PerfTrack" Level="4" NonPagedMemory="true" />
        <EventProvider Id="EventProvider_Microsoft-Windows-Win32k_MessagePump" Name="Microsoft-Windows-Win32k" Stack="true">
            <Keywords>
                <Keyword Value="0x400000" />
            </Keywords>
        </EventProvider>

        <!-- Base providers -->
        <EventProvider Id="EventProvider_WPR_Status" Name="36b6f488-aad7-48c2-afe3-d4ec2c8b46fa">
            <Keywords>
                <Keyword Value="0x10000" />
            </Keywords>
        </EventProvider>

        <EventProvider Id="EventProvider_Microsoft_Windows_Performance_Recorder_Context" Name="b7a19fcd-15ba-41ba-a3d7-dc352d5f79ba" NonPagedMemory="true" Strict="true" />

        <EventProvider Id="EventProvider_PerfTrack" Name="PerfTrack" NonPagedMemory="true" Level="4" />

        <EventProvider Id="EventProvider_Microsoft-Windows-Kernel-EventTracing" Name="b675ec37-bdb6-4648-bc92-f3fdc74d3ca2" Level="15" NonPagedMemory="true">
            <Keywords>
                <Keyword Value="0x40" />
            </Keywords>
        </EventProvider>

        <!-- Heap Event Providers -->

        <HeapEventProvider Id="HeapProvider_WDHeap">
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
                        <EventProviderId Value="EventProvider_AM_Engine_With_StartRundown" />
                        <EventProviderId Value="EventProvider_AM_Service" />
                        <EventProviderId Value="EventProvider_AM_RTP" />
                        <EventProviderId Value="EventProvider_AM_Filter" />
                        <EventProviderId Value="EventProvider_AM_Protection" />
                        <EventProviderId Value="EventProvider_DWMWin32k" />
                        <EventProviderId Value="EventProvider_DWMWin32k_CaptureState" />
                        <EventProviderId Value="EventProvider_Microsoft-Windows-Win32k_Focus" />
                        <EventProviderId Value="EventProvider_Microsoft-Windows-Win32k_CaptureState" />
                        <EventProviderId Value="EventProvider_Windows_Kernel_Process" />

                        <EventProviderId Value="EventProvider_Windows_AssessmentExecutionEngine" />

                        <EventProviderId Value="EventProvider_Microsoft_Windows_NCSI" />
                        <EventProviderId Value="EventProvider_Microsoft_Windows_WLAN_AutoConfig" />
                        <EventProviderId Value="EventProvider_Microsoft_Windows_TCPIP" />

                        <!-- Microsoft-Antimalware-Engine-DynamicSymbols & Microsoft-Antimalware-Engine-DynamicSymbolsRundown -->
                        <EventProviderId Value="EventProvider_Microsoft-Antimalware-Engine-DynamicSymbols" />
                        <EventProviderId Value="EventProvider_Microsoft-Antimalware-Engine-DynamicSymbolsRundown_CaptureState_StartRundown" />
                    </EventProviders>
                </EventCollectorId>
            </Collectors>
        </Profile>

        <Profile Id="WDHeap.Light.File" Base="WD.Light.File" LoggingMode="File" Name="WDHeap" DetailLevel="Light" Description="Microsoft Defender for Endpoint heap analysis">
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
                        <EventProviderId Value="EventProvider_AM_Engine_With_EndRundown" />
                        <EventProviderId Value="EventProvider_AM_Service" />
                        <EventProviderId Value="EventProvider_AM_RTP" />
                        <EventProviderId Value="EventProvider_AM_Filter" />
                        <EventProviderId Value="EventProvider_AM_Protection" />
                        <EventProviderId Value="EventProvider_DWMWin32k" />
                        <EventProviderId Value="EventProvider_DWMWin32k_CaptureState" />
                        <EventProviderId Value="EventProvider_Microsoft-Windows-Win32k_Focus" />
                        <EventProviderId Value="EventProvider_Microsoft-Windows-Win32k_CaptureState" />
                        <EventProviderId Value="EventProvider_Windows_Kernel_Process" />

                        <EventProviderId Value="EventProvider_Windows_AssessmentExecutionEngine" />

                        <EventProviderId Value="EventProvider_Microsoft_Windows_NCSI" />
                        <EventProviderId Value="EventProvider_Microsoft_Windows_WLAN_AutoConfig" />
                        <EventProviderId Value="EventProvider_Microsoft_Windows_TCPIP" />

                        <!-- Microsoft-Antimalware-Engine-DynamicSymbols & Microsoft-Antimalware-Engine-DynamicSymbolsRundown -->
                        <EventProviderId Value="EventProvider_Microsoft-Antimalware-Engine-DynamicSymbols" />
                        <EventProviderId Value="EventProvider_Microsoft-Antimalware-Engine-DynamicSymbolsRundown_CaptureState_EndRundown" />
                    </EventProviders>
                </EventCollectorId>
            </Collectors>
        </Profile>

        <Profile Id="WDHeap.Light.Memory" Base="WD.Light.Memory" LoggingMode="Memory" Name="WDHeap" DetailLevel="Light" Description="Microsoft Defender for Endpoint heap analysis">
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
                        <EventProviderId Value="EventProvider_AM_Engine_With_Stacks_StartRundown" />
                        <EventProviderId Value="EventProvider_AM_Service" />
                        <EventProviderId Value="EventProvider_AM_RTP" />
                        <EventProviderId Value="EventProvider_AM_Filter_With_Stacks" />
                        <EventProviderId Value="EventProvider_AM_Protection" />
                        <EventProviderId Value="EventProvider_DWMWin32k" />
                        <EventProviderId Value="EventProvider_DWMWin32k_CaptureState" />
                        <EventProviderId Value="EventProvider_Microsoft-Windows-Win32k_Focus" />
                        <EventProviderId Value="EventProvider_Microsoft-Windows-Win32k_CaptureState" />
                        <EventProviderId Value="EventProvider_Microsoft-Windows-COMRuntime" />
                        <EventProviderId Value="EventProvider_Windows_Kernel_Process" />

                        <EventProviderId Value="EventProvider_Windows_AssessmentExecutionEngine" />

                        <EventProviderId Value="EventProvider_Microsoft_Windows_NCSI" />
                        <EventProviderId Value="EventProvider_Microsoft_Windows_WLAN_AutoConfig" />
                        <EventProviderId Value="EventProvider_Microsoft_Windows_TCPIP" />

                        <!-- Additional providers that enhance Wait Analysis -->
                        <EventProviderId Value="EventProvider_ThreadPool" />
                        <EventProviderId Value="EventProvider_Microsoft-Windows-RPC" />
                        <EventProviderId Value="EventProvider_Microsoft-Windows-RPCSS" />
                        <EventProviderId Value="EventProvider_Microsoft-Windows-Networking-Correlation" />
                        <EventProviderId Value="EventProviderClass_PerfTrack" />
                        <EventProviderId Value="EventProvider_Microsoft-Windows-Win32k_MessagePump" />

                        <!-- SMB -->
                        <EventProviderId Value="EventProvider_Microsoft_Windows_SMBClient" />

                        <!-- Microsoft-Antimalware-Engine-DynamicSymbols & Microsoft-Antimalware-Engine-DynamicSymbolsRundown -->
                        <EventProviderId Value="EventProvider_Microsoft-Antimalware-Engine-DynamicSymbols" />
                        <EventProviderId Value="EventProvider_Microsoft-Antimalware-Engine-DynamicSymbolsRundown_CaptureState_StartRundown" />
                    </EventProviders>
                </EventCollectorId>
            </Collectors>
        </Profile>

        <Profile Id="WDHeap.Verbose.File" Base="WD.Verbose.File" LoggingMode="File" Name="WDHeap" DetailLevel="Verbose" Description="Microsoft Defender for Endpoint heap analysis">
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
                        <EventProviderId Value="EventProvider_AM_Engine_With_Stacks_EndRundown" />
                        <EventProviderId Value="EventProvider_AM_Service" />
                        <EventProviderId Value="EventProvider_AM_RTP" />
                        <EventProviderId Value="EventProvider_AM_Filter_With_Stacks" />
                        <EventProviderId Value="EventProvider_AM_Protection" />
                        <EventProviderId Value="EventProvider_DWMWin32k" />
                        <EventProviderId Value="EventProvider_DWMWin32k_CaptureState" />
                        <EventProviderId Value="EventProvider_Microsoft-Windows-Win32k_Focus" />
                        <EventProviderId Value="EventProvider_Microsoft-Windows-Win32k_CaptureState" />
                        <EventProviderId Value="EventProvider_Microsoft-Windows-COMRuntime" />
                        <EventProviderId Value="EventProvider_Windows_Kernel_Process" />

                        <EventProviderId Value="EventProvider_Windows_AssessmentExecutionEngine" />

                        <EventProviderId Value="EventProvider_Microsoft_Windows_NCSI" />
                        <EventProviderId Value="EventProvider_Microsoft_Windows_WLAN_AutoConfig" />
                        <EventProviderId Value="EventProvider_Microsoft_Windows_TCPIP" />

                        <!-- Additional providers that enhance Wait Analysis -->
                        <EventProviderId Value="EventProvider_ThreadPool" />
                        <EventProviderId Value="EventProvider_Microsoft-Windows-RPC" />
                        <EventProviderId Value="EventProvider_Microsoft-Windows-RPCSS" />
                        <EventProviderId Value="EventProvider_Microsoft-Windows-Networking-Correlation" />
                        <EventProviderId Value="EventProviderClass_PerfTrack" />
                        <EventProviderId Value="EventProvider_Microsoft-Windows-Win32k_MessagePump" />

                        <!-- SMB -->
                        <EventProviderId Value="EventProvider_Microsoft_Windows_SMBClient" />

                        <!-- Microsoft-Antimalware-Engine-DynamicSymbols & Microsoft-Antimalware-Engine-DynamicSymbolsRundown -->
                        <EventProviderId Value="EventProvider_Microsoft-Antimalware-Engine-DynamicSymbols" />
                        <EventProviderId Value="EventProvider_Microsoft-Antimalware-Engine-DynamicSymbolsRundown_CaptureState_EndRundown" />
                    </EventProviders>
                </EventCollectorId>
            </Collectors>
        </Profile>

        <Profile Id="WDHeap.Verbose.Memory" Base="WD.Verbose.Memory" LoggingMode="Memory" Name="WDHeap" DetailLevel="Verbose" Description="Microsoft Defender for Endpoint heap analysis">
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
}


$HeapProcessName = 'MsMpEng'

if ($Heap.IsPresent) {
    $HeapProcessId = @((Get-Process -Name:$HeapProcessName -ErrorAction:Stop).Id)
} else {
    $HeapProcessId = @(0)
}

$tempFile = New-TemporaryFile -ErrorAction:Stop

$wprProfile = (Get-DefenderHeapWPRProfile -HeapProcessId:$HeapProcessId | Out-File -Encoding:'utf8' -FilePath:$tempFile.FullName -ErrorAction:Stop)

$wprOptions = @()

if ($FileMode.IsPresent) {
    $wprOptions += '-filemode'
}

if ($Shutdown.IsPresent) {
    $wprOptions += '-shutdown'
}

if (-not [string]::IsNullOrEmpty($RecordTempTo)) {
    $wprOptions += @('-recordtempto',$RecordTempTo)
}

if (-not [string]::IsNullOrEmpty($InstanceName)) {
    $wprOptions += @('-instancename',$InstanceName)
}

wpr.exe -start "$($tempFile.FullName)!WD$(if ($Heap.IsPresent) {'Heap'} else {''}).$(if ($Light.IsPresent) {'Light'} else {'Verbose'})" @wprOptions

$tempFile.Delete()
