#include "WZDKS.h"
#include "WZDKRB.h"
#include <WzdIoctl.h>
#include <WzdTelemetry.h>

// -------------------------------------------------------------------------
// Helper function to retrieve the full process image path using documented APIs
// IRQL Constraint: PASSIVE_LEVEL (calls ObOpenObjectByPointer + ZwQueryInformationProcess)
// Memory: Allocates from PagedPool. Caller MUST free with ExFreePoolWithTag(ptr, 'GMIN')
// Execution Context: Must be in the context of a valid process (not System context for target)
// Failure Mode: Returns STATUS_INSUFFICIENT_RESOURCES if pool exhausted,
//               STATUS_PROCESS_IS_TERMINATING if process is dying.
// -------------------------------------------------------------------------
_IRQL_requires_max_(PASSIVE_LEVEL)
    _Must_inspect_result_
    NTSTATUS WZDKS_GetProcessImageName(
        _In_ PEPROCESS Process,
        _Outptr_result_maybenull_ PUNICODE_STRING *pImageFileName)
{
    NTSTATUS status;
    HANDLE hProcess = NULL;
    ULONG returnLength = 0;
    PUNICODE_STRING processName = NULL;

    *pImageFileName = NULL;

    // Open a kernel handle to the process
    status = ObOpenObjectByPointer(
        Process,
        OBJ_KERNEL_HANDLE,
        NULL,
        PROCESS_QUERY_LIMITED_INFORMATION, // Minimum required access
        *PsProcessType,
        KernelMode,
        &hProcess);

    if (!NT_SUCCESS(status))
        return status;

    // First call to get required buffer size
    status = ZwQueryInformationProcess(
        hProcess,
        ProcessImageFileName, // 27
        NULL,
        0,
        &returnLength);

    if (status != STATUS_INFO_LENGTH_MISMATCH)
    {
        ZwClose(hProcess);
        return status;
    }

    // Allocate buffer for UNICODE_STRING structure + actual string data
    // Secure allocation: Automatically zero-initializes memory to prevent kernel info-leaks.
    processName = (PUNICODE_STRING)ExAllocatePool2(
        POOL_FLAG_PAGED,
        returnLength,
        'GMIN' // 'NIMG' reversed for tag
    );

    if (processName == NULL)
    {
        ZwClose(hProcess);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Second call to get the actual image file name
    status = ZwQueryInformationProcess(
        hProcess,
        ProcessImageFileName,
        processName,
        returnLength,
        &returnLength);

    ZwClose(hProcess);

    if (NT_SUCCESS(status))
    {
        *pImageFileName = processName;
    }
    else
    {
        ExFreePoolWithTag(processName, 'GMIN');
    }

    return status;
}

// -------------------------------------------------------------------------
// Helper function to extract the SID (Security Identifier) from a Process
// -------------------------------------------------------------------------
_IRQL_requires_max_(PASSIVE_LEVEL)
    NTSTATUS WZDKS_GetProcessSid(
        _In_ PEPROCESS Process,
        _Out_writes_bytes_(WZD_MAX_SID_SIZE) PUCHAR SidBuffer,
        _Out_ PULONG SidLength)
{
    NTSTATUS status;
    HANDLE hProcess = NULL;
    HANDLE hToken = NULL;
    PTOKEN_USER pTokenUser = NULL;
    ULONG returnLength = 0;
    ULONG bufferSize = 0; // NEW: Separate variable to track allocated size

    *SidLength = 0;
    RtlZeroMemory(SidBuffer, WZD_MAX_SID_SIZE); // <-- [FIXED C6101: Securely zero out buffer]
    // Safe handle creation directly from the provided PEPROCESS
    status = ObOpenObjectByPointer(
        Process,
        OBJ_KERNEL_HANDLE, // Prevents handle leak to User Mode
        NULL,
        PROCESS_QUERY_INFORMATION, // Principle of Least Privilege
        *PsProcessType,
        KernelMode,
        &hProcess);
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[WZDK] WZDKS_GetProcessSid: ObOpenObjectByPointer failed with status 0x%X\n", status);
        return status;
    }
    //  Open Token
    status = ZwOpenProcessTokenEx(hProcess, TOKEN_QUERY, OBJ_KERNEL_HANDLE, &hToken);
    ZwClose(hProcess);
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[WZDK] WZDKS_GetProcessSid: ZwOpenProcessTokenEx failed with status 0x%X\n", status);
        return status;
    }

    // Get required buffer size for TOKEN_USER
    status = ZwQueryInformationToken(hToken, TokenUser, NULL, 0, &returnLength);

    // We expect STATUS_BUFFER_TOO_SMALL here - that's success for the probe call
    if (returnLength == 0)
    {
        ZwClose(hToken);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[WZDK] WZDKS_GetProcessSid: ZwQueryInformationToken failed to return required buffer size for TOKEN_USER\n");
        return STATUS_UNSUCCESSFUL;
    }

    // Store the allocated size separately for Code Analysis
    bufferSize = returnLength;

    // Allocate buffer for TOKEN_USER structure based on the required size
    pTokenUser = (PTOKEN_USER)ExAllocatePool2(POOL_FLAG_PAGED, bufferSize, 'NKoT');

    if (pTokenUser == NULL)
    {
        ZwClose(hToken);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[WZDK] WZDKS_GetProcessSid: Failed to allocate initial memory for TOKEN_USER structure\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Second call: Use bufferSize (allocated size) as input, returnLength as output
    status = ZwQueryInformationToken(hToken, TokenUser, pTokenUser, bufferSize, &returnLength);

    if (NT_SUCCESS(status) && pTokenUser->User.Sid != NULL)
    {
        ULONG length = RtlLengthSid(pTokenUser->User.Sid);
        if (length <= WZD_MAX_SID_SIZE)
        {
            RtlCopyMemory(SidBuffer, pTokenUser->User.Sid, length);
            *SidLength = length;
        }
        else
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "[WZDK] WZDKS_GetProcessSid: SID length (%u) exceeds buffer size (%u)\n", length, WZD_MAX_SID_SIZE);
            status = STATUS_BUFFER_TOO_SMALL;
        }
    }
    else
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[WZDK] WZDKS_GetProcessSid: ZwQueryInformationToken failed with status 0x%X or returned NULL SID\n", status);
        // status = NT_SUCCESS(status) ? STATUS_UNSUCCESSFUL : status; // If call succeeded but SID is NULL, treat as failure
    }

    ExFreePoolWithTag(pTokenUser, 'NKoT');
    ZwClose(hToken);
    return status;
}

// -------------------------------------------------------------------------
// WZDKS_ProcessNotifyCallbackEx
// Description: Sensor callback invoked by the Windows Kernel on process events.
// IRQL Constraint: Called at PASSIVE_LEVEL (0).
// Memory Constraint: Must reside in NonPagedPool or .text segment.
// Execution Context: Runs in the context of the thread requesting the process creation/termination.
// Failure Mode: BSOD if unhandled NULL pointer is dereferenced.
// -------------------------------------------------------------------------
VOID WZDKS_ProcessNotifyCallbackEx(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    // UNREFERENCED_PARAMETER(Process);
    //  If CreateInfo is not NULL, a new process is being CREATED
    if (CreateInfo != NULL)
    {

        // Essential identifier for the new process to track its future actions in the OS
        HANDLE pid = ProcessId;

        // Parent PID (Spoofed). Attackers spoof this to blend in (e.g., pretending to be spawned by explorer.exe)
        HANDLE ppid = CreateInfo->ParentProcessId;

        // True Creator PID & TID
        // Unmasks the actual process making the NtCreateUserProcess syscall, defeating PPID Spoofing
        HANDLE trueCreatorPid = CreateInfo->CreatingThreadId.UniqueProcess;
        // Identifies the exact thread executing the creation, useful for thread-level anomaly detection
        HANDLE trueCreatorTid = CreateInfo->CreatingThreadId.UniqueThread;

        // Architecture (WoW64 vs Native). 32-bit malware on 64-bit OS tries to hide in WoW64 subsystems to evade memory scanners.
        PVOID wow64Process = PsGetProcessWow64Process(Process);
        BOOLEAN is32Bit = (wow64Process != NULL);

        // Old String (Kept for historical context, though unused in the new DbgPrintEx)
        // PCSTR archStr = is32Bit ? "x86 (WoW64)" : "x64 (Native)";

        // Image File Name. The binary path on disk; crucial for static analysis, hash calculation, and signature verification.
        PCUNICODE_STRING imageName = CreateInfo->ImageFileName;
        PUNICODE_STRING pAllocatedImageName = NULL;

        // Mitigation for Process Forking where ImageFileName is NULL
        if (imageName == NULL)
        {
            // Defensive check: Ensure we are at PASSIVE_LEVEL before calling blocking APIs
            if (KeGetCurrentIrql() == PASSIVE_LEVEL)
            {
                NTSTATUS nameStatus = WZDKS_GetProcessImageName(Process, &pAllocatedImageName);
                if (NT_SUCCESS(nameStatus) && pAllocatedImageName != NULL)
                {
                    imageName = pAllocatedImageName; // Point the image name to our dynamically allocated buffer
                }
            }
        }

        // Attackers use Living-off-the-Land Binaries (LOLBins) where the path is safe but arguments are malicious.
        PCUNICODE_STRING cmdLine = CreateInfo->CommandLine;

        // WZD TELEMETRY DISPATCH (Ring Buffer Integration)
        WZD_PROCESS_EVENT EventPayload = {0}; // Zero-initialize stack memory

        // 1. Determine Event Type
        EventPayload.EventType = WZDEventProcessCreate;

        // 2. Fill Identifiers
        EventPayload.ProcessId = (ULONG)(((ULONG_PTR)pid) & 0xFFFFFFFF);
        EventPayload.ParentProcessId = (ULONG)(((ULONG_PTR)ppid) & 0xFFFFFFFF);
        EventPayload.TrueCreatorPid = (ULONG)(((ULONG_PTR)trueCreatorPid) & 0xFFFFFFFF);
        EventPayload.TrueCreatorTid = (ULONG)(((ULONG_PTR)trueCreatorTid) & 0xFFFFFFFF);
        EventPayload.Is32Bit = is32Bit;

        // Enrichment: Session and SID
        EventPayload.SessionId = PsGetProcessSessionId(Process);
        WZDKS_GetProcessSid(Process, EventPayload.Sid, &EventPayload.SidLength);

        // 3. Fill Strings safely
        if (imageName != NULL && imageName->Buffer != NULL)
        {
            // wcsncpy_s(EventPayload.ImageFileName, WZD_MAX_PATH_LENGTH, imageName->Buffer, _TRUNCATE);

            USHORT copyBytes = imageName->Length < (WZD_MAX_PATH_LENGTH - 1) * sizeof(WCHAR) ? imageName->Length : (WZD_MAX_PATH_LENGTH - 1) * sizeof(WCHAR);
            RtlCopyMemory(EventPayload.ImageFileName, imageName->Buffer, copyBytes);
            EventPayload.ImageFileName[copyBytes / sizeof(WCHAR)] = L'\0';
        }
        else
        {
            wcscpy_s(EventPayload.ImageFileName, WZD_MAX_PATH_LENGTH, L"<UNKNOWN/NULL>");
        }

        if (cmdLine != NULL && cmdLine->Buffer != NULL)
        {
            // wcsncpy_s(EventPayload.CommandLine, WZD_MAX_CMD_LENGTH, cmdLine->Buffer, _TRUNCATE);

            USHORT cmdCopyBytes = cmdLine->Length < (WZD_MAX_CMD_LENGTH - 1) * sizeof(WCHAR) ? cmdLine->Length : (WZD_MAX_CMD_LENGTH - 1) * sizeof(WCHAR);
            RtlCopyMemory(EventPayload.CommandLine, cmdLine->Buffer, cmdCopyBytes);
            EventPayload.CommandLine[cmdCopyBytes / sizeof(WCHAR)] = L'\0';
        }
        else
        {
            wcscpy_s(EventPayload.CommandLine, WZD_MAX_CMD_LENGTH, L"<EMPTY/NULL>");
        }

        /* [COMMENTED OUT] Old debugging output:
        // Optional: Keep a small log for debugging
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "[WZDKS] Event Dispatched to Ring Buffer. PID: %p:%u\n", EventPayload.ProcessId, EventPayload.ProcessId);

        // Memory-Safe Logging Output (BSOD Prevention for NULL Pointers)
        if (imageName != NULL && cmdLine != NULL) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, ... )
        } ...
        */

        // Unified Hex:Dec Log BEFORE writing to Ring Buffer
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "[WZDKS] [+] CREATE DISPATCH | PID: 0x%04lX:%lu\n",
                   EventPayload.ProcessId, EventPayload.ProcessId);

        // 4. Dispatch to Lock-Free Ring Buffer
        WZDK_WriteEventToRingBuffer(&EventPayload);

        // Free dynamically allocated memory if we obtained it to prevent memory leaks
        if (pAllocatedImageName != NULL)
        {
            ExFreePoolWithTag(pAllocatedImageName, 'GMIN');
        }
    }
    // If CreateInfo is NULL, an existing process is being TERMINATED.
    else
    {
        WZD_PROCESS_EVENT EventPayload = {0};
        EventPayload.EventType = WZDEventProcessTerminate;
        EventPayload.ProcessId = (ULONG)(((ULONG_PTR)ProcessId) & 0xFFFFFFFF);

        // Enrichment: Session and SID for terminating process
        EventPayload.SessionId = PsGetProcessSessionId(Process);
        WZDKS_GetProcessSid(Process, EventPayload.Sid, &EventPayload.SidLength);

        // Attempt to get the image name for terminated process
        if (KeGetCurrentIrql() == PASSIVE_LEVEL)
        {
            PUNICODE_STRING pImageName = NULL;
            NTSTATUS nameStatus = WZDKS_GetProcessImageName(Process, &pImageName);
            if (NT_SUCCESS(nameStatus) && pImageName != NULL)
            {

                // wcsncpy_s(EventPayload.ImageFileName, WZD_MAX_PATH_LENGTH, pImageName->Buffer, _TRUNCATE);
                // Safe RtlCopyMemory approach
                USHORT copyBytes = pImageName->Length < (WZD_MAX_PATH_LENGTH - 1) * sizeof(WCHAR) ? pImageName->Length : (WZD_MAX_PATH_LENGTH - 1) * sizeof(WCHAR);
                RtlCopyMemory(EventPayload.ImageFileName, pImageName->Buffer, copyBytes);
                EventPayload.ImageFileName[copyBytes / sizeof(WCHAR)] = L'\0';

                ExFreePoolWithTag(pImageName, 'GMIN');
            }
            else
            {
                wcscpy_s(EventPayload.ImageFileName, WZD_MAX_PATH_LENGTH, L"<UNAVAILABLE>");
            }
        }

        // Unified Hex:Dec Log BEFORE writing to Ring Buffer
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "[WZDKS] [-] TERMINATE DISPATCH | PID: 0x%04lX:%lu\n",
                   EventPayload.ProcessId, EventPayload.ProcessId);
        // [NEW] THE SANITY CHECK PROBE
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "[WZDKS] SANITY CHECK | PID: 0x%04lX | SidLength: %lu\n",
                   EventPayload.ProcessId, EventPayload.SidLength);
        WZDK_WriteEventToRingBuffer(&EventPayload);

        /* [COMMENTED OUT] Old debugging output:
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "[WZDKS] [-] TERMINATED | PID: %p -> Dispatched to Ring Buffer\n",
            ProcessId);
        */
    }
}

// -------------------------------------------------------------------------
// WZDKS_InitializeProcessSensor
// Description: Registers the callback with the OS.
// IRQL Constraint: PASSIVE_LEVEL (0).
// Failure Mode: Fails with STATUS_ACCESS_DENIED if /INTEGRITYCHECK is missing.
// -------------------------------------------------------------------------
NTSTATUS WZDKS_InitializeProcessSensor(VOID)
{
    NTSTATUS status;

    status = PsSetCreateProcessNotifyRoutineEx(WZDKS_ProcessNotifyCallbackEx, FALSE);

    if (NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "[WZDKS] Process Sensor Registered Successfully.\n");
    }
    else
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[WZDKS] ERROR: Failed to register Process Sensor (Status: 0x%X).\n", status);
    }

    return status;
}

// -------------------------------------------------------------------------
// WZDKS_RemoveProcessSensor
// Description: Unregisters the callback. MUST be called before driver unload.
// IRQL Constraint: PASSIVE_LEVEL (0).
// Failure Mode: BSOD (DRIVER_UNLOADED_WITHOUT_CANCELLING_PENDING_OPERATIONS) if skipped.
// -------------------------------------------------------------------------
VOID WZDKS_RemoveProcessSensor(VOID)
{
    NTSTATUS status;

    // WDK strictly requires inspecting the NTSTATUS result of this API.
    status = PsSetCreateProcessNotifyRoutineEx(WZDKS_ProcessNotifyCallbackEx, TRUE);

    if (NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "[WZDKS] Process Sensor Unregistered Safely.\n");
    }
    else
    {
        // If this fails, the driver is in a corrupted state and unload will likely bugcheck.
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[WZDKS] CRITICAL ERROR: Failed to unregister Process Sensor (Status: 0x%X). Expect BSOD on unload!\n", status);
    }
}