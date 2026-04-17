#include "WZDKRB.h"

// The global instance
PWZD_RING_BUFFER g_WZDRB = NULL;
PMDL g_WzdRingBufferMdl = NULL;

// WZDK_InitializeRingBuffer: Allocates ~1.5MB in NonPagedPool for the telemetry buffer
NTSTATUS WZDK_InitializeRingBuffer(VOID)
{
    // Ensure we don't double-allocate
    if (g_WZDRB != NULL) return STATUS_ALREADY_COMMITTED;

    // SECURE ALLOCATION: Zero-initialized NonPagedPool
    // POOL_FLAG_NON_PAGED is mandatory because this memory will be mapped via MDL
    g_WZDRB = (PWZD_RING_BUFFER)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(WZD_RING_BUFFER),
        'BRzW' // Tag: Zork Ring Buffer
    );

    if (g_WZDRB == NULL) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WZDK] ERROR: Failed to allocate Ring Buffer (%llu bytes).\n",
            sizeof(WZD_RING_BUFFER));
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Explicitly initialize indices (though ExAllocatePool2 zeroes it)
    g_WZDRB->Head = 0;
    g_WZDRB->Tail = 0;
	g_WZDRB->DroppedEventsCount = 0;
	//IoAllocateMdl is used to create an MDL that describes the physical pages of the ring buffer, which can then be mapped to user mode. 
    // This is necessary because user mode cannot directly access kernel memory,
    // but it can access memory described by an MDL that has been mapped into its address space.
	// IoAllocateMdl( VirtualAddress, Length, SecondaryBuffer, ChargeQuota, Irp )
    g_WzdRingBufferMdl = IoAllocateMdl(g_WZDRB, sizeof(WZD_RING_BUFFER), FALSE, FALSE, NULL);

    if (g_WzdRingBufferMdl == NULL) {
        ExFreePoolWithTag(g_WZDRB, 'BRzW');
        g_WZDRB = NULL;
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
			"[WZDK] ERROR: Failed to allocate MDL for Ring Buffer.\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Build the physical pages array for the MDL
    MmBuildMdlForNonPagedPool(g_WzdRingBufferMdl);
    
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[WZDK] Ring Buffer & MDL Initialized.\n");
    return STATUS_SUCCESS;
}

// WZDK_MapRingBufferToUserMode: Maps the NonPaged physical memory to User Space via SEH.
NTSTATUS WZDK_MapRingBufferToUserMode(_Out_ PVOID* UserAddress)
{
    if (g_WzdRingBufferMdl == NULL) return STATUS_UNSUCCESSFUL;

    *UserAddress = NULL;
    PVOID mappedAddress = NULL;

    // SEH is MANDATORY here. If the User Mode process is terminating or has invalid context,
    // this API will throw a hardware exception resulting in BSOD if unhandled.
    __try {
        mappedAddress = MmMapLockedPagesSpecifyCache(
			g_WzdRingBufferMdl, // The MDL describing our buffer
			UserMode, // Access from User Mode
            MmCached, // Cached memory
			NULL, // No specific user-mode address requested (let the system choose)
			FALSE, // Don't bug check on failure, we'll handle it gracefully
			NormalPagePriority | MdlMappingNoExecute // Normal priority, and mark as non-executable for security
        );
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WZDK] CRITICAL: MmMapLockedPages Threw Exception!\n");
        return GetExceptionCode();
    }

    if (mappedAddress == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    *UserAddress = mappedAddress;
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[WZDK] Ring Buffer Mapped to User Space at %p\n", mappedAddress);
    return STATUS_SUCCESS;
}

// WZDK_UnmapRingBufferFromUserMode: Unmaps the User Space address safely.
VOID WZDK_UnmapRingBufferFromUserMode(_In_ PVOID UserAddress)
{
    if (g_WzdRingBufferMdl != NULL && UserAddress != NULL) {
        __try {
            MmUnmapLockedPages(
				UserAddress, // The User Mode address to unmap
				g_WzdRingBufferMdl // The MDL describing the original buffer (for validation and cleanup purposes)
            );
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[WZDK] Ring Buffer Unmapped.\n");
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WZDK] CRITICAL: MmUnmapLockedPages Threw Exception!\n");
        }
    }
}


// WZDK_WriteEventToRingBuffer
// Description: Copies an event into the array using a SpinLock to prevent
// race conditions if two processes are created at the exact same microsecond.
// IRQL Constraint: Called at PASSIVE_LEVEL, raises briefly to DISPATCH_LEVEL.
// Failure Mode: BSOD if g_WZDRB is NULL.

VOID WZDK_WriteEventToRingBuffer(_In_ PWZD_PROCESS_EVENT NewEvent)
{
    if (g_WZDRB == NULL || NewEvent == NULL) return;

    LONG currentIndex, nextIndex;
    // Atomically Claim an Index (Lock-Free CAS Loop)
    do {
        currentIndex = g_WZDRB->Head;

        nextIndex = (currentIndex + 1) & WZD_EVENT_MASK;

        // Flooding Protection: If Buffer is Full, DROP the event. NEVER BLOCK.
        if (nextIndex == g_WZDRB->Tail) {
            InterlockedIncrement(&g_WZDRB->DroppedEventsCount);
            return;
        }

    } while (InterlockedCompareExchange(&g_WZDRB->Head, nextIndex, currentIndex) != currentIndex);

    // We successfully claimed 'currentIndex'.
    PWZD_PROCESS_EVENT slot = &g_WZDRB->Events[currentIndex];

    // FIX #4: Force state to Writing. We own this slot via Head CAS.
    // If it wasn't Free, the consumer is behind — log but don't stall.
    LONG previousState = InterlockedExchange(&g_WZDRB->SlotStates[currentIndex], WZDRB_SlotWriting);
    if (previousState != WZDRB_SlotFree) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[WZDK] WARNING: Slot %d was state %d (expected Free). Overwriting.\n",
            currentIndex, previousState);
    }

    // ====================================================================
    // THE SMOKING GUN: Manual field copying caused the missing Session/SID bug!
    // We commented this out to prevent future omissions when adding new fields.
    // ====================================================================
    /*
    // Deep Copy the Event Data
    slot->EventType = NewEvent->EventType;
    slot->ProcessId = NewEvent->ProcessId;
    slot->ParentProcessId = NewEvent->ParentProcessId;
    slot->TrueCreatorPid = NewEvent->TrueCreatorPid;
    slot->TrueCreatorTid = NewEvent->TrueCreatorTid;
    slot->Is32Bit = NewEvent->Is32Bit;

    // Copy Strings (Using precise lengths to avoid buffer overflows)
    wcsncpy_s(slot->ImageFileName, WZD_MAX_PATH_LENGTH, NewEvent->ImageFileName, _TRUNCATE);
    wcsncpy_s(slot->CommandLine, WZD_MAX_CMD_LENGTH, NewEvent->CommandLine, _TRUNCATE);
    */

    // [NEW] Bulletproof Raw Memory Copy. Copies all 3KB instantly.
    // This guarantees that SessionId, SidLength, and the Sid array are 
    // pushed into the Ring Buffer without relying on manual variable typing.
    RtlCopyMemory(slot, NewEvent, sizeof(WZD_PROCESS_EVENT));

    // Guarantee data is written to RAM before changing state
    KeMemoryBarrier();

    // Tell User Mode this slot is ready 
    InterlockedExchange(&g_WZDRB->SlotStates[currentIndex], WZDRB_SlotReady);
}

// WZDK_DestroyRingBuffer
// Description: Frees the memory. MUST be called on DriverUnload.
// IRQL Constraint: PASSIVE_LEVEL
// Failure Mode: BAD_POOL_CALLER BSOD if called twice or with invalid pointer.

VOID WZDK_DestroyRingBuffer(VOID)
{
	if (g_WzdRingBufferMdl != NULL) {
        IoFreeMdl(g_WzdRingBufferMdl);
        g_WzdRingBufferMdl = NULL;
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "[WZDK] Ring Buffer MDL Freed.\n");
    }
    if (g_WZDRB != NULL) {
        ExFreePoolWithTag(g_WZDRB, 'BRzW');
        g_WZDRB = NULL;
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "[WZDK] Ring Buffer Destroyed and Memory Freed.\n");
    }
}