#ifndef WZDK_RINGBUFFER_H
#define WZDK_RINGBUFFER_H

#include <ntddk.h>
#include <WzdIoctl.h>
#include <WzdTelemetry.h>

// =========================================================================
// WZDK Ring Buffer Subsystem
// Description: Manages the allocation, mapping, and production of telemetry
//              data via a Lock-Free MPSC Shared Memory architecture.
// =========================================================================

// Global pointer to the ring buffer (resides in NonPagedPool)
extern PWZD_RING_BUFFER g_WZDRB;

// Global pointer to the Memory Descriptor List (MDL)
extern PMDL g_WzdRingBufferMdl;

// -------------------------------------------------------------------------
// Initialization and Cleanup
// -------------------------------------------------------------------------

_IRQL_requires_(PASSIVE_LEVEL)
    _Must_inspect_result_
    NTSTATUS WZDK_InitializeRingBuffer(VOID);

_IRQL_requires_(PASSIVE_LEVEL)
    VOID WZDK_DestroyRingBuffer(VOID);

// -------------------------------------------------------------------------
// Producer API
// -------------------------------------------------------------------------

// Lock-Free Producer (Called by Kernel Sensor)
_IRQL_requires_max_(PASSIVE_LEVEL)
    VOID WZDK_WriteEventToRingBuffer(_In_ PWZD_PROCESS_EVENT NewEvent);

// -------------------------------------------------------------------------
// Mapping API
// -------------------------------------------------------------------------

// Maps the buffer to User Mode via MDL
_IRQL_requires_(PASSIVE_LEVEL)
    _Must_inspect_result_
    NTSTATUS WZDK_MapRingBufferToUserMode(_Out_ PVOID *UserAddress);

// Unmaps the buffer safely
_IRQL_requires_(PASSIVE_LEVEL)
    VOID WZDK_UnmapRingBufferFromUserMode(_In_ PVOID UserAddress);

// NOTE: During termination, the process is being torn down.
// ZwQueryInformationProcess may return STATUS_PROCESS_IS_TERMINATING.
// This is expected behavior - we fall back to <UNAVAILABLE>.

#endif // WZDK_RINGBUFFER_H