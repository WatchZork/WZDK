#ifndef WZDKS_H
#define WZDKS_H

// <-- NEW: The Ultimate Security Header (Must be first)
#include <ntifs.h>

// <-- NEW: The Bridge between the WDF Manager and this IFS Sensor
#include "WZDKShared.h"
#include <WzdIoctl.h>
#include <WzdTelemetry.h>

// =========================================================================
// WZDK Missing Prototypes & External Definitions (Isolated in Header)
// These MUST appear before any function that calls them.
// =========================================================================

// KERNEL MODE PROCESS ACCESS DEFINITIONS
#ifndef PROCESS_QUERY_LIMITED_INFORMATION
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000
#endif

// Added PROCESS_QUERY_INFORMATION which was missing and caused C2065
#ifndef PROCESS_QUERY_INFORMATION
#define PROCESS_QUERY_INFORMATION 0x0400
#endif

// [COMMENTED OUT] WZD CUSTOM SECURITY TYPES (Bypassing Header Hell)
// We no longer need the Raw Memory Bypass because ntifs.h provides the real structures natively.
/*
#define WZD_TOKEN_QUERY 0x0008

#define WZD_TokenUser 1

typedef struct _WZD_TOKEN_USER {
    PSID Sid;
    ULONG Attributes;
    //SID_AND_ATTRIBUTES User;
} WZD_TOKEN_USER, * PWZD_TOKEN_USER;
*/

// -------------------------------------------------------------------------
// Kernel Exports
// NOTE: Since we successfully included <ntifs.h> above, the Windows SDK
// already defines SOME of these functions. Redeclaring them manually here
// causes C2375 (different linkage) and C2371.
// They are commented out to prevent compiler crashes, as requested.
// -------------------------------------------------------------------------

extern POBJECT_TYPE *PsProcessType;

NTKERNELAPI NTSTATUS ObOpenObjectByPointer(
    _In_ PVOID Object,
    _In_ ULONG HandleAttributes,
    _In_opt_ PACCESS_STATE PassedAccessState,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_TYPE ObjectType,
    _In_ KPROCESSOR_MODE AccessMode,
    _Out_ PHANDLE Handle);

NTKERNELAPI NTSTATUS ZwQueryInformationProcess(
    _In_ HANDLE ProcessHandle,
    _In_ ULONG ProcessInformationClass,
    _Out_writes_bytes_opt_(ProcessInformationLength) PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength,
    _Out_opt_ PULONG ReturnLength);

NTKERNELAPI PVOID PsGetProcessWow64Process(_In_ PEPROCESS Process);

NTKERNELAPI ULONG PsGetProcessSessionId(_In_ PEPROCESS Process);

// [COMMENTED OUT] These three are explicitly provided by <ntifs.h>.
/*
NTKERNELAPI NTSTATUS ZwOpenProcessTokenEx(
    _In_ HANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ ULONG HandleAttributes,
    _Out_ PHANDLE TokenHandle
);

NTKERNELAPI NTSTATUS ZwQueryInformationToken(
    _In_ HANDLE TokenHandle,
    _In_ ULONG TokenInformationClass,
    _Out_writes_bytes_to_opt_(TokenInformationLength, *ReturnLength) PVOID TokenInformation,
    _In_ ULONG TokenInformationLength,
    _Out_ PULONG ReturnLength
);

NTKERNELAPI ULONG RtlLengthSid( _In_ PSID Sid);
*/

// =========================================================================
// WZDKS Function Declarations (bodies live in WZDKS.c)
// =========================================================================

// Helper: Retrieves full image path using documented APIs
_IRQL_requires_max_(PASSIVE_LEVEL)
    _Must_inspect_result_
    NTSTATUS WZDKS_GetProcessImageName(
        _In_ PEPROCESS Process,
        _Outptr_result_maybenull_ PUNICODE_STRING *pImageFileName);

// Helper: Extracts SID from a given Process ID
_IRQL_requires_max_(PASSIVE_LEVEL)
    NTSTATUS WZDKS_GetProcessSid(
        _In_ PEPROCESS Process,
        _Out_writes_bytes_(WZD_MAX_SID_SIZE) PUCHAR SidBuffer,
        _Out_ PULONG SidLength);

#endif // WZDKS_H