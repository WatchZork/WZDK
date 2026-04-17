#include <ntddk.h>
#include <wdf.h>
#include <WzdIoctl.h>
#include <WzdTelemetry.h>
#include "WZDKShared.h"
#include "WZDKRB.h"

typedef struct _WZD_FILE_CONTEXT
{
    PVOID MappedUserAddress; // Tracks the mapped Ring Buffer address
} WZD_FILE_CONTEXT, *PWZD_FILE_CONTEXT;

// Generates an accessor function: WzdkGetFileContext(WDFFILEOBJECT)
WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(WZD_FILE_CONTEXT, WzdkGetFileContext)

// Forward Declarations (WZDK_ Naming Convention)
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DEVICE_FILE_CREATE WZDK_EvtDeviceFileCreate;
EVT_WDF_FILE_CLEANUP WZDK_EvtFileCleanup;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL WZDK_EvtIoDeviceControl;
EVT_WDF_DRIVER_UNLOAD WZDK_EvtDriverUnload;
volatile LONG g_ConsumerActive = 0;

// The Entry Point (creates a logical / control device)
NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    WDF_DRIVER_CONFIG config;
    WDFDRIVER driver;
    WDFDEVICE device;
    WDF_IO_QUEUE_CONFIG queueConfig;
    PWDFDEVICE_INIT pDeviceInit;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
               "[WZDK] DriverEntry: Starting WatchZork Kernel Driver...\n");

    WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);

    // Mark as non-PnP driver before creating the framework driver object.
    config.DriverInitFlags |= WdfDriverInitNonPnpDriver;

    config.EvtDriverUnload = WZDK_EvtDriverUnload;

    // Create the Framework Driver Object and obtain a WDFDRIVER handle
    status = WdfDriverCreate(
        DriverObject,
        RegistryPath,
        WDF_NO_OBJECT_ATTRIBUTES,
        &config,
        &driver);

    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[WZDK] DriverEntry: WdfDriverCreate failed 0x%X\n", status);
        return status;
    }
    else
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "[WZDK] DriverEntry: WDF Driver Object Created Successfully\n");

    // Create a logical (control) device
    DECLARE_CONST_UNICODE_STRING(deviceName, WZD_DEVICE_NAME);
    DECLARE_CONST_UNICODE_STRING(symbolicLinkName, WZD_SYMBOLIC_LINK_NAME);
    DECLARE_CONST_UNICODE_STRING(sddlString, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)"); // Admin & System only

    pDeviceInit = WdfControlDeviceInitAllocate(driver, &sddlString);
    if (pDeviceInit == NULL)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[WZDK] DriverEntry: WdfControlDeviceInitAllocate returned NULL\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    WDF_FILEOBJECT_CONFIG fileConfig;
    WDF_FILEOBJECT_CONFIG_INIT(&fileConfig, WZDK_EvtDeviceFileCreate, WDF_NO_EVENT_CALLBACK, WZDK_EvtFileCleanup);

    WDF_OBJECT_ATTRIBUTES fileAttributes;
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&fileAttributes, WZD_FILE_CONTEXT);

    fileAttributes.SynchronizationScope = WdfSynchronizationScopeNone; // Allow concurrent access to file contexts

    WdfDeviceInitSetFileObjectConfig(pDeviceInit, &fileConfig, &fileAttributes);

    status = WdfDeviceInitAssignName(pDeviceInit, &deviceName);
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[WZDK] DriverEntry: WdfDeviceInitAssignName failed 0x%X\n", status);
        WdfDeviceInitFree(pDeviceInit);
        return status;
    }

    status = WdfDeviceCreate(&pDeviceInit, WDF_NO_OBJECT_ATTRIBUTES, &device);
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[WZDK] DriverEntry: WdfDeviceCreate failed 0x%X\n", status);
        WdfDeviceInitFree(pDeviceInit);
        return status;
    }

    status = WdfDeviceCreateSymbolicLink(device, &symbolicLinkName);
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[WZDK] DriverEntry: WdfDeviceCreateSymbolicLink failed 0x%X\n", status);
        return status;
    }

    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchParallel);
    queueConfig.EvtIoDeviceControl = WZDK_EvtIoDeviceControl;

    status = WdfIoQueueCreate(
        device,
        &queueConfig,
        WDF_NO_OBJECT_ATTRIBUTES,
        WDF_NO_HANDLE);

    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[WZDK] DriverEntry: WdfIoQueueCreate failed 0x%X\n", status);
        return status;
    }

    // Activate Queue and link it to the device (ready to recive messages)
    WdfControlFinishInitializing(device);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[WZDK] DriverEntry: Logical control device created and ready\n");

    // SUBSYSTEM INITIALIZATION: Start the Ring Buffer
    status = WZDK_InitializeRingBuffer();
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WZDK] FATAL: Ring Buffer Init Failed.\n");
        return status;
    }

    // SUBSYSTEM INITIALIZATION: Start the Sensors
    status = WZDKS_InitializeProcessSensor();
    if (!NT_SUCCESS(status))
    {
        // Safe Teardown if sensor fails (Crucial for stability)
        WZDK_DestroyRingBuffer();
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[WZDK] DriverEntry: Sensor init failed, aborting load.\n");
        return status;
    }
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[WZDK] DriverEntry: All subsystems initialized successfully.\n");

    return STATUS_SUCCESS;
}

// WZDK_EvtDeviceFileCreate: Triggered when User Mode calls CreateFile.

VOID WZDK_EvtDeviceFileCreate(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ WDFFILEOBJECT FileObject)
{
    UNREFERENCED_PARAMETER(Device);

    // Initialize context to NULL
    PWZD_FILE_CONTEXT fileCtx = WzdkGetFileContext(FileObject);
    if (fileCtx != NULL)
    {
        fileCtx->MappedUserAddress = NULL;
    }

    WdfRequestComplete(Request, STATUS_SUCCESS);
}

// WZDK_EvtFileCleanup: Triggered when User Mode app closes handle or crashes.

VOID WZDK_EvtFileCleanup(_In_ WDFFILEOBJECT FileObject)
{
    PWZD_FILE_CONTEXT fileCtx = WzdkGetFileContext(FileObject);

    if (fileCtx != NULL && fileCtx->MappedUserAddress != NULL)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "[WZDK] Client disconnected. Auto-Unmapping address %p...\n", fileCtx->MappedUserAddress);

        WZDK_UnmapRingBufferFromUserMode(fileCtx->MappedUserAddress);
        fileCtx->MappedUserAddress = NULL; // Prevent double-free

        // Release the Global Singleton Lock so WZDS can reconnect if it restarts
        InterlockedExchange(&g_ConsumerActive, 0);
    }
}

// IOCTL Request Handler
VOID WZDK_EvtIoDeviceControl(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _In_ size_t InputBufferLength,
    _In_ ULONG IoControlCode)
{
    UNREFERENCED_PARAMETER(Queue);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(InputBufferLength);

    NTSTATUS status = STATUS_SUCCESS;
    ULONG_PTR bytesWritten = 0; // Tracking bytes returned to User Mode

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[WZDK] WZD_EvtIoDeviceControl: Received IOCTL 0x%X\n", IoControlCode);
    switch (IoControlCode)
    {
    case IOCTL_WZD_TEST_CONNECTION:
    {
        PULONG pOutBuffer = NULL;
        size_t bufferLength = 0;

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "[WZDK] WZD_EvtIoDeviceControl: IOCTL_WZD_TEST_CONNECTION received\n");

        HANDLE clientPid = PsGetCurrentProcessId();
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "[WZDK] Connection Verified. Client PID: %p\n", clientPid);

        status = WdfRequestRetrieveOutputBuffer(Request, sizeof(ULONG), (PVOID *)&pOutBuffer, &bufferLength);

        if (NT_SUCCESS(status) && pOutBuffer != NULL)
        {
            *pOutBuffer = (ULONG)(ULONG_PTR)clientPid;
            bytesWritten = sizeof(ULONG);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                       "[WZDK] Successfully wrote PID (%u) to User Mode buffer.\n", *pOutBuffer);
        }
        else
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "[WZDK] ERROR: Output buffer invalid. Real Status: 0x%X\n", status);
            bytesWritten = 0;
        }
        break;
    }
    case IOCTL_WZD_MAP_MEMORY:
    {
        // Early validation to prevent mapping without space
        if (OutputBufferLength < sizeof(PVOID))
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WZDK] ERROR: Output buffer too small.\n");
            status = STATUS_BUFFER_TOO_SMALL;
            bytesWritten = 0;
            break;
        }
        WDFFILEOBJECT fileObject = WdfRequestGetFileObject(Request);
        PWZD_FILE_CONTEXT fileCtx = WzdkGetFileContext(fileObject);

        if (fileCtx == NULL)
        {
            status = STATUS_INTERNAL_ERROR;
            bytesWritten = 0;
            break;
        }

        // Prevent PTE Exhaustion (Max 1 mapping per handle)
        if (fileCtx->MappedUserAddress != NULL)
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL, "[WZDK] Client attempted double-map. Rejected.\n");
            status = STATUS_ALREADY_COMMITTED;
            bytesWritten = 0;
            break;
        }

        // Global Singleton Protection: Ensure only ONE process system-wide can map this memory.
        if (InterlockedCompareExchange(&g_ConsumerActive, 1, 0) != 0)
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[WZDK] ATTACK BLOCKED: Concurrent mapping attempt rejected.\n");
            status = STATUS_DEVICE_ALREADY_ATTACHED;
            bytesWritten = 0;
            break;
        }

        PVOID userAddress = NULL;
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "[WZDK] WZD_EvtIoDeviceControl: IOCTL_WZD_MAP_MEMORY received\n");
        status = WZDK_MapRingBufferToUserMode(&userAddress);
        if (NT_SUCCESS(status) && userAddress != NULL)
        {
            PVOID *pOutBuffer = NULL;
            size_t bufferLength = 0;
            status = WdfRequestRetrieveOutputBuffer(Request, sizeof(PVOID), (PVOID *)&pOutBuffer, &bufferLength);
            if (NT_SUCCESS(status) && pOutBuffer != NULL)
            {
                *pOutBuffer = userAddress;
                bytesWritten = sizeof(PVOID);

                // FIX #2: Track mapping for lifecycle cleanup in EvtFileCleanup
                fileCtx->MappedUserAddress = userAddress;

                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                           "[WZDK] Successfully mapped Ring Buffer to User Mode at %p\n", userAddress);
            }
            else
            {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                           "[WZDK] ERROR: Output buffer invalid for mapping. Status: 0x%X\n", status);
                WZDK_UnmapRingBufferFromUserMode(userAddress); // Cleanup on failure
                InterlockedExchange(&g_ConsumerActive, 0);     // Rollback singleton
                bytesWritten = 0;
            }
        }
        else
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "[WZDK] ERROR: Failed to map Ring Buffer. Status: 0x%X\n", status);
            InterlockedExchange(&g_ConsumerActive, 0); // Rollback on MDL failure
            bytesWritten = 0;
        }
        break;
    }

    default:
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[WZDK] WZD_EvtIoDeviceControl: Unknown IOCTL 0x%X received\n", IoControlCode);
        status = STATUS_INVALID_DEVICE_REQUEST;
        bytesWritten = 0;
        break;
    }

    WdfRequestCompleteWithInformation(Request, status, bytesWritten);
}

// 5. WZDK_EvtDriverUnload: Cleanup Handler
VOID WZDK_EvtDriverUnload(
    _In_ WDFDRIVER Driver)
{
    UNREFERENCED_PARAMETER(Driver);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
               "[WZDK] WZDK_EvtDriverUnload: Shutting down WatchZork Driver...\n");

    WZDKS_RemoveProcessSensor();
    WZDK_DestroyRingBuffer();
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[WZDK] WZDK_EvtDriverUnload: Cleanup complete. Driver stopped.\n");
}
