#pragma once
#ifndef WZDK_SHARED_H
#define WZDK_SHARED_H

#include <ntdef.h>
#include <WzdIoctl.h>
#include <WzdTelemetry.h>

// 1. Opaque Pointers (The magic trick to hide Microsoft's complex structures)
// We tell the compiler "These are pointers to something, don't worry about what they are."
typedef PVOID WZD_OPAQUE_PROCESS;

// 2. Cross-Boundary Function Prototypes
// Subsystem: WZDKS (WatchZork Detection Kernel Sensor)
NTSTATUS WZDKS_InitializeProcessSensor(VOID);
VOID WZDKS_RemoveProcessSensor(VOID);
#endif // !WZDK_SHARED_H
