#pragma once
#include <windows.h>
#include <vector>
#include <string>
#include <unordered_map>
std::vector<std::string> listOfFonctionScan =
{
    // IOCTL / Device Creation
    "IoCreateDevice",
    "IoCreateSymbolicLink",
    "WdfDeviceCreate",
    "IRP_MJ_DEVICE_CONTROL",
    "DeviceIoControl",
    // Memory Copy / Write
    "RtlCopyMemory",
    "memcpy",
    "memmove",
    "MmCopyVirtualMemory",
    "ZwWriteVirtualMemory",
    "NtWriteVirtualMemory",
    "MmMapIoSpace",
    "MmMapLockedPages",
    "MmMapLockedPagesSpecifyCache",
	"MmGetPhysicalAddress",
    // Memory Allocation
    "ExAllocatePool",
    "ExAllocatePoolWithTag",
    "ExAllocatePool2",
    "ZwAllocateVirtualMemory",
    "NtAllocateVirtualMemory",
    "MmAllocateContiguousMemory",
    "MmAllocatePagesForMdl",
    // Physical Memory / Hardware
    "PhysicalMemory",
    "ZwOpenSection",
    "MmGetPhysicalAddress",
    "READ_PORT_UCHAR",
    "READ_PORT_ULONG",
    "WRITE_PORT_UCHAR",
    "WRITE_PORT_ULONG",
    // CPU / Registers
    "wrmsr",
    "rdmsr",
    "__writemsr",
    "__readmsr",
    "__writecr0",
    "__writecr3",
    "__writecr4",
    "__readcr0",
    "__readcr3",
    "__readcr4",
    "CR0",
    "CR3",
    "CR4",
    // Execution / Hooking
    "PsCreateSystemThread",
    "PsLookupProcessByProcessId",
    "KeInsertQueueDpc",
    "KeInitializeApc",
    "KeServiceDescriptorTable",
    "HalDispatchTable",
    "ObRegisterCallbacks",
    "PsSetCreateProcessNotifyRoutine",
    "PsSetLoadImageNotifyRoutine",
    // Dynamic Resolution
    "MmGetSystemRoutineAddress",
    "RtlFindExportedRoutineByName",
    "GetProcAddress",
    // Driver Loading
    "IoCreateDriver",
    "ZwLoadDriver",
    "NtLoadDriver",
    // Process / Handle Manipulation
    "ZwOpenProcess",
    "NtOpenProcess",
    "ObOpenObjectByPointer",
    "ZwDuplicateObject",
    // Registry
    "ZwSetValueKey",
    "ZwCreateKey",
    "ZwOpenKey",
    // Mapping / Sections
    "ZwMapViewOfSection",
    "NtMapViewOfSection",
    "ZwUnmapViewOfSection",
    // MDL Manipulation
    "IoAllocateMdl",
    "MmProbeAndLockPages",
    "MmUnlockPages",
    // Common Vulnerable Patterns
    "METHOD_NEITHER",
    "FILE_ANY_ACCESS",
    "DO_BUFFERED_IO",
    "DO_DIRECT_IO"
};


std::unordered_map<std::string, int> vulnerabilityScores =
{

    // LOW RISK (1-2)

    {"IoCreateDevice", 1},
    {"IoCreateSymbolicLink", 1},
    {"WdfDeviceCreate", 1},

    {"memcpy", 1},
    {"memmove", 1},

    {"ExAllocatePool", 1},
    {"ExAllocatePoolWithTag", 1},
    {"ExAllocatePool2", 1},

    {"IoAllocateMdl", 1},
    {"MmProbeAndLockPages", 1},
    {"MmUnlockPages", 1},

    {"ZwSetValueKey", 1},
    {"ZwCreateKey", 1},
    {"ZwOpenKey", 1},

    {"ZwMapViewOfSection", 1},
    {"NtMapViewOfSection", 1},
    {"ZwUnmapViewOfSection", 1},

    // MEDIUM RISK (3-5)

    {"IRP_MJ_DEVICE_CONTROL", 3},
    {"DeviceIoControl", 3},

    {"RtlCopyMemory", 3},

    {"ZwOpenProcess", 3},
    {"NtOpenProcess", 3},
    {"ObOpenObjectByPointer", 3},
    {"ZwDuplicateObject", 3},

    {"MmGetSystemRoutineAddress", 4},
    {"RtlFindExportedRoutineByName", 4},
    {"GetProcAddress", 4},

    {"KeInsertQueueDpc", 4},
    {"KeInitializeApc", 4},

    {"PsSetCreateProcessNotifyRoutine", 4},
    {"PsSetLoadImageNotifyRoutine", 4},
    {"ObRegisterCallbacks", 4},

    {"ZwAllocateVirtualMemory", 5},
    {"NtAllocateVirtualMemory", 5},

    {"ZwLoadDriver", 5},
    {"NtLoadDriver", 5},
    {"IoCreateDriver", 5},

    {"MmAllocateContiguousMemory", 5},
    {"MmAllocatePagesForMdl", 5},

    // HIGH RISK (6-8)

    {"MmCopyVirtualMemory", 8},

    {"ZwWriteVirtualMemory", 7},
    {"NtWriteVirtualMemory", 7},

    {"MmMapIoSpace", 8},
    {"MmMapLockedPages", 7},
    {"MmMapLockedPagesSpecifyCache", 7},

    {"MmGetPhysicalAddress", 7},
    {"PhysicalMemory", 8},
    {"ZwOpenSection", 7},

    {"READ_PORT_UCHAR", 6},
    {"READ_PORT_ULONG", 6},
    {"WRITE_PORT_UCHAR", 6},
    {"WRITE_PORT_ULONG", 6},

    {"PsCreateSystemThread", 6},

    // VERY HIGH RISK (9-10)

    {"wrmsr", 9},
    {"rdmsr", 8},

    {"__writemsr", 9},
    {"__readmsr", 8},

    {"__writecr0", 10},
    {"__writecr3", 10},
    {"__writecr4", 10},

    {"__readcr0", 7},
    {"__readcr3", 7},
    {"__readcr4", 7},

    {"CR0", 7},
    {"CR3", 8},
    {"CR4", 8},

    {"KeServiceDescriptorTable", 10},
    {"HalDispatchTable", 10}
};
