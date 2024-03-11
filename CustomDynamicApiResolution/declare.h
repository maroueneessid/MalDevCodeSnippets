#pragma once
#include "Windows.h"
#include <stdio.h>
#include <winternl.h>
#define PS_ATTRIBUTE_IMAGE_NAME \
    

// ############################ STRUCTS ############################ 
typedef struct USTRING
{
    DWORD	Length;
    DWORD	MaximumLength;
    PVOID	Buffer;

};

typedef struct _PS_ATTRIBUTE
{
	ULONG_PTR Attribute;
	SIZE_T Size;
	union
	{
		ULONG_PTR Value;
		PVOID ValuePtr;
	};
	PSIZE_T ReturnLength;
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST
{
	SIZE_T TotalLength;
	PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;




// ###########################################  API  DEFINITIONS ####################################################

typedef NTSTATUS(NTAPI* fnSystemFunction033)(struct USTRING* Data, struct USTRING* Key);

typedef PVOID (NTAPI* RtlAllocateHeap)(
	_In_ PVOID HeapHandle,
	_In_opt_ ULONG Flags,
	_In_ SIZE_T Size
);

typedef NTSTATUS (NTAPI* RtlCreateProcessParametersEx)(
	_Out_ PRTL_USER_PROCESS_PARAMETERS* pProcessParameters,
	_In_ PUNICODE_STRING ImagePathName,
	_In_opt_ PUNICODE_STRING DllPath,
	_In_opt_ PUNICODE_STRING CurrentDirectory,
	_In_opt_ PUNICODE_STRING CommandLine,
	_In_opt_ PVOID Environment,
	_In_opt_ PUNICODE_STRING WindowTitle,
	_In_opt_ PUNICODE_STRING DesktopInfo,
	_In_opt_ PUNICODE_STRING ShellInfo,
	_In_opt_ PUNICODE_STRING RuntimeData,
	_In_ ULONG Flags // pass RTL_USER_PROC_PARAMS_NORMALIZED to keep parameters normalized
);





typedef NTSTATUS(NTAPI* fnNtAllocateVirtualMemory)(
	HANDLE    ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T   RegionSize,
	ULONG     AllocationType,
	ULONG     Protect
	);

typedef NTSTATUS(NTAPI* fnNtProtectVirtualMemory)(
	IN HANDLE               ProcessHandle,              // Process handle whose memory protection is to be changed
	IN OUT PVOID* BaseAddress,               // Pointer to the base address to protect
	IN OUT PULONG           NumberOfBytesToProtect,     // Pointer to size of region to protect
	IN ULONG                NewAccessProtection,        // New memory protection to be set
	OUT PULONG              OldAccessProtection         // Pointer to a variable that receives the previous access protection
	);

typedef NTSTATUS(NTAPI* fnNtWriteVirtualMemory)(
	IN HANDLE               ProcessHandle,          // Process handle whose memory is to be written to
	IN PVOID                BaseAddress,            // Base address in the specified process to which data is written
	IN PVOID                Buffer,                 // Data to be written
	IN ULONG                NumberOfBytesToWrite,   // Number of bytes to be written
	OUT PULONG              NumberOfBytesWritten    // Pointer to a variable that receives the number of bytes actually written
	);

typedef NTSTATUS(NTAPI* fnNtCreateThreadEx)(
	OUT PHANDLE                 ThreadHandle,         // Pointer to a HANDLE variable that recieves the created thread's handle
	IN 	ACCESS_MASK             DesiredAccess,        // Thread's access rights (set to THREAD_ALL_ACCESS - 0x1FFFFF)
	IN 	POBJECT_ATTRIBUTES      ObjectAttributes,     // Pointer to OBJECT_ATTRIBUTES structure (set to NULL)
	IN 	HANDLE                  ProcessHandle,        // Handle to the process in which the thread is to be created.
	IN 	PVOID                   StartRoutine,         // Base address of the application-defined function to be executed
	IN 	PVOID                   Argument,             // Pointer to a variable to be passed to the thread function (set to NULL)
	IN 	ULONG                   CreateFlags,          // The flags that control the creation of the thread (set to NULL)
	IN 	SIZE_T                  ZeroBits,             // Set to NULL
	IN 	SIZE_T                  StackSize,            // Set to NULL
	IN 	SIZE_T                  MaximumStackSize,     // Set to NULL
	IN 	PPS_ATTRIBUTE_LIST      AttributeList         // Pointer to PS_ATTRIBUTE_LIST structure (set to NULL)
	);


typedef NTSTATUS(NTAPI* fnNtQueueApcThread)(
	IN HANDLE               ThreadHandle,                 // A handle to the thread to run the specified APC
	IN PIO_APC_ROUTINE      ApcRoutine,                   // Pointer to the application-supplied APC function to be executed
	IN PVOID                ApcRoutineContext OPTIONAL,   // Pointer to a parameter (1) for the APC (set to NULL)
	IN PIO_STATUS_BLOCK     ApcStatusBlock OPTIONAL,      // Pointer to a parameter (2) for the APC (set to NULL)
	IN ULONG                ApcReserved OPTIONAL          // Pointer to a parameter (3) for the APC (set to NULL)
	);

typedef NTSTATUS(NTAPI* fnNtResumeThread)(
	_In_ HANDLE ThreadHandle,
	_Out_opt_ PULONG PreviousSuspendCount
	);

typedef NTSTATUS(NTAPI* fnNtDelayExecution)(
	_In_ BOOLEAN Alertable,
	_In_ PLARGE_INTEGER DelayInterval
	);

typedef NTSTATUS(NTAPI* fnSystemFunction033)(struct USTRING* Data, struct USTRING* Key);

typedef NTSTATUS(NTAPI*	fnNtTestAlert)();

typedef NTSTATUS(NTAPI* fnNtQueryInformationProcess)(
	_In_ HANDLE ProcessHandle,
	_In_ PROCESSINFOCLASS ProcessInformationClass,
	_Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
	_In_ ULONG ProcessInformationLength,
	_Out_opt_ PULONG ReturnLength
	);

// ############################################  EXTERN #################################################

extern fnNtAllocateVirtualMemory virtualAlloc;
extern fnNtProtectVirtualMemory virtualProtect;
extern fnNtWriteVirtualMemory virtualMemoryWrite;
extern fnNtCreateThreadEx createThread;
extern fnNtQueueApcThread queueApc;
extern fnNtResumeThread resumeThread;
extern fnNtTestAlert NtTestAlert;
extern fnNtDelayExecution NtDelayExecution;
extern fnNtQueryInformationProcess QueryInformationProcess;

//extern fnSystemFunction033 SystemFunction033;

int DynamicDeclare();

