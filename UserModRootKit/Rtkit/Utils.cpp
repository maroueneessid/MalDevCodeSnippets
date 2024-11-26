#include <iostream>
#include <wchar.h>
#include "defs.h"
#include "eventSink.h"
#include "Utils.h"
#pragma comment(lib, "advapi32.lib")


BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege,  BOOL bEnablePrivilege)
{
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValue(
        NULL,            // lookup privilege on local system
        lpszPrivilege,   // privilege to lookup 
        &luid))        // receives LUID of privilege
    {
        printf("LookupPrivilegeValue error: %u\n", GetLastError());
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        tp.Privileges[0].Attributes = 0;

    // Enable the privilege or disable all privileges.

    
    if (!AdjustTokenPrivileges(
        hToken,
        FALSE,
        &tp,
        sizeof(TOKEN_PRIVILEGES),
        (PTOKEN_PRIVILEGES)NULL,
        (PDWORD)NULL))
    {
        printf("AdjustTokenPrivileges error: %u\n", GetLastError());
        return FALSE;
    }
    
    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

    {
        printf("The token does not have the specified privilege. \n");
        return FALSE;
    }
    
    return TRUE;
}

BOOL enableAllPrivs() {


    LPCTSTR privs[] = {
       L"SeAssignPrimaryTokenPrivilege",
       L"SeLockMemoryPrivilege",
       L"SeIncreaseQuotaPrivilege",
       L"SeTcbPrivilege",
       L"SeSecurityPrivilege",
       L"SeTakeOwnershipPrivilege",
       L"SeLoadDriverPrivilege",
       L"SeSystemProfilePrivilege",
       L"SeSystemtimePrivilege",
       L"SeProfileSingleProcessPrivilege",
       L"SeIncreaseBasePriorityPrivilege",
       L"SeCreatePagefilePrivilege",
       L"SeCreatePermanentPrivilege",
       L"SeBackupPrivilege",
       L"SeRestorePrivilege",
       L"SeShutdownPrivilege",
       L"SeDebugPrivilege",
       L"SeAuditPrivilege",
       L"SeSystemEnvironmentPrivilege",
       L"SeChangeNotifyPrivilege",
       L"SeUndockPrivilege",
       L"SeManageVolumePrivilege",
       L"SeImpersonatePrivilege",
       L"SeCreateGlobalPrivilege",
       L"SeIncreaseWorkingSetPrivilege",
       L"SeTimeZonePrivilege",
       L"SeCreateSymbolicLinkPrivilege",
       L"SeDelegateSessionUserImpersonatePrivilege"
    };

    HANDLE token;
    OpenProcessToken((HANDLE)-1, TOKEN_ALL_ACCESS, &token);
    if (!token) {
        printf("[-] Error getting needed token. Error: %lu\n", GetLastError());
        return FALSE;
    }

    for (int i = 0; i < (sizeof(privs) / sizeof(privs[0])); i++) {
        if (SetPrivilege(token, privs[i], TRUE) == FALSE) {
            return FALSE;
        }
    }

    return TRUE;
}

BOOL inbl(const wchar_t* str) {

	int string_list_size = sizeof(blacklist) / sizeof(blacklist[0]);
	for (int i = 0; i < string_list_size; i++) {
		if (_wcsicmp(str, (const wchar_t*)blacklist[i]) == 0) {
			return TRUE; 
		}
	}
	return FALSE;
}

BOOL inject(DWORD pid) {


	wchar_t dllPath[] = TEXT(dllFilepathA);

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        printf("[-] Error getting target process handle. Error:%lu\n", GetLastError());
        return FALSE;
    }
	PVOID remoteBuffer = VirtualAllocEx(hProcess, NULL, sizeof(dllPath), MEM_COMMIT, PAGE_READWRITE);
    if (!remoteBuffer) {
        printf("[-] Failed to alloc mem in remote process. Error: %lu\n", GetLastError());
        return FALSE;
    }
    if (WriteProcessMemory(hProcess, remoteBuffer, dllPath, sizeof(dllPath), NULL) == 0) {
        printf("[-] Failed to write mem in remote process. Error: %lu\n", GetLastError());
        return FALSE;
    }
	
    PTHREAD_START_ROUTINE threatStartRoutineAddress = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("Kernel32")), "LoadLibraryW");

	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, threatStartRoutineAddress, remoteBuffer, 0, NULL);
    if (!hThread) {
        printf("[-] Failed to start remote thread. Error: %lu\n", GetLastError());
        return FALSE;
    }

	CloseHandle(hProcess);


	return TRUE;


}



