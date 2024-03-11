#include <Windows.h>
#include <winternl.h>
#include "apiHashing.h"
#include "apiHashing.cpp"

BOOL IsStringEqual(IN LPCWSTR Str1, IN LPCWSTR Str2) {

	WCHAR   lStr1[MAX_PATH], lStr2[MAX_PATH];

	int		len1 = lstrlenW(Str1), len2 = lstrlenW(Str2);

	int		i = 0, j = 0;

	// Checking length. We dont want to overflow the buffers
	if (len1 >= MAX_PATH || len2 >= MAX_PATH)
		return FALSE;

	// Converting Str1 to lower case string (lStr1)
	for (i = 0; i < len1; i++) {
		lStr1[i] = (WCHAR)tolower(Str1[i]);
	}
	lStr1[i++] = L'\0'; // null terminating

	// Converting Str2 to lower case string (lStr2)
	for (j = 0; j < len2; j++) {
		lStr2[j] = (WCHAR)tolower(Str2[j]);
	}
	lStr2[j++] = L'\0'; // null terminating

	// Comparing the lower-case strings
	if (lstrcmpiW(lStr1, lStr2) == 0)
		return TRUE;

	return FALSE;
}

FARPROC GetProcAddressReplacement(IN HMODULE hModule, IN DWORD HashedlpApiName) {

	// We do this to avoid casting at each time we use 'hModule'
	PBYTE pBase = (PBYTE)hModule;

	// Getting the dos header and doing a signature check
	PIMAGE_DOS_HEADER	pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
	if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	// Getting the nt headers and doing a signature check
	PIMAGE_NT_HEADERS	pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	// Getting the optional header
	IMAGE_OPTIONAL_HEADER	ImgOptHdr = pImgNtHdrs->OptionalHeader;

	// Getting the image export table
	PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	// Getting the function's names array pointer
	PDWORD FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);

	// Getting the function's addresses array pointer
	PDWORD FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);

	// Getting the function's ordinal array pointer
	PWORD  FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);



	// Looping through all the exported functions
	for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {

		// Getting the name of the function
		CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);

		// Getting the address of the function through its ordinal
		PVOID pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);

		// Searching for the function specified
		if (HashedlpApiName == RTIME_HASHA(pFunctionName)) {
			//printf("[ %0.4d ] FOUND API -\t NAME: %s -\t ADDRESS: 0x%p  -\t ORDINAL: %d\n", i, pFunctionName, pFunctionAddress, FunctionOrdinalArray[i]);
			return (FARPROC)pFunctionAddress;
		}
	}

	return NULL;
}

HMODULE GetModuleHandleReplacement(IN LPCWSTR szModuleName) {
#ifdef _WIN64
	PPEB pPeb = (PPEB)(__readgsqword(0x60));
#elif _WIN32
	PPEB pPeb = (PPEB)(__readfsdword(0x30));
#endif

	PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);
	PLDR_DATA_TABLE_ENTRY pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);

	while (pDte) {
		if (pDte->FullDllName.Length != NULL) {
			if (IsStringEqual(pDte->FullDllName.Buffer, szModuleName)) {
				//wprintf(L"[+] Found Dll \"%s\" \n", pDte->FullDllName.Buffer);
#ifdef STRUCTS
				return (HMODULE)(pDte->InInitializationOrderLinks.Flink);
#else
				return (HMODULE)pDte->Reserved2[0];
#endif 
			}
		}

		pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);
	}

	return NULL;
}