#pragma once
#include <Windows.h>

FARPROC GetProcAddressReplacement(IN HMODULE hModule, IN DWORD HashedlpApiName);
HMODULE GetModuleHandleReplacement(IN LPCWSTR szModuleName);
BOOL IsStringEqual(IN LPCWSTR Str1, IN LPCWSTR Str2);