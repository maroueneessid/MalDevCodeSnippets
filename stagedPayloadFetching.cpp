#include <stdio.h>
#include <windows.h>
#include <wininet.h>
#include <stdlib.h>
#include <wchar.h>
#pragma comment(lib, "wininet.lib")

// convert command line argument as valid object for InternetUrlOpenW
wchar_t* charToWchar(const char* str) {
    size_t len;
    if (mbstowcs_s(&len, NULL, 0, str, _TRUNCATE) != 0) {
        return NULL;
    }

    wchar_t* wstr = (wchar_t*)malloc((len + 1) * sizeof(wchar_t)); // Allocate memory
    if (wstr == NULL) {
        return NULL;
    }

    if (mbstowcs_s(NULL, wstr, len + 1, str, _TRUNCATE) != 0) {
        free(wstr);
        return NULL;
    }

    return wstr;
}

int main(int argc, char** argv[])
{
    if (argc < 2)
    {
        printf("[!] Usage: program.exe <URL2BIN>");
        return -1;
    }
    HINTERNET session = InternetOpenW(NULL, NULL, NULL, NULL, NULL);

    if (!session)
    {
        printf("[-] Error creating internet session. Error: %lu", GetLastError());
        return -1;
    }

    HINTERNET hLink = InternetOpenUrlW(session, charToWchar(argv[1]), NULL, NULL, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID | INTERNET_FLAG_RELOAD, NULL);

    if (!hLink)
    {
        printf("[+] Error fetching url. Error: %lu\n", GetLastError());
        return -1;
    }

    DWORD szPayload = 0;
    unsigned tmpBuf[1024];
    DWORD bytesRead = 0;

    while (TRUE)
    {
        if (!InternetReadFile(hLink, tmpBuf, 1024, &bytesRead))
        {
            printf("[-] Something went wrong reading remote file. Error: %lu\n", GetLastError());
            return -1;
        }
        szPayload = szPayload + bytesRead;
        if (bytesRead < 1024)
        {
            printf("[!] Finished reading remote file of size %lu\n", szPayload);
            break;
        }
    }

    unsigned char* buf = (unsigned char*)malloc(szPayload + 1);
    if (!buf)
    {
        printf("[-] Could not allocate enough memory for the payload. Error: %lu\n", GetLastError());
        return -1;
    }

    // Reset position in the file before re-reading
    InternetSetFilePointer(hLink, 0, NULL, FILE_BEGIN, 0);
    
    if (!InternetReadFile(hLink, buf, szPayload, &bytesRead))
    {
        printf("[-] Could not fetch the totality of the payload. Error: %lu\n", GetLastError());
        return -1;
    }

    for (int i = 0; i < szPayload; i++)
    {
        printf("\\x%02x", buf[i]);
    }

    // Cleanup
    InternetCloseHandle(session);
    InternetCloseHandle(hLink);
    free(buf);
    return 0;
}
