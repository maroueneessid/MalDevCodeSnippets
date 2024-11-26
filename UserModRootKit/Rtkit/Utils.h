#include <Windows.h>

#define dllFilepath L"C:\\Users\\User\\source\\repos\\goDark\\x64\\Release\\goDark.dll"
#define dllFilepathA "C:\\Users\\User\\source\\repos\\goDark\\x64\\Release\\goDark.dll"


extern const wchar_t* blacklist[10];

BOOL enableAllPrivs();
BOOL inbl(const wchar_t* str);
BOOL inject(DWORD pid);



