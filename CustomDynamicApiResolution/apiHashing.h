#pragma once
#include <Windows.h>

constexpr ULONG hashItA(LPCSTR String);
constexpr ULONG hashItW(LPCWSTR String);

// runtime hashing macros
#define RTIME_HASHA( API ) hashItA((const char*) API)
#define RTIME_HASHW( API ) hashItW((const wchar_t*) API)
// compile time hashing macros (used to create variables)
#define CTIME_HASHA( API ) constexpr auto API##_Rotr32A = hashItA((const char*) #API);
#define CTIME_HASHW( API ) constexpr auto API##_Rotr32W = hashItW((const wchar_t*) L#API);
