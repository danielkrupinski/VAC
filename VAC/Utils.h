#pragma once

#include <Windows.h>

// 83 C8 FF 83 E9 00
INT Utils_getProtect(BYTE);

// E8 ? ? ? ? 89 7E 04 (relative jump)
LPVOID Utils_heapAlloc(SIZE_T);

// E8 ? ? ? ? 5B (relative jump)
BOOL Utils_heapFree(LPVOID);

// 83 61 10 00 83 61 14 00
VOID Utils_initializeMD5(DWORD*);

// E8 ? ? ? ? 6A 58 (relative jump)
PBYTE Utils_memcpy(PBYTE, PBYTE, INT);

// 8B 4C 24 0C 85 C9
PBYTE Utils_memset(PBYTE, INT, INT);

// 8B 44 24 0C 53
INT Utils_strncmp(PBYTE, PBYTE, SIZE_T);

// 52 85 C9
LPVOID Utils_heapReAlloc(LPVOID, SIZE_T);

// 33 C0 38 01
INT Utils_strlen(PCSTR);

// E8 ? ? ? ? A3 ? ? ? ? (relative jump)
UINT Utils_crc32ForByte(PBYTE, INT, UINT);

// FF 74 24 04
INT Utils_compareStringW(PCNZWCH, PCNZWCH, INT);

// E8 ? ? ? ? 59 59 33 F6 (relative jump)
BOOL Utils_iceEncrypt(INT, PSTR, INT, PCSTR);

// E8 ? ? ? ? 83 4C 24 (relative jump)
BOOL Utils_iceDecrypt(INT, PSTR, INT, PCSTR);

extern PVOID winapiFunctions[200];
extern HMODULE moduleHandles[16];
extern INT winapiFunctionsCount;
extern INT moduleHandlesCount;
extern BOOL(WINAPI* freeLibrary)(HMODULE);

// E8 ? ? ? ? 8B 45 F0 (relative jump)
VOID Utils_resetFunctionsAndModuleHandles(VOID);

extern UINT winapiFunctionsHash;

// E8 ? ? ? ? B3 01 (relative jump)
BOOLEAN Utils_calculateWinapiFunctionsHash(VOID);

// 56 8B F1 56
LPCWSTR Utils_skipPath(LPCWSTR);

// E8 ? ? ? ? 32 C0 59 (relative jump)
VOID Utils_copyStringW(PWSTR, PCWSTR, UINT);
