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

// 33 C0 BA ? ? ? ?
UINT Utils_icePerm32(UINT);

// E8 ? ? ? ? 59 5F (relative jump)
UINT Utils_gfMul(UINT, UINT, UINT);

// E8 ? ? ? ? 8B C8 (relative jump)
UINT Utils_gfExp7(UINT, UINT);

// E8 ? ? ? ? 89 3D ? ? ? ? (relative jump)
VOID Utils_iceInitSboxes(VOID);

typedef struct IceSubkey {
    UINT val[3];
} IceSubkey;

typedef struct IceKey {
    INT size;
    INT rounds;
    IceSubkey* keys;
} IceKey;

// 56 57 33 FF 8B F1
IceKey* Utils_createIceKey(IceKey*, INT);

// E8 ? ? ? ? EB 68 (relative jump)
VOID Utils_scheduleIceBuild(IceKey*, PUSHORT, INT, CONST INT*);

// E8 ? ? ? ? 2B FE (relative jump)
VOID Utils_setIce(IceKey*, PCSTR);

// 53 33 DB 56 8B F3
BOOL Utils_destroyIceKey(IceKey*);

// E8 ? ? ? ? 8B 4C 24 14 (relative jump) or E8 ? ? ? ? 8B 4D 08 (relative jump)
UINT Utils_iceF(UINT, const IceSubkey*);
