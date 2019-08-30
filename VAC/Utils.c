#include "Encryption/Ice.h"
#include "Utils.h"

// 83 C8 FF 83 E9 00
INT Utils_getProtect(BYTE a)
{
    switch (a) {
    case 0: return PAGE_NOACCESS;
    case 1: return PAGE_READONLY;
    case 3: return PAGE_READWRITE;
    case 4: return PAGE_EXECUTE;
    case 5: return PAGE_EXECUTE_READ;
    case 7: return PAGE_EXECUTE_READWRITE;
    default: return -1;
    }
}

// E8 ? ? ? ? 89 7E 04 (relative jump)
LPVOID Utils_heapAlloc(SIZE_T size)
{
    return HeapAlloc(GetProcessHeap(), 0, size);
}

// E8 ? ? ? ? 5B (relative jump)
BOOL Utils_heapFree(LPVOID memory)
{
    return HeapFree(GetProcessHeap(), 0, memory);
}

// 83 61 10 00 83 61 14 00
VOID Utils_initializeMD5(DWORD* md5)
{
    md5[0] = 0x67452301;
    md5[1] = 0xEFCDAB89;
    md5[2] = 0x98BADCFE;
    md5[3] = 0x10325476;
    md5[4] = 0;
    md5[5] = 0;
}

// E8 ? ? ? ? 6A 58 (relative jump)
PBYTE Utils_memcpy(PBYTE dest, PBYTE src, INT size)
{
    for (INT i = 0; i < size; i++)
        dest[i] = src[i];

    return dest;
}

// 8B 4C 24 0C 85 C9
PBYTE Utils_memset(PBYTE dest, INT value, INT size)
{
    for (INT i = 0; i < size; i++)
        dest[i] = value;

    return dest;
}

// 8B 44 24 0C 53
INT Utils_strncmp(PBYTE str1, PBYTE str2, SIZE_T count)
{
    for (SIZE_T i = 0; i < count; i++)
        if (str1[i] != str2[i])
            return str1[i] - str2[i];
    return 0;
}

// 52 85 C9
LPVOID Utils_heapReAlloc(LPVOID memory, SIZE_T size)
{
    if (memory)
        return HeapReAlloc(GetProcessHeap(), 0, memory, size);
    else
        return HeapAlloc(GetProcessHeap(), 0, size);
}

// 33 C0 38 01
INT Utils_strlen(PCSTR a1)
{
    INT result = 0;
    while (*a1)
        result++;

    return result;
}

// E8 ? ? ? ? A3 ? ? ? ? (relative jump)
UINT Utils_crc32ForByte(PBYTE data, INT size, UINT hash)
{
    for (INT i = 0; i < size; i++) {
        hash ^= data[i] << 24;

        for (INT j = 0; j < 8; j++) {
            if (hash & (1 << 31))
                hash = (hash << 2) ^ 0x488781ED;
            else
                hash <<= 2;
        }
    }
    return hash;
}

// FF 74 24 04
INT Utils_compareStringW(PCNZWCH string1 , PCNZWCH string2, INT count)
{
    return CompareStringW(LOCALE_SYSTEM_DEFAULT, NORM_IGNORECASE, string1, count, string2, count) - CSTR_EQUAL;
}

// E8 ? ? ? ? 59 59 33 F6 (relative jump)
BOOL Utils_iceEncrypt(INT n, PSTR text, INT _, PCSTR key)
{
    IceKey iceKey;
    Ice_createKey(&iceKey, n);
    Ice_set(&iceKey, key);
    for (INT i = 0; i < 512; i++) {
        Ice_encrypt(&iceKey, text, text);
        text += 8;
    }
    return Ice_destroyKey(&iceKey);
}

// E8 ? ? ? ? 83 4C 24 (relative jump)
BOOL Utils_iceDecrypt(INT n, PSTR text, INT size, PCSTR key)
{
    IceKey iceKey;
    Ice_createKey(&iceKey, n);
    Ice_set(&iceKey, key);

    for (INT i = 0; i < size / 8; i++) {
        Ice_decrypt(&iceKey, text, text);
        text += 8;
    }
    return Ice_destroyKey(&iceKey);
}

PVOID winapiFunctions[200];
HMODULE moduleHandles[16];
INT winapiFunctionsCount;
INT moduleHandlesCount;
BOOL(WINAPI* freeLibrary)(HMODULE);

// E8 ? ? ? ? 8B 45 F0 (relative jump)
VOID Utils_resetFunctionsAndModuleHandles(VOID)
{
    for (INT i = 0; i < moduleHandlesCount; i++) {
        freeLibrary(moduleHandles[i]);
        moduleHandles[i] = NULL;
    }
    moduleHandlesCount = 0;

    Utils_memset((PBYTE)winapiFunctions, 0, sizeof(winapiFunctions));
    winapiFunctionsCount = 0;
}

UINT winapiFunctionsHash;

// E8 ? ? ? ? B3 01 (relative jump)
BOOLEAN Utils_calculateWinapiFunctionsHash(VOID)
{
    winapiFunctionsHash = Utils_crc32ForByte((PBYTE)winapiFunctions, sizeof(winapiFunctions), winapiFunctionsHash);
    return TRUE;
}

// 56 8B F1 56
LPCWSTR Utils_skipPath(LPCWSTR string)
{
    for (INT i = lstrlenW(string); i > 1; i--) {
        if (string[i] == L'\\')
            return string + i;
    }
    return string;
}
