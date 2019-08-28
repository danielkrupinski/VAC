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
    for (INT i = 0; i < count; i++)
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
