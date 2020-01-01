#include "SystemInfo.h"

// 55 8B EC B8
INT SystemInfo_collectData(PVOID unk, PVOID unk1, PVOID unk2, PVOID unk3)
{
    CHAR ntDll[] = "\x68\x52\x62\x4A\x4A\x8\x42\x4A\x4A";
    CHAR kernel32[] = "\x6D\x43\x54\x48\x43\x4A\x15\x14\x8\x42\x4A\x4A";

    PCHAR curr = ntDll;
    while (*curr) {
        *curr ^= '&';
        ++curr;
    }

    curr = kernel32;
    while (*curr) {
        *curr ^= '&';
        ++curr;
    }


    return 0;
}
