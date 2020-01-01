#include "SystemInfo.h"

// 55 8B EC B8
INT SystemInfo_collectData(PVOID unk, PVOID unk1, PVOID unk2, PVOID unk3)
{
    CHAR ntDll[] = "\x68\x52\x62\x4A\x4A\x8\x42\x4A\x4A";
    CHAR kernel32[] = "\x6D\x43\x54\x48\x43\x4A\x15\x14\x8\x42\x4A\x4A";
    CHAR ntQuerySystemInformation[] = "\x68\x52\x77\x53\x43\x54\x5F\x75\x5F\x55\x52\x43\x4B\x6F\x48\x40\x49\x54\x4B\x47\x52\x4F\x49\x48";
    CHAR getVersion[] = "\x61\x43\x52\x70\x43\x54\x55\x4F\x49\x48";
    CHAR getNativeSystemInfo[] = "\x61\x43\x52\x68\x47\x52\x4F\x50\x43\x75\x5F\x55\x52\x43\x4B\x6F\x48\x40\x49";
    
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

    curr = ntQuerySystemInformation;
    while (*curr) {
        *curr ^= '&';
        ++curr;
    }

    curr = getVersion;
    while (*curr) {
        *curr ^= '&';
        ++curr;
    }

    curr = getNativeSystemInfo;
    while (*curr) {
        *curr ^= '&';
        ++curr;
    }

    return 0;
}
