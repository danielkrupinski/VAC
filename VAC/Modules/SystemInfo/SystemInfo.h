#pragma once

#include <Windows.h>

typedef struct SystemInfo {
    DWORD unknown[4];
    DWORD scanType; // initialized to 0xA93E4B10
    DWORD scanError;

} SystemInfo;

// 55 8B EC B8
INT SystemInfo_collectData(PVOID unk, PVOID unk1, DWORD data[2048], PDWORD dataSize);

// 55 8D 6C 24 90
BOOLEAN SystemInfo_getFileInfo(PCWSTR fileName, DWORD* volumeSerialNumber, PLARGE_INTEGER fileId);
