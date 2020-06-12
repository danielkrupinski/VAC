#pragma once

#include <Windows.h>

//  55 8B EC 83 EC 1C
VOID ReadModules_enableDebugPrivilege(VOID);

typedef struct {
    DWORD volumeSerialNumber;
    DWORD fileIndexLow;
    DWORD fileIndexHigh;
} ReadModules_FileInfo;

// 55 8B EC A1
BOOLEAN ReadModules_getFileInformation(LPCWSTR filename, ReadModules_FileInfo* out);
