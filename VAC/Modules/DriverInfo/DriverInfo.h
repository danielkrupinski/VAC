#pragma once

#include <Windows.h>

// 55 8B EC A1
BOOLEAN DriveInfo_getFileInfo(PCWSTR, DWORD*, DWORD[2]);

// E8 ? ? ? ? 89 44 24 10 (relative jump)
LPCWSTR DriverInfo_findSystem32InString(PCWSTR);

typedef struct DriverInfo {
    DWORD unknown[4];
    DWORD mystery; // initialized to 0x6E1CA4EA
    DWORD scanResult; // return value from DriverInfo_getDriverInfo() or error code
    DWORD zero; // initialized to 0

    /* Members accessed by DriverInfo_getDriverInfo() */
    CHAR serviceName[256];
    CHAR displayName[256];
    DWORD serviceType;
    DWORD startType;
    DWORD errorControl;
    CHAR driverPath[256];
    CHAR loaderOrderGroup[32];
    CHAR dependencies[256];
    CHAR serviceStartName[32];
    DWORD fileIndex[2];
    DWORD volumeSerial;
    /* ---------------------------------------------- */
} DriverInfo;

// 81 EC ? ? ? ? 53
DWORD DriverInfo_getDriverInfo(DriverInfo* data, INT driverNameHash);
