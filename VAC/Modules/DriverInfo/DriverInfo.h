#pragma once

#include <Windows.h>

// 55 8B EC A1
BOOLEAN DriveInfo_getFileInfo(PCWSTR, DWORD*, DWORD[2]);

// E8 ? ? ? ? 89 44 24 10 (relative jump)
LPCWSTR DriverInfo_findSystem32InString(PCWSTR);
