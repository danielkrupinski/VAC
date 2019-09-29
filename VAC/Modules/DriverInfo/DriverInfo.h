#pragma once

#include <Windows.h>

// 55 8B EC A1
BOOLEAN DriveInfo_getFileInfo(PCWSTR, DWORD*, DWORD[2]);
