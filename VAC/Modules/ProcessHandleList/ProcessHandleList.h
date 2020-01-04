#pragma once

#include <Windows.h>

// 83 EC 2C
INT ProcessHandleList_getSystemHandles(DWORD pids[500], INT pidCount, INT unused, DWORD* handleCount, DWORD* systemHandleCount, LARGE_INTEGER out[500]);
