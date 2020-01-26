#pragma once

#include <Windows.h>

// E8 ? ? ? ? 59 8B F8 (relative jump)
PVOID ProcessMonitor_readFileMapping(PBOOLEAN md5Computed, PBYTE md5, DWORD out[2]);
