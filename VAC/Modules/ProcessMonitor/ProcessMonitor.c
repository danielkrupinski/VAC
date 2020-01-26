#include "ProcessMonitor.h"

// E8 ? ? ? ? 59 8B F8 (relative jump)
PVOID ProcessMonitor_readFileMapping(PBOOLEAN md5Computed, PBYTE md5, DWORD out[2])
{
    PVOID result = NULL;
    CHAR name[60];

    wsprintfA(name, "Steam_{E9FD3C51-9B58-4DA0-962C-734882B19273}_Pid:%000008X", GetCurrentProcessId());

    if (md5Computed)
        *md5Computed = FALSE;

    HANDLE fileMapping = OpenFileMappingA(FILE_MAP_READ, FALSE, name);

    if (fileMapping) {
        DWORD* mapped = MapViewOfFile(fileMapping, FILE_MAP_READ, 0, 0, 0);

        if (mapped) {
            if (out) {
                out[0] = mapped[0];
                out[1] = mapped[1];
            }
            if (mapped[0] == 0x30004) // magic number set by steamservice.dll when creating file mapping
                result = (PVOID)mapped[1];
            if (md5) {
                if (md5Computed)
                    *md5Computed = TRUE;

                // compute md5
            }
            UnmapViewOfFile(mapped);
        }
        CloseHandle(fileMapping);
    }
    return result;
}
