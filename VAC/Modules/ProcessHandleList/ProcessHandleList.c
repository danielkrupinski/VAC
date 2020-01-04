#define WIN32_NO_STATUS
#include "../../Utils.h"
#include "ProcessHandleList.h"
#undef WIN32_NO_STATUS

#include <ntstatus.h>

HMODULE ntdll;

typedef struct _SYSTEM_HANDLE {
    ULONG ProcessId;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG HandleCount;
    SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

#define SystemHandleInformation 16

#define __PAIR__(high, low) (((unsigned long)(high)<<sizeof(high)*8) | low)

// 83 EC 2C
INT ProcessHandleList_getSystemHandles(DWORD pids[500], INT pidCount, INT unused, DWORD* handleCount, DWORD* systemHandleCount, LARGE_INTEGER out[500])
{
    CHAR ntQuerySystemInformation[] = { "\x10\x2a\xf\x2b\x3b\x2c\x27\xd\x27\x2d\x2a\x3b\x33\x17\x30\x38\x31\x2c\x33\x3f\x2a\x37\x31\x30\x5e" }; // NtQuerySystemInformation xored with '^'

    for (PCHAR current = ntQuerySystemInformation; *current; current++)
        *current ^= '^';

    NTSTATUS(NTAPI * NtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG) = (PVOID)winApi.GetProcAddress(ntdll, ntQuerySystemInformation);

    INT result = 0;

    if (NtQuerySystemInformation) {
        INT handleInfoLength = 0;
        PSYSTEM_HANDLE_INFORMATION handleInfo = NULL;

        while (TRUE) {
            handleInfoLength += 0x100000;

            if (handleInfo)
                winApi.VirtualFree(handleInfo, 0, MEM_RELEASE);

            handleInfo = winApi.VirtualAlloc(NULL, handleInfoLength, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

            if (!handleInfo)
                break;

            result = NtQuerySystemInformation(SystemHandleInformation, handleInfo, handleInfoLength, NULL);

            if (result != STATUS_INFO_LENGTH_MISMATCH) {
                if (result == STATUS_SUCCESS) {
                    *systemHandleCount = handleInfo->HandleCount;
                    *handleCount = 0;

                    INT counter = 0;

                    for (ULONG i = 0; i < handleInfo->HandleCount; ++i) {
                        SYSTEM_HANDLE handle = handleInfo->Handles[i];

                        for (INT j = 0; j < pidCount; ++j) {
                            if (pids[counter] == handle.ProcessId)
                                break;

                            if (++counter >= pidCount)
                                counter %= pidCount;
                        }


                        if (pids[counter] == handle.ProcessId) {
                            INT unknown1 = 0, unknown2 = 0;

                            if (handle.ObjectTypeIndex < 0x37) {
                                if (handle.ObjectTypeIndex >= 0x20)
                                    unknown2 = 1 << handle.ObjectTypeIndex;

                                unknown1 = unknown2 ^ (1 << handle.ObjectTypeIndex);

                                if (handle.ObjectTypeIndex >= 0x40)
                                    unknown2 ^= 1 << handle.ObjectTypeIndex;
                            }

                            LONG highPart = out[counter].HighPart;
                            if (highPart < 0xFF000000)
                                highPart = (__PAIR__(highPart, out[counter].LowPart) + 0x100000000000000) >> 32;

                            out[counter].LowPart |= unknown1;
                            out[counter].HighPart = unknown2 | highPart;
                        } else {
                            ++*handleCount;

                            if (pidCount < 500) {
                                pids[pidCount] = handle.ProcessId;
                                counter = pidCount++;
                            }
                        }
                    }
                    result = 0;
                }
                if (handleInfo)
                    winApi.VirtualFree(handleInfo, 0, MEM_RELEASE);
                return result;
            }
        }
    }
    return winApi.GetLastError();
}
