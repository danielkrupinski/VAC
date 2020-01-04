#define WIN32_NO_STATUS
#include "../../Utils.h"
#include "ProcessHandleList.h"
#undef WIN32_NO_STATUS

#include <ntstatus.h>

HMODULE ntdll;

typedef struct _SYSTEM_HANDLE
{
    ULONG ProcessId;
    BYTE ObjectTypeNumber;
    BYTE Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, * PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG HandleCount;
    SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

#define SystemHandleInformation 16

// 83 EC 2C
INT Utils_getSystemHandles(DWORD pids[500], INT pidCount, INT unused, DWORD* handleCount, DWORD* systemHandleCount, DWORD* out)
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

                    if (handleInfo->HandleCount > 15) {

                        INT counter = 0;

                        SYSTEM_HANDLE handle = handleInfo->Handles[0];

                        for (INT i = 0; i < pidCount; i++) {
                            if (pids[counter] == handle.ProcessId) {

                                INT unknown = 0;
                                INT unknown_2 = 0;

                                if (handle.ObjectTypeNumber < 55) {
                                    if (handle.ObjectTypeNumber >= 32)
                                        unknown = 1 << handle.ObjectTypeNumber;
                                    unknown_2 = unknown ^ (1 << handle.ObjectTypeNumber);


                                }
                                // TODO: reverse it

                            }

                            if (++counter >= i)
                                counter %= i;
                        }

                        ++* handleCount;

                        if (pidCount < 500) {

                            pids[pidCount] = handle.ProcessId;
                            counter = pidCount++;
                        }
                    }
                }

                if (handleInfo)
                    winApi.VirtualFree(handleInfo, 0, MEM_RELEASE);
                return result;
            }
        }
    }
}
