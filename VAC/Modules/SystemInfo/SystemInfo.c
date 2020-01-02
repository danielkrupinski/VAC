#include "../../Utils.h"
#include "SystemInfo.h"

#include <winternl.h>

typedef struct _SYSTEM_TIMEOFDAY_INFORMATION_ {
    LARGE_INTEGER BootTime;
    LARGE_INTEGER CurrentTime;
    LARGE_INTEGER TimeZoneBias;
    ULONG TimeZoneId;
    ULONG Reserved;
    ULONGLONG BootTimeBias;
    ULONGLONG SleepTimeBias;
} SYSTEM_TIMEOFDAY_INFORMATION_, *PSYSTEM_TIMEOFDAY_INFORMATION_;

typedef struct _SYSTEM_DEVICE_INFORMATION {
    ULONG NumberOfDisks;
    ULONG NumberOfFloppies;
    ULONG NumberOfCdRoms;
    ULONG NumberOfTapes;
    ULONG NumberOfSerialPorts;
    ULONG NumberOfParallelPorts;
} SYSTEM_DEVICE_INFORMATION, *PSYSTEM_DEVICE_INFORMATION;

typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION {
    BOOLEAN KernelDebuggerEnabled;
    BOOLEAN KernelDebuggerNotPresent;
} SYSTEM_KERNEL_DEBUGGER_INFORMATION, *PSYSTEM_KERNEL_DEBUGGER_INFORMATION;

typedef struct _SYSTEM_BOOT_ENVIRONMENT_INFORMATION {
    GUID BootIdentifier;
    FIRMWARE_TYPE FirmwareType;
    ULONGLONG BootFlags;
} SYSTEM_BOOT_ENVIRONMENT_INFORMATION, *PSYSTEM_BOOT_ENVIRONMENT_INFORMATION;

typedef struct _SYSTEM_RANGE_START_INFORMATION {
    PVOID SystemRangeStart;
} SYSTEM_RANGE_START_INFORMATION, *PSYSTEM_RANGE_START_INFORMATION;

#define SystemDeviceInformation 7
#define SystemKernelDebuggerInformation 35
#define SystemBootEnvironmentInformation 90
#define SystemRangeStartInformation 50

DWORD(WINAPI* getProcessImageFileNameA)(HANDLE, LPSTR, DWORD);

// 55 8B EC B8
INT SystemInfo_collectData(PVOID unk, PVOID unk1, DWORD data[2048], PDWORD dataSize)
{
    CHAR ntDll[] = "\x68\x52\x62\x4A\x4A\x8\x42\x4A\x4A";
    CHAR kernel32[] = "\x6D\x43\x54\x48\x43\x4A\x15\x14\x8\x42\x4A\x4A";
    CHAR ntQuerySystemInformation[] = "\x68\x52\x77\x53\x43\x54\x5F\x75\x5F\x55\x52\x43\x4B\x6F\x48\x40\x49\x54\x4B\x47\x52\x4F\x49\x48";
    CHAR getVersion[] = "\x61\x43\x52\x70\x43\x54\x55\x4F\x49\x48";
    CHAR getNativeSystemInfo[] = "\x61\x43\x52\x68\x47\x52\x4F\x50\x43\x75\x5F\x55\x52\x43\x4B\x6F\x48\x40\x49";
    CHAR wow64EnableWow64FsRedirection[] = "\x71\x49\x51\x10\x12\x63\x48\x47\x44\x4A\x43\x71\x49\x51\x10\x12\x60\x55\x74\x43\x42\x4F\x54\x43\x45\x52\x4F\x49\x48";

    *dataSize = 2048;

    PCHAR curr = ntDll;
    while (*curr) {
        *curr ^= '&';
        ++curr;
    }

    curr = kernel32;
    while (*curr) {
        *curr ^= '&';
        ++curr;
    }

    HMODULE _ntdll = winApi.GetModuleHandleA(ntDll);
    DWORD error;

    if (_ntdll) {
        HMODULE _kernel32 = winApi.GetModuleHandleA(kernel32);

        if (_kernel32) {
            curr = ntQuerySystemInformation;
            while (*curr) {
                *curr ^= '&';
                ++curr;
            }

            curr = getVersion;
            while (*curr) {
                *curr ^= '&';
                ++curr;
            }

            curr = getNativeSystemInfo;
            while (*curr) {
                *curr ^= '&';
                ++curr;
            }

            curr = wow64EnableWow64FsRedirection;
            while (*curr) {
                *curr ^= '&';
                ++curr;
            }
            
            NTSTATUS(NTAPI* _ntQuerySystemInformation)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG) = (PVOID)winApi.GetProcAddress(_ntdll, ntQuerySystemInformation);
             
            if (_ntQuerySystemInformation) {
                DWORD(WINAPI* _getVersion)(VOID) = (PVOID)winApi.GetProcAddress(_kernel32, getVersion);
                
                if (_getVersion) {
                    VOID(WINAPI* _getNativeSystemInfo)(LPSYSTEM_INFO) = (PVOID)winApi.GetProcAddress(_kernel32, getNativeSystemInfo);

                    if (_getNativeSystemInfo) {
                        BOOLEAN(WINAPI* _wow64EnableWow64FsRedirection)(BOOLEAN) = (PVOID)winApi.GetProcAddress(_kernel32, wow64EnableWow64FsRedirection);

                        data[18] = _getVersion();
                        SYSTEM_INFO si;
                        _getNativeSystemInfo(&si);
                        data[20] = si.wProcessorArchitecture;
                        data[21] = si.dwProcessorType;
                        SYSTEM_TIMEOFDAY_INFORMATION_ sti;
                        data[6] = _ntQuerySystemInformation(SystemTimeOfDayInformation, &sti, sizeof(sti), NULL);
                        data[14] = sti.CurrentTime.LowPart;
                        data[15] = sti.CurrentTime.HighPart;
                        data[16] = sti.BootTime.LowPart;
                        data[17] = sti.BootTime.HighPart;
                        SYSTEM_CODEINTEGRITY_INFORMATION sci;
                        sci.Length = sizeof(sci);
                        data[7] = _ntQuerySystemInformation(SystemCodeIntegrityInformation, &sci, sizeof(sci), NULL);
                        data[19] = sci.CodeIntegrityOptions;
                        SYSTEM_DEVICE_INFORMATION sdi;
                        data[22] = _ntQuerySystemInformation(SystemDeviceInformation, &sdi, sizeof(sdi), NULL);
                        data[26] = sdi.NumberOfDisks;
                        SYSTEM_KERNEL_DEBUGGER_INFORMATION skdi;
                        data[23] = _ntQuerySystemInformation(SystemKernelDebuggerInformation, &skdi, sizeof(skdi), NULL);
                        *((PSYSTEM_KERNEL_DEBUGGER_INFORMATION)&data[27]) = skdi;
                        SYSTEM_BOOT_ENVIRONMENT_INFORMATION sbei;
                        Utils_memset(&sbei, 0, sizeof(sbei));
                        data[24] = _ntQuerySystemInformation(SystemBootEnvironmentInformation, &sbei, sizeof(sbei), NULL);
                        Utils_memcpy(&data[28], &sbei.BootIdentifier, sizeof(sbei.BootIdentifier));
                        SYSTEM_RANGE_START_INFORMATION srsi;
                        data[25] = _ntQuerySystemInformation(SystemRangeStartInformation, &srsi, sizeof(srsi), NULL);
                        data[34] = winApi.GetCurrentProcessId();
                        data[35] = winApi.GetCurrentThreadId();
                        data[36] = ERROR_FUNCTION_NOT_CALLED;

                        CHAR currentExe[MAX_PATH];
                        DWORD currentExeLen = 0;

                        if (getProcessImageFileNameA)
                            currentExeLen = getProcessImageFileNameA(winApi.GetCurrentProcess(), currentExe, _countof(currentExe));

                        if (currentExeLen) {
                            data[36] = 0;
                            Utils_memcpy(&data[37], &currentExe[currentExeLen >= 36 ? currentExeLen - 36 : 0], 36);
                        } else {
                            data[36] = GetLastError();
                        }

                        WCHAR systemDir[MAX_PATH];
                        UINT systemDirLen = winApi.GetSystemDirectoryW(systemDir, sizeof(systemDir));
                        
                        if (systemDirLen) {

                        } else {
                            data[159] = data[46] = winApi.GetLastError();
                        }
                    }
                } else {
                    error = GetLastError();
                }
            } else {
                error = GetLastError();
            }
        } else {
            error = GetLastError();
        }
    } else {
        error = GetLastError();
    }
    return 0;
}
