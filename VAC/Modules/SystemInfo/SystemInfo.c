#include "../../Utils.h"
#include "SystemInfo.h"

#include <intrin.h>
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
    WCHAR ntDllWide[] = L"\x68\x52\x62\x4A\x4A\x8\x42\x4A\x4A";
    CHAR ntDll[] = "\x68\x52\x62\x4A\x4A\x8\x42\x4A\x4A";
    CHAR kernel32[] = "\x6D\x43\x54\x48\x43\x4A\x15\x14\x8\x42\x4A\x4A";
    CHAR ntQuerySystemInformation[] = "\x68\x52\x77\x53\x43\x54\x5F\x75\x5F\x55\x52\x43\x4B\x6F\x48\x40\x49\x54\x4B\x47\x52\x4F\x49\x48";
    CHAR getVersion[] = "\x61\x43\x52\x70\x43\x54\x55\x4F\x49\x48";
    CHAR getNativeSystemInfo[] = "\x61\x43\x52\x68\x47\x52\x4F\x50\x43\x75\x5F\x55\x52\x43\x4B\x6F\x48\x40\x49";
    CHAR wow64EnableWow64FsRedirection[] = "\x71\x49\x51\x10\x12\x63\x48\x47\x44\x4A\x43\x71\x49\x51\x10\x12\x60\x55\x74\x43\x42\x4F\x54\x43\x45\x52\x4F\x49\x48";

    memset(data, 0, 2048);
    *dataSize = 2048;
    data[4] = 0xA93E4B10;

    PWCHAR currW = ntDllWide;
    while (*currW) {
        *currW ^= L'&';
        ++currW;
    }

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
                        memset(&sbei, 0, sizeof(sbei));
                        data[24] = _ntQuerySystemInformation(SystemBootEnvironmentInformation, &sbei, sizeof(sbei), NULL);
                        memcpy(&data[28], &sbei.BootIdentifier, sizeof(sbei.BootIdentifier));

                        SYSTEM_RANGE_START_INFORMATION srsi;
                        data[25] = _ntQuerySystemInformation(SystemRangeStartInformation, &srsi, sizeof(srsi), NULL);
                        data[32] = srsi.SystemRangeStart;
                        data[33] = (INT)srsi.SystemRangeStart >> 31;
                        data[34] = winApi.GetCurrentProcessId();
                        data[35] = winApi.GetCurrentThreadId();
                        data[36] = ERROR_FUNCTION_NOT_CALLED;

                        CHAR currentExe[MAX_PATH];
                        DWORD currentExeLen = 0;
                        
                        if (getProcessImageFileNameA)
                            currentExeLen = getProcessImageFileNameA(winApi.GetCurrentProcess(), currentExe, _countof(currentExe));

                        if (currentExeLen) {
                            data[36] = 0;
                            memcpy(&data[37], &currentExe[currentExeLen >= 36 ? currentExeLen - 36 : 0], 36);
                        } else {
                            data[36] = GetLastError();
                        }

                        WCHAR systemDir[MAX_PATH];
                        UINT systemDirLen = winApi.GetSystemDirectoryW(systemDir, sizeof(systemDir));
                       
                        if (systemDirLen) {
                            Utils_wideCharToMultiByte(systemDir, &data[106]);

                            DWORD systemVolumeSerial = 0;
                            LARGE_INTEGER systemFolderId = { 0 };

                            if (SystemInfo_getFileInfo(systemDir, &systemVolumeSerial, &systemFolderId)) {
                                data[156] = systemFolderId.LowPart;
                                data[157] = systemFolderId.HighPart;
                                data[158] = systemVolumeSerial;
                            } else {
                                data[159] = winApi.GetLastError();
                            }

                            systemDir[systemDirLen] = L'\\';
                            memcpy(systemDir[systemDirLen + 1], ntDllWide, sizeof(ntDllWide));

                            BOOLEAN fsRedirDisabled = FALSE;
                            if (_wow64EnableWow64FsRedirection)
                                fsRedirDisabled = _wow64EnableWow64FsRedirection(FALSE);

                            HANDLE ntdllHandle = winApi.CreateFileW(systemDir, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
                            DWORD ntdllOpenErr = winApi.GetLastError();

                            if (fsRedirDisabled)
                                _wow64EnableWow64FsRedirection(TRUE);
                            
                            if (ntdllHandle != INVALID_HANDLE_VALUE) {
                               // read ntdll.dll file and do some processing
                            } else {
                                data[46] = ntdllOpenErr;
                            }

                            WCHAR windowsDir[MAX_PATH];

                            if (winApi.GetWindowsDirectoryW(windowsDir, sizeof(windowsDir))) {
                                Utils_wideCharToMultiByte(windowsDir, &data[52]);

                                DWORD windowsVolumeSerial = 0;
                                LARGE_INTEGER windowsFolderId = { 0 };

                                if (SystemInfo_getFileInfo(windowsDir, &windowsVolumeSerial, &windowsFolderId)) {
                                    data[102] = windowsFolderId.LowPart;
                                    data[103] = windowsFolderId.HighPart;
                                    data[104] = windowsVolumeSerial;
                                } else {
                                    data[105] = winApi.GetLastError();
                                }
                                data[180] = moduleHandlesCount;
                                data[181] = winapiFunctionsCount;
                                memcpy(&data[182], moduleHandles, sizeof(moduleHandles) /* == 64 */);
                                memcpy(&data[198], &winApi, 640);
                                data[358] = (DWORD)_ReturnAddress() & 0xFFFF0000;
                                data[359] = *(DWORD*)((DWORD)_ReturnAddress() & 0xFFFF0000);
                                data[360] = *(DWORD*)((DWORD)_ReturnAddress() & 0xFFFF0000 + 0x114);
                                data[361] = *(DWORD*)((DWORD)_ReturnAddress() & 0xFFFF0000 + 0x400);
                                data[363] = SystemInfo_enumVolumes((VolumeData*)&data[364]);

                                DWORD gamePid = *((DWORD*)unk1 + 24);
                                data[444] = gamePid;

                                if (gamePid) {
                                    HANDLE gameHandle = winApi.OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, gamePid);

                                    if (gameHandle && gameHandle != INVALID_HANDLE_VALUE) {
                                        data[445] = gameHandle;
                                        data[446] = 0;
                                        data[447] = winApi.GetProcessId(gameHandle);
                                        winApi.CloseHandle(gameHandle);
                                    } else {
                                        data[445] = 0;
                                        data[446] = winApi.GetLastError();
                                    }
                                }
                            } else {
                                data[105] = data[46] = winApi.GetLastError();
                            }
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

// 55 8D 6C 24 90
BOOLEAN SystemInfo_getFileInfo(PCWSTR fileName, DWORD* volumeSerialNumber, PLARGE_INTEGER fileId)
{
    if (!winApi.GetFileInformationByHandle)
        return FALSE;

    HANDLE file = winApi.CreateFileW(fileName, READ_CONTROL | SYNCHRONIZE | FILE_READ_DATA | FILE_READ_EA | FILE_READ_ATTRIBUTES, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_SUPPORTS_USN_JOURNAL, NULL);

    if (file == INVALID_HANDLE_VALUE || !winApi.GetFileInformationByHandleEx)
        return FALSE;

    FILE_ID_BOTH_DIR_INFO fileInfo;
    memset(&fileInfo, 0, 132); // 132 while sizeof(FILE_ID_BOTH_DIR_INFO) = 112 ?
    BOOL gotInfo = winApi.GetFileInformationByHandleEx(file, FileIdBothDirectoryInfo, &fileInfo, 132);
    *volumeSerialNumber = 0;

    if (gotInfo && winApi.GetVolumeInformationByHandleW)
        winApi.GetVolumeInformationByHandleW(file, NULL, 0, volumeSerialNumber, NULL, NULL, NULL, 0);

    winApi.CloseHandle(file);

    if (!gotInfo) {
        winApi.GetLastError();
        return 0;
    }
    
    memcpy(&fileId->LowPart, &fileInfo.FileId.LowPart, sizeof(DWORD));
    memcpy(&fileId->HighPart, &fileInfo.FileId.HighPart, sizeof(LONG));
    return TRUE;
}

// E8 ? ? ? ? 89 86
INT SystemInfo_enumVolumes(VolumeData volumes[10])
{
    INT volCount = 0;

    // if (!dword_10008D68)
    //     return 0;

    WCHAR volGuid[MAX_PATH] = { 0 };

    HANDLE vol = winApi.FindFirstVolumeW(volGuid, MAX_PATH);

    if (vol == INVALID_HANDLE_VALUE) {
        VolumeData volData = { 0 };
        winApi.GetLastError();
        return 0;
    }

    if (!winApi.GetVolumeInformationW || !winApi.GetDriveTypeW || !winApi.GetVolumePathNamesForVolumeNameW)
        return 0;

    do {
        VolumeData volData = { 0 };
        volData.volumeGuidHash = Utils_hash(volGuid, lstrlenW(volGuid));

        DWORD volSerialNumber = 0, fileSystemFlags = 0;
        WCHAR volName[50], fileSystemName[50];

        if (winApi.GetVolumeInformationW(volGuid, volName, 50, &volSerialNumber, NULL, &fileSystemFlags, fileSystemName, 50)) {
            volData.fileSystemFlags = fileSystemFlags;
            volData.volumeSerialNumber = volSerialNumber;
            volData.volumeNameHash = Utils_hash(volName, lstrlenW(volName));
            volData.fileSystemNameHash = Utils_hash(fileSystemName, lstrlenW(fileSystemName));
        } else {
            volData.getVolumeInformationError = winApi.GetLastError();
        }
        volData.driveType = winApi.GetDriveTypeW(vol);

        WCHAR volPathName[50];
        DWORD volPathNameLen;
        UINT volPathNameHash;

        if (winApi.GetVolumePathNamesForVolumeNameW(volGuid, volPathName, 50, &volPathNameLen)) {
            volData.volumePathNameLength = volPathNameLen;
            volPathNameHash = Utils_hash(volPathName, lstrlenW(volPathName));
        } else {
            volData.volumePathNameLength = 0;
            volPathNameHash = winApi.GetLastError();
        }

        volData.volumePathNameHash = volPathNameHash;

        if (volCount < 10)
            volumes[volCount] = volData;

        ++volCount;
    } while (winApi.FindNextVolumeW(vol, volGuid, MAX_PATH));
    winApi.FindVolumeClose(vol);
    return volCount;
}
