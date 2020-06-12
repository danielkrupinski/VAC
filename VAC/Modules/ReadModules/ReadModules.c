#include "../../Utils.h"
#include "ReadModules.h"

BOOL (WINAPI* openProcessToken)(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
BOOL (WINAPI* lookupPrivilegeValueA)(LPCSTR lpSystemName, LPCSTR lpName, PLUID lpLuid);
BOOL (WINAPI* adjustTokenPrivileges)(HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength);

//  55 8B EC 83 EC 1C
VOID ReadModules_enableDebugPrivilege(VOID)
{
    if (!openProcessToken || !lookupPrivilegeValueA || !adjustTokenPrivileges)
        return;

    HANDLE tokenHandle;
    if (openProcessToken(winApi.GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &tokenHandle)) {
        LUID luid;
        if (lookupPrivilegeValueA(NULL, "SeDebugPrivilege", &luid)) {
            TOKEN_PRIVILEGES priv;
            priv.Privileges[0].Luid = luid;
            priv.PrivilegeCount = 1;
            priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

            adjustTokenPrivileges(tokenHandle, FALSE, &priv, sizeof(TOKEN_PRIVILEGES), NULL, NULL); // BufferLength could be zero because PreviousState is NULL - https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-adjusttokenprivileges
        }
        winApi.CloseHandle(tokenHandle);
    }
}

// 55 8B EC A1
BOOLEAN ReadModules_getFileInformation(LPCWSTR filename, ReadModules_FileInfo* out)
{
    if (!winApi.GetFileInformationByHandle)
        return FALSE;

    HANDLE handle = winApi.CreateFileW(filename, READ_CONTROL | SYNCHRONIZE | FILE_READ_DATA | FILE_READ_EA | FILE_READ_ATTRIBUTES, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (handle == INVALID_HANDLE_VALUE)
        return FALSE;

    BY_HANDLE_FILE_INFORMATION fileInfo;
    BOOL success = winApi.GetFileInformationByHandle(handle, &fileInfo);
    winApi.CloseHandle(handle);

    if (!success)
        return FALSE;

    out->volumeSerialNumber = fileInfo.dwVolumeSerialNumber;
    memcpy(&out->fileIndexLow, &fileInfo.nFileIndexLow, sizeof(DWORD));
    memcpy(&out->fileIndexHigh, &fileInfo.nFileIndexHigh, sizeof(DWORD));
   
    return TRUE;
}
