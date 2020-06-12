#include "../../Utils.h"
#include "ReadModules.h"

BOOL (WINAPI* openProcessToken)(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
BOOL (WINAPI* lookupPrivilegeValueA)(LPCSTR lpSystemName, LPCSTR lpName, PLUID lpLuid);
BOOL (WINAPI* adjustTokenPrivileges)(HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength);

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
