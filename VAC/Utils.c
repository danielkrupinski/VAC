#include "Utils.h"
#include "Encryption/Ice.h"

// 83 C8 FF 83 E9 00
INT Utils_getProtect(BYTE a)
{
    switch (a) {
    case 0: return PAGE_NOACCESS;
    case 1: return PAGE_READONLY;
    case 3: return PAGE_READWRITE;
    case 4: return PAGE_EXECUTE;
    case 5: return PAGE_EXECUTE_READ;
    case 7: return PAGE_EXECUTE_READWRITE;
    default: return -1;
    }
}

// E8 ? ? ? ? 89 7E 04 (relative jump)
LPVOID Utils_heapAlloc(SIZE_T size)
{
    return HeapAlloc(GetProcessHeap(), 0, size);
}

// E8 ? ? ? ? 5B (relative jump)
BOOL Utils_heapFree(LPVOID memory)
{
    return HeapFree(GetProcessHeap(), 0, memory);
}

// 83 61 10 00 83 61 14 00
VOID Utils_initializeMD5(DWORD* md5)
{
    md5[0] = 0x67452301;
    md5[1] = 0xEFCDAB89;
    md5[2] = 0x98BADCFE;
    md5[3] = 0x10325476;
    md5[4] = 0;
    md5[5] = 0;
}

// E8 ? ? ? ? 6A 58 (relative jump)
PBYTE Utils_memcpy(PVOID dest, PVOID src, INT size)
{
    for (INT i = 0; i < size; i++)
        ((PBYTE)dest)[i] = ((PBYTE)src)[i];

    return dest;
}

// 8B 4C 24 0C 85 C9
PBYTE Utils_memset(PBYTE dest, INT value, INT size)
{
    for (INT i = 0; i < size; i++)
        dest[i] = value;

    return dest;
}

// 8B 44 24 0C 53
INT Utils_memcmp(PVOID str1, PVOID str2, SIZE_T count)
{
    for (SIZE_T i = 0; i < count; i++)
        if (((PBYTE)str1)[i] != ((PBYTE)str2)[i])
            return ((PBYTE)str1)[i] - ((PBYTE)str2)[i];
    return 0;
}

// 52 85 C9
LPVOID Utils_heapReAlloc(LPVOID memory, SIZE_T size)
{
    if (memory)
        return HeapReAlloc(GetProcessHeap(), 0, memory, size);
    else
        return HeapAlloc(GetProcessHeap(), 0, size);
}

// 33 C0 38 01
INT Utils_strlen(PCSTR a1)
{
    INT result = 0;
    while (*a1)
        result++;

    return result;
}

// E8 ? ? ? ? A3 ? ? ? ? (relative jump)
UINT Utils_crc32ForByte(PBYTE data, INT size, UINT hash)
{
    for (INT i = 0; i < size; i++) {
        hash ^= data[i] << 24;

        for (INT j = 0; j < 8; j++) {
            if (hash & (1 << 31))
                hash = (hash << 2) ^ 0x488781ED;
            else
                hash <<= 2;
        }
    }
    return hash;
}

// FF 74 24 04
INT Utils_compareStringW(PCNZWCH string1 , PCNZWCH string2, INT count)
{
    return CompareStringW(LOCALE_SYSTEM_DEFAULT, NORM_IGNORECASE, string1, count, string2, count) - CSTR_EQUAL;
}

// E8 ? ? ? ? 59 59 33 F6 (relative jump)
BOOL Utils_iceEncrypt(INT n, PSTR text, INT _, PCSTR key)
{
    IceKey iceKey;
    Ice_createKey(&iceKey, n);
    Ice_set(&iceKey, key);
    for (INT i = 0; i < 512; i++) {
        Ice_encrypt(&iceKey, text, text);
        text += 8;
    }
    return Ice_destroyKey(&iceKey);
}

// E8 ? ? ? ? 83 4C 24 (relative jump)
BOOL Utils_iceDecrypt(INT n, PSTR text, INT size, PCSTR key)
{
    IceKey iceKey;
    Ice_createKey(&iceKey, n);
    Ice_set(&iceKey, key);

    for (INT i = 0; i < size / 8; i++) {
        Ice_decrypt(&iceKey, text, text);
        text += 8;
    }
    return Ice_destroyKey(&iceKey);
}

HMODULE moduleHandles[16];
INT winapiFunctionsCount;
INT moduleHandlesCount;
BOOL(WINAPI* freeLibrary)(HMODULE);

// E8 ? ? ? ? 8B 45 F0 (relative jump)
VOID Utils_resetFunctionsAndModuleHandles(VOID)
{
    for (INT i = 0; i < moduleHandlesCount; i++) {
        freeLibrary(moduleHandles[i]);
        moduleHandles[i] = NULL;
    }
    moduleHandlesCount = 0;

    Utils_memset((PBYTE)&winApi, 0, sizeof(winApi));
    winapiFunctionsCount = 0;
}

UINT winapiFunctionsHash;

// E8 ? ? ? ? B3 01 (relative jump)
BOOLEAN Utils_calculateWinapiFunctionsHash(VOID)
{
    winapiFunctionsHash = Utils_crc32ForByte((PBYTE)&winApi, sizeof(winApi), winapiFunctionsHash);
    return TRUE;
}

// 56 8B F1 56
LPCWSTR Utils_skipPath(LPCWSTR string)
{
    for (INT i = lstrlenW(string); i > 1; i--) {
        if (string[i] == L'\\')
            return string + i;
    }
    return string;
}

// E8 ? ? ? ? 32 C0 59 (relative jump)
VOID Utils_copyStringW(PWSTR dest, PCWSTR src, UINT count)
{
    Utils_memcpy((PBYTE)dest, (PBYTE)src, count * sizeof(WCHAR));
    UINT srcLength = lstrlenW(src);
    if (count > srcLength)
        Utils_memset((PBYTE)(dest + srcLength), 0, (count - srcLength) * sizeof(WCHAR));
}

Data data;
Snmp snmp;
WinApi winApi;

// 51 A1 ? ? ? ?
BOOLEAN Utils_getSystemInformation(VOID)
{
    data.currentProcessId = winApi.GetCurrentProcessId();
    data.currentThreadId = winApi.GetCurrentThreadId();

    if (data.currentProcessId && data.currentThreadId) {
        winApi.GetSystemInfo(&data.systemInfo);

        if (data.systemInfo.dwPageSize == 4096) {
            data.osVersionInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXA);

            if (winApi.GetVersionExA(&data.osVersionInfo)) {
                data.systemVersion = data.osVersionInfo.dwPlatformId | ((data.osVersionInfo.dwMajorVersion | (data.osVersionInfo.dwMinorVersion << 8)) << 8);
                if (winApi.GetSystemDirectoryW(data.systemDirectory, sizeof(data.systemDirectory)) && winApi.GetWindowsDirectoryW(data.windowsDirectory, sizeof(data.windowsDirectory))) // VALVE PLS FIX - BUFFER SIZE SHOULD BE MAX_PATH - https://docs.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectoryw
                    return TRUE;
            }
        }
    }
    return FALSE;
}

// A1 ? ? ? ? 53 56
int Utils_wideCharToMultiByte(LPCWCH wideCharStr, LPSTR multiByteStr)
{
    int result = winApi.WideCharToMultiByte(CP_UTF8, 0, wideCharStr, -1, multiByteStr, MAX_PATH, NULL, NULL);

    if (!result)
        multiByteStr[MAX_PATH - 1] = 0;
    return result;
}

// E8 ? ? ? ? 59 B0 01 (relative jump)
VOID Utils_copyStringW2(PWSTR dest, PCWSTR src)
{
    Utils_memcpy((PBYTE)dest, (PBYTE)src, 512 * sizeof(WCHAR));
    INT srcLength = lstrlenW(src);
    if (srcLength < 512)
        Utils_memset((PBYTE)(dest + srcLength), 0, (512 - srcLength) * sizeof(WCHAR));
}

// E8 ? ? ? ? 8D 44 24 48 (relative jump)
BOOLEAN Utils_replaceDevicePathWithName(PWSTR devicePath, INT unused)
{
    WCHAR driveStrings[250];
    if (!GetLogicalDriveStringsW(250, driveStrings))
        return FALSE;

    WCHAR deviceName[3] = { L"C:" };
    INT devicePathLength = 0;

    PCWSTR currentDrive = driveStrings;
    while (TRUE) {
        deviceName[0] = currentDrive[0];
        WCHAR devicePath[MAX_PATH];
        if (QueryDosDeviceW(deviceName, devicePath, MAX_PATH)) {
            devicePathLength = lstrlenW(devicePath);
            if (devicePathLength < MAX_PATH && !Utils_compareStringW(devicePath, devicePath, devicePathLength))
                break;
        }
        while (*currentDrive++);

        if (!*currentDrive)
            return FALSE;
    }

    WCHAR result[MAX_PATH];
    result[0] = L'\0';
    lstrcatW(result, deviceName);
    lstrcatW(result, devicePath + devicePathLength);
    Utils_copyStringW2(devicePath, result);
    return TRUE;
}

// E8 ? ? ? ? EB 07 (relative jump)
VOID Utils_freeSnmp(VOID)
{
    if (snmp.inetmib1) {
        VOID(WINAPI* SnmpExtensionClose)(VOID) = (PVOID)winApi.GetProcAddress(snmp.inetmib1, "SnmpExtensionClose");

        if (SnmpExtensionClose)
            SnmpExtensionClose();
        winApi.FreeLibrary(snmp.inetmib1);
        snmp.inetmib1 = NULL;
        snmp.SnmpExtensionQuery = NULL;
    }

    if (snmp.snmpapi) {
        winApi.FreeLibrary(snmp.snmpapi);
        snmp.snmpapi = NULL;
        snmp.SnmpUtilMemAlloc = NULL;
        snmp.SnmpUtilVarBindFree = NULL;
    }
}

// E8 ? ? ? ? 84 C0 74 6B (relative jump)
BOOLEAN Utils_initializeSnmp(VOID)
{
    if (snmp.inetmib1)
        Utils_freeSnmp();

    snmp.inetmib1 = winApi.LoadLibraryExA("inetmib1.dll", NULL, 0);
    BOOL(WINAPI* snmpExtensionInit)(DWORD, HANDLE*, AsnObjectIdentifier*) = (PVOID)winApi.GetProcAddress(snmp.inetmib1, "SnmpExtensionInit");
    snmp.SnmpExtensionQuery = (PVOID)winApi.GetProcAddress(snmp.inetmib1, "SnmpExtensionQuery");

    snmp.snmpapi = winApi.LoadLibraryExA("snmpapi.dll", NULL, 0);
    snmp.SnmpUtilMemAlloc = (PVOID)winApi.GetProcAddress(snmp.snmpapi, "SnmpUtilMemAlloc");
    snmp.SnmpUtilVarBindFree = (PVOID)winApi.GetProcAddress(snmp.snmpapi, "SnmpUtilVarBindFree");

    HANDLE dummy;
    AsnObjectIdentifier asnId;

    if (!snmp.inetmib1 || !snmpExtensionInit || !snmp.SnmpExtensionQuery || !snmp.snmpapi || !snmp.SnmpUtilMemAlloc || !snmp.SnmpUtilVarBindFree || !snmpExtensionInit(winApi.GetTickCount(), &dummy, &asnId)) {
        Utils_freeSnmp();
        return FALSE;
    }
    return TRUE;
}

static DWORD snmpIds[14] = { 1, 3, 6, 1, 2, 1, 4, 0x15, 1, 7, 0, 0, 0, 0 };
static DWORD snmpIds2[10] = { 1, 3, 6, 1, 2, 1, 4, 0x16, 1, 2 };

// 55 8B EC 83 EC 10
BOOLEAN Utils_retrieveAsnValue(AsnInteger32* out)
{
    SnmpVarBindList varBindList;
    varBindList.len = 1;

    PUINT ids = snmp.SnmpUtilMemAlloc(sizeof(snmpIds));
    Utils_memcpy((PBYTE)ids, (PBYTE)snmpIds, sizeof(snmpIds));
    SnmpVarBind* varBind = snmp.SnmpUtilMemAlloc(sizeof(SnmpVarBind));
    varBind->name.idLength = 14;
    varBind->name.ids = ids;
    varBind->value.asnType = ASN_NULL;
    varBind->value.asnValue.number = 0;

    varBindList.list = varBind;
    AsnInteger32 errorStatus, errorIndex;

    if (snmp.SnmpExtensionQuery(SNMP_PDU_GET, &varBindList, &errorStatus, &errorIndex) && !errorStatus && varBindList.len && varBindList.list->name.idLength == 14) {
        if (!Utils_memcmp((PBYTE)varBindList.list->name.ids, (PBYTE)snmpIds, sizeof(snmpIds)) && varBindList.list->value.asnType == ASN_IPADDRESS && varBindList.list->value.asnValue.counter64.HighPart == 4) {
            *out = varBindList.list->value.asnValue.number;
            snmp.SnmpUtilVarBindFree(varBind);
            return TRUE;
        }
    }
    snmp.SnmpUtilVarBindFree(varBind);
    return FALSE;
}

// 83 EC 10 53 55
BOOLEAN Utils_findAsnString(AsnInteger32 asnValue, PBYTE out)
{
    Utils_memset(out, 0, 6);
    SnmpVarBindList varBindList;
    varBindList.len = 1;

    PUINT ids = snmp.SnmpUtilMemAlloc(40);
    Utils_memcpy(ids, snmpIds2, sizeof(snmpIds2));
    SnmpVarBind* varBind = snmp.SnmpUtilMemAlloc(sizeof(SnmpVarBind));
    varBind->name.idLength = 10;
    varBind->name.ids = ids;
    varBind->value.asnType = ASN_NULL;
    varBind->value.asnValue.number = 0;

    varBindList.list = varBind;

    AsnInteger32 errorStatus = 0, errorIndex;

    BOOLEAN result = FALSE;

    while (!result) {
        if (!snmp.SnmpExtensionQuery(SNMP_PDU_GETNEXT, &varBindList, &errorStatus, &errorIndex) || errorStatus || varBindList.list->name.idLength < 15 || Utils_memcmp(varBindList.list->name.ids, snmpIds2, sizeof(snmpIds2)))
            break;

        if (varBindList.list->name.ids[11] | varBindList.list->name.ids[12] | (((varBindList.list->name.ids[14] << 8) | varBindList.list->name.ids[13] << 8)) << 8 == asnValue && varBindList.list->value.asnType == ASN_OCTETSTRING && varBindList.list->value.asnValue.counter64.HighPart == 6) {
            Utils_memcpy(out, varBindList.list->value.asnValue.string.stream, 6);
            result = TRUE;
        }
    }

    snmp.SnmpUtilVarBindFree(varBind);
    return result;
}

// E8 ? ? ? ? 89 45 54 (relative jump)
INT Utils_enumProcesses(DWORD pids[500], DWORD parentPids[500])
{
    INT processCount = 0;
    HANDLE snapshot = winApi.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snapshot == INVALID_HANDLE_VALUE)
        return 60;
    PROCESSENTRY32W processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32W);

    if (winApi.Process32FirstW(snapshot, &processEntry)) {
        do {
            if (processCount < 500) {
                INT i;
                for (i = processCount - 1; i >= 0 && pids[i] > processEntry.th32ProcessID; i--)
                    pids[i + 1] = pids[i];

                processCount++;
                pids[i + 1] = processEntry.th32ProcessID;
                parentPids[i + 1] = processEntry.th32ParentProcessID;
            }
        } while (winApi.Process32NextW(snapshot, &processEntry));
    }
    winApi.CloseHandle(snapshot);
    return processCount;
}

HMODULE ntdll;

typedef struct _SYSTEM_HANDLE
{
    ULONG ProcessId;
    BYTE ObjectTypeNumber;
    BYTE Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG HandleCount;
    SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

#define SystemHandleInformation 16

#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004

// 83 EC 2C
INT Utils_getSystemHandles(DWORD pids[500], INT pidCount, INT unused, DWORD* handleCount, DWORD* systemHandleCount, DWORD* out)
{
    CHAR ntQuerySystemInformation[] = { "\x10\x2a\xf\x2b\x3b\x2c\x27\xd\x27\x2d\x2a\x3b\x33\x17\x30\x38\x31\x2c\x33\x3f\x2a\x37\x31\x30\x5e" }; // NtQuerySystemInformation xored with '^'

    for (PCHAR current = ntQuerySystemInformation; *current; current++)
        *current ^= '^';

    NTSTATUS(NTAPI* NtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG) = winApi.GetProcAddress(ntdll, ntQuerySystemInformation);

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
                
                if (!result) {
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

                        ++*handleCount;

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
