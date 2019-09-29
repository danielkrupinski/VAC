#include "../../Utils.h"
#include "DriverInfo.h"

// 55 8B EC A1
BOOLEAN DriveInfo_getFileInfo(PCWSTR fileName, DWORD* volumeSerialNumber, DWORD fileIndex[2])
{
    if (!winApi.GetFileInformationByHandle)
        return FALSE;
    
    HANDLE fileHandle = winApi.CreateFileW(fileName, READ_CONTROL | SYNCHRONIZE | FILE_READ_DATA | FILE_READ_EA | FILE_READ_ATTRIBUTES, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (fileHandle == INVALID_HANDLE_VALUE)
        return FALSE;

    BY_HANDLE_FILE_INFORMATION fileInformation;
    BOOL getFileResult = winApi.GetFileInformationByHandle(fileHandle, &fileInformation);
    winApi.CloseHandle(fileHandle);

    if (!getFileResult)
        return FALSE;

    *volumeSerialNumber = fileInformation.dwVolumeSerialNumber;
    Utils_memcpy(&fileIndex[0], &fileInformation.nFileIndexLow, sizeof(DWORD));
    Utils_memcpy(&fileIndex[1], &fileInformation.nFileIndexHigh, sizeof(DWORD));

    return TRUE;
}

// E8 ? ? ? ? 89 44 24 10 (relative jump)
LPCWSTR DriverInfo_findSystem32InString(PCWSTR str)
{
    PCWSTR first = str;
    PCWSTR second = L"system32";

    while (*first && *second) {
        if (CharUpperW((LPWSTR)*first) == CharUpperW((LPWSTR)*second)) {
            ++second;
            ++first;
        } else {
            first = ++str;
            second = L"system32";
        }
    }
    return !*second ? str : NULL;
}
