#include "../../Utils.h"
#include "DriverInfo.h"

// 55 8B EC A1
BOOLEAN DriveInfo_getFileInfo(PCWSTR fileName, DWORD* volumeSerialNumber, DWORD fileIndex[2])
{
    if (!winApi.GetFileInformationByHandle)
        return FALSE;
    
    HANDLE fileHandle = winApi.CreateFileW(fileName, 1179785, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (fileHandle == INVALID_HANDLE_VALUE)
        return FALSE;

    BY_HANDLE_FILE_INFORMATION fileInformation;
    BOOL getFileResult = winApi.GetFileInformationByHandle(fileHandle, &fileInformation);
    winApi.CloseHandle(fileHandle);

    if (!getFileResult)
        return FALSE;

    *volumeSerialNumber = fileInformation.dwVolumeSerialNumber;
    Utils_memcpy(fileIndex, &fileInformation.nFileIndexLow, sizeof(DWORD));
    Utils_memcpy(fileIndex, &fileInformation.nFileIndexHigh, sizeof(DWORD));

    return TRUE;
}
