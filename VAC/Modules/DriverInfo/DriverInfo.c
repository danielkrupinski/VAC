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
    memcpy(&fileIndex[0], &fileInformation.nFileIndexLow, sizeof(DWORD));
    memcpy(&fileIndex[1], &fileInformation.nFileIndexHigh, sizeof(DWORD));

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

// 81 EC ? ? ? ? 53
DWORD DriverInfo_getDriverInfo(DriverInfo* data, INT driverNameHash)
{
    DWORD result = 0;
    SC_HANDLE scManager = winApi.OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);

    if (scManager) {
        LPENUM_SERVICE_STATUSW serviceStatus = Utils_heapAlloc(65536);
        LPQUERY_SERVICE_CONFIGW serviceConfig = Utils_heapAlloc(0x1000);
        
        if (serviceStatus && serviceConfig) {
            DWORD bytesNeeded, servicesReturned, resumeHandle;
            if ((winApi.EnumServicesStatusW(scManager, SERVICE_DRIVER, SERVICE_ACTIVE, serviceStatus, 65536, &bytesNeeded, &servicesReturned, &resumeHandle) || winApi.GetLastError() == ERROR_MORE_DATA) && servicesReturned > 0) {
                memset((PBYTE)serviceStatus, 0, 65536);
                LPENUM_SERVICE_STATUSW currentServiceStatus = serviceStatus;
                
                for (DWORD i = 0; i < servicesReturned; ++i) {
                    CHAR serviceName[64];
                    Utils_wideCharToMultiByteN(currentServiceStatus->lpServiceName, serviceName, 64);

                    if (Utils_hash(serviceName, Utils_strlen(serviceName)) == driverNameHash) {
                        SC_HANDLE service = winApi.OpenServiceW(scManager, currentServiceStatus->lpServiceName, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);

                        if (service && winApi.QueryServiceConfigW(service, serviceConfig, 4096, &bytesNeeded)) {
                            winApi.CloseServiceHandle(service);

                            Utils_wideCharToMultiByteN(currentServiceStatus->lpServiceName, data->serviceName, 256);
                            Utils_wideCharToMultiByteN(serviceConfig->lpDisplayName, data->displayName, 256);
                            data->serviceType = serviceConfig->dwServiceType;
                            data->startType = serviceConfig->dwStartType;
                            data->errorControl = serviceConfig->dwErrorControl;
                            WCHAR driverPath[256];
                            // TODO: sub_10004612(v4->lpBinaryPathName, &driverPath);
                            Utils_wideCharToMultiByteN(driverPath, data->driverPath, 256);
                            Utils_wideCharToMultiByteN(serviceConfig->lpLoadOrderGroup, data->loaderOrderGroup, 32);
                            Utils_wideCharToMultiByteN(serviceConfig->lpDependencies, data->dependencies, 256);
                            Utils_wideCharToMultiByteN(serviceConfig->lpServiceStartName, data->serviceStartName, 32);

                            LPCWSTR system32InPath = DriverInfo_findSystem32InString(driverPath);
                            if (system32InPath) {
                                // something if driver path contains "system32"

                                // TODO: sub_10004F09(system32InPath + 9, system32InPath + 8, lstrlenW(system32InPath + 8) * sizeof(WCHAR));
                                memcpy((PWSTR)system32InPath + 3, L"native", lstrlenW(L"native") * sizeof(WCHAR));
                            }
                            DriveInfo_getFileInfo(driverPath, &data->volumeSerial, data->fileIndex);
                            winApi.CloseServiceHandle(service);
                        }
                        break;

                    }
                    currentServiceStatus++;
                }
            } else {
                result = winApi.GetLastError();
            }
        } else {
            result = ERROR_NOT_ENOUGH_MEMORY;
        }
        Utils_heapFree(serviceConfig);
        Utils_heapFree(serviceStatus);
        winApi.CloseServiceHandle(scManager);
    } else {
        result = winApi.GetLastError();
    }
    return result;
}