#pragma once

#include <Windows.h>

typedef struct VolumeData {
    UINT volumeGuidHash;
    DWORD getVolumeInformationError;
    DWORD fileSystemFlags;
    DWORD volumeSerialNumber;
    UINT volumeNameHash;
    UINT fileSystemNameHash;
    WORD driveType;
    WORD volumePathNameLength;
    DWORD volumePathNameHash;
} VolumeData;

typedef struct SystemInfo {
    DWORD unknown[4];
    DWORD scanType; // initialized to 0xA93E4B10
    DWORD scanError;
    NTSTATUS queryTimeInfo;
    NTSTATUS queryCodeIntegrity;
    /* TODO: time + something from KUSER_SHARED_DATA */
    DWORD unk;
    DWORD unk1;
    DWORD pad[4];
    /* END */
    LARGE_INTEGER currentTime;
    LARGE_INTEGER bootTime;
    DWORD systemVersion;
    ULONG codeIntegrityOptions;
    DWORD processorArchitecture;
    DWORD processorType;
    NTSTATUS queryDeviceInfo;
    NTSTATUS queryKernelDebuggerInfo;
    NTSTATUS queryBootEnvironmentInfo;
    NTSTATUS queryRangeStartInfo;
    ULONG numberOfDisks;
    DWORD kernelDebuggerInfo;
    GUID bootIdentifier;
    PVOID systemRangeStart;
    PVOID systemRangeExtended;
    DWORD currentProcessId;
    DWORD currentThreadId;
    DWORD getCurrentExeNameError;
    CHAR currentExeName[36];
    DWORD winapiError;
    DWORD pad2[5];
    CHAR windowsDir[200];
    LARGE_INTEGER windowsFolderId;
    DWORD windowsVolumeSerial;
    DWORD getWindowsDirError;
    CHAR systemDir[200];
    LARGE_INTEGER systemFolderId;
    DWORD systemVolumeSerial;
    DWORD getSystemDirError;
    DWORD pad3[20];
    INT moduleHandlesCount;
    INT winapiFunctionsCount;
    HMODULE moduleHandles[16];
    PVOID winapiFunctions[160];
    DWORD vacModuleBase;
    DWORD vacModuleBaseVal;
    DWORD vacModuleSomething;
    DWORD vacModuleTextStart;
    DWORD unk2;
    INT volumeCount;
    VolumeData volumes[10];
    DWORD gamePidFromSteam;
    HANDLE gameProcessHandle;
    DWORD gameProcessOpenError;
    DWORD gamePid;
    DWORD unused[64];
} SystemInfo;

// 55 8B EC B8
INT SystemInfo_collectData(PVOID unk, PVOID unk1, DWORD data[2048], PDWORD dataSize);

// 55 8D 6C 24 90
BOOLEAN SystemInfo_getFileInfo(PCWSTR fileName, DWORD* volumeSerialNumber, PLARGE_INTEGER fileId);

// E8 ? ? ? ? 89 86
INT SystemInfo_enumVolumes(VolumeData volumes[10]);
