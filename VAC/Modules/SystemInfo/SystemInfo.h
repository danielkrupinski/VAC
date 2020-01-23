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
    DWORD unk;
    DWORD unk1;
    DWORD pad[4];
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
    DWORD winApiError;
    DWORD pad2[5];
    CHAR windowsDir[200];
    // ...
} SystemInfo;

// 55 8B EC B8
INT SystemInfo_collectData(PVOID unk, PVOID unk1, DWORD data[2048], PDWORD dataSize);

// 55 8D 6C 24 90
BOOLEAN SystemInfo_getFileInfo(PCWSTR fileName, DWORD* volumeSerialNumber, PLARGE_INTEGER fileId);

// E8 ? ? ? ? 89 86
INT SystemInfo_enumVolumes(VolumeData volumes[10]);
