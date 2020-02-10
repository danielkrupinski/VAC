# VAC 🛡️
This repository contains parts of source code of Valve Anti-Cheat for Windows systems recreated from machine code.

# Introduction
Valve Anti-Cheat (VAC) is user-mode noninvasive anti-cheat system developed by Valve. It is delivered in form of modules (dlls) streamed from the remote server. `steamservice.dll` loaded into `SteamService.exe` (or `Steam.exe` if run as admin) prepares and runs anti-cheat modules. Client VAC infrastructure is built using `C++` (indicated by many `thiscall` convention functions present in disassembly) but this repo contains `C` code for simplicity. Anti-cheat binaries are currently `32-bit`.

# Modules
| ID | Purpose | .text section raw size | Source folder |
| --- | --- | --- | --- |
| 1 | Collect information about system configuration.<br>This module is loaded first and sometimes even before any VAC-secured game is launched. | 0x5C00 | Modules/SystemInfo
| 2 | Enumerate running processes and handles.<br>This module is loaded shortly after game is launched but also repeatedly later. | 0x4A00 | Modules/ProcessHandleList
| 3 | Collect `VacProcessMonitor` data from filemapping created by `steamservice.dll`. It's the first module observed to use `virtual methods (polymorphism)`. | 0x6600 | Modules/ProcessMonitor

# Encryption / Hashing
VAC uses several encryption / hashing methods:
- MD5 - hashing data read from process memory
- ICE - decryption of imported functions names and encryption of scan results
- CRC32 - hashing table of WinAPI functions addresses
- Xor - encryption of function names on stack, e.g `NtQuerySystemInformation`. Strings are xor-ed with `^` or `>` or `&` char.

# Module Description

## #1 - SystemInfo
This module is loaded first and sometimes even before any VAC-secured game is launched.

At first module invokes [`GetVersion`](https://docs.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getversion) function to retrieve **major and build** system version e.g `0x47BB0A00` - which means:
- 0x47BB - build version (decimal `18363‬`) 
- 0x0A00 - major version (decimal `10`)

The module calls `GetNativeSystemInfo` function and reads fields from resultant [`SYSTEM_INFO`](https://docs.microsoft.com/en-us/windows/win32/api/sysinfoapi/ns-sysinfoapi-system_info) struct:
- wProcessorArchitecture
- dwProcessorType

Then it calls [`NtQuerySystemInformation`](https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation) API function with following `SystemInformationClass` values (in order they appear in code):
- SystemTimeOfDayInformation - returns undocumented [`SYSTEM_TIMEOFDAY_INFORMATION`](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/timeofday.htm) struct, VAC uses two fields:
    - LARGE_INTEGER CurrentTime
    - LARGE_INTEGER BootTime
- SystemCodeIntegrityInformation - returns [`SYSTEM_CODEINTEGRITY_INFORMATION`](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/codeintegrity.htm), module saves `CodeIntegrityOptions` field
- SystemDeviceInformation - returns [`SYSTEM_DEVICE_INFORMATION`](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/device.htm), module saves `NumberOfDisks` field
- SystemKernelDebuggerInformation - returns [`SYSTEM_KERNEL_DEBUGGER_INFORMATION`](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/kernel_debugger.htm), VAC uses whole struct
- SystemBootEnvironmentInformation - returns [`SYSTEM_BOOT_ENVIRONMENT_INFORMATION`](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/boot_environment.htm), VAC copies `BootIdentifier` GUID
- SystemRangeStartInformation - returns `SYSTEM_RANGE_START_INFORMATION` which is just `void*`. Anti-cheat saves returned **kernel space start address** and **sign bit** of that address (to check if executable inside which VAC is running is linked with [`LARGEADDRESSAWARE`](https://docs.microsoft.com/en-us/cpp/build/reference/largeaddressaware-handle-large-addresses) option)

For more information about `SYSTEM_INFORMATION_CLASS` enum see [Geoff Chappell's page](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/class.htm).

Next, anti-cheat calls [`GetProcessImageFileNameA`](https://docs.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getprocessimagefilenamea) function to retrieve path of current executable and **reads last 36 characters** (e.g. `\Program Files (x86)\Steam\Steam.exe`).

Later VAC retrieves **system directory path** (e.g `C:\WINDOWS\system32`) using [`GetSystemDirectoryW`](https://docs.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemdirectoryw), converts it from wide-char to multibyte string, and stores it (max length of multibyte string - 200).
Anti-cheat queries folder FileID (using [`GetFileInformationByHandleEx`](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getfileinformationbyhandleex)) and **volume serial number** ([`GetVolumeInformationByHandleW`](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getvolumeinformationbyhandlew)). Further it does the same with **windows directory** got from [`GetWindowsDirectoryW`](https://docs.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectoryw) API.

Module reads `NtDll.dll` file from **system directory** and does some processing on it (not reversed yet).

VAC saves **handles (base addresses) of imported system dlls** (max 16, this VAC module loads 12 dlls) and **pointers to WINAPI functions** (max 160, module uses 172 functions‬). This is done to detect **import address table hooking** on anti-cheat module, if **function address** is lower than corresponding **module base**, function has been hooked.

Anti-cheat gets self **module base** by performing **bitwise and** on **return address** (`_ReturnAddress() & 0xFFFF0000`). Then it collects:
- module base address
- first four bytes at module base address (from DOS header)
- DWORD at **module base + 0x114**
- DWORD at **module base + 0x400** (start of .text section)

Next it enumerates **volumes** using `FindFirstVolumeW` / `FindNextVolumeW` API. VAC queries volume information by calling `GetVolumeInformationW`, `GetDriveTypeW` and `GetVolumePathNamesForVolumeNameW` functions and fills following struct with collected data:

```cpp
struct VolumeData {
    UINT volumeGuidHash;
    DWORD getVolumeInformationError;
    DWORD fileSystemFlags;
    DWORD volumeSerialNumber;
    UINT volumeNameHash;
    UINT fileSystemNameHash;
    WORD driveType;
    WORD volumePathNameLength;
    DWORD volumePathNameHash;
}; // sizeof(VolumeData) == 32
```
VAC gathers data of max. 10 volumes.

If this module was streamed after VAC-secured game had started, it attemps to get handle to the game process (using `OpenProcess` API).

Eventually, module encrypts data (2048 bytes), DWORD by DWORD XORing with key received from server (e.g 0x1D4855D3)

## #2 - ProcessHandleList

To be disclosed...

## #3 - ProcessMonitor

This module seems to be relatively `new` or was disabled for a long time. First time I saw this module in `January 2020`. It has an ability to perform many different types of scans (currently `3`). Further scans depends on the results of previous ones.

Each scan type implements `four methods` of a base class.

Initially VAC server instructs client to perform `scan #1`.

### Scan #1 - VacProcessMonitor filemapping

First scan function attemps to open `Steam_{E9FD3C51-9B58-4DA0-962C-734882B19273}_Pid:%000008X` filemapping. The mapping has following layout:

```cpp
struct VacProcessMonitorMapping {
    DWORD magic; // when initialized - 0x30004
    PVOID vacProcessMonitor;
}; // sizeof(VacProcessMonitorMapping) == 8
```

`VacProcessMonitorMapping::vacProcessMonitor` is a pointer to the `VacProcessMonitor` object (size of which is `292 bytes`).

VAC then reads the whole `VacProcessMonitor` object (292 bytes) and its VMT (Virtual Method Table) containing pointers to `6` methods (24 bytes).
The base address of `steamservice.dll` is also gathered.

These data are probably used on VAC servers to detect hooking `VacProcessMonitor`. The procedure may be following:
```cpp
if (method_ptr & 0xFFFF0000 != steamservice_base)
    hook_detected();
```
