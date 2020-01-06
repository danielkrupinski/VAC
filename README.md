# VAC 🛡️
This repository contains parts of source code of Valve Anti-Cheat recreated from machine code.

## Introduction
Valve Anti-Cheat (VAC) is user-mode noninvasive anti-cheat system developed by Valve. It is delivered in form of modules (dlls) streamed from remote server. `steamservice.dll` handles module loading.

## Modules
| ID | Purpose | .text section raw size | Source folder |
| --- | --- | --- | --- |
| 1 | Collect information about system configuration.<br>This module is loaded first and sometimes even before any VAC-secured game is launched. | 0x5C00 | Modules/SystemInfo
| 2 | Enumerate running processes and handles.<br>This module is loaded shortly after game is launched but also repeatedly later. | 0x4A00 | Modules/ProcessHandleList

## Encryption / Hashing
VAC uses several encryption / hashing methods:
- MD5 - hashing data read from process memory
- ICE - decryption of imported functions names and encryption of scan results
- CRC32 - hashing table of WinAPI functions addresses
- Xor - encryption of function names on stack, e.g `NtQuerySystemInformation`. Strings are xor-ed with `^` or `>` or `&` char.

## Module Description

### #1 - SystemInfo
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
- SystemRangeStartInformation - returns `SYSTEM_RANGE_START_INFORMATION` which is just `void*`

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

Eventually, module encrypts data (2048 bytes), DWORD by DWORD XORing with key received from server (e.g 0x1D4855D3)
