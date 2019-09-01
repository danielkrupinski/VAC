#pragma once

#include <Windows.h>
#include <TlHelp32.h>

// 83 C8 FF 83 E9 00
INT Utils_getProtect(BYTE);

// E8 ? ? ? ? 89 7E 04 (relative jump)
LPVOID Utils_heapAlloc(SIZE_T);

// E8 ? ? ? ? 5B (relative jump)
BOOL Utils_heapFree(LPVOID);

// 83 61 10 00 83 61 14 00
VOID Utils_initializeMD5(DWORD*);

// E8 ? ? ? ? 6A 58 (relative jump)
PBYTE Utils_memcpy(PBYTE, PBYTE, INT);

// 8B 4C 24 0C 85 C9
PBYTE Utils_memset(PBYTE, INT, INT);

// 8B 44 24 0C 53
INT Utils_strncmp(PBYTE, PBYTE, SIZE_T);

// 52 85 C9
LPVOID Utils_heapReAlloc(LPVOID, SIZE_T);

// 33 C0 38 01
INT Utils_strlen(PCSTR);

// E8 ? ? ? ? A3 ? ? ? ? (relative jump)
UINT Utils_crc32ForByte(PBYTE, INT, UINT);

// FF 74 24 04
INT Utils_compareStringW(PCNZWCH, PCNZWCH, INT);

// E8 ? ? ? ? 59 59 33 F6 (relative jump)
BOOL Utils_iceEncrypt(INT, PSTR, INT, PCSTR);

// E8 ? ? ? ? 83 4C 24 (relative jump)
BOOL Utils_iceDecrypt(INT, PSTR, INT, PCSTR);

extern PVOID winapiFunctions[200];
extern HMODULE moduleHandles[16];
extern INT winapiFunctionsCount;
extern INT moduleHandlesCount;
extern BOOL(WINAPI* freeLibrary)(HMODULE);

// E8 ? ? ? ? 8B 45 F0 (relative jump)
VOID Utils_resetFunctionsAndModuleHandles(VOID);

extern UINT winapiFunctionsHash;

// E8 ? ? ? ? B3 01 (relative jump)
BOOLEAN Utils_calculateWinapiFunctionsHash(VOID);

// 56 8B F1 56
LPCWSTR Utils_skipPath(LPCWSTR);

// E8 ? ? ? ? 32 C0 59 (relative jump)
VOID Utils_copyStringW(PWSTR, PCWSTR, UINT);

typedef struct Data {
    DWORD currentProcessId;
    DWORD currentThreadId;
    SYSTEM_INFO systemInfo;
    OSVERSIONINFOEXA osVersionInfo;
    DWORD systemVersion;
    BYTE _pad[10];
    WCHAR systemDirectory[MAX_PATH];
    WCHAR windowsDirectory[MAX_PATH];
} Data;

extern Data data;

typedef struct WinApi {
    HMODULE(WINAPI* LoadLibraryExA)(LPCSTR, HANDLE, DWORD);
    FARPROC(WINAPI* GetProcAddress)(HMODULE, LPCSTR);
    NTSTATUS(NTAPI* NtOpenProcess)(PHANDLE, ACCESS_MASK, PVOID, PVOID);
    BOOL(WINAPI* FreeLibrary)(HMODULE);
    BOOL(WINAPI* GetVolumeInformationW)(LPCWSTR, LPWSTR, DWORD, LPDWORD, LPDWORD, LPDWORD, LPWSTR, DWORD);
    BOOL(WINAPI* GetFileInformationByHandleEx)(HANDLE, FILE_INFO_BY_HANDLE_CLASS, LPVOID, DWORD);
    BOOL(WINAPI* QueryFullProcessImageNameW)(HANDLE, DWORD, LPWSTR, PDWORD);
    DWORD(WINAPI* GetLastError)(VOID);
    HANDLE(WINAPI* OpenProcess)(DWORD, BOOL, DWORD);
    BOOL(WINAPI* CryptMsgGetParam)(HCRYPTMSG, DWORD, DWORD, void*, DWORD*);
    SC_HANDLE(WINAPI* OpenSCManagerA)(LPCSTR, LPCSTR, DWORD);
    BOOL(WINAPI* GetTokenInformation)(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);
    BOOL(WINAPI* CertCloseStore)(HCERTSTORE, DWORD);
    int(WINAPI* WideCharToMultiByte)(UINT, DWORD, LPCWCH, int, LPSTR, int, LPCCH, LPBOOL);
    BOOL(WINAPI* GetModuleHandleExA)(DWORD, LPCSTR, HMODULE*);
    BOOL(WINAPI* SetFilePointerEx)(HANDLE, LARGE_INTEGER, PLARGE_INTEGER, DWORD);
    HANDLE(WINAPI* FindFirstVolumeW)(LPWSTR, DWORD);
    BOOL(WINAPI* Module32FirstW)(HANDLE, LPMODULEENTRY32W);
    BOOL(WINAPI* CryptMsgClose)(HCRYPTMSG);
    DWORD(APIENTRY* GetFileVersionInfoSizeA)(LPCSTR, LPDWORD);
    HANDLE(WINAPI* GetCurrentProcess)(VOID);
    DWORD _pad[21];
    HANDLE(WINAPI* CreateToolhelp32Snapshot)(DWORD, DWORD);
    BOOL(WINAPI* ConvertSidToStringSidA)(PSID, LPSTR*);
    BOOL(WINAPI* WriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
    NTSTATUS(NTAPI* NtWow64QueryVirtualMemory64)(HANDLE, PVOID64, DWORD, PVOID, ULONG64, PULONG64);
    DWORD(WINAPI* GetModuleBaseNameA)(HANDLE, HMODULE, LPSTR, DWORD);
    LSTATUS(APIENTRY* RegEnumKeyExA)(HKEY, DWORD, LPSTR, LPDWORD, LPDWORD, LPSTR, LPDWORD, PFILETIME);
    DWORD(WINAPI* CertGetNameStringW)(PCCERT_CONTEXT, DWORD, DWORD, void*, LPWSTR, DWORD);
    UINT(WINAPI* GetSystemDirectoryW)(LPWSTR, UINT);
    DWORD _pad2[27];
    BOOL(WINAPI* CloseHandle)(HANDLE);
    DWORD _pad2_[11];
    UINT(WINAPI* GetWindowsDirectoryW)(LPWSTR, UINT);
    DWORD _pad3[27];
    DWORD(WINAPI* GetCurrentProcessId)(VOID);
    DWORD _pad4[5];
    BOOL(WINAPI* Process32FirstW)(HANDLE, LPPROCESSENTRY32W);
    DWORD _pad4_[15];
    BOOL(WINAPI* GetVersionExA)(LPOSVERSIONINFOEXA);
    DWORD _pad5;
    DWORD(WINAPI* GetCurrentThreadId)(VOID);
    DWORD _pad6[11];
    BOOL(WINAPI* Process32NextW)(HANDLE, LPPROCESSENTRY32W);
    DWORD _pad7[6];
    VOID(WINAPI* GetSystemInfo)(LPSYSTEM_INFO);
} WinApi;

extern WinApi winApi;

// 51 A1 ? ? ? ?
BOOLEAN Utils_getSystemInformation(VOID);
