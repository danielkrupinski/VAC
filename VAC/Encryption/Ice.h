#pragma once

#include <Windows.h>

// 33 C0 BA ? ? ? ?
UINT Ice_perm32(UINT);

// E8 ? ? ? ? 59 5F (relative jump)
UINT Ice_gfMul(UINT, UINT, UINT);

// E8 ? ? ? ? 8B C8 (relative jump)
UINT Ice_gfExp7(UINT, UINT);

// E8 ? ? ? ? 89 3D ? ? ? ? (relative jump)
VOID Ice_InitSboxes(VOID);

typedef struct IceSubkey {
    UINT val[3];
} IceSubkey;

typedef struct IceKey {
    INT size;
    INT rounds;
    IceSubkey* keys;
} IceKey;

// 56 57 33 FF 8B F1
IceKey* Ice_createKey(IceKey*, INT);

// E8 ? ? ? ? EB 68 (relative jump)
VOID Ice_scheduleBuild(IceKey*, PUSHORT, INT, CONST INT*);

// E8 ? ? ? ? 2B FE (relative jump)
VOID Ice_set(IceKey*, PCSTR);

// 53 33 DB 56 8B F3
BOOL Ice_destroyKey(IceKey*);

// E8 ? ? ? ? 8B 4C 24 14 (relative jump) or E8 ? ? ? ? 8B 4D 08 (relative jump)
UINT Ice_f(UINT, const IceSubkey*);

// E8 ? ? ? ? 83 C7 08 (relative jump)
VOID Ice_decrypt(IceKey*, PCSTR, PSTR);

// E8 ? ? ? ? 83 C6 08 (relative jump)
VOID Ice_encrypt(IceKey*, PCSTR, PSTR);
