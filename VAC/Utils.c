#include "Utils.h"

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
PBYTE Utils_memcpy(PBYTE dest, PBYTE src, INT size)
{
    for (INT i = 0; i < size; i++)
        dest[i] = src[i];

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
INT Utils_strncmp(PBYTE str1, PBYTE str2, SIZE_T count)
{
    for (SIZE_T i = 0; i < count; i++)
        if (str1[i] != str2[i])
            return str1[i] - str2[i];
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

// BA ? ? ? ? 85 C9
static CONST UINT icePbox[32] = {
    0x00000001, 0x00000080, 0x00000400, 0x00002000,
    0x00080000, 0x00200000, 0x01000000, 0x40000000,
    0x00000008, 0x00000020, 0x00000100, 0x00004000,
    0x00010000, 0x00800000, 0x04000000, 0x20000000,
    0x00000004, 0x00000010, 0x00000200, 0x00008000,
    0x00020000, 0x00400000, 0x08000000, 0x10000000,
    0x00000002, 0x00000040, 0x00000800, 0x00001000,
    0x00040000, 0x00100000, 0x02000000, 0x80000000 };

// 33 C0 BA ? ? ? ?
UINT Utils_icePerm32(UINT x)
{
    UINT result = 0;
    CONST UINT* pbox = icePbox;

    while (x) {
        if (x & 1)
            result |= *pbox;
        pbox++;
        x >>= 1;
    }

    return result;
}

// E8 ? ? ? ? 59 5F (relative jump)
UINT Utils_gfMul(UINT a, UINT b, UINT m)
{
    UINT result = 0;

    while (b) {
        if (b & 1)
            result ^= a;

        a <<= 1;
        b >>= 1;

        if (a >= 256)
            a ^= m;
    }

    return result;
}

// E8 ? ? ? ? 8B C8 (relative jump)
UINT Utils_gfExp7(UINT b, UINT m)
{
    if (!b)
        return 0;

    UINT x = Utils_gfMul(b, b, m);
    x = Utils_gfMul(b, x, m);
    x = Utils_gfMul(x, x, m);
    return Utils_gfMul(b, x, m);
}

static UINT iceSbox[4][1024];
static BOOL iceSboxesInitialised = 0;

// E8 ? ? ? ? 89 3D ? ? ? ? (relative jump)
VOID Utils_iceInitSboxes(VOID)
{
    static CONST INT iceSmod[4][4] = {
        { 333, 313, 505, 369 },
        { 379, 375, 319, 391 },
        { 361, 445, 451, 397 },
        { 397, 425, 395, 505 } };

    static CONST INT iceSxor[4][4] = {
        { 0x83, 0x85, 0x9B, 0xCD },
        { 0xCC, 0xA7, 0xAD, 0x41 },
        { 0x4B, 0x2E, 0xD4, 0x33 },
        { 0xEA, 0xCB, 0x2E, 0x04 } };

    for (INT i = 0; i < 1024; i++) {
        CONST INT col = (i >> 1) & 0xFF;
        CONST INT row = (i & 1) | ((i & 0x200) >> 8);

        UINT x = Utils_gfExp7(col ^ iceSxor[0][row], iceSmod[0][row]) << 24;
        iceSbox[0][i] = Utils_icePerm32(x);

        x = Utils_gfExp7(col ^ iceSxor[1][row], iceSmod[1][row]) << 16;
        iceSbox[1][i] = Utils_icePerm32(x);

        x = Utils_gfExp7(col ^ iceSxor[2][row], iceSmod[2][row]) << 8;
        iceSbox[2][i] = Utils_icePerm32(x);

        x = Utils_gfExp7(col ^ iceSxor[3][row], iceSmod[3][row]);
        iceSbox[3][i] = Utils_icePerm32(x);
    }
}

// 56 57 33 FF 8B F1
IceKey* Utils_createIceKey(IceKey* iceKey, INT n)
{
    if (!iceSboxesInitialised) {
        Utils_iceInitSboxes();
        iceSboxesInitialised = TRUE;
    }

    iceKey->size = 1;
    iceKey->rounds = 16;
    iceKey->keys = Utils_heapAlloc(192);
    return iceKey;
}

// E8 ? ? ? ? EB 68 (relative jump)
VOID Utils_scheduleIceBuild(IceKey* iceKey, PUSHORT kb, INT n, CONST INT* keyrot)
{
    for (INT i = 0; i < 8; i++) {
        IceSubkey* iceSubkey = &iceKey->keys[n + i];

        for (INT j = 0; j < 3; j++)
            iceSubkey->val[j] = 0;

        for (INT j = 0; j < 15; j++) {
            PULONG currentSubkey = &iceSubkey->val[j % 3];

            for (INT k = 0; k < 4; k++) {
                PUSHORT currentKb = &kb[(keyrot[i] + k) & 3];
                CONST INT bit = *currentKb & 1;

                *currentSubkey = (*currentSubkey << 1) | bit;
                *currentKb = (*currentKb >> 1) | ((bit ^ 1) << 15);
            }
        }
    }
}

// E8 ? ? ? ? 2B FE (relative jump)
VOID Utils_setIce(IceKey* iceKey, PCSTR key)
{
    static CONST INT iceKeyrot[16] = {
         0, 1, 2, 3, 2, 1, 3, 0,
         1, 3, 2, 0, 3, 1, 0, 2 };

    if (iceKey->rounds == 8) {
        USHORT kb[4];

        for (INT i = 0; i < 4; i++)
            kb[3 - i] = (key[i * 2] << 8) | key[i * 2 + 1];

        Utils_scheduleIceBuild(iceKey, kb, 0, iceKeyrot);
        return;
    }

    for (INT i = 0; i < iceKey->size; i++) {
        USHORT kb[4];

        for (INT j = 0; j < 4; j++)
            kb[3 - j] = (key[i * 8 + j * 2] << 8) | key[i * 8 + j * 2 + 1];

        Utils_scheduleIceBuild(iceKey, kb, i * 8, iceKeyrot);
        Utils_scheduleIceBuild(iceKey, kb, iceKey->rounds - 8 - i * 8, &iceKeyrot[8]);
    }
}

// 53 33 DB 56 8B F3
BOOL Utils_destroyIceKey(IceKey* iceKey)
{
    for (INT i = 0; i < iceKey->rounds; i++)
        for (INT j = 0; j < 3; j++)
            iceKey->keys[i].val[j] = 0;

    iceKey->rounds = iceKey->size = 0;

    return Utils_heapFree(iceKey->keys);
}

// E8 ? ? ? ? 8B 4C 24 14 (relative jump) or E8 ? ? ? ? 8B 4D 08 (relative jump)
UINT Utils_iceF(UINT p, const IceSubkey* sk)
{
    UINT tl = ((p >> 16) & 0x3FF) | (((p >> 14) | (p << 18)) & 0xFFC00);
    UINT tr = (p & 0x3FF) | ((p << 2) & 0xFFC00);

    UINT al = sk->val[2] & (tl ^ tr);
    UINT ar = al ^ tr ^ tl;

    al ^= sk->val[0];
    ar ^= sk->val[1];

    return iceSbox[0][al >> 10] | iceSbox[1][al & 0x3FF] | iceSbox[2][ar >> 10] | iceSbox[3][ar & 0x3FF];
}

// E8 ? ? ? ? 83 C7 08 (relative jump)
VOID Utils_decryptIce(IceKey* iceKey, PCSTR ctext, PSTR ptext)
{
    UINT l = ctext[3] | ((ctext[2] | ((ctext[1] | (ctext[0] << 8)) << 8)) << 8);
    UINT r = ctext[7] | ((ctext[6] | ((ctext[5] | (ctext[4] << 8)) << 8)) << 8);

    for (INT i = iceKey->rounds - 1; i > 0; i -= 2) {
        l ^= Utils_iceF(r, &iceKey->keys[i]);
        r ^= Utils_iceF(l, &iceKey->keys[i - 1]);
    }

    for (INT i = 0; i < 4; i++) {
        ptext[3 - i] = r & 0xff;
        ptext[7 - i] = l & 0xff;

        r >>= 8;
        l >>= 8;
    }
}

// E8 ? ? ? ? 83 C6 08 (relative jump)
VOID Utils_encryptIce(IceKey* iceKey, PCSTR ptext, PSTR ctext)
{
    UINT l = ctext[3] | ((ctext[2] | ((ctext[1] | (ctext[0] << 8)) << 8)) << 8);
    UINT r = ctext[7] | ((ctext[6] | ((ctext[5] | (ctext[4] << 8)) << 8)) << 8);

    for (INT i = 0; i < iceKey->rounds; i += 2) {
        l ^= Utils_iceF(r, &iceKey->keys[i]);
        r ^= Utils_iceF(l, &iceKey->keys[i + 1]);
    }

    for (INT i = 0; i < 4; i++) {
        ctext[3 - i] = r & 0xff;
        ctext[7 - i] = l & 0xff;

        r >>= 8;
        l >>= 8;
    }
}

// E8 ? ? ? ? 59 59 33 F6 (relative jump)
BOOL Utils_encryptWithIce(INT n, PSTR text, INT _, PCSTR key)
{
    IceKey iceKey;
    Utils_createIceKey(&iceKey, n);
    Utils_setIce(&iceKey, key);
    for (INT i = 0; i < 512; i++) {
        Utils_encryptIce(&iceKey, text, text);
        text += 8;
    }
    return Utils_destroyIceKey(&iceKey);
}
