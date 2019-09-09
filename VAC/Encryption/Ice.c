#include "../Utils.h"
#include "Ice.h"

// BA ? ? ? ? 85 C9
static CONST UINT Ice_pbox[32] = {
    0x00000001, 0x00000080, 0x00000400, 0x00002000,
    0x00080000, 0x00200000, 0x01000000, 0x40000000,
    0x00000008, 0x00000020, 0x00000100, 0x00004000,
    0x00010000, 0x00800000, 0x04000000, 0x20000000,
    0x00000004, 0x00000010, 0x00000200, 0x00008000,
    0x00020000, 0x00400000, 0x08000000, 0x10000000,
    0x00000002, 0x00000040, 0x00000800, 0x00001000,
    0x00040000, 0x00100000, 0x02000000, 0x80000000 };

// 33 C0 BA ? ? ? ?
UINT Ice_perm32(UINT x)
{
    UINT result = 0;
    CONST UINT* pbox = Ice_pbox;

    while (x) {
        if (x & 1)
            result |= *pbox;
        pbox++;
        x >>= 1;
    }

    return result;
}

// E8 ? ? ? ? 59 5F (relative jump)
UINT Ice_gfMul(UINT a, UINT b, UINT m)
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
UINT Ice_gfExp7(UINT b, UINT m)
{
    if (!b)
        return 0;

    UINT x = Ice_gfMul(b, b, m);
    x = Ice_gfMul(b, x, m);
    x = Ice_gfMul(x, x, m);
    return Ice_gfMul(b, x, m);
}

static UINT Ice_sbox[4][1024];
static BOOL Ice_sboxesInitialized = 0;

// E8 ? ? ? ? 89 3D ? ? ? ? (relative jump)
VOID Ice_InitSboxes(VOID)
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

        UINT x = Ice_gfExp7(col ^ iceSxor[0][row], iceSmod[0][row]) << 24;
        Ice_sbox[0][i] = Ice_perm32(x);

        x = Ice_gfExp7(col ^ iceSxor[1][row], iceSmod[1][row]) << 16;
        Ice_sbox[1][i] = Ice_perm32(x);

        x = Ice_gfExp7(col ^ iceSxor[2][row], iceSmod[2][row]) << 8;
        Ice_sbox[2][i] = Ice_perm32(x);

        x = Ice_gfExp7(col ^ iceSxor[3][row], iceSmod[3][row]);
        Ice_sbox[3][i] = Ice_perm32(x);
    }
}

// 56 57 33 FF 8B F1
IceKey* Ice_createKey(IceKey* iceKey, INT n)
{
    if (!Ice_sboxesInitialized) {
        Ice_InitSboxes();
        Ice_sboxesInitialized = TRUE;
    }

    iceKey->size = 1;
    iceKey->rounds = 16;
    iceKey->keys = Utils_heapAlloc(192);
    return iceKey;
}

// E8 ? ? ? ? EB 68 (relative jump)
VOID Ice_scheduleBuild(IceKey* iceKey, PUSHORT kb, INT n, CONST INT* keyrot)
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
VOID Ice_set(IceKey* iceKey, PCSTR key)
{
    static CONST INT iceKeyrot[16] = {
         0, 1, 2, 3, 2, 1, 3, 0,
         1, 3, 2, 0, 3, 1, 0, 2 };

    if (iceKey->rounds == 8) {
        USHORT kb[4];

        for (INT i = 0; i < 4; i++)
            kb[3 - i] = (key[i * 2] << 8) | key[i * 2 + 1];

        Ice_scheduleBuild(iceKey, kb, 0, iceKeyrot);
        return;
    }

    for (INT i = 0; i < iceKey->size; i++) {
        USHORT kb[4];

        for (INT j = 0; j < 4; j++)
            kb[3 - j] = (key[i * 8 + j * 2] << 8) | key[i * 8 + j * 2 + 1];

        Ice_scheduleBuild(iceKey, kb, i * 8, iceKeyrot);
        Ice_scheduleBuild(iceKey, kb, iceKey->rounds - 8 - i * 8, &iceKeyrot[8]);
    }
}

// 53 33 DB 56 8B F3
BOOL Ice_destroyKey(IceKey* iceKey)
{
    for (INT i = 0; i < iceKey->rounds; i++)
        for (INT j = 0; j < 3; j++)
            iceKey->keys[i].val[j] = 0;

    iceKey->rounds = iceKey->size = 0;

    return Utils_heapFree(iceKey->keys);
}

// E8 ? ? ? ? 8B 4C 24 14 (relative jump) or E8 ? ? ? ? 8B 4D 08 (relative jump)
UINT Ice_f(UINT p, const IceSubkey* sk)
{
    UINT tl = ((p >> 16) & 0x3FF) | (((p >> 14) | (p << 18)) & 0xFFC00);
    UINT tr = (p & 0x3FF) | ((p << 2) & 0xFFC00);

    UINT al = sk->val[2] & (tl ^ tr);
    UINT ar = al ^ tr ^ tl;

    al ^= sk->val[0];
    ar ^= sk->val[1];

    return Ice_sbox[0][al >> 10] | Ice_sbox[1][al & 0x3FF] | Ice_sbox[2][ar >> 10] | Ice_sbox[3][ar & 0x3FF];
}

// E8 ? ? ? ? 83 C7 08 (relative jump)
VOID Ice_decrypt(IceKey* iceKey, PCSTR ctext, PSTR ptext)
{
    UINT l = ctext[3] | ((ctext[2] | ((ctext[1] | (ctext[0] << 8)) << 8)) << 8);
    UINT r = ctext[7] | ((ctext[6] | ((ctext[5] | (ctext[4] << 8)) << 8)) << 8);

    for (INT i = iceKey->rounds - 1; i > 0; i -= 2) {
        l ^= Ice_f(r, &iceKey->keys[i]);
        r ^= Ice_f(l, &iceKey->keys[i - 1]);
    }

    for (INT i = 0; i < 4; i++) {
        ptext[3 - i] = r & 0xff;
        ptext[7 - i] = l & 0xff;

        r >>= 8;
        l >>= 8;
    }
}

// E8 ? ? ? ? 83 C6 08 (relative jump)
VOID Ice_encrypt(IceKey* iceKey, PCSTR ptext, PSTR ctext)
{
    UINT l = ptext[3] | ((ptext[2] | ((ptext[1] | (ptext[0] << 8)) << 8)) << 8);
    UINT r = ptext[7] | ((ptext[6] | ((ptext[5] | (ptext[4] << 8)) << 8)) << 8);

    for (INT i = 0; i < iceKey->rounds; i += 2) {
        l ^= Ice_f(r, &iceKey->keys[i]);
        r ^= Ice_f(l, &iceKey->keys[i + 1]);
    }

    for (INT i = 0; i < 4; i++) {
        ctext[3 - i] = r & 0xff;
        ctext[7 - i] = l & 0xff;

        r >>= 8;
        l >>= 8;
    }
}
