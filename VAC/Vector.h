#pragma once

#include <Windows.h>

typedef struct Vector {
    DWORD* memory;
    UINT allocationCount;
    UINT size;
    INT sizeInBits;
} Vector;

// E8 ? ? ? ? 8B 16 (relative jump)
VOID Vector_ensureCapacity(Vector*, UINT);

// 56 FF 74 24 08
VOID Vector_resize(Vector*, UINT);

// E8 ? ? ? ? 8B CD (relative jump)
VOID Vector_swap(Vector*, Vector*);
