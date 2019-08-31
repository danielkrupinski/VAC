#pragma once

#include <Windows.h>

typedef struct Vector {
    DWORD* memory;
    INT allocationCount;
    INT size;
    INT sizeInBits;
} Vector;

// E8 ? ? ? ? 8B 16 (relative jump)
VOID Vector_ensureCapacity(Vector*, UINT);
