#pragma once

#include <Windows.h>

typedef struct Vector {
    DWORD* memory;
    INT allocationCount;
    INT size;
    INT _unknown;
} Vector;
