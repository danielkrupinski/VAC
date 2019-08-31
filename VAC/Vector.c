#include "Utils.h"
#include "Vector.h"

// E8 ? ? ? ? 8B 16 (relative jump)
VOID Vector_ensureCapacity(Vector* vec, UINT capacity)
{
    if (vec->allocationCount < capacity) {
        DWORD* oldMemory = vec->memory;

        vec->allocationCount = capacity;
        vec->memory = Utils_heapAlloc(capacity * sizeof(DWORD));

        for (INT i = vec->size - 1; i; i--)
            vec->memory[i] = oldMemory[i];

        Utils_heapFree(oldMemory);
    }
}