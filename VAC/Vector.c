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

// 56 FF 74 24 08
VOID Vector_resize(Vector* vec, UINT size)
{
    Vector_ensureCapacity(vec, size);

    while (vec->size < size) {
        vec->memory[vec->size] = 0;
        vec->size++;
    }

    vec->sizeInBits = size * sizeof(DWORD) * 8;
}

// E8 ? ? ? ? 8B CD (relative jump)
VOID Vector_swap(Vector* vec1, Vector* vec2)
{
    CONST Vector temp = *vec1;
    vec1->memory = vec2->memory;
    vec1->allocationCount = vec2->allocationCount;
    vec1->size = vec2->size;
    vec1->sizeInBits = vec2->sizeInBits;

    vec2->memory = temp.memory;
    vec2->allocationCount = temp.allocationCount;
    vec2->size = temp.size;
    vec2->sizeInBits = temp.sizeInBits;
}
