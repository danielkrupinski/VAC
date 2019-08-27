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
