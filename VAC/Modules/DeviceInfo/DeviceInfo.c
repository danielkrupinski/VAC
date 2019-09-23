#include "DeviceInfo.h"

// E8 ? ? ? ? 8D 54 24 28 (relative jump)
PSTR DeviceInfo_strstr(PCSTR str1, PCSTR str2)
{
    PCSTR first = str1;
    PCSTR second = str2;

    while (*first && *second) {
        if (*first == *second) {
            ++second;
            ++first;
        } else {
            first = ++str1;
            second = str2;
        }
    }
    return !*second ? (PSTR)str1 : NULL;
}
