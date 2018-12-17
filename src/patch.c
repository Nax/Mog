#include <stdint.h>
#include <string.h>
#include <windows.h>
#include <mog/mog.h>

void mogReplaceFunction(void* dst, void* newAddr)
{
    DWORD oldProtect;
    uint32_t jmpDelta;

    jmpDelta = (uint32_t)newAddr - ((uint32_t)dst + 5);
    VirtualProtect(dst, 5, PAGE_READWRITE, &oldProtect);
    *(uint8_t*)(dst) = 0xe9;
    *((uint32_t*)((uint8_t*)dst + 1)) = jmpDelta;
    VirtualProtect(dst, 5, oldProtect, &oldProtect);
    FlushInstructionCache(GetCurrentProcess(), dst, 5);
}

void* mogRedirectFunction(void* dst, void* newAddr)
{
    DWORD oldProtect;
    uint32_t jmpDelta;

    uint8_t* trampoline = VirtualAlloc(NULL, 11, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    memcpy(trampoline, dst, 6);
    jmpDelta = ((char*)dst + 6) - (trampoline + 11);
    trampoline[6] = 0xe9;
    *(uint32_t*)(trampoline + 7) = jmpDelta;
    jmpDelta = (uint32_t)newAddr - ((uint32_t)dst + 5);
    VirtualProtect(dst, 6, PAGE_READWRITE, &oldProtect);
    *(uint8_t*)(dst) = 0xe9;
    *((uint32_t*)((uint8_t*)dst + 1)) = jmpDelta;
    *((uint8_t*)dst + 5) = 0x90;
    VirtualProtect(dst, 6, oldProtect, &oldProtect);
    VirtualProtect(trampoline, 11, PAGE_EXECUTE_READ, &oldProtect);
    FlushInstructionCache(GetCurrentProcess(), dst, 6);
    FlushInstructionCache(GetCurrentProcess(), trampoline, 11);
    return trampoline;
}

void mogReplaceSkip(void* dst, size_t len)
{
    size_t i;
    DWORD oldProtect;

    if (len >= 128)
    {
        mogReplaceFunction(dst, (char*)dst + len);
        return;
    }

    VirtualProtect(dst, len, PAGE_READWRITE, &oldProtect);

    i = len;
    while (i >= 9)
    {
        memcpy(dst, "\x66\x0f\x1f\x84\x00\x00\x00\x00\x00", 9);
        dst = (char*)dst + 9;
        i -= 9;
    }

    switch (i)
    {
    case 0:
        break;
    case 1:
        memcpy(dst, "\x90", 1);
        break;
    case 2:
        memcpy(dst, "\x66\x90", 2);
        break;
    case 3:
        memcpy(dst, "\x0f\x1f\x00", 3);
        break;
    case 4:
        memcpy(dst, "\x0f\x1f\x40\x00", 4);
        break;
    case 5:
        memcpy(dst, "\x0f\x1f\x44\x00\x00", 5);
        break;
    case 6:
        memcpy(dst, "\x66\x0f\x1f\x44\x00\x00", 6);
        break;
    case 7:
        memcpy(dst, "\x0f\x1f\x80\x00\x00\x00\x00", 7);
        break;
    case 8:
        memcpy(dst, "\x0f\x1f\x84\x00\x00\x00\x00\x00", 8);
        break;
    }

    VirtualProtect(dst, len, oldProtect, &oldProtect);
    FlushInstructionCache(GetCurrentProcess(), dst, len);
}

void mogReplaceNop(void* dst, size_t len)
{
    size_t i;
    DWORD oldProtect;

    VirtualProtect(dst, len, PAGE_READWRITE, &oldProtect);

    i = len;
    while (i >= 2)
    {
        memcpy(dst, "\x66\x90", 2);
        dst = (char*)dst + 2;
        i -= 2;
    }

    switch (i)
    {
    case 0:
        break;
    case 1:
        memcpy(dst, "\x90", 1);
        break;
    }

    VirtualProtect(dst, len, oldProtect, &oldProtect);
    FlushInstructionCache(GetCurrentProcess(), dst, len);
}

void* mogVirtualAddress(uint32_t fixedAddr)
{
    return (void*)(fixedAddr + (uint32_t)GetModuleHandleA(NULL));
}
