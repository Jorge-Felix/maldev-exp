#include "ldr.h"


__attribute__((section(".text")))
void entry(void)
{
    //resolve GetProcAddress and LoadLibraryA by hash
    HMODULE k32 = 0;
    FN_GetProcAddress GetProcAddr =
        (FN_GetProcAddress)ldr_get_by_hash(HASH_GETPROCADDRESS, (void**)&k32);
    if (!GetProcAddr || !k32) return;

    FN_LoadLibraryA LoadLib =
        (FN_LoadLibraryA)ldr_get_by_hash(HASH_LOADLIBRARYA, 0);
    if (!LoadLib) return;

    //payload ->

    SSTR(sUser32, 'u','s','e','r','3','2','.','d','l','l',0);
    HMODULE user32 = LoadLib((LPCSTR)sUser32);
    if (!user32) return;

    FN_MessageBoxA MsgBox =
        (FN_MessageBoxA)ldr_get_by_hash(HASH_MESSAGEBOXA, 0);
    if (!MsgBox) return;

    SSTR(sTitle, 'w','o','a','h',0);
    SSTR(sBody,  'P','I','C',' ','S','h','e','l','l','c','o','d','e',0);
    MsgBox(0, (LPCSTR)sBody, (LPCSTR)sTitle, 0x30);

    for (;;) {}
}
