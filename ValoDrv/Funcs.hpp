#include <ntifs.h>
#include <intrin.h>
#include "Structs.h"
#include "Defines.h"
#include "offsets.h"

extern "C" PVOID NTAPI PsGetProcessSectionBaseAddress(PEPROCESS Process);

uintptr_t context_cr3 = 0;

#define Win1803 17134
#define Win1809 17763
#define Win1903 18362
#define Win1909 18363
#define Win2004 19041
#define Win20H2 19569
#define Win21H1 20180

NTSTATUS ReadPhysicalMemory(PVOID TargetAddress, PVOID Buffer, SIZE_T Size, SIZE_T* BytesRead) {
    MM_COPY_ADDRESS CopyAddress = { 0 };
    CopyAddress.PhysicalAddress.QuadPart = (LONGLONG)TargetAddress;
    return MmCopyMemory(Buffer, CopyAddress, Size, MM_COPY_MEMORY_PHYSICAL, BytesRead);
}

INT32 GetWindowsVersion() {
    RTL_OSVERSIONINFOW VersionInfo = { 0 };
    RtlGetVersion(&VersionInfo);
    switch (VersionInfo.dwBuildNumber) {
    case Win1803:
        return 0x0278;
        break;
    case Win1809:
        return 0x0278;
        break;
    case Win1903:
        return 0x0280;
        break;
    case Win1909:
        return 0x0280;
        break;
    case Win2004:
        return 0x0388;
        break;
    case Win20H2:
        return 0x0388;
        break;
    case Win21H1:
        return 0x0388;
        break;
    default:
        return 0x0388;
    }
}

UINT64 GetProcessCr3(PEPROCESS Process) {
    if (!Process) return 0;
    uintptr_t process_dirbase = *(uintptr_t*)((UINT8*)Process + 0x28);
    if (process_dirbase == 0)
    {
        ULONG user_diroffset = GetWindowsVersion();
        process_dirbase = *(uintptr_t*)((UINT8*)Process + user_diroffset);
    }
    if ((process_dirbase >> 0x38) == 0x40)
    {
        uintptr_t SavedDirBase = 0;
        bool Attached = false;
        if (!Attached)
        {
            KAPC_STATE apc_state{};
            KeStackAttachProcess(Process, &apc_state);
            SavedDirBase = __readcr3();
            KeUnstackDetachProcess(&apc_state);
            Attached = true;
        }
        if (SavedDirBase) return SavedDirBase;

    }
    return process_dirbase;
}

UINT64 TranslateLinearAddress(UINT64 DirectoryTableBase, UINT64 VirtualAddress) {
    DirectoryTableBase &= ~0xf;

    UINT64 PageOffset = VirtualAddress & ~(~0ul << PageOffsetSize);
    UINT64 PteIndex = ((VirtualAddress >> 12) & (0x1ffll));
    UINT64 PtIndex = ((VirtualAddress >> 21) & (0x1ffll));
    UINT64 PdIndex = ((VirtualAddress >> 30) & (0x1ffll));
    UINT64 PdpIndex = ((VirtualAddress >> 39) & (0x1ffll));

    SIZE_T ReadSize = 0;
    UINT64 PdpEntry = 0;
    ReadPhysicalMemory(PVOID(DirectoryTableBase + 8 * PdpIndex), &PdpEntry, sizeof(PdpEntry), &ReadSize);
    if (~PdpEntry & 1)
        return 0;

    UINT64 PdEntry = 0;
    ReadPhysicalMemory(PVOID((PdpEntry & PageMask) + 8 * PdIndex), &PdEntry, sizeof(PdEntry), &ReadSize);
    if (~PdEntry & 1)
        return 0;

    if (PdEntry & 0x80)
        return (PdEntry & (~0ull << 42 >> 12)) + (VirtualAddress & ~(~0ull << 30));

    UINT64 PtEntry = 0;
    ReadPhysicalMemory(PVOID((PdEntry & PageMask) + 8 * PtIndex), &PtEntry, sizeof(PtEntry), &ReadSize);
    if (~PtEntry & 1)
        return 0;

    if (PtEntry & 0x80)
        return (PtEntry & PageMask) + (VirtualAddress & ~(~0ull << 21));

    VirtualAddress = 0;
    ReadPhysicalMemory(PVOID((PtEntry & PageMask) + 8 * PteIndex), &VirtualAddress, sizeof(VirtualAddress), &ReadSize);
    VirtualAddress &= PageMask;

    if (!VirtualAddress)
        return 0;

    return VirtualAddress + PageOffset;
}

ULONG64 FindMin(INT32 A, SIZE_T B) {
    INT32 BInt = (INT32)B;
    return (((A) < (BInt)) ? (A) : (BInt));
}

NTSTATUS HandleReadRequest(pr Request) {
    if (!Request->ProcessId)
        return STATUS_UNSUCCESSFUL;

    PEPROCESS Process = NULL;
    PsLookupProcessByProcessId((HANDLE)Request->ProcessId, &Process);
    if (!Process)
        return STATUS_UNSUCCESSFUL;

    ULONGLONG ProcessBase = GetProcessCr3(Process);
    ObDereferenceObject(Process);

    SIZE_T Offset = NULL;
    SIZE_T TotalSize = Request->Size;

    INT64 PhysicalAddress = TranslateLinearAddress(ProcessBase, (ULONG64)Request->Address + Offset);
    if (!PhysicalAddress)
        return STATUS_UNSUCCESSFUL;

    ULONG64 FinalSize = FindMin(PAGE_SIZE - (PhysicalAddress & 0xFFF), TotalSize);
    SIZE_T BytesRead = NULL;

    ReadPhysicalMemory(PVOID(PhysicalAddress), (PVOID)((ULONG64)Request->Buffer + Offset), FinalSize, &BytesRead);

    return STATUS_SUCCESS;
}

NTSTATUS HandleBaseAddressRequest(pb Request) {

    if (!Request->ProcessId)
        return STATUS_UNSUCCESSFUL;

    PEPROCESS Process = NULL;
    PsLookupProcessByProcessId((HANDLE)Request->ProcessId, &Process);
    if (!Process)
        return STATUS_UNSUCCESSFUL;

    ULONGLONG ImageBase = (ULONGLONG)PsGetProcessSectionBaseAddress(Process);
    if (!ImageBase)
        return STATUS_UNSUCCESSFUL;

    RtlCopyMemory(Request->Address, &ImageBase, sizeof(ImageBase));
    ObDereferenceObject(Process);

    return STATUS_SUCCESS;
}

//VALORANT PATCH 9.09
    
auto get_system_information(const SYSTEM_INFORMATION_CLASS information_class) -> const void*
{
    unsigned long size = 32;
    char buffer[32];

    ZwQuerySystemInformation(information_class, buffer, size, &size);

    const auto info = ExAllocatePool(NonPagedPool, size);

    if (!info)
    {
        return nullptr;
    }

    if (ZwQuerySystemInformation(information_class, info, size, &size) != STATUS_SUCCESS)
    {
        ExFreePool(info);
        return nullptr;
    }

    return info;
}

auto get_kernel_module(const char* name) -> const uintptr_t
{
    const auto to_lower = [](char* string) -> const char* {
        for (char* pointer = string; *pointer != '\0'; ++pointer)
        {
            *pointer = (char)(short)tolower(*pointer);
        }

        return string;
        };

    const auto info = (PRTL_PROCESS_MODULES)get_system_information(system_module_information);

    if (!info)
    {
        return 0;
    }

    for (auto i = 0ull; i < info->number_of_modules; ++i)
    {
        const auto& module = info->modules[i];

        if (strcmp(to_lower((char*)module.full_path_name + module.offset_to_file_name), name) == 0)
        {
            const auto address = module.image_base;

            ExFreePool(info);

            return reinterpret_cast<uintptr_t> (address);
        }
    }

    ExFreePool(info);

    return 0;
}

typedef struct ShadowRegionsDataStructure
{
    uintptr_t OriginalPML4_t;
    uintptr_t ClonedPML4_t;
    uintptr_t GameCr3;
    uintptr_t ClonedCr3;
    uintptr_t FreeIndex;
} ShadowRegionsDataStructure;

// simplified decryption for non-HVCI mode; HVCI version varies a little, use the decryption routine from vgk.sys for it
auto decrypt_cloned_cr3_simplified(uintptr_t cloned_cr3) -> uintptr_t
{
    uintptr_t Last = cloned_cr3 & 0xFFFFFFFFF;
    uintptr_t FirstDigit = Last >> 32 & 0xF;
    uintptr_t LastDigit = Last & 0xF;

    FirstDigit -= 1;
    LastDigit -= 1;

    return FirstDigit << 27 | Last & 0x0FFFFFFF0 | LastDigit;
}

NTSTATUS find_pml4_base(pgr Request)
{
    auto vgk = get_kernel_module("vgk.sys");
    if (!vgk) {
        dbg("vgk not found!");
        return 0;
    }

    auto ShadowRegionsData = *(ShadowRegionsDataStructure*)(vgk + offsets::shadow_region_offset);
    if (!ShadowRegionsData.GameCr3) {
        dbg("ShadowRegionsData not found!");
        return 0;
    }

    // set read/write translation context to the decrypted cloned cr3
    context_cr3 = decrypt_cloned_cr3_simplified(ShadowRegionsData.ClonedCr3);

    auto vaBase = ShadowRegionsData.FreeIndex << 0x27;

    RtlCopyMemory(Request->guarded, &vaBase, sizeof(vaBase));

    return STATUS_SUCCESS;
}