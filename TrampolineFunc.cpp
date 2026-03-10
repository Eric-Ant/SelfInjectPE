#include "SelfInjectPE.h"

#include <winternl.h>

//  #pragma optimize("", off)   -- Prevents the compiler from reordering, inlining,
//                                 or merging code.  Without this, the compiler may
//                                 merge TrampolineFunc with other functions or
//                                 eliminate the TrampolineFuncEnd marker entirely.
//
//  #pragma runtime_checks("", off) -- Disables /RTC runtime checks that insert
//                                     hidden calls to CRT helper functions (e.g.
//                                     _RTC_CheckStackVars).  Those helpers reside
//                                     at fixed addresses in the original module,
//                                     so calling them from relocated shellcode
//                                     would crash.
//
//  #pragma strict_gs_check(off)    -- Disables the stack-based buffer overrun
//  #pragma check_stack(off)           detection (/GS).  The security cookie lives
//                                     at a fixed address and the __security_check_
//                                     cookie helper is in the CRT -- both are
//                                     unreachable from copied shellcode.

#pragma optimize("", off)
#pragma runtime_checks("", off)
#pragma strict_gs_check(off)
#pragma check_stack(off)

// =============================================================================
//  TrampolineFunc -- Position-independent PE mapper
// =============================================================================
//
//  __declspec(noinline)    -- Ensures the function is not inlined into callers,
//                             so its address can be taken reliably.
//  __declspec(safebuffers) -- Tells the compiler this function manages its own
//                             buffer safety, suppressing /GS instrumentation
//                             even if the project-wide setting is on.
//
//  Execution flow:
//    1. VirtualProtect the target ImageBase region to RWX
//    2. Zero-fill the entire region
//    3. Copy PE headers from peDataCopy
//    4. Map each section to its correct VirtualAddress
//    5. Walk the Import Directory and resolve every imported function
//       via LoadLibraryA + GetProcAddress
//    6. Jump to the PE's original entry point (never returns)
// =============================================================================

__declspec(noinline, safebuffers) void TrampolineFunc(const TrampolineData* d) {
    // Step 1: Unlock the target image region so we can write to it
    DWORD old = 0;
    d->pVirtualProtect(d->targetBase, d->imageSize,
        PAGE_EXECUTE_READWRITE, &old);

    // Step 2: Wipe the region clean before mapping
    d->pRtlZeroMemory(d->targetBase, d->imageSize);

    // Step 3: Copy PE headers (DOS header + NT headers + section table)
    d->pRtlMoveMemory(d->targetBase, d->peDataCopy, d->sizeOfHeaders);

    // Step 4: Map each section to its virtual address
    for (int i = 0; i < d->numSections; i++) {
        if (d->sections[i].sizeOfRawData == 0) continue;
        d->pRtlMoveMemory(
            d->targetBase + d->sections[i].virtualAddress,
            d->peDataCopy + d->sections[i].dataOffset,
            d->sections[i].sizeOfRawData);
    }

    // Step 5: Resolve imports by walking the Import Directory
    const auto* dos = (IMAGE_DOS_HEADER*)d->targetBase;
    const auto* nt = (IMAGE_NT_HEADERS*)(d->targetBase + dos->e_lfanew);
    const auto& importDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    if (importDir.VirtualAddress && importDir.Size) {
        const auto* desc = (IMAGE_IMPORT_DESCRIPTOR*)(
            d->targetBase + importDir.VirtualAddress);

        while (desc->Name) {
            const char* dllName = (const char*)(d->targetBase + desc->Name);
            HMODULE hDll = d->pLoadLibraryA(dllName);

            if (hDll) {
                const auto* origThunk = (const IMAGE_THUNK_DATA*)(
                    d->targetBase + (desc->OriginalFirstThunk
                        ? desc->OriginalFirstThunk
                        : desc->FirstThunk));
                auto* thunk = (IMAGE_THUNK_DATA*)(
                    d->targetBase + desc->FirstThunk);

                while (origThunk->u1.AddressOfData) {
                    if (origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                        thunk->u1.Function = (uintptr_t)d->pGetProcAddress(
                            hDll, (LPCSTR)(origThunk->u1.Ordinal & 0xFFFF));
                    }
                    else {
                        const auto* named = (const IMAGE_IMPORT_BY_NAME*)(
                            d->targetBase + origThunk->u1.AddressOfData);
                        thunk->u1.Function = (uintptr_t)d->pGetProcAddress(
                            hDll, named->Name);
                    }
                    origThunk++;
                    thunk++;
                }
            }
            desc++;
        }
    }

    // Step 6: Jump to the original entry point (never returns)
    typedef void(*EntryPoint)();
    EntryPoint ep = (EntryPoint)(d->targetBase + d->entryPointRVA);
    ep();
}

// =============================================================================
//  TrampolineFuncEnd -- Marker function for size calculation
// =============================================================================
//
//  This function MUST be placed immediately after TrampolineFunc in the
//  translation unit, with no intervening functions.  The linker lays them out
//  sequentially, so:
//
//      size = (uintptr_t)&TrampolineFuncEnd - (uintptr_t)&TrampolineFunc
//
//  The single `nop` prevents the linker from discarding an empty function.
//  The same noinline + safebuffers attributes ensure the marker isn't merged
//  or reordered by the optimiser.
// =============================================================================

__declspec(noinline, safebuffers) void TrampolineFuncEnd() {
    __asm { nop }
}

#pragma check_stack()
#pragma strict_gs_check(on)
#pragma runtime_checks("", restore)
#pragma optimize("", on)
