#pragma once

#include <Windows.h>
#include <cstdint>

// =============================================================================
//  TrampolineData -- Position-independent data block for the trampoline
// =============================================================================
//
//  The trampoline shellcode (TrampolineFunc) is copied to a freshly allocated
//  RWX region at runtime, so it can NOT use any global/static data or import
//  table entries. Every Win32 API it needs must be pre-resolved and passed
//  through this structure as raw function pointers.
//
//  Layout in memory:
//
//    [ TrampolineFunc code ][ TrampolineData (this struct) ]
//     ^-- VirtualAlloc RWX   ^-- codeRegionSize offset
//
//  The caller fills in all fields, then calls the copied TrampolineFunc with
//  a pointer to this struct.  TrampolineFunc uses only the pointers stored
//  here -- never any fixed addresses -- so it remains fully position-independent.
//
//  The flexible array member `peDataCopy[]` at the end holds the entire raw PE
//  file.  Using a flexible array member keeps everything in a single contiguous
//  allocation, avoiding an extra indirection and making the whole block trivially
//  relocatable.
// =============================================================================

struct TrampolineData {
    // --- Pre-resolved API function pointers -----------------------------------
    // These are needed because TrampolineFunc runs from arbitrary memory and
    // has no import table of its own.  Each pointer is resolved via
    // GetProcAddress before the trampoline is invoked.

    decltype(&VirtualProtect)      pVirtualProtect;
    decltype(&LoadLibraryA)        pLoadLibraryA;
    decltype(&GetProcAddress)      pGetProcAddress;
    decltype(&OutputDebugStringA)  pOutputDebugStringA;
    VOID(WINAPI* pRtlZeroMemory)(PVOID, SIZE_T);
    VOID(WINAPI* pRtlMoveMemory)(PVOID, const VOID*, SIZE_T);

    // --- Target PE mapping parameters -----------------------------------------

    uint8_t* targetBase;       // The PE's preferred ImageBase (e.g. 0x00400000)
    DWORD    imageSize;        // SizeOfImage from the NT optional header
    DWORD    sizeOfHeaders;    // SizeOfHeaders -- how many bytes to copy for headers
    DWORD    entryPointRVA;    // AddressOfEntryPoint -- RVA of the original EP

    // --- Section table snapshot -----------------------------------------------
    // Stores VirtualAddress, SizeOfRawData, and PointerToRawData for each
    // section so the trampoline can map them without re-parsing the section
    // headers.  Fixed-size array of 64 is more than enough for any real PE.

    int numSections;
    struct {
        DWORD virtualAddress;
        DWORD sizeOfRawData;
        DWORD dataOffset;      // PointerToRawData in the raw PE file
    } sections[64];

    // --- PE raw data (flexible array member, must be last) --------------------
    // The entire original PE file is copied here.  Because this member has no
    // fixed size, sizeof(TrampolineData) gives the offset of the PE data,
    // which we use with offsetof() to compute the total allocation size.

    uint8_t peDataCopy[];
};

// Trampoline entry point -- position-independent shellcode
void TrampolineFunc(const TrampolineData* d);

// Marker function immediately after TrampolineFunc in the object file.
// The difference  &TrampolineFuncEnd - &TrampolineFunc  gives the exact
// byte size of the shellcode, which the loader uses to know how many bytes
// to memcpy into the RWX region.
void TrampolineFuncEnd();
