#include "SelfInjectPE.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

#pragma section(".lol", read, write)
__declspec(allocate(".lol")) volatile char padding[0x2F7D000] = { 1 };

static constexpr DWORD kTrampolineFuncMaxSize = 0x4000;

static std::vector<uint8_t> readFile(const char* path) {
    FILE* f = nullptr;
    fopen_s(&f, path, "rb");
    if (!f) return {};

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (size <= 0) { fclose(f); return {}; }

    std::vector<uint8_t> buf(static_cast<size_t>(size));
    fread(buf.data(), 1, buf.size(), f);
    fclose(f);
    return buf;
}

int main(int argc, char* argv[])
{
    printf("=== SelfInjectPE Demo ===\n\n");

    const char* pePath = (argc >= 2) ? argv[1] : "target.exe";
    printf("[1/5] Loading PE file: %s\n", pePath);

    const auto peData = readFile(pePath);
    if (peData.empty()) {
        printf("FATAL: Failed to read PE file '%s'\n", pePath);
        return -1;
    }
    printf("       Read %zu bytes\n", peData.size());

    // Parse PE headers
    printf("[2/5] Parsing PE headers...\n");

    if (peData.size() < sizeof(IMAGE_DOS_HEADER)) {
        printf("FATAL: PE data too small\n");
        return -1;
    }

    const auto* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(peData.data());
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("FATAL: Invalid DOS signature (0x%04X)\n", dosHeader->e_magic);
        return -1;
    }

    const auto* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(
        peData.data() + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        printf("FATAL: Invalid NT signature (0x%08X)\n",
            static_cast<unsigned>(ntHeaders->Signature));
        return -1;
    }

    if (ntHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) {
        printf("FATAL: PE is not 32-bit x86 (Machine=0x%04X)\n",
            ntHeaders->FileHeader.Machine);
        return -1;
    }

    DWORD imageSize     = ntHeaders->OptionalHeader.SizeOfImage;
    DWORD sizeOfHeaders = ntHeaders->OptionalHeader.SizeOfHeaders;
    DWORD entryPointRVA = ntHeaders->OptionalHeader.AddressOfEntryPoint;
    WORD  numSections   = ntHeaders->FileHeader.NumberOfSections;
    DWORD preferredBase = ntHeaders->OptionalHeader.ImageBase;

    if (numSections > 64) {
        printf("FATAL: Too many sections (%u)\n", numSections);
        return -1;
    }

    printf("       ImageBase=0x%08X  SizeOfImage=0x%08X\n",
        preferredBase, imageSize);
    printf("       EntryRVA=0x%08X   Sections=%u\n",
        entryPointRVA, numSections);

    // Calculate TrampolineFunc size using marker
    printf("[3/5] Calculating trampoline size...\n");

    const uint8_t* funcStart = reinterpret_cast<const uint8_t*>(&TrampolineFunc);
    const uint8_t* funcEnd   = reinterpret_cast<const uint8_t*>(&TrampolineFuncEnd);
    DWORD trampolineFuncSize = static_cast<DWORD>(funcEnd - funcStart);

    if (trampolineFuncSize == 0 || trampolineFuncSize > kTrampolineFuncMaxSize) {
        printf("WARNING: TrampolineFunc size = 0x%X, clamping to 0x%X\n",
            trampolineFuncSize, kTrampolineFuncMaxSize);
        trampolineFuncSize = kTrampolineFuncMaxSize;
    }

    DWORD codeRegionSize = (trampolineFuncSize + 0xFFF) & ~0xFFF;
    printf("       TrampolineFunc: 0x%X bytes (rounded to 0x%X)\n",
        trampolineFuncSize, codeRegionSize);

    // Allocate trampoline memory
    printf("[4/5] Allocating trampoline memory...\n");

    DWORD dataSize  = static_cast<DWORD>(
        offsetof(TrampolineData, peDataCopy) + peData.size());
    DWORD totalSize = codeRegionSize + dataSize;

    uint8_t* trampolineMem = reinterpret_cast<uint8_t*>(
        VirtualAlloc(NULL, totalSize, MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE));

    if (!trampolineMem) {
        printf("FATAL: VirtualAlloc failed (error %lu)\n", GetLastError());
        return -1;
    }

    printf("       Allocated at 0x%08X  total=0x%X\n",
        static_cast<unsigned>(reinterpret_cast<uintptr_t>(trampolineMem)),
        totalSize);

    std::memcpy(trampolineMem, funcStart, trampolineFuncSize);

    // Fill TrampolineData
    TrampolineData* td = reinterpret_cast<TrampolineData*>(
        trampolineMem + codeRegionSize);

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    HMODULE hNtdll    = GetModuleHandleA("ntdll.dll");

    if (!hKernel32 || !hNtdll) {
        printf("FATAL: Failed to get module handles\n");
        return -1;
    }

    td->pVirtualProtect = reinterpret_cast<decltype(td->pVirtualProtect)>(
        GetProcAddress(hKernel32, "VirtualProtect"));
    td->pLoadLibraryA = reinterpret_cast<decltype(td->pLoadLibraryA)>(
        GetProcAddress(hKernel32, "LoadLibraryA"));
    td->pGetProcAddress = reinterpret_cast<decltype(td->pGetProcAddress)>(
        GetProcAddress(hKernel32, "GetProcAddress"));
    td->pOutputDebugStringA = reinterpret_cast<decltype(td->pOutputDebugStringA)>(
        GetProcAddress(hKernel32, "OutputDebugStringA"));
    td->pRtlZeroMemory = reinterpret_cast<decltype(td->pRtlZeroMemory)>(
        GetProcAddress(hNtdll, "RtlZeroMemory"));
    td->pRtlMoveMemory = reinterpret_cast<decltype(td->pRtlMoveMemory)>(
        GetProcAddress(hNtdll, "RtlMoveMemory"));

    td->targetBase    = reinterpret_cast<uint8_t*>(preferredBase);
    td->imageSize     = imageSize;
    td->sizeOfHeaders = sizeOfHeaders;
    td->entryPointRVA = entryPointRVA;
    td->numSections   = static_cast<int>(numSections);

    const auto* section = IMAGE_FIRST_SECTION(ntHeaders);
    for (WORD i = 0; i < numSections; ++i, ++section) {
        td->sections[i].virtualAddress = section->VirtualAddress;
        td->sections[i].sizeOfRawData  = section->SizeOfRawData;
        td->sections[i].dataOffset     = section->PointerToRawData;
    }

    std::memcpy(td->peDataCopy, peData.data(), peData.size());

    // Jump to trampoline
    printf("[5/5] Jumping to trampoline... (will not return)\n");
    fflush(stdout);

    typedef void(*TrampolineFn)(TrampolineData*);
    TrampolineFn trampolineEntry = reinterpret_cast<TrampolineFn>(trampolineMem);
    trampolineEntry(td);

    return 0;
}
