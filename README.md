# SelfInjectPE

**A self-injection RunPE technique that executes a 32-bit PE in memory without requiring a base relocation table.**

`Windows` `x86` `C++17` `MSVC`

---

## Overview

SelfInjectPE is a proof-of-concept demonstrating a **self-injection manual mapping** technique for Windows x86. It reads a 32-bit PE file from disk, maps it into the current process at its preferred `ImageBase`, resolves imports, and transfers execution to the PE's original entry point — all without processing the `.reloc` section.

The key insight is that by compiling the loader itself at the same fixed base address (`0x00400000`) and inflating its image with a large padding section, the loader can **overwrite its own address space** with the target PE. Since the target lands at its expected `ImageBase`, every hardcoded absolute address in the PE is already correct, making base relocations entirely unnecessary. This means even PEs with stripped or absent `.reloc` sections can be loaded and executed.

> **This project is intended for educational and security research purposes only.**

---

## Key Technique: Relocation-Free PE Execution

### Why Relocations Exist

32-bit x86 compilers emit **absolute virtual addresses** for global variables, string literals, function calls, and vtable pointers. These addresses are computed assuming the PE will be loaded at its `OptionalHeader.ImageBase` (typically `0x00400000` for executables):

```asm
mov eax, dword ptr [0x0045A000]   ; global variable access
push 0x00412340                    ; string literal address
call 0x00401200                    ; direct function call
```

If the OS loads the PE at a different base address, every one of these hardcoded values must be patched. The `.reloc` section contains a table of all such fixup locations, and the loader applies a delta (`actual_base - preferred_base`) to each entry.

### How This Project Avoids Relocations

Instead of loading the target PE at an arbitrary address and fixing up references, SelfInjectPE guarantees the target is placed at **exactly** its preferred `ImageBase`:

1. The loader is linked with `/FIXED /BASE:0x400000` and ASLR disabled (`/DYNAMICBASE:NO`), so it occupies `0x00400000` at startup.
2. A ~50 MB padding section (`.lol`) inflates the loader's `SizeOfImage`, reserving enough virtual address space to accommodate any reasonably sized target PE.
3. At runtime, a position-independent trampoline copies the target PE over the loader's own image at `0x00400000`.

Since `actual_base == preferred_base`, the relocation delta is zero. No `.reloc` processing is needed — the technique works even if the target PE has no relocation table at all.

---

## How It Works

### Step 1 — Compile-Time Address Reservation

The loader binary is built with a fixed base address of `0x00400000` and contains a large initialized data section:

```cpp
#pragma section(".lol", read, write)
__declspec(allocate(".lol")) volatile char padding[0x2F7D000] = { 1 };
```

This ~50 MB array forces the linker to produce a PE whose `SizeOfImage` spans well beyond the typical target PE's footprint. The `volatile` qualifier and non-zero initializer prevent the compiler from optimizing it away or placing it in BSS.

### Step 2 — PE Loading and Validation

The target PE is read from disk (defaulting to `target.exe`). The loader validates the DOS signature (`MZ`), NT signature (`PE\0\0`), and confirms the PE is 32-bit x86 (`IMAGE_FILE_MACHINE_I386`).

### Step 3 — Trampoline Size Calculation

The trampoline function's byte size is determined at runtime using a marker technique:

```cpp
const uint8_t* funcStart = reinterpret_cast<const uint8_t*>(&TrampolineFunc);
const uint8_t* funcEnd   = reinterpret_cast<const uint8_t*>(&TrampolineFuncEnd);
DWORD trampolineFuncSize = static_cast<DWORD>(funcEnd - funcStart);
```

`TrampolineFuncEnd` is a stub function placed immediately after `TrampolineFunc` in the same translation unit. With incremental linking disabled and COMDAT folding off, MSVC lays them out sequentially, making the address difference equal to the exact code size.

### Step 4 — Trampoline Memory Allocation

A single `VirtualAlloc` call with `PAGE_EXECUTE_READWRITE` reserves a contiguous block for:

```
[ Trampoline Code | TrampolineData struct | Raw PE data copy ]
```

### Step 5 — Trampoline Preparation

The trampoline machine code is `memcpy`'d from its original location into the RWX region. The `TrampolineData` structure is populated with:

- **Pre-resolved API pointers** — `VirtualProtect`, `LoadLibraryA`, `GetProcAddress`, `RtlZeroMemory`, `RtlMoveMemory` (resolved via `GetModuleHandleA` + `GetProcAddress` against `kernel32.dll` and `ntdll.dll`)
- **PE metadata** — `ImageBase`, `SizeOfImage`, `SizeOfHeaders`, `AddressOfEntryPoint`, section table snapshot
- **Raw PE bytes** — the entire file content, stored in a flexible array member (`peDataCopy[]`)

All external dependencies are passed through this structure so the trampoline remains fully **position-independent** — it never references global variables, the IAT, or CRT functions.

### Step 6 — Execution Transfer

The loader casts the RWX region to a function pointer and calls it. **This call never returns** — the trampoline overwrites the loader's code and data, then jumps to the target PE's entry point.

### Step 7 — Trampoline: PE Mapping and Import Resolution

Inside the trampoline (running from the safe RWX region):

1. `VirtualProtect` — unlock the `0x00400000` region to `PAGE_EXECUTE_READWRITE`
2. `RtlZeroMemory` — wipe the entire image region
3. `RtlMoveMemory` — copy PE headers (DOS + NT + section table)
4. `RtlMoveMemory` — map each section to its `VirtualAddress`
5. **IAT resolution** — walk `IMAGE_DIRECTORY_ENTRY_IMPORT`, iterate each `IMAGE_IMPORT_DESCRIPTOR`, load DLLs via `LoadLibraryA`, resolve functions via `GetProcAddress` (supporting both name and ordinal imports)
6. Jump to `ImageBase + AddressOfEntryPoint`

---

## Memory Layout

```
BEFORE (loader at startup):

0x00400000  ┌────────────────────────────┐
            │  Loader .text              │  Code
            │  Loader .rdata / .data     │  Data
            │  Loader .lol (~50 MB)      │  Padding (address reservation)
            └────────────────────────────┘

0x????????  ┌────────────────────────────┐  VirtualAlloc RWX
            │  TrampolineFunc (copied)   │  Position-independent code
            ├────────────────────────────┤
            │  TrampolineData            │  API pointers + PE metadata
            │  peDataCopy[]              │  Full raw PE file
            └────────────────────────────┘

─── Trampoline executes ───────────────────────────────────────

AFTER (target PE mapped):

0x00400000  ┌────────────────────────────┐
            │  Target PE .text           │  New code
            │  Target PE .rdata / .data  │  New data (IAT resolved)
            │  Target PE .rsrc / ...     │  Resources, etc.
            └────────────────────────────┘
            EIP → Target EntryPoint

0x????????  ┌────────────────────────────┐  (still allocated)
            │  TrampolineFunc            │
            ├────────────────────────────┤
            │  TrampolineData + PE copy  │
            └────────────────────────────┘
```

---

## Project Structure

| File | Description |
|---|---|
| `main.cpp` | Entry point — reads the PE file, parses headers, allocates and populates the trampoline, transfers execution |
| `TrampolineFunc.cpp` | Position-independent PE mapper — maps sections, resolves imports, jumps to entry point. Compiled with all compiler security features disabled to ensure PIC correctness |
| `SelfInjectPE.h` | Defines the `TrampolineData` structure (API pointers, PE parameters, section table, flexible array for raw PE data) and function declarations |
| `SelfInjectPE.sln` | Visual Studio 2022 solution file |
| `SelfInjectPE.vcxproj` | MSBuild project with custom per-file compiler settings |

---

## Building

### Requirements

- **Visual Studio 2022** (or any version with MSVC toolset v143)
- **Platform:** Win32 (x86) — this project does not support x64
- **C++ Standard:** C++17
- **Windows SDK:** 10.0

### Critical Build Settings

These settings are already configured in the `.vcxproj` and are essential for correct operation:

**Linker (all configurations):**

| Setting | Value | Purpose |
|---|---|---|
| `RandomizedBaseAddress` | `false` | Disable ASLR (`/DYNAMICBASE:NO`) |
| `FixedBaseAddress` | `true` | Enable `/FIXED` |
| `BaseAddress` | `0x400000` | Match the target PE's preferred `ImageBase` |
| `AdditionalOptions` | `/INCREMENTAL:NO` | Prevent incremental linking (required for trampoline size calculation) |

**Linker (Release only):**

| Setting | Value | Purpose |
|---|---|---|
| `UACExecutionLevel` | `RequireAdministrator` | Elevated privileges for `VirtualProtect` on image base |

**Compiler — `TrampolineFunc.cpp` only (both configurations):**

| Setting | Value | Purpose |
|---|---|---|
| `BufferSecurityCheck` | `false` | Disable `/GS` — security cookie lives in the original image |
| `SDLCheck` | `false` | Disable SDL checks |
| `BasicRuntimeChecks` | `Default` | Disable `/RTC` — runtime check helpers live in the original image |
| `Optimization` | `Disabled` | Prevent inlining, reordering, and external references |

Additionally, `TrampolineFunc.cpp` uses pragma directives to suppress stack probing (`check_stack`), strict GS checks, and runtime checks at the source level.

### Build Steps

1. Open `SelfInjectPE.sln` in Visual Studio
2. Select **Release | Win32**
3. Build the solution (`Ctrl+Shift+B`)

---

## Usage

```
SelfInjectPE.exe [path-to-pe]
```

| Argument | Description |
|---|---|
| `path-to-pe` | Path to a 32-bit x86 PE executable. Defaults to `target.exe` in the current directory if omitted. |

**Example:**

```
SelfInjectPE.exe myapp.exe
```

The loader will print a step-by-step log to stdout before transferring execution to the target PE.

---

## Limitations

- **32-bit x86 only** — the technique relies on fixed `ImageBase` semantics specific to 32-bit PEs
- **No base relocation processing** — by design; the target PE must be loadable at `0x00400000`
- **No TLS callback support** — Thread Local Storage callbacks are not invoked
- **No delay-load import resolution** — only standard imports (`IMAGE_DIRECTORY_ENTRY_IMPORT`) are processed
- **No section permission enforcement** — all sections are mapped as RWX
- **Maximum 64 sections** — hardcoded limit in `TrampolineData::sections[]`
- **Target `SizeOfImage` must fit within the padding** — the `.lol` section reserves ~50 MB; larger PEs require increasing the padding array size

---

## Disclaimer

This project is provided **strictly for educational and security research purposes**. It demonstrates low-level Windows PE loading internals and position-independent code techniques. The author assumes no responsibility for misuse. Always comply with applicable laws and regulations.
