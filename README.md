
# elf_injector

Small educational tool: inject a stub into a Linux ELF64 (x86-64) so it
runs **before** the original program, then jumps back to `_start`.

It does **not** overwrite `.text`. It appends a new `PT_LOAD` and retargets
`e_entry`.

```text
./dummy_hello_world
Hola mundo

./elf_injector dummy_hello_world
./new_elf_file
>>> Codigo inyectado al arrancar
Hola mundo
```

Works on `ET_EXEC` (`-no-pie`) and `ET_DYN` (PIE / default `gcc`).

---

## 1. What is an ELF?

ELF = *Executable and Linkable Format*. `gcc` output is an ELF.

```bash
gcc -g -Wall -Wextra -pedantic -O0 -o dummy_hello_world dummy_hello_world.c
./dummy_hello_world
```

Two views of the same file:

| On disk | In memory (when you run it) |
|---------|-----------------------------|
| Bytes with a header | The kernel `mmap`s **segments** |
| You inspect with `readelf` | Addresses may be shifted (PIE / ASLR) |

**Sections** (`.text`, `.data`, names in `readelf -S`) are for the linker
and debugger. The **kernel only loads program headers** (`readelf -l`),
especially `PT_LOAD`.

---

## 2. ELF header (`readelf -h`)

```bash
readelf -h dummy_hello_world
```

Useful fields:

| Field | Meaning |
|-------|---------|
| `Magic` `7f 45 4c 46` | `\x7fELF` |
| `Class` | ELF64 |
| `Type` | `EXEC` = fixed addresses; `DYN` = PIE |
| `Entry point address` | First instruction. Often `_start`, **not** `main` |
| `Start of program headers` | `e_phoff` (usually `64`) |
| `Number of program headers` | `e_phnum` |

On a typical PIE hello:

```text
Type:                 DYN (Position-Independent Executable file)
Entry point address:  0x1040
```

`0x1040` is an **ELF virtual address**, not necessarily the runtime
address. The kernel adds an ASLR base. Our injector also talks in ELF
vaddrs; we never bake `0x7f…` into the file.

---

## 3. Program headers (`readelf -l`)

```bash
readelf -l dummy_hello_world
```

Each line is an `Elf64_Phdr` (56 bytes). This is **not** “the number of
LOADs”. You also get `PHDR`, `INTERP`, `DYNAMIC`, `NOTE`, `GNU_STACK`…

For a `PT_LOAD`:

| Field | Meaning |
|-------|---------|
| `Offset` | Byte in the **file** |
| `FileSiz` | How many bytes to copy from the file |
| `VirtAddr` | ELF virtual address where it should appear |
| `MemSiz` | Size in RAM (`>= FileSiz`; extra bytes are zeros = `.bss`) |
| `Flags` | `R`, `W`, `E` (execute) |
| `Align` | Usually `0x1000` (page) |

Rule the kernel requires:

```text
VirtAddr % Align  ==  Offset % Align
```

`PT_LOAD` + `R E` is the executable segment (`.text`, `_start`). That is
**not** where we write the stub. We add a **new** `PT_LOAD` after every
existing mapping.

`PT_PHDR` means: “the program-header **table** lives at this offset /
vaddr”. `ld.so` uses that, not only `e_phoff` on disk. If you move the
table and forget `PT_PHDR`, you get:

```text
Inconsistency detected by ld.so: rtld.c: … l_libname failed
```

---

## 4. PIE vs `-no-pie` (why the stub is RIP-relative)

| | `gcc … -no-pie` | default `gcc` (PIE) |
|--|-----------------|---------------------|
| Type | `EXEC` | `DYN` |
| `_start` in file | e.g. `0x401050` | e.g. `0x1040` |
| `_start` at runtime | that same number | `ASLR_base + 0x1040` |

An absolute `movabs rax, 0x401050; jmp rax` dies on PIE.

The stub uses:

- `lea rsi, [rip+disp]` for the message (`write`)
- `jmp rel32` back to `_start`, with `rel32` patched at inject time

```text
rel32 = old_e_entry - (payload_vaddr + offset_after_jmp)
```

At runtime the same base is added to both sides; the distance stays valid.

---

## 5. What the injector does

We **copy** the victim (`new_elf_file`). Original file is left alone.

### 5.1 Read the victim

- `Elf64_Ehdr`
- whole program-header table into `old[]`
  (`e_phnum` entries — PHDR, INTERP, LOAD, DYNAMIC, …)
- last occupied ELF vaddr:

```text
max_end   = max(p_vaddr + p_memsz) over every PT_LOAD
new_vaddr = max_end rounded up to p_align   # next free page
```

`new_vaddr` is the **virtual** start of the new segment, not a file
offset.

### 5.2 Debug helpers

`print_ehdr` / `print_ph` / `print_sh` reprint what `readelf` shows.
Optional.

### 5.3 `add_load_phdr` — the actual patch

Arguments:

| Arg | Meaning |
|-----|---------|
| `out` | the copy, open for update |
| `eh` | original ELF header (**still** with the old `e_entry`) |
| `old` | copy of **all** original program headers |
| `nold` | `e_phnum` (not “number of LOADs”) |
| `new_vaddr` | free ELF page |
| `page` | `p_align` (usually `0x1000`) |

**Step A — pad the file**

`align_offset` seeks to EOF and writes `0x00` until

```text
file_offset % page == new_vaddr % page
```

That offset is `table_off`. It is *not* “fill a whole page every time”.
It does not write headers; it only aligns.

**Step B — describe the new LOAD**

```text
p_type   = PT_LOAD
p_flags  = R | X
p_offset = table_off          # on disk
p_vaddr  = new_vaddr          # ELF vaddr
p_filesz = table_size + payload_size
p_memsz  = p_filesz
p_align  = page
```

One segment covers **new PHDR table + stub**.

```text
table_size = (nold + 1) * sizeof(Elf64_Phdr)
```

**Step C — retarget `PT_PHDR` inside `old[]`**

```text
p_offset / p_vaddr = table_off / new_vaddr
p_filesz           = table_size     # table only, not the stub
```

So `ld.so` sees the **new** table in memory.

**Step D — write the tail of the file**

```text
[ zeros ][ old PHDRs (patched) ][ new LOAD phdr ][ payload ]
           ▲
           table_off = e_phoff
```

Original `.text` is **not** copied again. Only the 56-byte descriptors
are duplicated at the end. Old bytes stay in the middle of the file.

**Step E — patch the stub, then the ELF header**

```text
rel32 patched into jmp
eh.e_phoff  = table_off
eh.e_phnum  = nold + 1
eh.e_entry  = new_vaddr + table_size   # first byte of the stub
```

`fwrite` the header at offset `0`.

`e_entry` is **not** `new_vaddr` (that is the table). The CPU must start
on instructions, after the table.

---

## 6. Pictures

### Original

```text
FILE                                    MEMORY (example EXEC)

[ ELF hdr  e_phoff=0x40                 LOAD R    header + old PHDRs
  e_entry=_start ]                      LOAD RE   .text  ← _start
[ PHDR table @ 0x40 ]                   LOAD RW   .data
[ .text .data … ]
```

On PIE the same layout uses low vaddrs (`0x0000`, `0x1000`, …) plus ASLR.

### After inject

```text
FILE

[ ELF hdr  e_phoff=table_off
           e_entry=new_vaddr+table_size ]
[ old PHDR table @ 0x40 ]          # leftover, unused as a table
[ .text .data … ]
[ padding zeros ]
[ NEW PHDR table                    ← e_phoff, PT_PHDR
    copies of old entries
    + extra PT_LOAD ]
[ payload: write + jmp rel32 ]      ← e_entry
```

```text
MEMORY

old LOADs unchanged
new page at new_vaddr:
    [ PHDR table ][ stub ]
         ▲              ▲
      PT_PHDR / ld.so   CPU starts here, then jmp to _start
```

Who points where:

```text
e_phoff          → table_off          (file)
e_entry          → new_vaddr + table  (ELF vaddr of stub)
PT_PHDR.p_offset → table_off
PT_PHDR.p_vaddr  → new_vaddr
new LOAD         → same start, longer (table + payload)
```

You can also keep the repo diagrams:

- `images/elf-layout.svg` — headers on disk vs `PT_LOAD` in memory
- `images/load-injection.svg` — before/after the extra segment

---

## 7. Why `ld.so` needed the `PT_PHDR` patch

`execve` reads `e_phoff` from **disk** and maps every `PT_LOAD`.

Then the dynamic linker uses the aux vector:

- `AT_PHDR` ← `PT_PHDR.p_vaddr` (table **in RAM**)
- `AT_PHNUM` ← `e_phnum`

If `e_phnum` is `nold+1` but `PT_PHDR` still points at the old table
(only `nold` real entries), `ld.so` reads one extra garbage header and
aborts. Mapping the new table inside the new `PT_LOAD` and updating
`PT_PHDR` keeps disk, RAM, and `e_phnum` consistent.

---

## 8. Payload (current)

Educational stub:

1. `push` caller-saved regs (`rdx` matters for `atexit`)
2. `write(1, ">>> Codigo inyectado al arrancar\n", 33)`
3. `pop`
4. `jmp rel32` to original `e_entry` (`_start`)

Not libc. No `printf`. Runs before `main`.

---

## 9. Limits

- ELF64 x86-64 Linux only
- Needs a writable copy of the binary
- `readelf -l` will show the extra `LOAD` (not stealth)
- Re-injecting an already patched file will use the wrong `old_entry`
- IoT is often ARM64: same ELF logic, different stub bytes

---

## 10. Quick check

```bash
gcc -o dummy_hello_world dummy_hello_world.c
./elf_injector dummy_hello_world
readelf -h new_elf_file | grep Entry
readelf -l new_elf_file          # extra LOAD R E, PHDR offset near EOF
./new_elf_file
```