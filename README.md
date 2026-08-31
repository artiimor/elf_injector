# elf_injector

Little tool to inject code in ELF files with educational purposes.

## What do you need to understand

### What is an elf file?

An ELF file is an Executable and Linkable File. It's what you get when you compile a file.

If you want to generate our example ELF file just run
```
gcc -g -Wall -Wextra -pedantic -O0 -o dummy_hello_world dummy_hello_world.c
```
You will notice a new file in the folder: `dummy_hello_world`. That's our elf file and we can run it with:
```
./dummy_hello_world
```

### How does an ELF file look like?

You can view the file headers of an elf file by running
```
readelf -h dummy_hello_world
```

you will see something like:
```
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              DYN (Position-Independent Executable file)
  Machine:                           Advanced Micro Devices X86-64
  Version:                           0x1
  Entry point address:               0x1040
  Start of program headers:          64 (bytes into file)
  Start of section headers:          14832 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         15
  Size of section headers:           64 (bytes)
  Number of section headers:         37
  Section header string table index: 36
```

The most important data here is `Entry point address`, which indicates where the program starts to run.

![ELF file layout: headers on disk and how PT_LOAD segments map into process memory](images/elf-layout.svg)

Also you can see the program headers by running
```
readelf -l dummy_hello_world
```
And you will see something like:
```
Elf file type is DYN (Position-Independent Executable file)
Entry point 0x1040
There are 15 program headers, starting at offset 64

Program Headers:
  Type           Offset             VirtAddr           PhysAddr
                 FileSiz            MemSiz              Flags  Align
  PHDR           0x0000000000000040 0x0000000000000040 0x0000000000000040
                 0x0000000000000348 0x0000000000000348  R      0x8
  INTERP         0x00000000000003ac 0x00000000000003ac 0x00000000000003ac
                 0x000000000000001c 0x000000000000001c  R      0x1
      [Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]
  LOAD           0x0000000000000000 0x0000000000000000 0x0000000000000000
                 0x0000000000000638 0x0000000000000638  R      0x1000
  LOAD           0x0000000000001000 0x0000000000001000 0x0000000000001000
                 0x0000000000000165 0x0000000000000165  R E    0x1000
  LOAD           0x0000000000002000 0x0000000000002000 0x0000000000002000
                 0x00000000000001a0 0x00000000000001a0  R      0x1000
  LOAD           0x0000000000002dd0 0x0000000000003dd0 0x0000000000003dd0
                 0x0000000000000248 0x0000000000000250  RW     0x1000
  DYNAMIC        0x0000000000002de0 0x0000000000003de0 0x0000000000003de0
                 0x00000000000001e0 0x00000000000001e0  RW     0x8
  NOTE           0x0000000000000388 0x0000000000000388 0x0000000000000388
                 0x0000000000000024 0x0000000000000024  R      0x4
  NOTE           0x0000000000002140 0x0000000000002140 0x0000000000002140
                 0x0000000000000040 0x0000000000000040  R      0x8
  NOTE           0x0000000000002180 0x0000000000002180 0x0000000000002180
                 0x0000000000000020 0x0000000000000020  R      0x4
  GNU_PROPERTY   0x0000000000002140 0x0000000000002140 0x0000000000002140
                 0x0000000000000040 0x0000000000000040  R      0x8
  GNU_EH_FRAME   0x0000000000002014 0x0000000000002014 0x0000000000002014
                 0x0000000000000024 0x0000000000000024  R      0x4
  GNU_SFRAME     0x00000000000020b8 0x00000000000020b8 0x00000000000020b8
                 0x0000000000000088 0x0000000000000088  R      0x8
  GNU_STACK      0x0000000000000000 0x0000000000000000 0x0000000000000000
                 0x0000000000000000 0x0000000000000000  RW     0x10
  GNU_RELRO      0x0000000000002dd0 0x0000000000003dd0 0x0000000000003dd0
                 0x0000000000000230 0x0000000000000230  R      0x1

 Section to Segment mapping:
  Segment Sections...
   00
   01     .interp
   02     .note.gnu.build-id .interp .gnu.hash .dynsym .dynstr .gnu.version .gnu.version_r .rela.dyn .rela.plt
   03     .init .plt .text .fini
   04     .rodata .eh_frame_hdr .eh_frame .sframe .note.gnu.property .note.ABI-tag
   05     .init_array .fini_array .dynamic .got .got.plt .data .bss
   06     .dynamic
   07     .note.gnu.build-id
   08     .note.gnu.property
   09     .note.ABI-tag
   10     .note.gnu.property
   11     .eh_frame_hdr
   12     .sframe
   13
   14     .init_array .fini_array .dynamic .got
```

In the program headers section you can notice 4 params:
- Offset: Indicates the offset to the section in the ELF file
- FileSiz: Indicates the size of the section in the ELF file.
- VirtAddr: Indicates where will it be located in the virtual address.
- Memsiz: Indicates how much memory it will occupy.

Also you can check the `LOAD` sections. They are the most important. Especially the one with R E permissions, which is the one that will be executed.

We also must know that the executable PT_LOAD segment contains the program's binary code.

## How does our injector work then?

### debug functions

We have some functions like
`void print_ehdr(Elf64_Ehdr ehdr);` which prints the ehdr or file Headers.
`void print_ph(FILE *f, Elf64_Ehdr ehdr);` which prints the program headers.
`void print_sh(FILE *f, Elf64_Ehdr ehdr);` Which print the section headers.
All of them will provide the same value that readelf does.
You can read the functions to see how we obtain these values.

### How does the main program work?

First we read all the headers.

Then we obtain the last PT_LOAD data.

With that we will be able to add our new LOAD data with our code in the same ELF file!
Notice how we calculate the address of our new LOAD:
```
 uint64_t new_vaddr;
  if (max_end % p_align == 0) {
    new_vaddr = max_end;
  } else {
    new_vaddr = max_end + p_align - (max_end % p_align);
  }

```
We need to write to the next page, or the program will be broken. The page size is provided by the p_align value.

![Before/after: injecting a new PT_LOAD segment with its own program header table and payload](images/load-injection.svg)

Once we have copied the elf file (we aren't overwriting it, that would be wrong ;)) we can modify that second elf file:

#### Changing the ELF file:
Check our function:
```
int add_load_phdr(FILE *out, Elf64_Ehdr eh,
                  Elf64_Phdr *old, int nold,
                  uint64_t new_vaddr, uint64_t page)
{
  const uint64_t table_size = (uint64_t)(nold + 1) * sizeof(Elf64_Phdr);
  uint64_t table_off = align_offset(out, new_vaddr, page);

  Elf64_Phdr new = {0};
  new.p_type   = PT_LOAD;
  new.p_flags  = PF_R | PF_X;
  new.p_offset = table_off;
  new.p_vaddr  = new_vaddr;
  new.p_paddr  = new_vaddr;
  new.p_filesz = table_size + sizeof(payload);
  new.p_memsz  = new.p_filesz;
  new.p_align  = page;

  for (int i = 0; i < nold; i++) {
    if (old[i].p_type == PT_PHDR) {
      old[i].p_offset = table_off;
      old[i].p_vaddr  = new_vaddr;
      old[i].p_paddr  = new_vaddr;
      old[i].p_filesz = table_size;
      old[i].p_memsz  = table_size;
      old[i].p_align  = 8;
    }
  }

  if (fwrite(old, sizeof(Elf64_Phdr), nold, out) != (size_t)nold)
    return -1;
  if (fwrite(&new, sizeof new, 1, out) != 1)
    return -1;
  if (fwrite(payload, 1, sizeof(payload), out) != sizeof(payload))
    return -1;

  eh.e_phoff = (Elf64_Off)table_off;
  eh.e_phnum = (Elf64_Half)(nold + 1);
  eh.e_entry = new_vaddr + table_size;

  fseek(out, 0, SEEK_SET);
  if (fwrite(&eh, sizeof eh, 1, out) != 1)
    return -1;

  return 0;
}

```
The args:
- `out` the new elf file already opened.
- `eh` the values of the original header
- `old` array with the original LOADs
- `nold` number of the original LOADs
- `new_vaddr` the new virtual address free (the new page)
- `page` page size

`const uint64_t table_size = (uint64_t)(nold + 1) * sizeof(Elf64_Phdr);` => Size of the new table (nold + 1 LOADs) times the size of a LOAD.

`align_offset` goes to the end of the file and fills it with 0s until we reach a new page. `table_off` is where the new table will start.

Then we have the new LOAD section information.
```
Elf64_Phdr new = {0};
new.p_type   = PT_LOAD;
new.p_flags  = PF_R | PF_X;
new.p_offset = table_off;
new.p_vaddr  = new_vaddr;
new.p_paddr  = new_vaddr;
new.p_filesz = table_size + sizeof(payload);
new.p_memsz  = new.p_filesz;
new.p_align  = page;
```
You can see that the flags are `PF_R | PF_X` because we want to execute the injected code. It doesn't matter that the table is executable.
The offset is the one we just calculated.
`p_filesz` is the table plus the code payload.

Then we have this code:
```
if (fwrite(old, sizeof(Elf64_Phdr), nold, out) != (size_t)nold)
    return -1;
if (fwrite(&new, sizeof new, 1, out) != 1)
    return -1;
if (fwrite(payload, 1, sizeof(payload), out) != sizeof(payload))
    return -1;
```
It means that we write the old P_LOADS, the new one and the payload.
We are already at table_off because we called align_offset.

Finally we need to change some eh data:
```
eh.e_phoff = (Elf64_Off)table_off;
eh.e_phnum = (Elf64_Half)(nold + 1);
eh.e_entry = new_vaddr + table_size;
```
`e_phoff` => `position of the table in the disk`
`e_phnum` => `Our new LOAD`
`e_entry` => `Our code is just after the table.`

And then we write it.

## Sumary (Generated with AI)

### Original ELF:
DISC                                     MEMORY (Execution time)

0x0     ┌─────────────┐                  0x400000 ┌─────────────┐
        │ ELF header  │                           │ header+PHDR │  LOAD R
        │ e_phoff=0x40│────────┐                  │ INTERP…     │
        │ e_entry=    │        │         0x400040 │ PHDRs       │ ← PT_PHDR
        │   0x401050  │        │                  └─────────────┘
0x40    ├─────────────┤        │
        │ PHDRs       │◄───────┘         0x401000  ┌─────────────┐
        │  PHDR       │── apunta a 0x40 / 0x400040 │ .text       │  LOAD RX
        │  LOAD R     │                           │ _start      │ ← e_entry
        │  LOAD RX    │                           └─────────────┘
        │  LOAD RW    │
        ├─────────────┤                  0x403df8  ┌─────────────┐
        │ .text .data │                           │ .data .bss  │  LOAD RW
        └─────────────┘                           └─────────────┘

### Our copy

DISC, final opened

          padding 00 00 00 …   (para alinear offset con new_vaddr)

table_off ┌──────────────────────────────────┐
          │ PHDR                             │
          │ INTERP                           │
          │ LOAD R     (copy, same)          │
          │ LOAD RX    (copy, same)          │
          │ LOAD RW    (copy, same)          │
          │ …                                │
          │ NEW LOAD RX  ← new               │
          ├──────────────────────────────────┤
          │ 48 c7 c0 3c … 0f 05   exit(0)    │
          └──────────────────────────────────┘

The old table still here but it's not useful now.

The payload is in a new page.

### Who points to that?
ELF header (offset 0)
  e_phoff  ──────────────► table_off          (DISC: “table here”)
  e_phnum  = nold + 1
  e_entry  ──────────────► new_vaddr + table_size
                           (RAM: “start execution here!!”)

PT_PHDR (inside new Table)
  p_offset ──────────────► table_off          (DISCO)
  p_vaddr  ──────────────► new_vaddr          (RAM)
  p_filesz = table_size                       (only the table, not the payload)

LOAD nuevo (at the end of the table)
  p_offset ──────────────► table_off          (DISC: table + exit)
  p_vaddr  ──────────────► new_vaddr          (RAM)
  p_filesz = table_size + sizeof(payload)
  flags    = R X

## TODO

needs to explain the ld.so when i understand it.
