#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stddef.h>
#include <elf.h>

#include "elf_debug.h"

// TODO pass as argvs
#define OFF_JMP_REL32 49 // SUM till 0xE9 (aka jump instruction)
#define OFF_AFTER_JMP 53  // next instruction

void obtain_last_load_data(FILE *f, Elf64_Ehdr ehdr, uint64_t *vaddr_last_load, uint64_t *memsz_last_load, uint64_t *p_align);
FILE *copy_elf_file(FILE *source_file, char *destination_file_name);
static uint64_t align_offset(FILE *out, uint64_t new_vaddr, uint64_t page);
int add_load_phdr(FILE *out, Elf64_Ehdr eh,
                  Elf64_Phdr *old, int nold,
                  uint64_t new_vaddr, uint64_t page);

/*
 * push rax
 * push rcx
 * push rdx
 * push rsi
 * push rdi
 * push r8
 * push r9
 * lea  rsi, [rip+0x25]      ; rsi = string direction
 * mov  rdi, 1               ; stdout
 * mov  rdx, 33              ; length 0x21
 * mov  rax, 1               ; syscall write
 * syscall
 * pop  r9
 * pop  r8
 * pop  rdi
 * pop  rsi
 * pop  rdx
 * pop  rcx
 * pop  rax
*/
static uint8_t injected_payload[] = {
    /*  0 */ 0x50,0x51,0x52,0x56,0x57,0x41,0x50,0x41,0x51,
    /*  9 */ 0x48,0x8d,0x35,0x25,0x00,0x00,0x00, /* lea rsi,[rip+0x25] */
    /* 16 */ 0x48,0xc7,0xc7,0x01,0x00,0x00,0x00,
    /* 23 */ 0x48,0xc7,0xc2,0x21,0x00,0x00,0x00,
    /* 30 */ 0x48,0xc7,0xc0,0x01,0x00,0x00,0x00,
    /* 37 */ 0x0f,0x05,
    /* 39 */ 0x41,0x59,0x41,0x58,0x5f,0x5e,0x5a,0x59,0x58,
    /* 48 */ 0xe9,0x00,0x00,0x00,0x00,           /* jmp rel32  ← parche */
    /* 53 */ '>','>','>',' ','C','o','d','i','g','o',' ',
             'i','n','y','e','c','t','a','d','o',' ','a','l',' ',
             'a','r','r','a','n','c','a','r','\n'
};

int main(int argc, char **argv) {
  if (argc != 2) {
    printf("Need to introduce the binary route\n");
    return 1;
  }

  FILE *f = fopen(argv[1], "rb");
  if (!f) {
    printf("error opening the binary\n");
    return 1;
  }

  // TODO adapt to other arquitectures
  Elf64_Ehdr ehdr;
  if(fread(&ehdr, 1, sizeof(ehdr), f) != sizeof(ehdr)) {
    printf("Error. Could not read the ehdr\n");
    fclose(f);
    return 1;
  }

  // Obtain old_entry, last pt load vaddr, memsz and p_align (page size)
  long old_entry = ehdr.e_entry;
  
  // max_end aka end of the last PT_LOAD
  uint64_t vaddr_last_load = 0;
  uint64_t memsz_last_load = 0;
  uint64_t p_align = 0;
  obtain_last_load_data(f, ehdr, &vaddr_last_load, &memsz_last_load, &p_align);

  if (vaddr_last_load == 0) {
    printf("ERROR could not obtain last PT_LOAD\n\n");

    fclose(f);
    return 1;
  }

  if (p_align == 0) p_align = 0x1000;
  uint64_t max_end = vaddr_last_load + memsz_last_load;

  // Calculate where the new PT_LOAD is placed (vaddr)
  uint64_t new_vaddr;
  if (max_end % p_align == 0) {
    new_vaddr = max_end;
  } else {
    new_vaddr = max_end + p_align - (max_end % p_align);
  }

  printf("old_entry => 0x%lx\n", old_entry);
  printf("max_end => 0x%lx\n", max_end);
  printf("new_vaddr => 0x%lx\n", new_vaddr);

  // Data of all program headers. PT_LOAD included
  Elf64_Phdr *old = malloc((size_t)ehdr.e_phnum * sizeof(*old));
  fseek(f, (long)ehdr.e_phoff, SEEK_SET);
  fread(old, sizeof(*old), ehdr.e_phnum, f);

  // Our new ELF file
  FILE *new_file = copy_elf_file(f, "new_elf_file");
  if (!new_file){
    free(old);
    fclose(f);
    return 1;
  }

  if (add_load_phdr(new_file, ehdr, old, ehdr.e_phnum, new_vaddr, p_align) != 0) {
    printf("Error adding PT_LOAD\n");
    free(old);
    fclose(f);
    fclose(new_file);
    return 1;
  }


  free(old);
  fclose(f);
  fclose(new_file);
  return 0;
}

void obtain_last_load_data(FILE *f, Elf64_Ehdr ehdr, uint64_t *vaddr_last_load, uint64_t *memsz_last_load, uint64_t *p_align) {
  fseek(f, (long)ehdr.e_phoff, SEEK_SET);
  for (int i = 0; i < (long)ehdr.e_phnum; i++){
    Elf64_Phdr ph;
    if (fread(&ph, 1, sizeof(ph), f) != sizeof(ph)) break;

    if (ph.p_type == PT_LOAD &&
        ph.p_vaddr > *vaddr_last_load){
      *vaddr_last_load = ph.p_vaddr;
      *memsz_last_load = ph.p_memsz;
      *p_align = ph.p_align;
    }
  }
}

FILE *copy_elf_file(FILE *source_file, char *destination_file_name){
  if(!source_file || !destination_file_name) {
    printf("ERROR in copy_elf_file\n");
    return NULL;
  }

  fseek(source_file, 0, SEEK_SET);

  FILE *new_file = fopen(destination_file_name, "wb");
  if (new_file == NULL) {
    printf("ERROR opening the file in copy_elf_file\n");
    return NULL;
  }

  int ch; 
  while ((ch = fgetc(source_file)) != EOF) {
    fputc(ch, new_file);
  }

  struct stat st;
  if (fstat(fileno(source_file), &st) == 0)
    fchmod(fileno(new_file), st.st_mode);

  rewind(new_file);
  return new_file;
}

int add_load_phdr(FILE *out, Elf64_Ehdr eh,
                  Elf64_Phdr *old, int nold,
                  uint64_t new_vaddr, uint64_t page)
{
  // table_size is our new PT_LOAD. size? All the old pt_loads plus the new one
  const uint64_t table_size = (uint64_t)(nold + 1) * sizeof(Elf64_Phdr);

  // Fill the last page with 0s and return the offset to the new last page.
  uint64_t table_off = align_offset(out, new_vaddr, page);

  // New PT_LOAD
  Elf64_Phdr new = {0};
  new.p_type   = PT_LOAD; // is a PT_LOAD
  new.p_flags  = PF_R | PF_X; // Read en Execute
  new.p_offset = table_off; // In the new page
  new.p_vaddr  = new_vaddr; // vaddr of the ELF file
  new.p_paddr  = new_vaddr; // Useless in linux
  new.p_filesz = table_size + sizeof(injected_payload); // Bytes copied from disk
  new.p_memsz  = new.p_filesz;
  new.p_align  = page; // Page size. Does not change

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

  // Copy every original byte in the output
  if (fwrite(old, sizeof(Elf64_Phdr), nold, out) != (size_t)nold) {
    printf("ERROR fwrite old phdrs\n");
    return -1;
  }

  // copy our new PT_LOAD at the end!
  if (fwrite(&new, sizeof new, 1, out) != 1) {
    printf("ERROR fwrite new\n");
    return -1;
  }

  // Copy the payload at the end of the PT_LOAD
  uint64_t old_entry = eh.e_entry;
  uint64_t payload_vaddr = new_vaddr + table_size;
  int32_t  rel32 = (int32_t)(old_entry - (payload_vaddr + OFF_AFTER_JMP));
  
  // asm magic
  memcpy(injected_payload + OFF_JMP_REL32, &rel32, 4);


  printf("old_entry=0x%lx payload=0x%lx rel32=%d\n",
       (unsigned long)old_entry, (unsigned long)payload_vaddr, rel32);

  // Finally injecting the code!
  if (fwrite(injected_payload, 1, sizeof(injected_payload), out) != sizeof(injected_payload)) {
    printf("ERROR fwrite payload\n");
    return -1;
  }

  eh.e_phoff = (Elf64_Off)table_off;
  eh.e_phnum = (Elf64_Half)(nold + 1);  // +1 header in the new ELF (out PT_LOAD)
  eh.e_entry = new_vaddr + table_size; // Here is the first instruction (Out injected code)

  // Change the header with our new info (e_entry, the loads...)
  fseek(out, 0, SEEK_SET);
  if (fwrite(&eh, sizeof eh, 1, out) != 1) {
    printf("Error write ehdr");
    return -1;
  }


  return 0;
}

// Copy the P_LOADs in the bottom of the file and return the offset.
static uint64_t align_offset(FILE *out, uint64_t new_vaddr, uint64_t page)
{
  fseek(out, 0, SEEK_END);
  uint64_t off = (uint64_t)ftell(out);
  while ((off % page) != (new_vaddr % page)) {
    fputc(0, out);
    off++;
  }
  return off;
}
