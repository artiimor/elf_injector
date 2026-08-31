#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stddef.h>
#include <elf.h>

void print_ehdr(Elf64_Ehdr ehdr);
void print_ph(FILE *f, Elf64_Ehdr ehdr); 
void print_sh(FILE *f, Elf64_Ehdr ehdr);
char *parse_e_type(uint16_t e_type);
char *machine_name(uint16_t machine);
void obtain_last_load_data(FILE *f, Elf64_Ehdr ehdr, uint64_t *vaddr_last_load, uint64_t *memsz_last_load, uint64_t *p_align);
FILE *copy_elf_file(FILE *source_file, char *destination_file_name);
int patch_entry(FILE *new_file, uint64_t new_vaddr);
static uint64_t align_offset(FILE *out, uint64_t new_vaddr, uint64_t page);
int add_load_phdr(FILE *out, Elf64_Ehdr eh,
                  Elf64_Phdr *old, int nold,
                  uint64_t new_vaddr, uint64_t page);
static const char *seg_type_name(uint32_t type);
static void print_flags(uint32_t flags, char *out);

static uint8_t injected_payload[] = {
    /* 0*/ 0x50,0x51,0x52,0x56,0x57,0x41,0x50,0x41,0x51,
    /* 9*/ 0x48,0x8d,0x35,0x2c,0x00,0x00,0x00,
    /*16*/ 0x48,0xc7,0xc7,0x01,0x00,0x00,0x00,
    /*23*/ 0x48,0xc7,0xc2,0x21,0x00,0x00,0x00,
    /*30*/ 0x48,0xc7,0xc0,0x01,0x00,0x00,0x00,
    /*37*/ 0x0f,0x05,
    /*39*/ 0x41,0x59,0x41,0x58,0x5f,0x5e,0x5a,0x59,0x58,
    /*48*/ 0x48,0xb8,
    /*50*/ 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, /* ← memcpy aquí */
    /*58*/ 0xff,0xe0,
    /*60*/ '>','>','>',' ','C','o','d','i','g','o',' ',
           'i','n','y','e','c','t','a','d','o',' ','a','l',' ',
           'a','r','r','a','n','c','a','r','\n'
};

struct inject_off {
  uint64_t table_off;   /* e_phoff / p_offset del LOAD nuevo */
  uint64_t payload_off; /* donde están las instrucciones */
};

#define OFF_OLD_ENTRY 50   /* primer byte del inmediato de 8 */

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

  // TODO to check if the binary if 64 bits
  Elf64_Ehdr ehdr;
  if(fread(&ehdr, 1, sizeof(ehdr), f) != sizeof(ehdr)) {
    printf("Error. Could not read the headers\n");
    fclose(f);
    return 1;
  }

  // print_ehdr(ehdr);
  // print_ph(f, ehdr); // Program headers
  // print_sh(f, ehdr); // Section headers

  // Obtaining useful data
  // e_entry
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

  uint64_t new_vaddr;
  if (max_end % p_align == 0) {
    new_vaddr = max_end;
  } else {
    new_vaddr = max_end + p_align - (max_end % p_align);
  }

  printf("old_entry => 0x%lx\n", old_entry);
  printf("max_end => 0x%lx\n", max_end);
  printf("new_vaddr => 0x%lx\n", new_vaddr);

  Elf64_Phdr *old = malloc((size_t)ehdr.e_phnum * sizeof(*old));
  fseek(f, (long)ehdr.e_phoff, SEEK_SET);
  fread(old, sizeof(*old), ehdr.e_phnum, f);

  // ehdr.e_entry = new_vaddr;

  FILE *new_file = copy_elf_file(f, "new_elf_file");
  if (!new_file)
      return 1;

  if (add_load_phdr(new_file, ehdr, old, ehdr.e_phnum, new_vaddr, p_align) != 0) {
    printf("Error adding PT_LOAD\n");
    return 1;
  }


  free(old);
  fclose(f);
  fclose(new_file);
  return 0;
}

void print_ehdr(Elf64_Ehdr ehdr) {
  char *parsed_e_type = parse_e_type(ehdr.e_type);
  char *parsed_machine_name = machine_name(ehdr.e_machine);

  printf("I need to see the headers\n");
  printf("e_ident => %s\n", ehdr.e_ident);
  printf("e_type => %s\n", parsed_e_type);
  printf("Machine => %s\n", parsed_machine_name);
  printf("Version => 0x%x\n", ehdr.e_version);
  printf("Entry point access => 0x%lx\n", ehdr.e_entry); // e_entry
  printf("Start of program headers => %ld bytes\n", ehdr.e_phoff);
  printf("Start of section headers => %ld bytes\n", ehdr.e_shoff);
  printf("Flags => 0x%x\n", ehdr.e_flags);
  // Debe ser igual que sizeof(Elf64_Shdr)
  printf("size of elf header => %d bytes\n", ehdr.e_ehsize);
  printf("number of program headers => %d\n", ehdr.e_phnum);
  printf("number of section headers => %d\n", ehdr.e_shnum);
  printf("offset of the headers table => %ld bytes\n", ehdr.e_shoff);
}

void print_ph(FILE *f, Elf64_Ehdr ehdr) {
  fseek(f, (long)ehdr.e_phoff, SEEK_SET);
  printf("======PROGRAM HEADERS======\n");
  for (int i = 0; i < (long)ehdr.e_phnum; i++){
    Elf64_Phdr ph;
    if (fread(&ph, 1, sizeof(ph), f) != sizeof(ph)) break;
    char flags[4];
    print_flags(ph.p_flags, flags);
    printf("[%2d] %-13s vaddr=0x%-10lx offset=0x%-10lx filesz=0x%-8lx memsz=0x%-8lx flags=%s\n",
           i, seg_type_name(ph.p_type),
           (unsigned long)ph.p_vaddr,
           (unsigned long)ph.p_offset,
           (unsigned long)ph.p_filesz,
           (unsigned long)ph.p_memsz,
           flags);
  }
  printf("\n\n");
}

void print_sh(FILE *f, Elf64_Ehdr ehdr) {
  Elf64_Shdr shstrtab_hdr; // section names dict. Has a size and we can be reading it...
  fseek(f, (long)(ehdr.e_shoff + (uint64_t)ehdr.e_shstrndx * sizeof(Elf64_Shdr)), SEEK_SET);
  fread(&shstrtab_hdr, 1, sizeof(shstrtab_hdr), f);

  char *shstrtab = malloc(shstrtab_hdr.sh_size);
  fseek(f, (long)shstrtab_hdr.sh_offset, SEEK_SET);
  fread(shstrtab, 1, shstrtab_hdr.sh_size, f);

  // Once we have the names dict we can start iterating it.
  fseek(f, (long)ehdr.e_shoff, SEEK_SET);
  printf("======SECTION HEADERS======\n");
  for(int i = 0; i < ehdr.e_shnum; i++) {
    Elf64_Shdr section_header;
    if (fread(&section_header, 1, ehdr.e_ehsize, f) != ehdr.e_ehsize) break;

    printf("[%2d] %-20s addr=0x%-10lx size=%-8lu\n",
               i, shstrtab + section_header.sh_name,
               (unsigned long)section_header.sh_addr,
               (unsigned long)section_header.sh_size);
  }

  free(shstrtab);
}

char *parse_e_type(uint16_t e_type) {
  char* parsed_e_type;

  switch(e_type) {
    case ET_EXEC : parsed_e_type = "EXEC (Statis executable)"; break;
    case ET_DYN : parsed_e_type = "DYN (Position-Independent Executable file)"; break;
    case ET_REL : parsed_e_type = "REL (.o)"; break;
    case ET_CORE : parsed_e_type = "CORE core dump3"; break;
    default : parsed_e_type = "Unknown";
  }

  return parsed_e_type;
}

char *machine_name(uint16_t machine) {
  switch (machine) {
    case 0x00: return "No specific instruction set";
    case 0x01: return "AT&T WE 32100";
    case 0x02: return "SPARC";
    case 0x03: return "x86";
    case 0x04: return "Motorola 68000k (M68k)";
    case 0x05: return "Motorola 88000 (M88k)";
    case 0x06: return "Intel MCU";
    case 0x07: return "Intel 80860";
    case 0x08: return "MIPS";
    case 0x09: return "IBM_System/370";
    case 0x0A: return "MIPS RS3000 Little-endian";
    case 0x0B: return "Reserved for future use";
    case 0x0C: return "Reserved for future use";
    case 0x0D: return "Reserved for future use";
    case 0x0E: return "Hewlett-Packard PA-RISC";
    case 0x0F: return "Reserved for future use";
    case 0x13: return "Intel 80960";
    case 0x14: return "PowerPC";
    case 0x15: return "PowerPC(64-bit)";
    case 0x16: return "S390, including S390x";
    case 0x28: return "ARM (up to ARMv7/Aarch32)";
    case 0x2A: return "SuperH";
    case 0x32: return "IA-64";
    case 0x3E: return "amd64";
    case 0x8C: return "TMS320C6000 Family";
    case 0xB7: return "ARM 64-bits (ARMv8/Aarch64)";
    case 0xF3: return "RISC-V";
    case 0xF7: return "Berkeley Packet Filter";
    case 0x101: return "WDC 65C816";
  }
  return "Unknown";
}

static const char *seg_type_name(uint32_t type) {
  switch (type) {
    case PT_NULL:         return "NULL";
    case PT_LOAD:         return "LOAD";
    case PT_DYNAMIC:      return "DYNAMIC";
    case PT_INTERP:       return "INTERP";
    case PT_NOTE:         return "NOTE";
    case PT_PHDR:         return "PHDR";
    case PT_TLS:          return "TLS";
    case PT_GNU_EH_FRAME: return "GNU_EH_FRAME";
    case PT_GNU_STACK:    return "GNU_STACK";
    case PT_GNU_RELRO:    return "GNU_RELRO";
    default:              return "OTRO";
  }
}

static void print_flags(uint32_t flags, char *out) {
  out[0] = (flags & PF_R) ? 'R' : '-';
  out[1] = (flags & PF_W) ? 'W' : '-';
  out[2] = (flags & PF_X) ? 'X' : '-';
  out[3] = '\0';
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

int patch_entry(FILE *new_file, uint64_t new_vaddr)
{
  if (fseek(new_file, offsetof(Elf64_Ehdr, e_entry), SEEK_SET) != 0)
    return -1;

  if (fwrite(&new_vaddr, sizeof(new_vaddr), 1, new_file) != 1)
    return -1;

  fflush(new_file);
  return 0;
}

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
  new.p_filesz = table_size + sizeof(injected_payload);
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

  if (fwrite(old, sizeof(Elf64_Phdr), nold, out) != (size_t)nold) {
    printf("ERROR fwrite old phdrs\n");
    return -1;
  }
  if (fwrite(&new, sizeof new, 1, out) != 1) {
    printf("ERROR fwrite new\n");
    return -1;
  }

  uint64_t old_entry = eh.e_entry;
  printf("jmp a 0x%lx\n", (unsigned long)old_entry);
  memcpy(injected_payload + 50, &old_entry, 8);
  if (fwrite(injected_payload, 1, sizeof(injected_payload), out) != sizeof(injected_payload)) {
    printf("ERROR fwrite payload\n");
    return -1;
  }

  eh.e_phoff = (Elf64_Off)table_off;
  eh.e_phnum = (Elf64_Half)(nold + 1);
  eh.e_entry = new_vaddr + table_size;

  fseek(out, 0, SEEK_SET);
  if (fwrite(&eh, sizeof eh, 1, out) != 1) {
    printf("Error write ehdr");
    return -1;
  }


  return 0;
}

// Copy the P_LOADs in the bottom and we must change ph_off
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
