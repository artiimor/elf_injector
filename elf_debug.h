#ifndef ELF_DEBUG_H
#define ELF_DEBUG_H

#include <stdio.h>
#include <stdint.h>
#include <elf.h>

void print_ehdr(Elf64_Ehdr ehdr);
void print_ph(FILE *f, Elf64_Ehdr ehdr);
void print_sh(FILE *f, Elf64_Ehdr ehdr);
char *parse_e_type(uint16_t e_type);
char *machine_name(uint16_t machine);

#endif
