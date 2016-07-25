#ifndef ELF64RELOCATOR_H
#define ELF64RELOCATOR_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <elf.h>

struct elf64_relocation {
	Elf64_Rela rel; /* spec */
};

struct elf64_relsection {
	struct elf64_relocation *rels;
	unsigned short nr_rels;
	unsigned short sh_index; /* current relocation section header index */
	unsigned short sh_link;
	unsigned short sh_info;
};

struct elf64_symbol {
	Elf64_Sym sym; /* spec */
};

struct elf64_program {
	Elf64_Phdr phdr;
	char *data;
};

struct elf64_section {
	Elf64_Shdr shdr; /* spec */
	char *data;
	unsigned short sh_index; /* current section header index */
};

/* Relocatable elf64 type, same little endian. Refer to ELF64 Spec. */
struct elf64_hierarchy {
	Elf64_Ehdr ehdr; /* spec */

	struct elf64_section *sections;
	unsigned short nr_sections;

	struct elf64_program *programs;
	unsigned short nr_programs;

	/* Assuming one symbol table */
	struct elf64_symbol *syms;
	unsigned short nr_syms;
	unsigned short sym_index; /* Symbol table section index */
	unsigned short sym_link; /* String table section index */

	/* We have multiple relocation sections */
	struct elf64_relsection *relsections;
	unsigned short nr_relsections;
};

enum elf64_show_type {
	ELF64_ELF_HDR,
	ELF64_PROGRAM_HDR,
	ELF64_SECTION_HDR,
	ELF64_SYM,
	ELF64_REL,
	ELF64_SECTION_DATA
};

static void perror_exit(const char *msg)
{
    if (errno)
        perror(msg);
    else
        printf("Error: %s!\n", msg);

    exit(-1);
}

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))


void parse_elf64_hierarchy(struct elf64_hierarchy *h, const char *data, size_t len);
void relocate_elf64_relocatable(struct elf64_hierarchy *h, unsigned long offset);
void show_elf64_info(const struct elf64_hierarchy *h, enum elf64_show_type type, int extra);
void run_elf64_relocatable(struct elf64_hierarchy *h, unsigned long offset);
void elf64_get_sym_address(const struct elf64_hierarchy *h, const char *sym_name, unsigned long *retaddr);

#endif /* ELF64RELOCATOR_H */
