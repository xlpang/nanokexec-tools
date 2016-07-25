/* ELF64 relocatable parser and loader, no BSS involved */

#include "elf64relocator.h"

static const char* elf_class(unsigned char code)
{
	if (code == ELFCLASS32)
		return "ELF32";
	else if (code == ELFCLASS64)
		return "ELF64";
	else
		return "Unkown";
}

static const char* elf_endian(unsigned char code)
{
	if (code == 1)
		return "little endian";
	else if (code == 2)
		return "big endian";
	else
		return "Unkown";
}

static const char* elf_abi(unsigned char code)
{
	if (code == 0)
		return "UNIX - System V";
	else if (code == 1)
		return "HP-UX operating system";
	else if (code == 255)
		return "Standalone (embedded) application";
	else
		return "Unkown";
}

static const char* elf_type(unsigned char code)
{
	if (code == 0)
		return "NONE";
	else if (code == 1)
		return "REL (Relocatable file)";
	else if (code == 2)
		return "EXEC (Executable file)";
	else if (code == 3)
		return "DYN (Shared object file)";
	else if (code == 4)
		return "CORE (Core dump file)";
	else
		return "Unkown";
}

#define NR_RELS(s) ((s)->shdr.sh_size / (s)->shdr.sh_entsize)
static void parse_elf64_rels(struct elf64_hierarchy *h, struct elf64_section *section)
{
	unsigned long entsize = section->shdr.sh_entsize;
	struct elf64_relsection *relsection;
	unsigned short i;

	relsection = &h->relsections[h->nr_relsections];
	h->nr_relsections++;

	relsection->nr_rels = NR_RELS(section);
	relsection->sh_index = section->sh_index;
	relsection->sh_info = section->shdr.sh_info;
	relsection->sh_link = section->shdr.sh_link;
	relsection->rels = malloc(relsection->nr_rels * sizeof(struct elf64_relocation));
	if (relsection->rels == NULL)
		perror_exit("[parse_elf64_rels]: malloc");

	for (i = 0; i < relsection->nr_rels; i++) {
		relsection->rels[i].rel.r_addend = 0; /* In case we have SHT_REL */
		memcpy(&relsection->rels[i].rel, section->data + i*entsize, entsize);
	}
}

static void parse_elf64_hierarchy_rels(struct elf64_hierarchy *h)
{
	unsigned short i;
	unsigned int nr_relsections = 0;

	if (h->nr_sections == 0)
		return;

	for (i = 0; i < h->nr_sections; i++) {
		if (h->sections[i].shdr.sh_type == SHT_RELA || h->sections[i].shdr.sh_type == SHT_REL)
			nr_relsections++;
	}

	h->relsections = malloc(nr_relsections * sizeof(struct elf64_relsection));
	if (h->relsections == NULL)
		perror_exit("[parse_elf64_hierarchy_rels]: malloc");

	for (i = 0; i < h->nr_sections; i++)
		if (h->sections[i].shdr.sh_type == SHT_RELA || h->sections[i].shdr.sh_type == SHT_REL)
			parse_elf64_rels(h, &h->sections[i]);
}

static unsigned short elf64_find_symtab(struct elf64_hierarchy *h)
{
	unsigned short i;

	for (i = 0; i < h->nr_sections; i++) {
		/* RELA/REL sections link to the symbol table, return the first one */
		if (h->sections[i].shdr.sh_type == SHT_RELA || h->sections[i].shdr.sh_type == SHT_REL)
			return h->sections[i].shdr.sh_link;
	}

	return 0;
}

static void parse_elf64_hierarchy_syms(struct elf64_hierarchy *h)
{
	unsigned short i;
	unsigned short sym_index;
	struct elf64_section *symtab;
	unsigned long entsize;

	if (h->nr_sections == 0)
		return;

	sym_index = elf64_find_symtab(h);
	if (sym_index == 0 || sym_index >= h->nr_sections)
		perror_exit("[parse_elf64_hierarchy_syms]: Bad symtab section index");

	symtab = &h->sections[sym_index];
	if (symtab->shdr.sh_entsize != sizeof(Elf64_Sym))
		perror_exit("[parse_elf64_hierarchy_syms]: Bad symtab sh_entsize");

	h->sym_index = sym_index;
	h->sym_link = symtab->shdr.sh_link;
	if (h->sym_link >= h->nr_sections)
		perror_exit("[parse_elf64_hierarchy_syms]: Bad symtab sh_link");

	h->nr_syms = symtab->shdr.sh_size / symtab->shdr.sh_entsize;
	h->syms = malloc(h->nr_syms * sizeof(struct elf64_symbol));
	if (h->syms == NULL)
		perror_exit("[parse_elf64_hierarchy_syms]: malloc");

	entsize = symtab->shdr.sh_entsize;
	for (i = 0; i < h->nr_syms; i++) {
		memcpy(&h->syms[i].sym, symtab->data + i*entsize, entsize);
		if (h->syms[i].sym.st_shndx >= h->nr_sections &&
			/* Speical Section index: SHN_COMMON, SHN_ABS, etc */
		    (h->syms[i].sym.st_shndx & 0xff00) != 0xff00)
			perror_exit("[parse_elf64_hierarchy_syms]: Bad sym->st_shndx");
	}
}

static void
parse_elf64_hierarchy_programs(struct elf64_hierarchy *h, const char *data, size_t len)
{
	unsigned short i;
	off_t offset;

	h->nr_programs = h->ehdr.e_phnum;
	if (h->nr_programs == 0)
		return;

	h->programs = malloc(h->nr_programs * sizeof(struct elf64_program));
	if (h->programs == NULL)
		perror_exit("[parse_elf64_hierarchy_programs] malloc");

	offset = h->ehdr.e_phoff;
	for (i = 0; i < h->nr_programs; i++) {
		memcpy(&h->programs[i].phdr, data + offset, h->ehdr.e_phentsize);
		h->programs[i].data = (char *)data + h->programs[i].phdr.p_offset;
		offset += h->ehdr.e_phentsize;
	}
}

static void
parse_elf64_hierarchy_sections(struct elf64_hierarchy *h, const char *data, size_t len)
{
	unsigned short i;
	off_t offset;

	h->nr_sections = h->ehdr.e_shnum;
	if (h->nr_sections == 0)
		return;

	h->sections = malloc(h->nr_sections * sizeof(struct elf64_section));
	if (h->sections == NULL)
		perror_exit("[parse_elf64_hierarchy_sections] malloc");

	offset = h->ehdr.e_shoff;
	for (i = 0; i < h->nr_sections; i++) {
		memcpy(&h->sections[i].shdr, data + offset, h->ehdr.e_shentsize);
		h->sections[i].data = (char *)data + h->sections[i].shdr.sh_offset;
		h->sections[i].sh_index = i;
		if (h->sections[i].shdr.sh_link >= h->nr_sections)
			perror_exit("[parse_elf64_hierarchy_sections] Bad shdr.sh_link");
		if (h->sections[i].shdr.sh_info >= h->nr_sections &&
		    h->sections[i].shdr.sh_type != SHT_SYMTAB && /* sh_info means the number of local syms for them */
		    h->sections[i].shdr.sh_type != SHT_DYNSYM)
			perror_exit("[parse_elf64_hierarchy_sections] Bad shdr.sh_info");

		offset += h->ehdr.e_shentsize;
	}

	/* Section 0 is a special NULL section */
	h->sections[0].data = NULL;
}

static void
parse_elf64_hierarchy_elfhdr(struct elf64_hierarchy *h, const char *data, size_t len)
{
	if (len <= sizeof (Elf64_Ehdr))
		perror_exit("[parse_elf64_hierarchy_elfhdr] Target too short");

	memcpy(&h->ehdr, data, sizeof(Elf64_Ehdr));

	if (h->ehdr.e_shnum && h->ehdr.e_shentsize != sizeof(Elf64_Shdr))
		perror_exit("[parse_elf64_hierarchy_elfhdr] Bad Section header entry size");
}

void parse_elf64_hierarchy(struct elf64_hierarchy *h, const char *data, size_t len)
{
	memset(h, 0, sizeof(*h));
	parse_elf64_hierarchy_elfhdr(h, data, len);
	parse_elf64_hierarchy_programs(h, data, len);
	parse_elf64_hierarchy_sections(h, data, len);
	parse_elf64_hierarchy_syms(h);
	parse_elf64_hierarchy_rels(h);
}

static void show_elf64_ehdr(const struct elf64_hierarchy *h)
{
	int i;

	printf("\nELF Header:\n");
	printf("Magic:\t\t");
	for (i = 0; i < 16; i++)
		printf("%02x ", h->ehdr.e_ident[i]);
	printf("\n");

	printf("Class:\t\t\t\t\t%s\n", elf_class(h->ehdr.e_ident[4]));
	printf("Endian:\t\t\t\t\t%s\n", elf_endian(h->ehdr.e_ident[5]));
	printf("Version:\t\t\t\t%d\n", h->ehdr.e_ident[6]);
	printf("OS/ABI:\t\t\t\t\t%s\n", elf_abi(h->ehdr.e_ident[7]));
	printf("ABI Version:\t\t\t\t%d\n", h->ehdr.e_ident[8]);

	printf("Type:\t\t\t\t\t%s\n", elf_type(h->ehdr.e_type));
	printf("Machine:\t\t\t\t0x%x\n", h->ehdr.e_machine);
	printf("Entry point address:\t\t\t0x%lx\n", h->ehdr.e_entry);
	printf("Start of program headers:\t\t%d  (bytes into file)\n", h->ehdr.e_phoff);
	printf("Start of section headers:\t\t%d  (bytes into file)\n", h->ehdr.e_shoff);
	printf("Size of this header:\t\t\t%d (bytes)\n", h->ehdr.e_ehsize);
	printf("Size of program headers:\t\t%d (bytes)\n", h->ehdr.e_phentsize);
	printf("Number of program headers:\t\t%d\n", h->ehdr.e_phnum);
	printf("Size of section headers:\t\t%d (bytes)\n", h->ehdr.e_shentsize);
	printf("Number of section headers:\t\t%d\n", h->ehdr.e_shnum);
	printf("Section header string table index:\t%d\n", h->ehdr.e_shstrndx);
}

static char *elf64_get_section_name(const struct elf64_hierarchy *h, struct elf64_section *section)
{
	struct elf64_section *shstrtab;
	unsigned int shstrtab_offset;
	
	/* Get the section header string table, which contains section names */
	shstrtab_offset = section->shdr.sh_name;
	shstrtab = &h->sections[h->ehdr.e_shstrndx];

	return (shstrtab->data + shstrtab_offset);
}

const char *elf64_sectype_string[] = {
	"NULL",
	"PROGBITS",
	"SYMTAB",
	"STRTAB",
	"RELA",
	"HASH",
	"DYNAMIC",
	"NOTE",
	"NOBITS",
	"REL",
	"SHLIB",
	"DYNSYM"
};

static const char *elf64_get_section_type(struct elf64_section *section)
{
	unsigned int type = section->shdr.sh_type;

	if (type < ARRAY_SIZE(elf64_sectype_string))
		return elf64_sectype_string[type];

	return "Unknow";
}

const char *elf64_progtype_string[] = { 
    "NULL",
    "LOAD",
    "DYNAMIC",
    "INTERP",
    "NOTE",
    "SH_LIB",
    "PHDR",
    "TLS",
};

static const char *elf64_get_program_type(struct elf64_program *program)
{
	unsigned int type = program->phdr.p_type;

	if (type < ARRAY_SIZE(elf64_progtype_string))
		return elf64_progtype_string[type];

	return "Unknow";
}

static void show_elf64_phdr(const struct elf64_hierarchy *h)
{
	unsigned short i;

	if (h->nr_programs == 0)
		return;

	printf("\nThere are %d program headers, starting at offset 0x%x:\n",
			h->nr_programs, h->ehdr.e_phoff);

	for (i = 0; i < h->nr_programs; i++)
		printf("%s\t0x%016lx\n", elf64_get_program_type(&h->programs[i]), h->programs[i].phdr.p_offset);
}

static void show_elf64_shdr(const struct elf64_hierarchy *h)
{
	unsigned short i;

	if (h->nr_sections == 0)
		return;

	printf("\nThere are %d section headers, starting at offset 0x%x:\n",
			h->nr_sections, h->ehdr.e_shoff);

	for (i = 0; i < h->nr_sections; i++)
		printf("[ %d]\t%-20s\t%-10s\t[0x%x, 0x%x)\n", i,
				elf64_get_section_name(h, &h->sections[i]),
				elf64_get_section_type(&h->sections[i]),
				h->sections[i].shdr.sh_offset,
				h->sections[i].shdr.sh_offset+
				((h->sections[i].shdr.sh_type == SHT_NOBITS)? 0: h->sections[i].shdr.sh_size));
}

static const char *
elf64_get_symbol_name(const struct elf64_hierarchy *h, Elf64_Sym *sym)
{
	struct elf64_section *strtab = &h->sections[h->sym_link];

	if (ELF64_ST_TYPE(sym->st_info) == STT_SECTION)
		return elf64_get_section_name(h, &h->sections[sym->st_shndx]);

	if (sym->st_name < strtab->shdr.sh_size)
		return (strtab->data + sym->st_name);
	else
		return NULL;
}

const char *elf64_symtype_string[] = { 
    "NOTYPE",
    "OBJECT",
    "FUNC",
    "SECTION",
    "FILE",
};

static const char *elf64_get_sym_type(Elf64_Sym *sym)
{
    unsigned char type = ELF64_ST_TYPE(sym->st_info); 

    if (type < ARRAY_SIZE(elf64_symtype_string))
        return elf64_symtype_string[type];

    return "Unknow";
}

elf64_get_program_value(const struct elf64_section *section, unsigned long offset, unsigned long size)
{
	/* BSS */
	if (section->shdr.sh_type == SHT_NOBITS)
		return 0;

	if (size > 4)
		return *(unsigned long *)(section->data + offset);
	else if (size == 4)
		return *(unsigned int *)(section->data + offset);
	else if (size == 2)
		return *(unsigned short *)(section->data + offset);
	else if (size == 1)
		return *(unsigned char *)(section->data + offset);
	else
		return 0;
}

void elf64_get_sym_address(const struct elf64_hierarchy *h, const char *sym_name, unsigned long *retaddr)
{
	unsigned short i;

	if (h->nr_syms == 0)
		return;

	for (i = 0; i < h->nr_syms; i++) {
		if (!strcmp(elf64_get_symbol_name(h, &h->syms[i].sym), sym_name)) {
			*retaddr = (unsigned long)h->sections[h->syms[i].sym.st_shndx].data + h->syms[i].sym.st_value;
			break;
		}
	}
}

static void show_elf64_sym(const struct elf64_hierarchy *h)
{
	unsigned short i;
	unsigned long program_value;

	if (h->nr_syms == 0)
		return;

	printf("\nSymbol table '.%s' contains %d entries:\n",
		elf64_get_section_name(h, &h->sections[h->sym_index]), h->nr_syms);

	for (i = 0; i < h->nr_syms; i++) {
		program_value = 0;
		if (ELF64_ST_TYPE(h->syms[i].sym.st_info) == STT_OBJECT)
			program_value = elf64_get_program_value(&h->sections[h->syms[i].sym.st_shndx],
								h->syms[i].sym.st_value, h->syms[i].sym.st_size);

		printf("%d:\t%-15s\t0x%x\t%s\t%ld\n", i,
			elf64_get_symbol_name(h, &h->syms[i].sym),
			h->syms[i].sym.st_shndx,
			elf64_get_sym_type(&h->syms[i].sym),
			program_value);
	}
}

static void show_elf64_rel(const struct elf64_hierarchy *h)
{
	unsigned short i;

	for (i = 0; i < h->nr_relsections; i++) {
		unsigned int j;
		struct elf64_relsection *relsection;
		struct elf64_section *section;

		relsection = &h->relsections[i];
		section = &h->sections[relsection->sh_index];

		printf("\nRelocation section '%s' at offset 0x%lx contains %d entries:\n",
			elf64_get_section_name(h, section),
			section->shdr.sh_offset,
			relsection->nr_rels);

		printf("Offset\t\tInfo\t\tType\tSym.Value\t\tSym.Name + Addend\n");
		for (j = 0; j < relsection->nr_rels; j++) {
			Elf64_Rela *rel = &relsection->rels[j].rel;
			struct elf64_section *symtab = &h->sections[relsection->sh_link];
			Elf64_Sym *sym = (Elf64_Sym *)(symtab->data) + ELF64_R_SYM(rel->r_info);

			printf("%012lx\t%012lx\t%d\t%016lx\t%s %c %ld\n",
					rel->r_offset,
					rel->r_info,
					ELF64_R_TYPE(rel->r_info),
					sym->st_value,
					elf64_get_symbol_name(h, sym),
					(rel->r_addend < 0)? '-' : '+',
					(rel->r_addend < 0) ? -rel->r_addend : rel->r_addend);
		}
	}
}

void show_elf64_info(const struct elf64_hierarchy *h, enum elf64_show_type type, int extra)
{
	switch(type) {
	case ELF64_ELF_HDR:
		show_elf64_ehdr(h);
		break;
	case ELF64_PROGRAM_HDR:
		show_elf64_phdr(h);
		break;
	case ELF64_SECTION_HDR:
		show_elf64_shdr(h);
		break;
	case ELF64_SYM:
		show_elf64_sym(h);
		break;
	case ELF64_REL:
		show_elf64_rel(h);
		break;
	default:
		;
	}
}

static void relocate_elf64_rela(struct elf64_hierarchy *h, Elf64_Rela *rela,
			unsigned short sh_info, unsigned short sh_link, unsigned long offset)
{
	unsigned int type = ELF64_R_TYPE(rela->r_info);
	unsigned long target_offset = rela->r_offset;
	unsigned long S, P;
	long A;
	char *target_base; /* target section to be relocated */
	char *sym_base;
	char *target;
	struct elf64_section *symtab = &h->sections[sh_link];
	Elf64_Sym *sym = (Elf64_Sym *)(symtab->data) + ELF64_R_SYM(rela->r_info);
	
	target_base = h->sections[sh_info].data;
	
	target = target_base + target_offset;
	sym_base = h->sections[sym->st_shndx].data + offset; /* real position */

	S = (unsigned long)sym_base + sym->st_value;
	A = rela->r_addend;
	P = (unsigned long)target + offset; /* real position */

	switch(type) {
	case R_X86_64_NONE:
		break;
	case R_X86_64_64:
		*(unsigned long *)target = S + A;
		break;
	case R_X86_64_PC32:
		*(unsigned int *)target = S + A - P;
		break;
	case R_X86_64_32:
	case R_X86_64_32S:
		*(unsigned int *)target = S + A;
		if ((S + A) != *(unsigned int *)target)
			goto overflow;
		break;
	default:
		perror_exit("[relocate_elf64_rela] Unknown relocation type");
		break;
	}

	return;

overflow:
	perror_exit("[relocate_elf64_rela] Overflow");
}

static void relocate_elf64_relsection(struct elf64_hierarchy *h,
		struct elf64_relsection *relsection, unsigned long offset)
{
	unsigned short i;

	for (i = 0; i < relsection->nr_rels; i++)
		relocate_elf64_rela(h, &relsection->rels[i].rel,
			relsection->sh_info, relsection->sh_link, offset);
}

static void dump_data(unsigned char *buf, unsigned long len)
{
	unsigned long i;

	printf("\nDump data at %p:\n", buf);
	for (i = 0; i < len;) {
		printf("0x%02x, ", buf[i]);
		i++;
		if ((i % 16) == 0)
			printf("\n");
	}

	printf("\n");
}

void relocate_elf64_relocatable(struct elf64_hierarchy *h, unsigned long offset)
{
	unsigned short i;

	/* Only handle ELF64 Relocatable */
	if (h->ehdr.e_ident[4] != ELFCLASS64 || h->ehdr.e_type != 1)
		exit(-1);

	for (i = 0; i < h->nr_relsections; i++) {
		relocate_elf64_relsection(h, &h->relsections[i], offset);
	}
}

/* Return the 1st section with SHF_EXECINSTR flag */
static struct elf64_section * elf64_get_code_section(struct elf64_hierarchy *h)
{
	unsigned short i;

	for (i = 0; i < h->nr_sections; i++) {
		if (h->sections[i].shdr.sh_flags & SHF_EXECINSTR)
			return &h->sections[i];
	}

	return NULL;
}

typedef void (*FUNC_ENTRY)(void);
void run_elf64_relocatable(struct elf64_hierarchy *h, unsigned long offset) 
{
	struct elf64_section *code = elf64_get_code_section(h);

	if (code == NULL) {
		printf("[run_elf64_relocatable] Can't get the code section\n");
		return;
	}

    /* Assume the 1st code section */
    FUNC_ENTRY entry = (FUNC_ENTRY)(h->ehdr.e_entry + code->data + offset);

	//printf("run elf64_relocatable entry %p, instr data: 0x%08x\n", entry, *(unsigned long *)entry);

    //printf("\nBegin to jump to entry point: 0x%lx\n", (unsigned long)entry);
    if (entry)
		entry();
    //printf("Return from the entry point.\n");
}

