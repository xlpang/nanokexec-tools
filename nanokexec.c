/* Nano kexec only for x86_64 bzImage64: study purpose */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/reboot.h>

#include "linux_x86_boot.h"
#include "elf64relocator.h"
#include "purgatory.h"

int debug = 0;
int kdump_mode = 0;

#define dbgprintf(...) \
do { \
    if (debug) \
        fprintf(stderr, __VA_ARGS__); \
} while(0)

#define MIN(a, b) ((a)) > ((b)) ? (b) : (a)

#define PAGE_SIZE 0x1000

/* ALign with E820 type defined in the kernel */
#define MEMINFO_RAM   0
#define MEMINFO_RESERVED  1
#define MEMINFO_ACPI  2
#define MEMINFO_ACPI_NVS  3

const char *kernel_name;
char *kernel_buf; /* Real kernel data begins at kernel_buf + realmode_size */
unsigned long kernel_buf_len;

char *realmode;
unsigned long realmode_size; /* [kernel_buf, kernel_buf+realmode_size) is bootsect+setup */

const char *initrd_name;
char *initrd_buf;
unsigned long initrd_buf_len;

//#define PURGATORY_FILE
#ifdef PURGATORY_FILE
const char *purgatory_name = "./purgatory.orgin/purgatory.ro.sym";
#endif

char *purgatory_buf;
unsigned long purgatory_buf_len;

char *kexec_entry;

#define MAX_CMDLINE_LEN 2048
char cmdline_buf[MAX_CMDLINE_LEN];

struct memory_info {
	unsigned long start;
	unsigned long end;
	unsigned char type;
};

#define NR_MEMINFO_MAX	64 
struct memory_info memory_infos[NR_MEMINFO_MAX];
unsigned short nr_memory_infos;

struct kexec_segment {
	const char *buf;
	unsigned int bufsz;
	char *mem;
	unsigned int memsz;
};

#define NR_KEXEC_SEGMENT_MAX 16
struct kexec_segment segments[NR_KEXEC_SEGMENT_MAX];
unsigned short nr_segments;

/* Initialize cmdline_buf[] */
static int get_current_cmdline(void)
{
	FILE *file;
	const char *proc_name = "/proc/cmdline";

	file = fopen(proc_name, "r");
	if (file == NULL)
		return -1;

	fgets(cmdline_buf, sizeof(cmdline_buf), file);
	fclose(file);

	if (strlen(cmdline_buf) > sizeof(cmdline_buf) - 10)
		return -1;

	strcpy(cmdline_buf + strlen(cmdline_buf), " xunlei");

	return 0;
}

/* Initialize memory_infos[] */
static int get_memory_info_iomem(int kdump)
{
	FILE *file;
	const char *proc_name = "/proc/iomem";
	char tmp[128];

	nr_memory_infos = 0;

	file = fopen(proc_name, "r");
	if (file == NULL)
		return -1;

	while (fgets(tmp, sizeof(tmp), file) > 0) {
		unsigned long start, end;
		int consumed, count;
		char *desc;
		unsigned short type;

		count = sscanf(tmp, "%lx-%lx : %n", &start, &end, &consumed);
		if (count != 2)
			continue;
		desc = tmp + consumed;

		if (kdump) {
			if (memcmp(desc, "Crash kernel\n", 13) == 0) {
				type = MEMINFO_RAM;
				goto got_one;
			} else if (memcmp(desc, "ACPI Tables\n", 12) == 0) {
				type = MEMINFO_ACPI;
				goto got_one;
			} else if (memcmp(desc, "ACPI Non-volatile Storage\n", 26) == 0) {
				type = MEMINFO_ACPI_NVS;
				goto got_one;
			} else if (memcmp(desc, "reserved\n", 9) == 0) {
				type = MEMINFO_RESERVED;
				goto got_one;
			/* Backup the 640KB area for real mode */
			} else if ((memcmp(desc, "System RAM\n", 11) == 0) && (end <= 0xA0000)) {
				type = MEMINFO_RAM;
				goto got_one;
			} else {
				continue;
			}
		}

		if (memcmp(desc, "System RAM\n", 11) == 0) {
			type = MEMINFO_RAM;
		} else if (memcmp(desc, "reserved\n", 9) == 0) {
			type = MEMINFO_RESERVED;
		} else if (memcmp(desc, "ACPI Tables\n", 12) == 0) {
			type = MEMINFO_ACPI;
		} else if (memcmp(desc, "ACPI Non-volatile Storage\n", 26) == 0) {
			type = MEMINFO_ACPI_NVS;
		} else {
			continue;
		}

got_one:
		if (nr_memory_infos == ARRAY_SIZE(memory_infos)) {
			fclose(file);
			return -1;
		}

		//dbgprintf("%016lx - %016lx : %s", start, end, desc);
		memory_infos[nr_memory_infos].start = start;
		memory_infos[nr_memory_infos].end = end;
		memory_infos[nr_memory_infos].type = type;
		nr_memory_infos++;
	} /* while */

	fclose(file);

	return 0;
}

/* TODO */
int validate_kernel_bzImage64(const char *image)
{

	return 0;
}

int load_file(const char *filename, char **retbuf, unsigned long *retlen)
{
	int fd, ret;
    struct stat s;
    char *data;

    fd = open(filename, O_RDONLY);
    if (fd < 0)
		return -1;

    ret = fstat(fd, &s);
    if (ret < 0)
		return ret;
    
    data = malloc(s.st_size);
    if (data == NULL)
		return -1;

    ret = read(fd, data, s.st_size);
    if (ret < 0) {
        free(data);
		close(fd);
		return -1;
	}

	*retbuf = data;
	*retlen = s.st_size;
	dbgprintf("[load_file] address %p, size 0x%x\n", *retbuf, ret);
	close(fd);

	return 0;
}

static int create_e820_map_from_meminfo(struct x86_linux_bootparam *bootparam, struct e820entry *e820)
{
	unsigned short i;

	/* Regenerate memory_infos[] */
	if (get_memory_info_iomem(kdump_mode) < 0)
		return -1;

	bootparam->e820_map_nr = nr_memory_infos;
	for (i = 0; i < nr_memory_infos; i++) {
		e820[i].addr = memory_infos[i].start;
		e820[i].size = memory_infos[i].end - memory_infos[i].start + 1;

		switch (memory_infos[i].type) {
		case MEMINFO_RAM:
			e820[i].type = E820_RAM;
			break;
		case MEMINFO_ACPI:
			e820[i].type = E820_ACPI;
			break;
		case MEMINFO_ACPI_NVS:
			e820[i].type = E820_NVS;
			break;
		case MEMINFO_RESERVED:
			e820[i].type = E820_RESERVED;
			break;
		default:
			break;
		}

		dbgprintf("e820: %016lx-%016lx (%d)\n", e820[i].addr, e820[i].addr+e820[i].size-1, e820[i].type);

		if (memory_infos[i].type != MEMINFO_RAM)
			continue;
		if ((memory_infos[i].start <= 0x100000) && memory_infos[i].end > 0x100000) {
			unsigned long long mem_k = (memory_infos[i].end >> 10) - (0x100000 >> 10);

			bootparam->ext_mem_k = mem_k;
			bootparam->alt_mem_k = mem_k;
			if (mem_k > 0xfc00)
				bootparam->ext_mem_k = 0xfc00; /* 64M */
			if (mem_k > 0xffffffff)
				bootparam->alt_mem_k = 0xffffffff;
		}
	} /* for */

	return 0;
}

/* A simple implementation */
char* generate_kexec_segment(const char *buf, unsigned int buf_len, unsigned int mem_len, unsigned long mem_hint)
{
	short i;
	char *mem = NULL;
	unsigned int mem_len_align;

	/* Align with page */
	mem_len_align = (mem_len + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);

try_again:
	/* Alloc memory from memory_infos[], from top to down */
	for (i = nr_memory_infos - 1; i >= 0; i--) {
		unsigned long target, size;

		if (memory_infos[i].type != MEMINFO_RAM)
			continue;
		if (memory_infos[i].start > memory_infos[i].end)
			continue;
		if (mem_hint && memory_infos[i].start > mem_hint)
			continue;
		if (mem_hint && memory_infos[i].end < mem_hint)
			continue;

		target = (mem_hint != 0) ? mem_hint : memory_infos[i].start;
		size = memory_infos[i].end + 1 - target;
		if (size < mem_len_align + 2*PAGE_SIZE)
			continue;

		if (nr_memory_infos == ARRAY_SIZE(memory_infos))
			break;

		/* Simply use the range including mem_hint, expand memory_infos[] */
		memmove(memory_infos + i + 1, memory_infos + i, sizeof(memory_infos[0]) * (nr_memory_infos - i));
		memory_infos[i].end = target - 1;
		memory_infos[i+1].start = target + mem_len_align;
		nr_memory_infos++;
		mem = (char *)target;
		break;
	}

	if (mem == NULL) {
		if (mem_hint) {
			mem_hint = 0;
			goto try_again;
		} else {
			dbgprintf("generate segments mem_hint(0x%lx) failed!\n", mem_hint);
			return NULL;
		}
	}

	if (nr_segments == ARRAY_SIZE(segments))
		return NULL;

	mem = (char *) (((long)mem + PAGE_SIZE -1) & ~(PAGE_SIZE - 1));
	/* Create new segment using mem */
	segments[nr_segments].buf = buf;
	segments[nr_segments].bufsz = buf_len;
	segments[nr_segments].mem = mem;
	segments[nr_segments].memsz = mem_len_align;
	nr_segments++;

	return mem;
}

/* See kernel Documentation/x86/boot.txt */
int setup_zero_page(const char *kernel, unsigned int kernel_len,
				const char *initrd, unsigned long initrd_len,
				const char *cmdline, unsigned int cmdline_len,
				const char *purgatory, unsigned int purgatory_len)
{
	unsigned short i;
	unsigned int setup_size;
	struct x86_linux_bootparam *bootparam; /* the so-called zero page */
	/* kexeced kernel memory */
	char *realmode_kmem, *kernel_kmem, *initrd_kmem, *cmdline_kmem, *purgatory_kmem;
	unsigned long sym_addr;
	struct entry64_regs *regs64;
	struct elf64_hierarchy hierarchy;

	if (get_memory_info_iomem(kdump_mode) < 0)
		perror_exit("Parse /proc/iomem failed");

	bootparam = (struct x86_linux_bootparam *)kernel;
	setup_size = bootparam->setup_sects; /* bootsector is not included */
	if (setup_size == 0)
		setup_size = 4;

	dbgprintf("setup_size = %d, header_magic:%c%c%c%c, protocol version: 0x%04x\n",
			setup_size,
			bootparam->header_magic[0],
			bootparam->header_magic[1],
			bootparam->header_magic[2],
			bootparam->header_magic[3],
			bootparam->protocol_version);

	/* setup_sects plus the bootsector */
	realmode_size = (setup_size + 1) * 512;

	realmode = malloc(realmode_size + cmdline_len);
	memcpy(realmode, kernel, realmode_size);
	memcpy(realmode + realmode_size, cmdline, cmdline_len);

	printf("init_size=0x%lx, realmode_size=0x%lx, kernel_len=0x%lx, kernel_alignment=0x%x\n",
			bootparam->init_size, realmode_size, kernel_len - realmode_size, bootparam->kernel_alignment);

	/* Please make sure the right kexec segment order here */
	realmode_kmem = generate_kexec_segment(realmode, realmode_size + cmdline_len,
						realmode_size + cmdline_len, 0);
	if (realmode_kmem == NULL)
		return -1;

	cmdline_kmem = realmode_kmem + realmode_size;

	purgatory_kmem = generate_kexec_segment(purgatory, purgatory_len, purgatory_len, 0);
	if (purgatory_kmem == NULL)
		return -1;

	/* Must use bootparam->init_size(INIT_SIZE) for kexec memory size, which is max(VO_INIT_SIZE, ZO_INIT_SIZE). */
	kernel_kmem = generate_kexec_segment(kernel + realmode_size, kernel_len - realmode_size,
					bootparam->init_size + bootparam->kernel_alignment - 1, 0x1000000);
	if (kernel_kmem == NULL)
		return -1;

	initrd_kmem = generate_kexec_segment(initrd, initrd_len, initrd_len, 0);
	if (initrd_kmem == NULL)
		return -1;

	printf("[kexec mem] realmode: %p, purgatory: %p, kernel: %p, initrd: %p\n",
			realmode_kmem, purgatory_kmem, kernel_kmem, initrd_kmem);


	/* Now we got all the necessary data to initialize the "zero page" */
	bootparam = (struct x86_linux_bootparam *) realmode;
	bootparam->loader_type = LOADER_TYPE_KEXEC << 4;
	bootparam->loader_flags = 0;

	/* Setup ramdisk address and size */
	bootparam->initrd_start = (unsigned long)initrd_kmem & 0xffffffffUL;
	bootparam->initrd_size  = initrd_len & 0xffffffffUL;
	if (bootparam->protocol_version >= 0x020c &&
	    ((unsigned long)initrd_kmem & 0xffffffffUL) != (unsigned long)initrd_kmem)
		bootparam->ext_ramdisk_image = (unsigned long)initrd_kmem >> 32;
	if (bootparam->protocol_version >= 0x020c &&
	    (initrd_len & 0xffffffffUL) != initrd_len)
		bootparam->ext_ramdisk_size = initrd_len >> 32;

	/* Setup command line */
	if (bootparam->protocol_version >= 0x0202) {
		bootparam->cmd_line_ptr = (unsigned long)cmdline_kmem & 0xffffffffUL;
		if ((bootparam->protocol_version >= 0x020c) &&
		    (((unsigned long)cmdline_kmem & 0xffffffffUL) != (unsigned long)cmdline_kmem))
		bootparam->ext_cmd_line_ptr = (unsigned long)cmdline_kmem >> 32;
	}

	/* Setup e820 memory layout */
	if (create_e820_map_from_meminfo(bootparam, bootparam->e820_map) < 0)
		return -1;

	/* Parse and relocate purgatory - relocatable ELF64 type */
	parse_elf64_hierarchy(&hierarchy, purgatory, purgatory_len);
	/* We must do the relocation first */
	relocate_elf64_relocatable(&hierarchy, (unsigned long)(purgatory_kmem - purgatory));

	/* Update kexec entry(first purgatory, then 2nd kernel entry) to be passed to kexec syscall */
	kexec_entry = (purgatory_kmem - purgatory) + hierarchy.ehdr.e_entry + hierarchy.sections[1].data;
	printf("[kexec mem] purgatory entry: 0x%lx\n", kexec_entry);

	/* Update some purgatory symbols */
	elf64_get_sym_address(&hierarchy, "entry64_regs", &sym_addr);
	regs64 = (struct entry64_regs *)sym_addr;
	dbgprintf("before: regs64->rsi = 0x%lx\n", regs64->rsi);
	dbgprintf("before: regs64->rsp = 0x%lx\n", regs64->rsp);
	dbgprintf("before: regs64->rip = 0x%lx\n", regs64->rip);
    regs64->rbx = 0;           /* Bootstrap processor */
    regs64->rsi = (unsigned long)realmode_kmem;  /* Pointer to the parameters */
    regs64->rip = (unsigned long)kernel_kmem + 0x200; /* the entry point for startup_64 */
    elf64_get_sym_address(&hierarchy, "stack_end", &sym_addr); /* Stack, unused */
	regs64->rsp = sym_addr;
	regs64->rsp = regs64->rsp - (unsigned long)(purgatory - purgatory_kmem);

	elf64_get_sym_address(&hierarchy, "entry64_regs", &sym_addr);
	regs64 = (struct entry64_regs *)sym_addr;
	dbgprintf("after: regs64->rsi = 0x%lx\n", regs64->rsi);
	dbgprintf("after: regs64->rsp = 0x%lx\n", regs64->rsp);
	dbgprintf("after: regs64->rip = 0x%lx\n", regs64->rip);

#if 0
	purgatory_kmem = mmap((char *)0x40000000, purgatory_len, 
				PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
	if (purgatory_kmem == MAP_FAILED)
		return -1;

	printf("purgatory_kmem: %p\n", purgatory_kmem);
	memcpy(purgatory_kmem, purgatory, purgatory_len);
	parse_elf64_hierarchy(&hierarchy, purgatory_kmem, purgatory_len);
	//run_elf64_relocatable(&hierarchy, (unsigned long)hierarchy.sections[1].data);
	relocate_elf64_relocatable(&hierarchy, 0);
	//show_elf64_info(&hierarchy, ELF64_SYM, 0);
    /* Already relocated, can be run directly */
	run_elf64_relocatable(&hierarchy, 0);
#endif

	return 0;
}

#define __NR_kexec_load	246
#define KEXEC_ARCH_X86_64	(62 << 16)
#define KEXEC_ON_CRASH      0x00000001
static inline long kexec_load(void *entry, unsigned long nr_segments,
            struct kexec_segment *segments)
{
	unsigned short i;
	unsigned long flags;

	for (i = 0; i < nr_segments; i++) {
		dbgprintf("0x%016lx - 0x%x\t->  0x%016lx - 0x%x\n",
					(unsigned long)segments[i].buf, segments[i].bufsz,
					(unsigned long)segments[i].mem, segments[i].memsz);
	}

	flags = KEXEC_ARCH_X86_64;
	if (kdump_mode)
		flags |= KEXEC_ON_CRASH;

    return (long) syscall(__NR_kexec_load, entry, nr_segments, segments, flags);
}

void free_resources(void)
{
	free(kernel_buf);
	free(initrd_buf);
#ifdef PURGATORY_FILE
	free(purgatory_buf);
#endif
}

#define LINUX_REBOOT_KEXEC	0x45584543

int main(int argc, char *argv[])
{
	int has_cmdline = 0, reboot_exec = 0;
	int opt;
	int ret;

	while ((opt = getopt(argc, argv, "p:l:i:c:de")) != -1) {
		switch (opt) {
		case 'p':
			kdump_mode = 1;
		case 'l':
			kernel_name = optarg;
			break;
		case 'i':
			initrd_name = optarg;
			break;
		case 'c':
			strncpy(cmdline_buf, optarg, MIN(sizeof(cmdline_buf), strlen(optarg)));
			has_cmdline = 1;
			break;
		case 'd':
			debug = 1;
			break;
		case 'e':
			reboot_exec = 1;
			break;
		default: /* '?' */
			fprintf(stderr, "Usage: %s -l <kernel> -i <initrd> -c <cmdline> [-d]\n", argv[0]);
			fprintf(stderr, "Usage: %s -e\n", argv[0]);
			exit(-1);
		}
	}

	if (kdump_mode) {
		FILE *file;
		const char *crashsize_file = "/sys/kernel/kexec_crash_size";
		char tmpbuf[20];
		unsigned long crashsize;

		file = fopen(crashsize_file, "r");
		if (file == NULL) {
			printf("Can't open /sys/kernel/kexec_crash_size\n");
			return -1;
		}

		fgets(tmpbuf, sizeof(tmpbuf), file);
		fclose(file);
		crashsize = atol(tmpbuf);
		if (crashsize == 0) {
			perror_exit("kdump mode specified, but no reserved memory");
		}
	}

	if (reboot_exec) {
		reboot(LINUX_REBOOT_KEXEC);
		printf("kexec -e failed! Please load something beforehand.\n");
		return -1;
	}

	if (kernel_name == NULL || initrd_name == NULL)
		perror_exit("Please specify bzImage and initrd to be loaded");

	/* Get /proc/cmdline as the default command line */
	if (!has_cmdline && get_current_cmdline() < 0)
		perror_exit("get_current_cmdline failed");

	printf("kernel: %s\ninitrd: %s\ncmdline: %s\n", kernel_name, initrd_name, cmdline_buf);

	if (validate_kernel_bzImage64(kernel_name) < 0)
		perror_exit("Not a valid bzImage64");

	if (load_file(kernel_name, &kernel_buf, &kernel_buf_len) < 0)
		perror_exit("load kernel image failed");
	if (load_file(initrd_name, &initrd_buf, &initrd_buf_len) < 0)
		perror_exit("load initrd failed");

#ifdef PURGATORY_FILE
	if (load_file(purgatory_name, &purgatory_buf, &purgatory_buf_len) < 0)
		perror_exit("load purgatory failed");
#else
	purgatory_buf = purgatory;
	purgatory_buf_len = purgatory_size;
#endif

	/* Generate kexec segments and setup zero pange */
	if (setup_zero_page(kernel_buf, kernel_buf_len, initrd_buf, initrd_buf_len,
			cmdline_buf, strlen(cmdline_buf), purgatory_buf, purgatory_buf_len) < 0)
		perror_exit("setup zero page failed");

	/* Make kexec syscall */
	ret = kexec_load(kexec_entry, nr_segments, segments);
	if (ret != 0)
		perror_exit("kexec_load syscall failed");
	else
		dbgprintf("kexec_load syscall success.\n");

	free_resources();

	return 0;
}

