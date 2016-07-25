#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include "elf64relocator.h"

char *consume_file(const char *filename, size_t *retsize)
{
    int fd, ret;
    struct stat s;
    char *data;

    fd = open(filename, O_RDONLY);
    if (fd < 0)
        perror_exit("[consume_file] open");

    ret = fstat(fd, &s);
    if (ret < 0)
        perror_exit("[consume_file] fstat");

    *retsize = (size_t)s.st_size;
    if (*retsize > 1024*1024*10) /* max 10MB */
        *retsize = 1024*1024*10;

    /* Use mmap to gain PROT_EXEC priviledge */
    data = mmap(NULL, *retsize, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
    if (data == MAP_FAILED)
        perror_exit("[consume_file] mmap");

    ret = read(fd, data, *retsize);
    if (ret < 0)
        perror_exit("[consume_file] read");
    close(fd);

    return data;
}

int main(int argc, char **argv)
{
	struct elf64_hierarchy h;
    const char *relfile = NULL;
    size_t relsize;
    char *reldata;

    if (argc < 2) {
        relfile = "test.o"; /* Use default name */
    }

    if (relfile == NULL)
        relfile = argv[1];

    printf("filename: %s\n", relfile);
    reldata = consume_file(relfile, &relsize);
    printf("totalsize:%ld\n", relsize);

    parse_elf64_hierarchy(&h, reldata, relsize);
    relocate_elf64_relocatable(&h, 0);
    show_elf64_info(&h, ELF64_SYM, 0);
    printf("\nAfter run_elf64_relocatable, you can compare the symbol value\n");
	run_elf64_relocatable(&h, 0);
    show_elf64_info(&h, ELF64_SYM, 0);

    munmap(reldata, relsize);

    return 0;
}

