nanokexec: elf64relocator.o nanokexec.o
	gcc nanokexec.o elf64relocator.o -o nanokexec

elf64relocator.o: elf64relocator.c elf64relocator.h
nanokexec.o: elf64relocator.o linux_x86_boot.h nanokexec.c purgatory.h

clean:
	rm -f elf64relocator.o nanokexec.o nanokexec
