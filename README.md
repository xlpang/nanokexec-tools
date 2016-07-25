# nanokexec-tools
Simple kexec on 64-bit x86 Linux platform at the first stage of this project, named "nanokexec".
Support ELF64 bzImage initially.

# Usage
[Step 1] Load new kernel, initrd and command line: "nanokexec -l kernel-image -i initrd [-c cmdline] [-d]".

[Step 2] Execute nanokexec to boot the loaded kernel: "nanokexec -e".
