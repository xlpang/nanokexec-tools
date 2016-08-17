# nanokexec-tools
Simple kexec on 64-bit x86 Linux platform at the first stage of this project, named "nanokexec".
Support ELF64 bzImage initially.

# Usage
- kexec function
[Step 1] Load new kernel, initrd and command line: "nanokexec -l kernel-image -i initrd [-c cmdline] [-d]".

[Step 2] Execute nanokexec to boot the loaded kernel: "nanokexec -e".

- kdump function (Using kernel command line "crashkernel=XXX" to reserve some memory beforehand)
[Step 1] Load new kernel, initrd and command line: "nanokexec -p kernel-image -i initrd [-c cmdline] [-d]".

[Step 2] Execute nanokexec to boot the loaded kernel: "echo c > /proc/sysrq-trigger".
