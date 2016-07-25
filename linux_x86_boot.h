#ifndef LINUX_X86_BOOT_H
#define LINUX_X86_BOOT_H

/* X86 boot zero page. Reference: kernel Documentation/x86/boot.txt. */

#define E820MAX 128
struct e820entry {
	uint64_t addr;	/* start of memory segment */
	uint64_t size;	/* size of memory segment */
	uint32_t type;		/* type of memory segment */
#define E820_RAM    1
#define E820_RESERVED   2
#define E820_ACPI   3 /* usable as RAM once ACPI tables have been read */
#define E820_NVS    4
} __attribute__((packed));

/* fixme expand on drive_info_)struct... */
struct drive_info_struct {
	uint8_t dummy[32];
};
struct sys_desc_table {
	uint16_t length;
	uint8_t  table[30];
};

struct apm_bios_info {
	uint16_t version;       /* 0x40 */
	uint16_t cseg;		/* 0x42 */
	uint32_t offset;	/* 0x44 */
	uint16_t cseg_16;	/* 0x48 */
	uint16_t dseg;		/* 0x4a */
	uint16_t flags;		/* 0x4c */
	uint16_t cseg_len;	/* 0x4e */
	uint16_t cseg_16_len;	/* 0x50 */
	uint16_t dseg_len;	/* 0x52 */
	uint8_t  reserved[44];	/* 0x54 */
};

#define EDDMAXNR    6

#define EDD_DEVICE_PARAM_SIZE 74
struct edd_info {
	uint8_t	 device;
	uint8_t  version;
	uint16_t interface_support;
	uint16_t legacy_max_cylinder;
	uint8_t  legacy_max_head;
	uint8_t  legacy_sectors_per_track;
	uint8_t  edd_device_params[EDD_DEVICE_PARAM_SIZE];
} __attribute__ ((packed));

#define EDD_MBR_SIG_MAX 16

struct x86_linux_bootparam {
	uint8_t  orig_x;			/* 0x00 */
	uint8_t  orig_y;			/* 0x01 */
	uint16_t ext_mem_k;			/* 0x02 -- ext_mem_k sits here */
	uint16_t orig_video_page;		/* 0x04 */
	uint8_t  orig_video_mode;		/* 0x06 */
	uint8_t  orig_video_cols;		/* 0x07 */
	uint16_t unused2;			/* 0x08 */
	uint16_t orig_video_ega_bx;		/* 0x0a */
	uint16_t unused3;			/* 0x0c */
	uint8_t	 orig_video_lines;		/* 0x0e */
	uint8_t	 orig_video_isvga;		/* 0x0f */
	uint16_t orig_video_points;		/* 0x10 */

	/* vesa graphic mode -- linear frame buffer */
	uint16_t lfb_width;			/* 0x12 */
	uint16_t lfb_height;			/* 0x14 */
	uint16_t lfb_depth;			/* 0x16 */
	uint32_t lfb_base;			/* 0x18 */
	uint32_t lfb_size;			/* 0x1c */
	uint16_t cl_magic;			/* 0x20 */
	uint16_t cl_offset;			/* 0x22 */
#define CL_MAGIC_VALUE 0xA33F
	uint16_t lfb_linelength;		/* 0x24 */
	uint8_t	 red_size;			/* 0x26 */
	uint8_t	 red_pos;			/* 0x27 */
	uint8_t	 green_size;			/* 0x28 */
	uint8_t	 green_pos;			/* 0x29 */
	uint8_t	 blue_size;			/* 0x2a */
	uint8_t	 blue_pos;			/* 0x2b */
	uint8_t	 rsvd_size;			/* 0x2c */
	uint8_t	 rsvd_pos;			/* 0x2d */
	uint16_t vesapm_seg;			/* 0x2e */
	uint16_t vesapm_off;			/* 0x30 */
	uint16_t pages;				/* 0x32 */
	uint8_t  reserved4[12];			/* 0x34 -- 0x3f reserved for future expansion */

	struct apm_bios_info apm_bios_info;	/* 0x40 */
	struct drive_info_struct drive_info;	/* 0x80 */
	struct sys_desc_table sys_desc_table;	/* 0xa0 */
	uint32_t ext_ramdisk_image;		/* 0xc0 */
	uint32_t ext_ramdisk_size;		/* 0xc4 */
	uint32_t ext_cmd_line_ptr;		/* 0xc8 */
	uint8_t reserved4_1[0x1c0 - 0xcc];	/* 0xe4 */
	uint8_t efi_info[32];			/* 0x1c0 */
	uint32_t alt_mem_k;			/* 0x1e0 */
	uint8_t  reserved5[4];			/* 0x1e4 */
	uint8_t  e820_map_nr;			/* 0x1e8 */
	uint8_t  eddbuf_entries;		/* 0x1e9 */
	uint8_t  edd_mbr_sig_buf_entries;	/* 0x1ea */
	uint8_t  reserved6[6];			/* 0x1eb */
	uint8_t  setup_sects;			/* 0x1f1 */
	uint16_t mount_root_rdonly;		/* 0x1f2 */
	uint16_t syssize;			/* 0x1f4 */
	uint16_t swapdev;			/* 0x1f6 */
	uint16_t ramdisk_flags;			/* 0x1f8 */
	uint16_t vid_mode;			/* 0x1fa */
	uint16_t root_dev;			/* 0x1fc */
	uint8_t  reserved9[1];			/* 0x1fe */
	uint8_t  aux_device_info;		/* 0x1ff */
	/* 2.00+ */
	uint8_t  reserved10[2];			/* 0x200 */
	uint8_t  header_magic[4];		/* 0x202 */
	uint16_t protocol_version;		/* 0x206 */
	uint16_t rmode_switch_ip;		/* 0x208 */
	uint16_t rmode_switch_cs;		/* 0x20a */
	uint8_t  reserved11[4];			/* 0x208 */
	uint8_t  loader_type;			/* 0x210 */
#define LOADER_TYPE_LOADLIN         1
#define LOADER_TYPE_BOOTSECT_LOADER 2
#define LOADER_TYPE_SYSLINUX        3
#define LOADER_TYPE_ETHERBOOT       4
#define LOADER_TYPE_KEXEC           0x0D
#define LOADER_TYPE_UNKNOWN         0xFF
	uint8_t  loader_flags;			/* 0x211 */
	uint8_t  reserved12[2];			/* 0x212 */
	uint32_t kernel_start;			/* 0x214 */
	uint32_t initrd_start;			/* 0x218 */
	uint32_t initrd_size;			/* 0x21c */
	uint8_t  reserved13[4];			/* 0x220 */
	/* 2.01+ */
	uint16_t heap_end_ptr;			/* 0x224 */
	uint8_t  reserved14[2];			/* 0x226 */
	/* 2.02+ */
	uint32_t cmd_line_ptr;			/* 0x228 */
	/* 2.03+ */
	uint32_t initrd_addr_max;		/* 0x22c */
	/* 2.04+ */
	uint32_t kernel_alignment;		/* 0x230 */
	uint8_t  relocatable_kernel;		/* 0x234 */
	uint8_t  min_alignment;			/* 0x235 */
	uint16_t xloadflags;			/* 0x236 */
	uint32_t cmdline_size;			/* 0x238 */
	uint32_t hardware_subarch;		/* 0x23c */
	uint64_t hardware_subarch_data;		/* 0x240 */
	uint32_t payload_offset;		/* 0x248 */
	uint32_t payload_length;		/* 0x24c */
	uint64_t setup_data;			/* 0x250 */
	uint64_t pref_address;			/* 0x258 */
	uint32_t init_size;			/* 0x260 */
	uint32_t handover_offset;		/* 0x264 */
	uint8_t  reserved16[0x290 - 0x268];	/* 0x268 */
	uint32_t edd_mbr_sig_buffer[EDD_MBR_SIG_MAX];	/* 0x290 */

	struct 	e820entry e820_map[E820MAX];	/* 0x2d0 */
	uint8_t _pad8[48];			/* 0xcd0 */
	struct 	edd_info eddbuf[EDDMAXNR];	/* 0xd00 */
};

#endif /* LINUX_X86_BOOT_H */
