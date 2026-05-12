#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>

/* ------------------------------------------------------------------ */
/*  Type aliases                                                       */
/* ------------------------------------------------------------------ */

#define EB_VERSION_STRING	"0.3a"

#define Elf32_Addr		uint32_t
#define Elf32_Half		uint16_t
#define Elf32_Off		uint32_t
#define Elf32_Sword		int32_t
#define Elf32_Word		uint32_t

#define Elf64_Addr		uint64_t
#define Elf64_Off		uint64_t
#define Elf64_xword		uint64_t
#define Elf64_Sxword	int64_t

/* ------------------------------------------------------------------ */
/*  ELF constants                                                      */
/* ------------------------------------------------------------------ */

/* e_ident */
#define EI_MAG0		0
#define EI_MAG1		1
#define EI_MAG2		2
#define EI_MAG3		3
#define EI_CLASS	4
#define EI_DATA		5
#define EI_VERSION	6
#define EI_OSABI	7   /* Linux ABI extension; kernel ignores on x86/amd64 */
#define EI_ABIVERSION	8   /* kernel ignores on x86/amd64 */
#define EI_PAD		9   /* true padding: bytes 9-15 */
#define EI_PADLEN	7
#define EI_NIDENT	16
#define EI_IDENT_SLACK	9   /* total usable: EI_OSABI + EI_ABIVERSION + EI_PAD */

/* e_type */
#define ET_NONE		0x0000
#define ET_REL		0x0001
#define ET_ExEC		0x0002
#define ET_DYN		0x0003
#define ET_CORE		0x0004
#define ET_LOPROC	0xFF00
#define ET_HIPROC	0xFFFF

/* e_machine */
#define EM_NONE		0
#define EM_M32		1
#define EM_SPARC	2
#define EM_386		3
#define EM_68K		4
#define EM_88K		5
#define EM_860		7
#define EM_MIPS		8
#define EM_AMD8664	0x3E

/* e_version */
#define EV_NONE		0
#define EV_CURRENT	1

/* EI_MAGx */
#define ELFMAG0		0x7F
#define ELFMAG1		0x45
#define ELFMAG2		0x4C
#define ELFMAG3		0x46
#define ELFMAG		0x7F454C46

/* EI_CLASS */
#define ELFCLASSNONE	0
#define ELFCLASS32		1
#define ELFCLASS64		2

/* EI_DATA */
#define ELFDATANONE	0
#define ELFDATA2LSB	1
#define ELFDATA2MSB	2

/* Special Section Indexes */
#define SHN_UNDEF		0x0000
#define SHN_LORESERVE	0xFF00
#define SHN_LOPROC		0xFF00
#define SHN_HIPROC		0xFF1F
#define SHN_ABS			0xFFF1
#define SHN_COMMON		0xFFF2
#define SHN_HIRESERVE	0xFFFF

/* sh_type */
#define SHT_NULL		0
#define SHT_PROGBITS	1
#define SHT_SYMTAB		2
#define SHT_STRTAB		3
#define SHT_RELA		4
#define SHT_HASH		5
#define SHT_DYNAMIC		6
#define SHT_NOTE		7
#define SHT_NOBITS		8
#define SHT_REL			9
#define SHT_SHLIB		10
#define SHT_DYNSYM		11
#define SHT_INIT_ARRAY		14
#define SHT_FINI_ARRAY		15
#define SHT_PREINIT_ARRAY	16
#define SHT_GROUP		17
#define SHT_SYMTAB_SHNDx	18
#define SHT_GNU_ATTRIBUTES	0x6FFFFFF5
#define SHT_GNU_HASH		0x6FFFFFF6
#define SHT_GNU_LIBLIST		0x6FFFFFF7
#define SHT_GNU_VERDEF		0x6FFFFFFD
#define SHT_GNU_VERNEED		0x6FFFFFFE
#define SHT_GNU_VERSYM		0x6FFFFFFF
#define SHT_LOPROC		0x70000000
#define SHT_HIPROC		0x7FFFFFFF
#define SHT_LOUSER		0x80000000
#define SHT_HIUSER		0xFFFFFFFF

/* sh_flags */
#define SHF_WRITE		1
#define SHF_ALLOC		2
#define SHF_ExECINSTR	4
#define SHF_MASKPROC	0xF0000000

/* Elf32_Sym */
#define STN_UNDEF	0
#define ELF32_ST_BIND(b)	((b)>>4)
#define ELF32_ST_TYPE(t)	((t)&0xf)
#define ELF32_ST_INFO(b,t)	(((b)<<4)+((t)&0xf))
#define STB_LOCAL	0
#define STB_GLOBAL	1
#define STB_WEAK	2
#define STB_LOPROC	13
#define STB_HIPROC	15

/* r_info */
#define ELF32_R_SYM(s)		((s)>>8)
#define ELF32_R_TYPE(t)		((unsigned char)(t))
#define ELF32_R_INFO(s,t)	(((s)<<8)+(unsigned char)(t))

/* R_386 relocation types */
#define R_386_NONE		0
#define R_386_32		1
#define R_386_PC32		2
#define R_386_GOT32		3
#define R_386_PLT32		4
#define R_386_COPY		5
#define R_386_GLOB_DAT	6
#define R_386_JMP_SLOT	7
#define R_386_RELATIVE	8
#define R_386_GOTOFF	9
#define R_386_GOTPC		10

/* p_type */
#define PT_NULL		0
#define PT_LOAD		1
#define PT_DYNAMIC	2
#define PT_INTERP	3
#define PT_NOTE		4
#define PT_SHLIB	5
#define PT_PHDR		6
#define PT_TLS		7
#define PT_GNU_EH_FRAME	0x6474E550
#define PT_GNU_STACK	0x6474E551
#define PT_GNU_RELRO	0x6474E552
#define PT_GNU_PROPERTY	0x6474E553
#define PT_LOPROC	0x70000000
#define PT_HIPROC	0x7FFFFFFF

/* p_flags */
#define PF_x		0x1
#define PF_W		0x2
#define PF_R		0x4
#define PF_MASKPROC	0xF0000000

/* d_tag */
#define DT_NULL		0
#define DT_NEEDED	1
#define DT_PLTRELSZ	2
#define DT_PLTGOT	3
#define DT_HASH		4
#define DT_STRTAB	5
#define DT_SYMTAB	6
#define DT_RELA		7
#define DT_RELASZ	8
#define DT_RELAENT	9
#define DT_STRSZ	10
#define DT_SYMENT	11
#define DT_INIT		12
#define DT_FINI		13
#define DT_SONAME	14
#define DT_RPATH	15
#define DT_SYMBOLIC	16
#define DT_REL		17
#define DT_RELSZ	18
#define DT_RELENT	19
#define DT_PLTREL	20
#define DT_DEBUG	21
#define DT_TExTREL	22
#define DT_JMPREL	23
#define DT_LOPROC	0x70000000
#define DT_HIPROC	0x7FFFFFFF

/* elfbrk magic switch flags */
#define EB_MAGICPATCH_UNDEF		0
#define EB_MAGICPATCH_RESET		0x00000001
#define EB_MAGICPATCH_SLACK		0x00000002
#define EB_MAGICPATCH_SIG		0x00000004
#define EB_MAGICPATCH_PK1		0x00000008
#define EB_MAGICPATCH_PK2		0x00000010
#define EB_MAGICPATCH_PK3		0x00000020
#define EB_MAGICPATCH_PE		0x00000040
#define EB_MAGICPATCH_RAR		0x00000080
#define EB_MAGICPATCH_GZ		0x00000100
#define EB_MAGICPATCH_PDF		0x00000200
#define EB_MAGICPATCH_TAR		0x00000400
#define EB_MAGICPATCH_DOS		0x00000800
#define EB_MAGICPATCH_ZB1		0x00001000
#define EB_MAGICPATCH_ZB2		0x00002000
#define EB_MAGICPATCH_ZB3		0x00004000

/* magic patch signatures */
#define EB_EBSIG		0xBADC0DE0
#define EB_RESETSIG		0x7F454C46
#define EB_PKSIG1		0x504B0304
#define EB_PKSIG2		0x504B0506
#define EB_PKSIG3		0x504B0708
#define EB_ZBSIG1		0x4D530304
#define EB_ZBSIG2		0x4D530506
#define EB_ZBSIG3		0x4D530708
#define EB_RARSIG		0x00000000
#define EB_DOSSIG		0x4D5A4CCC
#define EB_PESIG		0x00000000

/* ------------------------------------------------------------------ */
/*  ELF32 structs                                                      */
/* ------------------------------------------------------------------ */

#pragma pack(push, 1)
typedef struct s_elf32_ehdr {
	unsigned char e_ident[EI_NIDENT];
	Elf32_Half	e_type;
	Elf32_Half	e_machine;
	Elf32_Word	e_version;
	Elf32_Addr	e_entry;
	Elf32_Off	e_phoff;
	Elf32_Off	e_shoff;
	Elf32_Word	e_flags;
	Elf32_Half	e_ehsize;
	Elf32_Half	e_phentsize;
	Elf32_Half	e_phnum;
	Elf32_Half	e_shentsize;
	Elf32_Half	e_shnum;
	Elf32_Half	e_shstrndx;
} Elf32_Ehdr;

typedef struct s_elf32_shdr {
	Elf32_Word	sh_name;
	Elf32_Word	sh_type;
	Elf32_Word	sh_flags;
	Elf32_Addr	sh_addr;
	Elf32_Off	sh_offset;
	Elf32_Word	sh_size;
	Elf32_Word	sh_link;
	Elf32_Word	sh_info;
	Elf32_Word	sh_addralign;
	Elf32_Word	sh_entsize;
} Elf32_Shdr;

typedef struct s_elf32_sym {
	Elf32_Word		st_name;
	Elf32_Addr		st_value;
	Elf32_Word		st_size;
	unsigned char	st_info;
	unsigned char	st_other;
	Elf32_Half		st_shndx;
} Elf32_Sym;

typedef struct s_elf32_rel {
	Elf32_Addr	r_offset;
	Elf32_Word	r_info;
} Elf32_Rel;

typedef struct s_elf32_rela {
	Elf32_Addr	r_offset;
	Elf32_Word	r_info;
	Elf32_Sword	r_addend;
} Elf32_Rela;

typedef struct s_elf32_phdr {
	Elf32_Word	p_type;
	Elf32_Off	p_offset;
	Elf32_Addr	p_vaddr;
	Elf32_Addr	p_paddr;
	Elf32_Word	p_filesz;
	Elf32_Word	p_memsz;
	Elf32_Word	p_flags;
	Elf32_Word	p_align;
} Elf32_Phdr;

typedef struct s_elf32_dyn {
	Elf32_Sword	d_tag;
	union { Elf32_Word d_val; Elf32_Word d_ptr; } d_un;
} Elf32_Dyn;

/* ------------------------------------------------------------------ */
/*  ELF64 structs                                                      */
/* ------------------------------------------------------------------ */

typedef struct s_elf64_ehdr {
	unsigned char e_ident[EI_NIDENT];
	Elf32_Half	e_type;
	Elf32_Half	e_machine;
	Elf32_Word	e_version;
	Elf64_Addr	e_entry;
	Elf64_Off	e_phoff;
	Elf64_Off	e_shoff;
	Elf32_Word	e_flags;
	Elf32_Half	e_ehsize;
	Elf32_Half	e_phentsize;
	Elf32_Half	e_phnum;
	Elf32_Half	e_shentsize;
	Elf32_Half	e_shnum;
	Elf32_Half	e_shstrndx;
} Elf64_Ehdr;

typedef struct s_elf64_shdr {
	Elf32_Word	sh_name;
	Elf32_Word	sh_type;
	Elf64_xword	sh_flags;
	Elf64_Addr	sh_addr;
	Elf64_Off	sh_offset;
	Elf64_xword	sh_size;
	Elf32_Word	sh_link;
	Elf32_Word	sh_info;
	Elf64_xword	sh_addralign;
	Elf64_xword	sh_entsize;
} Elf64_Shdr;

typedef struct s_elf64_sym {
	Elf32_Word		st_name;
	unsigned char	st_info;	/* NOTE: moved before st_other vs ELF32 */
	unsigned char	st_other;
	Elf32_Half		st_shndx;
	Elf64_Addr		st_value;
	Elf64_xword		st_size;
} Elf64_Sym;

typedef struct s_elf64_rel {
	Elf64_Addr	r_offset;
	Elf64_xword	r_info;
} Elf64_Rel;

typedef struct s_elf64_rela {
	Elf64_Addr	r_offset;
	Elf64_xword	r_info;
	Elf64_Sxword	r_addend;
} Elf64_Rela;

typedef struct s_elf64_phdr {
	Elf32_Word	p_type;
	Elf32_Word	p_flags;	/* NOTE: p_flags before p_offset in ELF64 */
	Elf64_Off	p_offset;
	Elf64_Addr	p_vaddr;
	Elf64_Addr	p_paddr;
	Elf64_xword	p_filesz;
	Elf64_xword	p_memsz;
	Elf64_xword	p_align;
} Elf64_Phdr;

typedef struct s_elf64_dyn {
	Elf64_Sxword	d_tag;
	union { Elf64_xword d_val; Elf64_Addr d_ptr; } d_un;
} Elf64_Dyn;
#pragma pack(pop)

/* ------------------------------------------------------------------ */
/*  ElfCtx: normalized header + raw buffer, valid for ELF32 + ELF64  */
/* ------------------------------------------------------------------ */

typedef struct {
	int            elfclass;
	unsigned char *buf;
	size_t         len;
	/* header fields normalized to 64-bit */
	uint16_t  e_type;
	uint16_t  e_machine;
	uint32_t  e_version;
	uint32_t  e_flags;
	uint64_t  e_entry;
	uint64_t  e_phoff;
	uint64_t  e_shoff;
	uint16_t  e_ehsize;
	uint16_t  e_phentsize;
	uint16_t  e_phnum;
	uint16_t  e_shentsize;
	uint16_t  e_shnum;
	uint16_t  e_shstrndx;
} ElfCtx;

/* normalized section info for class-agnostic sorting */
typedef struct {
	uint64_t sh_offset;
	uint64_t sh_size;
	uint32_t sh_type;
} ShdrInfo;

/* flat (offset, size) record used by collect_slack */
typedef struct {
	uint64_t offset;
	uint64_t size;
} SlackRegion;

static int elf_ctx_init(ElfCtx *ctx, unsigned char *buf, size_t len)
{
	Elf32_Ehdr *e32;
	Elf64_Ehdr *e64;

	if (len < EI_NIDENT) return -1;
	ctx->buf      = buf;
	ctx->len      = len;
	ctx->elfclass = buf[EI_CLASS];

	if (ctx->elfclass == ELFCLASS32) {
		if (len < sizeof(Elf32_Ehdr)) return -1;
		e32 = (Elf32_Ehdr *)buf;
		ctx->e_type      = e32->e_type;
		ctx->e_machine   = e32->e_machine;
		ctx->e_version   = e32->e_version;
		ctx->e_flags     = e32->e_flags;
		ctx->e_entry     = e32->e_entry;
		ctx->e_phoff     = e32->e_phoff;
		ctx->e_shoff     = e32->e_shoff;
		ctx->e_ehsize    = e32->e_ehsize;
		ctx->e_phentsize = e32->e_phentsize;
		ctx->e_phnum     = e32->e_phnum;
		ctx->e_shentsize = e32->e_shentsize;
		ctx->e_shnum     = e32->e_shnum;
		ctx->e_shstrndx  = e32->e_shstrndx;
	} else if (ctx->elfclass == ELFCLASS64) {
		if (len < sizeof(Elf64_Ehdr)) return -1;
		e64 = (Elf64_Ehdr *)buf;
		ctx->e_type      = e64->e_type;
		ctx->e_machine   = e64->e_machine;
		ctx->e_version   = e64->e_version;
		ctx->e_flags     = e64->e_flags;
		ctx->e_entry     = e64->e_entry;
		ctx->e_phoff     = e64->e_phoff;
		ctx->e_shoff     = e64->e_shoff;
		ctx->e_ehsize    = e64->e_ehsize;
		ctx->e_phentsize = e64->e_phentsize;
		ctx->e_phnum     = e64->e_phnum;
		ctx->e_shentsize = e64->e_shentsize;
		ctx->e_shnum     = e64->e_shnum;
		ctx->e_shstrndx  = e64->e_shstrndx;
	} else {
		return -1;
	}
	return 0;
}

/* ------------------------------------------------------------------ */
/*  Globals                                                            */
/* ------------------------------------------------------------------ */

long g_slack;
uint8_t g_iotype;
static long g_slack_ehdr  = 0;
static long g_slack_paddr = 0;
static long g_slack_note  = 0;
static long g_slack_shdr  = 0;
static long g_slack_gap   = 0;
static long g_slack_eof   = 0;
static int  g_did_slack_count = 0;

/* ------------------------------------------------------------------ */
/*  Core functions                                                     */
/* ------------------------------------------------------------------ */

unsigned long elf_hash(const unsigned char *name)
{
	unsigned long h = 0, g;
	while ( *name )
	{
		h = ( h << 4 ) + *name++;
		if ( (g = h & 0xF0000000) )
			h ^= g >> 24;
		h &= ~g;
	}
	return h;
}

void show_help()
{
	printf(
		"elfbrk-%s  --  ELF32/ELF64 fuzzer, analyzer, steganography tool\n"
		"\n"
		"  usage:  elfbrk <elf_file> [options ...]\n"
		"\n"
		"  multiple flags can be combined in one invocation.\n"
		"  analysis flags are read-only.  write flags modify the file in place.\n"
		"\n"
		"  -----------------------------------------------------------------------\n"
		"  analysis\n"
		"  -----------------------------------------------------------------------\n"
		"\n"
		"  --help, -h, /?                show this message\n"
		"  --phdr                        walk and print all program headers\n"
		"  --shdr                        walk and print all section headers\n"
		"  --slack-count                 enumerate all slack regions with hex content\n"
		"\n"
		"  -----------------------------------------------------------------------\n"
		"  steganography  (p_paddr)\n"
		"  -----------------------------------------------------------------------\n"
		"\n"
		"  --paddr-read                  hex dump p_paddr fields from all segments\n"
		"  --paddr-read-file  <file>     extract p_paddr bytes to file\n"
		"  --paddr-write      <hex>      pack hex bytes across p_paddr fields\n"
		"  --paddr-write-file <file>     same but read payload from file\n"
		"\n"
		"  -----------------------------------------------------------------------\n"
		"  steganography  (slack regions)\n"
		"  -----------------------------------------------------------------------\n"
		"\n"
		"  --slack-read-file  <file>     extract all slack region bytes to file\n"
		"  --slack-write-file <file>     scatter file into slack regions\n"
		"\n"
		"  -----------------------------------------------------------------------\n"
		"  section / note manipulation\n"
		"  -----------------------------------------------------------------------\n"
		"\n"
		"  --shdr-strip                  zero e_shoff/e_shnum/e_shstrndx\n"
		"  --note-inject      <file>     write file into first PT_NOTE segment\n"
		"\n"
		"  -----------------------------------------------------------------------\n"
		"  debug section manipulation\n"
		"  -----------------------------------------------------------------------\n"
		"\n"
		"  --debuglink-corrupt           flip CRC32 in .gnu_debuglink\n"
		"  --debuglink-path   <path>     replace filename in .gnu_debuglink\n"
		"  --build-id-patch   <hex>      overwrite GNU build ID bytes\n"
		"  --debug-inject     <sec> <f>  write file into named section\n"
		"  --debug-zero                  zero all .debug_* section contents\n"
		"\n"
		"  -----------------------------------------------------------------------\n"
		"  magic patch\n"
		"  -----------------------------------------------------------------------\n"
		"\n"
		"  --magic-patch                 0xBADC0DE0  elfbrk signature\n"
		"  --magic-patch-reset           0x7F454C46  restore ELF magic\n"
		"  --magic-patch-slack           0x90909090  NOP sled\n"
		"  --magic-patch-pk1             0x504B0304  ZIP local file header\n"
		"  --magic-patch-pk2             0x504B0506  ZIP end of central directory\n"
		"  --magic-patch-pk3             0x504B0708  ZIP data descriptor\n"
		"  --magic-patch-zb1             0x4D530304  zipbrk variant 1\n"
		"  --magic-patch-zb2             0x4D530506  zipbrk variant 2\n"
		"  --magic-patch-zb3             0x4D530708  zipbrk variant 3\n"
		"  --magic-patch-dos             0x4D5A4CCC  DOS MZ header\n"
		"\n"
		"  -----------------------------------------------------------------------\n"
		"\n"
		"  elfbrk ./ls --phdr\n"
		"  elfbrk ./ls --slack-count\n"
		"  elfbrk ./a.out --paddr-write deadbeefcafebabe\n"
		"  elfbrk ./a.out --debug-zero --shdr-strip\n"
		"\n",
		EB_VERSION_STRING
	);
	exit(1);
}

void printbin(const void *buffer, uint16_t index_len, uint16_t total_len)
{
	uint32_t n, size;
	unsigned char *p = (unsigned char *)buffer;
	size = index_len * total_len;
	for ( n = 0; n < size; n++ )
		printf("%.2x ", p[n]);
}

/* ------------------------------------------------------------------ */
/*  ELF header printing                                                */
/* ------------------------------------------------------------------ */

static void print_ehdr_decoded(ElfCtx *ctx)
{
	printf("|--------------------------------------------------------------------\n"
	       "|=>>  Ehdr Member Definitions\n"
	       "|--------------------------------------------------------------------\n");

	switch (ctx->buf[EI_CLASS]) {
		case ELFCLASSNONE: printf("|  EI_CLASS:         ELFCLASSNONE [%u]\n", ctx->buf[EI_CLASS]); break;
		case ELFCLASS32:   printf("|  EI_CLASS:         ELFCLASS32 [%u]\n",   ctx->buf[EI_CLASS]); break;
		case ELFCLASS64:   printf("|  EI_CLASS:         ELFCLASS64 [%u]\n",   ctx->buf[EI_CLASS]); break;
		default:           printf("|  EI_CLASS:         Undefined [%u]\n",    ctx->buf[EI_CLASS]); break;
	}
	switch (ctx->buf[EI_DATA]) {
		case ELFDATANONE: printf("|  EI_DATA:          ELFDATANONE [%u]\n",                    ctx->buf[EI_DATA]); break;
		case ELFDATA2LSB: printf("|  EI_DATA:          ELFDATA2LSB (Little Endian) [%u]\n",    ctx->buf[EI_DATA]); break;
		case ELFDATA2MSB: printf("|  EI_DATA:          ELFDATA2MSB (Big Endian) [%u]\n",       ctx->buf[EI_DATA]); break;
		default:          printf("|  EI_DATA:          Undefined [%u]\n",                      ctx->buf[EI_DATA]); break;
	}
	switch (ctx->buf[EI_VERSION]) {
		case EV_NONE:    printf("|  EI_VERSION:       EV_NONE [%u]\n",    ctx->buf[EI_VERSION]); break;
		case EV_CURRENT: printf("|  EI_VERSION:       EV_CURRENT [%u]\n", ctx->buf[EI_VERSION]); break;
		default:         printf("|  EI_VERSION:       Undefined [%u]\n",  ctx->buf[EI_VERSION]); break;
	}
	switch (ctx->e_type) {
		case ET_NONE:  printf("|  e_type:           ET_NONE [%u]\n",  ctx->e_type); break;
		case ET_REL:   printf("|  e_type:           ET_REL [%u]\n",   ctx->e_type); break;
		case ET_ExEC:  printf("|  e_type:           ET_ExEC [%u]\n",  ctx->e_type); break;
		case ET_DYN:   printf("|  e_type:           ET_DYN [%u]\n",   ctx->e_type); break;
		case ET_CORE:  printf("|  e_type:           ET_CORE [%u]\n",  ctx->e_type); break;
		default:       printf("|  e_type:           Undefined [%u]\n", ctx->e_type); break;
	}
	switch (ctx->e_machine) {
		case EM_NONE:    printf("|  e_machine:        EM_NONE [%u]\n",    ctx->e_machine); break;
		case EM_M32:     printf("|  e_machine:        EM_M32 [%u]\n",     ctx->e_machine); break;
		case EM_SPARC:   printf("|  e_machine:        EM_SPARC [%u]\n",   ctx->e_machine); break;
		case EM_386:     printf("|  e_machine:        EM_386 [%u]\n",     ctx->e_machine); break;
		case EM_68K:     printf("|  e_machine:        EM_68K [%u]\n",     ctx->e_machine); break;
		case EM_88K:     printf("|  e_machine:        EM_88K [%u]\n",     ctx->e_machine); break;
		case EM_860:     printf("|  e_machine:        EM_860 [%u]\n",     ctx->e_machine); break;
		case EM_MIPS:    printf("|  e_machine:        EM_MIPS [%u]\n",    ctx->e_machine); break;
		case EM_AMD8664: printf("|  e_machine:        EM_AMD8664 [%u]\n", ctx->e_machine); break;
		default:
			printf("|  e_machine:        Undefined (%s) [%u]\n",
			       ctx->elfclass == ELFCLASS64 ? "ia64/amd64" : "Unknown",
			       ctx->e_machine);
			break;
	}
	switch (ctx->e_version) {
		case EV_NONE:    printf("|  e_version:        EV_NONE [%u]\n",    ctx->e_version); break;
		case EV_CURRENT: printf("|  e_version:        EV_CURRENT [%u]\n", ctx->e_version); break;
		default:         printf("|  e_version:        Undefined [%u]\n",  ctx->e_version); break;
	}
}

static void print_Elf32_Ehdr(ElfCtx *ctx)
{
	Elf32_Ehdr e;
	memcpy(&e, ctx->buf, sizeof(e));

	printf("|=>>  [Elf32_Ehdr]:\n"
	       "|--------------------------------------------------------------------\n");
	printf("| .e_ident           "); printbin(&e, 1, EI_NIDENT); printf("\n");
	printf("|    - ELFMAG        "); printbin(&e, 1, 4); printf("\n");
	printf("|    - EI_CLASS      "); printbin(&e.e_ident[EI_CLASS],   1, 1);        printf("\n");
	printf("|    - EI_DATA       "); printbin(&e.e_ident[EI_DATA],    1, 1);        printf("\n");
	printf("|    - EI_VERSION    "); printbin(&e.e_ident[EI_VERSION], 1, 1);        printf("\n");
	printf("|    - EI_PAD[9]     ");
	                                 printbin(&e.e_ident[EI_OSABI], 1, EI_IDENT_SLACK); printf("\n");
	printf("| .e_type            "); printbin(&e.e_type,     1, sizeof(e.e_type));     printf("\n");
	printf("| .e_machine         "); printbin(&e.e_machine,  1, sizeof(e.e_machine));  printf("\n");
	printf("| .e_version         "); printbin(&e.e_version,  1, sizeof(e.e_version));  printf("\n");
	printf("| .e_entry           "); printbin(&e.e_entry,    1, sizeof(e.e_entry));    printf("\n");
	printf("| .e_phoff           "); printbin(&e.e_phoff,    1, sizeof(e.e_phoff));    printf("\n");
	printf("| .e_shoff           "); printbin(&e.e_shoff,    1, sizeof(e.e_shoff));    printf("\n");
	printf("| .e_flags           "); printbin(&e.e_flags,    1, sizeof(e.e_flags));    printf("\n");
	printf("| .e_ehsize          "); printbin(&e.e_ehsize,   1, sizeof(e.e_ehsize));   printf("\n");
	printf("| .e_phentsize       "); printbin(&e.e_phentsize,1, sizeof(e.e_phentsize));printf("\n");
	printf("| .e_phnum           "); printbin(&e.e_phnum,    1, sizeof(e.e_phnum));    printf("\n");
	printf("| .e_shentsize       "); printbin(&e.e_shentsize,1, sizeof(e.e_shentsize));printf("\n");
	printf("| .e_shnum           "); printbin(&e.e_shnum,    1, sizeof(e.e_shnum));    printf("\n");
	printf("| .e_shstrndx        "); printbin(&e.e_shstrndx, 1, sizeof(e.e_shstrndx)); printf("\n");
	print_ehdr_decoded(ctx);
}

static void print_Elf64_Ehdr(ElfCtx *ctx)
{
	Elf64_Ehdr e;
	memcpy(&e, ctx->buf, sizeof(e));

	printf("|=>>  [Elf64_Ehdr]:\n"
	       "|--------------------------------------------------------------------\n");
	printf("| .e_ident           "); printbin(&e, 1, EI_NIDENT); printf("\n");
	printf("|    - ELFMAG        "); printbin(&e, 1, 4); printf("\n");
	printf("|    - EI_CLASS      "); printbin(&e.e_ident[EI_CLASS],   1, 1);        printf("\n");
	printf("|    - EI_DATA       "); printbin(&e.e_ident[EI_DATA],    1, 1);        printf("\n");
	printf("|    - EI_VERSION    "); printbin(&e.e_ident[EI_VERSION], 1, 1);        printf("\n");
	printf("|    - EI_PAD[9]     ");
	                                 printbin(&e.e_ident[EI_OSABI], 1, EI_IDENT_SLACK); printf("\n");
	printf("| .e_type            "); printbin(&e.e_type,     1, sizeof(e.e_type));     printf("\n");
	printf("| .e_machine         "); printbin(&e.e_machine,  1, sizeof(e.e_machine));  printf("\n");
	printf("| .e_version         "); printbin(&e.e_version,  1, sizeof(e.e_version));  printf("\n");
	printf("| .e_entry           "); printbin(&e.e_entry,    1, sizeof(e.e_entry));    printf("\n"); /* 8 bytes */
	printf("| .e_phoff           "); printbin(&e.e_phoff,    1, sizeof(e.e_phoff));    printf("\n"); /* 8 bytes */
	printf("| .e_shoff           "); printbin(&e.e_shoff,    1, sizeof(e.e_shoff));    printf("\n"); /* 8 bytes */
	printf("| .e_flags           "); printbin(&e.e_flags,    1, sizeof(e.e_flags));    printf("\n");
	printf("| .e_ehsize          "); printbin(&e.e_ehsize,   1, sizeof(e.e_ehsize));   printf("\n");
	printf("| .e_phentsize       "); printbin(&e.e_phentsize,1, sizeof(e.e_phentsize));printf("\n");
	printf("| .e_phnum           "); printbin(&e.e_phnum,    1, sizeof(e.e_phnum));    printf("\n");
	printf("| .e_shentsize       "); printbin(&e.e_shentsize,1, sizeof(e.e_shentsize));printf("\n");
	printf("| .e_shnum           "); printbin(&e.e_shnum,    1, sizeof(e.e_shnum));    printf("\n");
	printf("| .e_shstrndx        "); printbin(&e.e_shstrndx, 1, sizeof(e.e_shstrndx)); printf("\n");
	print_ehdr_decoded(ctx);
}

void print_ehdr(ElfCtx *ctx)
{
	if (ctx->elfclass == ELFCLASS64)
		print_Elf64_Ehdr(ctx);
	else
		print_Elf32_Ehdr(ctx);
}

/* ------------------------------------------------------------------ */
/*  Slack counting                                                     */
/* ------------------------------------------------------------------ */

static int bounds_ok(size_t filelen, uint64_t offset, uint64_t size); /* forward */

/* ------------------------------------------------------------------ */
/*  Patching                                                           */
/* ------------------------------------------------------------------ */

int patch_Elf32_Ehdr(FILE *target, ElfCtx *ctx)
{
	Elf32_Ehdr e;

	if (ctx->elfclass != ELFCLASS32) {
		printf("|  [!] patch_Elf32_Ehdr: not an ELF32 file\n"); return 0; }
	if (target == NULL) {
		printf("|  [!] NULL file target\n"); return 0; }

	memcpy(&e, ctx->buf, sizeof(e));
	printf("|  * Applying Elf32_Ehdr patch ...\n");

	e.e_version = 0x90909090;
	memset(&e.e_ident[EI_PAD], 0x90, EI_PADLEN);
	if (e.e_phoff == 0) { e.e_phentsize = 0x9090; e.e_phnum = 0x9090; }
	if (e.e_shoff == 0) { e.e_shentsize = 0x9090; e.e_shnum = 0x9090; e.e_shstrndx = 0x9090; }

	memcpy(ctx->buf, &e, sizeof(e));
	fseek(target, 0, SEEK_SET);
	fwrite(&e, sizeof(e), 1, target);
	fflush(target);

	return 0;
}

uint32_t magic_patch(FILE *target, ElfCtx *ctx, uint32_t mode)
{
	uint32_t sig = 0;
	uint16_t hdrlen = (ctx->elfclass == ELFCLASS64)
	                  ? (uint16_t)sizeof(Elf64_Ehdr)
	                  : (uint16_t)sizeof(Elf32_Ehdr);

	if ( mode == EB_MAGICPATCH_SIG ) {
		sig = htonl(EB_EBSIG);
		printf("|  * Applying *magic patch* sig: 0x%.8x ...\n", EB_EBSIG);
	} else if ( mode == EB_MAGICPATCH_SLACK ) {
		sig = 0x90909090;
		g_slack += (long)sizeof(sig);
		printf("|  * Applying *magic slack patch*: 0x90909090 ...\n");
	} else if ( mode == EB_MAGICPATCH_RESET ) {
		sig = htonl(EB_RESETSIG);
		printf("|  * Resetting *magic patch* sig: 0x%.8x ...\n", EB_RESETSIG);
	} else if ( mode == EB_MAGICPATCH_PK1 ) {
		sig = htonl(EB_PKSIG1);
		printf("|  * Applying *magic pk1 patch* sig: 0x%.8x ...\n", EB_PKSIG1);
	} else if ( mode == EB_MAGICPATCH_PK2 ) {
		sig = htonl(EB_PKSIG2);
		printf("|  * Applying *magic pk2 patch* sig: 0x%.8x ...\n", EB_PKSIG2);
	} else if ( mode == EB_MAGICPATCH_PK3 ) {
		sig = htonl(EB_PKSIG3);
		printf("|  * Applying *magic pk3 patch* sig: 0x%.8x ...\n", EB_PKSIG3);
	} else if ( mode == EB_MAGICPATCH_ZB1 ) {
		sig = htonl(EB_ZBSIG1);
		printf("|  * Applying *magic zb1 patch* sig: 0x%.8x ...\n", EB_ZBSIG1);
	} else if ( mode == EB_MAGICPATCH_ZB2 ) {
		sig = htonl(EB_ZBSIG2);
		printf("|  * Applying *magic zb2 patch* sig: 0x%.8x ...\n", EB_ZBSIG2);
	} else if ( mode == EB_MAGICPATCH_ZB3 ) {
		sig = htonl(EB_ZBSIG3);
		printf("|  * Applying *magic zb3 patch* sig: 0x%.8x ...\n", EB_ZBSIG3);
	} else if ( mode == EB_MAGICPATCH_DOS ) {
		sig = htonl(EB_DOSSIG);
		printf("|  * Applying *magic dos patch* sig: 0x%.8x ...\n", EB_DOSSIG);
	}

	/* overwrite magic bytes in buffer, write correct header size back to file */
	memcpy(ctx->buf, &sig, sizeof(sig));
	if (target != NULL) {
		fseek(target, 0, SEEK_SET);
		fwrite(ctx->buf, hdrlen, 1, target);
		fflush(target);
	}
	return sig;
}

/* ------------------------------------------------------------------ */
/*  Helpers for segment / section walking                              */
/* ------------------------------------------------------------------ */

static int bounds_ok(size_t filelen, uint64_t offset, uint64_t size)
{
	return offset + size <= (uint64_t)filelen;
}

static const char *shtype_name(uint32_t type)
{
	switch (type) {
		case SHT_NULL:     return "NULL";
		case SHT_PROGBITS: return "PROGBITS";
		case SHT_SYMTAB:   return "SYMTAB";
		case SHT_STRTAB:   return "STRTAB";
		case SHT_RELA:     return "RELA";
		case SHT_HASH:     return "HASH";
		case SHT_DYNAMIC:  return "DYNAMIC";
		case SHT_NOTE:     return "NOTE";
		case SHT_NOBITS:   return "NOBITS";
		case SHT_REL:      return "REL";
		case SHT_SHLIB:    return "SHLIB";
		case SHT_DYNSYM:        return "DYNSYM";
		case SHT_INIT_ARRAY:    return "INIT_ARRAY";
		case SHT_FINI_ARRAY:    return "FINI_ARRAY";
		case SHT_PREINIT_ARRAY: return "PREINIT_ARRAY";
		case SHT_GROUP:         return "GROUP";
		case SHT_SYMTAB_SHNDx:  return "SYMTAB_SHNDx";
		case SHT_GNU_ATTRIBUTES:return "GNU_ATTR";
		case SHT_GNU_HASH:      return "GNU_HASH";
		case SHT_GNU_LIBLIST:   return "GNU_LIBLIST";
		case SHT_GNU_VERDEF:    return "GNU_VERDEF";
		case SHT_GNU_VERNEED:   return "GNU_VERNEED";
		case SHT_GNU_VERSYM:    return "GNU_VERSYM";
		default:
			if (type >= SHT_LOPROC && type <= SHT_HIPROC) return "PROC";
			if (type >= SHT_LOUSER) return "USER";
			return "UNKNOWN";
	}
}

static const char *phtype_name(uint32_t type)
{
	switch (type) {
		case PT_NULL:    return "NULL";
		case PT_LOAD:    return "LOAD";
		case PT_DYNAMIC: return "DYNAMIC";
		case PT_INTERP:  return "INTERP";
		case PT_NOTE:    return "NOTE";
		case PT_SHLIB:   return "SHLIB";
		case PT_PHDR:         return "PHDR";
		case PT_TLS:          return "TLS";
		case PT_GNU_EH_FRAME: return "GNU_EH_FRAME";
		case PT_GNU_STACK:    return "GNU_STACK";
		case PT_GNU_RELRO:    return "GNU_RELRO";
		case PT_GNU_PROPERTY: return "GNU_PROPERTY";
		default:
			if (type >= PT_LOPROC && type <= PT_HIPROC) return "PROC";
			return "UNKNOWN";
	}
}

static void phflags_str(uint32_t flags, char *buf)
{
	buf[0] = (flags & PF_R) ? 'R' : '-';
	buf[1] = (flags & PF_W) ? 'W' : '-';
	buf[2] = (flags & PF_x) ? 'x' : '-';
	buf[3] = '\0';
}

static void shflags_str(uint32_t flags, char *buf)
{
	buf[0] = (flags & SHF_WRITE)     ? 'W' : '-';
	buf[1] = (flags & SHF_ALLOC)     ? 'A' : '-';
	buf[2] = (flags & SHF_ExECINSTR) ? 'x' : '-';
	buf[3] = '\0';
}

static const char *get_section_name(ElfCtx *ctx, uint32_t name_off)
{
	uint64_t strtab_off, sh_offset, sh_size;

	if (ctx->e_shstrndx == SHN_UNDEF || ctx->e_shstrndx >= ctx->e_shnum)
		return "?";
	strtab_off = ctx->e_shoff + (uint64_t)ctx->e_shstrndx * ctx->e_shentsize;

	if (ctx->elfclass == ELFCLASS64) {
		Elf64_Shdr *s;
		if (!bounds_ok(ctx->len, strtab_off, sizeof(Elf64_Shdr))) return "?";
		s = (Elf64_Shdr *)(ctx->buf + strtab_off);
		sh_offset = s->sh_offset;
		sh_size   = s->sh_size;
	} else {
		Elf32_Shdr *s;
		if (!bounds_ok(ctx->len, strtab_off, sizeof(Elf32_Shdr))) return "?";
		s = (Elf32_Shdr *)(ctx->buf + strtab_off);
		sh_offset = s->sh_offset;
		sh_size   = s->sh_size;
	}

	if (!bounds_ok(ctx->len, sh_offset, sh_size)) return "?";
	if (name_off >= sh_size) return "?";
	return (const char *)(ctx->buf + sh_offset + name_off);
}

/* ------------------------------------------------------------------ */
/*  Segment / section walkers                                          */
/* ------------------------------------------------------------------ */

void walk_segments(ElfCtx *ctx)
{
	uint32_t i;
	uint64_t off;
	char fstr[4];
	int is64 = (ctx->elfclass == ELFCLASS64);

	if (ctx->e_phoff == 0 || ctx->e_phnum == 0) {
		printf("|  (no program headers)\n");
		return;
	}

	if (is64)
		printf("|  %-4s %-10s %-18s %-18s %-18s %-18s %-18s %-5s %-18s\n",
		       "IDx","TYPE","OFFSET","VADDR","PADDR","FILESZ","MEMSZ","FLG","ALIGN");
	else
		printf("|  %-4s %-10s %-10s %-10s %-10s %-10s %-10s %-5s %-10s\n",
		       "IDx","TYPE","OFFSET","VADDR","PADDR","FILESZ","MEMSZ","FLG","ALIGN");
	printf("|  ---------------------------------------------------------------------------\n");

	for (i = 0; i < ctx->e_phnum; i++) {
		off = ctx->e_phoff + (uint64_t)i * ctx->e_phentsize;
		if (is64) {
			Elf64_Phdr *ph;
			if (!bounds_ok(ctx->len, off, sizeof(Elf64_Phdr))) {
				printf("|  [%u] out of bounds\n", i); break;
			}
			ph = (Elf64_Phdr *)(ctx->buf + off);
			phflags_str(ph->p_flags, fstr);
			printf("|  [%-2u] %-10s 0x%016llx 0x%016llx 0x%016llx 0x%016llx 0x%016llx %-5s 0x%016llx\n",
			       i, phtype_name(ph->p_type),
			       (unsigned long long)ph->p_offset,
			       (unsigned long long)ph->p_vaddr,
			       (unsigned long long)ph->p_paddr,
			       (unsigned long long)ph->p_filesz,
			       (unsigned long long)ph->p_memsz,
			       fstr,
			       (unsigned long long)ph->p_align);
		} else {
			Elf32_Phdr *ph;
			if (!bounds_ok(ctx->len, off, sizeof(Elf32_Phdr))) {
				printf("|  [%u] out of bounds\n", i); break;
			}
			ph = (Elf32_Phdr *)(ctx->buf + off);
			phflags_str(ph->p_flags, fstr);
			printf("|  [%-2u] %-10s 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x %-5s 0x%08x\n",
			       i, phtype_name(ph->p_type),
			       ph->p_offset, ph->p_vaddr, ph->p_paddr,
			       ph->p_filesz, ph->p_memsz, fstr, ph->p_align);
		}
	}
}

void walk_sections(ElfCtx *ctx)
{
	uint32_t i;
	uint64_t off;
	char fstr[4];
	int is64 = (ctx->elfclass == ELFCLASS64);

	if (ctx->e_shoff == 0 || ctx->e_shnum == 0) {
		printf("|  (no section headers)\n");
		return;
	}

	if (is64)
		printf("|  %-4s %-24s %-10s %-18s %-18s %-18s %-5s %-18s\n",
		       "IDx","NAME","TYPE","ADDR","OFFSET","SIZE","FLG","ALIGN");
	else
		printf("|  %-4s %-24s %-10s %-10s %-10s %-10s %-5s %-8s\n",
		       "IDx","NAME","TYPE","ADDR","OFFSET","SIZE","FLG","ALIGN");
	printf("|  ---------------------------------------------------------------------------\n");

	for (i = 0; i < ctx->e_shnum; i++) {
		off = ctx->e_shoff + (uint64_t)i * ctx->e_shentsize;
		if (is64) {
			Elf64_Shdr *sh;
			if (!bounds_ok(ctx->len, off, sizeof(Elf64_Shdr))) {
				printf("|  [%u] out of bounds\n", i); break;
			}
			sh = (Elf64_Shdr *)(ctx->buf + off);
			shflags_str((uint32_t)sh->sh_flags, fstr);
			printf("|  [%-2u] %-24.24s %-10s 0x%016llx 0x%016llx 0x%016llx %-5s 0x%016llx\n",
			       i,
			       get_section_name(ctx, sh->sh_name),
			       shtype_name(sh->sh_type),
			       (unsigned long long)sh->sh_addr,
			       (unsigned long long)sh->sh_offset,
			       (unsigned long long)sh->sh_size,
			       fstr,
			       (unsigned long long)sh->sh_addralign);
		} else {
			Elf32_Shdr *sh;
			if (!bounds_ok(ctx->len, off, sizeof(Elf32_Shdr))) {
				printf("|  [%u] out of bounds\n", i); break;
			}
			sh = (Elf32_Shdr *)(ctx->buf + off);
			shflags_str(sh->sh_flags, fstr);
			printf("|  [%-2u] %-24.24s %-10s 0x%08x 0x%08x 0x%08x %-5s 0x%08x\n",
			       i,
			       get_section_name(ctx, sh->sh_name),
			       shtype_name(sh->sh_type),
			       sh->sh_addr, sh->sh_offset, sh->sh_size,
			       fstr, sh->sh_addralign);
		}
	}
}

/* ------------------------------------------------------------------ */
/*  Stego scanner                                                      */
/* ------------------------------------------------------------------ */

/* sections where sh_link is semantically used by the dynamic linker / loader */
static int sh_link_used(uint32_t t)
{
	switch (t) {
		case SHT_DYNAMIC: case SHT_HASH: case SHT_GNU_HASH:
		case SHT_REL:     case SHT_RELA:
		case SHT_SYMTAB:  case SHT_DYNSYM:
		case SHT_GROUP:   case SHT_SYMTAB_SHNDx:
		case SHT_GNU_VERDEF: case SHT_GNU_VERNEED: case SHT_GNU_VERSYM:
			return 1;
		default: return 0;
	}
}

/* sections where sh_info is semantically used */
static int sh_info_used(uint32_t t)
{
	switch (t) {
		case SHT_REL: case SHT_RELA:
		case SHT_SYMTAB: case SHT_DYNSYM:
		case SHT_GROUP:
		case SHT_GNU_VERDEF: case SHT_GNU_VERNEED:
			return 1;
		default: return 0;
	}
}

/* sections where sh_entsize is used to index entries */
static int sh_entsize_used(uint32_t t)
{
	switch (t) {
		case SHT_SYMTAB:  case SHT_DYNSYM:
		case SHT_REL:     case SHT_RELA:
		case SHT_HASH:    case SHT_GNU_HASH:
		case SHT_DYNAMIC:
		case SHT_GNU_VERSYM: case SHT_GNU_VERDEF: case SHT_GNU_VERNEED:
			return 1;
		default: return 0;
	}
}

static int shdr_info_cmp(const void *a, const void *b); /* forward decl */

static int slack_region_cmp(const void *a, const void *b)
{
	const SlackRegion *ra = (const SlackRegion *)a;
	const SlackRegion *rb = (const SlackRegion *)b;
	if (ra->offset < rb->offset) return -1;
	if (ra->offset > rb->offset) return  1;
	return 0;
}

/* build sorted list of every slack region; caller must free the returned array */
static SlackRegion *collect_slack(ElfCtx *ctx, uint32_t *count)
{
	uint32_t maxr = 16 + 2 * ctx->e_phnum + 4 * ctx->e_shnum;
	SlackRegion *r = malloc(maxr * sizeof(SlackRegion));
	uint32_t n = 0, i;
	int is64 = (ctx->elfclass == ELFCLASS64);

	if (!r) { *count = 0; return NULL; }

#define SADD(off, sz) do { \
	if (n < maxr && (sz) > 0 && bounds_ok(ctx->len, (uint64_t)(off), (uint64_t)(sz))) \
		{ r[n].offset = (uint64_t)(off); r[n].size = (uint64_t)(sz); n++; } \
} while(0)

	/* ELF header fields */
	SADD(EI_OSABI,    1);
	SADD(EI_ABIVERSION, 1);
	SADD(EI_PAD,      EI_PADLEN);
	SADD(0x14,        4); /* e_version */
	SADD(is64 ? 0x30 : 0x24, 4); /* e_flags: always in read/write map; safe on x86/amd64 */

	/* p_paddr per phdr */
	if (ctx->e_phoff != 0) {
		uint64_t paddr_sz = is64 ? 8 : 4;
		for (i = 0; i < ctx->e_phnum; i++) {
			uint64_t off = ctx->e_phoff + (uint64_t)i * ctx->e_phentsize;
			SADD(off + (is64 ? offsetof(Elf64_Phdr, p_paddr)
			                 : offsetof(Elf32_Phdr, p_paddr)), paddr_sz);
		}
	}

	/* PT_NOTE content */
	if (ctx->e_phoff != 0) {
		for (i = 0; i < ctx->e_phnum; i++) {
			uint64_t off = ctx->e_phoff + (uint64_t)i * ctx->e_phentsize;
			if (is64) {
				Elf64_Phdr *ph;
				if (!bounds_ok(ctx->len, off, sizeof(Elf64_Phdr))) continue;
				ph = (Elf64_Phdr *)(ctx->buf + off);
				if (ph->p_type == PT_NOTE && ph->p_filesz > 0)
					SADD(ph->p_offset, ph->p_filesz);
			} else {
				Elf32_Phdr *ph;
				if (!bounds_ok(ctx->len, off, sizeof(Elf32_Phdr))) continue;
				ph = (Elf32_Phdr *)(ctx->buf + off);
				if (ph->p_type == PT_NOTE && ph->p_filesz > 0)
					SADD(ph->p_offset, ph->p_filesz);
			}
		}
	}

	/* unused section header fields */
	if (ctx->e_shoff != 0) {
		for (i = 0; i < ctx->e_shnum; i++) {
			uint64_t off = ctx->e_shoff + (uint64_t)i * ctx->e_shentsize;
			uint32_t stype;
			if (is64) {
				Elf64_Shdr *sh;
				if (!bounds_ok(ctx->len, off, sizeof(Elf64_Shdr))) break;
				sh = (Elf64_Shdr *)(ctx->buf + off);
				stype = sh->sh_type;
				if (stype == SHT_NULL) continue;
				if (!sh_link_used(stype))    SADD(off + offsetof(Elf64_Shdr, sh_link),    4);
				if (!sh_info_used(stype))    SADD(off + offsetof(Elf64_Shdr, sh_info),    4);
				if (!sh_entsize_used(stype)) SADD(off + offsetof(Elf64_Shdr, sh_entsize), 8);
			} else {
				Elf32_Shdr *sh;
				if (!bounds_ok(ctx->len, off, sizeof(Elf32_Shdr))) break;
				sh = (Elf32_Shdr *)(ctx->buf + off);
				stype = sh->sh_type;
				if (stype == SHT_NULL) continue;
				if (!sh_link_used(stype))    SADD(off + offsetof(Elf32_Shdr, sh_link),    4);
				if (!sh_info_used(stype))    SADD(off + offsetof(Elf32_Shdr, sh_info),    4);
				if (!sh_entsize_used(stype)) SADD(off + offsetof(Elf32_Shdr, sh_entsize), 4);
			}
		}
	}

	/* inter-section gaps and EOF overlay */
	if (ctx->e_shoff != 0 && ctx->e_shnum > 0) {
		ShdrInfo *shdrs = malloc(ctx->e_shnum * sizeof(ShdrInfo));
		if (shdrs) {
			uint32_t valid = 0;
			for (i = 0; i < ctx->e_shnum; i++) {
				uint64_t off = ctx->e_shoff + (uint64_t)i * ctx->e_shentsize;
				uint32_t stype; uint64_t sh_off, sh_sz;
				if (is64) {
					Elf64_Shdr *sh;
					if (!bounds_ok(ctx->len, off, sizeof(Elf64_Shdr))) break;
					sh = (Elf64_Shdr *)(ctx->buf + off);
					stype = sh->sh_type; sh_off = sh->sh_offset; sh_sz = sh->sh_size;
				} else {
					Elf32_Shdr *sh;
					if (!bounds_ok(ctx->len, off, sizeof(Elf32_Shdr))) break;
					sh = (Elf32_Shdr *)(ctx->buf + off);
					stype = sh->sh_type; sh_off = sh->sh_offset; sh_sz = sh->sh_size;
				}
				if (stype != SHT_NULL && stype != SHT_NOBITS && sh_sz > 0) {
					shdrs[valid].sh_offset = sh_off;
					shdrs[valid].sh_size   = sh_sz;
					shdrs[valid].sh_type   = stype;
					valid++;
				}
			}
			if (valid > 0) {
				uint64_t last_end, shdr_end, phdr_end, after;
				qsort(shdrs, valid, sizeof(ShdrInfo), shdr_info_cmp);
				for (i = 0; i + 1 < valid; i++) {
					uint64_t end  = shdrs[i].sh_offset + shdrs[i].sh_size;
					uint64_t next = shdrs[i + 1].sh_offset;
					if (next > end) SADD(end, next - end);
				}
				last_end = shdrs[valid-1].sh_offset + shdrs[valid-1].sh_size;
				shdr_end = ctx->e_shoff + (uint64_t)ctx->e_shnum * ctx->e_shentsize;
				phdr_end = ctx->e_phoff + (uint64_t)ctx->e_phnum * ctx->e_phentsize;
				after = last_end;
				if (shdr_end > after) after = shdr_end;
				if (phdr_end > after) after = phdr_end;
				if (after < (uint64_t)ctx->len)
					SADD(after, (uint64_t)ctx->len - after);
			}
			free(shdrs);
		}
	}

#undef SADD

	qsort(r, n, sizeof(SlackRegion), slack_region_cmp);
	*count = n;
	return r;
}

static int shdr_info_cmp(const void *a, const void *b)
{
	const ShdrInfo *sa = (const ShdrInfo *)a;
	const ShdrInfo *sb = (const ShdrInfo *)b;
	if (sa->sh_offset < sb->sh_offset) return -1;
	if (sa->sh_offset > sb->sh_offset) return  1;
	return 0;
}

static void print_slack_bytes(const unsigned char *p, size_t n)
{
	size_t k;
	for (k = 0; k < n; k++) {
		if (k > 0 && k % 16 == 0)
			printf("\n|                    ");
		printf("%.2x ", p[k]);
	}
}

void slack_count(ElfCtx *ctx)
{
	uint32_t i, valid;
	uint64_t off;
	int is64 = (ctx->elfclass == ELFCLASS64);
	uint32_t paddr_sz    = is64 ? 8 : 4;
	uint32_t eflags_off  = is64 ? 0x30 : 0x24;
	uint32_t entsz_bytes = is64 ? 8 : 4;
	ShdrInfo *shdrs = NULL;

	g_did_slack_count = 1;

	printf("|=>>  [Slack Count] (%s)\n", is64 ? "ELF64" : "ELF32");
	printf("|--------------------------------------------------------------------\n");

	/* --- ELF header slack fields --- */
	printf("| .%-18s", "EI_OSABI");      print_slack_bytes(ctx->buf + 7, 1);            printf("\n");
	printf("| .%-18s", "EI_ABIVERSION"); print_slack_bytes(ctx->buf + 8, 1);            printf("\n");
	printf("| .%-18s", "EI_PAD");        print_slack_bytes(ctx->buf + 9, 7);            printf("\n");
	printf("| .%-18s", "e_version");     print_slack_bytes(ctx->buf + 0x14, 4);         printf("\n");
	printf("| .%-18s", "e_flags");       print_slack_bytes(ctx->buf + eflags_off, 4);   printf("\n");
	g_slack_ehdr = EI_IDENT_SLACK + 4 + 4;

	/* --- p_paddr fields --- */
	if (ctx->e_phoff != 0 && ctx->e_phnum > 0) {
		printf("| .p_paddr\n");
		for (i = 0; i < ctx->e_phnum; i++) {
			const char *tname;
			unsigned char *pptr;
			off = ctx->e_phoff + (uint64_t)i * ctx->e_phentsize;
			if (is64) {
				Elf64_Phdr *ph;
				if (!bounds_ok(ctx->len, off, sizeof(Elf64_Phdr))) break;
				ph    = (Elf64_Phdr *)(ctx->buf + off);
				tname = phtype_name(ph->p_type);
				pptr  = ctx->buf + off + offsetof(Elf64_Phdr, p_paddr);
			} else {
				Elf32_Phdr *ph;
				if (!bounds_ok(ctx->len, off, sizeof(Elf32_Phdr))) break;
				ph    = (Elf32_Phdr *)(ctx->buf + off);
				tname = phtype_name(ph->p_type);
				pptr  = ctx->buf + off + offsetof(Elf32_Phdr, p_paddr);
			}
			printf("|    - %-14s", tname);
			print_slack_bytes(pptr, paddr_sz);
			printf("\n");
			g_slack_paddr += paddr_sz;
		}
	}

	/* --- PT_NOTE content --- */
	if (ctx->e_phoff != 0 && ctx->e_phnum > 0) {
		int ph_hdr = 0;
		for (i = 0; i < ctx->e_phnum; i++) {
			uint32_t ptype; uint64_t poff, pfsz;
			off = ctx->e_phoff + (uint64_t)i * ctx->e_phentsize;
			if (is64) {
				Elf64_Phdr *ph;
				if (!bounds_ok(ctx->len, off, sizeof(Elf64_Phdr))) break;
				ph = (Elf64_Phdr *)(ctx->buf + off);
				ptype = ph->p_type; poff = ph->p_offset; pfsz = ph->p_filesz;
			} else {
				Elf32_Phdr *ph;
				if (!bounds_ok(ctx->len, off, sizeof(Elf32_Phdr))) break;
				ph = (Elf32_Phdr *)(ctx->buf + off);
				ptype = ph->p_type; poff = ph->p_offset; pfsz = ph->p_filesz;
			}
			if (ptype == PT_NOTE && pfsz > 0 && bounds_ok(ctx->len, poff, pfsz)) {
				if (!ph_hdr) { printf("| .PT_NOTE\n"); ph_hdr = 1; }
				printf("|    - %-14s", "NOTE");
				print_slack_bytes(ctx->buf + poff, (size_t)pfsz);
				printf("\n");
				g_slack_note += (long)pfsz;
			}
		}
	}

	/* --- section header slack fields + gaps --- */
	if (ctx->e_shoff != 0 && ctx->e_shnum > 0) {
		shdrs = malloc(ctx->e_shnum * sizeof(ShdrInfo));
		if (!shdrs) { printf("|  [!] out of memory\n"); return; }
		valid = 0;

		/* sh_link group */
		{
			int grp = 0;
			for (i = 0; i < ctx->e_shnum; i++) {
				off = ctx->e_shoff + (uint64_t)i * ctx->e_shentsize;
				uint32_t stype; const char *sname; unsigned char *fp;
				if (is64) {
					Elf64_Shdr *sh;
					if (!bounds_ok(ctx->len, off, sizeof(Elf64_Shdr))) break;
					sh = (Elf64_Shdr *)(ctx->buf + off);
					stype = sh->sh_type; sname = get_section_name(ctx, sh->sh_name);
					fp = (unsigned char *)&sh->sh_link;
				} else {
					Elf32_Shdr *sh;
					if (!bounds_ok(ctx->len, off, sizeof(Elf32_Shdr))) break;
					sh = (Elf32_Shdr *)(ctx->buf + off);
					stype = sh->sh_type; sname = get_section_name(ctx, sh->sh_name);
					fp = (unsigned char *)&sh->sh_link;
				}
				if (stype != SHT_NULL && !sh_link_used(stype)) {
					if (!grp) { printf("| .sh_link\n"); grp = 1; }
					printf("|    - %-20s", sname);
					print_slack_bytes(fp, 4); printf("\n");
					g_slack_shdr += 4;
				}
			}
		}

		/* sh_info group */
		{
			int grp = 0;
			for (i = 0; i < ctx->e_shnum; i++) {
				off = ctx->e_shoff + (uint64_t)i * ctx->e_shentsize;
				uint32_t stype; const char *sname; unsigned char *fp;
				if (is64) {
					Elf64_Shdr *sh;
					if (!bounds_ok(ctx->len, off, sizeof(Elf64_Shdr))) break;
					sh = (Elf64_Shdr *)(ctx->buf + off);
					stype = sh->sh_type; sname = get_section_name(ctx, sh->sh_name);
					fp = (unsigned char *)&sh->sh_info;
				} else {
					Elf32_Shdr *sh;
					if (!bounds_ok(ctx->len, off, sizeof(Elf32_Shdr))) break;
					sh = (Elf32_Shdr *)(ctx->buf + off);
					stype = sh->sh_type; sname = get_section_name(ctx, sh->sh_name);
					fp = (unsigned char *)&sh->sh_info;
				}
				if (stype != SHT_NULL && !sh_info_used(stype)) {
					if (!grp) { printf("| .sh_info\n"); grp = 1; }
					printf("|    - %-20s", sname);
					print_slack_bytes(fp, 4); printf("\n");
					g_slack_shdr += 4;
				}
			}
		}

		/* sh_entsize group */
		{
			int grp = 0;
			for (i = 0; i < ctx->e_shnum; i++) {
				off = ctx->e_shoff + (uint64_t)i * ctx->e_shentsize;
				uint32_t stype; const char *sname; unsigned char *fp;
				if (is64) {
					Elf64_Shdr *sh;
					if (!bounds_ok(ctx->len, off, sizeof(Elf64_Shdr))) break;
					sh = (Elf64_Shdr *)(ctx->buf + off);
					stype = sh->sh_type; sname = get_section_name(ctx, sh->sh_name);
					fp = (unsigned char *)&sh->sh_entsize;
				} else {
					Elf32_Shdr *sh;
					if (!bounds_ok(ctx->len, off, sizeof(Elf32_Shdr))) break;
					sh = (Elf32_Shdr *)(ctx->buf + off);
					stype = sh->sh_type; sname = get_section_name(ctx, sh->sh_name);
					fp = (unsigned char *)&sh->sh_entsize;
				}
				if (stype != SHT_NULL && !sh_entsize_used(stype)) {
					if (!grp) { printf("| .sh_entsize\n"); grp = 1; }
					printf("|    - %-20s", sname);
					print_slack_bytes(fp, entsz_bytes); printf("\n");
					g_slack_shdr += (long)entsz_bytes;
				}
			}
		}

		/* collect section extents for gap computation */
		for (i = 0; i < ctx->e_shnum; i++) {
			off = ctx->e_shoff + (uint64_t)i * ctx->e_shentsize;
			uint32_t stype; uint64_t soff, ssz;
			if (is64) {
				Elf64_Shdr *sh;
				if (!bounds_ok(ctx->len, off, sizeof(Elf64_Shdr))) break;
				sh = (Elf64_Shdr *)(ctx->buf + off);
				stype = sh->sh_type; soff = sh->sh_offset; ssz = sh->sh_size;
			} else {
				Elf32_Shdr *sh;
				if (!bounds_ok(ctx->len, off, sizeof(Elf32_Shdr))) break;
				sh = (Elf32_Shdr *)(ctx->buf + off);
				stype = sh->sh_type; soff = sh->sh_offset; ssz = sh->sh_size;
			}
			if (stype != SHT_NULL && stype != SHT_NOBITS && ssz > 0) {
				shdrs[valid].sh_offset = soff;
				shdrs[valid].sh_size   = ssz;
				shdrs[valid].sh_type   = stype;
				valid++;
			}
		}

		if (valid > 0) {
			uint64_t end, next, gap, last_end, shdr_end, phdr_end, after;
			qsort(shdrs, valid, sizeof(ShdrInfo), shdr_info_cmp);

			for (i = 0; i + 1 < valid; i++) {
				end  = shdrs[i].sh_offset + shdrs[i].sh_size;
				next = shdrs[i + 1].sh_offset;
				if (next > end) {
					gap = next - end;
					if (bounds_ok(ctx->len, end, gap)) {
						printf("| .%-18s", "gap");
						print_slack_bytes(ctx->buf + end, (size_t)gap);
						printf("\n");
					}
					g_slack_gap += (long)gap;
				}
			}

			last_end = shdrs[valid - 1].sh_offset + shdrs[valid - 1].sh_size;
			shdr_end = ctx->e_shoff + (uint64_t)ctx->e_shnum * ctx->e_shentsize;
			phdr_end = ctx->e_phoff + (uint64_t)ctx->e_phnum * ctx->e_phentsize;
			after = last_end;
			if (shdr_end > after) after = shdr_end;
			if (phdr_end > after) after = phdr_end;
			if (after < (uint64_t)ctx->len) {
				gap = (uint64_t)ctx->len - after;
				if (bounds_ok(ctx->len, after, gap)) {
					printf("| .%-18s", "eof");
					print_slack_bytes(ctx->buf + after, (size_t)gap);
					printf("\n");
				}
				g_slack_eof += (long)gap;
			}
		}
		free(shdrs);
	}

	g_slack += g_slack_ehdr + g_slack_paddr + g_slack_note
	         + g_slack_shdr + g_slack_gap   + g_slack_eof;
}

/* ------------------------------------------------------------------ */
/*  paddr_read / paddr_read_file                                       */
/* ------------------------------------------------------------------ */

void paddr_read(ElfCtx *ctx)
{
	int is64 = (ctx->elfclass == ELFCLASS64);
	uint32_t paddr_sz = is64 ? 8 : 4;
	uint32_t i, b;

	printf("|=>>  [Paddr Read]\n");
	printf("|--------------------------------------------------------------------\n");

	if (ctx->e_phoff == 0 || ctx->e_phnum == 0) {
		printf("|  [paddr-read] no program headers\n");
		return;
	}

	for (i = 0; i < ctx->e_phnum; i++) {
		uint64_t off = ctx->e_phoff + (uint64_t)i * ctx->e_phentsize;
		uint64_t poff = off + (is64 ? offsetof(Elf64_Phdr, p_paddr)
		                            : offsetof(Elf32_Phdr, p_paddr));
		if (!bounds_ok(ctx->len, poff, paddr_sz)) break;
		printf("|  [%-3u] 0x%016llx  ", i, (unsigned long long)poff);
		for (b = 0; b < paddr_sz; b++)
			printf("%02x ", ctx->buf[poff + b]);
		printf("\n");
	}
	printf("|  total: %llu bytes across %u segment(s)\n",
	       (unsigned long long)((uint64_t)ctx->e_phnum * paddr_sz), ctx->e_phnum);
	printf("|--------------------------------------------------------------------\n");
}

void paddr_read_file(ElfCtx *ctx, const char *path)
{
	int is64 = (ctx->elfclass == ELFCLASS64);
	uint32_t paddr_sz = is64 ? 8 : 4;
	uint32_t i;
	size_t written = 0;
	FILE *out;

	printf("|=>>  [Paddr Read File]\n");
	printf("|--------------------------------------------------------------------\n");

	if (ctx->e_phoff == 0 || ctx->e_phnum == 0) {
		printf("|  [paddr-read-file] no program headers\n");
		return;
	}

	out = fopen(path, "wb");
	if (!out) { printf("|  [paddr-read-file] cannot open: %s\n", path); return; }

	for (i = 0; i < ctx->e_phnum; i++) {
		uint64_t off = ctx->e_phoff + (uint64_t)i * ctx->e_phentsize;
		uint64_t poff = off + (is64 ? offsetof(Elf64_Phdr, p_paddr)
		                            : offsetof(Elf32_Phdr, p_paddr));
		if (!bounds_ok(ctx->len, poff, paddr_sz)) break;
		fwrite(ctx->buf + poff, 1, paddr_sz, out);
		written += paddr_sz;
	}
	fclose(out);

	printf("|  [paddr-read-file] wrote %zu bytes to %s\n", written, path);
	printf("|--------------------------------------------------------------------\n");
}

/* ------------------------------------------------------------------ */
/*  slack_read_file / slack_write_file                                 */
/* ------------------------------------------------------------------ */

void slack_read_file(ElfCtx *ctx, const char *path)
{
	SlackRegion *regions;
	uint32_t count, i;
	uint64_t total = 0;
	FILE *out;

	printf("|=>>  [Slack Read File]\n");
	printf("|--------------------------------------------------------------------\n");

	regions = collect_slack(ctx, &count);
	if (!regions) { printf("|  [slack-read-file] out of memory\n"); return; }

	out = fopen(path, "wb");
	if (!out) {
		printf("|  [slack-read-file] cannot open: %s\n", path);
		free(regions); return;
	}

	for (i = 0; i < count; i++) {
		fwrite(ctx->buf + regions[i].offset, 1, (size_t)regions[i].size, out);
		total += regions[i].size;
	}
	fclose(out);
	free(regions);

	printf("|  [slack-read-file] %u regions, %llu bytes -> %s\n",
	       count, (unsigned long long)total, path);
	printf("|--------------------------------------------------------------------\n");
}

void slack_write_file(FILE *target, ElfCtx *ctx, const char *path)
{
	SlackRegion *regions;
	uint32_t count, i;
	uint64_t capacity = 0, written = 0, remaining;
	FILE *pf;
	unsigned char *payload;
	long pflen;
	size_t plen, src = 0;

	printf("|=>>  [Slack Write File]\n");
	printf("|--------------------------------------------------------------------\n");

	pf = fopen(path, "rb");
	if (!pf) { printf("|  [slack-write-file] cannot open: %s\n", path); return; }
	fseek(pf, 0, SEEK_END);
	pflen = ftell(pf);
	fseek(pf, 0, SEEK_SET);
	if (pflen <= 0) {
		printf("|  [slack-write-file] file is empty\n");
		fclose(pf); return;
	}
	plen = (size_t)pflen;
	payload = malloc(plen);
	if (!payload) {
		printf("|  [slack-write-file] out of memory\n");
		fclose(pf); return;
	}
	if (fread(payload, 1, plen, pf) != plen) {
		printf("|  [slack-write-file] read error\n");
		free(payload); fclose(pf); return;
	}
	fclose(pf);

	regions = collect_slack(ctx, &count);
	if (!regions) {
		printf("|  [slack-write-file] out of memory\n");
		free(payload); return;
	}

	for (i = 0; i < count; i++)
		capacity += regions[i].size;

	for (i = 0; i < count && src < plen; i++) {
		size_t chunk = (size_t)regions[i].size;
		if (src + chunk > plen) chunk = plen - src;
		memcpy(ctx->buf + regions[i].offset, payload + src, chunk);
		src   += chunk;
		written += chunk;
	}

	/* flush the entire modified buffer back to disk */
	fseek(target, 0, SEEK_SET);
	fwrite(ctx->buf, 1, ctx->len, target);
	fflush(target);

	free(regions);
	free(payload);

	remaining = capacity - written;
	printf("|  [slack-write-file] payload:  %zu bytes\n", plen);
	printf("|  [slack-write-file] capacity: %llu bytes across %u regions\n",
	       (unsigned long long)capacity, count);
	printf("|  [slack-write-file] written:  %llu bytes\n", (unsigned long long)written);
	if (src < plen)
		printf("|  [slack-write-file] overflow: %zu bytes did not fit\n", plen - src);
	else
		printf("|  [slack-write-file] unused:   %llu bytes of slack remaining\n",
		       (unsigned long long)remaining);
	printf("|--------------------------------------------------------------------\n");
}

/* ------------------------------------------------------------------ */
/*  shdr_strip: zero e_shoff/e_shnum/e_shstrndx — binary still runs  */
/* ------------------------------------------------------------------ */

void shdr_strip(FILE *target, ElfCtx *ctx)
{
	printf("|=>>  [SHdr Strip]\n");
	printf("|--------------------------------------------------------------------\n");

	if (ctx->elfclass == ELFCLASS64) {
		Elf64_Ehdr *e = (Elf64_Ehdr *)ctx->buf;
		e->e_shoff    = 0;
		e->e_shnum    = 0;
		e->e_shstrndx = 0;
		fseek(target, 0, SEEK_SET);
		fwrite(ctx->buf, sizeof(Elf64_Ehdr), 1, target);
	} else {
		Elf32_Ehdr *e = (Elf32_Ehdr *)ctx->buf;
		e->e_shoff    = 0;
		e->e_shnum    = 0;
		e->e_shstrndx = 0;
		fseek(target, 0, SEEK_SET);
		fwrite(ctx->buf, sizeof(Elf32_Ehdr), 1, target);
	}
	fflush(target);

	ctx->e_shoff    = 0;
	ctx->e_shnum    = 0;
	ctx->e_shstrndx = 0;

	printf("|  [shdr-strip] zeroed e_shoff, e_shnum, e_shstrndx\n");
	printf("|  [shdr-strip] section header table hidden — binary still executes\n");
	printf("|  [shdr-strip] readelf/objdump/gdb will lose section visibility\n");
	printf("|--------------------------------------------------------------------\n");
}

/* ------------------------------------------------------------------ */
/*  note_inject: write payload into first PT_NOTE segment             */
/* ------------------------------------------------------------------ */

void note_inject(FILE *target, ElfCtx *ctx, const char *payload_path)
{
	uint64_t note_off = 0, note_sz = 0;
	uint32_t note_idx = 0, i;
	int is64 = (ctx->elfclass == ELFCLASS64);
	int found = 0;
	FILE *pf;
	unsigned char *payload;
	long pflen;
	size_t plen;
	uint64_t off;

	printf("|=>>  [Note Inject]\n");
	printf("|--------------------------------------------------------------------\n");

	if (ctx->e_phoff == 0 || ctx->e_phnum == 0) {
		printf("|  [note-inject] no program headers\n");
		return;
	}

	for (i = 0; i < ctx->e_phnum && !found; i++) {
		off = ctx->e_phoff + (uint64_t)i * ctx->e_phentsize;
		if (is64) {
			Elf64_Phdr *ph;
			if (!bounds_ok(ctx->len, off, sizeof(Elf64_Phdr))) break;
			ph = (Elf64_Phdr *)(ctx->buf + off);
			if (ph->p_type == PT_NOTE && ph->p_filesz > 0) {
				note_off = ph->p_offset;
				note_sz  = ph->p_filesz;
				note_idx = i;
				found = 1;
			}
		} else {
			Elf32_Phdr *ph;
			if (!bounds_ok(ctx->len, off, sizeof(Elf32_Phdr))) break;
			ph = (Elf32_Phdr *)(ctx->buf + off);
			if (ph->p_type == PT_NOTE && ph->p_filesz > 0) {
				note_off = ph->p_offset;
				note_sz  = ph->p_filesz;
				note_idx = i;
				found = 1;
			}
		}
	}

	if (!found) {
		printf("|  [note-inject] no PT_NOTE segment found\n");
		return;
	}

	pf = fopen(payload_path, "rb");
	if (!pf) {
		printf("|  [note-inject] cannot open payload: %s\n", payload_path);
		return;
	}
	fseek(pf, 0, SEEK_END);
	pflen = ftell(pf);
	fseek(pf, 0, SEEK_SET);

	if (pflen <= 0) {
		printf("|  [note-inject] payload file is empty\n");
		fclose(pf);
		return;
	}
	if ((uint64_t)pflen > note_sz) {
		printf("|  [note-inject] payload %ld bytes exceeds PT_NOTE [%u] capacity %llu bytes\n",
		       pflen, note_idx, (unsigned long long)note_sz);
		fclose(pf);
		return;
	}

	plen = (size_t)pflen;
	payload = malloc(plen);
	if (!payload) { printf("|  [note-inject] out of memory\n"); fclose(pf); return; }

	if (fread(payload, 1, plen, pf) != plen) {
		printf("|  [note-inject] error reading payload\n");
		free(payload); fclose(pf); return;
	}
	fclose(pf);

	if (!bounds_ok(ctx->len, note_off, plen)) {
		printf("|  [note-inject] note offset 0x%llx out of bounds\n",
		       (unsigned long long)note_off);
		free(payload); return;
	}

	fseek(target, (long)note_off, SEEK_SET);
	fwrite(payload, 1, plen, target);
	fflush(target);

	printf("|  [note-inject] PT_NOTE [%u] @ offset 0x%llx: wrote %zu bytes\n",
	       note_idx, (unsigned long long)note_off, plen);
	if (plen < note_sz)
		printf("|  [note-inject] remaining unused: %llu bytes\n",
		       (unsigned long long)(note_sz - plen));
	printf("|--------------------------------------------------------------------\n");

	free(payload);
}

/* ------------------------------------------------------------------ */
/*  Debug section manipulation                                         */
/* ------------------------------------------------------------------ */

static int parse_hex(const char *s, unsigned char *out, size_t *outlen, size_t maxlen); /* forward */

static int find_section(ElfCtx *ctx, const char *name,
                        uint64_t *out_off, uint64_t *out_size)
{
	uint32_t i;
	int is64 = (ctx->elfclass == ELFCLASS64);
	if (!ctx->e_shoff || !ctx->e_shnum) return -1;
	for (i = 0; i < ctx->e_shnum; i++) {
		uint64_t off = ctx->e_shoff + (uint64_t)i * ctx->e_shentsize;
		const char *sname; uint64_t soff, ssz;
		if (is64) {
			Elf64_Shdr *sh;
			if (!bounds_ok(ctx->len, off, sizeof(Elf64_Shdr))) continue;
			sh = (Elf64_Shdr *)(ctx->buf + off);
			sname = get_section_name(ctx, sh->sh_name);
			soff = sh->sh_offset; ssz = sh->sh_size;
		} else {
			Elf32_Shdr *sh;
			if (!bounds_ok(ctx->len, off, sizeof(Elf32_Shdr))) continue;
			sh = (Elf32_Shdr *)(ctx->buf + off);
			sname = get_section_name(ctx, sh->sh_name);
			soff = sh->sh_offset; ssz = sh->sh_size;
		}
		if (strcmp(sname, name) == 0) {
			*out_off = soff; *out_size = ssz; return 0;
		}
	}
	return -1;
}

void debuglink_corrupt(FILE *target, ElfCtx *ctx)
{
	uint64_t soff, ssz;
	unsigned char *sec; size_t namelen; uint64_t crc_off; uint32_t old, new;

	printf("|=>>  [debuglink-corrupt]\n");
	printf("|--------------------------------------------------------------------\n");

	if (find_section(ctx, ".gnu_debuglink", &soff, &ssz) != 0) {
		printf("|  .gnu_debuglink not found\n");
		printf("|--------------------------------------------------------------------\n");
		return;
	}
	if (!bounds_ok(ctx->len, soff, ssz) || ssz < 8) {
		printf("|  .gnu_debuglink too small\n");
		printf("|--------------------------------------------------------------------\n");
		return;
	}
	sec     = ctx->buf + soff;
	namelen = strnlen((char *)sec, (size_t)ssz);
	crc_off = (namelen + 1 + 3) & ~(uint64_t)3;
	if (crc_off + 4 > ssz) {
		printf("|  CRC not present in section\n");
		printf("|--------------------------------------------------------------------\n");
		return;
	}
	memcpy(&old, sec + crc_off, 4);
	new = old ^ 0xFFFFFFFF;
	memcpy(sec + crc_off, &new, 4);
	printf("| .path              %s\n", (char *)sec);
	printf("| .CRC               %08X -> %08X\n", old, new);
	fwrite(ctx->buf, 1, ctx->len, target);
	fflush(target);
	printf("|--------------------------------------------------------------------\n");
}

void debuglink_path(FILE *target, ElfCtx *ctx, const char *newpath)
{
	uint64_t soff, ssz;
	unsigned char *sec; size_t oldlen, newlen; uint64_t old_crc_off, new_crc_off;
	uint32_t saved_crc = 0;

	printf("|=>>  [debuglink-path]\n");
	printf("|--------------------------------------------------------------------\n");

	if (find_section(ctx, ".gnu_debuglink", &soff, &ssz) != 0) {
		printf("|  .gnu_debuglink not found\n");
		printf("|--------------------------------------------------------------------\n");
		return;
	}
	if (!bounds_ok(ctx->len, soff, ssz) || ssz < 8) {
		printf("|  .gnu_debuglink too small\n");
		printf("|--------------------------------------------------------------------\n");
		return;
	}
	sec         = ctx->buf + soff;
	oldlen      = strnlen((char *)sec, (size_t)ssz);
	old_crc_off = (oldlen + 1 + 3) & ~(uint64_t)3;
	if (old_crc_off + 4 <= ssz)
		memcpy(&saved_crc, sec + old_crc_off, 4);

	newlen      = strlen(newpath);
	new_crc_off = (newlen + 1 + 3) & ~(uint64_t)3;
	if (new_crc_off + 4 > ssz) {
		printf("|  new path too long (max %llu bytes)\n",
		       (unsigned long long)(ssz - 5));
		printf("|--------------------------------------------------------------------\n");
		return;
	}
	printf("| .path              %s -> %s\n", (char *)sec, newpath);
	memset(sec, 0, (size_t)ssz);
	memcpy(sec, newpath, newlen);
	memcpy(sec + new_crc_off, &saved_crc, 4);
	fwrite(ctx->buf, 1, ctx->len, target);
	fflush(target);
	printf("|--------------------------------------------------------------------\n");
}

void build_id_patch(FILE *target, ElfCtx *ctx, const char *hexstr)
{
	uint64_t soff, ssz;
	unsigned char newid[64]; size_t newlen = 0, maxlen = sizeof(newid);
	unsigned char *sec; uint32_t descsz; uint64_t desc_off; size_t write_len;

	printf("|=>>  [build-id-patch]\n");
	printf("|--------------------------------------------------------------------\n");

	if (parse_hex(hexstr, newid, &newlen, maxlen) != 0 || newlen == 0) {
		printf("|  invalid hex string\n");
		printf("|--------------------------------------------------------------------\n");
		return;
	}
	if (find_section(ctx, ".note.gnu.build-id", &soff, &ssz) != 0) {
		printf("|  .note.gnu.build-id not found\n");
		printf("|--------------------------------------------------------------------\n");
		return;
	}
	if (!bounds_ok(ctx->len, soff, ssz) || ssz < 16) {
		printf("|  section too small\n");
		printf("|--------------------------------------------------------------------\n");
		return;
	}
	sec      = ctx->buf + soff;
	memcpy(&descsz, sec + 4, 4);
	desc_off = 16;  /* namesz(4) + descsz(4) + type(4) + "GNU\0"(4) */
	if (desc_off + descsz > ssz) {
		printf("|  malformed note\n");
		printf("|--------------------------------------------------------------------\n");
		return;
	}
	printf("| .old               "); printbin(sec + desc_off, 1, (uint16_t)descsz); printf("\n");
	write_len = newlen < descsz ? newlen : descsz;
	memcpy(sec + desc_off, newid, write_len);
	if (write_len < descsz)
		memset(sec + desc_off + write_len, 0, descsz - write_len);
	printf("| .new               "); printbin(sec + desc_off, 1, (uint16_t)descsz); printf("\n");
	if (newlen != descsz)
		printf("|  note: payload %zu bytes, slot %u bytes\n", newlen, descsz);
	fwrite(ctx->buf, 1, ctx->len, target);
	fflush(target);
	printf("|--------------------------------------------------------------------\n");
}

void debug_inject(FILE *target, ElfCtx *ctx, const char *section, const char *path)
{
	uint64_t soff, ssz; FILE *pf; long pflen; size_t write_len, n;

	printf("|=>>  [debug-inject] %s\n", section);
	printf("|--------------------------------------------------------------------\n");

	if (find_section(ctx, section, &soff, &ssz) != 0) {
		printf("|  section \"%s\" not found\n", section);
		printf("|--------------------------------------------------------------------\n");
		return;
	}
	pf = fopen(path, "rb");
	if (!pf) {
		printf("|  cannot open %s\n", path);
		printf("|--------------------------------------------------------------------\n");
		return;
	}
	fseek(pf, 0, SEEK_END); pflen = ftell(pf); fseek(pf, 0, SEEK_SET);
	if (pflen <= 0) { fclose(pf); return; }

	write_len = (size_t)pflen < (size_t)ssz ? (size_t)pflen : (size_t)ssz;
	n = fread(ctx->buf + soff, 1, write_len, pf);
	fclose(pf);
	if (write_len < (size_t)ssz)
		memset(ctx->buf + soff + write_len, 0, (size_t)ssz - write_len);
	fwrite(ctx->buf, 1, ctx->len, target);
	fflush(target);
	printf("|  wrote %zu bytes (section capacity %llu bytes)\n",
	       n, (unsigned long long)ssz);
	if ((size_t)pflen > (size_t)ssz)
		printf("|  overflow: %zu bytes did not fit\n", (size_t)pflen - (size_t)ssz);
	printf("|--------------------------------------------------------------------\n");
}

void debug_zero(FILE *target, ElfCtx *ctx)
{
	uint32_t i; uint64_t off; int is64 = (ctx->elfclass == ELFCLASS64); int count = 0;

	printf("|=>>  [debug-zero]\n");
	printf("|--------------------------------------------------------------------\n");

	if (!ctx->e_shoff || !ctx->e_shnum) {
		printf("|  no section headers\n");
		printf("|--------------------------------------------------------------------\n");
		return;
	}
	for (i = 0; i < ctx->e_shnum; i++) {
		off = ctx->e_shoff + (uint64_t)i * ctx->e_shentsize;
		const char *sname; uint64_t soff, ssz;
		if (is64) {
			Elf64_Shdr *sh;
			if (!bounds_ok(ctx->len, off, sizeof(Elf64_Shdr))) continue;
			sh = (Elf64_Shdr *)(ctx->buf + off);
			sname = get_section_name(ctx, sh->sh_name);
			soff = sh->sh_offset; ssz = sh->sh_size;
		} else {
			Elf32_Shdr *sh;
			if (!bounds_ok(ctx->len, off, sizeof(Elf32_Shdr))) continue;
			sh = (Elf32_Shdr *)(ctx->buf + off);
			sname = get_section_name(ctx, sh->sh_name);
			soff = sh->sh_offset; ssz = sh->sh_size;
		}
		if (strncmp(sname, ".debug_", 7) != 0) continue;
		if (!bounds_ok(ctx->len, soff, ssz) || ssz == 0) continue;
		memset(ctx->buf + soff, 0, (size_t)ssz);
		printf("| .%-30s %llu bytes zeroed\n", sname, (unsigned long long)ssz);
		count++;
	}
	if (count == 0) {
		printf("|  no .debug_* sections found\n");
		printf("|--------------------------------------------------------------------\n");
		return;
	}
	fwrite(ctx->buf, 1, ctx->len, target);
	fflush(target);
	printf("|--------------------------------------------------------------------\n");
}

/* ------------------------------------------------------------------ */
/*  paddr_write: pack bytes across p_paddr fields in phdr order       */
/* ------------------------------------------------------------------ */

/* parse hex string; separators ' ', ':', '-' are ignored between byte pairs */
static int parse_hex(const char *s, unsigned char *out, size_t *outlen, size_t maxlen)
{
	size_t n = 0;
	while (*s) {
		unsigned char hi, lo;
		while (*s == ' ' || *s == ':' || *s == '-') s++;
		if (!*s) break;
		if (!isxdigit((unsigned char)*s)) return -1;
		hi = (unsigned char)*s++;
		if (!isxdigit((unsigned char)*s)) return -1; /* lone nibble */
		lo = (unsigned char)*s++;
		if (n >= maxlen) return -1;
		hi = (hi >= 'a') ? hi - 'a' + 10 : (hi >= 'A') ? hi - 'A' + 10 : hi - '0';
		lo = (lo >= 'a') ? lo - 'a' + 10 : (lo >= 'A') ? lo - 'A' + 10 : lo - '0';
		out[n++] = (hi << 4) | lo;
	}
	*outlen = n;
	return 0;
}

void paddr_write(FILE *target, ElfCtx *ctx, const unsigned char *data, size_t dlen)
{
	int is64 = (ctx->elfclass == ELFCLASS64);
	uint32_t paddr_sz = is64 ? 8 : 4;
	uint64_t total_cap = (uint64_t)ctx->e_phnum * paddr_sz;
	uint32_t i, segs_used;
	size_t written = 0;

	printf("|=>>  [Paddr Write]\n");
	printf("|--------------------------------------------------------------------\n");

	if (ctx->e_phoff == 0 || ctx->e_phnum == 0) {
		printf("|  [paddr-write] no program headers\n");
		return;
	}
	if (dlen == 0) {
		printf("|  [paddr-write] empty payload\n");
		return;
	}
	if (dlen > total_cap) {
		printf("|  [paddr-write] payload %zu bytes exceeds p_paddr capacity %llu bytes (%u segments x %u)\n",
		       dlen, (unsigned long long)total_cap, ctx->e_phnum, paddr_sz);
		return;
	}

	for (i = 0; i < ctx->e_phnum && written < dlen; i++) {
		uint64_t off = ctx->e_phoff + (uint64_t)i * ctx->e_phentsize;
		uint64_t paddr_off = off + (is64 ? offsetof(Elf64_Phdr, p_paddr)
		                                 : offsetof(Elf32_Phdr, p_paddr));
		size_t chunk = dlen - written;
		if (chunk > paddr_sz) chunk = paddr_sz;

		memcpy(ctx->buf + paddr_off, data + written, chunk);
		if (chunk < paddr_sz)
			memset(ctx->buf + paddr_off + chunk, 0, paddr_sz - chunk);

		fseek(target, (long)paddr_off, SEEK_SET);
		fwrite(ctx->buf + paddr_off, paddr_sz, 1, target);
		written += chunk;
	}
	fflush(target);

	segs_used = (uint32_t)((written + paddr_sz - 1) / paddr_sz);
	printf("|  [paddr-write] wrote %zu bytes across %u p_paddr field(s)\n",
	       written, segs_used);
	printf("|  [paddr-write] capacity: %llu bytes total, %llu unused\n",
	       (unsigned long long)total_cap,
	       (unsigned long long)(total_cap - written));
	printf("|--------------------------------------------------------------------\n");
}

/* ------------------------------------------------------------------ */
/*  main                                                               */
/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
	ElfCtx ctx;
	uint32_t elf_sig;
	FILE *target;
	unsigned char *filebuf;
	size_t filelen;
	long flen;
	char name[128];
	int n;

	g_slack  = 0;
	g_iotype = 0;
	g_slack_ehdr = g_slack_paddr = g_slack_note = 0;
	g_slack_shdr = g_slack_gap   = g_slack_eof  = 0;
	g_did_slack_count = 0;

	if (argc >= 2) {
		memset(name, 0, sizeof(name));
		strncpy(name, argv[1], sizeof(name) - 1);
	} else {
		show_help();
		return 0;
	}

	for (n = 2; n < argc; n++) {
		if (!strcmp(argv[n], "--help") || !strcmp(argv[n], "/?") || !strcmp(argv[n], "-h")) {
			show_help();
			return 0;
		}
	}

	if ((target = fopen(name, "rb+")) == NULL) {
		printf("elfbrk: error opening file %s\n", name);
		return 1;
	}

	fseek(target, 0, SEEK_END);
	flen = ftell(target);
	fseek(target, 0, SEEK_SET);

	if (flen < EI_NIDENT) {
		printf("elfbrk: file too small (%ld bytes)\n", flen);
		fclose(target);
		return 1;
	}
	filelen = (size_t)flen;

	filebuf = malloc(filelen + 1);
	if (!filebuf) {
		printf("elfbrk: out of memory\n");
		fclose(target);
		return 1;
	}
	filebuf[filelen] = '\0';

	if (fread(filebuf, 1, filelen, target) != filelen) {
		printf("elfbrk: error reading file\n");
		free(filebuf);
		fclose(target);
		return 1;
	}

	printf("|--------------------------------------------------------------------\n"
	       "|=>>  Starting file dissection...\n");
	printf("|=>>  FILE: %s (%zu bytes)\n", name, filelen);

	elf_sig = htonl(ELFMAG);
	if (!memcmp(filebuf, &elf_sig, 4)) {
		switch (filebuf[EI_CLASS]) {
			case ELFCLASS32: printf("|=>>  TYPE: ELF32\n"); break;
			case ELFCLASS64: printf("|=>>  TYPE: ELF64\n"); break;
			default:         printf("|=>>  TYPE: ELF (unsupported class %u)\n", filebuf[EI_CLASS]); break;
		}
	} else {
		printf("|=>>  TYPE: Unknown File Type\n");
	}

	if (elf_ctx_init(&ctx, filebuf, filelen) < 0) {
		printf("|=>>  Cannot parse ELF header — exiting.\n");
		free(filebuf);
		fclose(target);
		return 1;
	}

	if (argc >= 3) {
		printf("|=>>  OPTIONS:");
		for (n = 2; n < argc; n++)
			printf("\n|        %s", argv[n]);
		printf("\n");
		printf("|====================================================================\n"
		       "|=>>  OPERATIONS:\n"
		       "|--------------------------------------------------------------------\n");

		for (n = 2; n < argc; n++) {
			if (!strcmp(argv[n], "--slack-count"))
				slack_count(&ctx);

			else if (!strcmp(argv[n], "--phdr")) {
				printf("|=>>  [Program Headers / Segments]\n");
				walk_segments(&ctx);
				printf("|--------------------------------------------------------------------\n");
			}

			else if (!strcmp(argv[n], "--shdr")) {
				printf("|=>>  [Section Headers]\n");
				walk_sections(&ctx);
				printf("|--------------------------------------------------------------------\n");
			}

			else if (!strcmp(argv[n], "--shdr-strip")) {
				shdr_strip(target, &ctx); g_iotype = 1; }

			else if (!strcmp(argv[n], "--debuglink-corrupt")) {
				debuglink_corrupt(target, &ctx); g_iotype = 1; }

			else if (!strcmp(argv[n], "--debuglink-path")) {
				if (n + 1 < argc) {
					debuglink_path(target, &ctx, argv[n + 1]);
					n++; g_iotype = 1;
				} else printf("|  [debuglink-path] usage: --debuglink-path <path>\n");
			}

			else if (!strcmp(argv[n], "--build-id-patch")) {
				if (n + 1 < argc) {
					build_id_patch(target, &ctx, argv[n + 1]);
					n++; g_iotype = 1;
				} else printf("|  [build-id-patch] usage: --build-id-patch <hexstring>\n");
			}

			else if (!strcmp(argv[n], "--debug-inject")) {
				if (n + 2 < argc) {
					debug_inject(target, &ctx, argv[n + 1], argv[n + 2]);
					n += 2; g_iotype = 1;
				} else printf("|  [debug-inject] usage: --debug-inject <section> <file>\n");
			}

			else if (!strcmp(argv[n], "--debug-zero")) {
				debug_zero(target, &ctx); g_iotype = 1; }

			else if (!strcmp(argv[n], "--note-inject")) {
				if (n + 1 < argc) {
					note_inject(target, &ctx, argv[n + 1]);
					n++;
					g_iotype = 1;
				} else {
					printf("|  [note-inject] usage: --note-inject <payload_file>\n");
				}
			}

			else if (!strcmp(argv[n], "--paddr-read"))
				paddr_read(&ctx);

			else if (!strcmp(argv[n], "--paddr-read-file")) {
				if (n + 1 < argc) { paddr_read_file(&ctx, argv[n + 1]); n++; }
				else printf("|  [paddr-read-file] usage: --paddr-read-file <file>\n");
			}

			else if (!strcmp(argv[n], "--slack-read-file")) {
				if (n + 1 < argc) { slack_read_file(&ctx, argv[n + 1]); n++; }
				else printf("|  [slack-read-file] usage: --slack-read-file <file>\n");
			}

			else if (!strcmp(argv[n], "--slack-write-file")) {
				if (n + 1 < argc) {
					slack_write_file(target, &ctx, argv[n + 1]);
					n++;
					g_iotype = 1;
				} else {
					printf("|  [slack-write-file] usage: --slack-write-file <file>\n");
				}
			}

			else if (!strcmp(argv[n], "--paddr-write")) {
				if (n + 1 < argc) {
					size_t maxbytes = strlen(argv[n + 1]) / 2 + 1;
					unsigned char *data = malloc(maxbytes);
					if (data) {
						size_t dlen = 0;
						if (parse_hex(argv[n + 1], data, &dlen, maxbytes) < 0)
							printf("|  [paddr-write] invalid hex string"
							       " (use pairs: deadbeef or de:ad:be:ef)\n");
						else if (dlen == 0)
							printf("|  [paddr-write] empty hex string\n");
						else {
							paddr_write(target, &ctx, data, dlen);
							g_iotype = 1;
						}
						free(data);
					}
					n++;
				} else {
					printf("|  [paddr-write] usage: --paddr-write <hexstring>\n");
				}
			}

			else if (!strcmp(argv[n], "--paddr-write-file")) {
				if (n + 1 < argc) {
					FILE *pf = fopen(argv[n + 1], "rb");
					if (!pf) {
						printf("|  [paddr-write-file] cannot open: %s\n", argv[n + 1]);
					} else {
						fseek(pf, 0, SEEK_END);
						long pflen = ftell(pf);
						fseek(pf, 0, SEEK_SET);
						if (pflen > 0) {
							unsigned char *data = malloc((size_t)pflen);
							if (data) {
								if (fread(data, 1, (size_t)pflen, pf) == (size_t)pflen) {
									paddr_write(target, &ctx, data, (size_t)pflen);
									g_iotype = 1;
								} else {
									printf("|  [paddr-write-file] read error\n");
								}
								free(data);
							}
						} else {
							printf("|  [paddr-write-file] file is empty\n");
						}
						fclose(pf);
					}
					n++;
				} else {
					printf("|  [paddr-write-file] usage: --paddr-write-file <file>\n");
				}
			}

			else if (!strcmp(argv[n], "--magic-patch")) {
				magic_patch(target, &ctx, EB_MAGICPATCH_SIG);   g_iotype = 1; }
			else if (!strcmp(argv[n], "--magic-patch-slack")) {
				magic_patch(target, &ctx, EB_MAGICPATCH_SLACK); g_iotype = 1; }
			else if (!strcmp(argv[n], "--magic-patch-reset")) {
				magic_patch(target, &ctx, EB_MAGICPATCH_RESET); g_iotype = 1; }
			else if (!strcmp(argv[n], "--magic-patch-pk1")) {
				magic_patch(target, &ctx, EB_MAGICPATCH_PK1);   g_iotype = 1; }
			else if (!strcmp(argv[n], "--magic-patch-pk2")) {
				magic_patch(target, &ctx, EB_MAGICPATCH_PK2);   g_iotype = 1; }
			else if (!strcmp(argv[n], "--magic-patch-pk3")) {
				magic_patch(target, &ctx, EB_MAGICPATCH_PK3);   g_iotype = 1; }
			else if (!strcmp(argv[n], "--magic-patch-zb1")) {
				magic_patch(target, &ctx, EB_MAGICPATCH_ZB1);   g_iotype = 1; }
			else if (!strcmp(argv[n], "--magic-patch-zb2")) {
				magic_patch(target, &ctx, EB_MAGICPATCH_ZB2);   g_iotype = 1; }
			else if (!strcmp(argv[n], "--magic-patch-zb3")) {
				magic_patch(target, &ctx, EB_MAGICPATCH_ZB3);   g_iotype = 1; }
			else if (!strcmp(argv[n], "--magic-patch-dos")) {
				magic_patch(target, &ctx, EB_MAGICPATCH_DOS);   g_iotype = 1; }

			else if (!strcmp(argv[n], "--patch")) {
				/* patch_Elf32_Ehdr(target, &ctx); g_iotype = 1; */ }
		}
	}

	printf("|====================================================================\n");
	print_ehdr(&ctx);
	if (g_did_slack_count) {
		printf("|--------------------------------------------------------------------\n");
		printf("|=>>  [Slack Summary]\n");
		printf("|--------------------------------------------------------------------\n");
		printf("|  %-24s%6ld bytes\n", "ehdr fields:",           g_slack_ehdr);
		printf("|  %-24s%6ld bytes\n", "p_paddr fields:",        g_slack_paddr);
		printf("|  %-24s%6ld bytes\n", "PT_NOTE content:",       g_slack_note);
		printf("|  %-24s%6ld bytes\n", "sh_link/info/entsize:",  g_slack_shdr);
		printf("|  %-24s%6ld bytes\n", "gap + eof:",             g_slack_gap + g_slack_eof);
	}
	printf("|--------------------------------------------------------------------\n");
	if (g_slack < 0)
		printf("|=>>  Total Slack Space: Error\n");
	else
		printf("|=>>  Total Slack Space: %ld bytes\n", g_slack);
	printf("|--------------------------------------------------------------------\n");

	free(filebuf);
	fclose(target);
	return 0;
}
