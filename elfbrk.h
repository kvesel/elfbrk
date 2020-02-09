#ifndef __ELFHDR_H__H4C587NY0C5G89VHV383JF3__
#define __ELFHDR_H__H4C587NY0C5G89VHV383JF3__
#include <stdint.h>

#define EB_VERSION_STRING	"0.1a"

#define Elf32_Addr		uint32_t
#define Elf32_Half		uint16_t
#define Elf32_Off		uint32_t
#define Elf32_Sword		uint32_t
#define Elf32_Word		uint32_t

/* e_ident definitions */
#define EI_MAG0		0	/* file identification */
#define EI_MAG1		1	/* file identification */
#define EI_MAG2		2	/* file identification */
#define EI_MAG3		3	/* file identification */
#define EI_CLASS	4	/* file class */
#define EI_DATA		5	/* data encoding */
#define EI_VERSION	6	/* file version */
#define EI_PAD		7	/* start of padding bytes */
#define EI_NIDENT	16	/* sizeof e_ident[] */
#define EI_PADLEN	(EI_NIDENT - EI_PAD)

/* e_type definitions */
#define ET_NONE		0x0000	/* no file type */
#define ET_REL		0x0001	/* relocatable file */
#define ET_EXEC		0x0002	/* executable file */
#define ET_DYN		0x0003	/* shared object file */
#define ET_CORE		0x0004	/* core file */
#define ET_LOPROC	0xFF00	/* processor-specific */
#define ET_HIPROC	0xFFFF	/* processor-specific */

/* e_machine definitions */
#define EM_NONE		0	/* no machine */
#define EM_M32		1	/* AT&T WE 32100 */
#define EM_SPARC	2	/* SPARC */
#define EM_386		3	/* Intel 80386 */
#define EM_68K		4	/* Motorola 68000 */
#define EM_88K		5	/* Motorola 88000 */
#define EM_860		7	/* Intel 80860 */
#define EM_MIPS		8	/* MIPS RS3000 */
#define EM_AMD8664	0x3E	/* Advanced Micro Devices X86-64 (alex) */

/* e_version definitions */
#define EV_NONE		0	/* invalid version */
#define EV_CURRENT	1	/* current version */

/* EI_MAGx definitions */
#define ELFMAG0		0x7F		/* <DEL> */
#define ELFMAG1		0x45		/* E */
#define ELFMAG2		0x4C		/* L */
#define ELFMAG3		0x46		/* F */
#define ELFMAG		0x7F454C46	/* sig = htonl(ELFMAG); */

/* EI_CLASS definitions */
#define ELFCLASSNONE	0	/* invalid class */
#define ELFCLASS32		1	/* 32-bit objects */
#define ELFCLASS64		2	/* 64-bit objects */

/* EI_DATA definitions */
#define ELFDATANONE	0
#define ELFDATA2LSB	1	/* 2's complement, least significant byte */
#define ELFDATA2MSB	2	/* 2's complement, most significant byte */


/* Special Section Indexes */
#define SHN_UNDEF		0x0000
#define SHN_LORESERVE	0xFF00
#define SHN_LOPROC		0xFF00
#define SHN_HIPROC		0xFF1F
#define SHN_ABS			0xFFF1
#define SHN_COMMON		0xFFF2
#define SHN_HIRESERVE	0xFFFF

/* sh_type definitions */
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
#define SHT_LOPROC		0x70000000
#define SHT_HIPROC		0x7FFFFFFF
#define SHT_LOUSER		0x80000000
#define SHT_HIUSER		0xFFFFFFFF

/* sh_flags definitions */
#define SHF_WRITE		1
#define SHF_ALLOC		2
#define SHF_EXECINSTR	4
#define SHF_MASKPROC	0xF0000000

/* Elf32_Sym definitions */
#define STN_UNDEF	0

/* st_info definitions */
#define ELF32_ST_BIND(b)	((b)>>4)
#define ELF32_ST_TYPE(t)	((t)&0xf)
#define ELF32_ST_INFO(b,t)	(((b)<<4)+((t)&0xf))

/* st_shndx definitions */
/* ELF32_ST_BIND */
#define STB_LOCAL	0
#define STB_GLOBAL	1
#define STB_WEAK	2
#define STB_LOPROC	13
#define STB_HIPROC	15

/* r_info definitions */
#define ELF32_R_SYM(s)		((s)>>8)
#define ELF32_R_TYPE(t)		((unsigned char)(t))
#define ELF32_R_INFO(s,t)	(((s)<<8)+(unsigned char)(t))

/* r_offset definitions */
#define R_386_NONE			0
#define R_386_32			1
#define R_386_PC32			2
#define R_386_GOT32			3
#define R_386_PLT32			4
#define R_386_COPY			5
#define R_386_GLOB_DAT		6
#define R_386_JMP_SLOT		7
#define R_386_RELATIVE		8
#define R_386_GOTOFF		9
#define R_386_GOTPC			10

/* p_type definitions */
#define PT_NULL		0
#define PT_LOAD		1
#define PT_DYNAMIC	2
#define PT_INTERP	3
#define PT_NOTE		4
#define PT_SHLIB	5
#define PT_PHDR		6
#define PT_LOPROC	0x70000000
#define PT_HIPROC	0x7FFFFFFF

/* d_ptr definitions */			/* d_un */
#define DT_NULL		0			/* ignored */
#define DT_NEEDED	1			/* d_val */
#define DT_PLTRELSZ	2			/* d_val */
#define DT_PLTGOT	3			/* d_ptr */
#define DT_HASH		4			/* d_ptr */
#define DT_STRTAB	5			/* d_ptr */
#define DT_SYMTAB	6			/* d_ptr */
#define DT_RELA		7			/* d_ptr */
#define DT_RELASZ	8			/* d_val */
#define DT_RELAENT	9			/* d_val */
#define DT_STRSZ	10			/* d_val */
#define DT_SYMENT	11			/* d_val */
#define DT_INIT		12			/* d_ptr */
#define DT_FINI		13			/* d_ptr */
#define DT_SONAME	14			/* d_val */
#define DT_RPATH	15			/* d_val */
#define DT_SYMBOLIC	16			/* ignored */
#define DT_REL		17			/* d_ptr */
#define DT_RELSZ	18			/* d_val */
#define DT_RELENT	19			/* d_val */
#define DT_PLTREL	20			/* d_val */
#define DT_DEBUG	21			/* d_ptr */
#define DT_TEXTREL	22			/* ignored */
#define DT_JMPREL	23			/* d_ptr */
#define DT_LOPROC	0x70000000	/* unspecified */
#define DT_HIPROC	0x7FFFFFFF	/* unspecified */


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


#pragma pack(push, 1)
typedef struct s_elf32_ehdr
{
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

typedef struct s_elf32_shdr
{
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

typedef struct s_elf32_sym
{
	Elf32_Word		st_name;
	Elf32_Addr		st_value;
	Elf32_Word		st_size;
	unsigned char	st_info;
	unsigned char	st_other;
	Elf32_Half		st_shndx;
} Elf32_Sym;

typedef struct s_elf32_rel
{
	Elf32_Addr	r_offset;
	Elf32_Word	r_info;
} Elf32_Rel;

typedef struct s_el32_rela
{
	Elf32_Addr	r_offset;
	Elf32_Word	r_info;
	Elf32_Sword	r_addend;
} Elf32_Rela;

typedef struct s_elf32_phdr
{
	Elf32_Word	p_type;
	Elf32_Off	p_offset;
	Elf32_Addr	p_vaddr;
	Elf32_Addr	p_paddr;
	Elf32_Word	p_filesz;
	Elf32_Word	p_memsz;
	Elf32_Word	p_flags;
	Elf32_Word	p_align;
} Elf32_Phdr;

typedef struct s_elf32_dyn
{
	Elf32_Sword	d_tag;
	union
	{
		Elf32_Word	d_val;
		Elf32_Word	d_ptr;
	} d_un;
} Elf32_Dyn;
#pragma pack(pop)
//extern Elf32_Dyn_DYNAMIC[];
long g_slack; /* total slack space located */
uint8_t g_iotype; /* 0 read-only, 1 write (def. 0) */

#endif //__ELFHDR_H__H4C587NY0C5G89VHV383JF3__
