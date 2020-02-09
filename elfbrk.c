#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>

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





/***************************************************************************************/
/*
 *	CODE START  ||  CODE START || CODE START || CODE START || CODE START || CODE START
*/
/***************************************************************************************/

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
		"elfbrk-%s elf file format fuzzer\n"
		"Usage: elfbrk <elf_file> [options]\n"
		"Options:\n"
		"  --help, -h, /?      show this message\n"
		"  --slack-count       enumerate available slack space\n"
		"  --patch             write slack patch to file (disabled)\n"
		"  --magic-patch       write elfbrk magic 0xBADC0DE0 patch\n"
		"     --magic-patch-reset     0x7F454C46 (\"ELF<DEL>\")\n"
		"     --magic-patch-slack     slack patch 0x90\n"
		"     --magic-patch-pk1       pkzip 0x0304 patch\n"
		"     --magic-patch-pk2       pkzip 0x0506 patch\n"
		"     --magic-patch-pk3       pkzip 0x0708 patch\n"
		"     --magic-patch-zb1       zipbrk 0x0304 patch\n"
		"     --magic-patch-zb2       zipbrk 0x0506 patch\n"
		"     --magic-patch-zb3       zipbrk 0x0708 patch\n"
		"     --magic-patch-dos       dos 0x4D5A patch (int 21h, int 03h)\n"
		"     --magic-patch-elf32     elf32 0x7F454C46 patch (reset)\n"
		"\n"
		"ex.\n"
		"  elfbrk /bin/ls --slack-count\n"
		"  elfbrk ./a.out --patch\n",
		EB_VERSION_STRING
	);
	exit(1);
}

void printbin(const void *buffer, uint16_t index_len, uint16_t total_len)
{
	uint32_t n, size;
	unsigned char *bin_stream;

	bin_stream = (unsigned char *)buffer;
	size = index_len * total_len;
	for ( n = 0; n < size; n++ )
		printf("%.2X ", bin_stream[n]);
}
	
int print_Elf32_Ehdr(Elf32_Ehdr *pe32hdr, uint16_t size)
{
	Elf32_Ehdr e32hdr;

	if ( size != sizeof(Elf32_Ehdr) ) {
		printf("print_Elf32_Ehdr: header size mismatch\n"); return 0; }
	memcpy(&e32hdr, pe32hdr, sizeof(e32hdr));

	printf("|=>>  [Elf32_Ehdr]:\n"
		   "|--------------------------------------------------------------------\n"
	);

	printf("| .e_ident           ");
	printbin(&e32hdr, sizeof(unsigned char), sizeof(e32hdr.e_ident)); printf("\n");
	printf("|    - ELFMAG        ");
	printbin(&e32hdr, sizeof(unsigned char), sizeof(ELFMAG)); printf("\n");
	printf("|    - EI_CLASS      ");
	printbin(&e32hdr.e_ident[EI_CLASS], sizeof(unsigned char), sizeof(e32hdr.e_ident[EI_CLASS])); printf("\n");
	printf("|    - EI_DATA       ");
	printbin(&e32hdr.e_ident[EI_DATA], sizeof(unsigned char), sizeof(e32hdr.e_ident[EI_DATA])); printf("\n");
	printf("|    - EI_VERSION    ");
	printbin(&e32hdr.e_ident[EI_VERSION], sizeof(unsigned char), sizeof(e32hdr.e_ident[EI_VERSION])); printf("\n");
	printf("|    - EI_PAD[%u]     ", EI_PADLEN);
	printbin(&e32hdr.e_ident[EI_PAD], sizeof(unsigned char), EI_PADLEN); printf("\n");

	printf("| .e_type            ");
	printbin(&e32hdr.e_type, sizeof(unsigned char), sizeof(e32hdr.e_type)); printf("\n");
	printf("| .e_machine         ");
	printbin(&e32hdr.e_machine, sizeof(unsigned char), sizeof(e32hdr.e_machine)); printf("\n");
	printf("| .e_version         ");
	printbin(&e32hdr.e_version, sizeof(unsigned char), sizeof(e32hdr.e_version)); printf("\n");
	printf("| .e_entry           ");
	printbin(&e32hdr.e_entry, sizeof(unsigned char), sizeof(e32hdr.e_entry)); printf("\n");
	printf("| .e_phoff           ");
	printbin(&e32hdr.e_phoff, sizeof(unsigned char), sizeof(e32hdr.e_phoff)); printf("\n");
	printf("| .e_shoff           ");
	printbin(&e32hdr.e_shoff, sizeof(unsigned char), sizeof(e32hdr.e_shoff)); printf("\n");
	printf("| .e_flags           ");
	printbin(&e32hdr.e_flags, sizeof(unsigned char), sizeof(e32hdr.e_flags)); printf("\n");
	printf("| .e_ehsize          ");
	printbin(&e32hdr.e_ehsize, sizeof(unsigned char), sizeof(e32hdr.e_ehsize)); printf("\n");
	printf("| .e_phentsize       ");
	printbin(&e32hdr.e_phentsize, sizeof(unsigned char), sizeof(e32hdr.e_phentsize)); printf("\n");
	printf("| .e_phnum           ");
	printbin(&e32hdr.e_phnum, sizeof(unsigned char), sizeof(e32hdr.e_phnum)); printf("\n");
	printf("| .e_shentsize       ");
	printbin(&e32hdr.e_shentsize, sizeof(unsigned char), sizeof(e32hdr.e_shentsize)); printf("\n");
	printf("| .e_shnum           ");
	printbin(&e32hdr.e_shnum, sizeof(unsigned char), sizeof(e32hdr.e_shnum)); printf("\n");
	printf("| .e_shstrndx        ");
	printbin(&e32hdr.e_shstrndx, sizeof(unsigned char), sizeof(e32hdr.e_shstrndx)); printf("\n");

	printf("|--------------------------------------------------------------------\n"
		   "|=>>  Elf32_Ehdr Member Definitions\n"
		   "|--------------------------------------------------------------------\n"
	);

	switch ( e32hdr.e_ident[EI_CLASS] )
	{
		case ELFCLASSNONE:
			printf("|  EI_CLASS:         ELFCLASSNONE [%u]\n", e32hdr.e_ident[EI_CLASS]); break;
		case ELFCLASS32:
			printf("|  EI_CLASS:         ELFCLASS32 [%u]\n", e32hdr.e_ident[EI_CLASS]); break;
		case ELFCLASS64:
			printf("|  EI_CLASS:         ELFCLASS64 [%u]\n", e32hdr.e_ident[EI_CLASS]); break;
		default:
			printf("|  EI_CLASS:         Undefined [%u]\n", e32hdr.e_ident[EI_CLASS]); break;
	}

	switch ( e32hdr.e_ident[EI_DATA] )
	{
		case ELFDATANONE:
			printf("|  EI_DATA:          ELFDATANONE [%u]\n", e32hdr.e_ident[EI_DATA]); break;
		case ELFDATA2LSB:
			printf("|  EI_DATA:          ELFDATA2LSB (Little Endian) [%u]\n", e32hdr.e_ident[EI_DATA]); break;
		case ELFDATA2MSB:
			printf("|  EI_DATA:          ELFDATA2MSB (Big Endian) [%u]\n", e32hdr.e_ident[EI_DATA]); break;
		default:
			printf("|  EI_DATA:          Undefined [%u]\n", e32hdr.e_ident[EI_DATA]); break;
	}

	switch ( e32hdr.e_ident[EI_VERSION] )
	{
		case EV_NONE:
			printf("|  EI_VERSION:       EV_NONE [%u]\n", e32hdr.e_ident[EI_VERSION]); break;
		case EV_CURRENT:
			printf("|  EI_VERSION:       EV_CURRENT [%u]\n", e32hdr.e_ident[EI_VERSION]); break;
		default:
			printf("|  EI_VERSION:       Undefined [%u]\n", e32hdr.e_ident[EI_VERSION]); break;
	}

	switch ( e32hdr.e_type )
	{
		case ET_NONE:
			printf("|  e_type:           ET_NONE [%u]\n", e32hdr.e_type); break;
		case ET_REL:
			printf("|  e_type:           ET_REL [%u]\n", e32hdr.e_type); break;
		case ET_EXEC:
			printf("|  e_type:           ET_EXEC [%u]\n", e32hdr.e_type); break;
		case ET_DYN:
			printf("|  e_type:           ET_DYN [%u]\n", e32hdr.e_type); break;
		case ET_CORE:
			printf("|  e_type:           ET_CORE [%u]\n", e32hdr.e_type); break;
		case ET_LOPROC:
			printf("|  e_type:           ET_LOPROC [%u]\n", e32hdr.e_type); break;
		case ET_HIPROC:
			printf("|  e_type:           ET_HIPROC [%u]\n", e32hdr.e_type); break;
		default:
			printf("|  e_type:           Undefined [%u]\n", e32hdr.e_type); break;
	}

	switch ( e32hdr.e_machine )
	{
		case EM_NONE:
			printf("|  e_machine:        EM_NONE [%u]\n", e32hdr.e_machine); break;
		case EM_M32:
			printf("|  e_machine:        EM_M32 [%u]\n", e32hdr.e_machine); break;
		case EM_SPARC:
			printf("|  e_machine:        EM_SPARC [%u]\n", e32hdr.e_machine); break;
		case EM_386:
			printf("|  e_machine:        EM_386 [%u]\n", e32hdr.e_machine); break;
		case EM_68K:
			printf("|  e_machine:        EM_68K [%u]\n", e32hdr.e_machine); break;
		case EM_88K:
			printf("|  e_machine:        EM_88K [%u]\n", e32hdr.e_machine); break;
		case EM_860:
			printf("|  e_machine:        EM_860 [%u]\n", e32hdr.e_machine); break;
		case EM_MIPS:
			printf("|  e_machine:        EM_MIPS [%u]\n", e32hdr.e_machine); break;
		case EM_AMD8664:
			printf("|  e_machine:        EM_AMD8664 [%u]\n", e32hdr.e_machine); break;
		default:
			printf("|  e_machine:        Undefined (");
			if ( e32hdr.e_ident[EI_CLASS] == ELFCLASS64 )
				printf("ia64/amd64");
			else
				printf("Unknown");
			printf(") [%u]\n", e32hdr.e_machine);
			break;
	}

	switch ( e32hdr.e_version )
	{
		case EV_NONE:
			printf("|  e_version:        EV_NONE [%lu]\n", e32hdr.e_version); break;
		case EV_CURRENT:
			printf("|  e_version:        EV_CURRENT [%lu]\n", e32hdr.e_version); break;
		default:
			printf("|  e_version:        Undefined [%lu]\n", e32hdr.e_version); break;
	}

	return 1;
}

int slack_Elf32_Ehdr(Elf32_Ehdr *pe32hdr, uint16_t hdrlen)
{
	int slack = 0;
	Elf32_Ehdr e32hdr;
	
	if ( hdrlen != sizeof(e32hdr) )
		return -1;
	memcpy(&e32hdr, pe32hdr, sizeof(e32hdr));
	
	printf("|  * Enumerating Elf32_Ehdr slack ...\n");
	
	/* .e_ident[EI_PAD] + .e_version */
	slack += sizeof(e32hdr.e_version);
	slack += EI_PADLEN;

	/* .e_phoff */
	if ( e32hdr.e_phoff == 0x00000000 )
	{
		slack += sizeof(e32hdr.e_phentsize);
		slack += sizeof(e32hdr.e_phnum);
	}

	/* .e_shoff */
	if ( e32hdr.e_shoff == 0x00000000 )
	{
		slack += sizeof(e32hdr.e_shentsize);
		slack += sizeof(e32hdr.e_shnum);
		slack += sizeof(e32hdr.e_shstrndx);
	}

	/* .e_flags */
	//e32hdr.e_flags = 0x90909090; slack += sizeof(e32hdr.e_flags);

	g_slack += (slack * 8);
	return slack;
}

int patch_Elf32_Ehdr(FILE *target, Elf32_Ehdr *pe32hdr, uint16_t hdrlen)
{
	Elf32_Ehdr e32hdr;

	if ( hdrlen != sizeof(e32hdr) )
		return -1;
	memcpy(&e32hdr, pe32hdr, sizeof(e32hdr));

	if ( target == NULL ) {
		printf("|  [!] Error opening NULL file."); return 0; }
	printf("|  * Applying Elf32_Ehdr patch ...\n");

	/* .e_ident[EI_PAD] + .e_version */
	if ( target != NULL ) {
		e32hdr.e_version = 0x90909090;
		memset(&e32hdr.e_ident[EI_PAD], 0x90, EI_PADLEN); }

	/* .e_phoff */
	if ( e32hdr.e_phoff == 0x00000000 )
	{
		if ( target != NULL ) {
			e32hdr.e_phentsize = 0x9090;
			e32hdr.e_phnum = 0x9090; }
	}

	/* .e_shoff */
	if ( e32hdr.e_shoff == 0x00000000 )
	{
		if ( target != NULL ) {
			e32hdr.e_shentsize = 0x9090;
			e32hdr.e_shnum = 0x9090;
			e32hdr.e_shstrndx = 0x9090; }
	}

	/* .e_flags */
	//e32hdr.e_flags = 0x90909090; slack += sizeof(e32hdr.e_flags);

	/* write patch to file */
	if ( target != NULL )
	{
		memcpy(pe32hdr, &e32hdr, sizeof(e32hdr));
		fseek(target, 0, SEEK_SET);
		fwrite(&e32hdr, hdrlen, 1, target);
		fflush(target);
	}

	return slack_Elf32_Ehdr(&e32hdr, hdrlen);
}

uint32_t magic_patch(FILE *target, Elf32_Ehdr *pe32hdr, uint16_t hdrlen, uint32_t mode)
{
	uint32_t sig = 0;

	/* magic patch elfbrk default */
	if ( mode == EB_MAGICPATCH_SIG )
	{
		sig = htonl(EB_EBSIG);
		printf("|  * Applying *magic patch* sig: 0x%.8X ...\n", EB_EBSIG);
	}
	/* magic slack patch */
	else if ( mode == EB_MAGICPATCH_SLACK )
	{
		sig = 0x90909090;
		g_slack += (sizeof(sig) * 8);
		printf("|  * Applying *magic slack patch*: 0x90909090 ...\n");
	}
	/* reset magic patch sig */
	else if ( mode == EB_MAGICPATCH_RESET )
	{
		sig = htonl(EB_RESETSIG);
		printf("|  * Resetting *magic patch* sig: 0x%.8X ...\n", EB_RESETSIG);
	}



	/* magic patch PKSIGx */
	else if ( mode == EB_MAGICPATCH_PK1 )
	{
		sig = htonl(EB_PKSIG1);
		printf("|  * Applying *magic pk1 patch* sig: 0x%.8X ...\n", EB_PKSIG1);
	}
	else if ( mode == EB_MAGICPATCH_PK2 )
	{
		sig = htonl(EB_PKSIG2);
		printf("|  * Applying *magic pk2 patch* sig: 0x%.8X ...\n", EB_PKSIG2);
	}
	else if ( mode == EB_MAGICPATCH_PK3 )
	{
		sig = htonl(EB_PKSIG3);
		printf("|  * Applying *magic pk3 patch* sig: 0x%.8X ...\n", EB_PKSIG3);
	}


	/* magic patch ZBSIGx */
	else if ( mode == EB_MAGICPATCH_ZB1 )
	{
		sig = htonl(EB_ZBSIG1);
		printf("|  * Applying *magic zb1 patch* sig: 0x%.8X ...\n", EB_ZBSIG1);
	}
	else if ( mode == EB_MAGICPATCH_ZB2 )
	{
		sig = htonl(EB_ZBSIG2);
		printf("|  * Applying *magic zb2 patch* sig: 0x%.8X ...\n", EB_ZBSIG2);
	}
	else if ( mode == EB_MAGICPATCH_ZB3 )
	{
		sig = htonl(EB_ZBSIG3);
		printf("|  * Applying *magic zb3 patch* sig: 0x%.8X ...\n", EB_ZBSIG3);
	}



	/* magic patch DOSSIG */
	else if ( mode == EB_MAGICPATCH_DOS )
	{
		sig = htonl(EB_DOSSIG);
		printf("|  * Applying *magic dos patch* sig: 0x%.8X ...\n", EB_DOSSIG);
	}

	/* set and write patch */
	memcpy(pe32hdr, &sig, sizeof(sig));
	if ( target != NULL )
	{
		fseek(target, 0, SEEK_SET);
		fwrite(pe32hdr, hdrlen, 1, target);
		fflush(target);
	}
	
	return sig;
}
		
	

int main(int argc, char **argv)
{
	Elf32_Ehdr e32hdr;
	uint32_t Elf32_Sig;
	FILE *target;
	unsigned char buffer[4096];
	unsigned char name[128];
	int n;

	g_slack = 0;
	g_iotype = 0;
	if ( argc >= 2 )
	{
		memset(name, 0, sizeof(name));
		strncpy(name, argv[1], sizeof(name)-1);
	}
	else
	{
		show_help();
		return 0;
	}


	for ( n = 2; n < argc; n++ )
	{
		if ( !strcmp(argv[n], "--help") || !strcmp(argv[n], "/?") || !strcmp(argv[n], "-h") )
		{
			show_help();
			return 0;
		}
	}

	memset(&e32hdr, 0, sizeof(e32hdr));


	/* Elf32 magic bit hack signature >:) */
	Elf32_Sig = htonl(ELFMAG);
	memcpy(&e32hdr.e_ident, &Elf32_Sig, sizeof(Elf32_Sig));


	memset(buffer, 0, sizeof(buffer));
	if ( (target = fopen(name, "rb+")) == NULL )
		printf("elfbrk: error opening file %s\n", name);
	else
	{
		fread(buffer, sizeof(e32hdr), sizeof(unsigned char), target);
		memcpy(&e32hdr, buffer, sizeof(e32hdr));
		//show_banner();
		printf("|--------------------------------------------------------------------\n"
			   "|=>>  Starting file dissection...\n");
		printf("|=>>  FILE: %s\n", name);
		if ( !memcmp(&e32hdr.e_ident, &Elf32_Sig, sizeof(Elf32_Sig)) )
			printf("|=>>  TYPE: Elf32\n");
		else
			printf("|=>>  TYPE: Unknown File Type\n");


		if ( argc >= 3 )
		{
			printf("|=>>  OPTIONS:");
			for ( n = 2; n < argc; n++ )
				printf("\n|        %s", argv[n]);
			printf("\n");
			printf("|====================================================================\n"
				   "|=>>  OPERATIONS:\n"
				   "|--------------------------------------------------------------------\n"
			);

			for ( n = 2; n < argc; n++ )
			{
				if ( !strcmp(argv[n], "--slack-count") )
					slack_Elf32_Ehdr(&e32hdr, sizeof(e32hdr));

				else if ( !strcmp(argv[n], "--magic-patch") ) {
					magic_patch(target, &e32hdr, sizeof(e32hdr), EB_MAGICPATCH_SIG); g_iotype = 1; }
				else if ( !strcmp(argv[n], "--magic-patch-slack") ) {
					magic_patch(target, &e32hdr, sizeof(e32hdr), EB_MAGICPATCH_SLACK); g_iotype = 1; }
				else if ( !strcmp(argv[n], "--magic-patch-reset") || !strcmp(argv[n], "--magic-patch-elf32") ) {
					magic_patch(target, &e32hdr, sizeof(e32hdr), EB_MAGICPATCH_RESET); g_iotype = 1; }

				else if ( !strcmp(argv[n], "--magic-patch-pk1") ) {
					magic_patch(target, &e32hdr, sizeof(e32hdr), EB_MAGICPATCH_PK1); g_iotype = 1; }
				else if ( !strcmp(argv[n], "--magic-patch-pk2") ) {
					magic_patch(target, &e32hdr, sizeof(e32hdr), EB_MAGICPATCH_PK2); g_iotype = 1; }
				else if ( !strcmp(argv[n], "--magic-patch-pk3") ) {
					magic_patch(target, &e32hdr, sizeof(e32hdr), EB_MAGICPATCH_PK3); g_iotype = 1; }
				else if ( !strcmp(argv[n], "--magic-patch-zb1") ) {
					magic_patch(target, &e32hdr, sizeof(e32hdr), EB_MAGICPATCH_ZB1); g_iotype = 1; }
				else if ( !strcmp(argv[n], "--magic-patch-zb2") ) {
					magic_patch(target, &e32hdr, sizeof(e32hdr), EB_MAGICPATCH_ZB2); g_iotype = 1; }
				else if ( !strcmp(argv[n], "--magic-patch-zb3") ) {
					magic_patch(target, &e32hdr, sizeof(e32hdr), EB_MAGICPATCH_ZB3); g_iotype = 1; }

				else if ( !strcmp(argv[n], "--magic-patch-dos") ) {
					magic_patch(target, &e32hdr, sizeof(e32hdr), EB_MAGICPATCH_DOS); g_iotype = 1; }

				else if ( !strcmp(argv[n], "--patch") ) {
					/* patch_Elf32_Ehdr(target, &e32hdr, sizeof(e32hdr)); g_iotype = 1; */ }
			}
		}

		printf("|====================================================================\n");
		print_Elf32_Ehdr(&e32hdr, sizeof(e32hdr));

		printf("|--------------------------------------------------------------------\n");
		if ( g_slack < 0 )
			printf("|=>>  Total Slack Space: Error %d\n", g_slack);
		else
			printf("|=>>  Total Slack Space: %ld bits\n", g_slack);
		printf("|--------------------------------------------------------------------\n");

		fclose(target);
	}
	return 0;
}
