/*
 * gtests/include/x86.h
 *
 * Copyright (C) 2018, Google LLC.
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 *
 */

#ifndef GTESTS_KVM_X86_H
#define GTESTS_KVM_X86_H

#include <assert.h>
#include <stdint.h>

#define X86_EFLAGS_FIXED	 (1u << 1)

#define X86_CR4_VME		(1ul << 0)
#define X86_CR4_PVI		(1ul << 1)
#define X86_CR4_TSD		(1ul << 2)
#define X86_CR4_DE		(1ul << 3)
#define X86_CR4_PSE		(1ul << 4)
#define X86_CR4_PAE		(1ul << 5)
#define X86_CR4_MCE		(1ul << 6)
#define X86_CR4_PGE		(1ul << 7)
#define X86_CR4_PCE		(1ul << 8)
#define X86_CR4_OSFXSR		(1ul << 9)
#define X86_CR4_OSXMMEXCPT	(1ul << 10)
#define X86_CR4_UMIP		(1ul << 11)
#define X86_CR4_VMXE		(1ul << 13)
#define X86_CR4_SMXE		(1ul << 14)
#define X86_CR4_FSGSBASE	(1ul << 16)
#define X86_CR4_PCIDE		(1ul << 17)
#define X86_CR4_OSXSAVE		(1ul << 18)
#define X86_CR4_SMEP		(1ul << 20)
#define X86_CR4_SMAP		(1ul << 21)
#define X86_CR4_PKE		(1ul << 22)

/* The enum values match the intruction encoding of each register */
enum x86_register {
	RAX = 0,
	RCX,
	RDX,
	RBX,
	RSP,
	RBP,
	RSI,
	RDI,
	R8,
	R9,
	R10,
	R11,
	R12,
	R13,
	R14,
	R15,
};

struct desc64 {
	uint16_t limit0;
	uint16_t base0;
	unsigned base1:8, type:5, dpl:2, p:1;
	unsigned limit1:4, zero0:3, g:1, base2:8;
	uint32_t base3;
	uint32_t zero1;
} __attribute__((packed));

struct desc_ptr {
	uint16_t size;
	uint64_t address;
} __attribute__((packed));

static inline uint64_t get_desc64_base(const struct desc64 *desc)
{
	return ((uint64_t)desc->base3 << 32) |
		(desc->base0 | ((desc->base1) << 16) | ((desc->base2) << 24));
}

static inline uint64_t rdtsc(void)
{
	uint32_t eax, edx;

	/*
	 * The lfence is to wait (on Intel CPUs) until all previous
	 * instructions have been executed.
	 */
	__asm__ __volatile__("lfence; rdtsc" : "=a"(eax), "=d"(edx));
	return ((uint64_t)edx) << 32 | eax;
}

static inline uint64_t rdtscp(uint32_t *aux)
{
	uint32_t eax, edx;

	__asm__ __volatile__("rdtscp" : "=a"(eax), "=d"(edx), "=c"(*aux));
	return ((uint64_t)edx) << 32 | eax;
}

static inline uint64_t rdmsr(uint32_t msr)
{
	uint32_t a, d;

	__asm__ __volatile__("rdmsr" : "=a"(a), "=d"(d) : "c"(msr) : "memory");

	return a | ((uint64_t) d << 32);
}

static inline void wrmsr(uint32_t msr, uint64_t value)
{
	uint32_t a = value;
	uint32_t d = value >> 32;

	__asm__ __volatile__("wrmsr" :: "a"(a), "d"(d), "c"(msr) : "memory");
}


static inline uint16_t inw(uint16_t port)
{
	uint16_t tmp;

	__asm__ __volatile__("in %%dx, %%ax"
		: /* output */ "=a" (tmp)
		: /* input */ "d" (port));

	return tmp;
}

static inline uint16_t get_es(void)
{
	uint16_t es;

	__asm__ __volatile__("mov %%es, %[es]"
			     : /* output */ [es]"=rm"(es));
	return es;
}

static inline uint16_t get_cs(void)
{
	uint16_t cs;

	__asm__ __volatile__("mov %%cs, %[cs]"
			     : /* output */ [cs]"=rm"(cs));
	return cs;
}

static inline uint16_t get_ss(void)
{
	uint16_t ss;

	__asm__ __volatile__("mov %%ss, %[ss]"
			     : /* output */ [ss]"=rm"(ss));
	return ss;
}

static inline uint16_t get_ds(void)
{
	uint16_t ds;

	__asm__ __volatile__("mov %%ds, %[ds]"
			     : /* output */ [ds]"=rm"(ds));
	return ds;
}

static inline uint16_t get_fs(void)
{
	uint16_t fs;

	__asm__ __volatile__("mov %%fs, %[fs]"
			     : /* output */ [fs]"=rm"(fs));
	return fs;
}

static inline uint16_t get_gs(void)
{
	uint16_t gs;

	__asm__ __volatile__("mov %%gs, %[gs]"
			     : /* output */ [gs]"=rm"(gs));
	return gs;
}

static inline uint16_t get_tr(void)
{
	uint16_t tr;

	__asm__ __volatile__("str %[tr]"
			     : /* output */ [tr]"=rm"(tr));
	return tr;
}

static inline uint64_t get_cr0(void)
{
	uint64_t cr0;

	__asm__ __volatile__("mov %%cr0, %[cr0]"
			     : /* output */ [cr0]"=r"(cr0));
	return cr0;
}

static inline uint64_t get_cr3(void)
{
	uint64_t cr3;

	__asm__ __volatile__("mov %%cr3, %[cr3]"
			     : /* output */ [cr3]"=r"(cr3));
	return cr3;
}

static inline uint64_t get_cr4(void)
{
	uint64_t cr4;

	__asm__ __volatile__("mov %%cr4, %[cr4]"
			     : /* output */ [cr4]"=r"(cr4));
	return cr4;
}

static inline void set_cr4(uint64_t val)
{
	__asm__ __volatile__("mov %0, %%cr4" : : "r" (val) : "memory");
}

static inline uint64_t get_gdt_base(void)
{
	struct desc_ptr gdt;
	__asm__ __volatile__("sgdt %[gdt]"
			     : /* output */ [gdt]"=m"(gdt));
	return gdt.address;
}

static inline uint64_t get_idt_base(void)
{
	struct desc_ptr idt;
	__asm__ __volatile__("sidt %[idt]"
			     : /* output */ [idt]"=m"(idt));
	return idt.address;
}

#define SET_XMM(__var, __xmm) \
	asm volatile("movq %0, %%"#__xmm : : "r"(__var) : #__xmm)

static inline void set_xmm(int n, unsigned long val)
{
	switch (n) {
	case 0:
		SET_XMM(val, xmm0);
		break;
	case 1:
		SET_XMM(val, xmm1);
		break;
	case 2:
		SET_XMM(val, xmm2);
		break;
	case 3:
		SET_XMM(val, xmm3);
		break;
	case 4:
		SET_XMM(val, xmm4);
		break;
	case 5:
		SET_XMM(val, xmm5);
		break;
	case 6:
		SET_XMM(val, xmm6);
		break;
	case 7:
		SET_XMM(val, xmm7);
		break;
	}
}

typedef unsigned long v1di __attribute__ ((vector_size (8)));
static inline unsigned long get_xmm(int n)
{
	assert(n >= 0 && n <= 7);

	register v1di xmm0 __asm__("%xmm0");
	register v1di xmm1 __asm__("%xmm1");
	register v1di xmm2 __asm__("%xmm2");
	register v1di xmm3 __asm__("%xmm3");
	register v1di xmm4 __asm__("%xmm4");
	register v1di xmm5 __asm__("%xmm5");
	register v1di xmm6 __asm__("%xmm6");
	register v1di xmm7 __asm__("%xmm7");
	switch (n) {
	case 0:
		return (unsigned long)xmm0;
	case 1:
		return (unsigned long)xmm1;
	case 2:
		return (unsigned long)xmm2;
	case 3:
		return (unsigned long)xmm3;
	case 4:
		return (unsigned long)xmm4;
	case 5:
		return (unsigned long)xmm5;
	case 6:
		return (unsigned long)xmm6;
	case 7:
		return (unsigned long)xmm7;
	}
	return 0;
}

#endif /* !GTESTS_KVM_X86_H */
