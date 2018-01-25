/*
 * gtests/lib/kvm_util.c
 *
 * Copyright (C) 2018, Google LLC.
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 */

#define _GNU_SOURCE /* for program_invocation_short_name */
#define __STDC_FORMAT_MACROS
#include <ctype.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <linux/fs.h>
#include <linux/elf.h>

#include "asm/processor-flags.h"
#include "asm/msr.h"
#include "asm/msr-index.h"

#include "test_sparsebit.h"
#include "test_util.h"

#include "kvm_util.h"

#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))

#define PMEM_BASE 0x40000000

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

#ifndef PAGE_SHIFT
#define PAGE_SHIFT 12
#endif

/* For bitmap operations */

#ifndef BITS_PER_BYTE
#define BITS_PER_BYTE           8
#endif

#ifndef BITS_PER_LONG
#define BITS_PER_LONG (BITS_PER_BYTE * sizeof(long))
#endif

#define DIV_ROUND_UP(n, d)	(((n) + (d) - 1) / (d))
#define BITS_TO_LONGS(nr)       DIV_ROUND_UP(nr, BITS_PER_LONG)

/* Aligns x up to the next multiple of size. Size must be a power of 2. */
static void *align(void *x, size_t size)
{
	size_t mask = size - 1;
	TEST_ASSERT(size != 0 && !(size & (size - 1)),
		    "size not a power of 2: %lu", size);
	return (void *) (((size_t) x + mask) & ~mask);
}

/* Virtual translation table structure declarations */
struct pageMapL4Entry {
	uint64_t present:1;
	uint64_t writable:1;
	uint64_t user:1;
	uint64_t write_through:1;
	uint64_t cache_disable:1;
	uint64_t accessed:1;
	uint64_t ignored_06:1;
	uint64_t page_size:1;
	uint64_t ignored_11_08:4;
	uint64_t address:40;
	uint64_t ignored_62_52:11;
	uint64_t execute_disable:1;
};

struct pageDirectoryPointerEntry {
	uint64_t present:1;
	uint64_t writable:1;
	uint64_t user:1;
	uint64_t write_through:1;
	uint64_t cache_disable:1;
	uint64_t accessed:1;
	uint64_t ignored_06:1;
	uint64_t page_size:1;
	uint64_t ignored_11_08:4;
	uint64_t address:40;
	uint64_t ignored_62_52:11;
	uint64_t execute_disable:1;
};

struct pageDirectoryEntry {
	uint64_t present:1;
	uint64_t writable:1;
	uint64_t user:1;
	uint64_t write_through:1;
	uint64_t cache_disable:1;
	uint64_t accessed:1;
	uint64_t ignored_06:1;
	uint64_t page_size:1;
	uint64_t ignored_11_08:4;
	uint64_t address:40;
	uint64_t ignored_62_52:11;
	uint64_t execute_disable:1;
};

struct pageTableEntry {
	uint64_t present:1;
	uint64_t writable:1;
	uint64_t user:1;
	uint64_t write_through:1;
	uint64_t cache_disable:1;
	uint64_t accessed:1;
	uint64_t dirty:1;
	uint64_t reserved_07:1;
	uint64_t global:1;
	uint64_t ignored_11_09:3;
	uint64_t address:40;
	uint64_t ignored_62_52:11;
	uint64_t execute_disable:1;
};

/* Concrete definition of kvm_util_vm_t. */
struct userspace_mem_region {
	struct userspace_mem_region *next, *prev;
	struct kvm_userspace_memory_region region;
	enum vm_mem_backing_src_type backing_src_type;
	test_sparsebit_t *unused_phy_pages;
	int fd;
	off_t offset;
	bool caller_memory;
	void *host_mem;
	void *mmap_start;
	size_t mmap_size;
};
struct vcpu {
	struct vcpu *next, *prev;
	uint32_t id;
	int fd;
	struct kvm_run *state;
};
struct kvm_util_vm {
	int mode;
	int fd;
	unsigned int page_size;
	uint64_t ppgidx_max;  /* Maximum physical page index */
	struct vcpu *vcpu_head;
	struct userspace_mem_region *userspace_mem_region_head;
	test_sparsebit_t *vpages_valid;
	test_sparsebit_t *vpages_mapped;
	bool virt_l4_created;
	vm_paddr_t virt_l4;
};

/* File Scope Function Prototypes */
static int vcpu_mmap_sz(void);
static bool hugetlb_supported(const kvm_util_vm_t *vm, uint64_t npages);
static const struct userspace_mem_region *userspace_mem_region_find(
	const kvm_util_vm_t *vm, uint64_t start, uint64_t end);
static const struct vcpu *vcpu_find(const kvm_util_vm_t *vm,
	uint32_t vcpuid);
static vm_paddr_t phy_page_alloc(kvm_util_vm_t *vm,
	vm_paddr_t paddr_min, uint32_t memslot);
static struct userspace_mem_region *memslot2region(kvm_util_vm_t *vm,
	uint32_t memslot);
static int get_hugepfnmap_size(void *start_addr);

/* Capability
 *
 * Input Args:
 *   cap - Capability
 *
 * Output Args: None
 *
 * Return:
 *   On success, the Value corresponding to the capability (KVM_CAP_*)
 *   specified by the value of cap.  On failure a TEST_ASSERT failure
 *   is produced.
 *
 * Looks up and returns the value corresponding to the capability
 * (KVM_CAP_*) given by cap.
 */
int kvm_util_cap(long cap)
{
	int rv;
	int kvm_fd;

	kvm_fd = open(KVM_DEV_PATH, O_RDONLY);
	TEST_ASSERT(kvm_fd >= 0, "open %s failed, rv: %i errno: %i",
		KVM_DEV_PATH, kvm_fd, errno);

	rv = ioctl(kvm_fd, KVM_CHECK_EXTENSION, cap);
	TEST_ASSERT(rv != -1, "KVM_CHECK_EXTENSION IOCTL failed,\n"
		"  rv: %i errno: %i", rv, errno);

	close(kvm_fd);

	return rv;
}

/* VM Create
 *
 * Input Args:
 *   mode - VM Mode (e.g. VM_MODE_FLAT48PG)
 *   phy_pages - Physical memory pages
 *   perm - permission
 *
 * Output Args: None
 *
 * Return:
 *   Pointer to opaque structure that describes the created VM.
 *
 * Creates a VM with the mode specified by mode (e.g. VM_MODE_FLAT48PG).
 * When phy_pages is non-zero, a memory region of phy_pages physical pages
 * is created and mapped starting at guest physical address 0.  The file
 * descriptor to control the created VM is created with the permissions
 * given by perm (e.g. O_RDWR).
 */
kvm_util_vm_t *vm_create(enum guest_mode mode, uint64_t phy_pages, int perm)
{
	kvm_util_vm_t *vm;
	int kvm_fd;

	/* Allocate memory. */
	vm = calloc(1, sizeof(*vm));
	TEST_ASSERT(vm != NULL, "Insufficent Memory");

	vm->mode = mode;
	kvm_fd = open(KVM_DEV_PATH, perm);
	TEST_ASSERT(kvm_fd >= 0, "open %s failed, rv: %i errno: %i",
		KVM_DEV_PATH, kvm_fd, errno);

	/* Create VM. */
	vm->fd = ioctl(kvm_fd, KVM_CREATE_VM, NULL);
	TEST_ASSERT(vm->fd >= 0, "KVM_CREATE_VM ioctl failed, "
		"rv: %i errno: %i", vm->fd, errno);

	close(kvm_fd);

	/* Setup mode specific traits. */
	switch (vm->mode) {
	case VM_MODE_FLAT48PG:
		vm->page_size = 0x1000;  /* 4K */

		/* Limit to 48-bit canonical virtual addresses. */
		vm->vpages_valid = test_sparsebit_alloc();
		test_sparsebit_set_num(vm->vpages_valid,
			0, (1ULL << (48 - 1)) / vm->page_size);
		test_sparsebit_set_num(vm->vpages_valid,
			(~((1ULL << (48 - 1)) - 1)) / vm->page_size,
			(1ULL << (48 - 1)) / vm->page_size);

		/* Limit physical addresses to 52-bits. */
		vm->ppgidx_max = ((1ULL << 52) / vm->page_size) - 1;
		break;

	default:
		TEST_ASSERT(false, "Unknown guest mode, mode: 0x%x", mode);
	}

	/* Allocate and setup memory for guest. */
	vm->vpages_mapped = test_sparsebit_alloc();
	if (phy_pages != 0)
		vm_userspace_mem_region_add(vm, NULL,
		0, 0, phy_pages, 0);

	return vm;
}

/* Create a VM with reasonable defaults
 *
 * Input Args:
 *   vcpuid - The id of the single VCPU to add to the VM.
 *   guest_code - The vCPU's entry point
 *
 * Output Args: None
 *
 * Return:
 *   Pointer to opaque structure that describes the created VM.
 */
kvm_util_vm_t *vm_create_default(uint32_t vcpuid, void *guest_code)
{
	kvm_util_vm_t *vm;

	/* Create VM */
	vm = vm_create(VM_MODE_FLAT48PG, DEFAULT_GUEST_PHY_PAGES, O_RDWR);

	/* Setup guest code */
	kvm_util_vm_elf_load(vm, program_invocation_name, 0, 0);

	/* Setup IRQ Chip */
	vm_create_irqchip(vm);

	/* Add the first vCPU. */
	vm_vcpu_add_default(vm, vcpuid, guest_code);

	return vm;
}

/* Adds a vCPU with reasonable defaults (i.e., a stack)
 *
 * Input Args:
 *   vcpuid - The id of the VCPU to add to the VM.
 *   guest_code - The vCPU's entry point
 */
void vm_vcpu_add_default(kvm_util_vm_t *vm, uint32_t vcpuid, void *guest_code)
{
	struct kvm_mp_state mp_state;
	struct kvm_regs regs;
	vm_vaddr_t stack_vaddr;
	stack_vaddr = vm_vaddr_alloc(vm, DEFAULT_STACK_PGS * getpagesize(),
				     DEFAULT_GUEST_STACK_VADDR_MIN, 0, 0);

	/* Create VCPU */
	vm_vcpu_add(vm, vcpuid);

	/* Setup guest general purpose registers */
	vcpu_regs_get(vm, vcpuid, &regs);
	regs.rflags = regs.rflags | 0x2;
	regs.rsp = stack_vaddr + (DEFAULT_STACK_PGS * getpagesize());
	regs.rip = (unsigned long) guest_code;
	vcpu_regs_set(vm, vcpuid, &regs);

	/* Setup the MP state */
	mp_state.mp_state = 0;
	vcpu_set_mp_state(vm, vcpuid, &mp_state);
}

/* Create a default VM for VMX tests.
 *
 * Input Args:
 *   vcpuid - The id of the single VCPU to add to the VM.
 *   guest_code - The vCPU's entry point
 *
 * Output Args: None
 *
 * Return:
 *   Pointer to opaque structure that describes the created VM.
 */
kvm_util_vm_t *
vm_create_default_vmx(uint32_t vcpuid, vmx_guest_code_t guest_code)
{
	struct kvm_cpuid2 *cpuid;
	kvm_util_vm_t *vm;
	vm_vaddr_t vmxon_vaddr;
	vm_paddr_t vmxon_paddr;
	vm_vaddr_t vmcs_vaddr;
	vm_paddr_t vmcs_paddr;

	vm = vm_create_default(vcpuid, (void *) guest_code);

	/* Enable nesting in CPUID */
	cpuid = allocate_kvm_cpuid2();
	kvm_get_supported_cpuid(cpuid);
	find_cpuid_entry(cpuid, 0x1)->ecx |= (1 << 5) /* VMX */;
	vcpu_set_cpuid(vm, vcpuid, cpuid);
	free(cpuid);

	/* Setup of a region of guest memory for the vmxon region. */
	vmxon_vaddr = vm_vaddr_alloc(vm, getpagesize(), 0, 0, 0);
	vmxon_paddr = addr_vmvirt2vmphy(vm, vmxon_vaddr);

	/* Setup of a region of guest memory for a vmcs. */
	vmcs_vaddr = vm_vaddr_alloc(vm, getpagesize(), 0, 0, 0);
	vmcs_paddr = addr_vmvirt2vmphy(vm, vmcs_vaddr);

	vcpu_args_set(vm, vcpuid, 4, vmxon_vaddr, vmxon_paddr, vmcs_vaddr,
		      vmcs_paddr);

	return vm;
}

/*
 * Getter for the VM's fd.
 */
int vm_fd(const kvm_util_vm_t *vm)
{
	return vm->fd;
}

/*
 * Getter for a VCPU's fd.
 */
int vcpu_fd(const kvm_util_vm_t *vm, uint32_t vcpuid)
{
	return vcpu_find(vm, vcpuid)->fd;
}

/* VM Free
 *
 * Input Args: None
 *
 * Output Args: None
 *
 * Input/Output Args:
 *   vmpp - Pointer to pointer to opaque type that describes the VM.
 *
 * Return: None
 *
 * Destroys and frees the VM pointed to by *vmpp.  On success, the
 * contents of *vmpp is poisoned, such that any further use causes
 * a SEGV.
 */
void kvm_util_vm_free(kvm_util_vm_t **vmpp)
{
	int rv;
	kvm_util_vm_t *vmp = *vmpp;

	if (vmp == NULL)
		return;

	/* Free userspace_mem_regions. */
	while (vmp->userspace_mem_region_head) {
		struct userspace_mem_region *region
			= vmp->userspace_mem_region_head;

		region->region.memory_size = 0;
		rv = ioctl(vmp->fd, KVM_SET_USER_MEMORY_REGION,
			&region->region);
		TEST_ASSERT(rv == 0, "KVM_SET_USER_MEMORY_REGION IOCTL failed, "
			"rv: %i errno: %i", rv, errno);

		vmp->userspace_mem_region_head = region->next;
		test_sparsebit_free(&region->unused_phy_pages);
		switch (region->backing_src_type) {
		case VM_MEM_SRC_PMEM_HUGE:
			rv = get_hugepfnmap_size(region->mmap_start);
			/*
			 * Users of /dev/pmem may not fault in region->mmap_size
			 * entirely. e.g. in the demand paging tests.
			 * Hence, the ASSERT below can only check if HugePFNMap
			 * is within a range.
			 */
			TEST_ASSERT(rv > 0 && rv <= (region->mmap_size / 1024),
					"HugePFNMap: %d out of range", rv);

			rv = munmap(region->mmap_start, region->mmap_size);
			TEST_ASSERT(rv == 0, "munmap failed, rv: %i errno: %i",
				rv, errno);
			break;
		case VM_MEM_SRC_PMEM_SMALL:
			rv = get_hugepfnmap_size(region->mmap_start);
			TEST_ASSERT(rv == 0, "unexpected HugePFNMap size: %d",
					rv);

			rv = munmap(region->mmap_start, region->mmap_size);
			TEST_ASSERT(rv == 0, "munmap failed, rv: %i errno: %i",
				rv, errno);
			break;
		case VM_MEM_SRC_ANONYMOUS:
		case VM_MEM_SRC_ANONYMOUS_THP:
		case VM_MEM_SRC_ANONYMOUS_HUGETLB:
		case VM_MEM_SRC_FD_PRIVATE:
			rv = munmap(region->mmap_start, region->mmap_size);
			TEST_ASSERT(rv == 0, "munmap failed, rv: %i errno: %i",
				rv, errno);
			break;

		default:
			TEST_ASSERT((region->backing_src_type
					== VM_MEM_SRC_CALLER_MAINTAINED)
				|| (region->backing_src_type
					== VM_MEM_SRC_DIR),
				"Unexpected backing_source: 0x%i",
				region->backing_src_type);
			/* Intentional, nothing to do */
			break;
		}

		free(region);
	}

	/* Free VCPUs. */
	while (vmp->vcpu_head)
		vm_vcpu_rm(vmp, vmp->vcpu_head->id);

	/* Free sparsebit arrays. */
	test_sparsebit_free(&vmp->vpages_valid);
	test_sparsebit_free(&vmp->vpages_mapped);

	/* Close file descriptor for the VM. */
	rv = close(vmp->fd);
	TEST_ASSERT(rv == 0, "Close of vm fd failed,\n"
		"  vmp->fd: %i rv: %i errno: %i", vmp->fd, rv, errno);

	/* Free the structure describing the VM. */
	free(vmp);
	*vmpp = NULL;
}

#if 0 
/* Allocate kvm_dirty_log
 *
 * Input Args:
 *   region - The memslot to track.
 *
 * Output Args: None
 *
 * Return:
 *   A pointer to the allocated kvm_dirty_log struct. Never returns NULL.
 *
 * Allocates a kvm_dirty_log struct for a corresponding memslot.
 */
struct kvm_dirty_log *
allocate_kvm_dirty_log(const struct kvm_userspace_memory_region *region)
{
	struct kvm_dirty_log *dirty_log;
	size_t bitmap_size = region->memory_size / 4096 / 8;

	dirty_log = calloc(1, sizeof(*dirty_log));
	TEST_ASSERT(dirty_log, "Failed to allocate struct kvm_dirty_log.");

	dirty_log->slot = region->slot;
	dirty_log->dirty_bitmap = calloc(1, bitmap_size);
	TEST_ASSERT(dirty_log->dirty_bitmap,
		    "Failed to allocate dirty_bitmap (%lu bytes).",
		    bitmap_size);

	return dirty_log;
}
#endif

/* VM Get Dirty Log
 *
 * Input Args:
 *   vm - Virtual Machine
 *
 * Output Args: None
 *
 * Input/Output Args:
 *   logp - pointer to kvm dirty log
 *
 * Return:
 *   Return value from KVM_GET_DIRTY_LOG IOCTL call.
 *
 * Performs the KVM_GET_DIRTY_LOG IOCTL call to obtain the dirty log
 * for the kvm memory slot given by logp->slot.
 */
int kvm_util_vm_get_dirty_log(const kvm_util_vm_t *vm,
	struct kvm_dirty_log *logp)
{
	int rv;

	rv = ioctl(vm->fd, KVM_GET_DIRTY_LOG, logp);

	return rv;
}

/* Memory Compare, host virtual to guest virtual
 *
 * Input Args:
 *   hvirt - Starting host virtual address
 *   vm - Virtual Machine
 *   vmvirt - Starting guest virtual address
 *   len - number of bytes to compare
 *
 * Output Args: None
 *
 * Input/Output Args: None
 *
 * Return:
 *   Returns 0 if the bytes starting at hvirt for a length of len
 *   are equal the guest virtual bytes starting at vmvirt.  Returns
 *   a value < 0, if bytes at hvirt are less than those at vmvirt.
 *   Otherwise a value > 0 is returned.
 *
 * Compares the bytes starting at the host virtual address hvirt, for
 * a length of len, to the guest bytes starting at the guest virtual
 * address given by vmvirt.
 */
int kvm_util_memcmp_hvirt_gvirt(const host_vaddr_t hvirt,
	const kvm_util_vm_t *vm, const vm_vaddr_t vmvirt, size_t len)
{
	size_t amt;

	/* Compare a batch of bytes until either a match is found
	 * or all the bytes have been compared.
	 */
	for (uintptr_t offset = 0; offset < len; offset += amt) {
		host_vaddr_t ptr1 = hvirt + offset;

		/* Determine host address for guest virtual address
		 * at offset.
		 */
		host_vaddr_t ptr2 = addr_vmvirt2hvirt(vm, vmvirt + offset);

		/* Determine amount to compare on this pass.
		 * Don't allow the comparsion to cross a page boundary.
		 */
		amt = len - offset;
		if (((uintptr_t) ptr1 / vm->page_size)
			!= (((uintptr_t) ptr1 + amt) / vm->page_size))
			amt = vm->page_size - ((uintptr_t) ptr1
				% vm->page_size);
		if (((uintptr_t) ptr2 / vm->page_size)
			!= (((uintptr_t) ptr2 + amt) / vm->page_size))
			amt = vm->page_size - ((uintptr_t) ptr2
				% vm->page_size);
		TEST_ASSERT((((uintptr_t) ptr1 / vm->page_size)
				== (((uintptr_t) ptr1 + amt - 1)
					/ vm->page_size))
			&& (((uintptr_t) ptr2 / vm->page_size)
				== (((uintptr_t) ptr2 + amt - 1)
					/ vm->page_size)),
			"Attempt to cmp host to guest memory across a page "
			"boundary,\n"
			"  ptr1: %p ptr2: %p\n"
			"  amt: 0x%zx page_size: 0x%x",
			ptr1, ptr2, amt, vm->page_size);

		/* Perform the comparison.  If there is a difference
		 * return that result to the caller, otherwise need
		 * to continue on looking for a mismatch.
		 */
		int rv = memcmp(ptr1, ptr2, amt);
		if (rv != 0)
			return rv;
	}

	/* No mismatch found.  Let the caller know the two memory
	 * areas are equal.
	 */
	return 0;
}

/* VM ELF Load
 *
 * Input Args:
 *   filename - Path to ELF file
 *
 * Output Args: None
 *
 * Input/Output Args:
 *   vm - Pointer to opaque type that describes the VM.
 *
 * Return: None, TEST_ASSERT failures for all error conditions
 *
 * Loads the program image of the ELF file specified by filename,
 * into the virtual address space of the VM pointed to by vm.  On entry
 * the VM needs to not be using any of the virtual address space used
 * by the image and it needs to have sufficient available physical pages, to
 * back the virtual pages used to load the image.
 */
void kvm_util_vm_elf_load(kvm_util_vm_t *vm, const char *filename,
	uint32_t data_memslot, uint32_t vttbl_memslot)
{
	off_t offset, offset_rv;

	/* Open the ELF file. */
	int fd;
	fd = open(filename, O_RDONLY);
	TEST_ASSERT(fd >= 0, "Failed to open ELF file,\n"
		"  filename: %s\n"
		"  rv: %i errno: %i", filename, fd, errno);

	/* Read in the ELF header. */
	Elf64_Ehdr hdr;
	test_elfhdr_get(filename, &hdr);

	/* For each program header.
	 * The following ELF header members specify the location
	 * and size of the program headers:
	 *
	 *   e_phoff - File offset to start of program headers
	 *   e_phentsize - Size of each program header
	 *   e_phnum - Number of program header entries
	 */
	for (unsigned int n1 = 0; n1 < hdr.e_phnum; n1++) {
		/* Seek to the beginning of the program header. */
		offset = hdr.e_phoff + (n1 * hdr.e_phentsize);
		offset_rv = lseek(fd, offset, SEEK_SET);
		TEST_ASSERT(offset_rv == offset,
			"Failed to seek to begining of program header %u,\n"
			"  filename: %s\n"
			"  rv: %jd errno: %i",
			n1, filename, (intmax_t) offset_rv, errno);

		/* Read in the program header. */
		Elf64_Phdr phdr;
		test_read(fd, &phdr, sizeof(phdr));

		/* Skip if this header doesn't describe a loadable segment. */
		if (phdr.p_type != PT_LOAD)
			continue;

		/* Allocate memory for this segment within the VM. */
		TEST_ASSERT(phdr.p_memsz > 0, "Unexpected loadable segment "
			"memsize of 0,\n"
			"  phdr index: %u p_memsz: 0x%" PRIx64,
			n1, (uint64_t) phdr.p_memsz);
		vm_vaddr_t seg_vstart = phdr.p_vaddr;
		seg_vstart &= ~(vm_vaddr_t)(vm->page_size - 1);
		vm_vaddr_t seg_vend = phdr.p_vaddr + phdr.p_memsz - 1;
		seg_vend |= vm->page_size - 1;
		size_t seg_size = seg_vend - seg_vstart + 1;

		vm_vaddr_t vaddr = vm_vaddr_alloc(vm, seg_size, seg_vstart,
			data_memslot, vttbl_memslot);
		TEST_ASSERT(vaddr == seg_vstart, "Unable to allocate "
			"virtual memory for segment at requested min addr,\n"
			"  segment idx: %u\n"
			"  seg_vstart: 0x%lx\n"
			"  vaddr: 0x%lx",
			n1, seg_vstart, vaddr);
		memset(addr_vmvirt2hvirt(vm, vaddr), 0, seg_size);
		/* TODO(lhuemill): Set permissions of each memory segment
		 * based on the least-significant 3 bits of phdr.p_flags.
		 */

		/* Load portion of initial state that is contained within
		 * the ELF file.
		 */
		if (phdr.p_filesz) {
			offset_rv = lseek(fd, phdr.p_offset, SEEK_SET);
			TEST_ASSERT(offset_rv == phdr.p_offset,
				"Seek to program segment offset failed,\n"
				"  program header idx: %u errno: %i\n"
				"  offset_rv: 0x%jx\n"
				"  expected: 0x%jx\n",
				n1, errno, (intmax_t) offset_rv,
				(intmax_t) phdr.p_offset);
			test_read(fd, addr_vmvirt2hvirt(vm, phdr.p_vaddr),
				phdr.p_filesz);
		}
	}
}

/* VM Clock Get
 *
 * Input Args:
 *   vm - Virtual Machine
 *
 * Output Args:
 *   clockp - Where to store the current time.
 *
 * Return:
 *   0 on success, -1 on failure, with errno specifying reason for failure.
 *
 * Obtains the current time for the vm specified by vm and stores it
 * at the location specified by clockp.
 */
int vm_clock_get(const kvm_util_vm_t *vm, struct kvm_clock_data *clockp)
{
	int rv;

	rv = ioctl(vm->fd, KVM_GET_CLOCK, clockp);

	return rv;
}

/* VM Clock Set
 *
 * Input Args:
 *   vm - Virtual Machine
 *   clockp - Pointer to time to be set
 *
 * Output Args: None
 *
 * Return:
 *   0 on success, -1 on failure, with errno specifying reason for failure.
 *
 * Sets the time of the VM specified by vm to the time pointed to by clockp.
 */
int vm_clock_set(kvm_util_vm_t *vm, const struct kvm_clock_data *clockp)
{
	int rv;

	rv = ioctl(vm->fd, KVM_SET_CLOCK, clockp);

	return rv;
}

/* Allocate an instance of struct kvm_cpuid2
 *
 * Input Args: None
 *
 * Output Args: None
 *
 * Return: A pointer to the allocated struct. The caller is responsible
 * for freeing this struct.
 *
 * Since kvm_cpuid2 uses a 0-length array to allow a the size of the
 * array to be decided at allocation time, allocation is slightly
 * complicated. This function uses a reasonable default length for
 * the array and performs the appropriate allocation.
 */
struct kvm_cpuid2 *allocate_kvm_cpuid2(void)
{
	struct kvm_cpuid2 *cpuid;
	int nent = 100; /* copied from vanadium */
	size_t size;

	size = sizeof(*cpuid);
	size += nent * sizeof(struct kvm_cpuid_entry2);
	cpuid = malloc(size);
	TEST_ASSERT(cpuid != NULL, "Insufficient memory.");

	cpuid->nent = nent;

	return cpuid;
}

/* KVM Supported CPUID Get
 *
 * Input Args: None
 *
 * Output Args:
 *   cpuid - The supported KVM CPUID
 *
 * Return: void
 *
 * Get the guest CPUID supported by KVM.
 */
void kvm_get_supported_cpuid(struct kvm_cpuid2 *cpuid)
{
	int rv;
	int kvm_fd;

	kvm_fd = open(KVM_DEV_PATH, O_RDONLY);
	TEST_ASSERT(kvm_fd >= 0, "open %s failed, rv: %i errno: %i",
		KVM_DEV_PATH, kvm_fd, errno);

	rv = ioctl(kvm_fd, KVM_GET_SUPPORTED_CPUID, cpuid);
	TEST_ASSERT(rv == 0, "KVM_GET_SUPPORTED_CPUID failed %d %d\n",
		    rv, errno);

	close(kvm_fd);
}

/* Locate a cpuid entry.
 *
 * Input Args:
 *   cpuid: The cpuid.
 *   function: The function of the cpuid entry to find.
 *
 * Output Args: None
 *
 * Return: A pointer to the cpuid entry. Never returns NULL.
 */
struct kvm_cpuid_entry2 *
find_cpuid_index_entry(struct kvm_cpuid2 *cpuid, uint32_t function,
		       uint32_t index)
{
	struct kvm_cpuid_entry2 *entry = NULL;
	int i;

	for (i = 0; i < cpuid->nent; i++) {
		if (cpuid->entries[i].function == function &&
		    cpuid->entries[i].index == index) {
			entry = &cpuid->entries[i];
			break;
		}
	}

	TEST_ASSERT(entry, "Guest CPUID entry not found: (EAX=%x, ECX=%x).",
		    function, index);
	return entry;
}

/* VM VCPU CPUID Set
 *
 * Input Args:
 *   vm - Virtual Machine
 *   vcpuid - VCPU id
 *   cpuid - The CPUID values to set.
 *
 * Output Args: None
 *
 * Return: void
 *
 * Set the VCPU's CPUID.
 */
void vcpu_set_cpuid(kvm_util_vm_t *vm,
		uint32_t vcpuid, const struct kvm_cpuid2 *cpuid)
{
	int rv;
	const struct vcpu *vcpu;

	vcpu = vcpu_find(vm, vcpuid);
	TEST_ASSERT(vcpu != NULL, "vcpu not found, vcpuid: %u", vcpuid);

	rv = ioctl(vcpu->fd, KVM_SET_CPUID2, cpuid);
	TEST_ASSERT(rv == 0, "KVM_SET_CPUID2 failed, rv: %i errno: %i",
		    rv, errno);

}

static bool has_hugepfn_flag(char *str)
{
	char *saveptr;
	char *tok;

	do {
		tok = strtok_r(str, " ", &saveptr);
		str = NULL;

		if (!strcmp("hp", tok))
			return true;
	} while (tok);

	return false;
}

static int get_hugepfnmap_size(void *start_addr)
{
	FILE *fp = fopen("/proc/self/smaps", "r");
	bool found_map = false;
	char *line, *path, c;
	void *start, *end;
	unsigned long offset;
	int major, minor, inode, sz = 0, ret = 0;

	if (!fp)
		return -ENOENT;

	while (1) {
		int r;

		r = fscanf(fp, "%m[^\n]%c", &line, &c);

		if (r == 1)
			free(line);

		if (r == EOF || r == 1)
			goto out;

		if (isdigit(line[0])) {
			char bits[4];

			r = sscanf(line, "%lx-%lx %4c %lx %x:%x %d %m[^\n]",
					(unsigned long *) &start,
					(unsigned long *) &end,
					bits, &offset, &major, &minor,
					&inode, &path);

			if ((unsigned long) start_addr == (unsigned long) start)
				found_map = true;

		} else if (found_map && (strstr(line, "HugePFNMap:") == line)) {
			r = sscanf(line, "HugePFNMap: %d kB", &sz);

			if (!sz)
				break;
		} else if (found_map && (strstr(line, "VmFlags:") == line)) {

			if (has_hugepfn_flag(line + strlen("VmFlags:")))
				ret = sz;
			break;
		}

		free(line);
	}

	free(line);
out:
	fclose(fp);
	return ret;
}

/* VM Userspace Memory Region Add
 *
 * Input Args:
 *   vm - Virtual Machine
 *   backing_src - Storage source for this region.
 *                 NULL to use anonymous memory.
 *   guest_paddr - Starting guest physical address
 *   slot - KVM region slot
 *   npages - Number of physical pages
 *   flags - KVM memory region flags (e.g. KVM_MEM_LOG_DIRTY_PAGES)
 *
 * Output Args: None
 *
 * Return: None
 *
 * Allocates a memory area of the number of pages specified by npages
 * and maps it to the VM specified by vm, at a starting physical address
 * given by guest_paddr.  The region is created with a KVM region slot
 * given by slot, which must be unique and < KVM_MEM_SLOTS_NUM.  The
 * region is created with the flags given by flags.
 */
void vm_userspace_mem_region_add(kvm_util_vm_t *vm,
	struct vm_mem_backing_src *backing_src,
	uint64_t guest_paddr, uint32_t slot, uint64_t npages,
	uint32_t flags)
{
	int rv;
	unsigned long pmem_size = 0;
	struct userspace_mem_region *region;
	size_t huge_page_size = KVM_UTIL_PGS_PER_HUGEPG * vm->page_size;

	/* For now (may change in the future), use anonymous mmap as the
	 * default backing source.  In the future, the default backing
	 * source can be changed to any source that doesn't take a
	 * backing arg.
	 */
	enum vm_mem_backing_src_type src_type
		= (backing_src) ? backing_src->type : VM_MEM_SRC_ANONYMOUS;

	TEST_ASSERT(src_type != VM_MEM_SRC_DIR,
		"Not Yet Supported, src_type: 0x%x", src_type);

	TEST_ASSERT((guest_paddr % vm->page_size) == 0, "Guest physical "
		"address not on a page boundary.\n"
		"  guest_paddr: 0x%lx vm->page_size: 0x%x",
		guest_paddr, vm->page_size);
	TEST_ASSERT((((guest_paddr / vm->page_size) + npages) - 1)
		<= vm->ppgidx_max, "Physical range beyond maximum "
		"supported physical address,\n"
		"  guest_paddr: 0x%lx npages: 0x%lx\n"
		"  vm->ppgidx_max: 0x%lx vm->page_size: 0x%x",
		guest_paddr, npages, vm->ppgidx_max, vm->page_size);

	/* Confirm a mem region with an overlapping address doesn't
	 * already exist.
	 */
	region = (struct userspace_mem_region *) userspace_mem_region_find(
		vm, guest_paddr, guest_paddr + npages * vm->page_size);
	if (region != NULL)
		TEST_ASSERT(false, "overlapping userspace_mem_region already "
			"exists\n"
			"  requested guest_paddr: 0x%lx npages: 0x%lx "
			"page_size: 0x%x\n"
			"  existing guest_paddr: 0x%lx size: 0x%lx",
			guest_paddr, npages, vm->page_size,
			(uint64_t) region->region.guest_phys_addr,
			(uint64_t) region->region.memory_size);

	/* Confirm no region with the requested slot already exists. */
	for (region = vm->userspace_mem_region_head; region;
		region = region->next) {
		if (region->region.slot == slot)
			break;
		if ((guest_paddr <= (region->region.guest_phys_addr
				+ region->region.memory_size))
			&& ((guest_paddr + npages * vm->page_size)
				>= region->region.guest_phys_addr))
			break;
	}
	if (region != NULL)
		TEST_ASSERT(false, "A mem region with the requested slot "
			"or overlapping physical memory range already exists.\n"
			"  requested slot: %u paddr: 0x%lx npages: 0x%lx\n"
			"  existing slot: %u paddr: 0x%lx size: 0x%lx",
			slot, guest_paddr, npages,
			region->region.slot,
			(uint64_t) region->region.guest_phys_addr,
			(uint64_t) region->region.memory_size);

	/* Allocate and initialize new mem region structure. */
	region = calloc(1, sizeof(*region));
	TEST_ASSERT(region != NULL, "Insufficient Memory");
	region->backing_src_type = src_type;
	region->fd = (src_type == VM_MEM_SRC_FD_PRIVATE)
		? backing_src->fd_private.fd : -1;
	switch (src_type) {
	case VM_MEM_SRC_PMEM_SMALL:
		region->caller_memory = false;
		region->mmap_size = npages * vm->page_size;

		TEST_ASSERT(backing_src->pmem.pmem_fd > 0,
				"pmem fd not initialized: %d",
				backing_src->pmem.pmem_fd);

		rv = ioctl(backing_src->pmem.pmem_fd, BLKGETSIZE64, &pmem_size);
		TEST_ASSERT(rv == 0, "err getting Pmem size\n");

		TEST_ASSERT(region->mmap_size <= pmem_size,
				"requested size: %ld, available pmem: %ld\n",
				region->mmap_size, pmem_size);
		/* Force small page mappings */
		region->mmap_start = mmap((void *) (PMEM_BASE - PAGE_SIZE),
				region->mmap_size,
				PROT_READ | PROT_WRITE,
				MAP_SHARED | MAP_FIXED, backing_src->pmem.pmem_fd,
				0);
		TEST_ASSERT(region->mmap_start != MAP_FAILED,
				"test_malloc failed, mmap_start: %p errno: %i",
				region->mmap_start, errno);

		TEST_ASSERT((unsigned long) region->mmap_start &
				(huge_page_size - 1),
				"mmap_start is not small page aligned: %lx\n",
				(unsigned long) region->mmap_start);

		region->host_mem = region->mmap_start;
		break;
	case VM_MEM_SRC_PMEM_HUGE:
		region->caller_memory = false;
		region->mmap_size = npages * vm->page_size;
		TEST_ASSERT(!(region->mmap_size & (huge_page_size - 1)),
				"mmap size not huge page aligned");

		TEST_ASSERT(backing_src->pmem.pmem_fd > 0,
				"pmem fd not initialized: %d",
				backing_src->pmem.pmem_fd);

		rv = ioctl(backing_src->pmem.pmem_fd, BLKGETSIZE64, &pmem_size);
		TEST_ASSERT(rv == 0, "err getting Pmem size\n");

		TEST_ASSERT(region->mmap_size <= pmem_size,
				"requested size: %ld, available pmem: %ld\n",
				region->mmap_size, pmem_size);

		region->mmap_start = mmap(NULL, region->mmap_size,
					  PROT_READ | PROT_WRITE,
					  MAP_SHARED, backing_src->pmem.pmem_fd,
					  0);
		TEST_ASSERT(region->mmap_start != MAP_FAILED,
				"test_malloc failed, mmap_start: %p errno: %i",
				region->mmap_start, errno);

		TEST_ASSERT(!((unsigned long) region->mmap_start &
					(huge_page_size - 1)),
				"mmap_start is not huge page aligned: %lx\n",
				(unsigned long) region->mmap_start);

		region->host_mem = region->mmap_start;
		break;
	case VM_MEM_SRC_ANONYMOUS:
	case VM_MEM_SRC_ANONYMOUS_THP:
	case VM_MEM_SRC_ANONYMOUS_HUGETLB:
		if ((src_type == VM_MEM_SRC_ANONYMOUS_THP)
			|| (src_type == VM_MEM_SRC_ANONYMOUS_HUGETLB)) {
			TEST_ASSERT(hugetlb_supported(vm, npages),
			"Unsupported huge TLB settings,\n"
			"  src_type: 0x%x\n"
			"  npages: 0x%lx", src_type, npages);
		}
		region->caller_memory = false;
		region->mmap_size = npages * vm->page_size;
		if (src_type == VM_MEM_SRC_ANONYMOUS_THP) {
			/* Enough memory to align up to a huge page. */
			region->mmap_size += huge_page_size;
		}
		region->mmap_start = mmap(NULL, region->mmap_size,
			PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS
				| (src_type == VM_MEM_SRC_ANONYMOUS_HUGETLB
					? MAP_HUGETLB : 0),
				-1, 0);
		TEST_ASSERT(region->mmap_start != MAP_FAILED,
			"test_malloc failed, mmap_start: %p errno: %i",
			region->mmap_start, errno);

		/* Align THP allocation up to start of a huge page. */
		region->host_mem = align(region->mmap_start,
					src_type == VM_MEM_SRC_ANONYMOUS_THP
						?  huge_page_size : 1);

		/* As needed perform madvise */
		if ((src_type == VM_MEM_SRC_ANONYMOUS)
			|| (src_type == VM_MEM_SRC_ANONYMOUS_THP)) {
			rv = madvise(region->host_mem, npages * vm->page_size,
				(src_type == VM_MEM_SRC_ANONYMOUS)
				? MADV_NOHUGEPAGE : MADV_HUGEPAGE);
			TEST_ASSERT(rv == 0, "madvise failed,\n"
				"  addr: %p\n"
				"  length: 0x%lx\n"
				"  src_type: %x",
				region->host_mem, npages * vm->page_size,
				src_type);
		}

		break;

	case VM_MEM_SRC_FD_PRIVATE:
		region->caller_memory = false;
		region->fd = backing_src->fd_private.fd;
		region->offset = backing_src->fd_private.offset;
		region->mmap_size = npages * vm->page_size;
		region->mmap_start = mmap(NULL, region->mmap_size,
			PROT_READ | PROT_WRITE, MAP_PRIVATE,
			region->fd, region->offset);
		TEST_ASSERT(region->mmap_start != MAP_FAILED,
			"test_malloc failed, mmap_start: %p errno: %i",
			region->mmap_start, errno);
		region->host_mem = region->mmap_start;
		break;

	case VM_MEM_SRC_DIR:
		TEST_ASSERT(backing_src != NULL,
			"Unexpected NULL backing_src for VM_MEM_SRC_DIR");
		/* TODO(lhuemill): implement VM_MEM_SRC_DIR backing src. */
		break;

	case VM_MEM_SRC_CALLER_MAINTAINED:
		region->caller_memory = true;
		TEST_ASSERT(backing_src != NULL,
			"Unexpected NULL backing_src for "
			"VM_MEM_SRC_CALLER_MAINTAINED");
		region->host_mem = backing_src->caller_maintained.mem_start;
		break;

	default:
		TEST_ASSERT(false, "Unknown backing source, src_type: 0x%i",
			src_type);
		/* NOT REACHED */
	}

	region->unused_phy_pages = test_sparsebit_alloc();
	test_sparsebit_set_num(region->unused_phy_pages,
		guest_paddr / vm->page_size, npages);
	region->region.slot = slot;
	region->region.flags = flags;
	region->region.guest_phys_addr = guest_paddr;
	region->region.memory_size = npages * vm->page_size;
	region->region.userspace_addr = (uintptr_t) region->host_mem;
	rv = ioctl(vm->fd, KVM_SET_USER_MEMORY_REGION, &region->region);
	TEST_ASSERT(rv == 0, "KVM_SET_USER_MEMORY_REGION IOCTL failed,\n"
		"  rv: %i errno: %i\n"
		"  slot: %u flags: 0x%x\n"
		"  guest_phys_addr: 0x%lx size: 0x%lx",
		rv, errno, slot, flags,
		guest_paddr, (uint64_t) region->region.memory_size);

	/* Add to linked-list of memory regions. */
	if (vm->userspace_mem_region_head)
		vm->userspace_mem_region_head->prev = region;
	region->next = vm->userspace_mem_region_head;
	vm->userspace_mem_region_head = region;
}

/* VM Memory Region Flags Set
 *
 * Input Args:
 *   vm - Virtual Machine
 *   flags - Starting guest physical address
 *
 * Output Args: None
 *
 * Return: None
 *
 * Sets the flags of the memory region specified by the value of slot,
 * to the values given by flags.
 */
void vm_mem_region_set_flags(kvm_util_vm_t *vm, uint32_t slot, uint32_t flags)
{
	int rv;
	struct userspace_mem_region *region;

	/* Locate memory region. */
	region = memslot2region(vm, slot);

	region->region.flags = flags;

	rv = ioctl(vm->fd, KVM_SET_USER_MEMORY_REGION, &region->region);

	TEST_ASSERT(rv == 0, "KVM_SET_USER_MEMORY_REGION IOCTL failed,\n"
		"  rv: %i errno: %i slot: %u flags: 0x%x",
		rv, errno, slot, flags);
}

/* VM VCPU Add
 *
 * Input Args:
 *   vm - Virtual Machine
 *   vcpuid - VCPU ID
 *
 * Output Args: None
 *
 * Return: None
 *
 * Creates and adds to the VM specified by vm and virtual CPU with
 * the ID given by vcpuid.
 */
void vm_vcpu_add(kvm_util_vm_t *vm, uint32_t vcpuid)
{
	struct vcpu *vcpu;
	struct kvm_sregs sregs;

	/* Confirm a vcpu with the specified id doesn't already exist. */
	vcpu = (struct vcpu *) vcpu_find(vm, vcpuid);
	if (vcpu != NULL)
		TEST_ASSERT(false, "vcpu with the specified id "
			"already exists,\n"
			"  requested vcpuid: %u\n"
			"  existing vcpuid: %u state: %p",
			vcpuid, vcpu->id, vcpu->state);

	/* Allocate and initialize new vcpu structure. */
	vcpu = calloc(1, sizeof(*vcpu));
	TEST_ASSERT(vcpu != NULL, "Insufficient Memory");
	vcpu->id = vcpuid;
	vcpu->fd = ioctl(vm->fd, KVM_CREATE_VCPU, vcpuid);
	TEST_ASSERT(vcpu->fd >= 0, "KVM_CREATE_VCPU failed, rv: %i errno: %i",
		vcpu->fd, errno);

	TEST_ASSERT(vcpu_mmap_sz() >= sizeof(*vcpu->state), "vcpu mmap size "
		"smaller than expected, vcpu_mmap_sz: %i expected_min: %zi",
		vcpu_mmap_sz(), sizeof(*vcpu->state));
	vcpu->state = (struct kvm_run *) mmap(NULL, sizeof(*vcpu->state),
		PROT_READ | PROT_WRITE, MAP_SHARED, vcpu->fd, 0);
	TEST_ASSERT(vcpu->state != MAP_FAILED, "mmap vcpu_state failed, "
		"vcpu id: %u errno: %i", vcpuid, errno);

	/* Add to linked-list of VCPUs. */
	if (vm->vcpu_head)
		vm->vcpu_head->prev = vcpu;
	vcpu->next = vm->vcpu_head;
	vm->vcpu_head = vcpu;

	/* Set mode specific system register values. */
	vcpu_sregs_get(vm, vcpuid, &sregs);
	switch (vm->mode) {
	case VM_MODE_FLAT48PG:
		 sregs.cr0 = X86_CR0_PE | X86_CR0_NE | X86_CR0_PG;
		sregs.cr4 |= X86_CR4_PAE;
		sregs.efer |= (EFER_LME | EFER_LMA | EFER_NX);

		setUnusableSegment(&sregs.ldt);
		setLongModeFlatKernelCodeSegment(0x8, &sregs.cs);
		setLongModeFlatKernelDataSegment(0x10, &sregs.ds);
		setLongModeFlatKernelDataSegment(0x10, &sregs.es);
		break;

	default:
		TEST_ASSERT(false, "Unknown guest mode, mode: 0x%x", vm->mode);
	}
	vcpu_sregs_set(vm, vcpuid, &sregs);

	/* If virtual translation table have been setup, set system register
	 * to point to the tables.  It's okay if they haven't been setup yet,
	 * in that the code that sets up the virtual translation tables, will
	 * go back through any VCPUs that have already been created and set
	 * their values.
	 */
	if (vm->virt_l4_created) {
		struct kvm_sregs sregs;

		vcpu_sregs_get(vm, vcpuid, &sregs);

		sregs.cr3 = vm->virt_l4;
		vcpu_sregs_set(vm, vcpuid, &sregs);
	}
}

/* VM VCPU Remove
 *
 * Input Args:
 *   vm - Virtual Machine
 *   vcpuid - VCPU ID
 *
 * Output Args: None
 *
 * Return: None, TEST_ASSERT failures for all error conditions
 *
 * Within the VM specified by vm, removes the VCPU given by vcpuid.
 */
void vm_vcpu_rm(kvm_util_vm_t *vm, uint32_t vcpuid)
{
	struct vcpu *vcpu = (struct vcpu *) vcpu_find(vm, vcpuid);

	int rv = close(vcpu->fd);
	TEST_ASSERT(rv == 0, "Close of VCPU fd failed, rv: %i "
		"errno: %i", rv, errno);

	if (vcpu->next)
		vcpu->next->prev = vcpu->prev;
	if (vcpu->prev)
		vcpu->prev->next = vcpu->next;
	else
		vm->vcpu_head = vcpu->next;
	free(vcpu);
}

/* VM Virtual Address Unused Gap
 *
 * Input Args:
 *   vm - Virtual Machine
 *   sz - Size (bytes)
 *   vaddr_min - Minimum Virtual Address
 *
 * Output Args: None
 *
 * Return:
 *   Lowest virtual address at or below vaddr_min, with at least
 *   sz unused bytes.  TEST_ASSERT failure if no area of at least
 *   size sz is available.
 *
 * Within the VM specified by vm, locates the lowest starting virtual
 * address >= vaddr_min, that has at least sz unallocated bytes.  A
 * TEST_ASSERT failure occurs for invalid input or no area of at least
 * sz unallocated bytes >= vaddr_min is available.
 */
vm_vaddr_t vm_vaddr_unused_gap(const kvm_util_vm_t *vm, size_t sz,
	vm_vaddr_t vaddr_min)
{
	uint64_t pages = (sz + (vm->page_size - 1)) / vm->page_size;

	/* Determine lowest permitted virtual page index. */
	uint64_t pgidx_start = (vaddr_min + (vm->page_size - 1))
		/ vm->page_size;
	if ((pgidx_start * vm->page_size) < vaddr_min)
			goto no_va_found;

	/* Loop over section with enough valid virtual page indexes. */
	if (!test_sparsebit_is_set_num(vm->vpages_valid,
		pgidx_start, pages))
		pgidx_start = test_sparsebit_next_set_num(vm->vpages_valid,
			pgidx_start, pages);
	do {
		/*
		 * Are there enough unused virtual pages available at
		 * the currently proposed starting virtual page index.
		 * If not, adjust proposed starting index to next
		 * possible.
		 */
		if (test_sparsebit_is_clear_num(vm->vpages_mapped,
			pgidx_start, pages))
			goto va_found;
		pgidx_start = test_sparsebit_next_clear_num(vm->vpages_mapped,
			pgidx_start, pages);
		if (pgidx_start == 0)
			goto no_va_found;

		/*
		 * If needed, adjust proposed starting virtual address,
		 * to next range of valid virtual addresses.
		 */
		if (!test_sparsebit_is_set_num(vm->vpages_valid,
			pgidx_start, pages)) {
			pgidx_start = test_sparsebit_next_set_num(
				vm->vpages_valid, pgidx_start, pages);
			if (pgidx_start == 0)
				goto no_va_found;
		}
	} while (pgidx_start != 0);

no_va_found:
	TEST_ASSERT(false, "No vaddr of specified pages available, "
		"pages: 0x%lx", pages);

	/* NOT REACHED */
	return -1;

va_found:
	TEST_ASSERT(test_sparsebit_is_set_num(vm->vpages_valid,
		pgidx_start, pages),
		"Unexpected, invalid virtual page index range,\n"
		"  pgidx_start: 0x%lx\n"
		"  pages: 0x%lx",
		pgidx_start, pages);
	TEST_ASSERT(test_sparsebit_is_clear_num(vm->vpages_mapped,
		pgidx_start, pages),
		"Unexpected, pages already mapped,\n"
		"  pgidx_start: 0x%lx\n"
		"  pages: 0x%lx",
		pgidx_start, pages);

	return pgidx_start * vm->page_size;
}

/* VM Virtual Address Allocate
 *
 * Input Args:
 *   vm - Virtual Machine
 *   sz - Size in bytes
 *   vaddr_min - Minimum starting virtual address
 *   data_memslot - Memory region slot for data pages
 *   vttbl_memslot - Memory region slot for new virtual translation tables
 *
 * Output Args: None
 *
 * Return:
 *   Starting guest virtual address
 *
 * Allocates at least sz bytes within the virtual address space of the vm
 * given by vm.  The allocated bytes are mapped to a virtual address >=
 * the address given by vaddr_min.  Note that each allocation uses a
 * a unique set of pages, with the minimum real allocation being at least
 * a page.
 */
vm_vaddr_t vm_vaddr_alloc(kvm_util_vm_t *vm, size_t sz, vm_vaddr_t vaddr_min,
	uint32_t data_memslot, uint32_t vttbl_memslot)
{
	uint64_t pages = (sz / vm->page_size) + ((sz % vm->page_size) != 0);

	TEST_ASSERT(vm->mode == VM_MODE_FLAT48PG, "Attempt to use "
		"unknown or unsupported guest mode, mode: 0x%x", vm->mode);

	/* If needed, create page map l4 table. */
	if (!vm->virt_l4_created) {
		vm_paddr_t paddr = phy_page_alloc(vm,
			KVM_UTIL_VIRT_MIN_PADDR, vttbl_memslot);
		vm->virt_l4 = paddr;

		/* Set pointer to virt_l4 tables in all the VCPUs that
		 * have already been created.  Future VCPUs will have
		 * the value set as each one is created.
		 */
		for (struct vcpu *vcpu = vm->vcpu_head; vcpu;
			vcpu = vcpu->next) {
			struct kvm_sregs sregs;

			/* Obtain the current system register settings */
			vcpu_sregs_get(vm, vcpu->id, &sregs);

			/* Set and store the pointer to the start of the
			 * virt_l4 tables.
			 */
			sregs.cr3 = vm->virt_l4;
			vcpu_sregs_set(vm, vcpu->id, &sregs);
		}

		vm->virt_l4_created = true;
	}

	/* Find an unused range of virtual page addresses of at least
	 * pages in length.
	 */
	vm_vaddr_t vaddr_start = vm_vaddr_unused_gap(vm, sz, vaddr_min);

	/* Map the virtual pages. */
	for (vm_vaddr_t vaddr = vaddr_start; pages > 0;
		pages--, vaddr += vm->page_size) {
		vm_paddr_t paddr;

		paddr = phy_page_alloc(vm, KVM_UTIL_MIN_PADDR, data_memslot);

		virt_pg_map(vm, vaddr, paddr, vttbl_memslot);

		test_sparsebit_set(vm->vpages_mapped,
			vaddr / vm->page_size);
	}

	return vaddr_start;
}

/* Address VM Physical to Host Virtual
 *
 * Input Args:
 *   vm - Virtual Machine
 *   vmphy - VM physical address
 *
 * Output Args: None
 *
 * Return:
 *   Equivalent host virtual address
 *
 * Locates the memory region containing the VM physical address given
 * by vmphy, within the VM given by vm.  When found, the host virtual
 * address providing the memory to the vm physical address is returned.
 * A TEST_ASSERT failure occurs if no region containing vmphy exists.
 */
host_vaddr_t addr_vmphy2hvirt(const kvm_util_vm_t *vm, vm_paddr_t vmphy)
{
	for (struct userspace_mem_region *region
		= vm->userspace_mem_region_head; region;
		region = region->next) {
		if ((vmphy >= region->region.guest_phys_addr)
			&& (vmphy <= (region->region.guest_phys_addr
				+ region->region.memory_size - 1)))
			return (host_vaddr_t) ((uintptr_t) region->host_mem
				+ (vmphy - region->region.guest_phys_addr));
	}

	TEST_ASSERT(false, "No vm physical memory at 0x%lx", vmphy);
	return NULL;
}

/* Address VM Virtual to Host Virtual
 *
 * Input Args:
 *   vm - Virtual Machine
 *   vmphy - VM virtual address
 *
 * Output Args: None
 *
 * Return:
 *   Equivalent host virtual address
 *
 * Translates the VM virtual address given by vmvirt to a VM physical
 * address and then locates the memory region containing the VM
 * physical address, within the VM given by vm.  When found, the host
 * virtual address providing the memory to the vm physical address is returned.
 * A TEST_ASSERT failure occurs if no region containing translated
 * VM virtual address exists.
 */
host_vaddr_t addr_vmvirt2hvirt(const kvm_util_vm_t *vm, vm_vaddr_t vmvirt)
{
	uint16_t index[4];
	struct pageMapL4Entry *pml4e;
	struct pageDirectoryPointerEntry *pdpe;
	struct pageDirectoryEntry *pde;
	struct pageTableEntry *pte;
	host_vaddr_t hvirt;

	TEST_ASSERT(vm->mode == VM_MODE_FLAT48PG, "Attempt to use "
		"unknown or unsupported guest mode, mode: 0x%x", vm->mode);

	index[0] = (vmvirt >> 12) & 0x1ffu;
	index[1] = (vmvirt >> 21) & 0x1ffu;
	index[2] = (vmvirt >> 30) & 0x1ffu;
	index[3] = (vmvirt >> 39) & 0x1ffu;

	if (!vm->virt_l4_created)
		goto unmapped_vmvirt;
	pml4e = addr_vmphy2hvirt(vm, vm->virt_l4);
	if (!pml4e[index[3]].present)
		goto unmapped_vmvirt;

	pdpe = addr_vmphy2hvirt(vm, pml4e[index[3]].address * vm->page_size);
	if (!pdpe[index[2]].present)
		goto unmapped_vmvirt;

	pde = addr_vmphy2hvirt(vm, pdpe[index[2]].address * vm->page_size);
	if (!pde[index[1]].present)
		goto unmapped_vmvirt;

	pte = addr_vmphy2hvirt(vm, pde[index[1]].address * vm->page_size);
	if (!pte[index[0]].present)
		goto unmapped_vmvirt;

	hvirt = addr_vmphy2hvirt(vm, pte[index[0]].address * vm->page_size);

	return hvirt + (vmvirt & 0xfffu);

unmapped_vmvirt:
	TEST_ASSERT(false, "No mapping for vm virtual address, "
		"vmvirt: 0x%lx", vmvirt);
	return NULL;
}

/* Address Host Virtual to VM Physical
 *
 * Input Args:
 *   vm - Virtual Machine
 *   hvirt - Host virtual address
 *
 * Output Args: None
 *
 * Return:
 *   Equivalent VM physical address
 *
 * Locates the memory region containing the host virtual address given
 * by hvirt, within the VM given by vm.  When found, the equivalent
 * VM physical address is returned. A TEST_ASSERT failure occurs if no
 * region containing hvirt exists.
 */
vm_paddr_t addr_hvirt2vmphy(const kvm_util_vm_t *vm, host_vaddr_t hvirt)
{
	for (struct userspace_mem_region *region
		= vm->userspace_mem_region_head; region;
		region = region->next) {
		if ((hvirt >= region->host_mem)
			&& (hvirt <= (region->host_mem
				+ region->region.memory_size - 1)))
			return (vm_paddr_t) ((uintptr_t)
				region->region.guest_phys_addr
				+ (hvirt - (uintptr_t) region->host_mem));
	}

	TEST_ASSERT(false, "No mapping to a guest physical address, "
		"hvirt: %p", hvirt);
	return -1;
}

/* Address VM Virtual to VM Physical
 *
 * Input Args:
 *   vm - Virtual Machine
 *   vmvirt - VM virtual address
 *
 * Output Args: None
 *
 * Return:
 *   Equivalent VM physical address
 */
vm_paddr_t addr_vmvirt2vmphy(const kvm_util_vm_t *vm, vm_vaddr_t vmvirt)
{
	host_vaddr_t hvirt = addr_vmvirt2hvirt(vm, vmvirt);

	return addr_hvirt2vmphy(vm, hvirt);
}

/* VM Create IRQ Chip
 *
 * Input Args:
 *   vm - Virtual Machine
 *
 * Output Args: None
 *
 * Return: None
 *
 * Creates an interrupt controller chip for the VM specified by vm.
 */
void vm_create_irqchip(kvm_util_vm_t *vm)
{
	int rv;

	rv = ioctl(vm->fd, KVM_CREATE_IRQCHIP, 0);
	TEST_ASSERT(rv == 0, "KVM_CREATE_IRQCHIP IOCTL failed, "
		"rv: %i errno: %i", rv, errno);
}

/* VM VCPU State
 *
 * Input Args:
 *   vm - Virtual Machine
 *   vcpuid - VCPU ID
 *
 * Output Args: None
 *
 * Return:
 *   Pointer to structure that describes the state of the VCPU.
 *
 * Locates and returns a pointer to a structure that describes the
 * state of the VCPU with the given vcpuid.
 */
struct kvm_run *vcpu_state(const kvm_util_vm_t *vm, uint32_t vcpuid)
{
	const struct vcpu *vcpu;

	vcpu = (struct vcpu *) vcpu_find(vm, vcpuid);
	TEST_ASSERT(vcpu != NULL, "vcpu not found, vcpuid: %u", vcpuid);

	return vcpu->state;
}

/* VM VCPU Run
 *
 * Input Args:
 *   vm - Virtual Machine
 *   vcpuid - VCPU ID
 *
 * Output Args: None
 *
 * Return: None
 *
 * Switch to executing the code for the VCPU given by vcpuid, within the VM
 * given by vm.
 */
void vcpu_run(kvm_util_vm_t *vm, uint32_t vcpuid)
{
	int rv;
	const struct vcpu *vcpu;

	vcpu = (struct vcpu *) vcpu_find(vm, vcpuid);
	TEST_ASSERT(vcpu != NULL, "vcpu not found, vcpuid: %u", vcpuid);

	do {
		rv = ioctl(vcpu->fd, KVM_RUN, NULL);
	} while (rv == -1 && errno == EINTR);
	TEST_ASSERT(rv == 0, "KVM_RUN IOCTL failed, "
		"rv: %i errno: %i", rv, errno);
}

/* VM VCPU Set MP State
 *
 * Input Args:
 *   vm - Virtual Machine
 *   vcpuid - VCPU ID
 *   mp_state - mp_state to be set
 *
 * Output Args: None
 *
 * Return: None
 *
 * Sets the MP state of the VCPU given by vcpuid, to the state given
 * by mp_state.
 */
void vcpu_set_mp_state(kvm_util_vm_t *vm, uint32_t vcpuid,
	const struct kvm_mp_state *mp_state)
{
	int rv;
	const struct vcpu *vcpu;

	vcpu = (struct vcpu *) vcpu_find(vm, vcpuid);
	TEST_ASSERT(vcpu != NULL, "vcpu not found, vcpuid: %u", vcpuid);

	rv = ioctl(vcpu->fd, KVM_SET_MP_STATE, mp_state);
	TEST_ASSERT(rv == 0, "KVM_SET_MP_STATE IOCTL failed, "
		"rv: %i errno: %i", rv, errno);
}

/* VM VCPU Regs Get
 *
 * Input Args:
 *   vm - Virtual Machine
 *   vcpuid - VCPU ID
 *
 * Output Args:
 *   regs - current state of VCPU regs
 *
 * Return: None
 *
 * Obtains the current register state for the VCPU specified by vcpuid
 * and stores it at the location given by regs.
 */
void vcpu_regs_get(const kvm_util_vm_t *vm,
	uint32_t vcpuid, struct kvm_regs *regs)
{
	int rv;
	const struct vcpu *vcpu;

	vcpu = vcpu_find(vm, vcpuid);
	TEST_ASSERT(vcpu != NULL, "vcpu not found, vcpuid: %u", vcpuid);

	/* Get the regs. */
	rv = ioctl(vcpu->fd, KVM_GET_REGS, regs);
	TEST_ASSERT(rv == 0, "KVM_GET_REGS failed, rv: %i errno: %i",
		rv, errno);
}

/* VM VCPU Regs Set
 *
 * Input Args:
 *   vm - Virtual Machine
 *   vcpuid - VCPU ID
 *   regs - Values to set VCPU regs to
 *
 * Output Args: None
 *
 * Return: None
 *
 * Sets the regs of the VCPU specified by vcpuid to the values
 * given by regs.
 */
void vcpu_regs_set(kvm_util_vm_t *vm,
	uint32_t vcpuid, const struct kvm_regs *regs)
{
	int rv;
	struct vcpu *vcpu;

	vcpu = (struct vcpu *) vcpu_find(vm, vcpuid);
	TEST_ASSERT(vcpu != NULL, "vcpu not found, vcpuid: %u", vcpuid);

	/* Set the regs. */
	rv = ioctl(vcpu->fd, KVM_SET_REGS, regs);
	TEST_ASSERT(rv == 0, "KVM_SET_REGS failed, rv: %i errno: %i",
		rv, errno);
}

void vcpu_events_get(const kvm_util_vm_t *vm, uint32_t vcpuid,
			  struct kvm_vcpu_events *events)
{
	int rv;
	const struct vcpu *vcpu;

	vcpu = vcpu_find(vm, vcpuid);
	TEST_ASSERT(vcpu != NULL, "vcpu not found, vcpuid: %u", vcpuid);

	/* Get the regs. */
	rv = ioctl(vcpu->fd, KVM_GET_VCPU_EVENTS, events);
	TEST_ASSERT(rv == 0, "KVM_GET_VCPU_EVENTS, failed, rv: %i errno: %i",
		rv, errno);
}

void vcpu_events_set(kvm_util_vm_t *vm, uint32_t vcpuid,
			  const struct kvm_vcpu_events *events)
{
	int rv;
	struct vcpu *vcpu;

	vcpu = (struct vcpu *) vcpu_find(vm, vcpuid);
	TEST_ASSERT(vcpu != NULL, "vcpu not found, vcpuid: %u", vcpuid);

	/* Set the regs. */
	rv = ioctl(vcpu->fd, KVM_SET_VCPU_EVENTS, events);
	TEST_ASSERT(rv == 0, "KVM_SET_VCPU_EVENTS, failed, rv: %i errno: %i",
		rv, errno);
}

/* VM VCPU Args Set
 *
 * Input Args:
 *   vm - Virtual Machine
 *   vcpuid - VCPU ID
 *   num - number of arguments
 *   ... - arguments, each of type uint64_t
 *
 * Output Args: None
 *
 * Return: None
 *
 * Sets the first num function input arguments to the values
 * given as variable args.  Each of the variable args is expected to
 * be of type uint64_t.
 */
void vcpu_args_set(kvm_util_vm_t *vm, uint32_t vcpuid, unsigned int num, ...)
{
	va_list ap;
	struct kvm_regs regs;

	TEST_ASSERT((num >= 1) && (num <= 6), "Unsupported number of args,\n"
		"  num: %u\n"
		"  expected: (num >= 1) && (num <= 6)",
		num);

	va_start(ap, num);
	vcpu_regs_get(vm, vcpuid, &regs);

	if (num >= 1)
		regs.rdi = va_arg(ap, uint64_t);

	if (num >= 2)
		regs.rsi = va_arg(ap, uint64_t);

	if (num >= 3)
		regs.rdx = va_arg(ap, uint64_t);

	if (num >= 4)
		regs.rcx = va_arg(ap, uint64_t);

	if (num >= 5)
		regs.r8 = va_arg(ap, uint64_t);

	if (num >= 6)
		regs.r9 = va_arg(ap, uint64_t);

	vcpu_regs_set(vm, vcpuid, &regs);
	va_end(ap);
}

/* VM VCPU System Regs Get
 *
 * Input Args:
 *   vm - Virtual Machine
 *   vcpuid - VCPU ID
 *
 * Output Args:
 *   sregs - current state of VCPU system regs
 *
 * Return: None
 *
 * Obtains the current system register state for the VCPU specified by
 * vcpuid and stores it at the location given by sregs.
 */
void vcpu_sregs_get(const kvm_util_vm_t *vm,
	uint32_t vcpuid, struct kvm_sregs *sregs)
{
	int rv;
	const struct vcpu *vcpu;

	vcpu = vcpu_find(vm, vcpuid);
	TEST_ASSERT(vcpu != NULL, "vcpu not found, vcpuid: %u", vcpuid);

	/* Get the regs. */
	rv = ioctl(vcpu->fd, KVM_GET_SREGS, sregs);
	TEST_ASSERT(rv == 0, "KVM_GET_SREGS failed, rv: %i errno: %i",
		rv, errno);
}

/* VM VCPU System Regs Set
 *
 * Input Args:
 *   vm - Virtual Machine
 *   vcpuid - VCPU ID
 *   sregs - Values to set VCPU system regs to
 *
 * Output Args: None
 *
 * Return: None
 *
 * Sets the system regs of the VCPU specified by vcpuid to the values
 * given by sregs.
 */
void vcpu_sregs_set(kvm_util_vm_t *vm,
	uint32_t vcpuid, const struct kvm_sregs *sregs)
{
	int rv;
	struct vcpu *vcpu;

	vcpu = (struct vcpu *) vcpu_find(vm, vcpuid);
	TEST_ASSERT(vcpu != NULL, "vcpu not found, vcpuid: %u", vcpuid);

	/* Set the sregs. */
	rv = ioctl(vcpu->fd, KVM_SET_SREGS, sregs);
	TEST_ASSERT(rv == 0, "KVM_SET_SREGS failed, rv: %i errno: %i",
		rv, errno);
}

/* VCPU Ioctl
 *
 * Input Args:
 *   vm - Virtual Machine
 *   vcpuid - VCPU ID
 *   cmd - Ioctl number
 *   arg - Argument to pass to the ioctl
 *
 * Return: None
 *
 * Issues an arbitrary ioctl on a VCPU fd.
 */
void vcpu_ioctl(kvm_util_vm_t *vm,
	uint32_t vcpuid, unsigned long cmd, void *arg)
{
	int rv;
	struct vcpu *vcpu;

	vcpu = (struct vcpu *) vcpu_find(vm, vcpuid);
	TEST_ASSERT(vcpu != NULL, "vcpu not found, vcpuid: %u", vcpuid);

	rv = ioctl(vcpu->fd, cmd, arg);
	TEST_ASSERT(rv == 0, "vcpu ioctl %lu failed, rv: %i errno: %i (%s)",
		cmd, rv, errno, strerror(errno));
}

/* VM Ioctl
 *
 * Input Args:
 *   vm - Virtual Machine
 *   cmd - Ioctl number
 *   arg - Argument to pass to the ioctl
 *
 * Return: None
 *
 * Issues an arbitrary ioctl on a VM fd.
 */
void vm_ioctl(kvm_util_vm_t *vm, unsigned long cmd, void *arg)
{
	int rv;

	rv = ioctl(vm->fd, cmd, arg);
	TEST_ASSERT(rv == 0, "vm ioctl %lu failed, rv: %i errno: %i (%s)",
		cmd, rv, errno, strerror(errno));
}

/* VM VCPU xcr Regs Get
 *
 * Output Args:
 *   xcrs - Values of VCPU xcr regs
 *
 * Return: None
 *
 * Gets the xcr regs of the VCPU specified by vcpuid.
 */
void vcpu_xcrs_get(kvm_util_vm_t *vm,
	uint32_t vcpuid, struct kvm_xcrs *xcrs)
{
	int rv;
	struct vcpu *vcpu;

	TEST_ASSERT(kvm_util_cap(KVM_CAP_XCRS),
		    "KVM does not support KVM_CAP_XCRS. Bailing.\n");

	vcpu = (struct vcpu *) vcpu_find(vm, vcpuid);
	TEST_ASSERT(vcpu != NULL, "vcpu not found, vcpuid: %u", vcpuid);

	/* Get the xcrs. */
	rv = ioctl(vcpu->fd, KVM_GET_XCRS, xcrs);
	TEST_ASSERT(rv == 0, "KVM_GET_XCRS failed, rv: %i errno: %i",
		rv, errno);
}

/* VM VCPU xcr Regs Set
 *
 * Input Args:
 *   vm - Virtual Machine
 *   vcpuid - VCPU ID
 *   xcrs - Values to set VCPU xcr regs to
 *
 * Output Args: None
 *
 * Return: None
 *
 * Sets the xcr regs of the VCPU specified by vcpuid to the values
 * given by xcrs.
 */
void vcpu_xcrs_set(kvm_util_vm_t *vm,
	uint32_t vcpuid, const struct kvm_xcrs *xcrs)
{
	int rv;
	struct vcpu *vcpu;

	vcpu = (struct vcpu *) vcpu_find(vm, vcpuid);
	TEST_ASSERT(vcpu != NULL, "vcpu not found, vcpuid: %u", vcpuid);

	/* Set the xcrs. */
	rv = ioctl(vcpu->fd, KVM_SET_XCRS, xcrs);
	TEST_ASSERT(rv == 0, "KVM_SET_XCRS failed, rv: %i errno: %i",
		rv, errno);
}

/* VM Dump
 *
 * Input Args:
 *   vm - Virtual Machine
 *   indent - Left margin indent amount
 *
 * Output Args:
 *   stream - Output FILE stream
 *
 * Return: None
 *
 * Dumps the current state of the VM given by vm, to the FILE stream
 * given by stream.
 */
void vm_dump(FILE *stream, const kvm_util_vm_t *vm, uint8_t indent)
{
	fprintf(stream, "%*smode: 0x%x\n", indent, "", vm->mode);
	fprintf(stream, "%*sfd: %i\n", indent, "", vm->fd);
	fprintf(stream, "%*spage_size: 0x%x\n", indent, "", vm->page_size);
	fprintf(stream, "%*sMem Regions:\n", indent, "");
	for (struct userspace_mem_region *region
		= vm->userspace_mem_region_head; region;
		region = region->next) {
		fprintf(stream, "%*sguest_phys: 0x%lx size: 0x%lx "
			"host_virt: %p\n", indent + 2, "",
			(uint64_t) region->region.guest_phys_addr,
			(uint64_t) region->region.memory_size,
			region->host_mem);
		fprintf(stream, "%*sunused_phy_pages: ", indent + 2, "");
		test_sparsebit_dump(stream, region->unused_phy_pages, 0);
	}
	fprintf(stream, "%*sMapped Virtual Pages:\n", indent, "");
	test_sparsebit_dump(stream, vm->vpages_mapped, indent + 2);
	fprintf(stream, "%*svirt_l4_created: %u\n", indent, "",
		vm->virt_l4_created);
	if (vm->virt_l4_created) {
		fprintf(stream, "%*sVirtual Translation Tables:\n",
			indent + 2, "");
		virt_dump(stream, vm, indent + 4);
	}
	fprintf(stream, "%*sVCPUs:\n", indent, "");
	for (struct vcpu *vcpu = vm->vcpu_head; vcpu; vcpu = vcpu->next)
		vcpu_dump(stream, vm, vcpu->id, indent + 2);
}

/* VM VCPU Dump
 *
 * Input Args:
 *   vm - Virtual Machine
 *   vcpuid - VCPU ID
 *   indent - Left margin indent amount
 *
 * Output Args:
 *   stream - Output FILE stream
 *
 * Return: None
 *
 * Dumps the current state of the VCPU specified by vcpuid, within the VM
 * given by vm, to the FILE stream given by stream.
 */
void vcpu_dump(FILE *stream, const kvm_util_vm_t *vm,
	uint32_t vcpuid, uint8_t indent)
{
		struct kvm_regs regs;
		struct kvm_sregs sregs;

		fprintf(stream, "%*scpuid: %u\n", indent, "", vcpuid);

		fprintf(stream, "%*sregs:\n", indent + 2, "");
		vcpu_regs_get(vm, vcpuid, &regs);
		regs_dump(stream, &regs, indent + 4);

		fprintf(stream, "%*ssregs:\n", indent + 2, "");
		vcpu_sregs_get(vm, vcpuid, &sregs);
		sregs_dump(stream, &sregs, indent + 4);
}

/* Register Dump
 *
 * Input Args:
 *   indent - Left margin indent amount
 *   regs - register
 *
 * Output Args:
 *   stream - Output FILE stream
 *
 * Return: None
 *
 * Dumps the state of the registers given by regs, to the FILE stream
 * given by steam.
 */
void regs_dump(FILE *stream, const struct kvm_regs *regs,
	uint8_t indent)
{
	fprintf(stream, "%*srax: 0x%.16llx rbx: 0x%.16llx "
		"rcx: 0x%.16llx rdx: 0x%.16llx\n",
		indent, "",
		regs->rax, regs->rbx, regs->rcx, regs->rdx);
	fprintf(stream, "%*srsi: 0x%.16llx rdi: 0x%.16llx "
		"rsp: 0x%.16llx rbp: 0x%.16llx\n",
		indent, "",
		regs->rsi, regs->rdi, regs->rsp, regs->rbp);
	fprintf(stream, "%*sr8:  0x%.16llx r9:  0x%.16llx "
		"r10: 0x%.16llx r11: 0x%.16llx\n",
		indent, "",
		regs->r8, regs->r9, regs->r10, regs->r11);
	fprintf(stream, "%*sr12: 0x%.16llx r13: 0x%.16llx "
		"r14: 0x%.16llx r15: 0x%.16llx\n",
		indent, "",
		regs->r12, regs->r13, regs->r14, regs->r15);
	fprintf(stream, "%*srip: 0x%.16llx rfl: 0x%.16llx\n",
		indent, "",
		regs->rip, regs->rflags);
}

/* Segment Dump
 *
 * Input Args:
 *   indent - Left margin indent amount
 *   segment - KVM segment
 *
 * Output Args:
 *   stream - Output FILE stream
 *
 * Return: None
 *
 * Dumps the state of the KVM segment given by segment, to the FILE stream
 * given by steam.
 */
void segment_dump(FILE *stream, const struct kvm_segment *segment,
	uint8_t indent)
{
	fprintf(stream, "%*sbase: 0x%.16llx limit: 0x%.8x "
		"selector: 0x%.4x type: 0x%.2x\n",
		indent, "", segment->base, segment->limit,
		segment->selector, segment->type);
	fprintf(stream, "%*spresent: 0x%.2x dpl: 0x%.2x "
		"db: 0x%.2x s: 0x%.2x l: 0x%.2x\n",
		indent, "", segment->present, segment->dpl,
		segment->db, segment->s, segment->l);
	fprintf(stream, "%*sg: 0x%.2x avl: 0x%.2x "
		"unusable: 0x%.2x padding: 0x%.2x\n",
		indent, "", segment->g, segment->avl,
		segment->unusable, segment->padding);
}

/* dtable Dump
 *
 * Input Args:
 *   indent - Left margin indent amount
 *   dtable - KVM dtable
 *
 * Output Args:
 *   stream - Output FILE stream
 *
 * Return: None
 *
 * Dumps the state of the KVM dtable given by dtable, to the FILE stream
 * given by steam.
 */
void dtable_dump(FILE *stream, const struct kvm_dtable *dtable,
	uint8_t indent)
{
	fprintf(stream, "%*sbase: 0x%.16llx limit: 0x%.4x "
		"padding: 0x%.4x 0x%.4x 0x%.4x\n",
		indent, "", dtable->base, dtable->limit,
		dtable->padding[0], dtable->padding[1], dtable->padding[2]);
}

/* System Register Dump
 *
 * Input Args:
 *   indent - Left margin indent amount
 *   sregs - System registers
 *
 * Output Args:
 *   stream - Output FILE stream
 *
 * Return: None
 *
 * Dumps the state of the system registers given by sregs, to the FILE stream
 * given by steam.
 */
void sregs_dump(FILE *stream, const struct kvm_sregs *sregs,
	uint8_t indent)
{
	unsigned int i;

	fprintf(stream, "%*scs:\n", indent, "");
	segment_dump(stream, &sregs->cs, indent + 2);
	fprintf(stream, "%*sds:\n", indent, "");
	segment_dump(stream, &sregs->ds, indent + 2);
	fprintf(stream, "%*ses:\n", indent, "");
	segment_dump(stream, &sregs->es, indent + 2);
	fprintf(stream, "%*sfs:\n", indent, "");
	segment_dump(stream, &sregs->fs, indent + 2);
	fprintf(stream, "%*sgs:\n", indent, "");
	segment_dump(stream, &sregs->gs, indent + 2);
	fprintf(stream, "%*sss:\n", indent, "");
	segment_dump(stream, &sregs->ss, indent + 2);
	fprintf(stream, "%*str:\n", indent, "");
	segment_dump(stream, &sregs->tr, indent + 2);
	fprintf(stream, "%*sldt:\n", indent, "");
	segment_dump(stream, &sregs->ldt, indent + 2);

	fprintf(stream, "%*sgdt:\n", indent, "");
	dtable_dump(stream, &sregs->gdt, indent + 2);
	fprintf(stream, "%*sidt:\n", indent, "");
	dtable_dump(stream, &sregs->idt, indent + 2);

	fprintf(stream, "%*scr0: 0x%.16llx cr2: 0x%.16llx "
		"cr3: 0x%.16llx cr4: 0x%.16llx\n",
		indent, "",
		sregs->cr0, sregs->cr2, sregs->cr3, sregs->cr4);
	fprintf(stream, "%*scr8: 0x%.16llx efer: 0x%.16llx "
		"apic_base: 0x%.16llx\n",
		indent, "",
		sregs->cr8, sregs->efer, sregs->apic_base);

	fprintf(stream, "%*sinterrupt_bitmap:\n", indent, "");
	for (i = 0; i < (KVM_NR_INTERRUPTS + 63) / 64; i++) {
		fprintf(stream, "%*s%.16llx\n", indent + 2, "",
			sregs->interrupt_bitmap[i]);
	}
}

/* Known KVM exit reasons */
struct exit_reason {
	unsigned int reason;
	const char *name;
} exit_reasons_known[] = {
	{KVM_EXIT_UNKNOWN, "UNKNOWN"},
	{KVM_EXIT_EXCEPTION, "EXCEPTION"},
	{KVM_EXIT_IO, "IO"},
	{KVM_EXIT_HYPERCALL, "HYPERCALL"},
	{KVM_EXIT_DEBUG, "DEBUG"},
	{KVM_EXIT_HLT, "HLT"},
	{KVM_EXIT_MMIO, "MMIO"},
	{KVM_EXIT_IRQ_WINDOW_OPEN, "IRQ_WINDOW_OPEN"},
	{KVM_EXIT_SHUTDOWN, "SHUTDOWN"},
	{KVM_EXIT_FAIL_ENTRY, "FAIL_ENTRY"},
	{KVM_EXIT_INTR, "INTR"},
	{KVM_EXIT_SET_TPR, "SET_TPR"},
	{KVM_EXIT_TPR_ACCESS, "TPR_ACCESS"},
	{KVM_EXIT_S390_SIEIC, "S390_SIEIC"},
	{KVM_EXIT_S390_RESET, "S390_RESET"},
	{KVM_EXIT_DCR, "DCR"},
	{KVM_EXIT_NMI, "NMI"},
	{KVM_EXIT_INTERNAL_ERROR, "INTERNAL_ERROR"},
	{KVM_EXIT_OSI, "OSI"},
	{KVM_EXIT_PAPR_HCALL, "PAPR_HCALL"},
#ifdef KVM_EXIT_MEMORY_NOT_PRESENT
	{KVM_EXIT_MEMORY_NOT_PRESENT, "MEMORY_NOT_PRESENT"},
#endif
};

/* Exit Reason String
 *
 * Input Args:
 *   exit_reason - Exit reason
 *
 * Output Args: None
 *
 * Return:
 *   Constant string pointer describing the exit reason.
 *
 * Locates and returns a constant string that describes the KVM exit
 * reason given by exit_reason.  If no such string is found, a constant
 * string of "Unknown" is returned.
 */
const char *exit_reason_str(unsigned int exit_reason)
{
	unsigned int n1;

	for (n1 = 0; n1 < ARRAY_SIZE(exit_reasons_known); n1++) {
		if (exit_reason == exit_reasons_known[n1].reason)
			return exit_reasons_known[n1].name;
	}

	return "Unknown";
}

/* Exit Reason Value
 *
 * Input Args:
 *   name - exit reason string
 *
 * Output Args: None
 *
 * Return:
 *   Equivalent exit reason value or -1 if no equivalent exit value is
 *   found.
 *
 * Searches for a KVM exit reason with a string name equal to name and if
 * found returns the value of that exit reason.  A value of -1 is returned
 * if no exit reason with the given name is found.
 */
int exit_reason_val(const char *name)
{
	for (unsigned int n1 = 0; n1 < ARRAY_SIZE(exit_reasons_known); n1++) {
		if (strcmp(exit_reasons_known[n1].name, name) == 0)
			return exit_reasons_known[n1].reason;
	}

	return -1;
}

/* Exit Reasons List
 *
 * Input Args:
 *   indent - Left margin indent amount
 *
 * Output Args:
 *   stream - Output FILE stream
 *
 * Return: None
 *
 * Displays to the FILE stream given by stream, a list of all known
 * exit reasons.
 */
void exit_reasons_list(FILE *stream, unsigned int indent)
{
	for (unsigned int n1 = 0; n1 < ARRAY_SIZE(exit_reasons_known); n1++) {
		fprintf(stream, "%*s%s\n",
			indent, "", exit_reasons_known[n1].name);
	}
}

/* VM Virtual Page Map
 *
 * Input Args:
 *   vm - Virtual Machine
 *   vaddr - VM Virtual Address
 *   paddr - VM Physical Address
 *   vttbl_memslot - Memory region slot for new virtual translation tables
 *
 * Output Args: None
 *
 * Return: None
 *
 * Within the VM given by vm, creates a virtual translation for the page
 * starting at vaddr to the page starting at paddr.
 */
void virt_pg_map(kvm_util_vm_t *vm, uint64_t vaddr, uint64_t paddr,
	uint32_t vttbl_memslot)
{
	uint16_t index[4];
	struct pageMapL4Entry *pml4e;

	TEST_ASSERT((vaddr % vm->page_size) == 0,
		"Virtual address not on page boundary,\n"
		"  vaddr: 0x%lx vm->page_size: 0x%x",
		vaddr, vm->page_size);
	TEST_ASSERT(test_sparsebit_is_set(vm->vpages_valid,
		(vaddr / vm->page_size)),
		"Invalid virtual address, vaddr: 0x%lx",
		vaddr);
	TEST_ASSERT((paddr % vm->page_size) == 0,
		"Physical address not on page boundary,\n"
		"  paddr: 0x%lx vm->page_size: 0x%x",
		paddr, vm->page_size);
	TEST_ASSERT((paddr / vm->page_size) <= vm->ppgidx_max,
		"Physical address beyond beyond maximum supported,\n"
		"  paddr: 0x%lx vm->ppgidx_max: 0x%lx vm->page_size: 0x%x",
		paddr, vm->ppgidx_max, vm->page_size);

	index[0] = (vaddr >> 12) & 0x1ffu;
	index[1] = (vaddr >> 21) & 0x1ffu;
	index[2] = (vaddr >> 30) & 0x1ffu;
	index[3] = (vaddr >> 39) & 0x1ffu;

	/* Allocate page directory pointer table if not present. */
	pml4e = addr_vmphy2hvirt(vm, vm->virt_l4);
	if (!pml4e[index[3]].present) {
		pml4e[index[3]].address = phy_page_alloc(vm,
			KVM_UTIL_VIRT_MIN_PADDR, vttbl_memslot)
			/ vm->page_size;
		pml4e[index[3]].writable = true;
		pml4e[index[3]].present = true;
	}

	/* Allocate page directory table if not present. */
	struct pageDirectoryPointerEntry *pdpe;
	pdpe = addr_vmphy2hvirt(vm, pml4e[index[3]].address * vm->page_size);
	if (!pdpe[index[2]].present) {
		pdpe[index[2]].address = phy_page_alloc(vm,
			KVM_UTIL_VIRT_MIN_PADDR, vttbl_memslot)
			/ vm->page_size;
		pdpe[index[2]].writable = true;
		pdpe[index[2]].present = true;
	}

	/* Allocate page table if not present. */
	struct pageDirectoryEntry *pde;
	pde = addr_vmphy2hvirt(vm, pdpe[index[2]].address * vm->page_size);
	if (!pde[index[1]].present) {
		pde[index[1]].address = phy_page_alloc(vm,
			KVM_UTIL_VIRT_MIN_PADDR, vttbl_memslot)
			/ vm->page_size;
		pde[index[1]].writable = true;
		pde[index[1]].present = true;
	}

	/* Fill in page table entry. */
	struct pageTableEntry *pte;
	pte = addr_vmphy2hvirt(vm, pde[index[1]].address * vm->page_size);
	pte[index[0]].address = paddr / vm->page_size;
	pte[index[0]].writable = true;
	pte[index[0]].present = 1;
}

/* Virtual Translation Tables Dump
 *
 * Input Args:
 *   vm - Virtual Machine
 *   indent - Left margin indent amount
 *
 * Output Args:
 *   stream - Output FILE stream
 *
 * Return: None
 *
 * Dumps to the FILE stream given by stream, the contents of all the
 * virtual translation tables for the VM given by vm.
 */
void virt_dump(FILE *stream, const kvm_util_vm_t *vm, uint8_t indent)
{
	struct pageMapL4Entry *pml4e, *pml4e_start;
	struct pageDirectoryPointerEntry *pdpe, *pdpe_start;
	struct pageDirectoryEntry *pde, *pde_start;
	struct pageTableEntry *pte, *pte_start;

	if (!vm->virt_l4_created)
		return;

	fprintf(stream, "%*s                                          "
		"                no\n", indent, "");
	fprintf(stream, "%*s      index hvaddr         gpaddr         "
		"addr         w exec dirty\n",
		indent, "");
	pml4e_start = (struct pageMapL4Entry *) addr_vmphy2hvirt(vm,
		vm->virt_l4);
	for (uint16_t n1 = 0; n1 <= 0x1ffu; n1++) {
		pml4e = &pml4e_start[n1];
		if (!pml4e->present)
			continue;
		fprintf(stream, "%*spml4e 0x%-3zx %p 0x%-12lx 0x%-10lx %u "
			" %u\n",
			indent, "",
			pml4e - pml4e_start, pml4e,
			addr_hvirt2vmphy(vm, pml4e), (uint64_t) pml4e->address,
			pml4e->writable, pml4e->execute_disable);

		pdpe_start = addr_vmphy2hvirt(vm, pml4e->address
			* vm->page_size);
		for (uint16_t n2 = 0; n2 <= 0x1ffu; n2++) {
			pdpe = &pdpe_start[n2];
			if (!pdpe->present)
				continue;
			fprintf(stream, "%*spdpe  0x%-3zx %p 0x%-12lx 0x%-10lx "
				"%u  %u\n",
				indent, "",
				pdpe - pdpe_start, pdpe,
				addr_hvirt2vmphy(vm, pdpe),
				(uint64_t) pdpe->address, pdpe->writable,
				pdpe->execute_disable);

			pde_start = addr_vmphy2hvirt(vm,
				pdpe->address * vm->page_size);
			for (uint16_t n3 = 0; n3 <= 0x1ffu; n3++) {
				pde = &pde_start[n3];
				if (!pde->present)
					continue;
				fprintf(stream, "%*spde   0x%-3zx %p "
					"0x%-12lx 0x%-10lx %u  %u\n",
					indent, "", pde - pde_start, pde,
					addr_hvirt2vmphy(vm, pde),
					(uint64_t) pde->address, pde->writable,
					pde->execute_disable);

				pte_start = addr_vmphy2hvirt(vm,
					pde->address * vm->page_size);
				for (uint16_t n4 = 0; n4 <= 0x1ffu; n4++) {
					pte = &pte_start[n4];
					if (!pte->present)
						continue;
					fprintf(stream, "%*spte   0x%-3zx %p "
						"0x%-12lx 0x%-10lx %u  %u "
						"    %u    0x%-10lx\n",
						indent, "",
						pte - pte_start, pte,
						addr_hvirt2vmphy(vm, pte),
						(uint64_t) pte->address,
						pte->writable,
						pte->execute_disable,
						pte->dirty,
						((uint64_t) n1 << 27)
							| ((uint64_t) n2 << 18)
							| ((uint64_t) n3 << 9)
							| ((uint64_t) n4));
				}
			}
		}
	}
}

/* Set Unusable Segment
 *
 * Input Args: None
 *
 * Output Args:
 *   segp - Pointer to segment register
 *
 * Return: None
 *
 * Sets the segment register pointed to by segp to an unusable state.
 */
void setUnusableSegment(struct kvm_segment *segp)
{
	memset(segp, 0, sizeof(*segp));
	segp->unusable = true;
}

/* Set Long Mode Flat Kernel Code Segment
 *
 * Input Args:
 *   selector - selector value
 *
 * Output Args:
 *   segp - Pointer to KVM segment
 *
 * Return: None
 *
 * Sets up the KVM segment pointed to by segp, to be a code segment
 * with the selector value given by selector.
 */
void setLongModeFlatKernelCodeSegment(uint16_t selector,
	struct kvm_segment *segp)
{
	memset(segp, 0, sizeof(*segp));
	segp->selector = selector;
	segp->limit = 0xFFFFFFFFu;
	segp->s = 0x1; /* kTypeCodeData */
	segp->type = 0x08 | 0x01 | 0x02; /* kFlagCode | kFlagCodeAccessed
					  * | kFlagCodeReadable
					  */
	segp->g = true;
	segp->l = true;
	segp->present = 1;
}

/* Set Long Mode Flat Kernel Data Segment
 *
 * Input Args:
 *   selector - selector value
 *
 * Output Args:
 *   segp - Pointer to KVM segment
 *
 * Return: None
 *
 * Sets up the KVM segment pointed to by segp, to be a data segment
 * with the selector value given by selector.
 */
void setLongModeFlatKernelDataSegment(uint16_t selector,
	struct kvm_segment *segp)
{
	memset(segp, 0, sizeof(*segp));
	segp->selector = selector;
	segp->limit = 0xFFFFFFFFu;
	segp->s = 0x1; /* kTypeCodeData */
	segp->type = 0x00 | 0x01 | 0x02; /* kFlagData | kFlagDataAccessed
					  * | kFlagDataWritable
					  */
	segp->g = true;
	segp->present = true;
}

/* VCPU mmap Size
 *
 * Input Args: None
 *
 * Output Args: None
 *
 * Return:
 *   Size of VCPU state
 *
 * Returns the size of the structure pointed to by the return value
 * of vcpu_state().
 */
static int vcpu_mmap_sz(void)
{
	int dev_fd, rv;

	dev_fd = open(KVM_DEV_PATH, O_RDONLY);
	TEST_ASSERT(dev_fd >= 0, "%s open %s failed, rv: %i errno: %i",
		__func__, KVM_DEV_PATH, dev_fd, errno);

	rv = ioctl(dev_fd, KVM_GET_VCPU_MMAP_SIZE, NULL);
	TEST_ASSERT(rv >= sizeof(struct kvm_run),
		"%s KVM_GET_VCPU_MMAP_SIZE ioctl failed, rv: %i errno: %i",
		__func__, rv, errno);

	close(dev_fd);

	return rv;
}

/* Huge TLB Supported
 *
 * Returns true iff the given parameters specify a condition that the
 * current platform is able to map via one or more huge TLB entries.
 *  see: ./Documentation/vm/hugetlbpage.txt
 *
 * Input Args:
 *   vm - Virtual Machine
 *   npages - number of regular pages (_SC_PAGESIZE bytes each)
 */
static bool hugetlb_supported(const kvm_util_vm_t *vm, uint64_t npages)
{
	TEST_ASSERT(vm->mode == VM_MODE_FLAT48PG,
		"Unknown VM mode, vm->mode: 0x%x", vm->mode);

	if ((npages % KVM_UTIL_PGS_PER_HUGEPG) != 0)
		return false;

	return true;
}

/* Userspace Memory Region Find
 *
 * Input Args:
 *   vm - Virtual Machine
 *   start - Starting VM physical address
 *   end - Ending VM physical address, inclusive.
 *
 * Output Args: None
 *
 * Return:
 *   Pointer to overlapping region, NULL if no such region.
 *
 * Searches for a region with any physical memory that overlaps with
 * any portion of the guest physical addresses from start to end
 * inclusive.  If multiple overlapping regions exist, a pointer to any
 * of the regions is returned.  Null is returned only when no overlapping
 * region exists.
 */
static const struct userspace_mem_region *userspace_mem_region_find(
	const kvm_util_vm_t *vm, uint64_t start, uint64_t end)
{
	struct userspace_mem_region *region;

	for (region = vm->userspace_mem_region_head; region;
		region = region->next) {
		uint64_t existing_start = region->region.guest_phys_addr;
		uint64_t existing_end = region->region.guest_phys_addr
			+ region->region.memory_size - 1;
		if ((start <= existing_end) && (end >= existing_start))
			return region;
	}

	return NULL;
}

/* KVM Userspace Memory Region Find
 *
 * Input Args:
 *   vm - Virtual Machine
 *   start - Starting VM physical address
 *   end - Ending VM physical address, inclusive.
 *
 * Output Args: None
 *
 * Return:
 *   Pointer to overlapping region, NULL if no such region.
 *
 * Public interface to userspace_mem_region_find. Allows tests to look up
 * the memslot datastructure for a given range of guest physical memory.
 */
const struct kvm_userspace_memory_region *
kvm_userspace_memory_region_find(const kvm_util_vm_t *vm, uint64_t start,
				 uint64_t end)
{
	const struct userspace_mem_region *region;

	region = userspace_mem_region_find(vm, start, end);
	if (!region)
		return NULL;

	return &region->region;
}

/* VCPU Find
 *
 * Input Args:
 *   vm - Virtual Machine
 *   vcpuid - VCPU ID
 *
 * Output Args: None
 *
 * Return:
 *   Pointer to VCPU structure
 *
 * Locates a vcpu structure that describes the VCPU specified by vcpuid and
 * returns a pointer to it.  Returns NULL if the VM doesn't contain a VCPU
 * for the specified vcpuid.
 */
static const struct vcpu *vcpu_find(const kvm_util_vm_t *vm,
	uint32_t vcpuid)
{
	struct vcpu *vcpup;

	for (vcpup = vm->vcpu_head; vcpup; vcpup = vcpup->next) {
		if (vcpup->id == vcpuid)
			return vcpup;
	}

	return NULL;
}

/* Physical Page Allocate
 *
 * Input Args:
 *   vm - Virtual Machine
 *   paddr_min - Physical address minimum
 *   memslot - Memory region to allocate page from
 *
 * Output Args: None
 *
 * Return:
 *   Starting physical address
 *
 * Within the VM specified by vm, locates an available physical page
 * at or above paddr_min.  If found, the page is marked as in use
 * and its address is returned.  A TEST_ASSERT failure occurs if no
 * page is available at or above paddr_min.
 */
static vm_paddr_t phy_page_alloc(kvm_util_vm_t *vm,
	vm_paddr_t paddr_min, uint32_t memslot)
{
	struct userspace_mem_region *region;
	test_sparsebit_idx_t pg;

	TEST_ASSERT((paddr_min % vm->page_size) == 0, "Min physical address "
		"not divisable by page size.\n"
		"  paddr_min: 0x%lx page_size: 0x%x",
		paddr_min, vm->page_size);

	/* Locate memory region. */
	region = memslot2region(vm, memslot);

	/* Locate next available physical page at or above paddr_min. */
	pg = paddr_min / vm->page_size;

	if (!test_sparsebit_is_set(region->unused_phy_pages, pg)) {
		pg = test_sparsebit_next_set(region->unused_phy_pages, pg);
		if (pg == 0) {
			fprintf(stderr, "No guest physical page available, "
				"paddr_min: 0x%lx page_size: 0x%x memslot: %u",
				paddr_min, vm->page_size, memslot);
			fputs("---- vm dump ----\n", stderr);
			vm_dump(stderr, vm, 2);
			TEST_ASSERT(false, "No guest physical page available");
		}
	}

	/* Specify page as in use and return its address. */
	test_sparsebit_clear(region->unused_phy_pages, pg);

	return pg * vm->page_size;
}

/* Memslot to region
 *
 * Input Args:
 *   vm - Virtual Machine
 *   memslot - KVM memory slot ID
 *
 * Output Args: None
 *
 * Return:
 *   Pointer to memory region structure that describe memory region
 *   using kvm memory slot ID given by memslot.  TEST_ASSERT failure
 *   on error (e.g. currently no memory region using memslot as a KVM
 *   memory slot ID).
 */
static struct userspace_mem_region *memslot2region(kvm_util_vm_t *vm,
	uint32_t memslot)
{
	struct userspace_mem_region *region;

	for (region = vm->userspace_mem_region_head; region;
		region = region->next) {
		if (region->region.slot == memslot)
			break;
	}
	if (region == NULL) {
		fprintf(stderr, "No mem region with the requested slot found,\n"
			"  requested slot: %u\n", memslot);
		fputs("---- vm dump ----\n", stderr);
		vm_dump(stderr, vm, 2);
		TEST_ASSERT(false, "Mem region not found");
	}

	return region;
}

/*
 * Reads a VCPU array from /proc/self/kvm.
 *
 * Input Args:
 *   name: The field to retrieve.
 *   index: The index of the VCPU array to read.
 *   out: The output array
 *   len: The capacity of the output array
 */
void vcpu_read_proc_array(const char *name, int index, uint64_t *out, int len)
{
	int r;
	FILE *fp = fopen("/proc/self/kvm", "r");
	TEST_ASSERT(fp, "Failed to open /proc/self/kvm with errno %d.", errno);

	for (;;) {
		char *field;
		int i;

		r = fscanf(fp, "%ms : ", &field);
		TEST_ASSERT(r == 1,
			    "Read %d items (errno=%d). Was looking for '%s'.",
			    r, errno, name);

		r = strcmp(name, field);
		free(field);
		if (r) {
			r = fscanf(fp, "%*[^\n]\n");
			TEST_ASSERT(r == 0, "Failed to scan to end of line.");
			continue;
		}

		for (i = 0; i < index; i++) {
			r = fscanf(fp, "%*[^ ] ");
			TEST_ASSERT(r == 0, "Failed to scan for index %d.", i);
		}

		for (i = 0; i < len; i++) {
			uint64_t x;
			r = fscanf(fp, "%" SCNu64 "%*[,\n ]", &x);
			TEST_ASSERT(r == 1,
				    "Array only had %d item(s). Needed %d.",
				    i, len);
			out[i] = x;
		}

		r = fclose(fp);
		TEST_ASSERT(r == 0,
			"Failed to close /proc/self/kvm with errno %d.",
			errno);
		return;
	}

	/* NOT REACHED */
}

void vm_read_proc_array(const char *name, uint64_t *out, int len)
{
	vcpu_read_proc_array(name, 0, out, len);
}

/*
 * Reads a VCPU field from /proc/self/kvm.
 *
 * Input Args:
 *   name: The field to retrieve.
 *   index: The index of the VCPU field to read.
 *
 * Output Args: None.
 * Return: The field's value.
 */
uint64_t vcpu_read_proc_field(const char *name, int index)
{
	uint64_t data;

	vcpu_read_proc_array(name, index, &data, 1);
	return data;
}

/*
 * Reads a VM field from /proc/self/kvm. Can't be used with per-vCPU fields.
 *
 * Input Args:
 *   name: The field to retrieve.
 *
 * Output Args: None.
 * Return: The field's value.
 */
uint64_t vm_read_proc_field(const char *name)
{
	return vcpu_read_proc_field(name, 0);
}

/* VM Create Device
 *
 * Input Args:
 *   vm - Virtual Machine
 *   cd - Create Device
 *
 * Output Args: device fd in cd->fd
 *
 * Return: 0/success errno/failure
 *
 * Creates an emulated device in the kernel.
 */
int vm_create_device(const kvm_util_vm_t *vm, struct kvm_create_device *cd)
{
	int rv;

	rv = ioctl(vm->fd, KVM_CREATE_DEVICE, cd);
	if (rv)
		return errno;
	return 0;
}
