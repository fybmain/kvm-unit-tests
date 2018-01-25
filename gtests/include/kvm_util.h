/*
 * gtests/include/kvm_util.h
 *
 * Copyright (C) 2018, Google LLC.
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 *
 */
#include <stdio.h>
#include <inttypes.h>

#ifdef __LINUX_KVM_H
#error "Do not #include <linux/kvm.h> in the kvm tests"
#endif

#include "asm/kvm.h"
#include "linux/kvm.h"

#include "test_sparsebit.h"

#define KVM_DEV_PATH "/dev/kvm"

#define KVM_UTIL_PGS_PER_HUGEPG 512

/*
 * Memslots can't cover the gfn starting at this gpa otherwise vCPUs can't be
 * created. Only applies to VMs using EPT.
 */
#define KVM_DEFAULT_IDENTITY_MAP_ADDRESS 0xfffbc000ul


/* Callers of kvm_util only have an incomplete/opaque description of the
 * structure kvm_util is using to maintain the state of a VM.
 */
struct kvm_util_vm;
typedef struct kvm_util_vm kvm_util_vm_t;

typedef void *host_vaddr_t; /* Host virtual address */
typedef uint64_t vm_paddr_t; /* Virtual Machine (Guest) physical address */
typedef uint64_t vm_vaddr_t; /* Virtual Machine (Guest) virtual address */

/* Minimum allocated guest virtual and physical addresses */
#define KVM_UTIL_MIN_VADDR 0x2000
#define KVM_UTIL_MIN_PADDR 0x5000

/* Minimum physical address used for virtual translation tables. */
#define KVM_UTIL_VIRT_MIN_PADDR 0x180000

#define KVM_UTIL_MAGIC001 0x3a60
#define KVM_UTIL_MAGIC002 0x5c70

#define DEFAULT_GUEST_PHY_PAGES		512
#define DEFAULT_GUEST_STACK_VADDR_MIN	0xab6000
#define DEFAULT_STACK_PGS               5

enum guest_mode {
	VM_MODE_FLAT48PG = KVM_UTIL_MAGIC001,
};

enum vm_mem_backing_src_type {
	VM_MEM_SRC_CALLER_MAINTAINED = KVM_UTIL_MAGIC002,
	VM_MEM_SRC_ANONYMOUS,
	VM_MEM_SRC_ANONYMOUS_THP,
	VM_MEM_SRC_ANONYMOUS_HUGETLB,
	VM_MEM_SRC_DIR,
	VM_MEM_SRC_FD_PRIVATE,
	VM_MEM_SRC_PMEM_HUGE,
	VM_MEM_SRC_PMEM_SMALL,
};
struct vm_mem_backing_src {
	enum vm_mem_backing_src_type type;
	union {
		struct { /* VM_MEM_SRC_CALLER_MAINTAINED */
			void *mem_start;
		} caller_maintained;

		struct { /* VM_MEM_SRC_DIR */
			const char *path;
		} dir;

		struct { /* VM_MEM_SRC_FD_PRIVATE */
			int fd;
			off_t offset;
		} fd_private;
		struct { /* VM_MEM_SRC_PMEM_{HUGE, SMALL} */
			int pmem_fd;
		} pmem;
	};
};
struct vm_mem_backing_src_alias {
	const char *name;
	enum vm_mem_backing_src_type type;
};
const struct vm_mem_backing_src_alias *vm_mem_backing_src_alias_first(void);
const struct vm_mem_backing_src_alias *vm_mem_backing_src_alias_next(
	const struct vm_mem_backing_src_alias *current);
const struct vm_mem_backing_src_alias *vm_mem_backing_src_alias_find(
	const char *name);
void vm_mem_backing_src_alias_setup(const char *alias_name,
	struct vm_mem_backing_src *backing_src);
void vm_mem_backing_src_alias_cleanup(
	const struct vm_mem_backing_src *backing_src);
void vm_mem_backing_src_caller_maintained(struct vm_mem_backing_src *out,
	void *mem_start);
void vm_mem_backing_src_anonymous(struct vm_mem_backing_src *out);
void vm_mem_backing_src_anonymous_thp(struct vm_mem_backing_src *out);
void vm_mem_backing_src_anonymous_hugetlb(struct vm_mem_backing_src *out);
void vm_mem_backing_src_dir(struct vm_mem_backing_src *out,
	const char *path);
void vm_mem_backing_src_fd(struct vm_mem_backing_src *out,
	int fd, off_t offset);
bool vm_mem_backing_src_uses_lpages(enum vm_mem_backing_src_type type);

int kvm_util_cap(long cap);

kvm_util_vm_t *vm_create(enum guest_mode mode, uint64_t phy_pages, int perm);
int vm_fd(const kvm_util_vm_t *vm);
void kvm_util_vm_free(kvm_util_vm_t **vmpp);

int kvm_util_memcmp_hvirt_gvirt(const host_vaddr_t hvirt,
	const kvm_util_vm_t *vm, const vm_vaddr_t vmvirt, size_t len);

void kvm_util_vm_elf_load(kvm_util_vm_t *vm, const char *filename,
	uint32_t data_memslot, uint32_t vttbl_memslot);

void vm_dump(FILE *stream, const kvm_util_vm_t *vm, uint8_t indent);
void vcpu_dump(FILE *stream, const kvm_util_vm_t *vm,
	uint32_t vcpuid, uint8_t indent);
void regs_dump(FILE *stream, const struct kvm_regs *regs,
	uint8_t indent);
void segment_dump(FILE *stream, const struct kvm_segment *segment,
	uint8_t indent);
void dtable_dump(FILE *stream, const struct kvm_dtable *dtable,
	uint8_t indent);
void sregs_dump(FILE *stream, const struct kvm_sregs *sregs,
	uint8_t indent);

int vm_clock_get(const kvm_util_vm_t *vm, struct kvm_clock_data *clockp);
int vm_clock_set(kvm_util_vm_t *vm, const struct kvm_clock_data *clockp);

void vm_create_irqchip(kvm_util_vm_t *vm);

void vm_userspace_mem_region_add(kvm_util_vm_t *vm,
	struct vm_mem_backing_src *backing_src,
	uint64_t guest_paddr, uint32_t slot, uint64_t npages,
	uint32_t flags);

void vcpu_ioctl(kvm_util_vm_t *vm,
	uint32_t vcpuid, unsigned long ioctl, void *arg);
void vm_ioctl(kvm_util_vm_t *vm, unsigned long ioctl, void *arg);
void vm_mem_region_set_flags(kvm_util_vm_t *vm, uint32_t slot, uint32_t flags);
void vm_vcpu_add(kvm_util_vm_t *vm, uint32_t vcpuid);
void vm_vcpu_rm(kvm_util_vm_t *vm, uint32_t vcpuid);
vm_vaddr_t vm_vaddr_alloc(kvm_util_vm_t *vm, size_t sz, vm_vaddr_t vaddr_min,
	uint32_t data_memslot, uint32_t vttbl_memslot);
vm_vaddr_t vm_vaddr_unused_gap(const kvm_util_vm_t *vm, size_t sz,
	vm_vaddr_t vaddr_min);
host_vaddr_t addr_vmphy2hvirt(const kvm_util_vm_t *vm, vm_paddr_t vmphy);
host_vaddr_t addr_vmvirt2hvirt(const kvm_util_vm_t *vm, vm_vaddr_t vmvirt);
vm_paddr_t addr_hvirt2vmphy(const kvm_util_vm_t *vm, host_vaddr_t hvirt);
vm_paddr_t addr_vmvirt2vmphy(const kvm_util_vm_t *vm, vm_vaddr_t vmvirt);

struct kvm_run *vcpu_state(const kvm_util_vm_t *vm, uint32_t vcpuid);
void vcpu_run(kvm_util_vm_t *vm, uint32_t vcpuid);
void vcpu_set_mp_state(kvm_util_vm_t *vm, uint32_t vcpuid,
	const struct kvm_mp_state *mp_state);
void vcpu_regs_get(const kvm_util_vm_t *vm,
	uint32_t vcpuid, struct kvm_regs *regs);
void vcpu_regs_set(kvm_util_vm_t *vm,
	uint32_t vcpuid, const struct kvm_regs *regs);
void vcpu_args_set(kvm_util_vm_t *vm, uint32_t vcpuid, unsigned int num, ...);
void vcpu_sregs_get(const kvm_util_vm_t *vm,
	uint32_t vcpuid, struct kvm_sregs *sregs);
void vcpu_sregs_set(kvm_util_vm_t *vm,
	uint32_t vcpuid, const struct kvm_sregs *sregs);
void vcpu_xcrs_get(kvm_util_vm_t *vm,
	uint32_t vcpuid, struct kvm_xcrs *xcrs);
void vcpu_xcrs_set(kvm_util_vm_t *vm,
	uint32_t vcpuid, const struct kvm_xcrs *xcrs);
void vcpu_events_get(const kvm_util_vm_t *vm, uint32_t vcpuid,
			  struct kvm_vcpu_events *events);
void vcpu_events_set(kvm_util_vm_t *vm, uint32_t vcpuid,
			  const struct kvm_vcpu_events *events);

const char *exit_reason_str(unsigned int exit_reason);
int exit_reason_val(const char *name);
void exit_reasons_list(FILE *stream, unsigned int indent);

void virt_pg_map(kvm_util_vm_t *vm, uint64_t vaddr, uint64_t paddr,
	uint32_t vttbl_memslot);
void virt_dump(FILE *stream, const kvm_util_vm_t *vm, uint8_t indent);
void setUnusableSegment(struct kvm_segment *segp);
void setLongModeFlatKernelCodeSegment(uint16_t selector,
	struct kvm_segment *segp);
void setLongModeFlatKernelDataSegment(uint16_t selector,
	struct kvm_segment *segp);

uint64_t vm_read_proc_field(const char *name);
uint64_t vcpu_read_proc_field(const char *name, int index);
void vm_read_proc_array(const char *name, uint64_t *out, int len);
void vcpu_read_proc_array(const char *name, int index, uint64_t *out, int len);

int get_num_metrics(unsigned long kind);
uint64_t vm_get_metric(const kvm_util_vm_t *vm, uint32_t id);
uint64_t vcpu_get_metric(const kvm_util_vm_t *vm, uint32_t vcpu_index,
			 uint32_t id);
void vcpu_get_metric_array(const kvm_util_vm_t *vm, uint32_t vcpu_index,
			   uint32_t start_id, uint64_t *out, int len);
void vm_get_metric_array(const kvm_util_vm_t *vm, uint32_t start_id,
			 uint64_t *out, int len);

#define __ASSERT_STAT_ARRAY(desc, op) do {				      \
	int found = 0;							      \
	int i;								      \
	int start = _start >= 0 ? _start : _len + _start;		      \
	/* _len, _data, _val defined by caller */			      \
									      \
	for (i = start; i < _len; i++) {				      \
		if (_data[i] op _val)					      \
			found += 1;					      \
		else if (_all)						      \
			fprintf(stderr, "%s data[%d]=%" PRIu64 "\n", desc, i, \
				_data[i]);				      \
	}								      \
	if (_all) {							      \
		int required = _len - start;				      \
									      \
		TEST_ASSERT(found == required,				      \
			    "Only %d of %d in %s data were %s %" PRIu64,      \
			    found, required, desc, #op, _val);		      \
	}								      \
	else								      \
		TEST_ASSERT(found, "Nothing in %s data was %s %" PRIu64,      \
			    desc, #op, _val);				      \
} while (0)

#define __ASSERT_VCPU_STAT(all, op, val, vm, vcpu, proc_name, metric_id, len, \
			   start)					      \
do {									      \
	uint64_t _val = (val);						      \
	kvm_util_vm_t *_vm = (vm);					      \
	uint32_t _vcpu = (vcpu);					      \
	int _len = (len);						      \
	uint64_t _data[_len];						      \
	bool _all = (all);						      \
	int _start = (start);						      \
									      \
	vcpu_get_metric_array(_vm, _vcpu, (metric_id), _data, _len);	      \
	__ASSERT_STAT_ARRAY("metric", op);				      \
									      \
	vcpu_read_proc_array((proc_name), _vcpu, _data, _len);		      \
	__ASSERT_STAT_ARRAY("proc", op);				      \
} while (0)

#define __ASSERT_VM_STAT(all, op, val, vm, proc_name, metric_id, len, start)  \
do {									      \
	uint64_t _val = (val);						      \
	kvm_util_vm_t *_vm = (vm);					      \
	int _len = (len);						      \
	uint64_t _data[_len];						      \
	bool _all = (all);						      \
	int _start = (start);						      \
									      \
	vm_get_metric_array(_vm, (metric_id), _data, _len);		      \
	__ASSERT_STAT_ARRAY("metric", op);				      \
									      \
	vm_read_proc_array((proc_name), _data, _len);			      \
	__ASSERT_STAT_ARRAY("proc", op);				      \
} while (0)

/* vm == */
#define ASSERT_VM_STAT_ALL_EQ(val, vm, name, metric, len) \
	__ASSERT_VM_STAT(true, ==, val, vm, name, metric, len, 0)
#define ASSERT_VM_STAT_SOME_EQ(val, vm, name, metric, len) \
	__ASSERT_VM_STAT(false, ==, val, vm, name, metric, len, 0)
#define ASSERT_VM_STAT_EQ(val, vm, name, metric) \
	__ASSERT_VM_STAT(true, ==, val, vm, name, metric, 1, 0)
#define ASSERT_VM_STAT_ELEM_EQ(val, vm, name, metric, i) \
	__ASSERT_VM_STAT(true, ==, val, vm, name, metric, (i + 1), -1)

/* vm > */
#define ASSERT_VM_STAT_ALL_GT(val, vm, name, metric, len) \
	__ASSERT_VM_STAT(true, >, val, vm, name, metric, len, 0)
#define ASSERT_VM_STAT_SOME_GT(val, vm, name, metric, len) \
	__ASSERT_VM_STAT(false, >, val, vm, name, metric, len, 0)
#define ASSERT_VM_STAT_GT(val, vm, name, metric) \
	__ASSERT_VM_STAT(true, >, val, vm, name, metric, 1, 0)
#define ASSERT_VM_STAT_ELEM_GT(val, vm, name, metric, i) \
	__ASSERT_VM_STAT(true, >, val, vm, name, metric, (i + 1), -1)

/* vcpu == */
#define ASSERT_VCPU_STAT_ALL_EQ(val, vm, vcpu, name, metric, len) \
	__ASSERT_VCPU_STAT(true, ==, val, vm, vcpu, name, metric, len, 0)
#define ASSERT_VCPU_STAT_SOME_EQ(val, vm, vcpu, name, metric, len) \
	__ASSERT_VCPU_STAT(false, ==, val, vm, vcpu, name, metric, len, 0)
#define ASSERT_VCPU_STAT_EQ(val, vm, vcpu, name, metric) \
	__ASSERT_VCPU_STAT(true, ==, val, vm, vcpu, name, metric, 1, 0)
#define ASSERT_VCPU_STAT_ELEM_EQ(val, vm, vcpu, name, metric, i) \
	__ASSERT_VCPU_STAT(true, ==, val, vm, vcpu, name, metric, (i + 1), -1)

/* vcpu > */
#define ASSERT_VCPU_STAT_ALL_GT(val, vm, vcpu, name, metric, len) \
	__ASSERT_VCPU_STAT(true, >, val, vm, vcpu, name, metric, len, 0)
#define ASSERT_VCPU_STAT_SOME_GT(val, vm, vcpu, name, metric, len) \
	__ASSERT_VCPU_STAT(false, >, val, vm, vcpu, name, metric, len, 0)
#define ASSERT_VCPU_STAT_GT(val, vm, vcpu, name, metric) \
	__ASSERT_VCPU_STAT(true, >, val, vm, vcpu, name, metric, 1, 0)
#define ASSERT_VCPU_STAT_ELEM_GT(val, vm, vcpu, name, metric, i) \
	__ASSERT_VCPU_STAT(true, >, val, vm, vcpu, name, metric, (i + 1), -1)

void kvm_get_supported_cpuid(struct kvm_cpuid2 *cpuid);
void vcpu_set_cpuid(
	kvm_util_vm_t *vm, uint32_t vcpuid, const struct kvm_cpuid2 *cpuid);

struct kvm_cpuid2 *allocate_kvm_cpuid2(void);
struct kvm_cpuid_entry2 *
find_cpuid_index_entry(struct kvm_cpuid2 *cpuid, uint32_t function,
		       uint32_t index);

static inline struct kvm_cpuid_entry2 *
find_cpuid_entry(struct kvm_cpuid2 *cpuid, uint32_t function)
{
	return find_cpuid_index_entry(cpuid, function, 0);
}

int vcpu_fd(const kvm_util_vm_t *vm, uint32_t vcpuid);

kvm_util_vm_t *vm_create_default(uint32_t vcpuid, void *guest_code);
void vm_vcpu_add_default(kvm_util_vm_t *vm, uint32_t vcpuid, void *guest_code);

typedef void (*vmx_guest_code_t)(vm_vaddr_t vmxon_vaddr,
				 vm_paddr_t vmxon_paddr,
				 vm_vaddr_t vmcs_vaddr,
				 vm_paddr_t vmcs_paddr);

kvm_util_vm_t *
vm_create_default_vmx(uint32_t vcpuid, vmx_guest_code_t guest_code);

const struct kvm_userspace_memory_region *
kvm_userspace_memory_region_find(const kvm_util_vm_t *vm, uint64_t start,
				 uint64_t end);

struct kvm_dirty_log *
allocate_kvm_dirty_log(const struct kvm_userspace_memory_region *region);

int vm_create_device(const kvm_util_vm_t *vm, struct kvm_create_device *cd);
