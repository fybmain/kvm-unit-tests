/*
 * gtests/tests/set_sregs_test.c
 *
 * Copyright (C) 2018, Google LLC.
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 *
 *
 * set_sregs_test
 *
 * This is a regression test for the bug fixed by the following commit:
 * d3802286fa0f ("kvm: x86: Disallow illegal IA32_APIC_BASE MSR values")
 *
 * That bug allowed a user-mode program that called the KVM_SET_SREGS
 * ioctl to put a VCPU's local APIC into an invalid state.
 *
 */
#define _GNU_SOURCE /* for program_invocation_short_name */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>

#include "test_util.h"

#include "kvm_util.h"
#include "x86.h"

#define VCPU_ID                  5

int set_sregs(kvm_util_vm_t *vm, uint32_t vcpuid, const struct kvm_sregs *sregs)
{
	return ioctl(vcpu_fd(vm, vcpuid), KVM_SET_SREGS, sregs);
}

void guest_code(void)
{
}

int main(int argc, char *argv[])
{
	struct kvm_sregs sregs;
	kvm_util_vm_t *vm;
	int rc;

	/* Tell stdout not to buffer its content */
	setbuf(stdout, NULL);

	/* Create VM */
	vm = vm_create_default(VCPU_ID, guest_code);

	vcpu_sregs_get(vm, VCPU_ID, &sregs);
	sregs.apic_base = 1 << 10;
	rc = set_sregs(vm, VCPU_ID, &sregs);
	TEST_ASSERT(rc, "Set IA32_APIC_BASE to %llx (invalid)",
		    sregs.apic_base);
	sregs.apic_base = 1 << 11;
	rc = set_sregs(vm, VCPU_ID, &sregs);
	TEST_ASSERT(!rc, "Couldn't set IA32_APIC_BASE to %llx (valid)",
		    sregs.apic_base);

	kvm_util_vm_free(&vm);

	return 0;
}
