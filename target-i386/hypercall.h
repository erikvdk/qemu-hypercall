#ifndef HYPERCALL_I386_H
#define HYPERCALL_I386_H

#include "config.h"
#include "qemu-common.h"

/* To invoke a hypercall, set EAX=HYPERCALL_CPUID_INDEX, set ECX to one of
 * the HYPERCALL_INDEX_* constants and perform a CPUID instruction.
 * To verify whether the hypercall was recognized, check that the instruction
 * has set EAX to HYPERCALL_CPUID_REPLY_EAX.
 */
#define HYPERCALL_CPUID_INDEX		0x228CC0B2
#define HYPERCALL_CPUID_REPLY_EAX	0x11981651

#define HYPERCALL_INDEX_NOP		1

int hypercall_execute(CPUX86State *env, uint32_t count, uint32_t *eax,
	uint32_t *ebx, uint32_t *ecx, uint32_t *edx);

#endif /* HYPERCALL_I386_H */
