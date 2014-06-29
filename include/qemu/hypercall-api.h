#ifndef HYPERCALL_API_H
#define HYPERCALL_API_H

/* To invoke a hypercall, set EAX=HYPERCALL_CPUID_INDEX, set ECX to one of
 * the HYPERCALL_INDEX_* constants and perform a CPUID instruction.
 * To verify whether the hypercall was recognized, check that the instruction
 * has set EAX to HYPERCALL_CPUID_REPLY_EAX.
 */
#define HYPERCALL_CPUID_INDEX		0x228CC0B2
#define HYPERCALL_CPUID_REPLY_EAX	0x11981651

#define HYPERCALL_INDEX_NOP		1

#endif /* HYPERCALL_API_H */
