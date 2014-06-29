#include <assert.h>

#include "qhyper.h"
#include "../include/qemu/hypercall-api.h"

static inline void cpuid(long eax_in, long ecx_in, long *eax, long *ebx,
	long *ecx, long *edx) {
	assert(eax);
	assert(ebx);
	assert(ecx);
	assert(edx);
	asm volatile(
		"cpuid" :
		"=a"(*eax),
		"=b"(*ebx),
		"=c"(*ecx),
		"=d"(*edx) :
		"a"(eax_in),
		"c"(ecx_in));
}

static inline int qhypercall(long callno, long *ebx, long *ecx, long *edx) {
	long eax;

	assert(ebx);
	assert(ecx);
	assert(edx);
	cpuid(HYPERCALL_CPUID_INDEX, callno, &eax, ebx, ecx, edx);
	return eax == HYPERCALL_CPUID_REPLY_EAX;
}

int qhyper_nop(void) {
	long ebx, ecx, edx;
	return qhypercall(HYPERCALL_INDEX_NOP, &ebx, &ecx, &edx);
}
