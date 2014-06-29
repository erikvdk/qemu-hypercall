#include "hypercall.h"

int hypercall_execute(CPUX86State *env, uint32_t count, uint32_t *eax,
	uint32_t *ebx, uint32_t *ecx, uint32_t *edx) {
	switch (count) {
	case HYPERCALL_INDEX_NOP:
		/* call just to test whether hypercalls are available */
		break;
	default:
		return 0;
	}

	*eax = HYPERCALL_CPUID_REPLY_EAX;
	return 1;
}
