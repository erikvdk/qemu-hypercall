#ifndef HYPERCALL_I386_H
#define HYPERCALL_I386_H

#include "config.h"
#include "qemu-common.h"

#include <qemu/hypercall-api.h>

int hypercall_execute(CPUX86State *env, uint32_t count, uint32_t *eax,
	uint32_t *ebx, uint32_t *ecx, uint32_t *edx);

#endif /* HYPERCALL_I386_H */
