#include "hw/hw.h"
#include "hw/isa/isa.h"
#include "hw/i386/pc.h"
#include "sysemu/kvm.h"
#include "hw/qdev.h"
#include "qemu/config-file.h"
#include "qemu/option.h"

#include "helper.h"
#include "exec/softmmu_exec.h"

#include <qemu/hypermem-api.h>

#include "hypermem.h"

HyperMemMagicContext *magic_context_create(HyperMemState *state, const char *name) 
{
    HyperMemMagicContext *ec;

    /* allocate structure */
    ec = CALLOC(1, HyperMemMagicContext);
    if (!ec) {
        return NULL;
    }
    ec->name = strdup(name);
    if (!ec->name) {
        fprintf(stderr, "hypermem: error: strdup failed: %s\n",
            strerror(errno));
        free(ec);
        return NULL;
    }

    /* add to linked list */
    ec->next = state->magic_context;
    state->magic_context = ec;
    return ec;
}

HyperMemMagicContext *magic_context_find(HyperMemState *state, const char *name)
{
    HyperMemMagicContext *ec;

    for (ec = state->magic_context; ec; ec = ec->next) {
        if (strcmp(ec->name, name) == 0) {
            return ec;
        }
    }
    return NULL;
}


