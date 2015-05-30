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

HyperMemMagicContext *magic_context_create(HyperMemState *state, const char *name) 
{
    HyperMemMagicContext *mc;

    /* allocate structure */
    mc = CALLOC(1, HyperMemMagicContext);
    if (!mc) {
        return NULL;
    }
    mc->name = strdup(name);
    if (!mc->name) {
        logprinterr(state, "error: strdup failed: %s\n",
            strerror(errno));
        free(mc);
        return NULL;
    }

    /* add to linked list */
    mc->next = state->magic_context;
    state->magic_context = mc;
    return mc;
}

void magic_context_set_with_name(
        HyperMemState *state,
        const char *name,
        hypermem_entry_t contextptr,
        hypermem_entry_t contextsize)
{
    HyperMemMagicContext *mc;
    vaddr contextptr_lin;

    /* overwrite if we've seen this module before */
    mc = magic_context_find(state, name);
    if (mc) {
        logprintf(state, "MAGIC context reset module=%s\n", name);
    } else {
        mc = magic_context_create(state, name);
        if (!mc) {
            return;
        }
        logprintf(state, "MAGIC context set module=%s\n", name);
    }

    if (!vaddr_to_laddr(state, contextptr, &contextptr_lin)) {
        logprinterr(state, "warning: failed to convert vaddr to laddr\n");
        state->magic_context = mc->next;
        free(mc);
        return;
    }

    mc->_magic_vars_addr = contextptr_lin;
    mc->_magic_vars_size = contextsize;
}

void magic_context_set(
        HyperMemState *state,
        hypermem_entry_t nameptr,
        hypermem_entry_t namelen,
        hypermem_entry_t contextptr,
        hypermem_entry_t contextsize)
{
    char *name;

    /* read module name from VM */
    name = read_string(state, nameptr, namelen);
    if (!name) return;

    /* now that we have the name, do the actual work */
    fprintf(stderr, "RG: setting context %s of size %d %x\n", name, contextsize, contextptr);
    magic_context_set_with_name(state, name, contextptr, contextsize);

    /* clean up */
    free(name);
}

void *magic_get_vars_with_context(
        HyperMemState *state,
        HyperMemMagicContext *mc)
{
    void *vars_buffer;

    /* read MAGIC context */
    vars_buffer = calloc(mc->_magic_vars_size, sizeof(uint8_t));
    if (!vars_buffer) {
        return NULL;
    }

    fprintf(stderr, "RG: reading context %s of size %d\n", mc->name, mc->_magic_vars_size);
    if (cpu_memory_rw_debug(hyperst_cpu, mc->_magic_vars_addr, (uint8_t *) vars_buffer,
        mc->_magic_vars_size, 0) < 0) {
        logprinterr(state, "warning: cannot read MAGIC context\n");
        free(vars_buffer);
        return NULL;
    }
    fprintf(stderr, "RG: read context %d\n", mc->_magic_vars_size);

    return vars_buffer;
}

void *magic_get_range_with_context(
        HyperMemState *state,
        HyperMemMagicContext *mc,
        uint32_t addr,
        uint32_t size)
{
    void *buff;
    vaddr addr_lin;

    buff = CALLOC(size, uint8_t);
    if (!buff) {
        return NULL;
    }

    if (!vaddr_to_laddr(state, addr, &addr_lin)) {
        return NULL;
    }

    if (cpu_memory_rw_debug(hyperst_cpu, addr_lin, (uint8_t *) buff, size, 0) < 0) {
        logprinterr(state, "warning: cannot read range\n");
        free(buff);
        return NULL;
    }
    return buff;
}

void magic_do_st(
        HyperMemState *state,
        hypermem_entry_t nameptr,
        hypermem_entry_t namelen)
{
    HyperMemMagicContext *mc;
    char *name;

    /* read module name from VM */
    name = read_string(state, nameptr, namelen);
    if (!name) {
        return;
    }
    mc = magic_context_find(state, name);
    if (!mc) {
        logprinterr(state, "warning: cannot find context for '%s'\n", name);
        return;
    }

    /* spawn hyperst_client */
    start_hyperst(state, state->hyperst, name);
    free(name);
}

void magic_do_st_all(HyperMemState *state)
{
    HyperMemMagicContext *mc;

    logprintf(state, "magic_st_all\n");
    for (mc = state->magic_context; mc; mc = mc->next) {
        start_hyperst(state, state->hyperst, mc->name);
    }
}


