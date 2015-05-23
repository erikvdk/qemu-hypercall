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

HyperMemEdfiContext *edfi_context_create(HyperMemState *state, const char *name)
{
    HyperMemEdfiContext *ec;

    /* allocate structure */
    ec = CALLOC(1, HyperMemEdfiContext);
    if (!ec) return NULL;
    ec->name = strdup(name);
    if (!ec->name) {
        fprintf(stderr, "hypermem: error: strdup failed: %s\n",
            strerror(errno));
        free(ec);
        return NULL;
    }

    /* add to linked list */
    ec->next = state->edfi_context;
    state->edfi_context = ec;
    return ec;
}

HyperMemEdfiContext *edfi_context_find(HyperMemState *state, const char *name)
{
    HyperMemEdfiContext *ec;

    for (ec = state->edfi_context; ec; ec = ec->next) {
        if (strcmp(ec->name, name) == 0) return ec;
    }
    return NULL;
}

void edfi_context_release(
	HyperMemState *state,
	uint32_t process_cr3)
{
    HyperMemEdfiContext *ec, **ec_p;

    ec_p = &state->edfi_context;
    while ((ec = *ec_p)) {
        if (ec->cr3 == process_cr3) {
            logprintf(state, "EDFI context release module=%s\n", ec->name);
	    *ec_p = ec->next;
	    free(ec->name);
	    free(ec);
	} else {
	    ec_p = &ec->next;
	}
    }
}

void edfi_context_set_with_name(
        HyperMemState *state,
        const char *name,
        hypermem_entry_t contextptr,
        hypermem_entry_t ptroffset,
	uint32_t process_cr3)
{
    CPUState *cs = current_cpu;
    X86CPU *cpu = X86_CPU(cs);
    HyperMemEdfiContext *ec;
    vaddr contextptr_lin;

    /* check that paging is enabled */
    if (!cpu_paging_enabled(cs)) {
        fprintf(stderr, "hypermem: warning: cannot set page table with paging disabled module=%s\n", name);
        logprintf(state, "warning: cannot set page table with paging disabled module=%s\n", name);
	return;
    }

    /* overwrite if we've seen this module before */
    ec = edfi_context_find(state, name);
    if (ec) {
        logprintf(state, "EDFI context reset module=%s\n", name);
    } else {
        ec = edfi_context_create(state, name);
        if (!ec) return;
        logprintf(state, "EDFI context set module=%s\n", name);
    }
    ec->cr3 = process_cr3;
    ec->cr4 = cpu->env.cr[4];

    /* read EDFI context */
    if (!vaddr_to_laddr(contextptr, &contextptr_lin)) {
        fprintf(stderr, "hypermem: warning: cannot convert contextptr to linear address module=%s\n", name);
        logprintf(state, "warning: cannot convert contextptr to linear address module=%s\n", name);
        return;
    }
    if (read_with_pagetable(ec->cr3, ec->cr4, contextptr_lin,
	&ec->context, sizeof(ec->context)) != sizeof(ec->context)) {
        fprintf(stderr, "hypermem: warning: cannot read EDFI context module=%s\n", name);
        logprintf(state, "warning: cannot read EDFI context module=%s\n", name);
        return;
    }

    /* verify canary */
    if (ec->context.canary_value1 != EDFI_CANARY_VALUE ||
        ec->context.canary_value2 != EDFI_CANARY_VALUE) {
        fprintf(stderr, "hypermem: warning: EDFI context canaries incorrect module=%s\n", name);
        logprintf(state, "warning: EDFI context canaries incorrect module=%s\n", name);
        return;
    }

    /* store linear addresse for bb_num_executions */
    if (!vaddr_to_laddr((vaddr) ec->context.bb_num_executions,
        &ec->bb_num_executions_linaddr)) {
        fprintf(stderr, "hypermem: warning: cannot convert EDFI context virtual address to linear address module=%s\n", name);
        logprintf(state, "warning: cannot convert EDFI context virtual address to linear address module=%s\n", name);
        ec->bb_num_executions_linaddr = 0;
	return;
    }
}

void edfi_context_set(
        HyperMemState *state,
        hypermem_entry_t nameptr,
        hypermem_entry_t namelen,
        hypermem_entry_t contextptr,
        hypermem_entry_t ptroffset,
	uint32_t process_cr3)
{
    char *name;

    /* read module name from VM */
    name = read_string(nameptr, namelen);
    if (!name) return;

    /* now that we have the name, do the actual work */
    edfi_context_set_with_name(state, name, contextptr, ptroffset, process_cr3);

    /* clean up */
    free(name);
}

void edfi_dump_stats_module_with_context(HyperMemState *state, HyperMemEdfiContext *ec) 
{
    exec_count *bb_num_executions, count, countrep;
    size_t bb_num_executions_count;
    size_t bb_num_executions_size;
    int i, repeats;

    if (!ec->bb_num_executions_linaddr) {
        logprintf(state, "%s warning: cannot dump EDFI context due to "
		"missing address\n", ec->name);
        return;
    }

    /* copy bb_num_executions (including canaries) */
    bb_num_executions_count = ec->context.num_bbs + 2;
    bb_num_executions_size = bb_num_executions_count * sizeof(exec_count);
    bb_num_executions = CALLOC(bb_num_executions_count, exec_count);
    if (read_with_pagetable(ec->cr3, ec->cr4, ec->bb_num_executions_linaddr,
        bb_num_executions, bb_num_executions_size) != bb_num_executions_size) {
        fprintf(stderr, "hypermem: %s warning: cannot read EDFI context\n",
		ec->name);
        logprintf(state, "%s warning: cannot read EDFI context\n", ec->name);
        goto cleanup;
    }

    /* check canaries */
    if (bb_num_executions[0] != EDFI_CANARY_VALUE ||
        bb_num_executions[ec->context.num_bbs + 1] != EDFI_CANARY_VALUE) {
        fprintf(stderr, "hypermem: %s warning: bb_num_executions canaries "
                "incorrect\n", ec->name);
        logprintf(state, "%s warning: bb_num_executions canaries incorrect\n",
		ec->name);
        goto cleanup;
    }    

    /* dump execution counts with run-length encoding */
    logprintf(state, "edfi_dump_stats_module name=%s", ec->name);
    countrep = 0;
    repeats = 0;
    for (i = 1; i <= ec->context.num_bbs; i++) {
        count = bb_num_executions[i];
        if (countrep == count) {
            repeats++;
        } else {
            if (repeats == 1) {
                logprintf(state, " %lu", (long) countrep);
            } else if (repeats != 0) {
                logprintf(state, " %lux%u", (long) countrep, repeats);
            }
            countrep = count;
            repeats = 1;
        }
    }
    if (repeats == 1) {
        logprintf(state, " %lu", (long) countrep);
    } else if (repeats != 0) { 
        logprintf(state, " %lux%u", (long) countrep, repeats);
    }
    logprintf(state, "\n");

    /* clean up */
cleanup:
    free(bb_num_executions);
}

void edfi_dump_stats_all(HyperMemState *state)
{
    HyperMemEdfiContext *ec;

    logprintf(state, "edfi_dump_stats\n");
    for (ec = state->edfi_context; ec; ec = ec->next) {
        edfi_dump_stats_module_with_context(state, ec);
    }
}

void edfi_dump_stats_module_with_name(HyperMemState *state, const char *name)
{
    HyperMemEdfiContext *ec = edfi_context_find(state, name);

    if (ec) {
        edfi_dump_stats_module_with_context(state, ec);
    } else {
        logprintf(state, "edfi_dump_stats_module name=%s no context known\n", name);
    }
}

void edfi_dump_stats_module(
        HyperMemState *state,
        hypermem_entry_t nameptr,
        hypermem_entry_t namelen)
{
    char *name;

    /* read module name from VM */
    name = read_string(nameptr, namelen);
    if (!name) return;

    /* now that we have the name, do the actual work */
    edfi_dump_stats_module_with_name(state, name);

    /* clean up */
    free(name);
}

hypermem_entry_t edfi_faultindex_get_with_name(HyperMemState *state, const char *name)
{
    int bbindex;
    const char *faultspec, *next;
    size_t namelen;
    char *tmp;

    /* remove instance specification from module name */
    tmp = strchr(name, '@');
    if (tmp != NULL)
        *tmp = 0;

    /* faultspec parameter present? */
    if (!state->faultspec) {
        logprintf(state, "edfi_faultindex_get name=%s "
                  "fault injection disabled\n", name);
        return 0;
    }

    /* remove comment (=path:line of fault) from fault specification */
    tmp = strchr(state->faultspec, '@');
    if (tmp != NULL)
        *tmp = 0;

    /* find a matching pair in faultspec */
    namelen = strlen(name);
    faultspec = state->faultspec;
    while (*faultspec) {
        /* look for delimiter at end of module name */
        next = strchr(faultspec, ':');
        if (!next) break;

        /* is this the module we are looking for */
        if ((next - faultspec == namelen) &&
            (strncmp(faultspec, name, namelen) == 0)) {
            bbindex = atoi(next + 1);
            logprintf(state, "edfi_faultindex_get name=%s bbindex=%d\n",
                      name, bbindex);
            return bbindex;
        }

        /* skip to next pair */
        next = strchr(next + 1, ':');
        if (!next) break;
        faultspec = next + 1;
    }

    logprintf(state, "edfi_faultindex_get name=%s not selected "
                     "for fault injection\n", name);
    return 0;
}

hypermem_entry_t edfi_faultindex_get(
        HyperMemState *state,
        hypermem_entry_t nameptr,
        hypermem_entry_t namelen)
{
    hypermem_entry_t bbindex;
    char *name;

    /* read module name from VM */
    name = read_string(nameptr, namelen);
    if (!name) return 0;

    /* now that we have the name, do the actual work */
    bbindex = edfi_faultindex_get_with_name(state, name);

    /* clean up */
    free(name);
    return bbindex;
}

#define FAULT_COUNT_DIRECT_TO_LOG 3

void flush_fault(struct logstate *state)
{
    if (!state->fault_name) return;

    if (state->fault_noflush) return;

    if (state->fault_count > FAULT_COUNT_DIRECT_TO_LOG) {
        state->fault_noflush = 1;
        logprintf_internal(state, "fault name=%s bbindex=0x%lx count=%ld\n",
            state->fault_name, (long) state->fault_bbindex,
            state->fault_count - FAULT_COUNT_DIRECT_TO_LOG);
        state->fault_noflush = 0;
    }

    free(state->fault_name);
    state->fault_name = NULL;
    state->fault_bbindex = 0;
    state->fault_count = 0;
}

void log_fault(
        struct logstate *state,
        hypermem_entry_t nameptr,
        hypermem_entry_t namelen,
        hypermem_entry_t bbindex)
{
    char *name;

    /* read module name from VM */
    name = read_string(nameptr, namelen);
    if (!name) return;

    if (state->fault_name && (
        strcmp(state->fault_name, name) != 0 || state->fault_bbindex != bbindex)) {
        flush_fault(state);
    }

    if (!state->fault_name) {
        state->fault_name = name;
        state->fault_bbindex = bbindex;
    } else {
        free(name);
    }

    /* log fault */
    state->fault_count++;
    if (gettimeofday(&state->fault_time, NULL) < 0) {
        perror("gettimofday failed");
        exit(-1);
    }
    if (state->fault_count <= FAULT_COUNT_DIRECT_TO_LOG) {
        assert(!state->fault_noflush);
        state->fault_noflush = 1;
        logprintf_internal(state, "fault name=%s bbindex=0x%lx\n",
            state->fault_name, (long) state->fault_bbindex);
        state->fault_noflush = 0;
    }
}



