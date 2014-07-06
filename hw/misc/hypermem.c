/*
 * HyperMem: hypercall mechanism using memory-mapped IO. For documentation
 * of the API to be used within the VM, see: include/qemu/hypermem-api.h
 *
 * Example device specification with properties:
 * -device hypermem,logpath=out.txt,flushlog=true,faultspec=vfs:123:pm:130
 *
 * logpath:   where to log interactions with the VM
 * flushlog:  set to true to flush the write buffer on every line of log output
 *            (useful for live debugging)
 * faultspec: specification of faults to be injected, consisting of 
 *            modulename:bbindex pairs separated by colons; bbindex is specified
 *            such that the first basic block has bbindex=1
 */

#include "hw/hw.h"
#include "hw/isa/isa.h"
#include "hw/i386/pc.h"
#include "sysemu/kvm.h"
#include "hw/qdev.h"

#include "helper.h"
#include "exec/softmmu_exec.h"

#include <qemu/hypermem-api.h>

#include "hypermem-edfi.h"

#define HYPERMEM_ENTRIES	(HYPERMEM_SIZE / sizeof(hypermem_entry_t))
#define HYPERMEM_PRIO		3 /* 1 and 2 used by video memory */
#define HYPERMEM_PENDING_MAX	HYPERMEM_ENTRIES

#define HYPERMEM_DEBUG

#define TYPE_HYPERMEM "hypermem"
#define HYPERMEM(obj) OBJECT_CHECK(HyperMemState, (obj), TYPE_HYPERMEM)

typedef struct HyperMemSessionState {
    int active;
    int command;
    int state;

    /* command state */
    union {
	struct {
	    hypermem_entry_t namelen;
	    hypermem_entry_t nameptr;
	} edfi_context_set;
	struct {
	    hypermem_entry_t namelen;
	} edfi_dump_stats_module;
	struct {
	    hypermem_entry_t namelen;
	    hypermem_entry_t nameptr;
	} edfi_faultindex_get;
	struct {
	    hypermem_entry_t namelen;
	    hypermem_entry_t nameptr;
	} fault;
	struct {
	    hypermem_entry_t strlen;
	    hypermem_entry_t strpos;
	    char *strdata;
	} print;
    } command_state;
} HyperMemSessionState;

typedef struct HyperMemPendingOperation {
    /* set for writes, clear for reads */
    int is_write;
    /* base address of operation aligned on hypermem_entry_t boundary */
    hwaddr baseaddr;
    /* bit mask of bytes valid in value */
    unsigned bytemask;
    /* value currently being read/written */
    hypermem_entry_t value;
} HyperMemPendingOperation;

typedef struct HyperMemEdfiContext {
    struct HyperMemEdfiContext *next;

    char *name;
    edfi_context_t context;
    hwaddr *bb_num_executions_hwaddr;
} HyperMemEdfiContext;

typedef struct HyperMemState
{
    ISADevice parent_obj;

    /* properties */
    char *logpath;
    bool flushlog;
    char *faultspec;

    /* QEMU objects */
    MemoryRegion io;

    /* open handles */
    FILE *logfile;

    /* EDFI contexts (linked list) */
    HyperMemEdfiContext *edfi_context;

    /* session state */
    unsigned session_next;
    HyperMemSessionState sessions[HYPERMEM_ENTRIES];

    /* state for partial reads and writes */
    HyperMemPendingOperation pending[HYPERMEM_PENDING_MAX];
} HyperMemState;

static Property hypermem_props[] = {
    DEFINE_PROP_STRING("logpath", HyperMemState, logpath),
    DEFINE_PROP_BOOL("flushlog", HyperMemState, flushlog, false),
    DEFINE_PROP_STRING("faultspec", HyperMemState, faultspec),
    DEFINE_PROP_END_OF_LIST()
};

static void logvprintf(HyperMemState *state, const char *fmt, va_list args) {
    vfprintf(state->logfile, fmt, args);
    if (state->flushlog && strchr(fmt, '\n')) fflush(state->logfile);
}

static void logprintf(HyperMemState *state, const char *fmt, ...)
    __attribute__ ((__format__ (__printf__, 2, 3)));

static void logprintf(HyperMemState *state, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    logvprintf(state, fmt, args);
    va_end(args);
}

#define CALLOC(count, type) ((type *) calloc_checked((count), sizeof(type), __FILE__, __LINE__))

static inline void *calloc_checked(size_t count, size_t size,
                                   const char *file, int line) {
    void *p;

    if (!count || !size) return NULL;

    p = calloc(count, size);
    if (!p) {
	fprintf(stderr, "hypermem: error: calloc(%lu, %lu) "
	        "failed at %s:%d: %s\n", (long) count, (long) size,
		file, line, strerror(errno));
    }
    return p;
}

static void hypermem_session_set_active(HyperMemSessionState *session)
{
    memset(session, 0, sizeof(HyperMemSessionState));
    session->active = 1;
}

static unsigned hypermem_session_allocate(HyperMemState *state)
{
    unsigned session_id;
    unsigned session_next = state->session_next;
    unsigned session_max = session_next + HYPERMEM_ENTRIES;

    while (session_next < session_max) {
	session_id = session_next % HYPERMEM_ENTRIES;
	if (session_id != 0 && !state->sessions[session_id].active) {
	    hypermem_session_set_active(&state->sessions[session_id]);
	    state->session_next = session_id + 1;
	    return session_id;
	}
	session_next++;
    }

    return 0;
}

static unsigned hypermem_session_from_address(hwaddr addr)
{
    unsigned session_id;

    if (addr < HYPERMEM_BASEADDR) return 0;
    session_id = (addr - HYPERMEM_BASEADDR) / sizeof(hypermem_entry_t);
    return (session_id < HYPERMEM_ENTRIES) ? session_id : 0;
}

static hwaddr hypermem_session_get_address(unsigned session_id)
{
    return session_id ? (HYPERMEM_BASEADDR + session_id * sizeof(hypermem_entry_t)) : 0;
}

static void hypermem_session_reset(HyperMemSessionState *session) {
    /* end the current command on the session (if any) and clean up
     * command state
     */
    switch (session->command) {
    case HYPERMEM_COMMAND_PRINT:
	if (session->command_state.print.strdata) {
	    free(session->command_state.print.strdata);
	}
	break;
    }
    session->command = 0;
    session->state = 0;
    memset(&session->command_state, 0, sizeof(session->command_state));
}

static HyperMemEdfiContext *edfi_context_create(HyperMemState *state,
                                                const char *name) {
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

static HyperMemEdfiContext *edfi_context_find(HyperMemState *state,
                                              const char *name) {
    HyperMemEdfiContext *ec;

    for (ec = state->edfi_context; ec; ec = ec->next) {
	if (strcmp(ec->name, name) == 0) return ec;
    }
    return NULL;
}

static void edfi_context_set_with_name(HyperMemState *state, const char *name,
                                       hypermem_entry_t contextptr) {
    HyperMemEdfiContext *ec;
    hwaddr page_hwaddr;
    vaddr page_count, page_index, page_vaddr;

    /* overwrite if we've seen this module before */
    ec = edfi_context_find(state, name);
    if (ec) {
	logprintf(state, "EDFI context reset module=%s\n", name);
    } else {
	ec = edfi_context_create(state, name);
	if (!ec) return;
	logprintf(state, "EDFI context set module=%s\n", name);
    }

    /* read EDFI context */
    if (cpu_memory_rw_debug(current_cpu, contextptr, (uint8_t *) &ec->context,
	sizeof(ec->context), 0) < 0) {
	fprintf(stderr, "hypermem: warning: cannot read EDFI context\n");
	return;
    }

    /* verify canary */
    if (ec->context.canary_value1 != EDFI_CANARY_VALUE ||
        ec->context.canary_value2 != EDFI_CANARY_VALUE) {
	fprintf(stderr, "hypermem: warning: EDFI context canaries incorrect\n");
	return;
    }

    /* store physical addresses for bb_num_executions */
    page_count = (sizeof(exec_count) * ec->context.num_bbs +
                 (vaddr) ec->context.bb_num_executions % TARGET_PAGE_SIZE +
		 TARGET_PAGE_SIZE - 1) / TARGET_PAGE_SIZE;
    ec->bb_num_executions_hwaddr = CALLOC(page_count, hwaddr);
    if (!ec->bb_num_executions_hwaddr) return;

    page_vaddr = (vaddr) ec->context.bb_num_executions;
    page_vaddr -= page_vaddr % TARGET_PAGE_SIZE;
    for (page_index = 0; page_index < page_count; page_index++) {
	page_hwaddr = cpu_get_phys_page_debug(current_cpu, page_vaddr);
	if (page_hwaddr == -1) {
	    fprintf(stderr, "hypermem: warning: EDFI context contains unmapped pages\n");
	    free(ec->bb_num_executions_hwaddr);
	    ec->bb_num_executions_hwaddr = NULL;
	    return;
	}
	ec->bb_num_executions_hwaddr[page_index] = page_hwaddr;
	page_vaddr += TARGET_PAGE_SIZE;
    }
}

static char *read_string(vaddr strptr, vaddr strlen) {
    char *str;

    str = CALLOC(strlen + 1, char);
    if (!str) return NULL;

    if (cpu_memory_rw_debug(current_cpu, strptr, (uint8_t *) str,
        strlen, 0) < 0) {
	fprintf(stderr, "hypermem: warning: cannot read string\n");
	free(str);
	return NULL;
    }
    str[strlen] = 0;
    return str;
}

static void edfi_context_set(HyperMemState *state, hypermem_entry_t nameptr,
                             hypermem_entry_t namelen,
			     hypermem_entry_t contextptr) {
    char *name;

    /* read module name from VM */
    name = read_string(nameptr, namelen);
    if (!name) return;

    /* now that we have the name, do the actual work */
    edfi_context_set_with_name(state, name, contextptr);

    /* clean up */
    free(name);
}

static void *load_from_hwaddrs(vaddr viraddr, vaddr size, hwaddr *hwaddrs) {
    uint8_t *buffer, *p;
    vaddr chunk;
    hwaddr hwaddr;

    buffer = CALLOC(size, uint8_t);
    if (!buffer) return NULL;

    /* load buffer from physical addresses, one page at a time */
    p = buffer;
    while (size > 0) {
	chunk = TARGET_PAGE_SIZE - viraddr % TARGET_PAGE_SIZE;
	hwaddr = *hwaddrs + viraddr % TARGET_PAGE_SIZE;
	cpu_physical_memory_read(hwaddr, p, chunk);
	viraddr += chunk;
	size -= chunk;
	hwaddrs++;
	p += chunk;
    }
    return buffer;
}

static void edfi_dump_stats_module_with_context(HyperMemState *state,
                                                HyperMemEdfiContext *ec) {
    exec_count *bb_num_executions, count, countrep;
    int i, repeats;

    /* copy bb_num_executions */
    bb_num_executions = load_from_hwaddrs((vaddr) ec->context.bb_num_executions,
	ec->context.num_bbs * sizeof(exec_count), ec->bb_num_executions_hwaddr);
    if (!bb_num_executions) return;

    /* dump execution counts with run-length encoding */
    logprintf(state, "edfi_dump_stats_module name=%s", ec->name);
    countrep = 0;
    repeats = 0;
    for (i = 0; i < ec->context.num_bbs; i++) {
        count = bb_num_executions[i];
	if (countrep == count) {
	    repeats++;
	} else {
	    if (repeats == 1) {
		logprintf(state, " %ld", (long) countrep);
	    } else if (repeats != 0) {
		logprintf(state, " %dx%ld", repeats, (long) countrep);
	    }
	    countrep = count;
	    repeats = 1;
	}
    }
    if (repeats == 1) {
	logprintf(state, " %ld", (long) countrep);
    } else if (repeats != 0) { 
	logprintf(state, " %dx%ld", repeats, (long) countrep);
    }
    logprintf(state, "\n");

    /* clean up */
    free(bb_num_executions);
}

static void edfi_dump_stats_all(HyperMemState *state) {
    HyperMemEdfiContext *ec;

    logprintf(state, "edfi_dump_stats\n");
    for (ec = state->edfi_context; ec; ec = ec->next) {
	edfi_dump_stats_module_with_context(state, ec);
    }
}

static void edfi_dump_stats_module_with_name(HyperMemState *state,
                                             const char *name) {
    HyperMemEdfiContext *ec = edfi_context_find(state, name);

    if (ec) {
	edfi_dump_stats_module_with_context(state, ec);
    } else {
	logprintf(state, "edfi_dump_stats_module name=%s no context known\n", name);
    }
}

static void edfi_dump_stats_module(HyperMemState *state,
                                   hypermem_entry_t nameptr,
                                   hypermem_entry_t namelen) {
    char *name;

    /* read module name from VM */
    name = read_string(nameptr, namelen);
    if (!name) return;

    /* now that we have the name, do the actual work */
    edfi_dump_stats_module_with_name(state, name);

    /* clean up */
    free(name);
}

static hypermem_entry_t edfi_faultindex_get_with_name(HyperMemState *state,
                                                      const char *name) {
    int bbindex;
    const char *faultspec, *next;
    size_t namelen = strlen(name);

    /* faultspec parameter present? */
    if (!state->faultspec) {
	logprintf(state, "edfi_faultindex_get name=%s "
	          "fault injection disabled\n", name);
	return 0;
    }

    /* find a matching pair in faultspec */
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

static hypermem_entry_t edfi_faultindex_get(HyperMemState *state,
                                            hypermem_entry_t nameptr,
                                            hypermem_entry_t namelen) {
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

static void log_fault(HyperMemState *state, hypermem_entry_t nameptr,
                             hypermem_entry_t namelen,
			     hypermem_entry_t bbindex) {
    char *name;

    /* read module name from VM */
    name = read_string(nameptr, namelen);
    if (!name) return;

    /* log fault */
    logprintf(state, "fault name=%s bbindex=0x%lx\n", name, (long) bbindex);

    /* clean up */
    free(name);
}

static hypermem_entry_t command_bad_read(HyperMemState *state,
                                         HyperMemSessionState *session)
{
    fprintf(stderr, "hypermem: warning: unexpected read during command %d\n",
            session->command);
    hypermem_session_reset(session);
    return 0;
}

static void command_bad_write(HyperMemState *state,
                              HyperMemSessionState *session,
                              hypermem_entry_t value)
{
    fprintf(stderr, "hypermem: warning: unexpected write during command %d "
            "(value=0x%llx)\n", session->command, (long long) value);
    hypermem_session_reset(session);
}

static void command_edfi_context_set_write(HyperMemState *state,
                              HyperMemSessionState *session,
                              hypermem_entry_t value)
{
    switch (session->state) {
    case 0:
	session->command_state.edfi_context_set.namelen = value;
	session->state++;
	break;
    case 1:
	session->command_state.edfi_context_set.nameptr = value;
	session->state++;
	break;
    default:
	edfi_context_set(state, session->command_state.edfi_context_set.nameptr,
	    session->command_state.edfi_context_set.namelen, value);
	hypermem_session_reset(session);
	break;
    }
}

static void command_edfi_dump_stats_module(HyperMemState *state,
                                           HyperMemSessionState *session,
                                           hypermem_entry_t value)
{
    switch (session->state) {
    case 0:
	session->command_state.edfi_dump_stats_module.namelen = value;
	session->state++;
	break;
    default:
	edfi_dump_stats_module(state, value,
	    session->command_state.edfi_dump_stats_module.namelen);
	hypermem_session_reset(session);
	break;
    }
}

static hypermem_entry_t command_edfi_faultindex_get_read(HyperMemState *state,
                                         HyperMemSessionState *session)
{
    hypermem_entry_t bbindex;

    switch (session->state) {
    case 2:
	bbindex = edfi_faultindex_get(state,
	                    session->command_state.edfi_faultindex_get.nameptr,
	                    session->command_state.edfi_faultindex_get.namelen);
	hypermem_session_reset(session);
	return bbindex;
    default:
	return command_bad_read(state, session);
    }
}

static void command_edfi_faultindex_get_write(HyperMemState *state,
                              HyperMemSessionState *session,
                              hypermem_entry_t value)
{
    switch (session->state) {
    case 0:
	session->command_state.edfi_faultindex_get.namelen = value;
	session->state++;
	break;
    case 1:
	session->command_state.edfi_faultindex_get.nameptr = value;
	session->state++;
	break;
    default:
	command_bad_write(state, session, value);
	break;
    }
}

static void command_fault_write(HyperMemState *state,
                              HyperMemSessionState *session,
                              hypermem_entry_t value)
{
    switch (session->state) {
    case 0:
	session->command_state.fault.namelen = value;
	session->state++;
	break;
    case 1:
	session->command_state.fault.nameptr = value;
	session->state++;
	break;
    default:
	log_fault(state, session->command_state.fault.nameptr,
	    session->command_state.fault.namelen, value);
	hypermem_session_reset(session);
	break;
    }
}

static hypermem_entry_t command_nop_read(HyperMemState *state,
                                         HyperMemSessionState *session)
{
    logprintf(state, "nop\n");
    hypermem_session_reset(session);
    return HYPERCALL_NOP_REPLY;
}

static void command_print_write(HyperMemState *state,
                              HyperMemSessionState *session,
                              hypermem_entry_t value)
{
    switch (session->state) {
    case 0:
	/* string length */
	session->command_state.print.strlen = value;
	session->command_state.print.strpos = 0;
	session->command_state.print.strdata =
	    CALLOC(value + sizeof(hypermem_entry_t), char);
	session->state++;
	break;
    default:
	/* string data, four bytes at a time */
	if (session->command_state.print.strdata) {
	    memcpy(session->command_state.print.strdata +
	           session->command_state.print.strpos,
	           &value, sizeof(hypermem_entry_t));
	}
	session->command_state.print.strpos += sizeof(hypermem_entry_t);
	break;
    }

    /* print string once we have all the chunks */
    if (session->command_state.print.strpos >=
        session->command_state.print.strlen) {
	if (session->command_state.print.strdata) {
	    session->command_state.print.strdata[session->command_state.print.strlen] = 0;
	    logprintf(state, "print %s\n", session->command_state.print.strdata);
	}
	hypermem_session_reset(session);
    }
}

static hypermem_entry_t handle_session_read(HyperMemState *state,
                                            HyperMemSessionState *session)
{
    /* handle a read operation within a session according to the current
     * command type
     */
    switch (session->command) {
    case 0: break;
    case HYPERMEM_COMMAND_EDFI_FAULTINDEX_GET: return command_edfi_faultindex_get_read(state, session);
    case HYPERMEM_COMMAND_NOP: return command_nop_read(state, session);
    default: return command_bad_read(state, session);
    }

    if (session->command) {
	fprintf(stderr, "hypermem: warning: read for invalid command %d\n",
	        session->command);
    } else {
	fprintf(stderr, "hypermem: warning: read before selecting command\n");
    }
    return 0;
}

static void handle_session_write(HyperMemState *state,
                                 HyperMemSessionState *session,
                                 hypermem_entry_t value)
{
    /* handle a write operation within a session according to the current
     * command type; if there is no current command, the value written is
     * the command identifier
     */
    switch (session->command) {
    case 0: break;
    case HYPERMEM_COMMAND_EDFI_CONTEXT_SET: command_edfi_context_set_write(state, session, value); return;
    case HYPERMEM_COMMAND_EDFI_DUMP_STATS_MODULE: command_edfi_dump_stats_module(state, session, value); return;
    case HYPERMEM_COMMAND_EDFI_FAULTINDEX_GET: command_edfi_faultindex_get_write(state, session, value); return;
    case HYPERMEM_COMMAND_FAULT: command_fault_write(state, session, value); return;
    case HYPERMEM_COMMAND_PRINT: command_print_write(state, session, value); return;
    default: command_bad_write(state, session, value); return;
    }

    if (!value) {
	fprintf(stderr, "hypermem: warning: command not specified\n");
    } else {
	session->command = value;

	/* command types that involve neither reads nor writes are
	 * handled immediately
	 */
	switch (session->command) {
	case HYPERMEM_COMMAND_EDFI_DUMP_STATS_MODULE:
	    edfi_dump_stats_all(state);
	    hypermem_session_reset(session);
	    break;
	}
    }
}

static hypermem_entry_t hypermem_mem_read_internal(HyperMemState *state,
                                                   hwaddr addr)
{
    hwaddr entry;
    unsigned session_id;
    hypermem_entry_t value;

#ifdef HYPERMEM_DEBUG
    printf("hypermem: read_internal; addr=0x%lx\n", (long) addr);
#endif

    /* verify address */
    entry = addr / sizeof(hypermem_entry_t);
    if (entry >= HYPERMEM_ENTRIES) {
	fprintf(stderr, "hypermem: error: read from invalid address 0x%lx\n",
	        (long) addr);
	return 0;
    }

    /* reads from base set up sessions */
    if (entry == 0) {
        session_id = hypermem_session_allocate(state);
#ifdef HYPERMEM_DEBUG
	printf("hypermem: set up new session %u at 0x%lx\n",
	       session_id, (long) hypermem_session_get_address(session_id));
#endif
	return hypermem_session_get_address(session_id);
    }

    /* other reads are in sessions */
    if (!state->sessions[entry].active) {
	fprintf(stderr, "hypermem: warning: attempt to read "
	        "in inactive session %u\n", (unsigned) entry);
	return 0;
    }
    value = handle_session_read(state, &state->sessions[entry]);
#ifdef HYPERMEM_DEBUG
    printf("hypermem: read_internal value 0x%lx\n", (long) value);
#endif
    return value;
}

static void hypermem_mem_write_internal(HyperMemState *state,
                                        hwaddr addr,
                                        hypermem_entry_t mem_value)
{
    hwaddr entry;
    unsigned session_id;

#ifdef HYPERMEM_DEBUG
    printf("hypermem: write_internal; addr=0x%lx, value=0x%lx\n",
	(long) addr, (long) mem_value);
#endif

    /* verify address */
    entry = addr / sizeof(hypermem_entry_t);
    if (entry >= HYPERMEM_ENTRIES) {
	fprintf(stderr, "hypermem: error: write to invalid address 0x%lx\n",
	        (long) addr);
	return;
    }

    /* writes to base tear down sessions */
    if (entry == 0) {
        session_id = hypermem_session_from_address(mem_value);
	if (!session_id) {
	    fprintf(stderr, "hypermem: warning: attempt to tear down session "
	            "for invalid address 0x%lx\n", (long) mem_value);
	    return;
	}
	if (!state->sessions[session_id].active) {
	    fprintf(stderr, "hypermem: warning: attempt to tear down inactive "
	            "session %u for address 0x%lx\n",
		    session_id, (long) mem_value);
	    return;
	}
#ifdef HYPERMEM_DEBUG
	printf("hypermem: tearing down session %u at 0x%lx\n",
	       session_id, (long) mem_value);
#endif
	hypermem_session_reset(&state->sessions[session_id]);
	state->sessions[session_id].active = 0;
	return;
    }

    /* other writes are in sessions */
    if (!state->sessions[entry].active) {
	fprintf(stderr, "hypermem: warning: attempt to write in inactive "
	        "session %u\n", (unsigned) entry);
	return;
    }
    handle_session_write(state, &state->sessions[entry], mem_value);
}

#define HYPERMEM_ENTRY_BYTES ((1 << sizeof(hypermem_entry_t)) - 1)

static HyperMemPendingOperation *hypermem_find_pending_operation(
    HyperMemState *state, int is_write, hwaddr addr, unsigned size,
    unsigned *bytemask) {
    hwaddr baseaddr = addr - addr % sizeof(hypermem_entry_t);
    int i;
    HyperMemPendingOperation *op, *opempty = NULL;

    /* we're assuming that QEMU splits up unaligned or oversized reads */
    assert(addr - baseaddr + size <= sizeof(op->value));
    *bytemask = ((1 << size) - 1) << (addr - baseaddr);

    /* locate a pending entry */
    for (i = 0; i < HYPERMEM_PENDING_MAX; i++) {
	op = &state->pending[i];
	if (!op->bytemask) {
	    if (!opempty) opempty = op;
	    continue;
	}
	if (!op->is_write != !is_write) continue;
	if (op->baseaddr != baseaddr) continue;
	if (is_write) {
	    if (!(op->bytemask & *bytemask)) return op;
	} else {
	    if (!(~op->bytemask & *bytemask)) return op;
	}
    }

    /* no entries available is an error (it means the VM is misbehaving) */
    if (!opempty) {
	fprintf(stderr, "hypermem: warning: %s, too many pending operations\n",
	    is_write ? "write ignored" : "read failed");
	return NULL;
    }

    /* allocate a new entry, bytemask is already clear */
    opempty->is_write = is_write;
    opempty->baseaddr = baseaddr;
    opempty->value = 0;
    return opempty;
}

static uint64_t hypermem_mem_read(void *opaque, hwaddr addr,
                                  unsigned size)
{
    unsigned bytemask;
    HyperMemPendingOperation *op;
    HyperMemState *state = opaque;
    int64_t value;

#ifdef HYPERMEM_DEBUG
    printf("hypermem: read; addr=0x%lx, size=0x%x\n", (long) addr, size);
#endif

    /* find a pending operation that has these bytes available for reading */
    op = hypermem_find_pending_operation(state, 0, addr, size, &bytemask);
    if (!op) return 0;

    /* perform a real read if we don't have the necessary bytes */
    if (!op->bytemask) {
	op->value = hypermem_mem_read_internal(state, op->baseaddr);
	op->bytemask = HYPERMEM_ENTRY_BYTES;
    }

    /* we're assuming that QEMU splits up unaligned or oversized reads */
    assert(addr - op->baseaddr + size <= sizeof(op->value));

    /* return the part requested and mark it not pending */
    value = 0;
    memcpy(&value, (char *) &op->value + (addr - op->baseaddr), size);
    op->bytemask &= ~bytemask;

#ifdef HYPERMEM_DEBUG
    printf("hypermem: read value 0x%llx\n", (long long) value);
#endif
    return value;
}

static void hypermem_mem_write(void *opaque,
                               hwaddr addr,
                               uint64_t mem_value,
                               uint32_t size)
{
    unsigned bytemask;
    HyperMemPendingOperation *op;
    HyperMemState *state = opaque;

#ifdef HYPERMEM_DEBUG
    printf("hypermem: write; addr=0x%lx, value=0x%lx, size=0x%lx\n",
	(long) addr, (long) mem_value, (long) size);
#endif

    /* find a pending operation that has these bytes available for reading */
    op = hypermem_find_pending_operation(state, 1, addr, size, &bytemask);
    if (!op) return;

    /* set the part requested and mark it pending */
    memcpy((char *) &op->value + (addr - op->baseaddr), &mem_value, size);
    op->bytemask |= bytemask;

    /* perform a real write once we have all the necessary bytes */
    if (!(~op->bytemask & HYPERMEM_ENTRY_BYTES)) {
	hypermem_mem_write_internal(state, op->baseaddr, op->value);
	op->bytemask = 0;
    }
}

const MemoryRegionOps hypermem_mem_ops = {
    .read = hypermem_mem_read,
    .write = hypermem_mem_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {
        .max_access_size = sizeof(hypermem_entry_t),
    },
    .impl = {
        .max_access_size = sizeof(hypermem_entry_t),
    },
};

static void hypermem_realizefn(DeviceState *dev, Error **errp)
{
    ISADevice *isadev = ISA_DEVICE(dev);
    HyperMemState *s = HYPERMEM(dev);

    /* open log file */
#ifdef HYPERMEM_DEBUG
    if (s->logpath) {
	printf("hypermem: log path \"%s\", %sflushing on every write\n",
	    s->logpath, s->flushlog ? "" : "not ");
    } else {
	printf("hypermem: logging to stdout\n");
    }
#endif
    if (s->logpath) {
	s->logfile = fopen(s->logpath, "w");
	if (!s->logfile) {
		perror("hypermem: could not open log file");
		exit(-1);
	}
    } else {
	s->logfile = stdout;
    }

    /* reserve memory area */
#ifdef HYPERMEM_DEBUG
    printf("hypermem: realize; HYPERMEM_BASEADDR=0x%lx, HYPERMEM_SIZE=0x%lx, "
	"isa_mem_base=0x%lx\n", (long) HYPERMEM_BASEADDR, (long) HYPERMEM_SIZE,
	(long) isa_mem_base);
#endif
    memory_region_init_io(&s->io, OBJECT(dev), &hypermem_mem_ops, s,
                          "hypermem-mem", HYPERMEM_SIZE);
    memory_region_set_flush_coalesced(&s->io);
    memory_region_add_subregion_overlap(isa_address_space(isadev),
                                        isa_mem_base + HYPERMEM_BASEADDR,
                                        &s->io, HYPERMEM_PRIO);
    memory_region_set_coalescing(&s->io);
}

static void hypermem_class_initfn(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

#ifdef HYPERMEM_DEBUG
    printf("hypermem: class init\n");
#endif
    dc->realize = hypermem_realizefn;
    dc->props   = hypermem_props;
}

static const TypeInfo hypermem_info = {
    .name          = TYPE_HYPERMEM,
    .parent        = TYPE_ISA_DEVICE,
    .instance_size = sizeof(HyperMemState),
    .class_init    = hypermem_class_initfn,
};

static void hypermem_register_types(void)
{
#ifdef HYPERMEM_DEBUG
    printf("hypermem: registering type\n");
#endif
    type_register_static(&hypermem_info);
}

type_init(hypermem_register_types)
