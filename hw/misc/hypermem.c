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
#include "qemu/config-file.h"
#include "qemu/option.h"

#include "helper.h"
#include "exec/softmmu_exec.h"
#include "qmp-commands.h"

#include <qemu/hypermem-api.h>

#include "hypermem.h"

static struct logstate *global_logstate;


static Property hypermem_props[] = {
    DEFINE_PROP_STRING("logpath", HyperMemState, logpath),
    DEFINE_PROP_BOOL("flushlog", HyperMemState, flushlog, false),
    DEFINE_PROP_STRING("faultspec", HyperMemState, faultspec),
    DEFINE_PROP_STRING("hyperst", HyperMemState, hyperst),
    DEFINE_PROP_END_OF_LIST()
};

static void logvprintf_internal(struct logstate *state, const char *fmt, va_list args) {
    int newline;
    struct timeval time = {};
    struct tm timefields = {};

    if (!fmt || !fmt[0]) return;

    flush_fault(state);

    /* write time when at start/after newline */
    if (!state->logfile_partialline) {
	if (state->fault_noflush) {
	    time = state->fault_time;
	} else {
	    if (gettimeofday(&time, NULL) < 0) {
		perror("gettimofday failed");
		exit(-1);
	    }
	}
	if (!localtime_r(&time.tv_sec, &timefields)) {
	    perror("localtime_r failed");
	    exit(-1);
	}
	fprintf(state->logfile, "[%.4d-%.2d-%.2d %2d:%.2d:%.2d.%.6d] ",
	    timefields.tm_year + 1900, timefields.tm_mon + 1,
	    timefields.tm_mday, timefields.tm_hour, timefields.tm_min,
	    timefields.tm_sec, (int) time.tv_usec);
    }

    /* write text to be logged */
    vfprintf(state->logfile, fmt, args);

    /* if requested, flush after newline  */
    newline = fmt[strlen(fmt) - 1] == '\n';
    if (state->flushlog && newline) fflush(state->logfile);
    state->logfile_partialline = !newline;
}

void logprintf_internal(struct logstate *state, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    logvprintf_internal(state, fmt, args);
    va_end(args);
}

static void logvprintf(HyperMemState *state, const char *fmt, va_list args) {
    logvprintf_internal(state->logstate, fmt, args);
}

void logprintf(HyperMemState *state, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    logvprintf(state, fmt, args);
    va_end(args);
}

static void swap_cr3(HyperMemSessionState *session) {
    X86CPU *cpu = X86_CPU(current_cpu);
    bool kvm_vcpu_dirty;
    uint32_t tmp;

    /* If we don't have a process_cr3 to swap we do nothing */
    kvm_vcpu_dirty = current_cpu->kvm_vcpu_dirty;
    cpu_synchronize_state(current_cpu);
    current_cpu->kvm_vcpu_dirty = kvm_vcpu_dirty;
    if (session->process_cr3 == 0)
        return;
    tmp = cpu->env.cr[3];
    cpu->env.cr[3] = session->process_cr3;
    session->process_cr3 = tmp;
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
    case 2:
	session->command_state.edfi_context_set.contextptr = value;
	session->state++;
	break;
    default:
	edfi_context_set(state, session->command_state.edfi_context_set.nameptr,
	    session->command_state.edfi_context_set.namelen,
	    session->command_state.edfi_context_set.contextptr, value,
	    session->process_cr3);
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
	log_fault(state->logstate, session->command_state.fault.nameptr,
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

static void command_release_cr3(HyperMemState *state,
                            HyperMemSessionState *session,
                            hypermem_entry_t value)
{
    edfi_context_release(state, value);
    hypermem_session_reset(session);
}

static void command_set_cr3(HyperMemState *state,
                            HyperMemSessionState *session,
                            hypermem_entry_t value)
{
    session->process_cr3 = value;
    hypermem_session_reset(session);
}

static void command_magic_context_set_write(HyperMemState *state,
                            HyperMemSessionState *session,
                            hypermem_entry_t value)
{
    switch (session->state) {
    case 0:
        session->command_state.magic_context_set.namelen = value;
        session->state++;
        break;
    case 1:
        session->command_state.magic_context_set.nameptr = value;
        session->state++;
        break;
    case 2:
        session->command_state.magic_context_set.contextptr = value;
        session->state++;
        break;
    default:
        swap_cr3 (session);
        magic_context_set(state,
                session->command_state.magic_context_set.nameptr,
                session->command_state.magic_context_set.namelen,
                session->command_state.magic_context_set.contextptr,
                value);
        swap_cr3 (session);
        hypermem_session_reset(session);
	break;
    }

}

static void command_magic_st_module(HyperMemState *state,
                            HyperMemSessionState *session,
                            hypermem_entry_t value)
{

    switch (session->state) {
    case 0:
        session->command_state.magic_st.namelen = value;
        session->state++;
        break;
    default:
        swap_cr3(session);
        magic_do_st(state, value,
            session->command_state.edfi_dump_stats_module.namelen);
        swap_cr3(session);
        hypermem_session_reset(session);
        break;
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
    case HYPERMEM_COMMAND_RELEASE_CR3: command_release_cr3(state, session, value); return;
    case HYPERMEM_COMMAND_SET_CR3: command_set_cr3(state, session, value); return;
    case HYPERMEM_COMMAND_MAGIC_CONTEXT_SET: command_magic_context_set_write(state, session, value); return;
    case HYPERMEM_COMMAND_MAGIC_ST: command_magic_st_module(state, session, value); return;
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
	case HYPERMEM_COMMAND_EDFI_DUMP_STATS:
	    edfi_dump_stats_all(state);
	    hypermem_session_reset(session);
	    break;
	case HYPERMEM_COMMAND_MAGIC_ST_ALL:
	    magic_do_st_all(state);
	    hypermem_session_reset(session);
	    break;
	case HYPERMEM_COMMAND_QUIT:
            logprintf(state, "quitting QEMU\n");
	    qmp_quit(NULL);
	    hypermem_session_reset(session); /* QEMU should be gone here, but just in case */
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

static int log_drive_options(QemuOpts *opts, void *opaque) {
    const char *file;
    HyperMemState *s = opaque;

    if (!opts) return 0;

    file = qemu_opt_get(opts, "file");
    if (!file) return 0;

    logprintf(s, "drive[%d]={ file: \"%s\" }\n", s->logfile_driveindex, file);
    s->logfile_driveindex++;

    return 0;
}

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
    global_logstate = s->logstate =
	(struct logstate *) calloc(1, sizeof(struct logstate));
    s->logstate->flushlog = s->flushlog;
    if (!s->logstate) {
	fprintf(stderr, "error: hypermem: "
	    "cannot allocate memory for log state\n");
	exit(-1);
    }
    if (s->logpath) {
	s->logstate->logfile = fopen(s->logpath, "w");
	if (!s->logstate->logfile) {
		perror("hypermem: could not open log file");
		exit(-1);
	}
    } else {
	s->logstate->logfile = stdout;
    }
    if (s->logpath) logprintf(s, "hypermem-logpath=\"%s\"\n", s->logpath);
    logprintf(s, "hypermem-flushlog=%s\n", s->flushlog ? "true" : "false");
    if (s->faultspec) logprintf(s, "hypermem-faultspec=\"%s\"\n", s->faultspec);
    qemu_opts_foreach(qemu_find_opts("drive"), log_drive_options, s, 0);

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

static void hypermem_cleanup(void) {
    if (!global_logstate || !global_logstate->logfile) return;
    logprintf_internal(global_logstate, "QEMU exiting\n");
}

static void hypermem_log_interrupt(int intno) {
    if (!global_logstate || !global_logstate->logfile) return;

    if (intno >= sizeof(global_logstate->interrupts) * 8 ||
	((1 << intno) & global_logstate->interrupts)) {
	return;
    }
    global_logstate->interrupts |= (1 << intno);

    logprintf_internal(global_logstate, "Interrupt %d\n", intno);
}

static void hypermem_register_types(void)
{
#ifdef HYPERMEM_DEBUG
    printf("hypermem: registering type\n");
#endif
    type_register_static(&hypermem_info);
    assert(!log_interrupt);
    log_interrupt = hypermem_log_interrupt;
    atexit(hypermem_cleanup);
}

type_init(hypermem_register_types)
