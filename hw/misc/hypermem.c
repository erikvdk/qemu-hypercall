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

typedef struct HyperMemState
{
    ISADevice parent_obj;

    /* properties */
    char *logpath;
    bool flushlog;

    /* QEMU objects */
    MemoryRegion io;

    /* open handles */
    FILE *logfile;

    /* session state */
    unsigned session_next;
    HyperMemSessionState sessions[HYPERMEM_ENTRIES];

    /* state for partial reads and writes */
    HyperMemPendingOperation pending[HYPERMEM_PENDING_MAX];
} HyperMemState;

static Property hypermem_props[] = {
    DEFINE_PROP_STRING("logpath", HyperMemState, logpath),
    DEFINE_PROP_BOOL("flushlog", HyperMemState, flushlog, false),
    DEFINE_PROP_END_OF_LIST()
};

static void logvprintf(HyperMemState *state, const char *fmt, va_list args) {
    vfprintf(state->logfile, fmt, args);
    if (state->flushlog) fflush(state->logfile);
}

static void logprintf(HyperMemState *state, const char *fmt, ...)
    __attribute__ ((__format__ (__printf__, 2, 3)));

static void logprintf(HyperMemState *state, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    logvprintf(state, fmt, args);
    va_end(args);
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

static void edfi_context_set(HyperMemState *state, hypermem_entry_t nameptr,
    hypermem_entry_t namelen, hypermem_entry_t contextptr) {
    edfi_context_t context;
    CPUState *cpu - current_cpu;
    char *name = NULL;

    /* read module name from VM */
    name = malloc(namelen + 1);
    if (!name) {
	fprintf(stderr, "hypermem: edfi_context_set: cannot allocate buffer "
		"for name (namelen=%lu): %s\n",
		(unsigned) namelen, strerror(errno));
	goto cleanup;
    }
    if (cpu_memory_rw_debug(cpu, nameptr, name, namelen, 0) < 0) {
	fprintf(stderr, "hypermem: edfi_context_set: cannot read name\n");
	goto cleanup;
    }
    name[namelen] = 0;

    /* read EDFI context */
    if (cpu_memory_rw_debug(cpu, contextptr, &context, sizeof(context), 0) < 0) {
	fprintf(stderr, "hypermem: edfi_context_set: cannot read context\n");
	goto cleanup;
    }

    /* TODO verify canary */
    /* TODO store physical addresses canary */

cleanup:
    /* clean up any allocated buffers not stored */
    if (name) free(name);
}

static hypermem_entry_t command_bad_read(HyperMemState *state,
                                         HyperMemSessionState *session)
{
    fprintf(stderr, "hypermem: unexpected read during command %d\n",
            session->command);
    return 0;
}

static void command_bad_write(HyperMemState *state,
                              HyperMemSessionState *session,
                              hypermem_entry_t value)
{
    fprintf(stderr, "hypermem: unexpected write during command %d "
            "(value=0x%llx)\n", session->command, (long long) value);
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
	logprintf(state, "edfi_context_set context=0x%lx\n", (long) value);
	edfi_context_set(state, session->command_state.edfi_context_set.nameptr,
	    session->command_state.edfi_context_set.namelen, value);
	hypermem_session_reset(session);
	break;
    }
}

static void command_fault_write(HyperMemState *state,
                              HyperMemSessionState *session,
                              hypermem_entry_t value)
{
    logprintf(state, "fault bbindex=0x%lx\n", (long) value);
    hypermem_session_reset(session);
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
	session->command_state.print.strlen = value;
	session->command_state.print.strpos = 0;
	session->command_state.print.strdata = malloc(value + sizeof(hypermem_entry_t));
	if (!session->command_state.print.strdata) {
	    fprintf(stderr, "hypermem: cannot allocate print buffer: %s\n",
	            strerror(errno));
	}
	session->state++;
	break;
    default:
	if (session->command_state.print.strdata) {
	    memcpy(session->command_state.print.strdata +
	           session->command_state.print.strpos,
	           &value, sizeof(hypermem_entry_t));
	}
	session->command_state.print.strpos += sizeof(hypermem_entry_t);
	break;
    }

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
    switch (session->command) {
    case HYPERMEM_COMMAND_EDFI_CONTEXT_SET: return command_bad_read(state, session);
    case HYPERMEM_COMMAND_FAULT: return command_bad_read(state, session);
    case HYPERMEM_COMMAND_NOP: return command_nop_read(state, session);
    case HYPERMEM_COMMAND_PRINT: return command_bad_read(state, session);
    }

    if (session->command) {
	fprintf(stderr, "hypermem: read for invalid command %d\n",
	        session->command);
    } else {
	fprintf(stderr, "hypermem: read before selecting command\n");
    }
    return 0;
}

static void handle_session_write(HyperMemState *state,
                                 HyperMemSessionState *session,
                                 hypermem_entry_t value)
{
    switch (session->command) {
    case HYPERMEM_COMMAND_EDFI_CONTEXT_SET: command_edfi_context_set_write(state, session, value); return;
    case HYPERMEM_COMMAND_FAULT: command_fault_write(state, session, value); return;
    case HYPERMEM_COMMAND_NOP: command_bad_write(state, session, value); return;
    case HYPERMEM_COMMAND_PRINT: command_print_write(state, session, value); return;
    }

    if (session->command) {
	fprintf(stderr, "hypermem: write for invalid command %d\n",
	        session->command);
    } else if (!value) {
	fprintf(stderr, "hypermem: command not specified\n");
    } else {
	session->command = value;
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
	fprintf(stderr, "hypermem: read from invalid address 0x%lx\n",
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
	fprintf(stderr, "hypermem: attempt to read in inactive session %u\n",
	        (unsigned) entry);
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
	fprintf(stderr, "hypermem: write to invalid address 0x%lx\n",
	        (long) addr);
	return;
    }

    /* writes to base tear down sessions */
    if (entry == 0) {
        session_id = hypermem_session_from_address(mem_value);
	if (!session_id) {
	    fprintf(stderr, "hypermem: attempt to tear down session for "
	            "invalid address 0x%lx\n", (long) mem_value);
	    return;
	}
	if (!state->sessions[session_id].active) {
	    fprintf(stderr, "hypermem: attempt to tear down inactive session "
	            "%u for address 0x%lx\n", session_id, (long) mem_value);
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
	fprintf(stderr, "hypermem: attempt to write in inactive session %u\n",
	        (unsigned) entry);
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
	fprintf(stderr, "hypermem: %s, too many pending operations\n",
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
