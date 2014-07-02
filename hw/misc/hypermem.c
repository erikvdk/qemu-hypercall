#include "hw/hw.h"
#include "hw/isa/isa.h"
#include "hw/i386/pc.h"
#include "sysemu/kvm.h"
#include "hw/qdev.h"

#include <qemu/hypermem-api.h>

#define HYPERMEM_ENTRIES	(HYPERMEM_SIZE / sizeof(hypermem_entry_t))
#define HYPERMEM_PRIO		3 /* 1 and 2 used by video memory */

#define HYPERMEM_DEBUG

#define TYPE_HYPERMEM "hypermem"
#define HYPERMEM(obj) OBJECT_CHECK(HyperMemState, (obj), TYPE_HYPERMEM)

typedef struct HyperMemSessionState {
	int active;
	int command;
	int state;
} HyperMemSessionState;

typedef struct HyperMemState
{
    ISADevice parent_obj;

    MemoryRegion io;
    unsigned session_next;
    HyperMemSessionState sessions[HYPERMEM_ENTRIES];

    hwaddr pending_read_addr;
    hypermem_entry_t pending_read_value;
    unsigned pending_read_bytes;
    hwaddr pending_write_addr;
    hypermem_entry_t pending_write_value;
    unsigned pending_write_bytes;
} HyperMemState;

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

static hypermem_entry_t command_nop_read(HyperMemSessionState *session)
{
    session->command = 0;
    return HYPERCALL_NOP_REPLY;
}

static void command_nop_write(HyperMemSessionState *session, hypermem_entry_t value)
{
    fprintf(stderr, "hypermem: unexpected write during NOP command "
            "(value=0x%llx)\n", (long long) value);
}

static hypermem_entry_t handle_session_read(HyperMemSessionState *session)
{
    switch (session->command) {
    case HYPERMEM_COMMAND_NOP: return command_nop_read(session);
    }

    if (session->command) {
	fprintf(stderr, "hypermem: read for invalid command %d\n",
	        session->command);
    } else {
	fprintf(stderr, "hypermem: read before selecting command\n");
    }
    return 0;
}

static void handle_session_write(HyperMemSessionState *session, hypermem_entry_t value)
{
    switch (session->command) {
    case HYPERMEM_COMMAND_NOP: command_nop_write(session, value); return;
    }

    if (session->command) {
	fprintf(stderr, "hypermem: write for invalid command %d\n",
	        session->command);
    } else if (!value) {
	fprintf(stderr, "hypermem: command not specified\n");
    } else {
	session->command = value;
	session->state = 0;
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
    value = handle_session_read(&state->sessions[entry]);
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
	state->sessions[session_id].active = 0;
	return;
    }

    /* other writes are in sessions */
    if (!state->sessions[entry].active) {
	fprintf(stderr, "hypermem: attempt to write in inactive session %u\n",
	        (unsigned) entry);
	return;
    }
    handle_session_write(&state->sessions[entry], mem_value);
}

#define HYPERMEM_ENTRY_BYTES ((1 << sizeof(hypermem_entry_t)) - 1)

static uint64_t hypermem_mem_read(void *opaque, hwaddr addr,
                                  unsigned size)
{
    hwaddr baseaddr = addr - addr % sizeof(hypermem_entry_t);
    unsigned bytemask = ((1 << size) - 1) << (addr - baseaddr);
    HyperMemState *state = opaque;
    int64_t value;

#ifdef HYPERMEM_DEBUG
    printf("hypermem: read; addr=0x%lx, size=0x%x\n", (long) addr, size);
#endif

    /* we're assuming that QEMU splits up reads that are either unaligned
     * or too large
     */
    assert(addr - baseaddr + size <= sizeof(hypermem_entry_t));

    /* perform a real read if we don't have all the necessary bytes */
    if (state->pending_read_addr != baseaddr ||
	(state->pending_read_bytes & bytemask) != bytemask) {
	if (state->pending_read_bytes) {
	    fprintf(stderr, "hypermem: partial read at 0x%lx\n",
		(long) state->pending_read_addr);
	}
	state->pending_read_addr = baseaddr;
	state->pending_read_bytes = HYPERMEM_ENTRY_BYTES;
	state->pending_read_value = hypermem_mem_read_internal(state, baseaddr);
    }

    /* select the part requested and mark it not pending */
    value = 0;
    memcpy(&value, (char *) &state->pending_read_value + (addr - baseaddr),
           size);
    state->pending_read_bytes &= ~bytemask;

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
    hwaddr baseaddr = addr - addr % sizeof(hypermem_entry_t);
    unsigned bytemask = ((1 << size) - 1) << (addr - baseaddr);
    HyperMemState *state = opaque;
    int64_t value;

#ifdef HYPERMEM_DEBUG
    printf("hypermem: write; addr=0x%lx, value=0x%lx, size=0x%lx\n",
	(long) addr, (long) mem_value, (long) size);
#endif

    /* we're assuming that QEMU splits up writes that are either unaligned
     * or too large
     */
    assert(addr - baseaddr + size <= sizeof(hypermem_entry_t));

    /* clean up when writing at another location or when overwriting previously
     * written bytes that did not fill up a word
     */
    if (state->pending_write_addr != baseaddr ||
	(state->pending_write_bytes & bytemask)) {
	if (state->pending_write_bytes) {
	    fprintf(stderr, "hypermem: partial write at 0x%lx ignored\n",
		(long) state->pending_write_addr);
	}
	state->pending_write_addr = baseaddr;
	state->pending_write_bytes = 0;
	state->pending_write_value = 0;
    }

    /* store the part requested and mark it pending */
    memcpy((char *) &state->pending_write_value + (addr - baseaddr), &value,
           size);
    state->pending_write_bytes |= bytemask;

    /* perform the actual write when we have a full word */
    if ((state->pending_write_bytes & HYPERMEM_ENTRY_BYTES) ==
        HYPERMEM_ENTRY_BYTES) {
	hypermem_mem_write_internal(state, state->pending_write_addr,
	                            state->pending_write_value);
	state->pending_write_bytes = 0;
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
