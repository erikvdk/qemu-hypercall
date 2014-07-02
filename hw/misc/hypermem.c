#include "hw/hw.h"
#include "hw/isa/isa.h"
#include "hw/i386/pc.h"
#include "sysemu/kvm.h"
#include "hw/qdev.h"

/*
 * hypermem protocol - session management
 * - read from HYPERMEM_BASEADDR (in physical memory) of a
 *   hypermem_entry_t-sized value initiates a session
 * - in case of success, the read returns the communication address for
 *   the session; it is within the range
 *   HYPERMEM_BASEADDR...HYPERMEM_BASEADDR+HYPERMEM_SIZE
 * - in case of failure because no more sessions are available,
 *   the read returns 0
 * - further communication within the session proceeds by reads and writes of
 *   hypermem_entry_t-sized values to/from the communication address
 * - each command starts by writing a command identifier to the communication
 *   address and the remainder of the sequence of operations is determinied
 *   by the protocol specified for that command type
 * - after a command has been completed the session process take another command
 * - the session is ended by writing the communication address
 *   to HYPERMEM_BASEADDR
 *
 * hypermem protocol - nop
 * - write command identifier HYPERMEM_COMMAND_NOP
 * - read back reply
*  - if the reply is HYPERCALL_NOP_REPLY, the hypermem interface works
 */

#define HYPERMEM_DEBUG

typedef uint32_t hypermem_entry_t;
#define HYPERMEM_BASEADDR	0xc0000
#define HYPERMEM_SIZE		0x01000
#define HYPERMEM_ENTRIES	(HYPERMEM_SIZE / sizeof(hypermem_entry_t))

#define HYPERMEM_COMMAND_NOP	1

#define HYPERCALL_NOP_REPLY	0x4e6f7021

#define TYPE_HYPERMEM "hypermem"
#define HYPERMEM(obj) OBJECT_CHECK(HyperMemState, (obj), TYPE_HYPERMEM)



typedef struct HyperMemSessionState {
	int active;
} HyperMemSessionState;

typedef struct HyperMemState
{
    ISADevice parent_obj;

    MemoryRegion io;
    int session_next;
    HyperMemSessionState sessions[HYPERMEM_ENTRIES];
} HyperMemState;

static uint64_t hypermem_mem_read(void *opaque, hwaddr addr,
                                  unsigned size)
{
#ifdef HYPERMEM_DEBUG
    printf("hypermem: read; addr=0x%lx, size=0x%x\n", (long) addr, size);
#endif
    /* TODO: implement */
}

static void hypermem_mem_write(void *opaque,
                               hwaddr addr,
                               uint64_t mem_value,
                               uint32_t size)
{
#ifdef HYPERMEM_DEBUG
    printf("hypermem: write; addr=0x%lx, value=0x%llx, size=0x%lx\n",
	(long) addr, (long long) value, (long) size);
#endif
    /* TODO: implement */
}

const MemoryRegionOps hypermem_mem_ops = {
    .read = hypermem_mem_read,
    .write = hypermem_mem_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl = {
        .min_access_size = sizeof(hypermem_entry_t),
        .max_access_size = sizeof(hypermem_entry_t),
    },
};

static void hypermem_realizefn(DeviceState *dev, Error **errp)
{
    ISADevice *isadev = ISA_DEVICE(dev);
    HyperMemState *s = HYPERMEM(dev);

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
                                        &s->io, 1);
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
