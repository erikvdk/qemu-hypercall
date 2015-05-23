#ifndef HYPERMEM_H
#define HYPERMEM_H

#include "hypermem-magic.h"
#include "hypermem-edfi.h"
#include "hyperst.h"

#define HYPERMEM_ENTRIES        (HYPERMEM_SIZE / sizeof(hypermem_entry_t))
#define HYPERMEM_PRIO           3 /* 1 and 2 used by video memory */
#define HYPERMEM_PENDING_MAX    HYPERMEM_ENTRIES


#define TYPE_HYPERMEM           "hypermem"
#define HYPERMEM(obj)           OBJECT_CHECK(HyperMemState, (obj), TYPE_HYPERMEM)

/*
 * Structure Declarations
 */

/* Struct used to store a state for every session generated to hypermem
 * from inside the guest, and that stores data necessary for proper handling
 * since the protocol forced upon as has quite some restrictions
 */

typedef struct HyperMemSessionState {
    int active;
    int command;
    int state;

    /* command state */
    union {
        struct {
            hypermem_entry_t namelen;
            hypermem_entry_t nameptr;
            hypermem_entry_t contextptr;
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
        struct {
            hypermem_entry_t namelen;
            hypermem_entry_t nameptr;
            hypermem_entry_t contextptr;
        } magic_context_set;
        struct {
            hypermem_entry_t namelen;
        } magic_st;
    } command_state;

    /* the cr3 in case we need this to do page translation */
    uint32_t process_cr3;
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
    char *faultspec;
    char *hyperst;

    /* QEMU objects */
    MemoryRegion io;

    /* logging */
    struct logstate *logstate;
    int logfile_driveindex;

    /* EDFI contexts (linked list) */
    HyperMemEdfiContext *edfi_context;

    /* Magic contexts (linked list) */
    HyperMemMagicContext *magic_context;

    /* session state */
    unsigned session_next;
    HyperMemSessionState sessions[HYPERMEM_ENTRIES];

    /* state for partial reads and writes */
    HyperMemPendingOperation pending[HYPERMEM_PENDING_MAX];
} HyperMemState;

struct logstate {
    /* log file */
    FILE *logfile;
    int logfile_partialline;
    bool flushlog;

    /* fault reporting aggregation */
    hypermem_entry_t fault_bbindex;
    unsigned long fault_count;
    char *fault_name;
    struct timeval fault_time;
    int fault_noflush;

    /* interrupt reporting */
    uint32_t interrupts;
};

/*
 * Utils Declarations
 */
#define CALLOC(count, type) ((type *) calloc_checked((count), sizeof(type), __FILE__, __LINE__))

static inline void *calloc_checked(size_t count, size_t size,
                                   const char *file, int line) {
    void *p;

    if (!count || !size) {
        return NULL;
    }

    p = calloc(count, size);
    if (!p) {
        fprintf(stderr, "hypermem: error: calloc(%lu, %lu) failed at %s:%d: %s\n",
                (long) count, (long) size,
                file, line, strerror(errno));
    }
    return p;
}

int vaddr_to_laddr(vaddr ptr, vaddr *result);
char *read_string(vaddr strptr, vaddr strlen);
size_t read_with_pagetable(uint32_t cr3, uint32_t cr4, vaddr linaddr,
    void *buffer, size_t size);
void logprintf(HyperMemState *state, const char *fmt, ...)
    __attribute__ ((__format__ (__printf__, 2, 3)));
void logprintf_internal(struct logstate *state, const char *fmt, ...)
    __attribute__ ((__format__ (__printf__, 2, 3)));
/*
 * Function Prototypes
 */

int start_hyperst(HyperMemState *state, char *path, char *target);

/* Magic Hypermem functions */

HyperMemMagicContext *magic_context_create(HyperMemState *state, const char *name);
HyperMemMagicContext *magic_context_find(HyperMemState *state, const char *name);
void *magic_get_vars_with_context(HyperMemState *state, HyperMemMagicContext *mc);
void magic_context_set_with_name(
        HyperMemState *state,
        const char *name,
        hypermem_entry_t contextptr,
        hypermem_entry_t contextsize);
void *magic_get_range_with_context(
        HyperMemState *state,
        HyperMemMagicContext *mc,
        uint32_t addr,
        uint32_t size);
void magic_do_st(
        HyperMemState *state,
        hypermem_entry_t nameptr,
        hypermem_entry_t namelen);
void magic_do_st_all(HyperMemState *state);

void magic_context_set(
        HyperMemState *state,
        hypermem_entry_t nameptr,
        hypermem_entry_t namelen,
        hypermem_entry_t contextptr,
        hypermem_entry_t contextsize);

/* EDFI Hypermem functions */
HyperMemEdfiContext *edfi_context_create(HyperMemState *state, const char *name);
HyperMemEdfiContext *edfi_context_find(HyperMemState *state, const char *name);
void edfi_context_release(HyperMemState *state, uint32_t process_cr3);
void edfi_context_set_with_name(
        HyperMemState *state, 
        const char *name,
        hypermem_entry_t contextptr,
        hypermem_entry_t ptroffset,
	uint32_t process_cr3);
void edfi_context_set(
        HyperMemState *state,
        hypermem_entry_t nameptr,
        hypermem_entry_t namelen,
        hypermem_entry_t contextptr,
        hypermem_entry_t ptroffset,
	uint32_t process_cr3);

void edfi_dump_stats_module_with_context(HyperMemState *state, HyperMemEdfiContext *ec);
void edfi_dump_stats_all(HyperMemState *state);
void edfi_dump_stats_module_with_name(HyperMemState *state, const char *name);
void edfi_dump_stats_module(
        HyperMemState *state,
        hypermem_entry_t nameptr,
        hypermem_entry_t namelen);

hypermem_entry_t edfi_faultindex_get_with_name(HyperMemState *state, const char *name);
hypermem_entry_t edfi_faultindex_get(
        HyperMemState *state,
        hypermem_entry_t nameptr,
        hypermem_entry_t namelen);


void flush_fault(struct logstate *state);
void log_fault(
        struct logstate *state,
        hypermem_entry_t nameptr,
        hypermem_entry_t namelen,
        hypermem_entry_t bbindex);


#endif
