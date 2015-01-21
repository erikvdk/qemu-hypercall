#ifndef HYPERMEM_MAGIC_H
#define HYPERMEM_MAGIC_H

extern CPUState *hyperst_cpu;
typedef struct HyperMemMagicContext {
    struct HyperMemMagicContext *next;

    char *name;
    uint32_t _magic_vars_addr;
    uint32_t _magic_vars_size;
} HyperMemMagicContext;


#endif
