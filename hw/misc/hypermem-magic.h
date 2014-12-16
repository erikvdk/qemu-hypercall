#ifndef HYPERMEM_MAGIC_H
#define HYPERMEM_MAGIC_H

typedef struct HyperMemMagicContext {
    struct HyperMemMagicContext *next;

    char *name;
} HyperMemMagicContext;


#endif
