#ifndef HYPERMEM_H
#define HYPERMEM_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

struct hypermem_session {
	int mem_fd;
	off_t address;
};

int hypermem_connect(struct hypermem_session *session);
void hypermem_disconnect(struct hypermem_session *session);

void hypermem_edfi_context_set(const struct hypermem_session *session,
	const char *name, const void *context, ptrdiff_t ptroffset);
void hypermem_edfi_dump_stats(const struct hypermem_session *session);
void hypermem_edfi_dump_stats_module(const struct hypermem_session *session,
	const char *name);
int hypermem_edfi_faultindex_get(const struct hypermem_session *session,
	const char *name);
void hypermem_fault(const struct hypermem_session *session, const char *name,
	unsigned bbindex);
void hypermem_magic_register(const struct hypermem_session *session);
void hypermem_magic_st_module(const struct hypermem_session *session);
void hypermem_magic_st(const struct hypermem_session *session);
int hypermem_nop(const struct hypermem_session *session);
void hypermem_print(const struct hypermem_session *session, const char *str);
void hypermem_quit(const struct hypermem_session *session);
void hypermem_release_cr3(const struct hypermem_session *session,
    uint32_t cr3);
void hypermem_set_cr3(const struct hypermem_session *session, uint32_t cr3);

#endif /* !defined(HYPERMEM_H) */
