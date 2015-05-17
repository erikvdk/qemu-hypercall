#ifndef HYPERMEM_H
#define HYPERMEM_H

#include <sys/types.h>

struct hypermem_session {
	int mem_fd;
	off_t address;
};

int hypermem_connect(struct hypermem_session *session);
void hypermem_disconnect(struct hypermem_session *session);

void hypermem_edfi_context_set(struct hypermem_session *session,
	const char *name, const void *context, ptrdiff_t ptroffset);
void hypermem_edfi_dump_stats(struct hypermem_session *session);
void hypermem_edfi_dump_stats_module(struct hypermem_session *session,
	const char *name);
int hypermem_edfi_faultindex_get(struct hypermem_session *session,
	const char *name);
void hypermem_fault(struct hypermem_session *session, const char *name,
	unsigned bbindex);
int hypermem_nop(struct hypermem_session *session);
void hypermem_print(struct hypermem_session *session, const char *str);
int hypermem_quit(struct hypermem_session *session);

#endif /* !defined(HYPERMEM_H) */
