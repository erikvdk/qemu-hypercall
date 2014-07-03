#ifndef HYPERMEM_H
#define HYPERMEM_H

#include <sys/types.h>

struct hypermem_session {
	int mem_fd;
	off_t address;
};

int hypermem_connect(struct hypermem_session *session);
void hypermem_disconnect(struct hypermem_session *session);

void hypermem_edfi_context_set(struct hypermem_session *session, void *context);
void hypermem_fault(struct hypermem_session *session, unsigned bbindex);
int hypermem_nop(struct hypermem_session *session);

#endif /* !defined(HYPERMEM_H) */
