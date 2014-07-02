#ifndef HYPERMEM_H
#define HYPERMEM_H

#include <sys/types.h>

struct hypermem_session {
	int mem_fd;
	off_t address;
};

int hypermem_connect(struct hypermem_session *session);
void hypermem_disconnect(struct hypermem_session *session);

int hypermem_nop(struct hypermem_session *session);

#endif /* !defined(HYPERMEM_H) */
