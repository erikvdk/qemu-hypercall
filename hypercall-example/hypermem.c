#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "hypermem.h"
#include "../include/qemu/hypermem-api.h"

static hypermem_entry_t hypermem_read(struct hypermem_session *session) {
	hypermem_entry_t value;

	if (pread(session->mem_fd, &value, sizeof(value), session->address) <
		sizeof(value)) {
		fprintf(stderr, "memory read failed at 0x%lx: %s\n",
		        (long) session->address, strerror(errno));
		exit(-1);
	}
	return value;
}

static void hypermem_write(struct hypermem_session *session,
	hypermem_entry_t value) {
	if (pwrite(session->mem_fd, &value, sizeof(value), session->address) <
		sizeof(value)) {
		fprintf(stderr, "memory write failed at 0x%lx: %s\n",
		        (long) session->address, strerror(errno));
		exit(-1);
	}
}

int hypermem_connect(struct hypermem_session *session) {
	session->mem_fd = open("/dev/mem", O_RDWR);
	if (session->mem_fd < 0) return -1;

	session->address = HYPERMEM_BASEADDR;
	session->address = hypermem_read(session);
	if (session->address < HYPERMEM_BASEADDR ||
		session->address >= HYPERMEM_BASEADDR + HYPERMEM_SIZE) {
		if (close(session->mem_fd) < 0) {
			perror("close failed");
			exit(-1);
		}
		errno = EHOSTUNREACH;
		return -1;
	}

	return 0;
}

void hypermem_disconnect(struct hypermem_session *session) {
	hypermem_entry_t address = session->address;
	session->address = HYPERMEM_BASEADDR;
	hypermem_write(session, address);
	if (close(session->mem_fd) < 0) {
		perror("close failed");
		exit(-1);
	}
}

void hypermem_edfi_context_set(struct hypermem_session *session,
	const char *name, const void *context) {
	hypermem_write(session, HYPERMEM_COMMAND_EDFI_CONTEXT_SET);
	hypermem_write(session, strlen(name));
	hypermem_write(session, (hypermem_entry_t) name);
	hypermem_write(session, (hypermem_entry_t) context);
}

int hypermem_edfi_dump_stats(struct hypermem_session *session) {
	hypermem_write(session, HYPERMEM_COMMAND_EDFI_DUMP_STATS);
}

int hypermem_edfi_dump_stats_module(struct hypermem_session *session,
	const char *name) {
	hypermem_write(session, HYPERMEM_COMMAND_EDFI_DUMP_STATS_MODULE);
	hypermem_write(session, strlen(name));
	hypermem_write(session, (hypermem_entry_t) name);
}

int hypermem_edfi_faultindex_get(struct hypermem_session *session,
	const char *name) {
	hypermem_write(session, HYPERMEM_COMMAND_EDFI_FAULTINDEX_GET);
	hypermem_write(session, strlen(name));
	hypermem_write(session, (hypermem_entry_t) name);
	return hypermem_read(session);
}

void hypermem_fault(struct hypermem_session *session, const char *name,
	unsigned bbindex) {
	hypermem_write(session, HYPERMEM_COMMAND_FAULT);
	hypermem_write(session, strlen(name));
	hypermem_write(session, (hypermem_entry_t) name);
	hypermem_write(session, bbindex);
}

int hypermem_nop(struct hypermem_session *session) {
	hypermem_write(session, HYPERMEM_COMMAND_NOP);
	return hypermem_read(session) == HYPERCALL_NOP_REPLY;
}

void hypermem_print(struct hypermem_session *session, const char *str) {
	hypermem_entry_t buf;
	size_t chunk, len = strlen(str);

	hypermem_write(session, HYPERMEM_COMMAND_PRINT);
	hypermem_write(session, len);
	while (len > 0) {
		chunk = sizeof(hypermem_entry_t);
		if (chunk > len) chunk = len;
		buf = 0;
		memcpy(&buf, str, chunk);
		hypermem_write(session, buf);
		str += chunk;
		len -= chunk;
	}
}
