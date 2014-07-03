#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "hypermem.h"

int main(int argc, char **argv) {
	char **arg;
	const char *cmd, *str;
	unsigned bbindex;
	int r = 0;
	struct hypermem_session session;

	if (hypermem_connect(&session) < 0) {
		perror("cannot connect to hypervisor");
		return 1;
	}

	arg = argv + 1;
	while (*arg) {
		cmd = *(arg++);
		if (strcmp(cmd, "nop") == 0) {
			if (hypermem_nop(&session)) {
				printf("NOP return value correct\n");
			} else {
				printf("NOP return value incorrect\n");
			}
		} else if (strcmp(cmd, "fault") == 0) {
			bbindex = *arg ? atoi(*(arg++)) : 0;
			hypermem_fault(&session, bbindex);
		} else if (strcmp(cmd, "print") == 0) {
			str = *arg ? *(arg++) : "hello world";
			hypermem_print(&session, str);
		} else {
			fprintf(stderr, "error: invalid command \"%s\"\n", cmd);
			r = 2;
			break;
		}
	}
	hypermem_disconnect(&session);
	return r;
}
