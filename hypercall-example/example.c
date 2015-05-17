#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "hypermem.h"

int main(int argc, char **argv) {
	char **arg;
	const char *cmd, *str;
	int r = 0;
	struct hypermem_session session;

	if (hypermem_connect(&session) < 0) {
		perror("cannot connect to hypervisor");
		return 1;
	}

	arg = argv + 1;
	while (*arg) {
		/* note: edfi_context_set, edfi_faultindex_get and fault calls
		 * not available from user space; they require memory access
		 * to this process, not /dev/mem context
		 */
		cmd = *(arg++);
		if (strcmp(cmd, "nop") == 0) {
			if (hypermem_nop(&session)) {
				printf("NOP return value correct\n");
			} else {
				printf("NOP return value incorrect\n");
			}
		} else if (strcmp(cmd, "print") == 0) {
			str = *arg ? *(arg++) : "hello world";
			hypermem_print(&session, str);
		} else if (strcmp(cmd, "quit") == 0) {
			hypermem_quit(&session);
		} else {
			fprintf(stderr, "error: invalid command \"%s\"\n", cmd);
			r = 2;
			break;
		}
	}
	hypermem_disconnect(&session);
	return r;
}
