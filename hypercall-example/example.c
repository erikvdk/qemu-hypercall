#include "hypermem.h"

int main(int argc, char **argv) {
	struct hypermem_session session;

	if (hypermem_connect(&session) < 0) {
		perror("cannot connect to hypervisor");
		return 1;
	}
	if (hypermem_nop(&session)) {
		printf("NOP return value correct\n");
	} else {
		printf("NOP return value incorrect\n");
	}
	hypermem_disconnect(&session);
	return 0;
}
