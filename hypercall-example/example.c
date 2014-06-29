#include <stdio.h>

#include "qhyper.h"

int main(int argc, char **argv) {
	if (!qhyper_nop()) {
		printf("hypercall interface not available\n");
		return 1;
	}

	printf("hypercall interface available\n");
	return 0;	
}
