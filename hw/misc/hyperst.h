#ifndef __HYPERMEM_MAIN__
#define __HYPERMEM_MAIN__
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>


#define MIN_PORT 1024
#define MAX_PORT 65535
#define MAX_TARGET_NAME 32

#define in_range(var, min, max) \
    ((var) >= (min)) && ((var) <= (max))

/* hyper_message types */
#define HYPERTYPE_REPLY     0x1
#define HYPERTYPE_CHECK     0x2
#define HYPERTYPE_ERROR     0xff

struct client_state {
    int hyper_port;
    char *hyper_address;

    int hyper_sock;
    char *target;
};


struct hyper_message {
    uint8_t type;
    uint32_t payload_size;
    char target[MAX_TARGET_NAME];
    uint8_t payload[];
};

#endif /*__HYPERMEM_MAIN__*/
