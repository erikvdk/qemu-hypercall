#ifndef HYPERST_H
#define HYPERST_H
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
#define MAX_TARGET_NAME 64

#define in_range(var, min, max) \
    ((var) >= (min)) && ((var) <= (max))

/* HYPER MESSAGE types */
#define HYPERTYPE_REPLY             0x1
/* REQUIRED FIELDS: .header.type
 */
#define HYPERTYPE_CHECK             0x2
/* REQUIRED FIELDS: .header.type
 *                  .header.target
 */
#define HYPERTYPE_GET_MAGIC_VARS    0x3
/* REQUIRED FIELDS: .header.type
 *                  .header.target
 */
#define HYPERTYPE_GET_DATA_REGION   0x4
/* REQUIRED FIELDS: .header.type
 *                  .header.target
 *                  .payload_size
 *                  .payload
 */
#define HYPERTYPE_ERROR             0xff



struct global_state {
    int hyper_port;
    char *hyper_address;

    int hyper_sock;
    char *target;
};

struct hyper_header {
    uint8_t type;
    char target[MAX_TARGET_NAME];
};

struct hyper_region {
    uint32_t address;
    uint32_t size;
};


struct hyper_message {
    struct hyper_header header;
    uint32_t payload_size;
    uint8_t payload[];
};

#endif /*__HYPERMEM_MAIN__*/
