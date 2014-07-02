#ifndef HYPERMEM_API_H
#define HYPERMEM_API_H

/*
 * hypermem protocol - session management
 * - read from HYPERMEM_BASEADDR (in physical memory) of a
 *   hypermem_entry_t-sized value initiates a session
 * - in case of success, the read returns the communication address for
 *   the session; it is within the range
 *   HYPERMEM_BASEADDR...HYPERMEM_BASEADDR+HYPERMEM_SIZE
 * - in case of failure because no more sessions are available,
 *   the read returns 0
 * - further communication within the session proceeds by reads and writes of
 *   hypermem_entry_t-sized values to/from the communication address
 * - each command starts by writing a command identifier to the communication
 *   address and the remainder of the sequence of operations is determinied
 *   by the protocol specified for that command type
 * - after a command has been completed the session process take another command
 * - the session is ended by writing the communication address
 *   to HYPERMEM_BASEADDR
 *
 * hypermem protocol - nop
 * - write command identifier HYPERMEM_COMMAND_NOP
 * - read back reply
*  - if the reply is HYPERCALL_NOP_REPLY, the hypermem interface works
 */
 
 #include <stdint.h>

typedef uint32_t hypermem_entry_t;
/* I don't know how to tell the OS a memory region is reserved so I'll just
 * steal part of the video memory and hope it won't be used
 */
#define HYPERMEM_BASEADDR	0xb7000
#define HYPERMEM_SIZE		0x01000

#define HYPERMEM_COMMAND_NOP	1

#define HYPERCALL_NOP_REPLY	0x4e6f7021

#endif /* !defined(HYPERMEM_API_H) */
