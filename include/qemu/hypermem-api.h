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
 * hypermem protocol - edfi context set
 * - write command identifier HYPERMEM_COMMAND_EDFI_CONTEXT_SET
 * - write module name length
 * - write module name pointer
 * - write a pointer to the EDFI context (note: physical address is stored so
 *   it must be pinned and pointers inside may not be changed afterwards)
 * - write pointer offset used to translate pointers within the context
 *   (normally 0xc0000000 for Linux, 0 otherwise)
 *
 * hypermem protocol - edfi dump all statistics
 * - write command identifier HYPERMEM_COMMAND_EDFI_DUMP_STATS
 *
 * hypermem protocol - edfi dump statistics for module
 * - write command identifier HYPERMEM_COMMAND_EDFI_DUMP_STATS_MODULE
 * - write module name length
 * - write module name pointer
 *
 * hypermem protocol - edfi faultindex get
 * - write command identifier HYPERMEM_COMMAND_EDFI_FAULTINDEX_GET
 * - write module name length
 * - write module name pointer
 * - read back reply
 * - the reply is the absolute basic block index where a fault should be
 *   injected; 0 means no fault, 1 means inject a fault in the first block
 *
 * hypermem protocol - fault
 * - write command identifier HYPERMEM_COMMAND_FAULT
 * - write module name length
 * - write module name pointer
 * - write basic block index
 *
 * hypermem protocol - nop
 * - write command identifier HYPERMEM_COMMAND_NOP
 * - read back reply
*  - if the reply is HYPERCALL_NOP_REPLY, the hypermem interface works
 *
 * hypermem protocol - print
 * - write command identifier HYPERMEM_COMMAND_PRINT
 * - write a length of the string in bytes, excluding terminator
 * - write string data, one hypermem_entry_t unit at a time
 *
 * * hypermem protocol - set_cr3
 * - write command identifier HYPERMEM_COMMAND_SET_CR3
 * - write the current process cr3 value, to be used for the rest of the session
 */
 
 #include <stdint.h>

typedef uint32_t hypermem_entry_t;
/* I don't know how to tell the OS a memory region is reserved so I'll just
 * steal part of the video memory and hope it won't be used
 *
 * note: more than 256 bytes risks a race condition if reads are not atomic 
 */
#define HYPERMEM_BASEADDR	0xb7000
#define HYPERMEM_SIZE		0x00100 

#define HYPERMEM_COMMAND_NOP			1
#define HYPERMEM_COMMAND_FAULT			2
#define HYPERMEM_COMMAND_EDFI_CONTEXT_SET	3
#define HYPERMEM_COMMAND_PRINT			4
#define HYPERMEM_COMMAND_EDFI_FAULTINDEX_GET	5
#define HYPERMEM_COMMAND_EDFI_DUMP_STATS	6
#define HYPERMEM_COMMAND_EDFI_DUMP_STATS_MODULE	7
#define HYPERMEM_COMMAND_SET_CR3	8
#define HYPERMEM_COMMAND_MAGIC_CONTEXT_SET	9
#define HYPERMEM_COMMAND_MAGIC_ST	10

#define HYPERCALL_NOP_REPLY	0x4e6f7021

#endif /* !defined(HYPERMEM_API_H) */
