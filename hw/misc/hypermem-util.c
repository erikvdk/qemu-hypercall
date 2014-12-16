#include "hw/hw.h"
#include "hw/isa/isa.h"
#include "hw/i386/pc.h"
#include "sysemu/kvm.h"
#include "hw/qdev.h"
#include "qemu/config-file.h"
#include "qemu/option.h"

#include "helper.h"
#include "exec/softmmu_exec.h"

#include <qemu/hypermem-api.h>

#include "hypermem-edfi.h"
#include "hypermem.h"

int vaddr_to_laddr(vaddr ptr, vaddr *result)
{
    X86CPU *cpu = X86_CPU(current_cpu);
    int segindex = R_DS;
    
    /* perform segment translation (cpu_get_phys_page_debug and
     * cpu_memory_rw_debug expect linear addresses)
     */
#ifdef HYPERMEM_DEBUG
    printf("hypermem: vaddr_to_laddr; ptr=0x%lx, "
        "base=0x%lx, limit=0x%lx\n", (long) ptr,
        (long) cpu->env.segs[segindex].base,
        (long) cpu->env.segs[segindex].limit);
#endif
    if (ptr >= cpu->env.segs[segindex].limit) {
        fprintf(stderr, "hypermem: warning: ptr 0x%lx exceeds "
                "segment limit 0x%lx\n", (long) ptr,
                (long) cpu->env.segs[segindex].limit);
        *result = 0;
	return 0;
    }
    *result = ptr + cpu->env.segs[segindex].base;
    return 1;
}

char *read_string(vaddr strptr, vaddr strlen)
{
    char *str;
    vaddr strptr_lin;

    str = CALLOC(strlen + 1, char);
    if (!str) return NULL;

    if (!vaddr_to_laddr(strptr, &strptr_lin)) {
	return NULL;
    }
    if (cpu_memory_rw_debug(current_cpu, strptr_lin, (uint8_t *) str,
        strlen, 0) < 0) {
	fprintf(stderr, "hypermem: warning: cannot read string\n");
	free(str);
	return NULL;
    }
    str[strlen] = 0;
    return str;
}

void *load_from_hwaddrs(vaddr viraddr, vaddr size, hwaddr *hwaddrs)
{
    uint8_t *buffer, *p;
    vaddr chunk;
    hwaddr hwaddr;

    buffer = CALLOC(size, uint8_t);
    if (!buffer) return NULL;

    /* load buffer from physical addresses, one page at a time */
    p = buffer;
    while (size > 0) {
	chunk = TARGET_PAGE_SIZE - viraddr % TARGET_PAGE_SIZE;
	if (chunk > size) chunk = size;

	hwaddr = *hwaddrs + viraddr % TARGET_PAGE_SIZE;
	if (hwaddr < HYPERMEM_BASEADDR + HYPERMEM_SIZE &&
	    hwaddr + chunk > HYPERMEM_BASEADDR) {
	    fprintf(stderr, "hypermem: warning: data to be loaded overlaps "
	            "with IO range (hwaddr=0x%lx, chunk=0x%lx)\n",
		    (long) hwaddr, (long) chunk);
	} else {
	    cpu_physical_memory_read(hwaddr, p, chunk);
	}
	viraddr += chunk;
	size -= chunk;
	hwaddrs++;
	p += chunk;
    }
    return buffer;
}


