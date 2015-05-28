#ifndef __ASM_EDAC_H
#define __ASM_EDAC_H

/* ECC atomic, DMA, SMP and interrupt safe scrub function */

static inline void atomic_scrub(void *va, u32 size)
{
	/* Stub function for now until an ARM64 HW has a way to test it */
	WARN_ONCE(1, "not implemented");
}

#endif
