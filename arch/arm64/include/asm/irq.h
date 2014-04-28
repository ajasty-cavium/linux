#ifndef __ASM_IRQ_H
#define __ASM_IRQ_H

#define NR_IRQS                         256

#include <asm-generic/irq.h>

extern void (*handle_arch_irq)(struct pt_regs *);
extern void migrate_irqs(void);
extern void set_handle_irq(void (*handle_irq)(struct pt_regs *));

#endif
