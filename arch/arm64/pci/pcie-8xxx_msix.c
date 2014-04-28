/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2013 Cavium, Inc.
 */
#include <linux/interrupt.h>
#include <linux/spinlock.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/cpu.h>
#include <linux/msi.h>
#include <linux/irq.h>
#include <linux/pci.h>

#include "pcie-8xxx.h"

#define THUNDER_IRQ_MSIX_START	(50)
#define THUNDER_GICR_SETLPIR_REG_ADDR		0x848000000000
#define THUNDER_GICD_SETSPI_NSR_REG_ADDR	0x801000000040

/*
 * Each bit in msix_free_irq_bitmask represents a MSI interrupt that is
 * in use.
 */
static u64 msix_free_irq_bitmask[64];

/*
 * This lock controls updates to msix_free_irq_bitmask
 */
static DEFINE_SPINLOCK(msix_free_irq_bitmask_lock);

/*
 * Number of MSIX IRQs used.
 */
static int msix_irq_size = 4096;

/**
 * Called when a device no longer needs its MSI interrupts. All
 * MSIX interrupts for the device are freed.
 */
void pcie_8xxx_teardown_msi_irq (struct msi_desc *msi)
{
	int irq;
	int index;

	irq = msi->msg.data - THUNDER_IRQ_MSIX_START;

	msi->msg.data = 0;
	msi->msg.address_lo = 0;
	msi->msg.address_hi = 0;
	msi->irq = 0;

	spin_lock(&msix_free_irq_bitmask_lock);
	index = irq / 64;
	irq = irq % 64;
	msix_free_irq_bitmask[index] &= (~(1 << irq));	
	spin_unlock(&msix_free_irq_bitmask_lock);
}

/**
 * Called when a driver request for MSIX interrupts
 */
int pcie_8xxx_setup_msi_irq(struct pci_dev *dev, struct msi_desc *desc)
{
	struct msi_msg msg;
	int irq = 0;
	int index;
	bool irq_found = false;

	/*
	 * We're going to search msix_free_irq_bitmask_lock for zero
	 * bits. This represents an MSI interrupt number that isn't in
	 * use.
	 */
	spin_lock(&msix_free_irq_bitmask_lock);
	for (index = 0; index < msix_irq_size/64; index++) {
		for (irq = 0; irq < 64; irq++) {
			if ((msix_free_irq_bitmask[index] & (1ULL << irq)) == 0) {
				msix_free_irq_bitmask[index] |= 1ULL << irq;
				irq_found = true;
				break;
			}
		}
		if (irq_found == true)
			break;
	}
	spin_unlock(&msix_free_irq_bitmask_lock);

	/* Make sure the search for free interrupts didn't fail */
	if (!irq_found) {
		panic("arch_setup_msi_irq: Unable to find free MSI-X interrupts");
	}

	/* MSIX interrupts start at logical IRQ THUNDER_IRQ_MSIX_START */
	irq += index*64;
	irq += THUNDER_IRQ_MSIX_START;
	msg.data = irq;

#if 0
	msg.address_lo = THUNDER_GICR_SETLPIR_REG_ADDR & 0xffffffff;
	msg.address_hi = THUNDER_GICR_SETLPIR_REG_ADDR >> 32;
#endif
	msg.address_lo = THUNDER_GICD_SETSPI_NSR_REG_ADDR & 0xffffffff;
	msg.address_hi = THUNDER_GICD_SETSPI_NSR_REG_ADDR >> 32;

	irq_set_msi_desc(irq, desc);
	write_msi_msg(irq, &msg);
	return 0;
}

int arch_setup_msi_irqs(struct pci_dev *pdev, int msix_vecs, int type)
{
	struct msi_desc *entry;
	int ret;

	/*
	 * Only MSI-X is supported.
	 */
	if (type != PCI_CAP_ID_MSIX)
		return -EINVAL;

	list_for_each_entry(entry, &pdev->msi_list, list) {
		ret = pcie_8xxx_setup_msi_irq(pdev, entry);
		if (ret < 0)
			return ret;
		if (ret > 0)
			return -ENOSPC;
	}

	return 0;
}

void arch_teardown_msi_irqs (struct pci_dev *pdev) 
{
	struct msi_desc *entry;

	list_for_each_entry(entry, &pdev->msi_list, list) {
		pcie_8xxx_teardown_msi_irq(entry);
	}
}
