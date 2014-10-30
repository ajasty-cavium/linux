/*
 * Copyright (C) 2014 Cavium, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 */

#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/pci.h>

#include "nic_reg.h"
#include "nic.h"
#include "thunder_bgx.h"

#define DRV_NAME	"thunder-BGX"
#define DRV_VERSION	"1.0"

struct lmac {
	int	dmac;
	bool	link_up;
} lmac;

struct bgx {
	uint8_t			bgx_id;
	struct	lmac		lmac[MAX_LMAC_PER_BGX];
	int			lmac_count;
	uint64_t		reg_base;
	struct	pci_dev		*pdev;
	 /* MSI-X */
	bool			msix_enabled;
	uint16_t		num_vec;
	struct	msix_entry	msix_entries[BGX_MSIX_VECTORS];
	char			irq_name[BGX_MSIX_VECTORS][20];
	uint8_t			irq_allocated[BGX_MSIX_VECTORS];
} bgx;

struct bgx *bgx_vnic[MAX_BGX_THUNDER];

/* Supported devices */
static const struct pci_device_id bgx_id_table[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, PCI_DEVICE_ID_THUNDER_BGX) },
	{ 0, }  /* end of table */
};

MODULE_AUTHOR("Cavium Inc");
MODULE_DESCRIPTION("Cavium Thunder BGX/MAC Driver");
MODULE_LICENSE("GPL v2");
MODULE_VERSION(DRV_VERSION);
MODULE_DEVICE_TABLE(pci, bgx_id_table);

/* Register read/write APIs */
static uint64_t bgx_reg_read(struct bgx *bgx, uint8_t lmac, uint64_t offset)
{
	uint64_t addr = bgx->reg_base + (lmac << 20) + offset;

	return readq_relaxed((void *)addr);
}

static void bgx_reg_write(struct bgx *bgx, uint8_t lmac,
			  uint64_t offset, uint64_t val)
{
	uint64_t addr = bgx->reg_base + (lmac << 20) + offset;

	writeq_relaxed(val, (void *)addr);
}

/* Return number of BGX present in HW */
void bgx_get_count(int node, int *bgx_count)
{
	int i;
	struct bgx *bgx;

	*bgx_count = 0;
	for (i = 0; i < MAX_BGX_PER_CN88XX; i++) {
		bgx = bgx_vnic[(node * MAX_BGX_PER_CN88XX) + i];
		if (bgx)
			*bgx_count |= (1 << i);
	}
}
EXPORT_SYMBOL(bgx_get_count);

/* Return number of LMAC configured for this BGX */
int bgx_get_lmac_count(int node, int bgx_idx)
{
	struct bgx *bgx;

	bgx = bgx_vnic[(node * MAX_BGX_PER_CN88XX) + bgx_idx];
	if (bgx)
		return bgx->lmac_count;

	return 0;
}
EXPORT_SYMBOL(bgx_get_lmac_count);

/* Link Interrupts APIs */
static void bgx_enable_link_intr(struct bgx *bgx, uint8_t lmac)
{
	uint64_t val;

	val = bgx_reg_read(bgx, lmac, BGX_SPUX_INT_ENA_W1S);
	val |= (LMAC_INTR_LINK_UP | LMAC_INTR_LINK_DOWN);
	bgx_reg_write(bgx, lmac, BGX_SPUX_INT_ENA_W1S, val);
}

static irqreturn_t bgx_lmac_intr_handler (int irq, void *bgx_irq)
{
	struct bgx *bgx = (struct bgx *)bgx_irq;
	u64 result;
	uint8_t lmac;

	for (lmac = 0; lmac < bgx->lmac_count; lmac++) {
		result = bgx_reg_read(bgx, lmac, BGX_SPUX_INT);
		if (result & LMAC_INTR_LINK_UP) {
			bgx_reg_write(bgx, lmac, BGX_SPUX_INT,
				      LMAC_INTR_LINK_UP);
			dev_info(&bgx->pdev->dev, "lmac %d link is Up\n", lmac);
			bgx->lmac[lmac].link_up = true;
		}

		if (result & LMAC_INTR_LINK_DOWN) {
			bgx_reg_write(bgx, lmac, BGX_SPUX_INT,
				      LMAC_INTR_LINK_DOWN);
			dev_info(&bgx->pdev->dev,
				 "lmac %d link is Down\n", lmac);
			bgx->lmac[lmac].link_up = false;
		}
	}
	return IRQ_HANDLED;
}

static int bgx_enable_msix(struct bgx *bgx)
{
	int vec, ret;

	bgx->num_vec = BGX_MSIX_VECTORS;
	for (vec = 0; vec < bgx->num_vec; vec++)
		bgx->msix_entries[vec].entry = vec;

	ret = pci_enable_msix(bgx->pdev, bgx->msix_entries, bgx->num_vec);
	if (ret) {
		dev_err(&bgx->pdev->dev ,
			"Request for #%d msix vectors failed\n", bgx->num_vec);
		return 0;
	}
	bgx->msix_enabled = 1;
	return 1;
}

static void bgx_disable_msix(struct bgx *bgx)
{
	if (bgx->msix_enabled) {
		pci_disable_msix(bgx->pdev);
		bgx->msix_enabled = 0;
		bgx->num_vec = 0;
	}
}

static int bgx_register_interrupts(struct bgx *bgx, uint8_t lmac)
{
	int irq, ret = 0;

	/* Register only link interrupts now */
	irq = SPUX_INT + (lmac * BGX_LMAC_VEC_OFFSET);
	sprintf(bgx->irq_name[irq], "LMAC%d", lmac);
	ret = request_irq(bgx->msix_entries[irq].vector,
			  bgx_lmac_intr_handler, 0, bgx->irq_name[irq], bgx);
	if (ret)
		goto fail;
	else
		bgx->irq_allocated[irq] = 1;

	/* Enable link interrupt */
	bgx_enable_link_intr(bgx, lmac);
	return 0;

fail:
	dev_err(&bgx->pdev->dev, "Request irq failed\n");
	for (irq = 0; irq < bgx->num_vec; irq++) {
		if (bgx->irq_allocated[irq])
			free_irq(bgx->msix_entries[irq].vector, bgx);
		bgx->irq_allocated[irq] = 0;
	}
	return 1;
}

static void bgx_unregister_interrupts(struct bgx *bgx)
{
	int irq;
	/* Free registered interrupts */
	for (irq = 0; irq < bgx->num_vec; irq++) {
		if (bgx->irq_allocated[irq])
			free_irq(bgx->msix_entries[irq].vector, bgx);
		bgx->irq_allocated[irq] = 0;
	}
	/* Disable MSI-X */
	bgx_disable_msix(bgx);
}

static void bgx_flush_dmac_addrs(struct bgx *bgx, uint64_t lmac)
{
	uint64_t dmac = 0x00;
	uint64_t offset, addr;

	while (bgx->lmac[lmac].dmac > 0) {
		offset = ((bgx->lmac[lmac].dmac - 1) * sizeof(dmac)) +
			(lmac * MAX_DMAC_PER_LMAC * sizeof(dmac));
		addr = bgx->reg_base + BGX_CMR_RX_DMACX_CAM + offset;
		writeq_relaxed(dmac, (void *)addr);
		bgx->lmac[lmac].dmac--;
	}
}

void bgx_add_dmac_addr(uint64_t dmac, int node, int bgx_idx, int lmac)
{
	uint64_t offset, addr;
	struct bgx *bgx;

	bgx_idx += node * MAX_BGX_PER_CN88XX;
	bgx = bgx_vnic[bgx_idx];

	if (!bgx) {
		pr_err("BGX%d not yet initialized, ignoring DMAC addition\n",
		       bgx_idx);
		return;
	}

	dmac = dmac | (1ULL << 48) | ((uint64_t)lmac << 49); /* Enable DMAC */
	if (bgx->lmac[lmac].dmac == MAX_DMAC_PER_LMAC) {
		pr_err("Max DMAC filters for LMAC%d reached, ignoring DMAC addition\n",
		       lmac);
		return;
	}

	if (bgx->lmac[lmac].dmac == MAX_DMAC_PER_LMAC_TNS_BYPASS_MODE)
		bgx->lmac[lmac].dmac = 1;

	offset = (bgx->lmac[lmac].dmac * sizeof(dmac)) +
		(lmac * MAX_DMAC_PER_LMAC * sizeof(dmac));
	addr = bgx->reg_base + BGX_CMR_RX_DMACX_CAM + offset;
	writeq_relaxed(dmac, (void *)addr);
	bgx->lmac[lmac].dmac++;

	bgx_reg_write(bgx, lmac, BGX_CMRX_RX_DMAC_CTL,
		      (CAM_ACCEPT << 3) | (MCAST_MODE_CAM_FILTER << 1)
		      | (BCAST_ACCEPT << 0));
}
EXPORT_SYMBOL(bgx_add_dmac_addr);

void bgx_lmac_enable(struct bgx *bgx, int8_t lmac)
{
	uint64_t dmac_bcast = (1ULL << 48) - 1;

	bgx_reg_write(bgx, lmac, BGX_CMRX_CFG,
		      (1 << 15) | (1 << 14) | (1 << 13));

	/* Register interrupts */
	bgx_register_interrupts(bgx, lmac);

	/* Add broadcast MAC into all LMAC's DMAC filters */
	for (lmac = 0; lmac < bgx->lmac_count; lmac++)
		bgx_add_dmac_addr(dmac_bcast, 0, bgx->bgx_id, lmac);
}

void bgx_lmac_disable(struct bgx *bgx, uint8_t lmac)
{
	bgx_reg_write(bgx, lmac, BGX_CMRX_CFG, 0x00);
	bgx_flush_dmac_addrs(bgx, lmac);
	bgx_unregister_interrupts(bgx);
}

static void bgx_init_hw(struct bgx *bgx)
{
	int lmac;
	uint64_t enable = 0;

	/* Enable all LMACs */
	/* Enable LMAC, Pkt Rx enable, Pkt Tx enable */
	enable = (1 << 15) | (1 << 14) | (1 << 13);
	for (lmac = 0; lmac < MAX_LMAC_PER_BGX; lmac++) {
		bgx_reg_write(bgx, lmac, BGX_CMRX_CFG, enable);
		bgx->lmac_count++;
	}
}

static int bgx_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	struct device *dev = &pdev->dev;
	struct bgx *bgx;
	int    err;
	uint8_t lmac = 0;

	bgx = kzalloc(sizeof(*bgx), GFP_KERNEL);
	bgx->pdev = pdev;

	pci_set_drvdata(pdev, bgx);

	err = pci_enable_device(pdev);
	if (err) {
		dev_err(dev, "Failed to enable PCI device\n");
		goto exit;
	}

	err = pci_request_regions(pdev, DRV_NAME);
	if (err) {
		dev_err(dev, "PCI request regions failed 0x%x\n", err);
		goto err_disable_device;
	}

	/* MAP configuration registers */
	bgx->reg_base = (uint64_t)pci_ioremap_bar(pdev, PCI_CFG_REG_BAR_NUM);
	if (!bgx->reg_base) {
		dev_err(dev, "BGX: Cannot map CSR memory space, aborting\n");
		err = -ENOMEM;
		goto err_release_regions;
	}
	bgx->bgx_id = (pci_resource_start(pdev, PCI_CFG_REG_BAR_NUM) >> 24) & 1;
	bgx->bgx_id += NODE_ID(pci_resource_start(pdev, PCI_CFG_REG_BAR_NUM))
							* MAX_BGX_PER_CN88XX;
	bgx_vnic[bgx->bgx_id] = bgx;

	/* Initialize BGX hardware */
	bgx_init_hw(bgx);
	/* Enable MSI-X */
	if (!bgx_enable_msix(bgx))
		return 1;
	/* Enable all LMACs */
	for (lmac = 0; lmac < bgx->lmac_count; lmac++)
		bgx_lmac_enable(bgx, lmac);
	goto exit;

	if (bgx->reg_base)
		iounmap((void *)bgx->reg_base);
err_release_regions:
	pci_release_regions(pdev);
err_disable_device:
	pci_disable_device(pdev);
exit:
	return err;
}

static void bgx_remove(struct pci_dev *pdev)
{
	struct bgx *bgx = pci_get_drvdata(pdev);
	uint8_t lmac;

	if (!bgx)
		return;
	/* Disable all LMACs */
	for (lmac = 0; lmac < 4; lmac++)
		bgx_lmac_disable(bgx, lmac);

	pci_set_drvdata(pdev, NULL);

	if (bgx->reg_base)
		iounmap((void *)bgx->reg_base);

	pci_release_regions(pdev);
	pci_disable_device(pdev);
	kfree(bgx);
}

static struct pci_driver bgx_driver = {
	.name = DRV_NAME,
	.id_table = bgx_id_table,
	.probe = bgx_probe,
	.remove = bgx_remove,
};

static int __init bgx_init_module(void)
{
	pr_info("%s, ver %s\n", DRV_NAME, DRV_VERSION);

	return pci_register_driver(&bgx_driver);
}

static void __exit bgx_cleanup_module(void)
{
	pci_unregister_driver(&bgx_driver);
}

module_init(bgx_init_module);
module_exit(bgx_cleanup_module);

