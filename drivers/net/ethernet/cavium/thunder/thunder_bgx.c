/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2014 Cavium, Inc.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/workqueue.h>
#include <linux/pci.h>

#include "nic.h"
#include "nic_reg.h"
#include "thunder_bgx.h"

#define DRV_NAME	"thunder-BGX"
#define DRV_VERSION	"1.0"

struct lmac {
	int dmac;
} lmac;

struct bgx {
	uint8_t	bgx_id;
	struct lmac lmac[MAX_LMAC_PER_BGX];
	uint64_t reg_base;
	struct pci_dev *pdev;
} bgx;

struct bgx *bgx_vnic[MAX_BGX_PER_CN88XX];

/* Supported devices */
static DEFINE_PCI_DEVICE_TABLE(bgx_id_table) = {
	{ PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, PCI_DEVICE_ID_THUNDER_BGX) },
	{ 0, }  /* end of table */
};

MODULE_AUTHOR("Cavium Inc");
MODULE_DESCRIPTION("Cavium Thunder BGX/MAC Driver");
MODULE_LICENSE("GPL");
MODULE_VERSION(DRV_VERSION);
MODULE_DEVICE_TABLE(pci, bgx_id_table);

/* Register read/write APIs */
#if 0
static uint64_t bgx_reg_read(struct bgx *bgx, uint8_t lmac, uint64_t offset)
{
	uint64_t addr = bgx->reg_base + (lmac << 20) + offset;

	return readq_relaxed((void *)addr);
}
#endif
static void bgx_reg_write(struct bgx *bgx, uint8_t lmac,
			uint64_t offset, uint64_t val)
{
	uint64_t addr = bgx->reg_base + (lmac << 20) + offset;

	writeq_relaxed(val, (void *)addr);
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
void bgx_add_dmac_addr(uint64_t dmac, uint64_t lmac)
{
	int bgx_index;
	uint64_t offset, addr;
	struct bgx *bgx;

	bgx_index = lmac / MAX_LMAC_PER_BGX;
	bgx = bgx_vnic[bgx_index];
	if (!bgx) {
		pr_err("BGX%d not yet initialized, ignoring DMAC addition\n",
								 bgx_index);
		return;
	}
	lmac = lmac % MAX_LMAC_PER_BGX;
	dmac = dmac | (1ULL << 48) | (lmac << 49); /* Enable DMAC */
	if (bgx->lmac[lmac].dmac == MAX_DMAC_PER_LMAC) {
		pr_err("Max DMAC filters for LMAC%lld reached, ignoring DMAC addition\n", lmac);
		return;
	}
	/* Simulator supports only TNS by pass mode */
	if (bgx->lmac[lmac].dmac == MAX_DMAC_PER_LMAC_TNS_BYPASS_MODE)
		bgx->lmac[lmac].dmac = 1;

	offset = (bgx->lmac[lmac].dmac * sizeof(dmac)) +
					(lmac * MAX_DMAC_PER_LMAC * sizeof(dmac));
	addr = bgx->reg_base + BGX_CMR_RX_DMACX_CAM + offset;
	writeq_relaxed(dmac, (void *)addr);
	bgx->lmac[lmac].dmac++;
}

void bgx_lmac_enable(uint64_t lmac)
{
	int bgx_index;
	struct bgx *bgx;
	//uint64_t dmac_bcast = (1ULL << 48) - 1;

	bgx_index = lmac / MAX_LMAC_PER_BGX;
	bgx = bgx_vnic[bgx_index];
	if (!bgx) {
		pr_err("BGX%d not yet initialized, ignoring LMAC disable\n",
								 bgx_index);
		return;
	}
	lmac = lmac % MAX_LMAC_PER_BGX;
	bgx_reg_write(bgx, lmac, BGX_CMRX_CFG,
			(1 << 15) | (1 << 14) | (1 << 13));
	//bgx_add_dmac_addr(dmac_bcast, lmac +
	//			(bgx->bgx_id * MAX_LMAC_PER_BGX));
}

void bgx_lmac_disable(uint64_t lmac)
{
	int bgx_index;
	struct bgx *bgx;

	bgx_index = lmac / MAX_LMAC_PER_BGX;
	bgx = bgx_vnic[bgx_index];
	if (!bgx) {
		pr_err("BGX%d not yet initialized, ignoring LMAC disable\n",
								 bgx_index);
		return;
	}
	lmac = lmac % MAX_LMAC_PER_BGX;
	bgx_reg_write(bgx, lmac, BGX_CMRX_CFG, 0x00);
	//bgx_flush_dmac_addrs(bgx, lmac);
}

static void bgx_init_hw(struct bgx *bgx)
{
	int lmac;
	uint64_t enable = 0;
	uint64_t dmac_bcast = (1ULL << 48) - 1;

	/* Enable all LMACs */
	/* Enable LMAC, Pkt Rx enable, Pkt Tx enable */
	enable = (1 << 15) | (1 << 14) | (1 << 13);
	for (lmac = 0; lmac < MAX_LMAC_PER_BGX; lmac++) {
		bgx_reg_write(bgx, lmac, BGX_CMRX_CFG, enable);
	}

	/* Add broadcast MAC into all LMAC's DMAC filters */
	for (lmac = 0; lmac < MAX_LMAC_PER_BGX; lmac++) {
		bgx_add_dmac_addr(dmac_bcast, lmac +
					(bgx->bgx_id * MAX_LMAC_PER_BGX));
	}
}

static int bgx_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	struct device *dev = &pdev->dev;
	struct bgx *bgx;
	int    err;

	bgx = kzalloc(sizeof(struct bgx), GFP_KERNEL);
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
	bgx->reg_base = (uint64_t) pci_ioremap_bar(pdev, PCI_CFG_REG_BAR_NUM);
	if (!bgx->reg_base) {
		dev_err(dev, "BGX: Cannot map CSR memory space, aborting\n");
		err = -ENOMEM;
		goto err_release_regions;
	}
	bgx->bgx_id = (pci_resource_start(pdev, PCI_CFG_REG_BAR_NUM) >> 24) & 1;
	bgx_vnic[bgx->bgx_id] = bgx;

	//pr_err("%s BGX%d CSR base %llx\n",__func__, bgx->bgx_id, bgx->reg_base);

	/* Initialize BGX hardware */
	bgx_init_hw(bgx);

	goto exit;

//err_unmap_resources:
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

	if (!bgx)
		return;

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

