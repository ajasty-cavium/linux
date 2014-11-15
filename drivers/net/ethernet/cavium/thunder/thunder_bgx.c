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
#include <linux/netdevice.h>
#include <linux/phy.h>
#include <linux/of.h>
#include <linux/of_mdio.h>

#include "nic_reg.h"
#include "nic.h"
#include "thunder_bgx.h"

#define DRV_NAME	"thunder-BGX"
#define DRV_VERSION	"1.0"

struct lmac {
	int			dmac;
	bool			link_up;
	int			lmacid;
	struct net_device       netdev;
	struct phy_device       *phydev;
	struct device_node      *phy_np;     
	unsigned int            last_duplex;
	unsigned int            last_link;
	unsigned int            last_speed;
} lmac;

struct bgx {
	uint8_t			bgx_id;
	struct	lmac		lmac[MAX_LMAC_PER_BGX];
	int			lmac_count;
	int                     lmac_type;
	int                     lane_to_sds;
	uint64_t		reg_base;
	struct pci_dev		*pdev;

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

static void bgx_reg_modify(struct bgx *bgx, uint8_t lmac,
                           uint64_t offset, uint64_t val)
{
        uint64_t addr = bgx->reg_base + (lmac << 20) + offset;

        writeq_relaxed(val | bgx_reg_read(bgx, lmac, offset), (void *)addr);
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

#ifdef LINK_INTR_ENABLE
/* Link Interrupts APIs */
static void bgx_enable_link_intr(struct bgx *bgx, uint8_t lmac)
{
	uint64_t val;

	val = bgx_reg_read(bgx, lmac, BGX_SPUX_INT_ENA_W1S);
	val |= (LMAC_INTR_LINK_UP | LMAC_INTR_LINK_DOWN);
	bgx_reg_write(bgx, lmac, BGX_SPUX_INT_ENA_W1S, val);
}
#endif

void bgx_lmac_handler(struct net_device *netdev)
{
	struct lmac *lmac = container_of(netdev, struct lmac, netdev);
	struct phy_device *phydev = lmac->phydev;
	int link_changed = 0;

	if (!phydev->link && lmac->last_link)
		link_changed = -1;

	if (phydev->link
	    && (lmac->last_duplex != phydev->duplex
		|| lmac->last_link != phydev->link
		|| lmac->last_speed != phydev->speed)) {
			link_changed = 1;
	}

	lmac->last_link = phydev->link;
	lmac->last_speed = phydev->speed;
	lmac->last_duplex = phydev->duplex;

	if (!link_changed)
		return;

	if (link_changed > 0) {
		pr_info("LMAC%d: Link is up - %d/%s\n", lmac->lmacid,
			phydev->speed, 
			DUPLEX_FULL == phydev->duplex ? "Full" : "Half");
	} else {
		pr_info("LMAC%d: Link is down\n", lmac->lmacid);
	}
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

void bgx_print_stats(int bgx_idx, int lmac)
{
	struct bgx *bgx;

	bgx = bgx_vnic[bgx_idx];

	dev_info(&bgx->pdev->dev, "BGX TX STATS0 0x%llx\n",
		 bgx_reg_read(bgx, lmac, BGX_CMRX_TX_STAT0));
	dev_info(&bgx->pdev->dev, "BGX TX STATS1 0x%llx\n",
		 bgx_reg_read(bgx, lmac, BGX_CMRX_TX_STAT1));
	dev_info(&bgx->pdev->dev, "BGX TX STATS2 0x%llx\n",
		 bgx_reg_read(bgx, lmac, BGX_CMRX_TX_STAT2));
	dev_info(&bgx->pdev->dev, "BGX TX STATS3 0x%llx\n",
		 bgx_reg_read(bgx, lmac, BGX_CMRX_TX_STAT3));
	dev_info(&bgx->pdev->dev, "BGX TX STATS4 0x%llx\n",
		 bgx_reg_read(bgx, lmac, BGX_CMRX_TX_STAT4));
	dev_info(&bgx->pdev->dev, "BGX TX STATS5 0x%llx\n",
		 bgx_reg_read(bgx, lmac, BGX_CMRX_TX_STAT5));
	dev_info(&bgx->pdev->dev, "BGX TX STATS6 0x%llx\n",
		 bgx_reg_read(bgx, lmac, BGX_CMRX_TX_STAT6));
	dev_info(&bgx->pdev->dev, "BGX TX STATS7 0x%llx\n",
		 bgx_reg_read(bgx, lmac, BGX_CMRX_TX_STAT7));
	dev_info(&bgx->pdev->dev, "BGX TX STATS8 0x%llx\n",
		 bgx_reg_read(bgx, lmac, BGX_CMRX_TX_STAT8));
	dev_info(&bgx->pdev->dev, "BGX TX STATS9 0x%llx\n",
		 bgx_reg_read(bgx, lmac, BGX_CMRX_TX_STAT9));
	dev_info(&bgx->pdev->dev, "BGX TX STATS10 0x%llx\n",
		 bgx_reg_read(bgx, lmac, BGX_CMRX_TX_STAT10));
	dev_info(&bgx->pdev->dev, "BGX TX STATS11 0x%llx\n",
		 bgx_reg_read(bgx, lmac, BGX_CMRX_TX_STAT11));
	dev_info(&bgx->pdev->dev, "BGX TX STATS11 0x%llx\n",
		 bgx_reg_read(bgx, lmac, BGX_CMRX_TX_STAT11));
	dev_info(&bgx->pdev->dev, "BGX TX STATS12 0x%llx\n",
		 bgx_reg_read(bgx, lmac, BGX_CMRX_TX_STAT12));
	dev_info(&bgx->pdev->dev, "BGX TX STATS13 0x%llx\n",
		 bgx_reg_read(bgx, lmac, BGX_CMRX_TX_STAT13));
	dev_info(&bgx->pdev->dev, "BGX TX STATS14 0x%llx\n",
		 bgx_reg_read(bgx, lmac, BGX_CMRX_TX_STAT14));
	dev_info(&bgx->pdev->dev, "BGX TX STATS15 0x%llx\n",
		 bgx_reg_read(bgx, lmac, BGX_CMRX_TX_STAT15));
	dev_info(&bgx->pdev->dev, "BGX TX STATS16 0x%llx\n",
		 bgx_reg_read(bgx, lmac, BGX_CMRX_TX_STAT16));
	dev_info(&bgx->pdev->dev, "BGX TX STATS17 0x%llx\n",
		 bgx_reg_read(bgx, lmac, BGX_CMRX_TX_STAT17));
	dev_info(&bgx->pdev->dev, "\n");
	dev_info(&bgx->pdev->dev, "BGX RX STATS0 0x%llx\n",
		 bgx_reg_read(bgx, lmac, BGX_CMRX_RX_STAT0));
	dev_info(&bgx->pdev->dev, "BGX RX STATS1 0x%llx\n",
		 bgx_reg_read(bgx, lmac, BGX_CMRX_RX_STAT1));
	dev_info(&bgx->pdev->dev, "BGX RX STATS2 0x%llx\n",
		 bgx_reg_read(bgx, lmac, BGX_CMRX_RX_STAT2));
	dev_info(&bgx->pdev->dev, "BGX RX STATS3 0x%llx\n",
		 bgx_reg_read(bgx, lmac, BGX_CMRX_RX_STAT3));
	dev_info(&bgx->pdev->dev, "BGX RX STATS4 0x%llx\n",
		 bgx_reg_read(bgx, lmac, BGX_CMRX_RX_STAT4));
	dev_info(&bgx->pdev->dev, "BGX RX STATS5 0x%llx\n",
		 bgx_reg_read(bgx, lmac, BGX_CMRX_RX_STAT5));
	dev_info(&bgx->pdev->dev, "BGX RX STATS6 0x%llx\n",
		 bgx_reg_read(bgx, lmac, BGX_CMRX_RX_STAT6));
	dev_info(&bgx->pdev->dev, "BGX RX STATS7 0x%llx\n",
		 bgx_reg_read(bgx, lmac, BGX_CMRX_RX_STAT7));
	/* FIX me: These stats cause a kernel crash */
#if 0
	dev_info(&bgx->pdev->dev, "BGX RX STATS8 0x%llx\n",
		 bgx_reg_read(bgx, lmac, BGX_CMRX_RX_STAT8));
	dev_info(&bgx->pdev->dev, "BGX RX STATS9 0x%llx\n",
		 bgx_reg_read(bgx, lmac, BGX_CMRX_RX_STAT9));
	dev_info(&bgx->pdev->dev, "BGX RX STATS10 0x%llx\n",
		 bgx_reg_read(bgx, lmac, BGX_CMRX_RX_STAT10));
#endif
	dev_info(&bgx->pdev->dev, "BGX RX BP_DROP 0x%llx\n",
		 bgx_reg_read(bgx, lmac, BGX_CMRX_RX_BP_DROP));
}

static int bgx_register_interrupts(struct bgx *bgx, uint8_t lmac)
{
	int irq, ret = 0;

	/* Register only link interrupts now */
	irq = SPUX_INT + (lmac * BGX_LMAC_VEC_OFFSET);
	sprintf(bgx->irq_name[irq], "BGX%d-LMAC%d", bgx->bgx_id, lmac);
	ret = request_irq(bgx->msix_entries[irq].vector,
			  bgx_lmac_intr_handler, 0, bgx->irq_name[irq], bgx);
	if (ret)
		goto fail;
	else
		bgx->irq_allocated[irq] = 1;

	/* Enable link interrupt */
#ifdef LINK_INTR_ENABLE
	bgx_enable_link_intr(bgx, lmac);
#endif
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

static int bgx_intf_init(struct bgx *bgx, int lmac)
{
	int reset, wait_for_reset = 1000;
	int sleep = 5;
	uint64_t cfg;

	/* Reset */
	bgx_reg_modify(bgx, lmac, BGX_GMP_PCS_MRX_CTL, 1ULL << 15);
	while (1) {
		reset = bgx_reg_read(bgx, lmac,
				     BGX_GMP_PCS_MRX_CTL) & (1ULL << 15);
		if (!reset)
			break;
		if (reset && (wait_for_reset == 0)) {
			pr_err("BGX PCS reset not completed in 200ms\n");
			return -1;
		}
		msleep(sleep);
		wait_for_reset -= sleep;
	}

	cfg = bgx_reg_read(bgx, lmac, BGX_GMP_PCS_MRX_CTL);
	cfg = cfg & (~(1ULL << 11));
	cfg = cfg | ((1ULL << 9) | (1 << 12));
	bgx_reg_write(bgx, lmac, BGX_GMP_PCS_MRX_CTL, cfg);

	while (1) {
		reset = bgx_reg_read(bgx, lmac,
				     BGX_GMP_PCS_MRX_STATUS) & (1ULL << 5);
		if (reset)
			break;
		if (!reset && (wait_for_reset == 0)) {
			pr_err("BGX AN_CPT not completed in 500ms\n");
			return -1;
		}
		msleep(sleep);
		wait_for_reset -= sleep;
	}

	/* Set to MAC_PHY mode */
	bgx_reg_modify(bgx, lmac, BGX_GMP_PCS_MISCX_CTL, 1ULL << 9);
	bgx_reg_modify(bgx, lmac,
		       BGX_GMP_PCS_SGM_AN_ADV, (1ULL << 12) | (2ULL << 10));
	return 0;
}

static int bgx_lmac_enable(struct bgx *bgx, int8_t lmacid)
{
	uint64_t dmac_bcast = (1ULL << 48) - 1;
	struct lmac *lmac;
	int lmac_type;

	lmac = &bgx->lmac[lmacid];

	bgx_reg_modify(bgx, lmacid, BGX_CMRX_CFG,
		       (1 << 15) | (1 << 14) | (1 << 13));

	if(bgx_intf_init(bgx, lmacid))
		return -1;

	lmac_type = (bgx_reg_read(bgx, lmacid, BGX_CMRX_CFG) >> 8) & 0x7;
	if (lmac_type == 0) /* SGMII */
		bgx_reg_write(bgx, lmacid, BGX_GMP_GMI_TXX_MIN_PKT, 60 - 1);
	else
		bgx_reg_write(bgx, lmacid, BGX_GMP_GMI_TXX_MIN_PKT, 60 + 4);

	/* Add broadcast MAC into all LMAC's DMAC filters */
	bgx_add_dmac_addr(dmac_bcast, 0, bgx->bgx_id, lmacid);

	/* Register interrupts */
	bgx_register_interrupts(bgx, lmacid);

	lmac->phydev = of_phy_connect(&lmac->netdev, lmac->phy_np,
				      bgx_lmac_handler, 0,
				      PHY_INTERFACE_MODE_SGMII);

	if (!lmac->phydev)
		return -ENODEV;

	phy_start_aneg(lmac->phydev);

	return 0;
}

void bgx_lmac_disable(struct bgx *bgx, uint8_t lmacid)
{
	struct lmac *lmac;
	uint64_t cmrx_cfg;

	lmac = &bgx->lmac[lmacid];

	cmrx_cfg = bgx_reg_read(bgx, lmacid, BGX_CMRX_CFG);
	cmrx_cfg &= ~(1 << 15);
	bgx_reg_write(bgx, lmacid, BGX_CMRX_CFG, cmrx_cfg);
	bgx_flush_dmac_addrs(bgx, lmacid);
	bgx_unregister_interrupts(bgx);

	if (lmac->phydev)
		phy_disconnect(lmac->phydev);

	lmac->phydev = NULL;
}

static void bgx_set_num_ports(struct bgx *bgx, int qlm_mode)
{
	switch (qlm_mode) {
	case QLM_MODE_SGMII:
		bgx->lmac_count = 4;
		bgx->lmac_type = 0;
		bgx->lane_to_sds = 0;
		break;
	case QLM_MODE_XAUI_1X4:
		bgx->lmac_count = 1;
		bgx->lmac_type = 1;
		bgx->lane_to_sds = 0xE4;
			break;
	case QLM_MODE_XFI_4X1:
		bgx->lmac_count = 4;
		bgx->lmac_type = 3;
		bgx->lane_to_sds = 0;
		break;
	case QLM_MODE_XLAUI_1X4:
		bgx->lmac_count = 1;
		bgx->lmac_type = 4;
		bgx->lane_to_sds = 0xE4;
		break;
	case QLM_MODE_10G_KR_4X1:
		bgx->lmac_count = 4;
		bgx->lmac_type = 3;
		bgx->lane_to_sds = 0;
		break;
	case QLM_MODE_40G_KR4_1X4:
		bgx->lmac_count = 1;
		bgx->lmac_type = 4;
		bgx->lane_to_sds = 0xE4;
		break;
	default:
		bgx->lmac_count = 0;
		break;
	}
}

static void bgx_init_hw(struct bgx *bgx)
{
	int i;
	uint64_t cfg;

	if (bgx->bgx_id == 0)
		bgx_set_num_ports(bgx, QLM0_MODE);
	else
		bgx_set_num_ports(bgx, QLM1_MODE);

	bgx_reg_modify(bgx, 0, BGX_CMR_GLOBAL_CFG, (1ULL << 6));
	if (bgx_reg_read(bgx, 0, BGX_CMR_BIST_STATUS))
		pr_err("%s: BGX%d BIST failed\n", __func__, bgx->bgx_id);

	for (i = 0; i < bgx->lmac_count; i++) {
		bgx_reg_modify(bgx, i, BGX_CMRX_CFG,
			       (bgx->lmac_type << 8) | (bgx->lane_to_sds + i));
	}

	bgx_reg_write(bgx, 0, BGX_CMR_TX_LMACS, bgx->lmac_count);
	bgx_reg_write(bgx, 0, BGX_CMR_RX_LMACS, bgx->lmac_count);

	for (i = 0; i < bgx->lmac_count; i++)
		bgx_reg_modify(bgx, 0, BGX_CMR_CHAN_MSK_AND,
			       (((1ULL << 16) - 1) << (i * 16)));

	/* Disable all MAC filtering */
	for (i = 0; i < 32; i++)
		bgx_reg_write(bgx, 0, BGX_CMR_RX_DMACX_CAM + (i * 8), 0x00);

	/* Disable MAC steering */
	for (i = 0; i < 8; i++)
		bgx_reg_write(bgx, 0, BGX_CMR_RX_STREERING + (i * 8), 0x00);

	for (i = 0; i < bgx->lmac_count; i++) {
		bgx_reg_modify(bgx, i, BGX_GMP_GMI_TXX_THRESH, (0x100 - 1));
		bgx_reg_modify(bgx, i, BGX_SMUX_TX_THRESH, (0x100 - 1));

		bgx_reg_modify(bgx, i, BGX_GMP_GMI_RXX_JABBER, 9200);
		bgx_reg_modify(bgx, i, BGX_SMUX_RX_JABBER, 9200);

		cfg = bgx_reg_read(bgx, i, BGX_GMP_GMI_TXX_APPEND);
		if (cfg & 1)
			bgx_reg_write(bgx, i, BGX_GMP_GMI_TXX_SGMII_CTL, 0);
	}
}

static int bgx_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	int    err;
	struct device *dev = &pdev->dev;
	struct bgx *bgx = NULL;
	uint8_t lmac = 0;
	char bgx_sel[5];
	const __be32 *reg;
	struct device_node *np_bgx, *np_child;

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

	/* Get BGX node from DT */
	snprintf(bgx_sel, 5, "bgx%d", bgx->bgx_id);
	np_bgx = of_find_node_by_name(NULL, bgx_sel);

	for_each_child_of_node(np_bgx, np_child) {
		reg = of_get_property(np_child, "reg", NULL);
		lmac = be32_to_cpup(reg);
		SET_NETDEV_DEV(&bgx->lmac[lmac].netdev, &pdev->dev);
		bgx->lmac[lmac].phy_np = of_parse_phandle(np_child,
							  "phy-handle", 0);
		bgx->lmac[lmac].lmacid = lmac;
		bgx->lmac_count++;
	}

	bgx_init_hw(bgx);

	/* Enable MSI-X */
	if (!bgx_enable_msix(bgx))
		return 1;
	/* Enable all LMACs */
	for (lmac = 0; lmac < bgx->lmac_count; lmac++) {
		err = bgx_lmac_enable(bgx, lmac);
		if (err) {
			bgx_vnic[bgx->bgx_id] = NULL;
			dev_err(dev, "BGX%d failed to enable lmac\n", lmac);
			goto err_enable;
		}
	}

	return 0;
err_enable:
	if (bgx->reg_base)
		iounmap((void *)bgx->reg_base);
err_release_regions:
	pci_release_regions(pdev);
err_disable_device:
	pci_disable_device(pdev);
	kfree(bgx);
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
	for (lmac = 0; lmac < bgx->lmac_count; lmac++)
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

