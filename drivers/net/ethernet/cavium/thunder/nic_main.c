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
#include <linux/etherdevice.h>

#include "nic_reg.h"
#include "nic.h"
#include "thunder_bgx.h"

#define DRV_NAME	"thunder-nic"
#define DRV_VERSION	"1.0"

static void nic_channel_cfg(struct nicpf *nic, int vnic);
static int nic_update_hw_frs(struct nicpf *nic, int new_frs, int vf);

/* Supported devices */
static DEFINE_PCI_DEVICE_TABLE(nic_id_table) = {
	{ PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, PCI_DEVICE_ID_THUNDER_NIC_PF) },
	{ 0, }  /* end of table */
};

MODULE_AUTHOR("Sunil Goutham");
MODULE_DESCRIPTION("Cavium Thunder NIC Physical Function Driver");
MODULE_LICENSE("GPL v2");
MODULE_VERSION(DRV_VERSION);
MODULE_DEVICE_TABLE(pci, nic_id_table);

/* Register read/write APIs */
static void nic_reg_write(struct nicpf *nic, uint64_t offset, uint64_t val)
{
	uint64_t addr = nic->reg_base + offset;

	writeq_relaxed(val, (void *)addr);
}

static uint64_t nic_reg_read(struct nicpf *nic, uint64_t offset)
{
	uint64_t addr = nic->reg_base + offset;

	return readq_relaxed((void *)addr);
}

/* PF -> VF mailbox communication APIs */
static void nic_enable_mbx_intr(struct nicpf *nic)
{
	/* Enable mailbox interrupt for all 128 VFs */
	nic_reg_write(nic, NIC_PF_MAILBOX_ENA_W1S, ~0x00ull);
	nic_reg_write(nic, NIC_PF_MAILBOX_ENA_W1S + (1 << 3), ~0x00ull);
}

static uint64_t nic_get_mbx_intr_status(struct nicpf *nic, int mbx_reg)
{
	return nic_reg_read(nic, NIC_PF_MAILBOX_INT + (mbx_reg << 3));
}

static void nic_clear_mbx_intr(struct nicpf *nic, int vf, int mbx_reg)
{
	nic_reg_write(nic, NIC_PF_MAILBOX_INT + (mbx_reg << 3), (1ULL << vf));
}

static uint64_t nic_get_mbx_addr(int vf)
{
	return NIC_PF_VF_0_127_MAILBOX_0_7 + (vf << NIC_VF_NUM_SHIFT);
}

static int nic_lock_mbox(struct nicpf *nic, int vf)
{
	int timeout = NIC_PF_VF_MBX_TIMEOUT;
	int sleep = 10;
	uint64_t lock, mbx_addr;

	mbx_addr = nic_get_mbx_addr(vf) + NIC_PF_VF_MBX_LOCK_OFFSET;
	lock = nic_reg_read(nic, mbx_addr);
	while (lock) {
		msleep(sleep);
		lock = nic_reg_read(nic, mbx_addr);
		timeout -= sleep;
		if (!timeout) {
			netdev_err(nic->netdev, "PF couldn't lock mailbox\n");
			return 0;
		}
	}
	nic_reg_write(nic, mbx_addr, 1);
	return 1;
}

void nic_release_mbx(struct nicpf *nic, int vf)
{
	uint64_t mbx_addr;

	mbx_addr = nic_get_mbx_addr(vf) + NIC_PF_VF_MBX_LOCK_OFFSET;
	nic_reg_write(nic, mbx_addr, 0);
}

static int nic_send_msg_to_vf(struct nicpf *nic, int vf,
			      struct nic_mbx *mbx, bool lock_needed)
{
	int i;
	uint64_t *msg;
	uint64_t mbx_addr;

	if (lock_needed && (!nic_lock_mbox(nic, vf)))
		return -EBUSY;

	mbx->mbx_trigger_intr = 1;
	msg = (uint64_t *)mbx;
	mbx_addr = nic->reg_base + nic_get_mbx_addr(vf);

	for (i = 0; i < NIC_PF_VF_MAILBOX_SIZE; i++)
		writeq_relaxed(*(msg + i), (void *)(mbx_addr + (i * 8)));

	if (lock_needed)
		nic_release_mbx(nic, vf);
	return 0;
}

static void nic_mbx_send_ready(struct nicpf *nic, int vf)
{
	struct nic_mbx mbx = {};

	/* Respond with VNIC ID */
	mbx.msg = NIC_PF_VF_MSG_READY;
	mbx.data.nic_cfg.vf_id = vf;
#ifndef NIC_TNS_ENABLE
	mbx.data.nic_cfg.tns_mode = NIC_TNS_BYPASS_MODE;
#else
	mbx.data.nic_cfg.tns_mode = NIC_TNS_MODE;
#endif
	nic_send_msg_to_vf(nic, vf, &mbx, false);
}

static void nic_mbx_send_ack(struct nicpf *nic, int vf)
{
	struct nic_mbx mbx = {};

	mbx.msg = NIC_PF_VF_MSG_ACK;
	nic_send_msg_to_vf(nic, vf, &mbx, false);
}

static void nic_mbx_send_nack(struct nicpf *nic, int vf)
{
	struct nic_mbx mbx = {};

	mbx.msg = NIC_PF_VF_MSG_NACK;
	nic_send_msg_to_vf(nic, vf, &mbx, false);
}

/* Handle Mailbox messgaes from VF and ack the message. */
static void nic_handle_mbx_intr(struct nicpf *nic, int vf)
{
	struct nic_mbx mbx = {};
	uint64_t *mbx_data;
	uint64_t mbx_addr;
	uint64_t reg_addr;
	int i;
	int ret = 0;

	mbx_addr = nic_get_mbx_addr(vf);
	mbx_data = (uint64_t *)&mbx;

	for (i = 0; i < NIC_PF_VF_MAILBOX_SIZE; i++) {
		*mbx_data = nic_reg_read(nic, mbx_addr);
		mbx_data++;
		mbx_addr += NIC_PF_VF_MAILBOX_SIZE;
	}

	mbx.msg &= 0xFF;
	nic_dbg(&nic->pdev->dev, "%s: Mailbox msg %d from VF%d\n",
		__func__, mbx.msg, vf);
	switch (mbx.msg) {
	case NIC_PF_VF_MSG_READY:
		nic_mbx_send_ready(nic, vf);
		ret = 1;
		break;
	case NIC_PF_VF_MSG_QS_CFG:
		reg_addr = NIC_PF_QSET_0_127_CFG | (mbx.data.qs.num << NIC_QS_ID_SHIFT);
		nic_reg_write(nic, reg_addr, mbx.data.qs.cfg);
		nic_channel_cfg(nic, mbx.data.qs.num);
		break;
	case NIC_PF_VF_MSG_RQ_CFG:
		reg_addr = NIC_PF_QSET_0_127_RQ_0_7_CFG | (mbx.data.rq.qs_num << NIC_QS_ID_SHIFT) |
							  (mbx.data.rq.rq_num << NIC_Q_NUM_SHIFT);
		nic_reg_write(nic, reg_addr, mbx.data.rq.cfg);
		break;
	case NIC_PF_VF_MSG_RQ_DROP_CFG:
		reg_addr = NIC_PF_QSET_0_127_RQ_0_7_DROP_CFG | (mbx.data.rq.qs_num << NIC_QS_ID_SHIFT) |
								(mbx.data.rq.rq_num << NIC_Q_NUM_SHIFT);
		nic_reg_write(nic, reg_addr, mbx.data.rq.cfg);
		break;
	case NIC_PF_VF_MSG_SQ_CFG:
		reg_addr = NIC_PF_QSET_0_127_SQ_0_7_CFG | (mbx.data.sq.qs_num << NIC_QS_ID_SHIFT) |
							  (mbx.data.sq.sq_num << NIC_Q_NUM_SHIFT);
		nic_reg_write(nic, reg_addr, mbx.data.sq.cfg);
		break;
	case NIC_PF_VF_MSG_SET_MAC:
#ifndef NIC_TNS_ENABLE
		bgx_add_dmac_addr(mbx.data.mac.addr, mbx.data.mac.vf_id);
#endif
		break;
	case NIC_VF_SET_MAX_FRS:
		ret = nic_update_hw_frs(nic, mbx.data.frs.max_frs,
					mbx.data.frs.vf_id);
		break;
	default:
		netdev_err(nic->netdev, "Invalid message from VF%d, msg 0x%llx\n", vf, mbx.msg);
		break;
	}

	if (!ret)
		nic_mbx_send_ack(nic, vf);
	else if (mbx.msg != NIC_PF_VF_MSG_READY)
		nic_mbx_send_nack(nic, vf);
}

static int nic_update_hw_frs(struct nicpf *nic, int new_frs, int vf)
{
	if ((new_frs > NIC_HW_MAX_FRS) || (new_frs < NIC_HW_MIN_FRS)) {
		netdev_err(nic->netdev,
			   "Invalid MTU setting from VF%d rejected"
			   "should be between %d and %d\n", vf,
			   NIC_HW_MIN_FRS, NIC_HW_MAX_FRS);
		return 1;
	}
	new_frs += ETH_HLEN;
	if (new_frs <= nic->pkind.maxlen)
		return 0;

	nic->pkind.maxlen = new_frs;
	nic_reg_write(nic, NIC_PF_PKIND_0_15_CFG, *(uint64_t *)&nic->pkind);
	return 0;
}

/* Set minimum transmit packet size */
static void nic_set_tx_pkt_pad(struct nicpf *nic, int size)
{
	int lmac;
	uint64_t lmac_cfg;

	/* Max value that can be set is 60 */
	if (size > 60)
		size = 60;

	for (lmac = 0; lmac < (MAX_BGX_PER_CN88XX * MAX_LMAC_PER_BGX); lmac++) {
		lmac_cfg = nic_reg_read(nic, NIC_PF_LMAC_0_7_CFG | (lmac << 3));
		lmac_cfg &= ~(0xF << 2);
		lmac_cfg |= ((size / 4) << 2);
		nic_reg_write(nic, NIC_PF_LMAC_0_7_CFG | (lmac << 3), lmac_cfg);
	}
}

static void nic_init_hw(struct nicpf *nic)
{
	int i;
	uint64_t reg;

	/* Reset NIC, incase if driver is repeatedly inserted and removed */
	nic_reg_write(nic, NIC_PF_SOFT_RESET, 1);

	/* Enable NIC HW block */
	nic_reg_write(nic, NIC_PF_CFG, 1);

#ifndef NIC_TNS_ENABLE
	/* Disable TNS mode on both interfaces */
	nic->flags |= NIC_TNS_BYPASS_MODE;
	reg = NIC_TNS_BYPASS_MODE << 7;
	reg |= 0x08; /* Block identifier */
	nic_reg_write(nic, NIC_PF_INTF_0_1_SEND_CFG, reg);
	reg &= ~0xFull;
	reg |= 0x09;
	nic_reg_write(nic, NIC_PF_INTF_0_1_SEND_CFG | (1 << 8), reg);
#else
	nic->flags |= NIC_TNS_MODE;
	reg = NIC_TNS_MODE << 7;
	reg |= 0x06;
	nic_reg_write(nic, NIC_PF_INTF_0_1_SEND_CFG, reg);
	reg &= ~0xFull;
	reg |= 0x07;
	nic_reg_write(nic, NIC_PF_INTF_0_1_SEND_CFG | (1 << 8), reg);
#endif

	/* PKIND configuration */
	nic->pkind.minlen = 0;
	nic->pkind.maxlen = NIC_HW_MAX_FRS + ETH_HLEN;
	nic->pkind.lenerr_en = 1;
	nic->pkind.rx_hdr = 0;
	nic->pkind.hdr_sl = 0;

	for (i = 0; i < NIC_MAX_PKIND; i++)
		nic_reg_write(nic, NIC_PF_PKIND_0_15_CFG | (i << 3),
			       *(uint64_t *)&nic->pkind);

	nic_set_tx_pkt_pad(nic, NIC_HW_MIN_FRS);

	/* Disable backpressure for now */
	for (i = 0; i < NIC_MAX_CHANS; i++)
		nic_reg_write(nic, NIC_PF_CHAN_0_255_TX_CFG | (i << 3), 0);

	/* Timer config */
	nic_reg_write(nic, NIC_PF_INTR_TIMER_CFG, NICPF_CLK_PER_INT_TICK);
}

static void nic_channel_cfg(struct nicpf *nic, int vnic)
{
	uint8_t  rq_idx = 0;
	uint8_t  sq_idx = 0;
	uint32_t bgx, lmac, chan, tl3, tl4;
	uint64_t cpi_base, rssi_base;

	/* Below are the channel mappings
	 * BGX0-LMAC0-CHAN0 - VNIC CHAN0
	 * BGX0-LMAC1-CHAN0 - VNIC CHAN16
	 * ...
	 * BGX1-LMAC0-CHAN0 - VNIC CHAN128
	 * ...
	 * BGX1-LMAC3-CHAN0 - VNIC CHAN174
	 */
	bgx = vnic / MAX_LMAC_PER_BGX;
	lmac = vnic - (bgx * MAX_LMAC_PER_BGX);
	chan = (lmac * MAX_BGX_CHANS_PER_LMAC) + (bgx * NIC_CHANS_PER_BGX_INF);
	cpi_base = (lmac * NIC_CPI_PER_LMAC) + (bgx * NIC_CPI_PER_BGX);
	rssi_base = (lmac * NIC_RSSI_PER_LMAC) + (bgx * NIC_RSSI_PER_BGX);

	nic_reg_write(nic, NIC_PF_CHAN_0_255_RX_CFG | (chan << 3),
		      cpi_base << 48);
	nic_reg_write(nic, NIC_PF_CPI_0_2047_CFG | (cpi_base << 3),
		      (vnic << 24) | rssi_base);
	/* RQ's QS & RQ idx within QS */
	nic_reg_write(nic, NIC_PF_RSSI_0_4097_RQ | (rssi_base << 3),
		      (vnic << 3) | rq_idx);

	/* Transmit Channel config (TL4 -> TL3 -> Chan) */
	/* VNIC0-SQ0 -> TL4(0)  -> TL4A(0) -> TL3[0] -> BGX0/LMAC0/Chan0
	 * VNIC1-SQ0 -> TL4(8)  -> TL4A(2) -> TL3[2] -> BGX0/LMAC1/Chan0
	 * VNIC2-SQ0 -> TL4(16) -> TL4A(4) -> TL3[4] -> BGX0/LMAC2/Chan0
	 * VNIC3-SQ0 -> TL4(32) -> TL4A(6) -> TL3[6] -> BGX0/LMAC3/Chan0
	 * VNIC4-SQ0 -> TL4(512)  -> TL4A(128) -> TL3[128] -> BGX1/LMAC0/Chan0
	 * VNIC5-SQ0 -> TL4(520)  -> TL4A(130) -> TL3[130] -> BGX1/LMAC1/Chan0
	 * VNIC6-SQ0 -> TL4(528)  -> TL4A(132) -> TL3[132] -> BGX1/LMAC2/Chan0
	 * VNIC7-SQ0 -> TL4(536)  -> TL4A(134) -> TL3[134] -> BGX1/LMAC3/Chan0
	 */
	tl4 = (lmac * NIC_TL4_PER_LMAC) + (bgx * NIC_TL4_PER_BGX);

	for (sq_idx = 0; sq_idx < 8; sq_idx++) {
		tl3 = tl4 / (NIC_MAX_TL4 / NIC_MAX_TL3);
		nic_reg_write(nic, NIC_PF_QSET_0_127_SQ_0_7_CFG2 |
					(vnic << NIC_QS_ID_SHIFT) |
					(sq_idx << NIC_Q_NUM_SHIFT), tl4);
		nic_reg_write(nic, NIC_PF_TL4_0_1023_CFG | (tl4 << 3),
			      (vnic << 27) | (sq_idx << 24));
		nic_reg_write(nic, NIC_PF_TL4A_0_255_CFG | (tl3 << 3), tl3);
		nic_reg_write(nic, NIC_PF_TL3_0_255_CHAN | (tl3 << 3),
			      (lmac << 4));
		tl4++;
	}
}

static irqreturn_t nic_mbx0_intr_handler (int irq, void *nic_irq)
{
	int vf;
	uint16_t vf_per_mbx_reg = 64;
	uint64_t intr;
	struct nicpf *nic = (struct nicpf *)nic_irq;

	intr = nic_get_mbx_intr_status(nic, 0);
	nic_dbg(&nic->pdev->dev, "PF MSIX interrupt Mbox0 0x%llx\n", intr);
	for (vf = 0; vf < min(nic->num_vf_en, vf_per_mbx_reg); vf++) {
		if (intr & (1ULL << vf)) {
			nic_dbg(&nic->pdev->dev, "Intr from VF %d\n", vf);
			nic_handle_mbx_intr(nic, vf);
			nic_clear_mbx_intr(nic, vf, 0);
		}
	}

	return IRQ_HANDLED;
}

static irqreturn_t nic_mbx1_intr_handler (int irq, void *nic_irq)
{
	int vf;
	uint16_t vf_per_mbx_reg = 64;
	uint64_t intr;
	struct nicpf *nic = (struct nicpf *)nic_irq;

	if (nic->num_vf_en <= vf_per_mbx_reg)
		return IRQ_HANDLED;

	intr = nic_get_mbx_intr_status(nic, 1);
	nic_dbg(&nic->pdev->dev, "PF MSIX interrupt Mbox1 0x%llx\n", intr);
	for (vf = 0; vf < (nic->num_vf_en - vf_per_mbx_reg); vf++) {
		if (intr & (1ULL << vf)) {
			nic_dbg(&nic->pdev->dev,
				"Intr from VF %d\n", vf + vf_per_mbx_reg);
			nic_handle_mbx_intr(nic, vf + vf_per_mbx_reg);
			nic_clear_mbx_intr(nic, vf, 1);
		}
	}

	return IRQ_HANDLED;
}

static int nic_enable_msix(struct nicpf *nic)
{
	int i, ret;

	nic->num_vec = NIC_PF_MSIX_VECTORS;

	for (i = 0; i < nic->num_vec; i++)
		nic->msix_entries[i].entry = i;

	ret = pci_enable_msix(nic->pdev, nic->msix_entries, nic->num_vec);
	if (ret) {
		netdev_err(nic->netdev,
			"Request for #%d msix vectors failed\n", nic->num_vec);
		return 0;
	}

	nic->msix_enabled = 1;
	return 1;
}

static void nic_disable_msix(struct nicpf *nic)
{
	if (nic->msix_enabled) {
		pci_disable_msix(nic->pdev);
		nic->msix_enabled = 0;
		nic->num_vec = 0;
	}
}

static int nic_register_interrupts(struct nicpf *nic)
{
	int irq, ret = 0;

	/* Enable MSI-X */
	if (!nic_enable_msix(nic))
		return 1;

	/* Register mailbox interrupt handlers */
	ret = request_irq(nic->msix_entries[NIC_PF_INTR_ID_MBOX0].vector,
			  nic_mbx0_intr_handler, 0 , "NIC Mbox0", nic);
	if (ret)
		goto fail;
	else
		nic->irq_allocated[NIC_PF_INTR_ID_MBOX0] = 1;

	ret = request_irq(nic->msix_entries[NIC_PF_INTR_ID_MBOX1].vector,
			  nic_mbx1_intr_handler, 0 , "NIC Mbox1", nic);
	if (ret)
		goto fail;
	else
		nic->irq_allocated[NIC_PF_INTR_ID_MBOX1] = 1;

	/* Enable mailbox interrupt */
	nic_enable_mbx_intr(nic);
	return 0;
fail:
	netdev_err(nic->netdev, "Request irq failed\n");
	for (irq = 0; irq < nic->num_vec; irq++) {
		if (nic->irq_allocated[irq])
			free_irq(nic->msix_entries[irq].vector, nic);
		nic->irq_allocated[irq] = 0;
	}
	return 1;
}

static void nic_unregister_interrupts(struct nicpf *nic)
{
	int irq;

	/* Free registered interrupts */
	for (irq = 0; irq < nic->num_vec; irq++) {
		if (nic->irq_allocated[irq])
			free_irq(nic->msix_entries[irq].vector, nic);
		nic->irq_allocated[irq] = 0;
	}

	/* Disable MSI-X */
	nic_disable_msix(nic);
}

void nic_set_sriov_enable(struct nicpf *nic)
{
	nic->flags |= NIC_SRIOV_ENABLED;
}

void nic_clear_sriov_enable(struct nicpf *nic)
{
	nic->flags &= ~NIC_SRIOV_ENABLED;
}

bool nic_is_sriov_enabled(struct nicpf *nic)
{
	if (nic->flags & NIC_SRIOV_ENABLED)
		return true;
	return false;
}

int nic_sriov_configure(struct pci_dev *pdev, int num_vfs_requested)
{
	struct net_device *netdev = pci_get_drvdata(pdev);
	struct nicpf *nic = netdev_priv(netdev);
	int err;

	if (nic->num_vf_en == num_vfs_requested)
		return num_vfs_requested;

	if (nic_is_sriov_enabled(nic)) {
		pci_disable_sriov(pdev);
		nic_clear_sriov_enable(nic);
	}

	nic->num_vf_en = 0;
	if (num_vfs_requested > MAX_NUM_VFS_SUPPORTED)
		return -EPERM;

	if (num_vfs_requested) {
		if ((err = pci_enable_sriov(pdev, num_vfs_requested))) {
			dev_err(&pdev->dev, "SRIOV, Failed to enable %d VFs\n", num_vfs_requested);
			return err;
		}
		nic->num_vf_en = num_vfs_requested;
		nic_set_sriov_enable(nic);
	}

	return num_vfs_requested;
}

static int  nic_sriov_init(struct pci_dev *pdev, struct nicpf *nic)
{
	int    pos = 0;

	pos = pci_find_ext_capability(pdev, PCI_EXT_CAP_ID_SRIOV);
	if (!pos) {
		dev_err(&pdev->dev, "SRIOV capability is not found in PCIe config space\n");
		return 0;
	}

	pci_read_config_word(pdev, (pos + PCI_SRIOV_TOTAL_VF), &nic->total_vf_cnt);
	if (nic->total_vf_cnt < DEFAULT_NUM_VF_ENABLED)
		nic->num_vf_en = nic->total_vf_cnt;
	else
		nic->num_vf_en = DEFAULT_NUM_VF_ENABLED;

	if (nic->total_vf_cnt && pci_enable_sriov(pdev, nic->num_vf_en)) {
		dev_err(&pdev->dev, "SRIOV enable failed, num VF is %d\n", nic->num_vf_en);
		nic->num_vf_en = 0;
		return 0;
	}
	dev_info(&pdev->dev, "SRIOV enabled, numer of VF available %d\n", nic->num_vf_en);

	nic_set_sriov_enable(nic);
	return 1;
}

static int nic_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	struct device *dev = &pdev->dev;
	struct net_device *netdev;
	struct nicpf *nic;
	int    err;

	netdev = alloc_etherdev(sizeof(struct nicpf));
	if (!netdev)
		return -ENOMEM;

	pci_set_drvdata(pdev, netdev);

	SET_NETDEV_DEV(netdev, &pdev->dev);

	nic = netdev_priv(netdev);
	nic->netdev = netdev;
	nic->pdev = pdev;

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

	err = pci_set_dma_mask(pdev, DMA_BIT_MASK(48));
	if (err) {
		dev_err(dev, "Unable to get usable DMA configuration\n");
		goto err_release_regions;
	}

	err = pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(48));
	if (err) {
		dev_err(dev, "unable to get 48-bit DMA for consistent allocations\n");
		goto err_release_regions;
	}

	/* MAP PF's configuration registers */
	nic->reg_base = (uint64_t)pci_ioremap_bar(pdev, PCI_CFG_REG_BAR_NUM);
	if (!nic->reg_base) {
		dev_err(dev, "Cannot map config register space, aborting\n");
		err = -ENOMEM;
		goto err_release_regions;
	}

	/* Initialize hardware */
	nic_init_hw(nic);

	/* Register interrupts */
	if (nic_register_interrupts(nic))
		goto err_unmap_resources;

	/* Configure SRIOV */
	if (!nic_sriov_init(pdev, nic))
		goto err_unmap_resources;

	goto exit;

err_unmap_resources:
	if (nic->reg_base)
		iounmap((void *)nic->reg_base);
err_release_regions:
	pci_release_regions(pdev);
err_disable_device:
	pci_disable_device(pdev);
exit:
	return err;
}

static void nic_remove(struct pci_dev *pdev)
{
	struct net_device *netdev = pci_get_drvdata(pdev);
	struct nicpf *nic;

	if (!netdev)
		return;

	nic = netdev_priv(netdev);

	nic_unregister_interrupts(nic);

	if (nic_is_sriov_enabled(nic))
		pci_disable_sriov(pdev);

	pci_set_drvdata(pdev, NULL);

	if (nic->reg_base)
		iounmap((void *)nic->reg_base);

	pci_release_regions(pdev);
	pci_disable_device(pdev);
	free_netdev(netdev);
}

static struct pci_driver nic_driver = {
	.name = DRV_NAME,
	.id_table = nic_id_table,
	.probe = nic_probe,
	.remove = nic_remove,
	.sriov_configure = nic_sriov_configure,
};

static int __init nic_init_module(void)
{
	pr_info("%s, ver %s\n", DRV_NAME, DRV_VERSION);

	return pci_register_driver(&nic_driver);
}

static void __exit nic_cleanup_module(void)
{
	pci_unregister_driver(&nic_driver);
}

module_init(nic_init_module);
module_exit(nic_cleanup_module);
