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
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/ethtool.h>
#include <linux/aer.h>

#include "nic.h"
#include "nic_reg.h"
#include "thunder_bgx.h"

#define DRV_NAME  	"thunder-nic"
#define DRV_VERSION  	"1.0"

static void nic_channel_cfg(struct nicpf *nic, int vnic);

/* Supported devices */
static DEFINE_PCI_DEVICE_TABLE(nic_id_table) = {
        { PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, PCI_DEVICE_ID_THUNDER_NIC_PF) },
        { 0, }  /* end of table */
};

MODULE_AUTHOR("Cavium Inc");
MODULE_DESCRIPTION("Cavium Thunder Physical Function Driver");
MODULE_LICENSE("GPL");
MODULE_VERSION(DRV_VERSION);
MODULE_DEVICE_TABLE(pci, nic_id_table);

/* Register read/write APIs */
static void nic_reg_write (struct nicpf *nic, uint64_t offset, uint64_t val)
{
	uint64_t addr = nic->reg_base + offset;
        writeq_relaxed(val, (void *)addr);
}

static uint64_t nic_reg_read (struct nicpf *nic, uint64_t offset)
{
	uint64_t addr = nic->reg_base + offset;
        return readq_relaxed((void *)addr);
}

/*
 * PF -> VF mailbox communication APIs
 */
static void nic_enable_mbx_intr (struct nicpf *nic)
{
	int	 irq;
	uint64_t vf_mbx_intr_enable = 0;

	/* TBD: Need to support runtime SRIOV VF count configuratuon */
	/* Or consider enabling all VF's interrupts, since there is no harm */
	for (irq = 0; irq < 64; irq++)
		if (irq < nic->num_vf_en)
			vf_mbx_intr_enable |= (1 << irq);
	nic_reg_write (nic, NIC_PF_MAILBOX_ENA_W1S, vf_mbx_intr_enable);

	if (nic->num_vf_en < 64)
		return;

	vf_mbx_intr_enable = 0;
	for (irq = 0; irq < 64; irq++)
		if (irq < (nic->num_vf_en - 64))
			vf_mbx_intr_enable |= (1 << irq);
	nic_reg_write (nic, NIC_PF_MAILBOX_ENA_W1S + (1 << 3), vf_mbx_intr_enable);
}

static uint64_t nic_get_mbx_intr_status (struct nicpf *nic, int mbx_reg)
{
	if (!mbx_reg)	/* first 64 VFs */
		return nic_reg_read(nic, NIC_PF_MAILBOX_INT);
	else		/* Next 64 VFs */
		return nic_reg_read(nic, NIC_PF_MAILBOX_INT + (1 << 3));
}

static void nic_clear_mbx_intr (struct nicpf *nic, int vf)
{
	if (!(vf / 64))	/* first 64 VFs */
		nic_reg_write (nic, NIC_PF_MAILBOX_INT, (1ULL << vf));
	else		/* Next 64 VFs */
		nic_reg_write (nic, NIC_PF_MAILBOX_INT + (1 << 3), (1ULL << (vf - 64)));
}

static void nic_mbx_send_ready (struct nicpf *nic, int vf)
{
	uint64_t mbx_addr;

	mbx_addr = NIC_PF_VF_0_127_MAILBOX_0_7;
	mbx_addr += (vf << NIC_VF_NUM_SHIFT);

	/* Respond with VNIC ID */
	nic_reg_write(nic, mbx_addr, NIC_PF_VF_MSG_READY);
	nic_reg_write(nic, mbx_addr + 8, vf);
	mbx_addr += (NIC_PF_VF_MAILBOX_SIZE - 1) * 8;
	/* Set 1 in last MBX reg */
	nic_reg_write (nic, mbx_addr, 1ULL);
}

static void nic_mbx_send_ack (struct nicpf *nic, int vf)
{
	uint64_t mbx_addr;

	mbx_addr = NIC_PF_VF_0_127_MAILBOX_0_7;
	mbx_addr += (vf << NIC_VF_NUM_SHIFT);

	nic_reg_write (nic, mbx_addr, NIC_PF_VF_MSG_ACK);
	mbx_addr += (NIC_PF_VF_MAILBOX_SIZE - 1) * 8;
	/* Set 1 in last MBX reg */
	nic_reg_write (nic, mbx_addr, 1ULL);
}

/*
 * Handle Mailbox messgaes from VF and ack the message.
 */
static void nic_handle_mbx_intr (struct nicpf *nic, int vf)
{
	int i;
	struct nic_mbx *mbx;
	uint64_t *mbx_data;
	uint64_t reg_addr;
	uint64_t mbx_addr;

	mbx_addr = NIC_PF_VF_0_127_MAILBOX_0_7;
	mbx_addr += (vf << NIC_VF_NUM_SHIFT);

	mbx_data = kzalloc(sizeof(struct nic_mbx), GFP_KERNEL);
	mbx = (struct nic_mbx *) mbx_data;

	for (i = 0; i < NIC_PF_VF_MAILBOX_SIZE; i++) {
		*mbx_data = nic_reg_read(nic, mbx_addr + (i * NIC_PF_VF_MAILBOX_SIZE));
		mbx_data++;
	}

	switch (mbx->msg & 0xFF) {
	case NIC_PF_VF_MSG_READY:
		nic_dbg(&nic->pdev->dev, "NIC_PF_VF_MSG_READY\n");
		nic_mbx_send_ready(nic, vf);
		goto exit;
		break;
	case NIC_PF_VF_MSG_QS_CFG:
		reg_addr = NIC_PF_QSET_0_127_CFG | (mbx->data.qs.num << NIC_QS_ID_SHIFT);
		nic_reg_write (nic, reg_addr, mbx->data.qs.cfg);
		nic_channel_cfg(nic, mbx->data.qs.num);
		if (!mbx->data.qs.cfg)
			bgx_lmac_disable(mbx->data.qs.num);
		else
			bgx_lmac_enable(mbx->data.qs.num);
		break;
	case NIC_PF_VF_MSG_RQ_CFG:
		reg_addr = NIC_PF_QSET_0_127_RQ_0_7_CFG | (mbx->data.rq.qs_num << NIC_QS_ID_SHIFT) |
							  (mbx->data.rq.rq_num << NIC_Q_NUM_SHIFT);
		nic_reg_write (nic, reg_addr, mbx->data.rq.cfg);
		break;
	case NIC_PF_VF_MSG_RQ_DROP_CFG:
		reg_addr = NIC_PF_QSET_0_127_RQ_0_7_DROP_CFG | (mbx->data.rq.qs_num << NIC_QS_ID_SHIFT) |
								(mbx->data.rq.rq_num << NIC_Q_NUM_SHIFT);
		nic_reg_write (nic, reg_addr, mbx->data.rq.cfg);
		break;
	case NIC_PF_VF_MSG_SQ_CFG:
		reg_addr = NIC_PF_QSET_0_127_SQ_0_7_CFG | (mbx->data.sq.qs_num << NIC_QS_ID_SHIFT) |
							  (mbx->data.sq.sq_num << NIC_Q_NUM_SHIFT);
		nic_reg_write (nic, reg_addr, mbx->data.sq.cfg);
		break;
	case NIC_PF_VF_MSG_SET_MAC:
		bgx_add_dmac_addr(mbx->data.mac.addr, mbx->data.mac.vnic_id);
		break;
	default:
		netdev_err(nic->netdev, "Invalid message from VF%d, msg 0x%llx\n", vf, mbx->msg);
		break;
	}
	nic_mbx_send_ack(nic, vf);
exit:
	kfree(mbx);
}

static void nic_init_hw (struct nicpf *nic)
{
	int i;

	/* Reset NIC, incase if driver is repeatedly inserted and removed */
	nic_reg_write (nic, NIC_PF_SOFT_RESET, 1);

	/* Enable NIC HW block */
	nic_reg_write (nic, NIC_PF_CFG, 1);

	/* Disable TNS mode, no TNS support in simulator */
	nic_reg_write (nic, NIC_PF_INTF_0_1_SEND_CFG, 0);
	nic_reg_write (nic, NIC_PF_INTF_0_1_SEND_CFG | (1 << 8), 0);

	/*
	 * Simulator doesn't support padding, disable min packet check.
	 * Max pkt size - 1536.
	 * Enable L2 length err check.
	 * Disable TNS receive header for now.
	 */
	for (i = 0; i < NIC_MAX_PKIND; i++)
		nic_reg_write (nic, NIC_PF_PKIND_0_15_CFG | (i << 3),
								0x206000000);
	/* Disable backpressure for now */
	for (i = 0; i < NIC_MAX_CHANS; i++)
		nic_reg_write(nic, NIC_PF_CHAN_0_255_TX_CFG | (i << 3), 0);
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
		tl4 = tl4 + sq_idx;
		tl3 = tl4 / (NIC_MAX_TL4 / NIC_MAX_TL3);
		nic_reg_write(nic, NIC_PF_QSET_0_127_SQ_0_7_CFG2 |
					(vnic << NIC_QS_ID_SHIFT) |
					(sq_idx << NIC_Q_NUM_SHIFT), tl4);
		nic_reg_write(nic, NIC_PF_TL4_0_1023_CFG | (tl4 << 3),
			      (vnic << 27) | (sq_idx << 24));
		nic_reg_write(nic, NIC_PF_TL4A_0_255_CFG | (tl3 << 3), tl3);
		nic_reg_write(nic, NIC_PF_TL3_0_255_CHAN | (tl3 << 3),
			      (lmac << 4));
	}
}

static irqreturn_t nic_intr_handler (int irq, void *nic_irq)
{
	int vf;
	uint64_t intr;
	struct nicpf *nic = (struct nicpf *) nic_irq;

	intr = nic_get_mbx_intr_status(nic, 0); /* Mbox 0 */
	nic_dbg(&nic->pdev->dev, "PF MSIX interrupt 0x%llx\n", intr);
	for (vf = 0; vf < nic->num_vf_en; vf++) {
		if (intr & (1 << vf)) {
			nic_dbg(&nic->pdev->dev, "Intr from VF %d\n", vf);
			nic_handle_mbx_intr(nic, vf);
			nic_clear_mbx_intr(nic, vf);
		}
	}

	return IRQ_HANDLED;
}

static int nic_enable_msix (struct nicpf *nic)
{
	int i, ret;

	nic->num_vec = NIC_PF_MSIX_VECTORS;

	for (i = 0; i < nic->num_vec; i++) {
		nic->msix_entries[i].entry = i;
	}

	ret = pci_enable_msix(nic->pdev, nic->msix_entries, nic->num_vec);
	if (ret < 0) {
		netdev_err(nic->netdev,
			"Request for #%d msix vectors failed\n", nic->num_vec);
		return 0;
	} else if (ret > 0) {
		netdev_err(nic->netdev,
			"Request for #%d msix vectors failed, requesting #%d\n",
			nic->num_vec, ret);

		nic->num_vec = ret;
		ret = pci_enable_msix(nic->pdev, nic->msix_entries, nic->num_vec);
		if (ret) {
			netdev_warn(nic->netdev, "Request for msix vectors failed\n");
			return 0;
		}
	}

	nic->msix_enabled = 1;
	return 1;
}

static void nic_disable_msix (struct nicpf *nic)
{
	if (nic->msix_enabled) {
		pci_disable_msix(nic->pdev);
		nic->msix_enabled = 0;
		nic->num_vec = 0;
	}
}

static int nic_register_interrupts (struct nicpf *nic)
{
	int irq, free, ret = 0;

	/* Enable MSI-X */
	if (!nic_enable_msix(nic))
		return 1;

	/* Register interrupts */
	/* For now skip ECC interrupts, register only Mbox interrupts */
	for (irq = 8; irq < nic->num_vec; irq++) {
		ret = request_irq (nic->msix_entries[irq].vector,
				nic_intr_handler, 0 , "NIC PF", nic);
		if (ret)
			break;
	}

	if (ret) {
		netdev_err(nic->netdev, "Request irq failed\n");
		for (free = 0; free < irq; free++)
			free_irq (nic->msix_entries[free].vector, nic);
		return 1;
	}

	/* Enable mailbox interrupt */
	nic_enable_mbx_intr(nic);

	return 0;
}

static void nic_unregister_interrupts (struct nicpf *nic)
{
	int irq;

	/* Free registered interrupts */
	for (irq = 0; irq < nic->num_vec; irq++)
		free_irq (nic->msix_entries[irq].vector, nic);

	/* Disable MSI-X */
	nic_disable_msix(nic);
}

void nic_set_sriov_enable (struct nicpf *nic)
{
	nic->flags |= NIC_SRIOV_ENABLED;
}

void nic_clear_sriov_enable (struct nicpf *nic)
{
	nic->flags &= ~NIC_SRIOV_ENABLED;
}

bool nic_is_sriov_enabled (struct nicpf *nic)
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
		if ((err = pci_enable_sriov (pdev, num_vfs_requested))) {
			dev_err(&pdev->dev, "SRIOV, Failed to enable %d VFs\n", num_vfs_requested);
			return err;
		}
		nic->num_vf_en = num_vfs_requested;
		nic_set_sriov_enable(nic);
	}

	return num_vfs_requested;
}

static int  nic_sriov_init (struct pci_dev *pdev, struct nicpf *nic)
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

	if(nic->total_vf_cnt && pci_enable_sriov(pdev, nic->num_vf_en)) {
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
	if (!err) {
		err = pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(48));
		if (err) {
			dev_err(dev, "unable to get 40-bit DMA for consistent allocations\n");
			goto err_release_regions;
		}
	} else {
		dev_err(dev, "Unable to get usable DMA configuration\n");
		goto err_release_regions;
	}

	/* MAP PF's configuration registers */
	nic->reg_base = (uint64_t) pci_ioremap_bar(pdev, PCI_CFG_REG_BAR_NUM);
        if (!nic->reg_base) {
                dev_err(dev, "Cannot map config register space, aborting\n");
                err = -ENOMEM;
                goto err_release_regions;
        }

	/* Initialize hardware */
	nic_init_hw(nic);

	/* Configure SRIOV */
	if (!nic_sriov_init(pdev, nic)) {
		goto err_unmap_resources;
	}

	/* Register interrupts */
	if (nic_register_interrupts(nic)) {
		goto err_unmap_resources;
	}

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

	if (nic_is_sriov_enabled(nic)) {
		pci_disable_sriov(pdev);
	}

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

