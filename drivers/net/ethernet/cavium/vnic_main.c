/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 * 
 * Copyright (C) 2013 Cavium, Inc. 
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

#include "vnic.h"
#include "vnic_hw.h"
#include "vnic_queues.h"
#include "cn88xx_bgx.h"

#define DRV_NAME  	"vnic-pf"
#define DRV_VERSION  	"1.0"

/* Supported devices */
static DEFINE_PCI_DEVICE_TABLE(vnic_id_table) = {
        { PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, PCI_DEVICE_ID_8XXX_VNIC_PF) },
        { 0, }  /* end of table */
};

MODULE_AUTHOR("Cavium Inc");
MODULE_DESCRIPTION("Cavium 8xxx VNIC Network Driver");
MODULE_LICENSE("GPL");
MODULE_VERSION(DRV_VERSION);
MODULE_DEVICE_TABLE(pci, vnic_id_table);

/* Register read/write APIs */
static void vnic_pf_reg_write (struct vnic_pf *pf, uint64_t offset, uint64_t val)
{
	uint64_t addr = pf->reg_base + offset;
        writeq_relaxed(val, (void *)addr);
}

static uint64_t vnic_pf_reg_read (struct vnic_pf *pf, uint64_t offset)
{
	uint64_t addr = pf->reg_base + offset;
        return readq_relaxed((void *)addr);
}

/* 
 * PF -> VF mailbox communication APIs 
 */
static void vnic_enable_mbx_intr (struct vnic_pf *pf)
{
	int	 irq;
	uint64_t vf_mbx_intr_enable = 0;

	/* TBD: Need to support runtime SRIOV VF count configuratuon */	
	/* Or consider enabling all VF's interrupts, since there is no harm */
	for (irq = 0; irq < 64; irq++)
		if (irq < pf->num_vf_en)
			vf_mbx_intr_enable |= (1 << irq);
	vnic_pf_reg_write (pf, NIC_PF_MAILBOX_ENA_W1S, vf_mbx_intr_enable);
	
	if (pf->num_vf_en < 64)
		return;

	vf_mbx_intr_enable = 0;
	for (irq = 0; irq < 64; irq++)
		if (irq < (pf->num_vf_en - 64))
			vf_mbx_intr_enable |= (1 << irq);
	vnic_pf_reg_write (pf, NIC_PF_MAILBOX_ENA_W1S + (1 << 3), vf_mbx_intr_enable);
}

static uint64_t vnic_get_mbx_intr_status (struct vnic_pf *pf, int mbx_reg)
{
	if (!mbx_reg)	/* first 64 VFs */
		return vnic_pf_reg_read(pf, NIC_PF_MAILBOX_INT);
	else		/* Next 64 VFs */
		return vnic_pf_reg_read(pf, NIC_PF_MAILBOX_INT + (1 << 3));
}

static void vnic_clear_mbx_intr (struct vnic_pf *pf, int vf)
{
	if (!(vf / 64))	/* first 64 VFs */
		vnic_pf_reg_write (pf, NIC_PF_MAILBOX_INT, (1ULL << vf));
	else		/* Next 64 VFs */
		vnic_pf_reg_write (pf, NIC_PF_MAILBOX_INT + (1 << 3), (1ULL << (vf - 64)));
}


static void vnic_mbx_send_ack (struct vnic_pf *pf, int vf)
{
	uint64_t mbx_addr;

	mbx_addr = NIC_PF_VF_0_127_MAILBOX_0_7;
	mbx_addr += (vf << VNIC_VF_NUM_SHIFT);

	vnic_pf_reg_write (pf, mbx_addr, VNIC_PF_VF_MSG_ACK);
	mbx_addr += (VNIC_PF_VF_MAILBOX_SIZE - 1) * 8;
	/* Set 1 in last MBX reg */ 
	vnic_pf_reg_write (pf, mbx_addr, 1ULL); 
}

/*
 * Handle Mailbox messgaes from VF and ack the message.
 */
static void vnic_handle_mbx_intr (struct vnic_pf *pf, int vf)
{
	int i;
	struct vnic_mbx *mbx;
	uint64_t *mbx_data;
	uint64_t reg_addr;
	uint64_t mbx_addr;

	mbx_addr = NIC_PF_VF_0_127_MAILBOX_0_7;
	mbx_addr += (vf << VNIC_VF_NUM_SHIFT);

	mbx_data = kzalloc(sizeof(struct vnic_mbx), GFP_KERNEL);
	mbx = (struct vnic_mbx *) mbx_data;

	for (i = 0; i < VNIC_PF_VF_MAILBOX_SIZE; i++) {
		*mbx_data = vnic_pf_reg_read(pf, mbx_addr + (i * VNIC_PF_VF_MAILBOX_SIZE));
		mbx_data++;
	}

	switch (mbx->msg & 0xFF) {
	case VNIC_PF_VF_MSG_READY:
		//pr_err("VNIC_PF_VF_MSG_READY\n");
		/* Nothing to do, just send an ack */
		break;
	case VNIC_PF_VF_MSG_QS_CFG:
		reg_addr = NIC_PF_QSET_0_127_CFG | (mbx->data.qs.num << VNIC_QS_ID_SHIFT);
		//pr_err("%s qs_num %d qs.cfg %d\n", __FUNCTION__,mbx->data.qs.num, mbx->data.qs.cfg);
		vnic_pf_reg_write (pf, reg_addr, mbx->data.qs.cfg); 
		break;
	case VNIC_PF_VF_MSG_RQ_CFG:
		reg_addr = NIC_PF_QSET_0_127_RQ_0_7_CFG | (mbx->data.rq.qs_num << VNIC_QS_ID_SHIFT) | 
							  (mbx->data.rq.rq_num << VNIC_Q_NUM_SHIFT);
		vnic_pf_reg_write (pf, reg_addr, mbx->data.rq.cfg); 
		break;
	case VNIC_PF_VF_MSG_SQ_CFG:
		reg_addr = NIC_PF_QSET_0_127_SQ_0_7_CFG | (mbx->data.sq.qs_num << VNIC_QS_ID_SHIFT) | 
							  (mbx->data.sq.sq_num << VNIC_Q_NUM_SHIFT);
		vnic_pf_reg_write (pf, reg_addr, mbx->data.sq.cfg); 
		break;
	case VNIC_PF_VF_MSG_SET_MAC:
		/* TBD: Add this MAC address to the list of DMAC filter addresses in BGX */
		//dev_info(&pf->pdev->dev, "Set VF%d's Mac address to %lld\n",vf, mbx->data.mac.addr);
		bgx_add_dmac_addr(mbx->data.mac.addr, mbx->data.mac.vnic_id);
		break;
	default:
		dev_err(&pf->pdev->dev, "Invalid message from VF%d, msg 0x%llx\n", vf, mbx->msg);
		break;
	}
	
	vnic_mbx_send_ack(pf, vf);
	kfree(mbx_data);
}

static void vnic_channel_cfg (struct vnic_pf *pf)
{
	uint8_t  rq_idx = 0;
	uint8_t  vnic, bgx;
	uint32_t chan, tl3, tl4;
	uint64_t cpi_base;
	uint64_t rssi_base;

	/* Disable backpressure for now */
	for (chan = 0; chan < VNIC_MAX_CHANNELS; chan++) {
		vnic_pf_reg_write(pf, NIC_PF_CHAN_0_255_TX_CFG | (chan << 3), 0);
	}

	for (vnic = 0; vnic < 8; vnic++) {
		/* Each BGX LMAC port has 16 channels */
		/* As per current simulator BGX implementation,
 		 * BGX0-LMAC0-CHAN0 - VNIC CHAN0
 		 * BGX0-LMAC1-CHAN0 - VNIC CHAN16
 		 * BGX1-LMAC0-CHAN0 - VNIC CHAN128
 		 */
		bgx = vnic / 4; 
		if (vnic < 4) {
		        chan = vnic * 16;
		        cpi_base = vnic * (2048 / 256);
		        rssi_base = vnic * (4096 / 256) * (bgx + 1);
		} else {
			chan = (vnic - 4) * 16 + 128;
		        cpi_base = (vnic - 4) * (2048 / 256) + 1024;
		        rssi_base = (vnic - 4) * (4096 / 256) + 2048;
		}

		/* CPI ALG none */
		vnic_pf_reg_write(pf, NIC_PF_CHAN_0_255_RX_CFG | (chan << 3), cpi_base << 48);
		vnic_pf_reg_write(pf, NIC_PF_CPI_0_2047_CFG | (cpi_base << 3), (vnic << 24) | rssi_base);
		/* RQ's QS & RQ idx within QS */
		vnic_pf_reg_write(pf, NIC_PF_RSSI_0_4097_RQ | (rssi_base << 3), (vnic << 3) | rq_idx);
	
		/* Transmit Channel config (TL4 -> TL3 -> Chan) */
		/* By-pass mode configuration
		 * For 0 - 3 VNICs
		 */
		/* VNIC0-SQ0 -> TL4(0)  -> TL4A(0) -> TL3[0] -> BGX0/LMAC0/Chan0
		 * VNIC1-SQ0 -> TL4(8)  -> TL4A(2) -> TL3[2] -> BGX0/LMAC1/Chan0
		 * VNIC2-SQ0 -> TL4(16) -> TL4A(4) -> TL3[4] -> BGX0/LMAC2/Chan0
		 * VNIC3-SQ0 -> TL4(32) -> TL4A(6) -> TL3[6] -> BGX0/LMAC3/Chan0
		 */
		if (vnic >= 4)
			goto vnic4;
		tl4 = vnic * 8;
		tl3 = tl4 / 4;
		vnic_pf_reg_write(pf, NIC_PF_QSET_0_127_SQ_0_7_CFG2 | 
					(vnic << VNIC_QS_ID_SHIFT), tl4);
		vnic_pf_reg_write(pf, NIC_PF_TL4_0_1023_CFG | 
					(tl4 << 3), (vnic << 27) | (0 << 24));
		vnic_pf_reg_write(pf, NIC_PF_TL4A_0_255_CFG | (tl3 << 3), tl3);
		vnic_pf_reg_write(pf, NIC_PF_TL3_0_255_CHAN | 
				(tl3 << 3), (bgx << 7) | (vnic << 4) | (0 << 0));

vnic4:
		if (!vnic >= 4)
			continue;
		/* For 4 - 7 VNICs
		 * VNIC4-SQ0 -> TL4(512)  -> TL4A(128) -> TL3[128] -> BGX1/LMAC0/Chan0
		 * VNIC5-SQ0 -> TL4(520)  -> TL4A(130) -> TL3[130] -> BGX1/LMAC1/Chan0
		 * VNIC6-SQ0 -> TL4(528)  -> TL4A(132) -> TL3[132] -> BGX1/LMAC2/Chan0
		 * VNIC7-SQ0 -> TL4(536)  -> TL4A(134) -> TL3[134] -> BGX1/LMAC3/Chan0
		 */
		tl4 = ((vnic - 4) * 8) + 512;
		tl3 = tl4 / 4;
		vnic_pf_reg_write(pf, NIC_PF_QSET_0_127_SQ_0_7_CFG2 | 
					(vnic << VNIC_QS_ID_SHIFT), tl4);
		vnic_pf_reg_write(pf, NIC_PF_TL4_0_1023_CFG | 
					(tl4 << 3), (vnic << 27) | (0 << 24));
		vnic_pf_reg_write(pf, NIC_PF_TL4A_0_255_CFG | (tl3 << 3), tl3);
		vnic_pf_reg_write(pf, NIC_PF_TL3_0_255_CHAN | 
			(tl3 << 3), (bgx << 7) | ((vnic - 4) << 4) | (0 << 0));
	}
}

static void vnic_init_hw (struct vnic_pf *pf)
{
	int i;

	/* Reset NIC, incase if driver is repeatedly inserted and removed */
	vnic_pf_reg_write (pf, NIC_PF_SOFT_RESET, 1);

	/* Enable NIC HW block */
	vnic_pf_reg_write (pf, NIC_PF_CFG, 1);

	/* Disable TNS mode, no TNS support in simulator */
	vnic_pf_reg_write (pf, NIC_PF_INTF_0_1_SEND_CFG, 0); 
	vnic_pf_reg_write (pf, NIC_PF_INTF_0_1_SEND_CFG | (1 << 8), 0);
	
	/* 
	 * Simulator doesn't support padding, disable min packet check.
	 * Max pkt size - 1536.
	 * Enable L2 length err check.
	 * Disable TNS receive header for now.
	 */
	for (i = 0; i < VNIC_MAX_PKIND; i++) 
		vnic_pf_reg_write (pf, NIC_PF_PKIND_0_15_CFG | (i << 3), 0x206000000);

	vnic_channel_cfg(pf);
}

static irqreturn_t vnic_intr_handler (int irq, void *vnic_irq) 
{
	int vf;
	uint64_t intr;
	struct vnic *vnic = (struct vnic *) vnic_irq;

	intr = vnic_get_mbx_intr_status(vnic->pf, 0); /* Mbox 0 */
	//pr_err("PF MSIX interrupt 0x%lx\n", intr);
	for (vf = 0; vf < vnic->pf->num_vf_en; vf++) {
		if (intr & (1 << vf)) {
			//pr_err("Intr from VF %d\n", vf);
			vnic_handle_mbx_intr(vnic->pf, vf);
			vnic_clear_mbx_intr(vnic->pf, vf);
		}
	}	
	
	return IRQ_HANDLED;
}

static int vnic_enable_msix (struct vnic *vnic)
{
	int i, ret;
	struct vnic_pf *pf = vnic->pf;

	pf->num_vec = VNIC_PF_MSIX_VECTORS;

	for (i = 0; i < pf->num_vec; i++) {
		pf->msix_entries[i].entry = i;
	}

	ret = pci_enable_msix(vnic->pdev, pf->msix_entries, pf->num_vec);
	if (ret < 0) {
		dev_err(&vnic->pdev->dev, 
			"Request for #%d msix vectors failed\n", pf->num_vec);
		return 0;
	} else if (ret > 0) {
		dev_err(&vnic->pdev->dev, 
			"Request for #%d msix vectors failed, requesting #%d\n", 
			pf->num_vec, ret);

		pf->num_vec = ret;
		ret = pci_enable_msix(vnic->pdev, pf->msix_entries, pf->num_vec);
		if (ret) { 
			dev_warn(&vnic->pdev->dev, "Request for msix vectors failed\n");
			return 0;
		}
	}
	
	pf->msix_enabled = 1;
	return 1;
}

static void vnic_disable_msix (struct vnic *vnic)
{
	struct vnic_pf *pf = vnic->pf;

	if (pf->msix_enabled) {
		pci_disable_msix(vnic->pdev);
		pf->msix_enabled = 0;
		pf->num_vec = 0;
	}
}

static int vnic_register_interrupts (struct vnic *vnic)
{
	int irq, free, ret = 0;
	struct vnic_pf *pf = vnic->pf;

	/* Enable MSI-X */
	if (!vnic_enable_msix(vnic))
		return 1;

	/* Register interrupts */
	/* For now skip ECC interrupts, register only Mbox interrupts */
	for (irq = 8; irq < pf->num_vec; irq++) {
		ret = request_irq (pf->msix_entries[irq].vector, 
				vnic_intr_handler, 0 , "VNIC PF", vnic);
		if (ret)
			break;
	}

	if (ret) { 
		dev_err(&vnic->pdev->dev, "Request irq failed\n");
		for (free = 0; free < irq; free++)
			free_irq (pf->msix_entries[free].vector, vnic);
		return 1;
	}
	
	/* Enable mailbox interrupt */
	vnic_enable_mbx_intr(vnic->pf);
	
	return 0;
}

static void vnic_unregister_interrupts (struct vnic *vnic)
{
	int irq;
	struct vnic_pf *pf = vnic->pf;

	/* Free registered interrupts */
	for (irq = 0; irq < pf->num_vec; irq++)
		free_irq (pf->msix_entries[irq].vector, vnic);

	/* Disable MSI-X */
	vnic_disable_msix(vnic);
}

void vnic_set_sriov_enable (struct vnic_pf *pf)
{
	pf->flags |= VNIC_SRIOV_ENABLED;
}

void vnic_clear_sriov_enable (struct vnic_pf *pf)
{
	pf->flags &= ~VNIC_SRIOV_ENABLED;
}

bool vnic_is_sriov_enabled (struct vnic_pf *pf)
{
	if (pf->flags & VNIC_SRIOV_ENABLED)
		return true;
	return false;
}

int vnic_sriov_configure(struct pci_dev *pdev, int num_vfs_requested)
{
        struct net_device *netdev = pci_get_drvdata(pdev);
	struct vnic *vnic = netdev_priv(netdev);
	int err;

	if (vnic->pf->num_vf_en == num_vfs_requested)
		return num_vfs_requested;

	if (vnic_is_sriov_enabled(vnic->pf)) {
		pci_disable_sriov(pdev);
		vnic_clear_sriov_enable(vnic->pf);
	}

	vnic->pf->num_vf_en = 0;
	if (num_vfs_requested > MAX_NUM_VFS_SUPPORTED) 
		return -EPERM;
	
	if (num_vfs_requested) {
		if ((err = pci_enable_sriov (pdev, num_vfs_requested))) {
			dev_err(&pdev->dev, "SRIOV, Failed to enable %d VFs\n", num_vfs_requested);
			return err;
		}
		vnic->pf->num_vf_en = num_vfs_requested;
		vnic_set_sriov_enable(vnic->pf);
	}
	
	return num_vfs_requested;
}

static int  vnic_sriov_init (struct pci_dev *pdev, struct vnic *vnic) 
{
	int    pos = 0;
	struct vnic_pf *pf = vnic->pf;
	
        pos = pci_find_ext_capability(pdev, PCI_EXT_CAP_ID_SRIOV);
	if (!pos) {
		dev_err(&pdev->dev, "SRIOV capability is not found in PCIe config space\n");
                return 0;
	}

	pci_read_config_word(pdev, (pos + PCI_SRIOV_TOTAL_VF), &pf->total_vf_cnt);
	if (pf->total_vf_cnt < DEFAULT_NUM_VF_ENABLED) 
		pf->num_vf_en = pf->total_vf_cnt;
	else 
		pf->num_vf_en = DEFAULT_NUM_VF_ENABLED;

	if(pf->total_vf_cnt && pci_enable_sriov(pdev, pf->num_vf_en)) {
		dev_err(&pdev->dev, "SRIOV enable failed, num VF is %d\n", pf->num_vf_en);
		pf->num_vf_en = 0;
		return 0;
	}
	dev_info(&pdev->dev, "SRIOV enabled, numer of VF available %d\n", pf->num_vf_en);

	vnic_set_sriov_enable(vnic->pf);
	return 1;
}

static int vnic_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
        struct device *dev = &pdev->dev;
        struct net_device *netdev;
	struct vnic *vnic;
	int    err;

        netdev = alloc_etherdev(sizeof(struct vnic));
        if (!netdev)
                return -ENOMEM;

        pci_set_drvdata(pdev, netdev);

        SET_NETDEV_DEV(netdev, &pdev->dev);

        vnic = netdev_priv(netdev);
        vnic->netdev = netdev;
        vnic->pdev = pdev;
	vnic->pf = kzalloc (sizeof (struct vnic_pf), GFP_ATOMIC);
	vnic->pf->pdev = pdev;

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
	vnic->pf->reg_base = (uint64_t) pci_ioremap_bar(pdev, PCI_CFG_REG_BAR_NUM);
        if (!vnic->pf->reg_base) {
                dev_err(dev, "PF: Cannot map config register space, aborting\n");
                err = -ENOMEM;
                goto err_release_regions;
        }       

	/* Initialize hardware */
	vnic_init_hw(vnic->pf);

	/* Configure SRIOV */
	if (!vnic_sriov_init(pdev, vnic)) {
		goto err_unmap_resources;
	}

	/* Register interrupts */
	if (vnic_register_interrupts(vnic)) {
		goto err_unmap_resources;
	}

	goto exit;

err_unmap_resources:
        if (vnic->pf->reg_base)
                iounmap((void *)vnic->pf->reg_base);
err_release_regions:
	pci_release_regions(pdev);
err_disable_device:
	pci_disable_device(pdev);
exit:
	return err;
}

static void vnic_remove(struct pci_dev *pdev)
{
        struct net_device *netdev = pci_get_drvdata(pdev);
	struct vnic *vnic;

	if (!netdev)
		return;
	
	vnic = netdev_priv(netdev);
	
	vnic_unregister_interrupts(vnic);

	if (vnic_is_sriov_enabled(vnic->pf)) {
		pci_disable_sriov(pdev);
	}

	pci_set_drvdata(pdev, NULL);

        if (vnic->pf->reg_base)
                iounmap((void *)vnic->pf->reg_base);
	kfree(vnic->pf);

	pci_release_regions(pdev);
	pci_disable_device(pdev);
	free_netdev(netdev);
}

static struct pci_driver vnic_driver = {
        .name = DRV_NAME,
        .id_table = vnic_id_table,
        .probe = vnic_probe,
        .remove = vnic_remove,
        .sriov_configure = vnic_sriov_configure,
};

static int __init vnic_init_module(void)
{
        pr_info("%s, ver %s\n", DRV_NAME, DRV_VERSION);

        return pci_register_driver(&vnic_driver);
}

static void __exit vnic_cleanup_module(void)
{
        pci_unregister_driver(&vnic_driver);
}

module_init(vnic_init_module);
module_exit(vnic_cleanup_module);

