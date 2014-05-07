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

#define DRV_NAME  	"vnic-vf"
#define DRV_VERSION  	"1.0"

/* Supported devices */
static DEFINE_PCI_DEVICE_TABLE(vnic_id_table) = {
        { PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, PCI_DEVICE_ID_8XXX_VNIC_VF) },
        { 0, }  /* end of table */
};

MODULE_AUTHOR("Cavium Inc");
MODULE_DESCRIPTION("Cavium 8xxx VNIC VF Network Driver");
MODULE_LICENSE("GPL");
MODULE_VERSION(DRV_VERSION);
MODULE_DEVICE_TABLE(pci, vnic_id_table);

static int vnic_enable_msix (struct vnic *vnic);

static void vnic_dump_packet (struct sk_buff *skb)
{
#ifdef VNIC_DUMP_PACKET
	int i;

	for (i = 0; i < skb->len; i++) {
		if (!(i % 16))
			printk("\n");
		printk("%02x ", (u_char)skb->data[i]);
	}
#endif
}

/* 
 * VF -> PF mailbox communication 
 */
static bool pf_ready_to_rcv_msg = false;
static bool vf_pf_msg_delivered = false;

struct vnic_mbx *vnic_get_mbx (void)
{
	return (struct vnic_mbx *)kzalloc(sizeof(struct vnic_mbx), GFP_KERNEL);
} 

static void vnic_enable_mbx_intr (struct vnic *vnic)
{
	vnic_enable_intr (vnic, VNIC_INTR_MBOX, 0);
}

static void vnic_disable_mbx_intr (struct vnic *vnic)
{
	vnic_disable_intr (vnic, VNIC_INTR_MBOX, 0);
}

void vnic_send_msg_to_pf (struct vnic_vf *vf, struct vnic_mbx *mbx)
{
	int i, timeout = 5000, sleep = 10;
	uint64_t *msg;
	uint64_t mbx_addr;

	vf_pf_msg_delivered = false;
	mbx->mbx_trigger_intr = 1;
	msg = (uint64_t *)mbx;
	mbx_addr = vf->reg_base + NIC_VF_0_127_PF_MAILBOX_0_7;
	for (i = 0; i < VNIC_PF_VF_MAILBOX_SIZE; i++) {
		writeq_relaxed(*(msg + i), (void *)(mbx_addr + (i * 8)));
	}
	
	/* Wait for previous message to be acked, timeout 5sec */
	while (!vf_pf_msg_delivered) {
		msleep(sleep);
		if (vf_pf_msg_delivered)
			break;
		else 
			timeout -= sleep;
		if (!timeout) {
			dev_err(&vf->pdev->dev, 
				"PF didn't ack mailbox msg from VF%d\n",
								vf->vnic_id);
			return;
		}
	}
}

static int vnic_check_pf_ready (struct vnic_vf *vf)
{
	int timeout = 5000, sleep = 20;
	uint64_t mbx_addr = NIC_VF_0_127_PF_MAILBOX_0_7;

	vnic_vf_reg_write(vf, mbx_addr, VNIC_PF_VF_MSG_READY);

	mbx_addr += (VNIC_PF_VF_MAILBOX_SIZE - 1) * 8;
	vnic_vf_reg_write(vf, mbx_addr, 1ULL);

	while (!pf_ready_to_rcv_msg) {
		msleep(sleep);
		if (pf_ready_to_rcv_msg)
			break;
		else 
			timeout -= sleep;
		if (!timeout) {
			dev_err(&vf->pdev->dev, 
				"PF didn't respond to mailbox msg from VF%d\n"
								,vf->vnic_id);
			return 0;
		}
	}
	return 1;
}

static void  vnic_handle_mbx_intr (struct vnic *vnic) 
{
	int i;
	struct vnic_vf *vf = vnic->vf;
	struct vnic_mbx *mbx;
	uint64_t *mbx_data;
	uint64_t mbx_addr;

	mbx_addr = NIC_VF_0_127_PF_MAILBOX_0_7;

	mbx_data = kzalloc(sizeof(struct vnic_mbx), GFP_KERNEL);
	mbx = (struct vnic_mbx *) mbx_data;

	for (i = 0; i < VNIC_PF_VF_MAILBOX_SIZE; i++) {
		*mbx_data = vnic_vf_reg_read(vf, mbx_addr + (i * VNIC_PF_VF_MAILBOX_SIZE));
		mbx_data++;
	}

	switch (mbx->msg & 0xFF) {
	case VNIC_PF_VF_MSG_ACK:
		vf_pf_msg_delivered = true;
		break;
	case VNIC_PF_VF_MSG_READY:
		pf_ready_to_rcv_msg = true;
		break;
	default:
		dev_err(&vf->pdev->dev, "Invalid message from PF, msg 0x%llx\n", 
								mbx->msg);
		break;
	}
	vnic_clear_intr (vnic, VNIC_INTR_MBOX, 0);
	kfree(mbx);
}

static void vnic_hw_set_mac_addr (struct vnic *vnic, struct net_device *netdev)
{
	int i;
	struct  vnic_mbx *mbx;
	
	
	mbx = vnic_get_mbx();
	mbx->msg = VNIC_PF_VF_MSG_SET_MAC;
	mbx->data.mac.vnic_id = vnic->vf->vnic_id;
	for (i = 0; i < ETH_ALEN; i++) {
		mbx->data.mac.addr = (mbx->data.mac.addr << 8) | netdev->dev_addr[i];
	}
	vnic_send_msg_to_pf(vnic->vf, mbx);
}

static int vnic_is_link_active(struct vnic *vnic) 
{
	return 1;
}

static int vnic_init_resources(struct vnic *vnic)
{
	int err;
	struct vnic_vf *vf = vnic->vf;

	vf->num_qs = 1; 
	vf->vf_mtu = vnic->mtu;
	vf->pdev = vnic->pdev;

	/* Initialize queues and HW for data transfer */
	if ((err = vnic_vf_config_data_transfer(vnic, vf, true))) {
		dev_err(&vnic->pdev->dev, 
			"Failed to allocate/configure VF's QSet resources, err %d\n", err);
		return err;
	}
	/* Enable Qset */	
	vnic_qset_config(vf, vf->qs, true);
	
	return 0;
}

static void vnic_free_skb (struct vnic *vnic, struct sk_buff *skb) 
{
	int i;

	if (!skb_shinfo(skb)->nr_frags) 
		goto free_skb;

	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		const struct skb_frag_struct *frag;
		frag = &skb_shinfo(skb)->frags[i];
		pci_unmap_single(vnic->pdev, (dma_addr_t)skb_frag_address(frag), 
						skb_frag_size(frag), PCI_DMA_TODEVICE);
	}
free_skb:
	pci_unmap_single(vnic->pdev, (dma_addr_t)skb->data, skb_headlen(skb), PCI_DMA_TODEVICE);
	dev_kfree_skb_any(skb);
}

static void vnic_snd_pkt_handler (struct net_device *netdev, 
				  void *cq_desc, int cqe_type)
{
	int i;
	struct sk_buff *skb = NULL;
	struct cqe_send_t *cqe_tx;
	struct vnic *vnic = netdev_priv(netdev);
	struct vnic_vf *vf = vnic->vf;
	struct vnic_snd_queue *sq;
	struct sq_hdr_subdesc *hdr, *desc;
	struct sq_gather_subdesc *gather;

	cqe_tx = (struct cqe_send_t *)cq_desc;
	sq = &vf->qs->sq[cqe_tx->sq_idx];
	
	hdr  = (struct sq_hdr_subdesc *)(sq->desc_mem.base + 
			(cqe_tx->sqe_ptr * SND_QUEUE_DESC_SIZE));

	//netdev_dbg(netdev, "%s Qset #%d SQ #%d SQ ptr #%d Subdesc count %d\n",
	//pr_err("%s Qset #%d SQ #%d SQ ptr #%d Subdesc count %d\n",
	//		 	__FUNCTION__, cqe_tx->sq_qs, cqe_tx->sq_idx, 
	//				cqe_tx->sqe_ptr, hdr->subdesc_cnt);

	for (i = 1; i <= hdr->subdesc_cnt; i++) {
		desc = (struct sq_hdr_subdesc *)(sq->desc_mem.base + 
			((cqe_tx->sqe_ptr + i) * SND_QUEUE_DESC_SIZE));

		switch (desc->subdesc_type) {
		case SQ_DESC_TYPE_GATHER:
			gather = (struct sq_gather_subdesc *)(sq->desc_mem.base +
						((cqe_tx->sqe_ptr + i) *
						SND_QUEUE_DESC_SIZE));

			if (skb)
				continue;

			skb = (struct sk_buff *)sq->skbuff[cqe_tx->sqe_ptr + i];
			atomic64_add(1, (atomic64_t *)&netdev->stats.tx_packets);
			atomic64_add(gather->size, (atomic64_t *)&netdev->stats.tx_bytes);
			vnic_free_skb(vnic, skb);
		break;
		default:
		break;
		}
	}
	vnic_put_sq_desc(vf->qs, cqe_tx->sq_idx, hdr->subdesc_cnt + 1);
}

static void vnic_rcv_pkt_handler (struct net_device *netdev, 
				  void *cq_desc, int cqe_type)
{
	struct sk_buff *skb;
	struct vnic *vnic = netdev_priv(netdev);
	struct vnic_vf *vf = vnic->vf;

	if (!((cqe_type == CQE_TYPE_RX) || (cqe_type == CQE_TYPE_RX_SPLIT) || 
						(cqe_type == CQE_TYPE_RX_TCP))) {
		atomic64_add(1, (atomic64_t *)&netdev->stats.rx_dropped);
		dev_kfree_skb_any(skb);
		return;
	}

	/* Check for errors */
	if (vnic_cq_check_errs(vnic, cq_desc)) {
		atomic64_add(1, (atomic64_t *)&netdev->stats.rx_errors);
		return;
	}
			
	skb = vnic_get_rcv_skb(vnic, vf->qs, cq_desc);
	if (!skb) {
		pr_err("Packet not received\n");
		return;
	}
#ifdef VNIC_RX_CHKSUM_SUPPORTED
	skb->ip_summed = CHECKSUM_UNNECESSARY;
#endif

	vnic_dump_packet(skb);

	/* Update stats */
	atomic64_add(1, (atomic64_t *)&netdev->stats.rx_packets);
	atomic64_add(skb->len, (atomic64_t *)&netdev->stats.rx_bytes);

	skb->protocol = eth_type_trans(skb, netdev);
#ifdef  VNIC_NAPI_ENABLE
	netif_receive_skb(skb);
#else
	netif_rx(skb);
#endif
}

static int vnic_cq_intr_handler (struct net_device *netdev, uint8_t cq_qnum, 
							bool napi, int budget)
{
	int processed_cqe = 0, work_done = 0;
	int cqe_count, cqe_head;
	struct vnic *vnic = netdev_priv(netdev);
	struct vnic_vf *vf = vnic->vf;
	struct vnic_queue_set *qs = vf->qs;
	struct vnic_cmp_queue *cq = &qs->cq[cq_qnum];
	struct cqe_rx_t *cq_desc;

	/* Get no of valid CQ entries to process */
	cqe_count = vnic_queue_reg_read(vf, NIC_QSET_0_127_CQ_0_7_STATUS, cq_qnum);
	cqe_count &= 0xFFFF;
	if (!cqe_count)
		return 0;

	/* Get head of the valid CQ entries */
	cqe_head = vnic_qset_reg_read(vf, NIC_QSET_0_127_CQ_0_7_HEAD) >> 9;
	cqe_head &= 0xFFFF;

	//pr_err("%s cqe_count %d cqe_head %d\n", __FUNCTION__, cqe_count, cqe_head);
	while (processed_cqe < cqe_count) {	
		/* Get the CQ descriptor */
		cq_desc = (struct cqe_rx_t *)(cq->desc_mem.base + 
				(cqe_head * CMP_QUEUE_DESC_SIZE));
		if (napi && (work_done >= budget) && 
			(cq_desc->cqe_type != CQE_TYPE_SEND)) {
			break;
		} 
		//pr_err("cq_desc->cqe_type %d\n", cq_desc->cqe_type);
		switch (cq_desc->cqe_type) {
		case CQE_TYPE_RX:
			vnic_rcv_pkt_handler(netdev, cq_desc, CQE_TYPE_RX);
			work_done++;
		break;
		case CQE_TYPE_SEND:
			vnic_snd_pkt_handler(netdev, cq_desc, CQE_TYPE_SEND);
		break;
		}
		processed_cqe++;
		cqe_head++;
		cqe_head &= (cq->desc_mem.q_len - 1);
	}
	//pr_err("%s processed_cqe %d work_done %d budget %d\n", 
	//		__FUNCTION__, processed_cqe, work_done, budget);
	/* Dequeue CQE */
	vnic_queue_reg_write(vf, NIC_QSET_0_127_CQ_0_7_DOOR,  
					cq_qnum, processed_cqe);
	return work_done;
}

#ifdef  VNIC_NAPI_ENABLE
static int vnic_poll (struct napi_struct *napi, int budget)
{
	int  work_done = 0;
	struct net_device *netdev = napi->dev;
	struct vnic *vnic = netdev_priv(netdev);
	struct vnic_cq_poll *cq = container_of(napi, struct vnic_cq_poll, napi);

	work_done = vnic_cq_intr_handler (netdev, cq->cq_idx, true, budget);
	
	if (work_done < budget) {
		/* Slow packet rate, exit polling */
		napi_complete(napi);
		/* Re-enable interrupts */
		vnic_enable_intr (vnic, VNIC_INTR_CQ, cq->cq_idx);
	}
		
	return work_done;
}
#endif

/*
 * Qset error interrupt handler
 * As of now only 'CQ full' errors are only handled
 */
void vnic_handle_qs_err (unsigned long data)
{
	struct vnic *vnic = (struct vnic *)data;
	struct vnic_vf *vf = vnic->vf;
	struct vnic_queue_set *qs = vf->qs;
	int cq_idx;
	uint64_t cq_status, cq_ena;
	
	for (cq_idx = 0; cq_idx < qs->cq_cnt; cq_idx++) {
		cq_status = vnic_queue_reg_read(vf, NIC_QSET_0_127_CQ_0_7_STATUS, cq_idx);
		if (!(cq_status & CQ_WR_FULL))
			continue;
		vnic_cq_intr_handler(vnic->netdev, cq_idx, false, 0); 
                /* Re-enable completion queue */
		cq_ena = vnic_queue_reg_read(vf, NIC_QSET_0_127_CQ_0_7_CFG, cq_idx);
		cq_ena |= (1ULL << 42);
                vnic_queue_reg_write(vf, NIC_QSET_0_127_CQ_0_7_CFG, cq_idx, cq_ena);
	}
	/* Re-enable Qset error interrupt */
	vnic_enable_intr (vnic, VNIC_INTR_QS_ERR, 0);
}

static irqreturn_t vnic_misc_intr_handler (int irq, void *vnic_irq) 
{
	struct vnic *vnic = (struct vnic *) vnic_irq;

	vnic_handle_mbx_intr (vnic);

	return IRQ_HANDLED;
}

static irqreturn_t vnic_intr_handler (int irq, void *vnic_irq) 
{
	uint64_t qidx, intr;
	uint64_t cq_intr, rbdr_intr, qs_err_intr;
	struct vnic *vnic = (struct vnic *) vnic_irq;
	struct vnic_queue_set *qs = vnic->vf->qs;

	intr = vnic_qset_reg_read(vnic->vf, NIC_VF_0_127_INT);
	//pr_err("%s intr status 0x%llx\n",__FUNCTION__, intr);

	cq_intr = (intr & VNIC_INTR_CQ_MASK) >> VNIC_INTR_CQ_SHIFT;
	qs_err_intr = intr & VNIC_INTR_QS_ERR_MASK;
	if (qs_err_intr) {
		/* Disable Qset err interrupt and schedule softirq */
		vnic_disable_intr (vnic, VNIC_INTR_QS_ERR, 0);
		tasklet_hi_schedule(&vnic->vf->qs_err_task);
	}

#ifdef  VNIC_NAPI_ENABLE 
	{
		struct vnic_cq_poll *cq_poll = NULL;
		/* Disable interrupts and start polling */
		for (qidx = 0; qidx < qs->cq_cnt; qidx++) {
			if (!(cq_intr & (1 << qidx)))
				continue;
			if (!vnic_is_intr_enabled(vnic, VNIC_INTR_CQ, qidx))
				continue;
			vnic_disable_intr (vnic, VNIC_INTR_CQ, qidx);
			cq_poll = vnic->vf->napi[qidx];
			/* Schedule NAPI */
			napi_schedule(&cq_poll->napi);	
		}
	}
#else
	for (qidx = 0; qidx < qs->cq_cnt; qidx++) {
		if (cq_intr & (1 << qidx))
			vnic_cq_intr_handler (vnic->netdev, qidx, false, 0);
	}
#endif
	/* Handle RBDR interrupts */
	rbdr_intr = (intr & VNIC_INTR_RBDR_MASK) >> VNIC_INTR_RBDR_SHIFT;
	if (rbdr_intr) {
		/* Disable RBDR interrupt and schedule softirq */
		for (qidx = 0; qidx < qs->rbdr_cnt; qidx++)
			vnic_disable_intr (vnic, VNIC_INTR_RBDR, qidx);

		tasklet_schedule(&vnic->vf->rbdr_task);
	}
		
	/* Clear interrupts */
	vnic_qset_reg_write(vnic->vf, NIC_VF_0_127_INT, 
				(cq_intr << VNIC_INTR_CQ_SHIFT) | 
				(rbdr_intr << VNIC_INTR_RBDR_SHIFT)| 
				(qs_err_intr << VNIC_INTR_QS_ERR_SHIFT));
	return IRQ_HANDLED;
}

static int vnic_enable_msix (struct vnic *vnic)
{
	int i, ret, vec;
	struct vnic_vf *vf = vnic->vf;
	struct vnic_queue_set *qs = vf->qs;

	vf->num_vec = VNIC_VF_MSIX_VECTORS;
	vec = qs->cq_cnt + qs->rbdr_cnt + qs->sq_cnt;
	vec = VNIC_VF_MSIX_VECTORS;
	if (vec > VNIC_VF_MSIX_VECTORS)
		vf->num_vec = vec;

	for (i = 0; i < vf->num_vec; i++) {
		vf->msix_entries[i].entry = i;
	}

	ret = pci_enable_msix(vnic->pdev, vf->msix_entries, vf->num_vec);
	if (ret < 0) {
		dev_err(&vnic->pdev->dev, 
			"Request for #%d msix vectors failed\n", vf->num_vec);
		return 0;
	} else if (ret > 0) {
		dev_err(&vnic->pdev->dev, 
			"Request for #%d msix vectors failed, requesting #%d\n", 
			vf->num_vec, ret);

		vf->num_vec = ret;
		ret = pci_enable_msix(vnic->pdev, vf->msix_entries, vf->num_vec);
		if (ret) { 
			dev_warn(&vnic->pdev->dev, "Request for msix vectors failed\n");
			return 0;
		}
	}
	vf->msix_enabled = 1;
	return 1;
}

static void vnic_disable_msix (struct vnic *vnic)
{
	struct vnic_vf *vf = vnic->vf;

	if (vf->msix_enabled) {
		pci_disable_msix(vnic->pdev);
		vf->msix_enabled = 0;
		vf->num_vec = 0;
	}
}

static int vnic_register_misc_interrupt (struct vnic *vnic)
{
	int  ret = 0;
	int irq = VNIC_VF_MISC_INTR_ID;
	struct vnic_vf *vf = vnic->vf;

	/* Enable MSI-X */
	if (!vnic_enable_msix(vnic))
		return 1;

	sprintf(vf->irq_name[irq], "%s%d Mbox", "VNIC", vf->vnic_id);
	/* Register Misc interrupt */
	ret = request_irq(vf->msix_entries[irq].vector, vnic_misc_intr_handler,
						0, vf->irq_name[irq], vnic);

	if(ret)
		return 1;
	vf->irq_allocated[irq] = 1;

	/* Enable mailbox interrupt */
	vnic_enable_mbx_intr(vnic);

	/* Check if PF is ready to receive mailbox messages */
	if (!vnic_check_pf_ready(vnic->vf))
		return 1;

	return 0;
}

static int vnic_register_interrupts (struct vnic *vnic)
{
	int irq, free, ret = 0;
	struct vnic_vf *vf = vnic->vf;

	for_each_cq_irq(irq) 
		sprintf(vf->irq_name[irq], "%s%d CQ%d", "VNIC", 
						vf->vnic_id, irq);

	for_each_sq_irq(irq) 
		sprintf(vf->irq_name[irq], "%s%d SQ%d", "VNIC", 
			vf->vnic_id, irq - VNIC_VF_SQ_INTR_ID);

	for_each_rbdr_irq(irq) 
		sprintf(vf->irq_name[irq], "%s%d RBDR%d", "VNIC", 
			vf->vnic_id, irq - VNIC_VF_RBDR_INTR_ID);

	/* Register all interrupts except mailbox */
	for (irq = 0; irq < VNIC_VF_MISC_INTR_ID; irq++) {
		if ((ret = request_irq (vf->msix_entries[irq].vector, 
				vnic_intr_handler, 0 , vf->irq_name[irq], vnic)))
			break;
		vf->irq_allocated[irq] = 1;
	}

	sprintf(vf->irq_name[VNIC_VF_QS_ERR_INTR_ID], 
				"%s%d Qset error", "VNIC", vf->vnic_id);
	if (!ret) {
		if (!(ret = request_irq (vf->msix_entries[VNIC_VF_QS_ERR_INTR_ID].vector, 
				vnic_intr_handler, 0 , vf->irq_name[VNIC_VF_QS_ERR_INTR_ID], vnic)))
			vf->irq_allocated[VNIC_VF_QS_ERR_INTR_ID] = 1;
	}

	if (ret) { 
		dev_err(&vnic->pdev->dev, "Request irq failed\n");
		for (free = 0; free < irq; free++)
			free_irq (vf->msix_entries[free].vector, vnic);
		return 1;
	}

	return 0;
}

static void vnic_unregister_interrupts (struct vnic *vnic)
{
	int irq;
	struct vnic_vf *vf = vnic->vf;

	/* Free registered interrupts */
	for (irq = 0; irq < vf->num_vec; irq++) {
		if (vf->irq_allocated[irq])
			free_irq (vf->msix_entries[irq].vector, vnic);
		vf->irq_allocated[irq] = 0;
	}

	/* Disable MSI-X */
	vnic_disable_msix(vnic);
}

static void vnic_update_tx_stats(struct vnic *vnic, struct sk_buff *skb)
{
	return;
}

static netdev_tx_t vnic_xmit(struct sk_buff *skb, struct net_device *netdev)
{
	struct vnic *vnic = netdev_priv(netdev);

	vnic_sq_append_skb(vnic, skb);

	vnic_update_tx_stats(vnic, skb);

	return NETDEV_TX_OK;
}

static int vnic_stop(struct net_device *netdev)
{
	int qidx;
        struct vnic *vnic = netdev_priv(netdev);
	struct vnic_vf *vf = vnic->vf;
	struct vnic_queue_set *qs = vf->qs;

        netif_carrier_off(netdev);
        netif_tx_disable(netdev);

	/* Disable HW Qset, to stop receiving packets */
	vnic_qset_config(vf, qs, false);

	/* disable mailbox interrupt */
	vnic_disable_mbx_intr(vnic);

	/* Disable interrupts */
	for (qidx = 0; qidx < qs->cq_cnt; qidx++)
		vnic_disable_intr (vnic, VNIC_INTR_CQ, qidx);
	for (qidx = 0; qidx < qs->rbdr_cnt; qidx++)
		vnic_disable_intr (vnic, VNIC_INTR_RBDR, qidx);
	vnic_disable_intr (vnic, VNIC_INTR_QS_ERR, 0);

	tasklet_kill(&vf->rbdr_task);
	tasklet_kill(&vf->qs_err_task);

	vnic_unregister_interrupts(vnic);
#ifdef VNIC_NAPI_ENABLE
	for (qidx = 0; qidx < vf->qs->cq_cnt; qidx++) {
		napi_disable(&vf->napi[qidx]->napi);
		netif_napi_del(&vf->napi[qidx]->napi);
		kfree(vf->napi[qidx]);
		vf->napi[qidx] = NULL;
	}
#endif
	/* Free resources */ 
	vnic_vf_config_data_transfer(vnic, vnic->vf, false);

	/* Free Qset */
	kfree(qs);	

	return 0;
}

static int vnic_open(struct net_device *netdev)
{
	int err, qidx;
        struct vnic *vnic = netdev_priv(netdev);
	struct vnic_vf *vf = vnic->vf;
	struct vnic_queue_set *qs;
	struct vnic_cq_poll *cq_poll = NULL;

	vnic->mtu = netdev->mtu;
	
	if ((err = vnic_register_misc_interrupt(vnic))) {
		vnic_stop(netdev);
		return -EIO;
	}

	if ((err = vnic_init_resources(vnic)))
		return err;

	if ((err = vnic_register_interrupts(vnic))) {
		vnic_stop(netdev);
		return -EIO;
	}

	qs = vf->qs;
	/* Enable interrupts */
	/* Enable completion queue interrupt */
	for (qidx = 0; qidx < qs->cq_cnt; qidx++)
		vnic_enable_intr (vnic, VNIC_INTR_CQ, qidx);

	/* Init RBDR tasklet and enable RBDR threshold interrupt */
	tasklet_init(&vf->rbdr_task, vnic_refill_rbdr, (unsigned long) vnic);

	for (qidx = 0; qidx < qs->rbdr_cnt; qidx++)
		vnic_enable_intr (vnic, VNIC_INTR_RBDR, qidx);

	/* Init tasklet for handling Qset err interrupt */
	tasklet_init(&vf->qs_err_task, vnic_handle_qs_err, (unsigned long) vnic);

	/* Enable Qset err interrupt */
	vnic_enable_intr (vnic, VNIC_INTR_QS_ERR, 0);

	if (is_zero_ether_addr(netdev->dev_addr))
		eth_hw_addr_random(netdev);

	vnic_hw_set_mac_addr(vnic, netdev);

	if (vnic_is_link_active(vnic)) {
		netif_carrier_on(netdev);
		netif_wake_queue(netdev);	
	}

#ifdef VNIC_NAPI_ENABLE
	for (qidx = 0; qidx < qs->cq_cnt; qidx++) {
		cq_poll = NULL;
		cq_poll = kzalloc(sizeof(struct vnic_cq_poll), GFP_KERNEL);
		if (!cq_poll)
			goto napi_del;
		cq_poll->cq_idx = qidx;
		netif_napi_add(netdev, &cq_poll->napi, vnic_poll, NAPI_POLL_WEIGHT);
		napi_enable(&cq_poll->napi);
		vf->napi[qidx] = cq_poll;
	}
	goto no_err;
napi_del:
	while(qidx) {
		qidx--;
		cq_poll = vnic->vf->napi[qidx];
		napi_disable(&cq_poll->napi);
		netif_napi_del(&cq_poll->napi);
		kfree(cq_poll);
		vnic->vf->napi[qidx] = NULL;
	}
	return -ENOMEM;
no_err:
#endif
	return 0;
}

static int vnic_change_mtu(struct net_device *netdev, int new_mtu)
{
	if (new_mtu > VNIC_MAX_MTU_SUPPORTED)
		return -EINVAL;	

	if (new_mtu < VNIC_MIN_MTU_SUPPORTED)
		return -EINVAL;	

	netdev->mtu = new_mtu;
	return 0;
}

static int vnic_set_mac_address(struct net_device *netdev, void *p)
{
	struct sockaddr *addr = p;
        struct vnic *vnic = netdev_priv(netdev);

	if (!is_valid_ether_addr(addr->sa_data))
		return -EADDRNOTAVAIL;

	memcpy(netdev->dev_addr, addr->sa_data, netdev->addr_len);
	if (netif_running(netdev)) 
		vnic_hw_set_mac_addr (vnic, netdev);

	return 0;
}

static const struct net_device_ops vnic_netdev_ops = {
        .ndo_open               = vnic_open,
        .ndo_stop               = vnic_stop,
        .ndo_start_xmit         = vnic_xmit,
        .ndo_change_mtu         = vnic_change_mtu,
        .ndo_set_mac_address    = vnic_set_mac_address,
#if 0
        .ndo_get_stats64        = vnic_get_stats,
        .ndo_validate_addr      = eth_validate_addr,
        .ndo_set_rx_mode        = vnic_set_rx_mode,
        .ndo_vlan_rx_add_vid    = vnic_vlan_rx_add_vid,
        .ndo_vlan_rx_kill_vid   = vnic_vlan_rx_kill_vid,
        .ndo_tx_timeout         = vnic_tx_timeout,
#endif
};

static int vnic_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
        struct device *dev = &pdev->dev;
        struct net_device *netdev;
	struct vnic *vnic;
	int    err;

        netdev = alloc_etherdev(sizeof(struct vnic)); /* Consider using alloc_etherdev_mq for multiple send queues */
        if (!netdev)
                return -ENOMEM;

        pci_set_drvdata(pdev, netdev);

        SET_NETDEV_DEV(netdev, &pdev->dev);

        vnic = netdev_priv(netdev);
        vnic->netdev = netdev;
        vnic->pdev = pdev;
	vnic->vf = kzalloc (sizeof (struct vnic_vf), GFP_KERNEL);
	
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
			dev_err(dev, "unable to get 48-bit DMA for consistent allocations\n");
			goto err_release_regions;
		}
	} else {
		dev_err(dev, "Unable to get usable DMA configuration\n");
		goto err_release_regions;
	} 

	/* MAP VF's configuration registers */
	vnic->vf->reg_base = (uint64_t) pci_ioremap_bar(pdev, PCI_CFG_REG_BAR_NUM);
        if (!vnic->vf->reg_base) {
                dev_err(dev, "VF: Cannot map config register space, aborting\n");
                err = -ENOMEM;
                goto err_release_regions;
        }       

	/* Get this VF's number */
	vnic->vf->vnic_id = (pci_resource_start(pdev, PCI_CFG_REG_BAR_NUM) >> 21) & 0xFF;

	if (vnic->hw_flags & VNIC_RX_CSUM_ENABLE)
		netdev->hw_features |= NETIF_F_RXCSUM; 
	if (vnic->hw_flags & VNIC_TX_CSUM_ENABLE)
		netdev->hw_features |= NETIF_F_IP_CSUM; 
	if (vnic->hw_flags & VNIC_SG_ENABLE)
		netdev->hw_features |= NETIF_F_SG;
	if (vnic->hw_flags & VNIC_TSO_ENABLE)
		netdev->hw_features |= NETIF_F_TSO | NETIF_F_SG | NETIF_F_HW_CSUM;
	if (vnic->hw_flags & VNIC_LRO_ENABLE)
		netdev->hw_features |= NETIF_F_LRO; 

	netdev->netdev_ops = &vnic_netdev_ops;

	if ((err = register_netdev(netdev))) {
		dev_err(dev, "Failed to register netdevice\n");
		goto err_unmap_resources;
	}

	goto exit;

err_unmap_resources:
        if (vnic->vf->reg_base)
                iounmap((void *)vnic->vf->reg_base);
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
	unregister_netdev(netdev);

	pci_set_drvdata(pdev, NULL);

        if (vnic->vf->reg_base)
                iounmap((void *)vnic->vf->reg_base);
	kfree(vnic->vf);

	pci_release_regions(pdev);
	pci_disable_device(pdev);
	free_netdev(netdev);
}

static struct pci_driver vnic_driver = {
        .name = DRV_NAME,
        .id_table = vnic_id_table,
        .probe = vnic_probe,
        .remove = vnic_remove,
};

static int __init vnic_vf_init_module(void)
{
        pr_info("%s, ver %s\n", DRV_NAME, DRV_VERSION);

        return pci_register_driver(&vnic_driver);
}

static void __exit vnic_vf_cleanup_module(void)
{
        pci_unregister_driver(&vnic_driver);
}

module_init(vnic_vf_init_module);
module_exit(vnic_vf_cleanup_module);

