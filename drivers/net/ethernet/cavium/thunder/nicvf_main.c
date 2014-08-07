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
#include <linux/ip.h>
#include <net/tcp.h>

#include "nic.h"
#include "nic_reg.h"
#include "nicvf_queues.h"

#define DRV_NAME	"thunder-nicvf"
#define DRV_VERSION	"1.0"

/* Supported devices */
static DEFINE_PCI_DEVICE_TABLE(nicvf_id_table) = {
	{ PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, PCI_DEVICE_ID_THUNDER_NIC_VF) },
	{ 0, }  /* end of table */
};

MODULE_AUTHOR("Cavium Inc");
MODULE_DESCRIPTION("Cavium Thunder Virtual Function Network Driver");
MODULE_LICENSE("GPL");
MODULE_VERSION(DRV_VERSION);
MODULE_DEVICE_TABLE(pci, nicvf_id_table);

static int nicvf_enable_msix(struct nicvf *nic);
static netdev_tx_t nicvf_xmit(struct sk_buff *skb, struct net_device *netdev);

static void nicvf_dump_packet(struct sk_buff *skb)
{
#ifdef NICVF_DUMP_PACKET
	int i;

	for (i = 0; i < skb->len; i++) {
		if (!(i % 16))
			printk("\n");
		printk("%02x ", (u_char)skb->data[i]);
	}
#endif
}

static void nicvf_update_stats(struct nicvf *nic, struct sk_buff *skb)
{
	if (skb->len <= 64)
		atomic64_add(1, (atomic64_t *)&nic->vstats.rx.rx_frames_64);
	else if ((skb->len > 64) && (skb->len <= 127))
		atomic64_add(1, (atomic64_t *)&nic->vstats.rx.rx_frames_127);
	else if ((skb->len > 127) && (skb->len <= 255))
		atomic64_add(1, (atomic64_t *)&nic->vstats.rx.rx_frames_255);
	else if ((skb->len > 255) && (skb->len <= 511))
		atomic64_add(1, (atomic64_t *)&nic->vstats.rx.rx_frames_511);
	else if ((skb->len > 511) && (skb->len <= 1023))
		atomic64_add(1, (atomic64_t *)&nic->vstats.rx.rx_frames_1023);
	else if ((skb->len > 1023) && (skb->len <= 1518))
		atomic64_add(1, (atomic64_t *)&nic->vstats.rx.rx_frames_1518);
	else if (skb->len > 1518)
		atomic64_add(1, (atomic64_t *)&nic->vstats.rx.rx_frames_jumbo);
}

/* Register read/write APIs */
void nicvf_reg_write(struct nicvf *nic, uint64_t offset, uint64_t val)
{
	uint64_t addr = nic->reg_base + offset;

	writeq_relaxed(val, (void *)addr);
}

uint64_t nicvf_reg_read(struct nicvf *nic, uint64_t offset)
{
	uint64_t addr = nic->reg_base + offset;

	return readq_relaxed((void *)addr);
}

void nicvf_qset_reg_write(struct nicvf *nic, uint64_t offset, uint64_t val)
{
	uint64_t addr = nic->reg_base + offset;

	writeq_relaxed(val, (void *)(addr));
}

uint64_t nicvf_qset_reg_read(struct nicvf *nic, uint64_t offset)
{
	uint64_t addr = nic->reg_base + offset;

	return readq_relaxed((void *)(addr));
}

void nicvf_queue_reg_write(struct nicvf *nic, uint64_t offset,
				uint64_t qidx, uint64_t val)
{
	uint64_t addr = nic->reg_base + offset;

	writeq_relaxed(val, (void *)(addr + (qidx << NIC_Q_NUM_SHIFT)));
}

uint64_t nicvf_queue_reg_read(struct nicvf *nic, uint64_t offset, uint64_t qidx)
{
	uint64_t addr = nic->reg_base + offset;

	return readq_relaxed((void *)(addr + (qidx << NIC_Q_NUM_SHIFT)));
}

/* VF -> PF mailbox communication */
static bool pf_ready_to_rcv_msg = false;
static bool vf_pf_msg_delivered = false;

struct nic_mbx *nicvf_get_mbx(void)
{
	return (struct nic_mbx *)kzalloc(sizeof(struct nic_mbx), GFP_KERNEL);
}

static void nicvf_enable_mbx_intr(struct nicvf *nic)
{
	nicvf_enable_intr(nic, NICVF_INTR_MBOX, 0);
}

static void nicvf_disable_mbx_intr(struct nicvf *nic)
{
	nicvf_disable_intr(nic, NICVF_INTR_MBOX, 0);
}

void nicvf_send_msg_to_pf(struct nicvf *nic, struct nic_mbx *mbx)
{
	int i, timeout = 5000, sleep = 10;
	uint64_t *msg;
	uint64_t mbx_addr;

	vf_pf_msg_delivered = false;
	mbx->mbx_trigger_intr = 1;
	msg = (uint64_t *)mbx;
	mbx_addr = nic->reg_base + NIC_VF_PF_MAILBOX_0_7;
	for (i = 0; i < NIC_PF_VF_MAILBOX_SIZE; i++) {
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
			netdev_err(nic->netdev,
				"PF didn't ack to mailbox msg %lld from VF%d\n",
						(mbx->msg & 0xFF), nic->vnic_id);
			return;
		}
	}
}

/* Checks if VF is able to comminicate with PF
* and also gets the VNIC number this VF is associated to.
*/
static int nicvf_check_pf_ready(struct nicvf *nic)
{
	int timeout = 5000, sleep = 20;
	uint64_t mbx_addr = NIC_VF_PF_MAILBOX_0_7;

	pf_ready_to_rcv_msg = false;

	nicvf_reg_write(nic, mbx_addr, NIC_PF_VF_MSG_READY);

	mbx_addr += (NIC_PF_VF_MAILBOX_SIZE - 1) * 8;
	nicvf_reg_write(nic, mbx_addr, 1ULL);

	while (!pf_ready_to_rcv_msg) {
		msleep(sleep);
		if (pf_ready_to_rcv_msg)
			break;
		else
			timeout -= sleep;
		if (!timeout) {
			netdev_err(nic->netdev,
				"PF didn't respond to READY msg\n");
			return 0;
		}
	}
	return 1;
}

static void  nicvf_handle_mbx_intr(struct nicvf *nic)
{
	int i;
	struct nic_mbx *mbx;
	uint64_t *mbx_data;
	uint64_t mbx_addr;

	mbx_addr = NIC_VF_PF_MAILBOX_0_7;

	mbx_data = kzalloc(sizeof(struct nic_mbx), GFP_KERNEL);
	mbx = (struct nic_mbx *)mbx_data;

	for (i = 0; i < NIC_PF_VF_MAILBOX_SIZE; i++) {
		*mbx_data = nicvf_reg_read(nic, mbx_addr + (i * NIC_PF_VF_MAILBOX_SIZE));
		mbx_data++;
	}

	switch (mbx->msg & 0xFF) {
	case NIC_PF_VF_MSG_ACK:
		vf_pf_msg_delivered = true;
		break;
	case NIC_PF_VF_MSG_READY:
		pf_ready_to_rcv_msg = true;
		nic->vnic_id = mbx->data.vnic_id & 0x7F;
		break;
	default:
		netdev_err(nic->netdev, "Invalid message from PF, msg 0x%llx\n",
								mbx->msg);
		break;
	}
	nicvf_clear_intr(nic, NICVF_INTR_MBOX, 0);
	kfree(mbx);
}

static void nicvf_hw_set_mac_addr(struct nicvf *nic, struct net_device *netdev)
{
	int i;
	struct  nic_mbx *mbx;


	mbx = nicvf_get_mbx();
	mbx->msg = NIC_PF_VF_MSG_SET_MAC;
	mbx->data.mac.vnic_id = nic->vnic_id;
	for (i = 0; i < ETH_ALEN; i++) {
		mbx->data.mac.addr = (mbx->data.mac.addr << 8) | netdev->dev_addr[i];
	}
	nicvf_send_msg_to_pf(nic, mbx);
}

static int nicvf_is_link_active(struct nicvf *nic)
{
	return 1;
}

static int nicvf_init_resources(struct nicvf *nic)
{
	int err;

	nic->num_qs = 1;

	/* Initialize queues and HW for data transfer */
	if ((err = nicvf_config_data_transfer(nic, true))) {
		netdev_err(nic->netdev,
			"Failed to allocate/configure VF's QSet resources, err %d\n", err);
		return err;
	}
	/* Enable Qset */
	nicvf_qset_config(nic, true);

	return 0;
}

void nicvf_free_skb(struct nicvf *nic, struct sk_buff *skb)
{
	int i;

	if (!skb_shinfo(skb)->nr_frags)
		goto free_skb;

	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		const struct skb_frag_struct *frag;

		frag = &skb_shinfo(skb)->frags[i];
		pci_unmap_single(nic->pdev, (dma_addr_t)skb_frag_address(frag),
						skb_frag_size(frag), PCI_DMA_TODEVICE);
	}
free_skb:
	pci_unmap_single(nic->pdev, (dma_addr_t)skb->data, skb_headlen(skb), PCI_DMA_TODEVICE);
	dev_kfree_skb_any(skb);
}

static void nicvf_snd_pkt_handler(struct net_device *netdev,
				  void *cq_desc, int cqe_type)
{
	struct sk_buff *skb = NULL;
	struct cqe_send_t *cqe_tx;
	struct nicvf *nic = netdev_priv(netdev);
	struct snd_queue *sq;
	struct sq_hdr_subdesc *hdr;

	cqe_tx = (struct cqe_send_t *)cq_desc;
	sq = &nic->qs->sq[cqe_tx->sq_idx];

	hdr  = (struct sq_hdr_subdesc *)(sq->desc_mem.base +
				(cqe_tx->sqe_ptr * SND_QUEUE_DESC_SIZE));
	if (hdr->subdesc_type != SQ_DESC_TYPE_HEADER)
		return;

	nic_dbg(&nic->pdev->dev, "%s Qset #%d SQ #%d SQ ptr #%d Subdesc count %d\n",
				__FUNCTION__, cqe_tx->sq_qs, cqe_tx->sq_idx,
					cqe_tx->sqe_ptr, hdr->subdesc_cnt);

	skb = (struct sk_buff *)sq->skbuff[cqe_tx->sqe_ptr];
	atomic64_add(1, (atomic64_t *)&netdev->stats.tx_packets);
	atomic64_add(hdr->tot_len, (atomic64_t *)&netdev->stats.tx_bytes);
	nicvf_free_skb(nic, skb);
	nicvf_put_sq_desc(sq, hdr->subdesc_cnt + 1);
}

static void nicvf_rcv_pkt_handler(struct net_device *netdev,
			struct napi_struct *napi, void *cq_desc, int cqe_type)
{
	struct sk_buff *skb;
	struct nicvf *nic = netdev_priv(netdev);

	if (!((cqe_type == CQE_TYPE_RX) || (cqe_type == CQE_TYPE_RX_SPLIT) ||
						(cqe_type == CQE_TYPE_RX_TCP))) {
		atomic64_add(1, (atomic64_t *)&netdev->stats.rx_dropped);
		return;
	}

	/* Check for errors */
	if (nicvf_cq_check_errs(nic, cq_desc)) {
		atomic64_add(1, (atomic64_t *)&netdev->stats.rx_errors);
		return;
	}

	skb = nicvf_get_rcv_skb(nic, cq_desc);
	if (!skb) {
		nic_dbg(&nic->pdev->dev, "Packet not received\n");
		return;
	}

	nicvf_dump_packet(skb);

	/* Update stats */
	atomic64_add(1, (atomic64_t *)&netdev->stats.rx_packets);
	atomic64_add(skb->len, (atomic64_t *)&netdev->stats.rx_bytes);

#ifdef NICVF_ETHTOOL_ENABLE
	nicvf_update_stats(nic, skb);
#endif

	skb->protocol = eth_type_trans(skb, netdev);

#ifdef VNIC_RX_CHKSUM_SUPPORTED
	skb->ip_summed = CHECKSUM_UNNECESSARY;
#else
	skb_checksum_none_assert(skb);
#endif

#ifdef	NICVF_NAPI_ENABLE
#ifdef	VNIC_SW_LRO_SUPPORT
	if (napi && (netdev->features & NETIF_F_GRO))
		napi_gro_receive(napi, skb);
	else
#endif
		netif_receive_skb(skb);
#else
	netif_rx(skb);
#endif
}

static int nicvf_cq_intr_handler(struct net_device *netdev, uint8_t cq_idx,
					struct napi_struct *napi, int budget)
{
	int processed_cqe = 0, work_done = 0;
	int cqe_count, cqe_head;
	struct nicvf *nic = netdev_priv(netdev);
	struct queue_set *qs = nic->qs;
	struct cmp_queue *cq = &qs->cq[cq_idx];
	struct cqe_rx_t *cq_desc;

	spin_lock(&cq->cq_lock);
	/* Get no of valid CQ entries to process */
	cqe_count = nicvf_queue_reg_read(nic, NIC_QSET_CQ_0_7_STATUS, cq_idx);
	cqe_count &= CQ_CQE_COUNT;
	if (!cqe_count)
		goto done;

	/* Get head of the valid CQ entries */
	cqe_head = nicvf_queue_reg_read(nic, NIC_QSET_CQ_0_7_HEAD, cq_idx) >> 9;
	cqe_head &= 0xFFFF;

	nic_dbg(&nic->pdev->dev, "%s cqe_count %d cqe_head %d\n", __FUNCTION__, cqe_count, cqe_head);
	while (processed_cqe < cqe_count) {
		/* Get the CQ descriptor */
		cq_desc = (struct cqe_rx_t *)(cq->desc_mem.base +
				(cqe_head * CMP_QUEUE_DESC_SIZE));

		if (napi && (work_done >= budget) &&
			(cq_desc->cqe_type != CQE_TYPE_SEND)) {
			break;
		}

		nic_dbg(&nic->pdev->dev, "cq_desc->cqe_type %d\n", cq_desc->cqe_type);
		switch (cq_desc->cqe_type) {
		case CQE_TYPE_RX:
			nicvf_rcv_pkt_handler(netdev, napi, cq_desc, CQE_TYPE_RX);
			work_done++;
		break;
		case CQE_TYPE_SEND:
			nicvf_snd_pkt_handler(netdev, cq_desc, CQE_TYPE_SEND);
		break;
		case CQE_TYPE_INVALID:
		case CQE_TYPE_RX_SPLIT:
		case CQE_TYPE_RX_TCP:
		case CQE_TYPE_SEND_PTP:
			/* Ignore for now */
		break;
		}
		cq_desc->cqe_type = CQE_TYPE_INVALID;
		processed_cqe++;
		cqe_head++;
		cqe_head &= (cq->desc_mem.q_len - 1);
	}
	nic_dbg(&nic->pdev->dev, "%s processed_cqe %d work_done %d budget %d\n",
			__FUNCTION__, processed_cqe, work_done, budget);

	/* Ring doorbell to inform H/W to reuse processed CQEs */
	nicvf_queue_reg_write(nic, NIC_QSET_CQ_0_7_DOOR,
					cq_idx, processed_cqe);
done:
	spin_unlock(&cq->cq_lock);
	return work_done;
}

#ifdef	NICVF_NAPI_ENABLE
static int nicvf_poll(struct napi_struct *napi, int budget)
{
	int  work_done = 0;
	struct net_device *netdev = napi->dev;
	struct nicvf *nic = netdev_priv(netdev);
	struct nicvf_cq_poll *cq = container_of(napi, struct nicvf_cq_poll, napi);
	struct netdev_queue *txq;

	work_done = nicvf_cq_intr_handler(netdev, cq->cq_idx, napi, budget);

	txq = netdev_get_tx_queue(netdev, cq->cq_idx);
	if (netif_tx_queue_stopped(txq))
		netif_tx_wake_queue(txq);

	if (work_done < budget) {
		/* Slow packet rate, exit polling */
		napi_complete(napi);
		/* Re-enable interrupts */
		nicvf_enable_intr(nic, NICVF_INTR_CQ, cq->cq_idx);
	}
	return work_done;
}
#endif

/* Qset error interrupt handler
 *
 * As of now only CQ errors are handled
 */
void nicvf_handle_qs_err(unsigned long data)
{
	struct nicvf *nic = (struct nicvf *)data;
	struct queue_set *qs = nic->qs;
	int qidx;
	uint64_t status;

	netif_tx_disable(nic->netdev);

	/* Check if it is CQ err */
	for (qidx = 0; qidx < qs->cq_cnt; qidx++) {
		status = nicvf_queue_reg_read(nic,
					NIC_QSET_CQ_0_7_STATUS, qidx);
		if (!(status & CQ_ERR_MASK))
			continue;
		/* Process already queued CQEs and reconfig CQ */
		nicvf_disable_intr(nic, NICVF_INTR_CQ, qidx);
		nicvf_sq_disable(nic, qidx);
		nicvf_cq_intr_handler(nic->netdev, qidx, NULL, 0);
		nicvf_cmp_queue_config(nic, qs, qidx, true);
		nicvf_sq_free_used_descs(nic->netdev, &qs->sq[qidx], qidx);
		nicvf_sq_enable(nic, &qs->sq[qidx], qidx);

		nicvf_enable_intr(nic, NICVF_INTR_CQ, qidx);
	}

	netif_tx_start_all_queues(nic->netdev);
	/* Re-enable Qset error interrupt */
	nicvf_enable_intr(nic, NICVF_INTR_QS_ERR, 0);
}

static irqreturn_t nicvf_misc_intr_handler(int irq, void *nicvf_irq)
{
	struct nicvf *nic = (struct nicvf *)nicvf_irq;

	nicvf_handle_mbx_intr(nic);

	return IRQ_HANDLED;
}

static irqreturn_t nicvf_intr_handler(int irq, void *nicvf_irq)
{
	uint64_t qidx, intr;
	uint64_t cq_intr, rbdr_intr, qs_err_intr;
	struct nicvf *nic = (struct nicvf *)nicvf_irq;
	struct queue_set *qs = nic->qs;

	intr = nicvf_qset_reg_read(nic, NIC_VF_INT);
	nic_dbg(&nic->pdev->dev, "%s intr status 0x%llx\n", __FUNCTION__, intr);

	cq_intr = (intr & NICVF_INTR_CQ_MASK) >> NICVF_INTR_CQ_SHIFT;
	qs_err_intr = intr & NICVF_INTR_QS_ERR_MASK;
	if (qs_err_intr) {
		/* Disable Qset err interrupt and schedule softirq */
		nicvf_disable_intr(nic, NICVF_INTR_QS_ERR, 0);
		tasklet_hi_schedule(&nic->qs_err_task);
	}

#ifdef	NICVF_NAPI_ENABLE
	{
		struct nicvf_cq_poll *cq_poll = NULL;
		/* Disable interrupts and start polling */
		for (qidx = 0; qidx < qs->cq_cnt; qidx++) {
			if (!(cq_intr & (1 << qidx)))
				continue;
			if (!nicvf_is_intr_enabled(nic, NICVF_INTR_CQ, qidx))
				continue;
			nicvf_disable_intr(nic, NICVF_INTR_CQ, qidx);
			cq_poll = nic->napi[qidx];
			/* Schedule NAPI */
			napi_schedule(&cq_poll->napi);
		}
	}
#else
	for (qidx = 0; qidx < qs->cq_cnt; qidx++) {
		if (cq_intr & (1 << qidx))
			nicvf_cq_intr_handler(nic->netdev, qidx, NULL, 0);
	}
#endif
	/* Handle RBDR interrupts */
	rbdr_intr = (intr & NICVF_INTR_RBDR_MASK) >> NICVF_INTR_RBDR_SHIFT;
	if (rbdr_intr) {
		/* Disable RBDR interrupt and schedule softirq */
		for (qidx = 0; qidx < qs->rbdr_cnt; qidx++)
			nicvf_disable_intr(nic, NICVF_INTR_RBDR, qidx);

		tasklet_hi_schedule(&nic->rbdr_task);
	}

	/* Clear interrupts */
	nicvf_qset_reg_write(nic, NIC_VF_INT, intr);
	return IRQ_HANDLED;
}

static int nicvf_enable_msix(struct nicvf *nic)
{
	int i, ret, vec;
	struct queue_set *qs = nic->qs;

	nic->num_vec = NIC_VF_MSIX_VECTORS;
	vec = qs->cq_cnt + qs->rbdr_cnt + qs->sq_cnt;
	vec = NIC_VF_MSIX_VECTORS;
	if (vec > NIC_VF_MSIX_VECTORS)
		nic->num_vec = vec;

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

static void nicvf_disable_msix(struct nicvf *nic)
{
	if (nic->msix_enabled) {
		pci_disable_msix(nic->pdev);
		nic->msix_enabled = 0;
		nic->num_vec = 0;
	}
}

static int nicvf_register_interrupts(struct nicvf *nic)
{
	int irq, free, ret = 0;

	for_each_cq_irq(irq)
		sprintf(nic->irq_name[irq], "%s%d CQ%d", "NICVF",
						nic->vnic_id, irq);

	for_each_sq_irq(irq)
		sprintf(nic->irq_name[irq], "%s%d SQ%d", "NICVF",
			nic->vnic_id, irq - NICVF_SQ_INTR_ID);

	for_each_rbdr_irq(irq)
		sprintf(nic->irq_name[irq], "%s%d RBDR%d", "NICVF",
			nic->vnic_id, irq - NICVF_RBDR_INTR_ID);

	/* Register all interrupts except mailbox */
	for (irq = 0; irq < NICVF_MISC_INTR_ID; irq++) {
		if ((ret = request_irq(nic->msix_entries[irq].vector,
				nicvf_intr_handler, 0 , nic->irq_name[irq], nic)))
			break;
		nic->irq_allocated[irq] = 1;
	}

	sprintf(nic->irq_name[NICVF_QS_ERR_INTR_ID],
				"%s%d Qset error", "VNICVF", nic->vnic_id);
	if (!ret) {
		if (!(ret = request_irq(nic->msix_entries[NICVF_QS_ERR_INTR_ID].vector,
				nicvf_intr_handler, 0 , nic->irq_name[NICVF_QS_ERR_INTR_ID], nic)))
			nic->irq_allocated[NICVF_QS_ERR_INTR_ID] = 1;
	}

	if (ret) {
		netdev_err(nic->netdev, "Request irq failed\n");
		for (free = 0; free < irq; free++)
			free_irq(nic->msix_entries[free].vector, nic);
		return 1;
	}

	return 0;
}

static void nicvf_unregister_interrupts(struct nicvf *nic)
{
	int irq;

	/* Free registered interrupts */
	for (irq = 0; irq < nic->num_vec; irq++) {
		if (nic->irq_allocated[irq])
			free_irq(nic->msix_entries[irq].vector, nic);
		nic->irq_allocated[irq] = 0;
	}

	/* Disable MSI-X */
	nicvf_disable_msix(nic);
}

static int nicvf_register_misc_interrupt(struct nicvf *nic)
{
	int  ret = 0;
	int irq = NICVF_MISC_INTR_ID;

	/* Enable MSI-X */
	if (!nicvf_enable_msix(nic))
		return 1;

	sprintf(nic->irq_name[irq], "%s%d Mbox", "VNIC", nic->vnic_id);
	/* Register Misc interrupt */
	ret = request_irq(nic->msix_entries[irq].vector, nicvf_misc_intr_handler,
						0, nic->irq_name[irq], nic);

	if (ret)
		return 1;
	nic->irq_allocated[irq] = 1;

	/* Enable mailbox interrupt */
	nicvf_enable_mbx_intr(nic);

	/* Check if VF is able to communicate with PF */
	if (!nicvf_check_pf_ready(nic)) {
		nicvf_disable_mbx_intr(nic);
		nicvf_unregister_interrupts(nic);
		return 1;
	}

	return 0;
}

static void nicvf_update_tx_stats(struct nicvf *nic, struct sk_buff *skb)
{
	return;
}

#ifdef VNIC_SW_TSO_SUPPORT
static int nicvf_sw_tso(struct sk_buff *skb, struct net_device *netdev)
{
	struct sk_buff *segs, *nskb;

	if (!skb_shinfo(skb)->gso_size)
		return 1;

	/* Segment the large frame */
	segs = skb_gso_segment(skb, netdev->features & ~NETIF_F_TSO);
	if (IS_ERR(segs))
		goto gso_err;

	do {
		nskb = segs;
		segs = segs->next;
		nskb->next = NULL;
		nicvf_xmit(nskb, netdev);
	} while (segs);

gso_err:
	dev_kfree_skb(skb);

	return NETDEV_TX_OK;
}
#endif

static netdev_tx_t nicvf_xmit(struct sk_buff *skb, struct net_device *netdev)
{
	struct nicvf *nic = netdev_priv(netdev);
	int qid = skb_get_queue_mapping(skb);
	struct netdev_queue *txq = netdev_get_tx_queue(netdev, qid);
	int ret = 1;

	/* Check for minimum packet length */
	if (skb->len <= ETH_HLEN) {
		atomic64_add(1, (atomic64_t *)&netdev->stats.tx_errors);
		dev_kfree_skb(skb);
		return NETDEV_TX_OK;
	}

#ifdef VNIC_SW_TSO_SUPPORT
	if (netdev->features & NETIF_F_TSO)
		ret = nicvf_sw_tso(skb, netdev);
#endif
	if (ret == NETDEV_TX_OK)
		return NETDEV_TX_OK;

#ifndef VNIC_TX_CSUM_OFFLOAD_SUPPORT
	/* Calculate checksum in software */
	if (skb->ip_summed == CHECKSUM_PARTIAL) {
		if (unlikely(skb_checksum_help(skb))) {
			netdev_dbg(netdev, "unable to do checksum\n");
			dev_kfree_skb_any(skb);
			return NETDEV_TX_OK;
		}
	}
#endif
#ifdef VNIC_HW_TSO_SUPPORT
	if (skb_shinfo(skb)->gso_size && ((skb->protocol == ETH_P_IP) &&
				(ip_hdr(skb)->protocol != IPPROTO_TCP))) {
		netdev_dbg(netdev, "Only TCP segmentation is supported, \
							dropping packet\n");
		dev_kfree_skb_any(skb);
		return NETDEV_TX_OK;
	}
#endif
	if (!nicvf_sq_append_skb(nic, skb) && !netif_tx_queue_stopped(txq)) {
		netif_tx_stop_queue(txq);
		atomic64_add(1, (atomic64_t *)&netdev->stats.tx_dropped);
		nic_dbg(&nic->pdev->dev,
			"VF%d: TX ring full, stop transmitting packets\n", nic->vnic_id);
		return NETDEV_TX_BUSY;
	}

	nicvf_update_tx_stats(nic, skb);
	return NETDEV_TX_OK;
}

static int nicvf_stop(struct net_device *netdev)
{
	int qidx;
	struct nicvf *nic = netdev_priv(netdev);
	struct queue_set *qs = nic->qs;

	netif_carrier_off(netdev);
	netif_tx_disable(netdev);

	/* Disable HW Qset, to stop receiving packets */
	nicvf_qset_config(nic, false);

	/* disable mailbox interrupt */
	nicvf_disable_mbx_intr(nic);

	/* Disable interrupts */
	for (qidx = 0; qidx < qs->cq_cnt; qidx++)
		nicvf_disable_intr(nic, NICVF_INTR_CQ, qidx);
	for (qidx = 0; qidx < qs->rbdr_cnt; qidx++)
		nicvf_disable_intr(nic, NICVF_INTR_RBDR, qidx);
	nicvf_disable_intr(nic, NICVF_INTR_QS_ERR, 0);

	tasklet_kill(&nic->rbdr_task);
	tasklet_kill(&nic->qs_err_task);

	nicvf_unregister_interrupts(nic);
#ifdef	NICVF_NAPI_ENABLE
	for (qidx = 0; qidx < nic->qs->cq_cnt; qidx++) {
		napi_synchronize(&nic->napi[qidx]->napi);
		napi_disable(&nic->napi[qidx]->napi);
		netif_napi_del(&nic->napi[qidx]->napi);
		kfree(nic->napi[qidx]);
		nic->napi[qidx] = NULL;
	}
#endif
	/* Free resources */
	nicvf_config_data_transfer(nic, false);

	/* Free Qset */
	kfree(qs);

	return 0;
}

static int nicvf_open(struct net_device *netdev)
{
	int err, qidx;
	struct nicvf *nic = netdev_priv(netdev);
	struct queue_set *qs;
	struct nicvf_cq_poll *cq_poll = NULL;

	nic->mtu = netdev->mtu;

	netif_carrier_off(netdev);

	if ((err = nicvf_register_misc_interrupt(nic))) {
		return -EIO;
	}

	if ((err = nicvf_init_resources(nic)))
		return err;

	qs = nic->qs;

	if ((err = netif_set_real_num_tx_queues(netdev, qs->sq_cnt))) {
		netdev_err(netdev,
			"Failed to set real number of Tx queues: %d\n", err);
		return err;
	}
	if ((err = netif_set_real_num_rx_queues(netdev, qs->rq_cnt))) {
		netdev_err(netdev,
			"Failed to set real number of Rx queues: %d\n", err);
		return err;
	}

	if ((err = nicvf_register_interrupts(nic))) {
		nicvf_stop(netdev);
		return -EIO;
	}

#ifdef	NICVF_NAPI_ENABLE
	for (qidx = 0; qidx < qs->cq_cnt; qidx++) {
		cq_poll = NULL;
		cq_poll = kzalloc(sizeof(struct nicvf_cq_poll), GFP_KERNEL);
		if (!cq_poll)
			goto napi_del;
		cq_poll->cq_idx = qidx;
		netif_napi_add(netdev, &cq_poll->napi, nicvf_poll, NAPI_POLL_WEIGHT);
		napi_enable(&cq_poll->napi);
		nic->napi[qidx] = cq_poll;
	}
	goto no_err;
napi_del:
	while (qidx) {
		qidx--;
		cq_poll = nic->napi[qidx];
		napi_disable(&cq_poll->napi);
		netif_napi_del(&cq_poll->napi);
		kfree(cq_poll);
		nic->napi[qidx] = NULL;
	}
	return -ENOMEM;
no_err:
#endif

	/* Set MAC-ID */
	if (is_zero_ether_addr(netdev->dev_addr))
		eth_hw_addr_random(netdev);

	nicvf_hw_set_mac_addr(nic, netdev);

	/* Init tasklet for handling Qset err interrupt */
	tasklet_init(&nic->qs_err_task, nicvf_handle_qs_err, (unsigned long)nic);

	/* Enable Qset err interrupt */
	nicvf_enable_intr(nic, NICVF_INTR_QS_ERR, 0);

	/* Enable completion queue interrupt */
	for (qidx = 0; qidx < qs->cq_cnt; qidx++)
		nicvf_enable_intr(nic, NICVF_INTR_CQ, qidx);

	/* Init RBDR tasklet and enable RBDR threshold interrupt */
	tasklet_init(&nic->rbdr_task, nicvf_refill_rbdr, (unsigned long)nic);

	for (qidx = 0; qidx < qs->rbdr_cnt; qidx++)
		nicvf_enable_intr(nic, NICVF_INTR_RBDR, qidx);

	if (nicvf_is_link_active(nic)) {
		netif_carrier_on(netdev);
		netif_tx_start_all_queues(netdev);
	}

	return 0;
}

static int nicvf_change_mtu(struct net_device *netdev, int new_mtu)
{
	if (new_mtu > NICVF_MAX_MTU_SUPPORTED)
		return -EINVAL;

	if (new_mtu < NICVF_MIN_MTU_SUPPORTED)
		return -EINVAL;

	netdev->mtu = new_mtu;
	return 0;
}

static int nicvf_set_mac_address(struct net_device *netdev, void *p)
{
	struct sockaddr *addr = p;
	struct nicvf *nic = netdev_priv(netdev);

	if (!is_valid_ether_addr(addr->sa_data))
		return -EADDRNOTAVAIL;

	memcpy(netdev->dev_addr, addr->sa_data, netdev->addr_len);
	if (netif_running(netdev))
		nicvf_hw_set_mac_addr(nic, netdev);

	return 0;
}

static const struct net_device_ops nicvf_netdev_ops = {
	.ndo_open		= nicvf_open,
	.ndo_stop		= nicvf_stop,
	.ndo_start_xmit		= nicvf_xmit,
	.ndo_change_mtu		= nicvf_change_mtu,
	.ndo_set_mac_address	= nicvf_set_mac_address,
#if 0
	.ndo_get_stats64	= nicvf_get_stats,
	.ndo_validate_addr	= eth_validate_addr,
	.ndo_set_rx_mode	= nicvf_set_rx_mode,
	.ndo_vlan_rx_add_vid	= nicvf_vlan_rx_add_vid,
	.ndo_vlan_rx_kill_vid	= nicvf_vlan_rx_kill_vid,
	.ndo_tx_timeout		= nicvf_tx_timeout,
#endif
};

static int nicvf_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	struct device *dev = &pdev->dev;
	struct net_device *netdev;
	struct nicvf *nic;
	int    err;

	netdev = alloc_etherdev_mqs(sizeof(struct nicvf),
			MAX_RCV_QUEUES_PER_QS, MAX_SND_QUEUES_PER_QS);

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
			dev_err(dev, "unable to get 48-bit DMA for consistent allocations\n");
			goto err_release_regions;
		}
	} else {
		dev_err(dev, "Unable to get usable DMA configuration\n");
		goto err_release_regions;
	}

	/* MAP VF's configuration registers */
	nic->reg_base = (uint64_t)pci_ioremap_bar(pdev, PCI_CFG_REG_BAR_NUM);
	if (!nic->reg_base) {
		dev_err(dev, "Cannot map config register space, aborting\n");
		err = -ENOMEM;
		goto err_release_regions;
	}

#ifdef VNIC_RX_CSUM_OFFLOAD_SUPPORT
	netdev->hw_features |= NETIF_F_RXCSUM;
#endif
#ifdef VNIC_TX_CSUM_OFFLOAD_SUPPORT
	netdev->hw_features |= NETIF_F_IP_CSUM;
#endif
#ifdef VNIC_SG_SUPPORT
	netdev->hw_features |= NETIF_F_SG;
#endif
#ifdef VNIC_TSO_SUPPORT
	netdev->hw_features |= NETIF_F_TSO | NETIF_F_SG | NETIF_F_IP_CSUM;
#endif
#ifdef VNIC_HW_LRO_SUPPORT
	netdev->hw_features |= NETIF_F_LRO;
#endif

	netdev->features |= netdev->hw_features;
	netdev->netdev_ops = &nicvf_netdev_ops;

	if ((err = register_netdev(netdev))) {
		dev_err(dev, "Failed to register netdevice\n");
		goto err_unmap_resources;
	}

#ifdef NICVF_ETHTOOL_ENABLE
	nicvf_set_ethtool_ops(netdev);
#endif
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

static void nicvf_remove(struct pci_dev *pdev)
{
	struct net_device *netdev = pci_get_drvdata(pdev);
	struct nicvf *nic;

	if (!netdev)
		return;

	nic = netdev_priv(netdev);
	unregister_netdev(netdev);

	pci_set_drvdata(pdev, NULL);

	if (nic->reg_base)
		iounmap((void *)nic->reg_base);

	pci_release_regions(pdev);
	pci_disable_device(pdev);
	free_netdev(netdev);
}

static struct pci_driver nicvf_driver = {
	.name = DRV_NAME,
	.id_table = nicvf_id_table,
	.probe = nicvf_probe,
	.remove = nicvf_remove,
};

static int __init nicvf_init_module(void)
{
	pr_info("%s, ver %s\n", DRV_NAME, DRV_VERSION);

	return pci_register_driver(&nicvf_driver);
}

static void __exit nicvf_cleanup_module(void)
{
	pci_unregister_driver(&nicvf_driver);
}

module_init(nicvf_init_module);
module_exit(nicvf_cleanup_module);

