/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 * 
 * Copyright (C) 2014 Cavium, Inc. 
 */

#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/pci.h>
#include <linux/netdevice.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <net/checksum.h>

#include "nic.h"
#include "nic_reg.h"
#include "q_struct.h"
#include "nicvf_queues.h"

#define DEFAULT_RCV_QUEUE_CNT 1
#define DEFAULT_CMP_QUEUE_CNT 1
#define DEFAULT_SND_QUEUE_CNT 1
#define DEFAULT_RBDR_CNT 1

#define  MIN_SND_QUEUE_DESC_FOR_PKT_XMIT 2

static int nicvf_alloc_q_desc_mem (struct nicvf *nic, 
				struct q_desc_mem *desc_mem, 
				int q_len, int desc_size, int align_bytes)
{
	desc_mem->q_len = q_len; 
	desc_mem->size = (desc_size * q_len) + align_bytes;
	desc_mem->unalign_base = dma_alloc_coherent (&nic->pdev->dev, desc_mem->size,
							&desc_mem->dma, GFP_ATOMIC);
	if (!desc_mem->unalign_base) {
		netdev_err(nic->netdev, 
			"Unable to allocate memory for Rcv.buffer descriptor ring\n");
		return -1;
	}

	desc_mem->base = (void *)NICVF_ALIGNED_ADDR((uint64_t)desc_mem->unalign_base, align_bytes); 
	return 0;
}

static void nicvf_free_q_desc_mem (struct nicvf *nic, struct q_desc_mem *desc_mem)
{
	if (!desc_mem)
		return;

	dma_free_coherent (&nic->pdev->dev, desc_mem->size, 
			desc_mem->unalign_base, desc_mem->dma);
	desc_mem->unalign_base = NULL;
	desc_mem->base = NULL;
}

static int nicvf_alloc_rcv_buffer(struct nicvf *nic, uint64_t buf_len, 
					unsigned char **rcv_buffer)
{
	struct sk_buff *skb = NULL;

	buf_len += NICVF_RCV_BUF_ALIGN_BYTES + sizeof(void *);

	if (!(skb = netdev_alloc_skb(nic->netdev, buf_len)))
                        return -ENOMEM;
		
	/* Reserve bytes for storing skb address */
	skb_reserve(skb, sizeof(void *));	
	/* Align buffer addr to cache line i.e 128 bytes */
	skb_reserve(skb, NICVF_RCV_BUF_ALIGN_LEN((uint64_t)skb->data));

	/* Store skb address */
	*(struct sk_buff **)(skb->data - sizeof(void *)) = skb;

	/* Return buffer address */
	*rcv_buffer = skb->data;
	return 0;
}

static struct sk_buff *nicvf_rb_ptr_to_skb (uint64_t rb_ptr)
{
	struct sk_buff *skb;

	rb_ptr = (uint64_t)phys_to_virt(rb_ptr);
	//pr_err("rb_ptr %llx \n",rb_ptr);
	//pr_err("*rb_ptr %llx \n",*(uint64_t *)(rb_ptr - sizeof(void *)));
	skb = (struct sk_buff *)*(uint64_t *)(rb_ptr - sizeof(void *));
	return skb;
}

int  nicvf_alloc_rbdr (struct nicvf *nic, struct rbdr *rbdr, 
						int ring_len, int mtu)
{
	int idx;
	unsigned char *rcv_buffer;

	if (nicvf_alloc_q_desc_mem (nic, &rbdr->desc_mem, ring_len, 
				sizeof(struct rbdr_entry_t), NICVF_RCV_BUF_ALIGN_BYTES))
		return -ENOMEM;

	//rbdr->buf_size = mtu + VLAN_ETH_HLEN;
	/* Buffer size has to be in multiples of 128 bytes */
	rbdr->buf_size = DEFAULT_RCV_BUFFER_LEN;
	rbdr->enable = true;
	//rbdr->thresh = DEFAULT_RBDR_THRESH;
	rbdr->thresh = ring_len / 2; 

        for (idx = 0; idx < ring_len; idx++) {
		rbdr->desc[idx] = &((struct rbdr_entry_t *)rbdr->desc_mem.base)[idx];

		if (nicvf_alloc_rcv_buffer (nic, rbdr->buf_size, &rcv_buffer))
			return -ENOMEM;
		
		rbdr->desc[idx]->buf_addr = pci_map_single(nic->pdev, rcv_buffer, 
				rbdr->buf_size, PCI_DMA_FROMDEVICE) >> NICVF_RCV_BUF_ALIGN;
	}
	return 0;
}

static void nicvf_free_rbdr (struct nicvf *nic, struct rbdr *rbdr, int rbdr_qidx)
{
	int head, tail;
	struct sk_buff *skb;

	if (!rbdr)
		return;

	rbdr->enable = false;
	if (!rbdr->desc_mem.base)
		return;

	head = nicvf_queue_reg_read (nic, NIC_QSET_RBDR_0_1_HEAD,
							rbdr_qidx) >> 3;
	tail = nicvf_queue_reg_read (nic, NIC_QSET_RBDR_0_1_TAIL, 
							rbdr_qidx) >> 3;
	/* Free SKBs */
	while (head != tail) {
		skb = nicvf_rb_ptr_to_skb(rbdr->desc[head]->buf_addr << NICVF_RCV_BUF_ALIGN);
		pci_unmap_single(nic->pdev, (dma_addr_t)skb->data, 
				rbdr->buf_size, PCI_DMA_FROMDEVICE);
		dev_kfree_skb(skb);
		head++;
		head &= (rbdr->desc_mem.q_len - 1);
	}
	/* Free RBDR ring */
	nicvf_free_q_desc_mem(nic, &rbdr->desc_mem);
}

/*
 * Refill receive buffer descriptors with new buffers.
 * This runs in softirq context .
 */
void nicvf_refill_rbdr (unsigned long data)
{
	struct nicvf *nic = (struct nicvf *)data;
	struct queue_set *qs = nic->qs;
	int rbdr_idx = qs->rbdr_cnt; 
	int tail_ptr, qcount;
	int refill_rb_cnt, rb_cnt = 0;
	struct rbdr *rbdr;
	unsigned char *rcv_buffer;

refill:
	if (!rbdr_idx)
		return;
	
	rbdr_idx--;
	rbdr = &qs->rbdr[rbdr_idx];
	/* Check if it's enabled */
	if (!rbdr->enable)
		goto next_rbdr;

	qcount = nicvf_queue_reg_read (nic, NIC_QSET_RBDR_0_1_STATUS0,
							rbdr_idx) & 0x7FFFF;

	/* check if valid descs reached or crossed threshold level */
	if (qcount > rbdr->thresh)
		goto next_rbdr;

	/* Get no of desc's to be refilled i.e (qsize - thresh) */
	refill_rb_cnt = rbdr->desc_mem.q_len - rbdr->thresh;
	rb_cnt = refill_rb_cnt;
	
	/* Start filling descs from tail */	
	tail_ptr = nicvf_queue_reg_read (nic, NIC_QSET_RBDR_0_1_TAIL, 
							rbdr_idx) >> 3;
	while (refill_rb_cnt) {
		tail_ptr++;
		tail_ptr &= (rbdr->desc_mem.q_len - 1);
	
		if (nicvf_alloc_rcv_buffer (nic, rbdr->buf_size, &rcv_buffer)) {
			netdev_err(nic->netdev, "Failed to allocate new rcv buffer\n");
			break;
		}
		
		rbdr->desc[tail_ptr]->buf_addr = pci_map_single(nic->pdev, rcv_buffer, 
				rbdr->buf_size, PCI_DMA_FROMDEVICE) >> NICVF_RCV_BUF_ALIGN;
		refill_rb_cnt--;
	}
	/* Notify HW */
	if (rb_cnt) {
		nicvf_queue_reg_write(nic, NIC_QSET_RBDR_0_1_DOOR, 
						rbdr_idx, rb_cnt);
	}

next_rbdr:
	if (rbdr_idx)
		goto refill;

	/* Re-enable RBDR interrupts */
	for (rbdr_idx = 0; rbdr_idx < qs->rbdr_cnt; rbdr_idx++) 
		nicvf_enable_intr (nic, NICVF_INTR_RBDR, rbdr_idx);
}

int nicvf_alloc_rcv_queue (struct rcv_queue *rq)
{
	/* Nothing to do */
	return 0;
}

void nicvf_free_rcv_queue (struct rcv_queue *rq)
{
	/* Nothing to do */
}

/* TBD: how to handle full packets received in CQ 
 * i.e conversion of buffers into SKBs
 */
int nicvf_alloc_cmp_queue (struct nicvf *nic, struct cmp_queue *cq) 
{
	int q_len = DEFAULT_CMP_QUEUE_LEN;

	if (nicvf_alloc_q_desc_mem (nic, &cq->desc_mem, q_len, 
				CMP_QUEUE_DESC_SIZE, NICVF_CQ_BASE_ALIGN_BYTES))
		return -ENOMEM;
	cq->intr_timer_thresh = 0;

	return 0;
}

void nicvf_free_cmp_queue (struct nicvf *nic, struct cmp_queue *cq)
{
	if (!cq)
		return;
	if (!cq->desc_mem.base)
		return;

	nicvf_free_q_desc_mem(nic, &cq->desc_mem);
}

int nicvf_alloc_snd_queue (struct nicvf *nic, struct snd_queue *sq)
{
	int q_len = DEFAULT_SND_QUEUE_LEN;

	if (nicvf_alloc_q_desc_mem (nic, &sq->desc_mem, q_len, 
				SND_QUEUE_DESC_SIZE, NICVF_SQ_BASE_ALIGN_BYTES))
		return -ENOMEM;
		
	sq->skbuff = kmalloc(sizeof(uint64_t) * q_len, GFP_ATOMIC);
	sq->head = 0;
	sq->tail = q_len - 1;
	sq->free_cnt = q_len;
	
	return 0;
}

void nicvf_free_snd_queue (struct nicvf *nic, struct snd_queue *sq)
{
	if (!sq)
		return;
	if (!sq->desc_mem.base)
		return;

	kfree(sq->skbuff);
	nicvf_free_q_desc_mem(nic, &sq->desc_mem);
}

void nicvf_rcv_queue_config (struct nicvf *nic, struct queue_set *qs, bool enable)
{
	int i;
	struct  nic_mbx *mbx;
	struct rcv_queue *rq;

	for (i = 0; i < qs->rq_cnt; i++) {
		rq = &qs->rq[i];

		if (!enable) {
			/* Disable receive queue */
			nicvf_queue_reg_write(nic, NIC_QSET_RQ_0_7_CFG, i, 0);
			continue;	
		}
		
		rq->cq_qs = qs->vnic_id;
		rq->cq_idx = DEFAULT_CMP_QUEUE_CNT - 1;
		rq->start_rbdr_qs = qs->vnic_id;
		rq->start_qs_rbdr_idx = DEFAULT_RBDR_CNT - 1;
		rq->cont_rbdr_qs = qs->vnic_id;
		rq->cont_qs_rbdr_idx = DEFAULT_RBDR_CNT - 1;

		/* Send a mailbox msg to PF to config RQ */
		mbx = nicvf_get_mbx();
		mbx->msg = NIC_PF_VF_MSG_RQ_CFG;
		mbx->data.rq.qs_num = qs->vnic_id;
		mbx->data.rq.rq_num = i;
		mbx->data.rq.cfg = (rq->cq_qs << 19) | (rq->cq_idx << 16) | 
				(rq->cont_rbdr_qs << 9) | (rq->cont_qs_rbdr_idx << 8) | 
				(rq->start_rbdr_qs << 1) | (rq->start_qs_rbdr_idx);
		nicvf_send_msg_to_pf(nic, mbx);

		/* Enable Receive queue */
		nicvf_queue_reg_write(nic, NIC_QSET_RQ_0_7_CFG, i, (1ULL << 63));
	}
}

void nicvf_cmp_queue_config (struct nicvf *nic, struct queue_set *qs, bool enable)
{
	int i;
	struct cmp_queue *cq;

	for (i = 0; i < qs->cq_cnt; i++) {
		cq = &qs->cq[i];

		if (!enable) {
			/* Disable completion queue */
			nicvf_queue_reg_write(nic, NIC_QSET_CQ_0_7_CFG, i, 0);
			continue;	
		}
		/* Reset completion queue */
		nicvf_queue_reg_write(nic, NIC_QSET_CQ_0_7_CFG, i, (1ULL << 41));

		/* Enable Completion queue */
		nicvf_queue_reg_write(nic, NIC_QSET_CQ_0_7_CFG, i,
				(1ULL << 42) | (COMPLETION_QUEUE_SIZE0 << 32));

		/* Set threshold value for interrupt generation */
		nicvf_queue_reg_write(nic, NIC_QSET_CQ_0_7_THRESH, i,
				DEFAULT_CMP_QUEUE_THRESH);

		/* Set completion queue base address */
		nicvf_queue_reg_write(nic, NIC_QSET_CQ_0_7_BASE, i, 
						(uint64_t)virt_to_phys(cq->desc_mem.base));

		/* Set CQ's head entry */
		nicvf_queue_reg_write(nic, NIC_QSET_CQ_0_7_HEAD, i, 0);
	}
}

/*
 * TBD
 * - Set TL3 index 
 */
void nicvf_snd_queue_config (struct nicvf *nic, struct queue_set *qs, bool enable)
{
	int i;
	struct nic_mbx *mbx;
	struct snd_queue *sq;
	
	for (i = 0; i < qs->sq_cnt; i++) {
		sq = &qs->sq[i];

		if (!enable) {
			/* Disable send queue */
			nicvf_queue_reg_write(nic, NIC_QSET_SQ_0_7_CFG, i, 0);
			continue;	
		}

		/* Reset send queue */
		nicvf_queue_reg_write(nic, NIC_QSET_SQ_0_7_CFG, i, (1ULL << 17));

		sq->cq_qs = qs->vnic_id;
		sq->cq_idx = DEFAULT_CMP_QUEUE_CNT - 1;

		/* Send a mailbox msg to PF to config SQ */
		mbx = nicvf_get_mbx();
		mbx->msg = NIC_PF_VF_MSG_SQ_CFG;
		mbx->data.sq.qs_num = qs->vnic_id;
		mbx->data.sq.sq_num = i;
		mbx->data.sq.cfg = (sq->cq_qs << 3) | sq->cq_idx;
		nicvf_send_msg_to_pf(nic, mbx);

		/* Enable send queue  & set queue size */
		nicvf_queue_reg_write(nic, NIC_QSET_SQ_0_7_CFG, i,
				(1ULL << 19) | (SND_QUEUE_SIZE0 << 8));

		/* Set threshold value for interrupt generation */
		nicvf_queue_reg_write(nic, NIC_QSET_SQ_0_7_THRESH, i,
				DEFAULT_SND_QUEUE_THRESH);

		/* Set queue base address */
		nicvf_queue_reg_write(nic, NIC_QSET_SQ_0_7_BASE, i, 
						(uint64_t)virt_to_phys(sq->desc_mem.base));
		
		/* Set SQ's head entry */
		nicvf_queue_reg_write(nic, NIC_QSET_SQ_0_7_HEAD, i, 0);
	}
}

void nicvf_rbdr_config (struct nicvf *nic, struct queue_set *qs, bool enable)
{
	int i;
	struct rbdr *rbdr;

	for (i = 0; i < qs->rbdr_cnt; i++) {
		rbdr = &qs->rbdr[i];

		if (!enable) {
			/* Disable RBDR */
			nicvf_queue_reg_write(nic, NIC_QSET_RBDR_0_1_CFG, i, 0);
			continue;	
		}

		/* Reset RBDR */
		nicvf_queue_reg_write(nic, NIC_QSET_RBDR_0_1_CFG, i, (1ULL << 43));

		/* Enable RBDR  & set queue size */
		/* Buffer size should be in multiples of 128 bytes */
		nicvf_queue_reg_write(nic, NIC_QSET_RBDR_0_1_CFG, i,
				(1ULL << 44) | (RBDR_SIZE0 << 32) | (rbdr->buf_size / 128));

		/* Set descriptor base address */
		nicvf_queue_reg_write(nic, NIC_QSET_RBDR_0_1_BASE, i, 
						(uint64_t)virt_to_phys(rbdr->desc_mem.base));
		
		/* Set RBDR head entry */
		nicvf_queue_reg_write(nic, NIC_QSET_RBDR_0_1_HEAD, i, 0);
	
		/* Notify HW */
		nicvf_queue_reg_write(nic, NIC_QSET_RBDR_0_1_DOOR,  
						i, rbdr->desc_mem.q_len -1);
		
		/* Set threshold value for interrupt generation */
		nicvf_queue_reg_write(nic, NIC_QSET_RBDR_0_1_THRESH, i,
				rbdr->thresh - 1);

	}
}

void nicvf_qset_config (struct nicvf *nic, bool enable)  
{
	struct  nic_mbx *mbx;
	struct queue_set *qs = nic->qs;

	/* Send a mailbox msg to PF to config Qset */
	mbx = nicvf_get_mbx();
	mbx->msg = NIC_PF_VF_MSG_QS_CFG;
	mbx->data.qs.num = qs->vnic_id;

	if (enable) {
		mbx->data.qs.cfg = 0x80000000 | qs->vnic_id;
		nicvf_send_msg_to_pf(nic, mbx);
	} else {  /* disable Qset */
		mbx->data.qs.cfg = 0;
		nicvf_send_msg_to_pf(nic, mbx);
	}
}

void nicvf_free_resources(struct nicvf *nic)
{
	int qidx;
	struct queue_set *qs = nic->qs;

	if (!qs)
		return;

	/* Free receive buffer descriptor ring */
	for (qidx = 0; qidx < qs->rbdr_cnt; qidx++) {
		nicvf_free_rbdr(nic, &qs->rbdr[qidx], qidx);
	}

	/* Free receive queue */	
	for (qidx = 0; qidx < qs->rq_cnt; qidx++) {
		nicvf_free_rcv_queue(&qs->rq[qidx]);
	}	
	
	/* Free completion queue */
	for (qidx = 0; qidx < qs->cq_cnt; qidx++) {
		nicvf_free_cmp_queue(nic, &qs->cq[qidx]);
	}	
	
	/* Free send queue */
	for (qidx = 0; qidx < qs->sq_cnt; qidx++) {
		nicvf_free_snd_queue(nic, &qs->sq[qidx]);
	}	
}

int nicvf_alloc_resources (struct nicvf *nic, int rq_cnt,
				int cq_cnt, int sq_cnt, int rbdr_cnt)
{
	int qidx;
	struct queue_set *qs = nic->qs;

	/* Set queue lenghts */
	qs->rq_cnt = rq_cnt;
	qs->cq_cnt = cq_cnt;
	qs->sq_cnt = sq_cnt;
	qs->rbdr_cnt = rbdr_cnt;

	/* Alloc receive buffer descriptor ring */
	for (qidx = 0; qidx < rbdr_cnt; qidx++) {
		if (nicvf_alloc_rbdr(nic, &qs->rbdr[qidx], 
					DEFAULT_RCV_BUF_COUNT, DEFAULT_RCV_BUFFER_LEN))
			goto alloc_fail;
	}

	/* Alloc receive queue */	
	for (qidx = 0; qidx < qs->rq_cnt; qidx++) {
		if (nicvf_alloc_rcv_queue(&qs->rq[qidx]))
			goto alloc_fail;
	}	
	
	/* Alloc completion queue */
	for (qidx = 0; qidx < cq_cnt; qidx++) {
		if (nicvf_alloc_cmp_queue(nic, &qs->cq[qidx]))
			goto alloc_fail;
	}	
	
	/* Alloc send queue */
	for (qidx = 0; qidx < sq_cnt; qidx++) {
		if (nicvf_alloc_snd_queue(nic, &qs->sq[qidx]))
			goto alloc_fail;
	}

	return 0;
alloc_fail:
	nicvf_free_resources(nic);
	return -ENOMEM;
}

int nicvf_config_data_transfer(struct nicvf *nic, bool enable)
{
	bool disable = false;
	struct queue_set *qs;
	
	if (enable) {
		if (!(qs = kzalloc(sizeof(struct queue_set), GFP_ATOMIC)))
			return -ENOMEM;
	
		qs->vnic_id = nic->vnic_id;
		nic->qs = qs;
		if (nicvf_alloc_resources(nic, DEFAULT_RCV_QUEUE_CNT, 
			DEFAULT_CMP_QUEUE_CNT, DEFAULT_SND_QUEUE_CNT, DEFAULT_RBDR_CNT))
			return -ENOMEM;

		nicvf_cmp_queue_config(nic, qs, enable);
		nicvf_rbdr_config(nic, qs, enable);
		nicvf_rcv_queue_config(nic, qs, enable);
		nicvf_snd_queue_config(nic, qs, enable);

	} else {
		if (!(qs = nic->qs))
			return 0;
		nicvf_cmp_queue_config(nic, qs, disable);
		nicvf_rbdr_config(nic, qs, disable);
		nicvf_rcv_queue_config(nic, qs, disable);
		nicvf_snd_queue_config(nic, qs, disable);
		
		nicvf_free_resources(nic); 
	}

	return 0;
}

/* 
 * Check for errors in the cmp.queue entry 
 */
int nicvf_cq_check_errs (struct nicvf *nic, void *cq_desc)
{
	uint32_t ret = false;
	struct cqe_rx_t *cqe_rx;

	cqe_rx = (struct cqe_rx_t *)cq_desc;
	if (cqe_rx->err_level || cqe_rx->err_opcode)
		ret = true;
		
	return ret;
}

/*
 * Get a free desc from send queue
 * @qs:   Qset from which to get a SQ descriptor
 * @qnum: SQ number (0...7) in the Qset
 *
 * returns descriptor ponter & descriptor number 
 */ 
int nicvf_get_sq_desc (struct queue_set *qs, int qnum, void **desc) 
{
	int qentry;
	struct snd_queue *sq = &qs->sq[qnum];

	if ((!sq->free_cnt) || (sq->head == sq->tail))
		return 0;

	qentry = sq->head++;
	sq->free_cnt--;
	if (sq->head == sq->desc_mem.q_len) {
		sq->head = 0;
	}
	*desc = sq->desc_mem.base + (qentry * SND_QUEUE_DESC_SIZE);
	return qentry;
}

void nicvf_put_sq_desc (struct queue_set *qs, int sq_idx, int desc_cnt) 
{
	struct snd_queue *sq = &qs->sq[sq_idx];

	while (desc_cnt--) {
		sq->free_cnt++;
		sq->tail++;
		if (sq->tail == sq->desc_mem.q_len) 
			sq->tail = 0;
	}
}

static int nicvf_sq_subdesc_required (struct nicvf *nic, struct sk_buff *skb)
{
	int subdesc_cnt = MIN_SND_QUEUE_DESC_FOR_PKT_XMIT;

	if (skb_shinfo(skb)->nr_frags)
		subdesc_cnt += skb_shinfo(skb)->nr_frags;

#ifdef VNIC_TX_CSUM_OFFLOAD_SUPPORT
	if (skb->ip_summed == CHECKSUM_PARTIAL) {
		if (skb->protocol == htons(ETH_P_IP))
			subdesc_cnt++;
		if ((ip_hdr(skb)->protocol == IPPROTO_TCP) || 
			(ip_hdr(skb)->protocol == IPPROTO_UDP))
			subdesc_cnt++;
	}
#endif

	return subdesc_cnt;
}

/* 
 * Add SQ HEADER subdescriptor.
 * First subdescriptor for every send descriptor.
 */
struct sq_hdr_subdesc *
nicvf_sq_add_hdr_subdesc (struct queue_set *qs, int sq_num, 
				int subdesc_cnt, struct sk_buff *skb)
{
	void *desc;
	struct sq_hdr_subdesc *hdr;
	
	nicvf_get_sq_desc(qs, sq_num, &desc);
	hdr = (struct sq_hdr_subdesc *) desc;
	
	memset(hdr, 0, SND_QUEUE_DESC_SIZE); /* TBD: Need to remove these memset */
	hdr->subdesc_type = SQ_DESC_TYPE_HEADER;
	hdr->post_cqe = 1;
	hdr->subdesc_cnt = subdesc_cnt;
	hdr->tot_len = skb->len;

#ifdef VNIC_HW_TSO_SUPPORT	
	if (!skb_shinfo(skb)->gso_size)
		return hdr;

	/* Packet to be subjected to TSO */
	hdr->tso = 1;
	hdr->tso_l4_offset = (int)(skb_transport_header(skb) - skb->data) +
                                tcp_hdrlen(skb);
	hdr->tso_max_paysize = skb_shinfo(skb)->gso_size + hdr->tso_l4_offset;
	/* TBD: These fields have to be setup properly */
	hdr->tso_sdc_first = hdr->tso_sdc_cont = 0
	hdr->tso_flags_first = hdr->tso_flags_last = 0;
#endif

	return hdr;
}

/* 
 * SQ GATHER subdescriptor 
 * Must follow HDR descriptor
 */
void nicvf_sq_add_gather_subdesc (struct nicvf *nic, struct queue_set *qs,
						int sq_num, struct sk_buff *skb)
{
	int i;
	int qentry;
	void *desc;
	struct sq_gather_subdesc *gather;
	struct snd_queue *sq;
	
	sq = &qs->sq[sq_num];
	qentry = nicvf_get_sq_desc(qs, sq_num, &desc); 
	gather = (struct sq_gather_subdesc *) desc;
	
	memset(gather, 0, SND_QUEUE_DESC_SIZE);
	gather->subdesc_type = SQ_DESC_TYPE_GATHER;
	gather->ld_type = 1;
	gather->size = skb_is_nonlinear(skb) ? skb_headlen(skb) : skb->len;
	gather->addr = pci_map_single(nic->pdev, skb->data, 
				gather->size, PCI_DMA_TODEVICE);

	sq->skbuff[qentry] = (uint64_t)skb;

	if (!skb_is_nonlinear(skb))
		return;
	
	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		const struct skb_frag_struct *frag;

		frag = &skb_shinfo(skb)->frags[i];

		nicvf_get_sq_desc(qs, sq_num, &desc);
		gather = (struct sq_gather_subdesc *) desc;

		memset(gather, 0, SND_QUEUE_DESC_SIZE);
		gather->subdesc_type = SQ_DESC_TYPE_GATHER;
		gather->ld_type = 1;
		gather->size = skb_frag_size(frag);
		gather->addr = pci_map_single(nic->pdev, skb_frag_address(frag),
						gather->size, PCI_DMA_TODEVICE);
	}
}

static void nicvf_fill_l3_crc_subdesc (struct sq_crc_subdesc *l3, 
					struct sk_buff *skb)
{
	int crc_pos;

	crc_pos = skb_network_header(skb) - skb_mac_header(skb);
	crc_pos += offsetof(struct iphdr, check);

	l3->subdesc_type = SQ_DESC_TYPE_CRC;
	l3->crc_alg = SEND_CRCALG_CRC32;
	l3->crc_insert_pos = crc_pos; 
	l3->hdr_start = skb_network_offset(skb); 
	l3->crc_len = skb_transport_header(skb) - skb_network_header(skb);
	l3->crc_ival = 0;
}

static void nicvf_fill_l4_crc_subdesc (struct sq_crc_subdesc *l4, 
					struct sk_buff *skb)
{
	l4->subdesc_type = SQ_DESC_TYPE_CRC;
	l4->crc_alg = SEND_CRCALG_CRC32;
	l4->crc_insert_pos = skb->csum_start + skb->csum_offset; 
	l4->hdr_start = skb->csum_start; 
	l4->crc_len = skb->len - skb_transport_offset(skb);
	l4->crc_ival = 0;
}

/* 
 * SQ CRC subdescriptor
 * Must follow HDR and precede GATHER, IMM subdescriptors
 */
void nicvf_sq_add_crc_subdesc (struct nicvf *nic, struct queue_set *qs,
				int sq_num, struct sk_buff *skb)
{
	int proto;
	void *desc;
	struct sq_crc_subdesc *crc;
	struct snd_queue *sq;
	
	if (skb->ip_summed != CHECKSUM_PARTIAL)
		return;

	if (skb->protocol != htons(ETH_P_IP))
		return;

        sq = &qs->sq[sq_num];
        nicvf_get_sq_desc(qs, sq_num, &desc);

        crc = (struct sq_crc_subdesc *) desc;
                        
	nicvf_fill_l3_crc_subdesc(crc, skb);

	proto = ip_hdr(skb)->protocol;
	if ((proto == IPPROTO_TCP) || (proto == IPPROTO_UDP)) {
		nicvf_get_sq_desc(qs, sq_num, &desc);
		crc = (struct sq_crc_subdesc *) desc;
		nicvf_fill_l4_crc_subdesc(crc, skb);
	}
}

/*
 * Append an skb to a SQ for packet transfer.  
 */
int nicvf_sq_append_skb (struct nicvf *nic, struct sk_buff *skb)
{
	int subdesc_cnt;
	int sq_num;
	struct queue_set *qs = nic->qs;
	struct snd_queue *sq;
	struct sq_hdr_subdesc *hdr_desc;

	sq_num = 0; 
	sq = &qs->sq[sq_num];

	subdesc_cnt = nicvf_sq_subdesc_required(nic, skb);

	if (subdesc_cnt > sq->free_cnt)
		goto append_fail;

	/* Add SQ header subdesc */
	hdr_desc = nicvf_sq_add_hdr_subdesc(qs, sq_num, subdesc_cnt - 1, skb);

#ifdef VNIC_TX_CSUM_OFFLOAD_SUPPORT
	/* Add CRC subdescriptor for IP/TCP/UDP (L3/L4) crc calculation */
	if (skb->ip_summed == CHECKSUM_PARTIAL)
		nicvf_sq_add_crc_subdesc(nic, qs, sq_num, skb);
#endif

	/* Add SQ gather subdesc */	
	nicvf_sq_add_gather_subdesc(nic, qs, sq_num, skb);

	/* Inform HW to xmit new packet */
	nicvf_queue_reg_write(nic, NIC_QSET_SQ_0_7_DOOR, 
						sq_num, subdesc_cnt);
	return 1;

append_fail:
	nic_dbg(&nic->pdev->dev, "Not enough SQ descriptors to xmit pkt\n");	
	return 0;
}

struct sk_buff *nicvf_get_rcv_skb (struct nicvf *nic, void *cq_desc)
{
	int frag;
	int payload_len = 0;
	struct sk_buff *skb = NULL;
	struct sk_buff *skb_frag = NULL;
	struct sk_buff *prev_frag = NULL;
	struct cqe_rx_t *cqe_rx;
	struct rbdr *rbdr;
	struct rcv_queue *rq;
	struct queue_set *qs = nic->qs;
	uint16_t *rb_lens = NULL;
	uint64_t *rb_ptrs = NULL;

	cqe_rx = (struct cqe_rx_t *)cq_desc;

	rq = &qs->rq[cqe_rx->rq_idx];
	rbdr = &qs->rbdr[rq->start_qs_rbdr_idx];
	rb_lens = cq_desc + (3 * sizeof(uint64_t)); /* Use offsetof */
	rb_ptrs = cq_desc + (6 * sizeof(uint64_t));
	nic_dbg(&nic->pdev->dev, "%s rb_cnt %d rb0_ptr %llx rb0_sz %d\n", 
		__FUNCTION__, cqe_rx->rb_cnt, cqe_rx->rb0_ptr, cqe_rx->rb0_sz);

	for (frag = 0; frag < cqe_rx->rb_cnt; frag++) {
		payload_len = *rb_lens;
		if (!frag) { 
			skb = nicvf_rb_ptr_to_skb(*rb_ptrs);
			skb_put (skb, payload_len);
			/* First fragment */
			pci_unmap_single(nic->pdev, (dma_addr_t)skb->data, rbdr->buf_size, PCI_DMA_FROMDEVICE);
		} else {
			/* Add fragments */
			skb_frag = nicvf_rb_ptr_to_skb(*rb_ptrs);
			pci_unmap_single(nic->pdev, (dma_addr_t)skb_frag->data, rbdr->buf_size, PCI_DMA_FROMDEVICE);

			if (!skb_shinfo(skb)->frag_list) 
				skb_shinfo(skb)->frag_list = skb_frag;
			else
				prev_frag->next = skb_frag; 

			prev_frag = skb_frag;
			skb->len += payload_len;
			skb->data_len += payload_len;
			skb_frag->len = payload_len;
			skb_shinfo(skb)->nr_frags++;
		}
		/* Next buffer pointer */
		rb_lens++;
		rb_ptrs++;
	}

	return skb;
}

/*
 * Enable interrupt
 */
void nicvf_enable_intr (struct nicvf *nic, int int_type, int q_idx)
{
	uint64_t reg_val;
		
	reg_val = nicvf_qset_reg_read(nic, NIC_VF_ENA_W1S);
	
	switch (int_type) {
	case NICVF_INTR_CQ:
		reg_val |= ((1ULL << q_idx) << NICVF_INTR_CQ_SHIFT);
	break;
	case NICVF_INTR_SQ:
		reg_val |= ((1ULL << q_idx) << NICVF_INTR_SQ_SHIFT);
	break;
	case NICVF_INTR_RBDR:
		reg_val |= ((1ULL << q_idx) << NICVF_INTR_RBDR_SHIFT);
	break;
	case NICVF_INTR_PKT_DROP:
		reg_val |= (1ULL << NICVF_INTR_PKT_DROP_SHIFT);
	break;
	case NICVF_INTR_TCP_TIMER:
		reg_val |= (1ULL << NICVF_INTR_TCP_TIMER_SHIFT);
	break;
	case NICVF_INTR_MBOX:
		reg_val |= (1ULL << NICVF_INTR_MBOX_SHIFT);
	break;
	case NICVF_INTR_QS_ERR:
		reg_val |= (1ULL << NICVF_INTR_QS_ERR_SHIFT);
	break;
	default:
		netdev_err(nic->netdev, "Failed to enable interrupt: unknown interrupt type\n");	
	break;
	}

	nicvf_qset_reg_write(nic, NIC_VF_ENA_W1S, reg_val);
}

/*
 * Disable interrupt
 */
void nicvf_disable_intr (struct nicvf *nic, int int_type, int q_idx)
{
	uint64_t reg_val = 0;
		
	switch (int_type) {
	case NICVF_INTR_CQ:
		reg_val |= ((1ULL << q_idx) << NICVF_INTR_CQ_SHIFT);
	break;
	case NICVF_INTR_SQ:
		reg_val |= ((1ULL << q_idx) << NICVF_INTR_SQ_SHIFT);
	break;
	case NICVF_INTR_RBDR:
		reg_val |= ((1ULL << q_idx) << NICVF_INTR_RBDR_SHIFT);
	break;
	case NICVF_INTR_PKT_DROP:
		reg_val |= (1ULL << NICVF_INTR_PKT_DROP_SHIFT);
	break;
	case NICVF_INTR_TCP_TIMER:
		reg_val |= (1ULL << NICVF_INTR_TCP_TIMER_SHIFT);
	break;
	case NICVF_INTR_MBOX:
		reg_val |= (1ULL << NICVF_INTR_MBOX_SHIFT);
	break;
	case NICVF_INTR_QS_ERR:
		reg_val |= (1ULL << NICVF_INTR_QS_ERR_SHIFT);
	break;
	default:
		netdev_err(nic->netdev, "Failed to disable interrupt: unknown interrupt type\n");	
	break;
	}

	nicvf_qset_reg_write(nic, NIC_VF_ENA_W1C, reg_val);
}

/*
 * Clear interrupt
 */
void nicvf_clear_intr (struct nicvf *nic, int int_type, int q_idx)
{
	uint64_t reg_val = 0;
		
	switch (int_type) {
	case NICVF_INTR_CQ:
		reg_val = ((1ULL << q_idx) << NICVF_INTR_CQ_SHIFT);
	break;
	case NICVF_INTR_SQ:
		reg_val = ((1ULL << q_idx) << NICVF_INTR_SQ_SHIFT);
	break;
	case NICVF_INTR_RBDR:
		reg_val = ((1ULL << q_idx) << NICVF_INTR_RBDR_SHIFT);
	break;
	case NICVF_INTR_PKT_DROP:
		reg_val = (1ULL << NICVF_INTR_PKT_DROP_SHIFT);
	break;
	case NICVF_INTR_TCP_TIMER:
		reg_val = (1ULL << NICVF_INTR_TCP_TIMER_SHIFT);
	break;
	case NICVF_INTR_MBOX:
		reg_val = (1ULL << NICVF_INTR_MBOX_SHIFT);
	break;
	case NICVF_INTR_QS_ERR:
		reg_val |= (1ULL << NICVF_INTR_QS_ERR_SHIFT);
	break;
	default:
		netdev_err(nic->netdev, "Failed to clear interrupt: unknown interrupt type\n");	
	break;
	}

	nicvf_qset_reg_write(nic, NIC_VF_INT, reg_val);
}

/*
 * Check if interrupt is enabled
 */
int nicvf_is_intr_enabled (struct nicvf *nic, int int_type, int q_idx)
{
	uint64_t reg_val;
	uint64_t mask = 0xff;
		
	reg_val = nicvf_qset_reg_read(nic, NIC_VF_ENA_W1S);
	
	switch (int_type) {
	case NICVF_INTR_CQ:
		mask = ((1ULL << q_idx) << NICVF_INTR_CQ_SHIFT);
	break;
	case NICVF_INTR_SQ:
		mask = ((1ULL << q_idx) << NICVF_INTR_SQ_SHIFT);
	break;
	case NICVF_INTR_RBDR:
		mask = ((1ULL << q_idx) << NICVF_INTR_RBDR_SHIFT);
	break;
	case NICVF_INTR_PKT_DROP:
		mask = NICVF_INTR_PKT_DROP_MASK;
	break;
	case NICVF_INTR_TCP_TIMER:
		mask = NICVF_INTR_TCP_TIMER_MASK;
	break;
	case NICVF_INTR_MBOX:
		mask = NICVF_INTR_MBOX_MASK;
	break;
	case NICVF_INTR_QS_ERR:
		mask = NICVF_INTR_QS_ERR_MASK;
	break;
	default:
		netdev_err(nic->netdev, "Failed to check interrupt enable: \
						unknown interrupt type\n");	
	break;
	}

	return (reg_val & mask);
}
