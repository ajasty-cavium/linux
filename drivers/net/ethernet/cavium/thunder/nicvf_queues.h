/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 * 
 * Copyright (C) 2013 Cavium, Inc. 
 */

#ifndef NICVF_QUEUES_H
#define NICVF_QUEUES_H

#include "q_struct.h"

#define    MAX_QUEUE_SET			128
#define    MAX_RCV_QUEUES_PER_QS 		8
#define    MAX_RCV_BUF_DESC_RINGS_PER_QS	2
#define    MAX_SND_QUEUES_PER_QS		8
#define    MAX_CMP_QUEUES_PER_QS		8

#define    RBDR_SIZE0	 0ULL /* 8K entries */   
#define    RBDR_SIZE1	 1ULL /* 16K entries */   
#define    RBDR_SIZE2	 2ULL /* 32K entries */   
#define    RBDR_SIZE3	 3ULL /* 64K entries */   
#define    RBDR_SIZE4	 4ULL /* 126K entries */   
#define    RBDR_SIZE5	 5ULL /* 256K entries */   
#define    RBDR_SIZE6	 6ULL /* 512K entries */   

#define    SND_QUEUE_SIZE0	 0ULL /* 1K entries */   
#define    SND_QUEUE_SIZE1	 1ULL /* 2K entries */   
#define    SND_QUEUE_SIZE2	 2ULL /* 4K entries */   
#define    SND_QUEUE_SIZE3	 3ULL /* 8K entries */   
#define    SND_QUEUE_SIZE4	 4ULL /* 16K entries */   
#define    SND_QUEUE_SIZE5	 5ULL /* 32K entries */   
#define    SND_QUEUE_SIZE6	 6ULL /* 64K entries */   

#define    CMP_QUEUE_SIZE0	 0ULL /* 1K entries */   
#define    CMP_QUEUE_SIZE1	 1ULL /* 2K entries */   
#define    CMP_QUEUE_SIZE2	 2ULL /* 4K entries */   
#define    CMP_QUEUE_SIZE3	 3ULL /* 8K entries */   
#define    CMP_QUEUE_SIZE4	 4ULL /* 16K entries */   
#define    CMP_QUEUE_SIZE5	 5ULL /* 32K entries */   
#define    CMP_QUEUE_SIZE6	 6ULL /* 64K entries */   

/* Default queue count per QS, its lengths and threshold values */
#define    RBDR_CNT		1
#define    RCV_QUEUE_CNT	1
#define    SND_QUEUE_CNT	8
#define    CMP_QUEUE_CNT	8 /* Max of RCV and SND qcount */

#define    SND_QUEUE_LEN	(1ULL << (SND_QUEUE_SIZE0 + 10))
#define    SND_QUEUE_THRESH	2ULL

#define    CMP_QUEUE_LEN	(1ULL << (CMP_QUEUE_SIZE1 + 10))
#define    CMP_QUEUE_THRESH	0

#define    RCV_BUF_COUNT	(1ULL << (RBDR_SIZE0 + 13) )
#define    RBDR_THRESH		2048
#define    RCV_BUFFER_LEN	2048 /* In multiples of 128bytes */

/* Descriptor size */
#define    SND_QUEUE_DESC_SIZE		16   /* 128 bits */
#define    CMP_QUEUE_DESC_SIZE		512

/* Buffer / descriptor alignments */
#define    NICVF_RCV_BUF_ALIGN		7 
#define    NICVF_RCV_BUF_ALIGN_BYTES	(1ULL << NICVF_RCV_BUF_ALIGN) 
#define    NICVF_CQ_BASE_ALIGN_BYTES	512  /* 9 bits */
#define    NICVF_SQ_BASE_ALIGN_BYTES	128  /* 7 bits */

#define    NICVF_ALIGNED_ADDR(ADDR, ALIGN_BYTES)		ALIGN(ADDR, ALIGN_BYTES)
#define    NICVF_ADDR_ALIGN_LEN(ADDR, BYTES) 	(NICVF_ALIGNED_ADDR(ADDR, BYTES) - BYTES)
#define    NICVF_RCV_BUF_ALIGN_LEN(X)		(NICVF_ALIGNED_ADDR(X, NICVF_RCV_BUF_ALIGN_BYTES) - X)

struct q_desc_mem {
	dma_addr_t	dma;
	uint64_t	size;
	uint16_t	q_len;
	dma_addr_t	phys_base;
	void		*base;
	void		*unalign_base;
};

struct rbdr {
	bool		enable;
	uint32_t	buf_size;
	uint32_t	thresh;      /* Threshold level for interrupt */
	struct q_desc_mem   desc_mem;
	struct rbdr_entry_t    *desc[RCV_BUF_COUNT];
};

struct rcv_queue {
	struct	rbdr  *rbdr_start;
	struct	rbdr  *rbdr_cont;
	bool	en_tcp_reassembly;
	uint8_t cq_qs;  /* CQ's QS to which this RQ is assigned */
	uint8_t cq_idx; /* CQ index (0 to 7) in the QS */
	uint8_t cont_rbdr_qs;      /* Continue buffer pointers - QS num */ 
	uint8_t cont_qs_rbdr_idx;  /* RBDR idx in the cont QS */
	uint8_t start_rbdr_qs;     /* First buffer pointers - QS num */
	uint8_t start_qs_rbdr_idx; /* RBDR idx in the above QS */
};

struct cmp_queue {
	struct q_desc_mem   desc_mem;
	uint8_t    intr_timer_thresh;
	uint16_t   thresh;
	spinlock_t cq_lock;  /* lock to serialize processing CQEs */
};

struct sq_desc {
	bool   free;
	struct sq_desc  *next;
};

struct snd_queue {
	struct    q_desc_mem   desc_mem;
	uint8_t   cq_qs;  /* CQ's QS to which this SQ is pointing */
	uint8_t   cq_idx; /* CQ index (0 to 7) in the above QS */
	uint16_t  thresh;
	uint16_t  free_cnt;
	uint64_t  head;
	uint64_t  tail;
	uint64_t  *skbuff;
};

struct queue_set {
	bool      enabled;
	bool      be_en;
	uint8_t   vnic_id;
	uint8_t   rq_cnt;
	struct	  rcv_queue rq[MAX_RCV_QUEUES_PER_QS];
	uint8_t   cq_cnt;
	struct    cmp_queue cq[MAX_CMP_QUEUES_PER_QS];
	uint64_t  cq_len;
	uint8_t   sq_cnt;
	struct    snd_queue sq[MAX_SND_QUEUES_PER_QS];
	uint64_t  sq_len;
	uint8_t   rbdr_cnt;
	struct    rbdr  rbdr[MAX_RCV_BUF_DESC_RINGS_PER_QS];
	uint64_t  rbdr_len;
};

/* CQ status bits */
#define 	CQ_WR_FULL 	(1 << 26)
#define 	CQ_WR_DISABLE 	(1 << 25)
#define 	CQ_WR_FAULT 	(1 << 24)
#define 	CQ_CQE_COUNT 	(0xFFFF << 0)

/* CQ err mask */
#define		CQ_ERR_MASK	(CQ_WR_FULL | CQ_WR_DISABLE | CQ_WR_FAULT)

int nicvf_config_data_transfer(struct nicvf *nic, bool enable);
void nicvf_qset_config (struct nicvf *nic, bool enable);
void nicvf_sq_enable(struct nicvf *nic, struct snd_queue *sq, int qidx);
void nicvf_sq_disable(struct nicvf *nic, int qidx);
void nicvf_put_sq_desc (struct snd_queue *sq, int desc_cnt); 
void nicvf_sq_free_used_descs (struct net_device *netdev, struct snd_queue *sq, int qidx);
int nicvf_sq_append_skb (struct nicvf *nic, struct sk_buff *skb);

int nicvf_cq_check_errs (struct nicvf *nic, void *cq_desc);
struct sk_buff *nicvf_get_rcv_skb (struct nicvf *nic, void *cq_desc);
void nicvf_refill_rbdr (unsigned long data);

void nicvf_enable_intr (struct nicvf *nic, int int_type, int q_idx);
void nicvf_disable_intr (struct nicvf *nic, int int_type, int q_idx);
void nicvf_clear_intr (struct nicvf *nic, int int_type, int q_idx);
int nicvf_is_intr_enabled (struct nicvf *nic, int int_type, int q_idx);

/* Register access APIs */
void nicvf_reg_write (struct nicvf *nic, uint64_t offset, uint64_t val);
uint64_t nicvf_reg_read (struct nicvf *nic, uint64_t offset);

void nicvf_qset_reg_write (struct nicvf *nic, uint64_t offset, uint64_t val);
uint64_t nicvf_qset_reg_read (struct nicvf *nic, uint64_t offset);

void nicvf_queue_reg_write (struct nicvf *nic, uint64_t offset, 
				uint64_t qidx, uint64_t val);
uint64_t nicvf_queue_reg_read (struct nicvf *nic, uint64_t offset, uint64_t qidx);
void nicvf_cmp_queue_config (struct nicvf *nic, struct queue_set *qs, int qidx, bool enable);
#endif /* NICVF_QUEUES_H */
