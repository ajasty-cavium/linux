/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 * 
 * Copyright (C) 2013 Cavium, Inc. 
 */

#ifndef VNIC_QUEUES_H
#define VNIC_QUEUES_H

#include "q_struct.h"

#define    MAX_QUEUE_SET			128
#define    MAX_RCV_QUEUES_PER_QS 		8
#define    MAX_SND_QUEUES_PER_QS		8
#define    MAX_CMP_QUEUES_PER_QS		8
#define    MAX_RCV_BUF_DESC_RINGS_PER_QS	2

#define    SND_QUEUE_SIZE0	 0ULL /* 1K entries */   
#define    SND_QUEUE_SIZE1	 1ULL /* 2K entries */   
#define    SND_QUEUE_SIZE2	 2ULL /* 4K entries */   
#define    SND_QUEUE_SIZE3	 3ULL /* 8K entries */   
#define    SND_QUEUE_SIZE4	 4ULL /* 16K entries */   
#define    SND_QUEUE_SIZE5	 5ULL /* 32K entries */   
#define    SND_QUEUE_SIZE6	 6ULL /* 64K entries */   

#define    DEFAULT_SND_QUEUE_LEN  	 (1ULL << (SND_QUEUE_SIZE0 + 10))
#define    DEFAULT_SND_QUEUE_THRESH	  2ULL

#define    COMPLETION_QUEUE_SIZE0	 0ULL /* 1K entries */   
#define    COMPLETION_QUEUE_SIZE1	 1ULL /* 2K entries */   
#define    COMPLETION_QUEUE_SIZE2	 2ULL /* 4K entries */   
#define    COMPLETION_QUEUE_SIZE3	 3ULL /* 8K entries */   
#define    COMPLETION_QUEUE_SIZE4	 4ULL /* 16K entries */   
#define    COMPLETION_QUEUE_SIZE5	 5ULL /* 32K entries */   
#define    COMPLETION_QUEUE_SIZE6	 6ULL /* 64K entries */   

#define    DEFAULT_CMP_QUEUE_LEN         (1ULL << (COMPLETION_QUEUE_SIZE0 + 10))
#define    DEFAULT_CMP_QUEUE_THRESH	  0

#define    RBDR_SIZE0	 0ULL /* 8K entries */   
#define    RBDR_SIZE1	 1ULL /* 16K entries */   
#define    RBDR_SIZE2	 2ULL /* 32K entries */   
#define    RBDR_SIZE3	 3ULL /* 64K entries */   
#define    RBDR_SIZE4	 4ULL /* 126K entries */   
#define    RBDR_SIZE5	 5ULL /* 256K entries */   
#define    RBDR_SIZE6	 6ULL /* 512K entries */   

#define    DEFAULT_RBDR_THRESH	  	 2048
#define    DEFAULT_RCV_BUF_COUNT  	 (1ULL << (RBDR_SIZE0 + 13) )
#define    DEFAULT_RCV_BUFFER_LEN	 2048 /* Should be multiples of 128bytes */

/* Descriptor size */
#define    SND_QUEUE_DESC_SIZE		16   /* 128 bits */
#define    CMP_QUEUE_DESC_SIZE		512

/* Buffer / descriptor alignments */
#define    VNIC_RCV_BUF_ALIGN		7 
#define    VNIC_RCV_BUF_ALIGN_BYTES	(1ULL << VNIC_RCV_BUF_ALIGN) 
#define    VNIC_CQ_BASE_ALIGN_BYTES	512  /* 9 bits */
#define    VNIC_SQ_BASE_ALIGN_BYTES	128  /* 7 bits */

#define    VNIC_ALIGNED_ADDR(ADDR, ALIGN_BYTES)		ALIGN(ADDR, ALIGN_BYTES)
#define    VNIC_ADDR_ALIGN_LEN(ADDR, BYTES) 	(VNIC_ALIGNED_ADDR(ADDR, BYTES) - BYTES)
#define    VNIC_RCV_BUF_ALIGN_LEN(X)		(VNIC_ALIGNED_ADDR(X, VNIC_RCV_BUF_ALIGN_BYTES) - X)

struct vnic_desc_mem {
	dma_addr_t	dma;
	uint64_t	size;
	uint16_t	q_len;
	void		*base;
	void		*unalign_base;
};

struct vnic_rbdr {
	bool		enable;
	uint32_t	buf_size;
	uint32_t	thresh;      /* Threshold level for interrupt */
	struct vnic_desc_mem   desc_mem;
	struct rbdr_entry_t    *desc[DEFAULT_RCV_BUF_COUNT];
};

struct vnic_rcv_queue {
	struct	vnic_rbdr  *rbdr_start;
	struct	vnic_rbdr  *rbdr_cont;
	bool	en_tcp_reassembly;
	uint8_t cq_qs;  /* CQ's QS to which this RQ is assigned */
	uint8_t cq_idx; /* CQ index (0 to 7) in the QS */
	uint8_t cont_rbdr_qs;      /* Continue buffer pointers - QS num */ 
	uint8_t cont_qs_rbdr_idx;  /* RBDR idx in the cont QS */
	uint8_t start_rbdr_qs;     /* First buffer pointers - QS num */
	uint8_t start_qs_rbdr_idx; /* RBDR idx in the above QS */
};

struct vnic_cmp_queue {
	struct vnic_desc_mem   desc_mem;
	uint8_t   intr_timer_thresh;
	uint16_t  thresh;
};

struct vnic_sq_desc {
	bool   free;
	struct vnic_sq_desc  *next;
};

struct vnic_snd_queue {
	struct vnic_desc_mem   desc_mem;
	uint8_t   cq_qs;  /* CQ's QS to which this SQ is pointing */
	uint8_t   cq_idx; /* CQ index (0 to 7) in the above QS */
	uint16_t  free_cnt;
	uint64_t  head;
	uint64_t  tail;
	uint64_t *skbuff;
};

struct vnic_queue_set {
	bool      enabled;
	bool      be_en;
	uint8_t   vnic_id;
	uint8_t   rq_cnt;
	struct	  vnic_rcv_queue rq[MAX_RCV_QUEUES_PER_QS];
	uint8_t   cq_cnt;
	struct    vnic_cmp_queue cq[MAX_CMP_QUEUES_PER_QS];
	uint8_t   sq_cnt;
	struct    vnic_snd_queue sq[MAX_SND_QUEUES_PER_QS];
	uint8_t   rbdr_cnt;
	struct    vnic_rbdr rbdr[MAX_RCV_BUF_DESC_RINGS_PER_QS];
};

int vnic_vf_config_data_transfer(struct vnic *vnic, struct vnic_vf *vf, bool enable);
int vnic_get_sq_desc (struct vnic_queue_set *qs, int qnum, void **desc); 
void vnic_put_sq_desc (struct vnic_queue_set *qs, int sq_idx, int desc_cnt); 
int vnic_sq_append_skb (struct vnic *vnic, struct sk_buff *skb);

int vnic_cq_check_errs (struct vnic *vnic, void *cq_desc);
struct sk_buff *vnic_get_rcv_skb (struct vnic *vnic, 
				struct vnic_queue_set *qs, void *cq_desc);
void vnic_refill_rbdr (unsigned long data);

void vnic_enable_intr (struct vnic *vnic, int int_type, int q_idx);
void vnic_disable_intr (struct vnic *vnic, int int_type, int q_idx);
void vnic_clear_intr (struct vnic *vnic, int int_type, int q_idx);
#endif /* VNIC_QUEUES_H */
