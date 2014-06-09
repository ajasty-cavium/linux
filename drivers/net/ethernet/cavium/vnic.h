/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 * 
 * Copyright (C) 2013 Cavium, Inc. 
 */

#ifndef VNIC_H
#define VNIC_H

#include <linux/netdevice.h>
#include <linux/interrupt.h>

#define 	MAX_NUM_VFS_SUPPORTED    128 /* Including VF0 which is PF */
#define 	DEFAULT_NUM_VF_ENABLED   8

/* VNIC priv flags */
#define         VNIC_SRIOV_ENABLED  (1 << 0)

#define		VNIC_VFID_PF	0

/* VNIC HW optimiation features */
#define 	VNIC_RX_CSUM_ENABLE    (1 << 0)
#define 	VNIC_TX_CSUM_ENABLE    (1 << 1)
#define 	VNIC_LRO_ENABLE	       (1 << 2)
#define 	VNIC_SG_ENABLE	       (1 << 3)
#define 	VNIC_TSO_ENABLE	       (1 << 4)

/* TSO not supported in Thunder pass1 */
#define 	VNIC_HW_TSO_NOT_SUPPORTED


/* ETHTOOL enable or disable, undef this to disable */
#define 	VNIC_ETHTOOL_ENABLE

/* NAPI enable or disable, undef this to disable */
#define		VNIC_NAPI_ENABLE      

/* Min/Max packet size */
#define		VNIC_MIN_MTU_SUPPORTED    64
#define		VNIC_MAX_MTU_SUPPORTED    1500

/* Max pkinds */
#define 	VNIC_MAX_PKIND            16

/* Channels */
#define		VNIC_MAX_CHANNELS	  256

/* VNIC Interrupts */
#define 	VNIC_INTR_CQ		 0
#define 	VNIC_INTR_SQ		 1
#define 	VNIC_INTR_RBDR		 2
#define 	VNIC_INTR_PKT_DROP	 3
#define 	VNIC_INTR_TCP_TIMER	 4
#define 	VNIC_INTR_MBOX		 5
#define 	VNIC_INTR_QS_ERR	 6

#define 	VNIC_INTR_CQ_SHIFT	   0	
#define		VNIC_INTR_SQ_SHIFT   	   8
#define		VNIC_INTR_RBDR_SHIFT   	   16
#define		VNIC_INTR_PKT_DROP_SHIFT   20
#define		VNIC_INTR_TCP_TIMER_SHIFT  21
#define		VNIC_INTR_MBOX_SHIFT	   22
#define		VNIC_INTR_QS_ERR_SHIFT	   23
	
#define		VNIC_INTR_CQ_MASK	 (0xFF << VNIC_INTR_CQ_SHIFT)
#define		VNIC_INTR_SQ_MASK	 (0xFF << VNIC_INTR_SQ_SHIFT)
#define		VNIC_INTR_RBDR_MASK	 (0x03 << VNIC_INTR_RBDR_SHIFT)
#define		VNIC_INTR_PKT_DROP_MASK  (1 << VNIC_INTR_PKT_DROP_SHIFT)
#define		VNIC_INTR_TCP_TIMER_MASK (1 << VNIC_INTR_TCP_TIMER_SHIFT)
#define		VNIC_INTR_MBOX_MASK	 (1 << VNIC_INTR_MBOX_SHIFT)
#define		VNIC_INTR_QS_ERR_MASK	 (1 << VNIC_INTR_QS_ERR_SHIFT)

/* VF MSI-X interrupts */
#define 	VNIC_PF_MSIX_VECTORS      	10
#define 	VNIC_VF_MSIX_VECTORS      	20

#define 	VNIC_VF_CQ_INTR_ID	   	0
#define 	VNIC_VF_SQ_INTR_ID	   	8
#define 	VNIC_VF_RBDR_INTR_ID		16
#define 	VNIC_VF_MISC_INTR_ID	   	18
#define 	VNIC_VF_QS_ERR_INTR_ID		19

#define for_each_cq_irq(irq) for (irq = VNIC_VF_CQ_INTR_ID; \
					irq < VNIC_VF_SQ_INTR_ID; irq++)
#define for_each_sq_irq(irq) for (irq = VNIC_VF_SQ_INTR_ID; \
					irq < VNIC_VF_RBDR_INTR_ID; irq++)
#define for_each_rbdr_irq(irq) for (irq = VNIC_VF_RBDR_INTR_ID; \
					irq < VNIC_VF_MISC_INTR_ID; irq++)

struct vnic_cq_poll {
	uint8_t	cq_idx;		/* Completion queue index */
	struct napi_struct napi;
};

struct vnic_vf {
	uint8_t            vnic_id;
	struct             vnic_queue_set *qs;  /* Queue set this VNIC is pointing to */
	uint8_t            num_qs;              /* No of QSs assigned to this VNIC */
	void               *addnl_qs;           /* Pointer to QSs additional to default 1 QS */
	uint16_t           vf_mtu;
	struct pci_dev     *pdev;
	uint64_t           reg_base;            /* Register start address */
	struct tasklet_struct	rbdr_task;	/* Tasklet to refill RBDR */
	struct tasklet_struct	qs_err_task;	/* Tasklet to handle Qset err */
#ifdef VNIC_NAPI_ENABLE
	struct vnic_cq_poll *napi[8];		/* NAPI */
#endif
	/* MSI-X  */
	bool	           msix_enabled;
	uint16_t           num_vec;
	struct msix_entry  msix_entries[VNIC_VF_MSIX_VECTORS];
	char		   irq_name[VNIC_VF_MSIX_VECTORS][20];
	uint8_t		   irq_allocated[VNIC_VF_MSIX_VECTORS];
};

struct vnic_pf {
	unsigned int       flags;
	uint16_t           total_vf_cnt;   /* Total num of VF supported */
	uint16_t           num_vf_en;      /* No of VF enabled */
	struct pci_dev     *pdev;
	uint64_t           reg_base;       /* Register start address */
	/* MSI-X  */
	bool               msix_enabled;
	uint16_t           num_vec;
	struct msix_entry  msix_entries[VNIC_PF_MSIX_VECTORS];
	uint8_t		   irq_allocated[VNIC_PF_MSIX_VECTORS];
};

struct vnic {
	struct net_device  *netdev;
	struct pci_dev     *pdev;
	uint16_t	   mtu;
	uint16_t	   hw_flags;
	struct vnic_vf     *vf;
	struct vnic_pf     *pf;
};

struct vnic_stats {
	struct {
		uint32_t partial_pkts;
		uint32_t jabber_errs;
		uint32_t fcs_errs;
		uint32_t terminate_errs;
		uint32_t bgx_rx_errs;
		uint32_t prel2_errs;
		uint32_t l2_frags;
		uint32_t l2_overruns;
		uint32_t l2_pfcs;
		uint32_t l2_puny;
		uint32_t l2_mal;
		uint32_t l2_oversize;
		uint32_t l2_len_mismatch;
		uint32_t l2_pclp;
		uint32_t not_ip;
		uint32_t ip_csum_err;
		uint32_t ip_mal;
		uint32_t ip_mal_payload;
		uint32_t ip_hop;
		uint32_t l3_icrc;
		uint32_t l3_pclp;
		uint32_t l4_mal;
		uint32_t l4_csum_err;
		uint32_t udp_len_err;
		uint32_t bad_l4_port;
		uint32_t bad_tcp_flag;
		uint32_t tcp_offset_err;
		uint32_t l4_pclp;
		uint32_t no_rbdr;
	}rx;
	struct {
	}tx;
};

/*
 * PF <--> Mailbox communication 
 * Eight 64bit registers are shared between PF and VF.
 * Separate set for each VF.
 * Writing '1' into last register mbx7 means end of message.
 */

/* PF <--> VF mailbox communication */
#define  	VNIC_PF_VF_MAILBOX_SIZE     8

/* Mailbox message types */
#define		VNIC_PF_VF_MSG_CLEAR        0x00
#define		VNIC_PF_VF_MSG_READY        0x01 /* Check if PF is ready to rcv messages */
#define		VNIC_PF_VF_MSG_ACK          0x02 /* ACK the message received */
#define		VNIC_PF_VF_MSG_QS_CFG       0x03 /* Configure Qset */
#define		VNIC_PF_VF_MSG_RQ_CFG       0x04 /* Configure receive queue */
#define		VNIC_PF_VF_MSG_SQ_CFG       0x05 /* Configure Send queue */
#define		VNIC_PF_VF_MSG_SET_MAC      0x06 /* Add VF's MAC ID into BGX's DMAC filter */

struct vnic_mbx {
	uint64_t	   msg;
	union	{
		struct {			/* Qset configuration */
			uint64_t   num;
			uint64_t   cfg;
		}qs;
		struct {			/* Receive queue configuration */
			uint64_t   qs_num;
			uint64_t   rq_num;
			uint64_t   cfg;
		}rq;
		struct {			/* Send queue configuration */
			uint64_t   qs_num;
			uint64_t   sq_num;
			uint64_t   cfg;
		}sq;
		struct {			/* VF's MAC address */
			uint64_t   vnic_id;
			uint64_t   addr;
		}mac;
	}data;
	uint64_t	   mbx4;
	uint64_t	   mbx5;
	uint64_t	   mbx6;
	uint64_t	   mbx_trigger_intr;
};

/*
 * Stats 
 */
 
#ifdef VNIC_ETHTOOL_ENABLE
/* Tx statistics */
struct vnic_tx_stats {
	u64 tx_frames_ok;
	u64 tx_unicast_frames_ok;
	u64 tx_multicast_frames_ok;
	u64 tx_broadcast_frames_ok;
	u64 tx_bytes_ok;
	u64 tx_unicast_bytes_ok;
	u64 tx_multicast_bytes_ok;
	u64 tx_broadcast_bytes_ok;
	u64 tx_drops;
	u64 tx_errors;
	u64 tx_tso;
	u64 rsvd[16];
};

/* Rx statistics */
struct vnic_rx_stats {
	u64 rx_frames_ok;
	u64 rx_frames_total;
	u64 rx_unicast_frames_ok;
	u64 rx_multicast_frames_ok;
	u64 rx_broadcast_frames_ok;
	u64 rx_bytes_ok;
	u64 rx_unicast_bytes_ok;
	u64 rx_multicast_bytes_ok;
	u64 rx_broadcast_bytes_ok;
	u64 rx_drop;
	u64 rx_no_bufs;
	u64 rx_errors;
	u64 rx_rss;
	u64 rx_crc_errors;
	u64 rx_frames_64;
	u64 rx_frames_127;
	u64 rx_frames_255;
	u64 rx_frames_511;
	u64 rx_frames_1023;
	u64 rx_frames_1518;
	u64 rx_frames_to_max;
	u64 rsvd[16];
};

struct eth_stats {
	struct vnic_tx_stats tx;
	struct vnic_rx_stats rx;
};

void vnic_set_ethtool_ops(struct net_device *netdev);
#endif

struct vnic_mbx *vnic_get_mbx (void);
void vnic_send_msg_to_pf (struct vnic_vf *vf, struct vnic_mbx *mbx);


#endif /* VNIC_H */
