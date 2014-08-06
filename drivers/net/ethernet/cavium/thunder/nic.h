/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2014 Cavium, Inc.
 */

#ifndef NIC_H
#define	NIC_H

#include <linux/netdevice.h>
#include <linux/interrupt.h>

/* PCI device IDs */
#define	PCI_DEVICE_ID_THUNDER_NIC_PF	0xA01E
#define	PCI_DEVICE_ID_THUNDER_NIC_VF	0x0011
#define	PCI_DEVICE_ID_THUNDER_BGX	0xA026

/* PCI BAR nos */
#define	PCI_CFG_REG_BAR_NUM		0
#define	PCI_MSIX_REG_BAR_NUM		4

/* NIC SRIOV VF count */
#define	MAX_NUM_VFS_SUPPORTED		128
#define	DEFAULT_NUM_VF_ENABLED		8

/* NIC priv flags */
#define	NIC_SRIOV_ENABLED		(1 << 0)

/* VNIC HW optimiation features */
#undef	VNIC_RX_CSUM_OFFLOAD_SUPPORT
#undef	VNIC_TX_CSUM_OFFLOAD_SUPPORT
#define	VNIC_SG_SUPPORT
#define	VNIC_TSO_SUPPORT
#define	VNIC_LRO_SUPPORT

/* TSO not supported in Thunder pass1 */
#ifdef	VNIC_TSO_SUPPORT
#define	VNIC_SW_TSO_SUPPORT
#undef	VNIC_HW_TSO_SUPPORT
#endif

/* LRO not supported even in Thunder pass2 */
#ifdef	VNIC_LRO_SUPPORT
#define	VNIC_SW_LRO_SUPPORT
#undef	VNIC_HW_LRO_SUPPORT
#endif


/* ETHTOOL enable or disable, undef this to disable */
#define	NICVF_ETHTOOL_ENABLE

/* NAPI enable or disable, undef this to disable */
#define	NICVF_NAPI_ENABLE

/* Min/Max packet size */
#define	NIC_HW_MIN_FRS			64
#define	NIC_HW_MAX_FRS			1500

/* Max pkinds */
#define	NIC_MAX_PKIND			16

/* Rx Channels */
#define	NIC_MAX_BGX			2
#define	NIC_CHANS_PER_BGX_INF		128
#define	NIC_MAX_CHANS			(NIC_MAX_BGX * NIC_CHANS_PER_BGX_INF)
#define	NIC_MAX_CPI			2048 /* Channel parse index */
#define	NIC_MAX_RSSI			4096 /* Receive side scaling index */

/* TNS bi-pass mode: 1-1 mapping between VNIC and LMAC */
#define	NIC_CPI_PER_BGX			(NIC_MAX_CPI / NIC_MAX_BGX)
#define	NIC_CPI_PER_LMAC		(NIC_MAX_CPI / NIC_MAX_CHANS)
#define	NIC_RSSI_PER_BGX		(NIC_MAX_RSSI / NIC_MAX_BGX)
#define	NIC_RSSI_PER_LMAC		(NIC_MAX_RSSI / NIC_MAX_CHANS)

/* Tx scheduling */
#define	NIC_MAX_TL4			1024
#define	NIC_MAX_TL4_SHAPERS		256 /* 1 shaper for 4 TL4s */
#define	NIC_MAX_TL3			256
#define	NIC_MAX_TL3_SHAPERS		64  /* 1 shaper for 4 TL3s */
#define	NIC_MAX_TL2			64
#define	NIC_MAX_TL2_SHAPERS		2  /* 1 shaper for 32 TL2s */
#define	NIC_MAX_TL1			2

/* TNS bi-pass mode */
#define	NIC_TL4_PER_BGX			(NIC_MAX_TL4 / NIC_MAX_BGX)
#define	NIC_TL4_PER_LMAC		(NIC_MAX_TL4 / NIC_CHANS_PER_BGX_INF)

/* NIC VF Interrupts */
#define	NICVF_INTR_CQ			0
#define	NICVF_INTR_SQ			1
#define	NICVF_INTR_RBDR			2
#define	NICVF_INTR_PKT_DROP		3
#define	NICVF_INTR_TCP_TIMER		4
#define	NICVF_INTR_MBOX			5
#define	NICVF_INTR_QS_ERR		6

#define	NICVF_INTR_CQ_SHIFT		0
#define	NICVF_INTR_SQ_SHIFT		8
#define	NICVF_INTR_RBDR_SHIFT		16
#define	NICVF_INTR_PKT_DROP_SHIFT	20
#define	NICVF_INTR_TCP_TIMER_SHIFT	21
#define	NICVF_INTR_MBOX_SHIFT		22
#define	NICVF_INTR_QS_ERR_SHIFT		23

#define	NICVF_INTR_CQ_MASK		(0xFF << NICVF_INTR_CQ_SHIFT)
#define	NICVF_INTR_SQ_MASK		(0xFF << NICVF_INTR_SQ_SHIFT)
#define	NICVF_INTR_RBDR_MASK		(0x03 << NICVF_INTR_RBDR_SHIFT)
#define	NICVF_INTR_PKT_DROP_MASK	(1 << NICVF_INTR_PKT_DROP_SHIFT)
#define	NICVF_INTR_TCP_TIMER_MASK	(1 << NICVF_INTR_TCP_TIMER_SHIFT)
#define	NICVF_INTR_MBOX_MASK		(1 << NICVF_INTR_MBOX_SHIFT)
#define	NICVF_INTR_QS_ERR_MASK		(1 << NICVF_INTR_QS_ERR_SHIFT)

/* MSI-X interrupts */
#define	NIC_PF_MSIX_VECTORS		10
#define	NIC_VF_MSIX_VECTORS		20

#define	NICVF_CQ_INTR_ID		0
#define	NICVF_SQ_INTR_ID		8
#define	NICVF_RBDR_INTR_ID		16
#define	NICVF_MISC_INTR_ID		18
#define	NICVF_QS_ERR_INTR_ID		19

#define for_each_cq_irq(irq) for (irq = NICVF_CQ_INTR_ID; \
					irq < NICVF_SQ_INTR_ID; irq++)
#define for_each_sq_irq(irq) for (irq = NICVF_SQ_INTR_ID; \
					irq < NICVF_RBDR_INTR_ID; irq++)
#define for_each_rbdr_irq(irq) for (irq = NICVF_RBDR_INTR_ID; \
					irq < NICVF_MISC_INTR_ID; irq++)

struct nicvf_cq_poll {
	uint8_t	cq_idx;		/* Completion queue index */
	struct napi_struct napi;
};

#ifdef NICVF_ETHTOOL_ENABLE

/* Stats */

/* Tx statistics */
struct nicvf_tx_stats {
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
struct nicvf_rx_stats {
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
	u64 rx_frames_jumbo;
	u64 rsvd[16];
};

struct eth_stats {
	struct nicvf_tx_stats tx;
	struct nicvf_rx_stats rx;
};

#endif /* NICVF_ETHTOOL_ENABLE */

struct nicvf {
	struct net_device	*netdev;
	struct pci_dev		*pdev;
	uint16_t		mtu;
	uint8_t			vnic_id;
	struct queue_set	*qs;		/* Queue set this VNIC is pointing to */
	uint8_t			num_qs;		/* No of QSs assigned to this VNIC */
	void			*addnl_qs;	/* Pointer to QSs additional to default 1 QS */
	uint16_t		vf_mtu;
	uint64_t		reg_base;	/* Register start address */
	struct tasklet_struct	rbdr_task;	/* Tasklet to refill RBDR */
	struct tasklet_struct	qs_err_task;	/* Tasklet to handle Qset err */
#ifdef NICVF_NAPI_ENABLE
	struct nicvf_cq_poll	*napi[8];	/* NAPI */
#endif
	/* MSI-X  */
	bool			msix_enabled;
	uint16_t		num_vec;
	struct msix_entry	msix_entries[NIC_VF_MSIX_VECTORS];
	char			irq_name[NIC_VF_MSIX_VECTORS][20];
	uint8_t			irq_allocated[NIC_VF_MSIX_VECTORS];
#ifdef NICVF_ETHTOOL_ENABLE
	struct eth_stats	vstats;
#endif
};

struct nicpf {
	struct net_device	*netdev;
	struct pci_dev		*pdev;
	unsigned int		flags;
	uint16_t		total_vf_cnt;   /* Total num of VF supported */
	uint16_t		num_vf_en;      /* No of VF enabled */
	uint64_t		reg_base;       /* Register start address */
	struct pkind_cfg	pkind;
	/* MSI-X */
	bool			msix_enabled;
	uint16_t		num_vec;
	struct msix_entry	msix_entries[NIC_PF_MSIX_VECTORS];
	uint8_t			irq_allocated[NIC_PF_MSIX_VECTORS];
};

struct nicvf_stats {
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
	} rx;
	struct {
	} tx;
};

/* PF <--> Mailbox communication
 * Eight 64bit registers are shared between PF and VF.
 * Separate set for each VF.
 * Writing '1' into last register mbx7 means end of message.
 */

/* PF <--> VF mailbox communication */
#define	NIC_PF_VF_MAILBOX_SIZE		8

/* Mailbox message types */
#define	NIC_PF_VF_MSG_READY		0x01	/* Is PF ready to rcv msgs */
#define	NIC_PF_VF_MSG_ACK		0x02	/* ACK the message received */
#define	NIC_PF_VF_MSG_NACK		0x03	/* NACK the message received */
#define	NIC_PF_VF_MSG_QS_CFG		0x04	/* Configure Qset */
#define	NIC_PF_VF_MSG_RQ_CFG		0x05	/* Configure receive queue */
#define	NIC_PF_VF_MSG_SQ_CFG		0x06	/* Configure Send queue */
#define	NIC_PF_VF_MSG_RQ_DROP_CFG	0x07	/* Configure receive queue */
#define	NIC_PF_VF_MSG_SET_MAC		0x08	/* Add MAC ID to BGX's DMAC filter */
#define	NIC_VF_SET_MAX_FRS		0x09	/* Set max frame size */

struct nic_mbx {
	uint64_t	   msg;
	union	{
		uint64_t	vnic_id;
		struct {			/* Qset configuration */
			uint64_t   num;
			uint64_t   cfg;
		} qs;
		struct {			/* Receive queue configuration */
			uint64_t   qs_num;
			uint64_t   rq_num;
			uint64_t   cfg;
		} rq;
		struct {			/* Send queue configuration */
			uint64_t   qs_num;
			uint64_t   sq_num;
			uint64_t   cfg;
		} sq;
		struct {			/* VF's MAC address */
			uint64_t   vnic_id;
			uint64_t   addr;
		} mac;
		uint64_t	max_frs; /* Max frame size */
	} data;
	uint64_t	   mbx4;
	uint64_t	   mbx5;
	uint64_t	   mbx6;
	uint64_t	   mbx_trigger_intr;
};

#ifdef NICVF_ETHTOOL_ENABLE
void nicvf_set_ethtool_ops(struct net_device *netdev);
#endif

struct nic_mbx *nicvf_get_mbx(void);
int nicvf_send_msg_to_pf(struct nicvf *vf, struct nic_mbx *mbx);
void nicvf_free_skb(struct nicvf *nic, struct sk_buff *skb);

/* Debug */
#undef	NIC_DEBUG

#ifdef	NIC_DEBUG
#define	nic_dbg(dev, fmt, arg...) \
		dev_info(dev, fmt, ##arg)
#else
#define	nic_dbg(dev, fmt, arg...) do {} while (0)
#endif

#endif /* NIC_H */
