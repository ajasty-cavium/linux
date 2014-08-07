/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2013 Cavium, Inc.
 */

#ifndef NIC_REG_H
#define NIC_REG_H

/* Physical function register offsets */
#define   NIC_PF_CFG				(0x0000)
#define   NIC_PF_STATUS				(0x0010)
#define   NIC_PF_INTR_TIMER_CFG			(0x0030)
#define   NIC_PF_BIST_STATUS			(0x0040)
#define   NIC_PF_SOFT_RESET			(0x0050)
#define   NIC_PF_TCP_TIMER			(0x0060)
#define   NIC_PF_BP_CFG				(0x0080)
#define   NIC_PF_RRM_CFG			(0x0088)
#define   NIC_PF_CQM_CF				(0x00A0)
#define   NIC_PF_CNM_CF				(0x00A8)
#define   NIC_PF_CNM_STATUS			(0x00B0)
#define   NIC_PF_CQ_AVG_CFG			(0x00C0)
#define   NIC_PF_RRM_AVG_CFG			(0x00C8)
#define   NIC_PF_INTF_0_1_SEND_CFG		(0x0200) /* (0..1) << 8 */
#define   NIC_PF_INTF_0_1_BP_CFG		(0x0208)
#define   NIC_PF_INTF_0_1_BP_DIS_0_1		(0x0210) /* (0..1) << 8 + (0..1) << 3 */
#define   NIC_PF_INTF_0_1_BP_SW_0_1		(0x0220)
#define   NIC_PF_ECC_INT			(0x0400)
#define   NIC_PF_MAILBOX_INT			(0x0410) /* (0..1) << 3 */
#define   NIC_PF_ECC_INT_W1S			(0x0420)
#define   NIC_PF_MAILBOX_INT_W1S		(0x0430)
#define   NIC_PF_ECC_ENA_W1C			(0x0440)
#define   NIC_PF_MAILBOX_ENA_W1C		(0x0450)
#define   NIC_PF_ECC_ENA_W1S			(0x0460)
#define   NIC_PF_MAILBOX_ENA_W1S		(0x0470)
#define   NIC_PF_ECC_CTL			(0x0480)
#define   NIC_PF_RX_ETYPE_0_7			(0x0500) /* + (0..7) << 3 */
#define   NIC_PF_PKIND_0_15_CFG			(0x0600)
#define   NIC_PF_CPI_0_2047_CFG			(0x200000)
#define   NIC_PF_RSSI_0_4097_RQ			(0x220000)
#define   NIC_PF_LMAC_0_7_CFG			(0x240000)
#define   NIC_PF_LMAC_0_7_SW_XOFF		(0x242000)
#define   NIC_PF_LMAC_0_7_CREDIT		(0x244000)
#define   NIC_PF_CHAN_0_255_TX_CFG		(0x400000)
#define   NIC_PF_CHAN_0_255_RX_CFG		(0x420000)
#define   NIC_PF_CHAN_0_255_SW_XOFF		(0x440000)
#define   NIC_PF_CHAN_0_255_CREDIT		(0x460000)
#define   NIC_PF_CHAN_0_255_RX_BP_CFG		(0x480000)
#define   NIC_PF_TL2_0_63_CFG			(0x500000)
#define   NIC_PF_TL2_0_63_PRI			(0x520000)
#define   NIC_PF_TL2_0_63_SH_STATUS		(0x580000)
#define   NIC_PF_TL3A_0_63_CFG			(0x5F0000)
#define   NIC_PF_TL3_0_255_CFG			(0x600000)
#define   NIC_PF_TL3_0_255_CHAN			(0x620000)
#define   NIC_PF_TL3_0_255_PIR			(0x640000)
#define   NIC_PF_TL3_0_255_SW_XOFF		(0x660000)
#define   NIC_PF_TL3_0_255_CNM_RATE		(0x680000)
#define   NIC_PF_TL3_0_255_SH_STATUS		(0x6A0000)
#define   NIC_PF_TL4A_0_255_CFG			(0x6F0000)
#define   NIC_PF_TL4_0_1023_CFG			(0x800000)
#define   NIC_PF_TL4_0_1023_SW_XOFF		(0x820000)
#define   NIC_PF_TL4_0_1023_SH_STATUS		(0x880000)
#define   NIC_PF_TL4A_0_1023_CNM_STATUS		(0x8A0000)
#define   NIC_PF_VF_0_127_MAILBOX_0_7		(0x20002000) /* + (0..127) << 21 + (0..7) << 3 */
#define   NIC_PF_VNIC_0_127_TX_STAT_0_4		(0x20004000) /* + (0..127) << 21 + (0..4) << 3 */
#define   NIC_PF_VNIC_0_127_RX_STAT_0_13	(0x20004100)
#define   NIC_PF_QSET_0_127_LOCK_0_15		(0x20006000)
#define   NIC_PF_QSET_0_127_CFG			(0x20010000) /* + (0..127) << 21 */
#define   NIC_PF_QSET_0_127_RQ_0_7_CFG		(0x20010400) /* + (0..127) << 21 + (0..7) << 18 */
#define   NIC_PF_QSET_0_127_RQ_0_7_DROP_CFG	(0x20010420)
#define   NIC_PF_QSET_0_127_RQ_0_7_BP_CFG	(0x20010500)
#define   NIC_PF_QSET_0_127_RQ_0_7_STAT_0_1	(0x20010600) /* + (0..127) << 21 + (0..7) << 18 + (0..1) << 3 */
#define   NIC_PF_QSET_0_127_SQ_0_7_CFG		(0x20010C00) /* + (0..127) << 21 + (0..7) << 18 */
#define   NIC_PF_QSET_0_127_SQ_0_7_CFG2		(0x20010C08)
#define   NIC_PF_QSET_0_127_SQ_0_7_STAT_0_1	(0x20010D00) /* + (0..127) << 21 + (0..7) << 18 + (0..1) << 3 */

#define   NIC_PF_MSIX_VEC_0_18_ADDR		(0x000000) /* + (0..18) << 4 */
#define   NIC_PF_MSIX_VEC_0_CTL			(0x000008)
#define   NIC_PF_MSIX_PBA_0			(0x010000)

/* Virtual function register offsets */
#define   NIC_VNIC_CFG				(0x000020)
#define   NIC_VF_PF_MAILBOX_0_7			(0x000100) /* + (0..7) << 3 */
#define   NIC_VF_INT				(0x000200)
#define   NIC_VF_INT_W1S			(0x000220)
#define   NIC_VF_ENA_W1C			(0x000240)
#define   NIC_VF_ENA_W1S			(0x000260)

#define   NIC_VNIC_RSS_CFG			(0x0020E0)
#define   NIC_VNIC_RSS_KEY_0_4			(0x002200) /* + (0..4) << 3*/
#define   NIC_VNIC_TX_STAT_0_5			(0x004000)
#define   NIC_VNIC_RX_STAT_0_13			(0x004100)

#define   NIC_QSET_CQ_0_7_CFG			(0x010400)
#define   NIC_QSET_CQ_0_7_CFG2			(0x010408)
#define   NIC_QSET_CQ_0_7_THRESH		(0x010410)
#define   NIC_QSET_CQ_0_7_BASE			(0x010420)
#define   NIC_QSET_CQ_0_7_HEAD			(0x010428)
#define   NIC_QSET_CQ_0_7_TAIL			(0x010430)
#define   NIC_QSET_CQ_0_7_DOOR			(0x010438)
#define   NIC_QSET_CQ_0_7_STATUS		(0x010440)
#define   NIC_QSET_CQ_0_7_STATUS2		(0x010448)
#define   NIC_QSET_CQ_0_7_DEBUG			(0x010450)

#define   NIC_QSET_RQ_GEN_CFG			(0x010010)
#define   NIC_QSET_RQ_0_7_CFG			(0x010600)
#define   NIC_QSET_RQ_0_7_STAT_0_1		(0x010700)

#define   NIC_QSET_SQ_0_7_CFG			(0x010800)
#define   NIC_QSET_SQ_0_7_THRESH		(0x010810)
#define   NIC_QSET_SQ_0_7_BASE			(0x010820)
#define   NIC_QSET_SQ_0_7_HEAD			(0x010828)
#define   NIC_QSET_SQ_0_7_TAIL			(0x010830)
#define   NIC_QSET_SQ_0_7_DOOR			(0x010838)
#define   NIC_QSET_SQ_0_7_STATUS		(0x010840)
#define   NIC_QSET_SQ_0_7_DEBUG			(0x010848)
#define   NIC_QSET_SQ_0_7_CNM_CHG		(0x010860)
#define   NIC_QSET_SQ_0_7_STAT_0_1		(0x010900)

#define   NIC_QSET_RBDR_0_1_CFG			(0x010C00)
#define   NIC_QSET_RBDR_0_1_THRESH		(0x010C10)
#define   NIC_QSET_RBDR_0_1_BASE		(0x010C20)
#define   NIC_QSET_RBDR_0_1_HEAD		(0x010C28)
#define   NIC_QSET_RBDR_0_1_TAIL		(0x010C30)
#define   NIC_QSET_RBDR_0_1_DOOR		(0x010C38)
#define   NIC_QSET_RBDR_0_1_STATUS0		(0x010C40)
#define   NIC_QSET_RBDR_0_1_STATUS1		(0x010C48)

#define   NIC_VF_MSIX_VECTOR_0_19_ADDR		(0x000000)
#define   NIC_VF_MSIX_VECTOR_0_19_CTL		(0x000008)
#define   NIC_VF_MSIX_PBA			(0x010000)

/* Offsets within registers */
#define   NIC_MSIX_VEC_SHIFT	4
#define   NIC_Q_NUM_SHIFT	18
#define   NIC_QS_ID_SHIFT	21
#define   NIC_VF_NUM_SHIFT	21

#endif /* NIC_REG_H */
