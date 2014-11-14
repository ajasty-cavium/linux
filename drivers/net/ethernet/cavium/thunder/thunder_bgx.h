/*
 * Copyright (C) 2014 Cavium, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 */

#ifndef THUNDER_BGX_H
#define THUNDER_BGX_H

#define    MAX_BGX_THUNDER			8 /* Max 4 nodes, 2 per node */
#define    MAX_BGX_PER_CN88XX			2
#define    MAX_LMAC_PER_BGX			4
#define    MAX_BGX_CHANS_PER_LMAC		16
#define    MAX_DMAC_PER_LMAC			8

#define    MAX_DMAC_PER_LMAC_TNS_BYPASS_MODE	2

#define    MAX_LMAC	(MAX_BGX_PER_CN88XX * MAX_LMAC_PER_BGX)

#define    NODE_ID_MASK				0x300000000000
#define    NODE_ID(x)				((x & NODE_ID_MASK) >> 44)

/* Registers */
#define BGX_CMRX_CFG				0x00
#define BGX_CMR_GLOBAL_CFG			0x08
#define BGX_CMRX_RX_ID_MAP			0x60
#define BGX_CMRX_RX_STAT0			0x70
#define BGX_CMRX_RX_STAT1			0x78
#define BGX_CMRX_RX_STAT2			0x80
#define BGX_CMRX_RX_STAT3			0x88
#define BGX_CMRX_RX_STAT4			0x90
#define BGX_CMRX_RX_STAT5			0x98
#define BGX_CMRX_RX_STAT6			0xA0
#define BGX_CMRX_RX_STAT7			0xA8
#define BGX_CMRX_RX_STAT8			0xB0
#define BGX_CMRX_RX_STAT9			0xB8
#define BGX_CMRX_RX_STAT10			0xC0
#define BGX_CMRX_RX_BP_DROP			0xC8
#define BGX_CMRX_TX_STAT0			0x600
#define BGX_CMRX_TX_STAT1			0x608
#define BGX_CMRX_TX_STAT2			0x610
#define BGX_CMRX_TX_STAT3			0x618
#define BGX_CMRX_TX_STAT4			0x620
#define BGX_CMRX_TX_STAT5			0x628
#define BGX_CMRX_TX_STAT6			0x630
#define BGX_CMRX_TX_STAT7			0x638
#define BGX_CMRX_TX_STAT8			0x640
#define BGX_CMRX_TX_STAT9			0x648
#define BGX_CMRX_TX_STAT10			0x650
#define BGX_CMRX_TX_STAT11			0x658
#define BGX_CMRX_TX_STAT12			0x660
#define BGX_CMRX_TX_STAT13			0x668
#define BGX_CMRX_TX_STAT14			0x670
#define BGX_CMRX_TX_STAT15			0x678
#define BGX_CMRX_TX_STAT16			0x680
#define BGX_CMRX_TX_STAT17			0x688
#define BGX_CMRX_RX_DMAC_CTL			0x0E8
#define BGX_CMR_RX_DMACX_CAM			0x200
#define BGX_CMR_RX_STREERING			0x300
#define BGX_CMR_CHAN_MSK_AND			0x450
#define BGX_CMR_BIST_STATUS			0x460
#define BGX_CMR_RX_LMACS			0x468
#define BGX_CMR_TX_LMACS			0x1000

#define BGX_CMRX_RX_DMAC_CTL			0x0E8
#define BGX_CMR_RX_DMACX_CAM			0x200
#define BGX_CMR_RX_LMACS			0x468
#define BGX_CMR_TX_LMACS			0x1000

#define BGX_SPUX_STATUS1			0x10008
#define BGX_SPUX_STATUS2			0x10020
#define BGX_SPUX_INT				0x10220	/* +(0..3) << 20 */
#define BGX_SPUX_INT_W1S			0x10228
#define BGX_SPUX_INT_ENA_W1C			0x10230
#define BGX_SPUX_INT_ENA_W1S			0x10238

#define BGX_SMUX_RX_JABBER			0x20030
#define BGX_SMUX_RX_CTL				0x20048
#define BGX_SMUX_CTL				0x20200
#define BGX_SMUX_TX_CTL				0x20178
#define BGX_SMUX_TX_THRESH			0x20180

#define BGX_GMP_PCS_MRX_CTL			0x30000
#define BGX_GMP_PCS_MRX_STATUS			0x30008
#define BGX_GMP_PCS_SGM_AN_ADV			0x30068
#define BGX_GMP_PCS_MISCX_CTL			0x30078
#define BGX_GMP_GMI_RXX_JABBER			0x38038
#define BGX_GMP_GMI_TXX_THRESH			0x38210
#define BGX_GMP_GMI_TXX_APPEND			0x38218
#define BGX_GMP_GMI_TXX_MIN_PKT			0x38240
#define BGX_GMP_GMI_TXX_SGMII_CTL		0x38300

#define BGX_MSIX_VEC_0_29_ADDR			0x400000 /* +(0..29) << 4 */
#define BGX_MSIX_VEC_0_29_CTL			0x400008
#define BGX_MSIX_PBA_0				0x4F0000

/* MSI-X interrupts */
#define BGX_MSIX_VECTORS	30
#define BGX_LMAC_VEC_OFFSET	7
#define BGX_MSIX_VEC_SHIFT	4

#define CMRX_INT		0
#define SPUX_INT		1
#define SMUX_RX_INT		2
#define SMUX_TX_INT		3
#define GMPX_PCS_INT		4
#define GMPX_GMI_RX_INT		5
#define GMPX_GMI_TX_INT		6
#define CMR_MEM_INT		28
#define SPU_MEM_INT		29

#define LMAC_INTR_LINK_UP	(1 << 0)
#define LMAC_INTR_LINK_DOWN	(1 << 1)

/*  RX_DMAC_CTL configuration*/
enum MCAST_MODE {
		MCAST_MODE_REJECT,
		MCAST_MODE_ACCEPT,
		MCAST_MODE_CAM_FILTER,
		RSVD
};

#define BCAST_ACCEPT	1
#define CAM_ACCEPT	1

void bgx_add_dmac_addr(uint64_t dmac, int node, int bgx_idx, int lmac);
void bgx_get_count(int node, int *bgx_count);
int bgx_get_lmac_count(int node, int bgx);
void bgx_print_stats(int bgx_idx, int lmac);

#undef LINK_INTR_ENABLE

enum LMAC_TYPE {
	BGX_MODE_SGMII = 0, /* 1 lane, 1.250 Gbaud */
	BGX_MODE_XAUI = 1,  /* 4 lanes, 3.125 Gbaud */
	BGX_MODE_10G_KR = 3,/* 1 lane, 10.3125 Gbaud */
	BGX_MODE_XFI = 3,
	BGX_MODE_40G_KR = 4,/* 4 lanes, 10.3125 Gbaud */
	BGX_MODE_XLAUI = 4,
};

enum qlm_mode {
	QLM_MODE_SGMII,         /* SGMII, each lane independent (cn88xx) */
	QLM_MODE_XAUI_1X4,      /* 1 XAUI or DXAUI, 4 lanes (cn88xx) */
	QLM_MODE_10G_KR_4X1,    /* 4 10GBASE-KR, 1 lane each (cn88xx) */
	QLM_MODE_XFI_4X1,       /* 4 XFI, 1 lane each (cn88xx) */
	QLM_MODE_40G_KR4_1X4,   /* 1 40GBASE-KR4, 4 lanes each (cn88xx) */
	QLM_MODE_XLAUI_1X4,     /* 1 XLAUI, 4 lanes each (cn88xx) */
};

#define  QLM0_MODE   QLM_MODE_SGMII
#define  QLM1_MODE   QLM_MODE_SGMII

#endif /* THUNDER_BGX_H */
