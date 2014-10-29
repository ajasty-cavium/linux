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
#define BGX_CMRX_RX_ID_MAP			0x60
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

#endif /* THUNDER_BGX_H */
