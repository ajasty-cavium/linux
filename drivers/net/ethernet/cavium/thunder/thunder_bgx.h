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

#define    MAX_BGX_PER_CN88XX			2
#define    MAX_LMAC_PER_BGX			4
#define    MAX_BGX_CHANS_PER_LMAC		16
#define    MAX_DMAC_PER_LMAC			8

#define    MAX_DMAC_PER_LMAC_TNS_BYPASS_MODE	2

/* Registers */
#define BGX_CMRX_CFG				0x00
#define BGX_CMRX_RX_DMAC_CTL			0x0E8
#define BGX_CMR_RX_DMACX_CAM			0x200

/*  RX_DMAC_CTL configuration*/
enum MCAST_MODE {
		MCAST_MODE_REJECT,
		MCAST_MODE_ACCEPT,
		MCAST_MODE_CAM_FILTER,
		RSVD
};
#define BCAST_ACCEPT	1
#define CAM_ACCEPT	1

void bgx_add_dmac_addr(uint64_t dmac, uint64_t lmac);
void bgx_lmac_disable(uint8_t lmac);
void bgx_lmac_enable(uint8_t lmac);

#endif /* THUNDER_BGX_H */
