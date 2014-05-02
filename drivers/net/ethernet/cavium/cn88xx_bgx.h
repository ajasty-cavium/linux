/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 * 
 * Copyright (C) 2014 Cavium, Inc. 
 */

#ifndef CN88XX_BGX_H
#define CN88XX_BGX_H

#define MAX_BGX_PER_CN88XX  2
#define MAX_LMAC_PER_BGX    4
#define MAX_DMAC_PER_LMAC   8

#define MAX_DMAC_PER_LMAC_TNS_BYPASS_MODE   2

/* Registers */
#define BGX_CMRX_CFG		0x00 
#define BGX_CMR_RX_DMACX_CAM	0x200

extern void bgx_add_dmac_addr(uint64_t dmac, uint64_t lmac);
extern void bgx_lmac_disable (uint64_t lmac);
extern void bgx_lmac_enable (uint64_t lmac);
#endif
