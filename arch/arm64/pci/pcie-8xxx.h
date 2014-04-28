/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2013 Cavium, Inc.
 */
#ifndef __PCIE_88XX_H__
#define __PCIE_88XX_H__

#define THUNDER_PCIE_BUS_SHIFT		20ul
#define THUNDER_PCIE_DEV_SHIFT		15ul
#define THUNDER_PCIE_FUNC_SHIFT		12ul

#define THUNDER_PCIE_CSR_REG         0x87e048000000
#define THUNDER_PCIE_CAR_REG_SIZE    6 * (1u << 16)
#endif
