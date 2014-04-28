/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 * 
 * Copyright (C) 2013 Cavium, Inc. 
 */

#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/pci.h>

#include "vnic.h"
#include "vnic_hw.h"

/* Virtual function's register read/write APIs */
void vnic_vf_reg_write (struct vnic_vf *vf, uint64_t offset, uint64_t val)
{
	uint64_t addr = vf->reg_base + offset;
        writeq_relaxed(val, (void *)addr);
}

uint64_t vnic_vf_reg_read (struct vnic_vf *vf, uint64_t offset)
{
	uint64_t addr = vf->reg_base + offset;
        return readq_relaxed((void *)addr);
}

void vnic_qset_reg_write (struct vnic_vf *vf, uint64_t offset, uint64_t val)
{	
	uint64_t addr = vf->reg_base + offset;

        writeq_relaxed(val, (void *)(addr));
}

uint64_t vnic_qset_reg_read (struct vnic_vf *vf, uint64_t offset)
{
	uint64_t addr = vf->reg_base + offset;
	return readq_relaxed((void *)(addr));
}

void vnic_queue_reg_write (struct vnic_vf *vf, uint64_t offset, 
				uint64_t qidx, uint64_t val)
{
	uint64_t addr = vf->reg_base + offset;
	writeq_relaxed(val, (void *)(addr + (qidx << VNIC_Q_NUM_SHIFT)));
}

uint64_t vnic_queue_reg_read (struct vnic_vf *vf, uint64_t offset, uint64_t qidx)
{
	uint64_t addr = vf->reg_base + offset;
	return readq_relaxed((void *)(addr + (qidx << VNIC_Q_NUM_SHIFT)));
}

