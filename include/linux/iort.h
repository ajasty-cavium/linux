/*
 * Copyright (C) 2014, Linaro Ltd.
 *	Author: Tomasz Nowicki <tomasz.nowicki@linaro.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 */

#ifndef __IORT_H__
#define __IORT_H__

struct msi_chip;

#define IORT_IRQ_MASK(irq)		(irq & 0xffffffffULL)
#define IORT_IRQ_TRIGGER_MASK(irq)	((irq >> 32) & 0xffffffffULL)

#ifdef CONFIG_IORT_TABLE
int iort_pci_msi_chip_add(struct msi_chip *chip, u32 its_id);
void iort_pci_msi_chip_remove(struct msi_chip *chip);
struct msi_chip *iort_find_pci_msi_chip(int segment, unsigned int idx);
struct acpi_table_iort_node_header *
iort_find_node_children(struct acpi_table_iort_node_header *parent,
			unsigned int idx);
int
iort_find_endpoint_id(struct acpi_table_iort_node_header *node, u32 *streamids);
int
iort_map_pcidev_to_streamid(struct pci_dev *pdev, u32 req_id, u32 *stream_id);
struct device *
iort_find_node_device(struct acpi_table_iort_node_header *node);
#else
inline int
iort_pci_msi_chip_add(struct msi_chip *chip, u32 its_id) { return 0; }
inline void
iort_pci_msi_chip_remove(struct msi_chip *chip) {}
struct msi_chip *
iort_find_pci_msi_chip(int segment, unsigned int idx) { return NULL; }
inline struct acpi_table_iort_node_header *
iort_find_node_children(struct acpi_table_iort_node_header *parent,
			unsigned int idx) { return NULL; }
int
iort_find_endpoint_id(struct acpi_table_iort_node_header *node, u32 *streamids)
{ return AE_ERROR; }
int
iort_map_pcidev_to_streamid(struct pci_dev *pdev, u32 req_id, u32 *stream_id)
{ return AE_ERROR; }
struct device *
iort_find_node_device(struct acpi_table_iort_node_header *node) { return NULL; }
#endif

#endif /* __IORT_H__ */
