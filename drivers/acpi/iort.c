/*
 * Copyright (C) 2014-2015, Linaro Ltd.
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
 * This file implements early detection/parsing of I/O mapping
 * reported to OS through BIOS via I/O Remapping Table (IORT) ACPI
 * table.
 *
 * These routines are used by ITS, PCI host bridge and SMMU drivers.
 */

#include <linux/acpi.h>
#include <linux/export.h>
#include <linux/iort.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/msi.h>
#include <linux/mutex.h>
#include <linux/pci.h>
#include <linux/platform_device.h>
#include <linux/slab.h>

#define IORT_PFX	"IORT: "

static LIST_HEAD(iort_node_list);
static DEFINE_MUTEX(iort_tree_roots_mutex);
static struct acpi_table_header *iort_table;

struct iort_its_msi_chip {
	struct list_head	list;
	struct msi_chip		*chip;
	u32			id;
};

struct iort_priv_ctx {
	struct acpi_iort_header	*parent;
	unsigned int				index;
};

typedef acpi_status (*iort_find_node_callback)
	(struct acpi_iort_header *node, void *context);

static LIST_HEAD(iort_pci_msi_chip_list);
static DEFINE_MUTEX(iort_pci_msi_chip_mutex);

int iort_pci_msi_chip_add(struct msi_chip *chip, u32 its_id)
{
	struct iort_its_msi_chip *its_msi_chip;

	its_msi_chip = kzalloc(sizeof(*its_msi_chip), GFP_KERNEL);
	if (!its_msi_chip)
		return -ENOMEM;

	its_msi_chip->chip = chip;
	its_msi_chip->id = its_id;

	mutex_lock(&iort_pci_msi_chip_mutex);
	list_add(&its_msi_chip->list, &iort_pci_msi_chip_list);
	mutex_unlock(&iort_pci_msi_chip_mutex);

	return 0;
}
EXPORT_SYMBOL_GPL(iort_pci_msi_chip_add);

void iort_pci_msi_chip_remove(struct msi_chip *chip)
{
	struct iort_its_msi_chip *its_msi_chip, *tmp;

	mutex_lock(&iort_pci_msi_chip_mutex);
	list_for_each_entry_safe(its_msi_chip, tmp, &iort_pci_msi_chip_list,
				 list) {
		if (its_msi_chip->chip == chip) {
			list_del(&chip->list);
			mutex_unlock(&iort_pci_msi_chip_mutex);
			kfree(its_msi_chip);
		}
	}
	mutex_unlock(&iort_pci_msi_chip_mutex);
}
EXPORT_SYMBOL_GPL(iort_pci_msi_chip_remove);

static struct msi_chip *iort_pci_find_msi_chip_by_id(u32 its_id)
{
	struct iort_its_msi_chip *its_msi_chip;

	mutex_lock(&iort_pci_msi_chip_mutex);
	list_for_each_entry(its_msi_chip, &iort_pci_msi_chip_list, list) {
		if (its_msi_chip->id == its_id) {
			mutex_unlock(&iort_pci_msi_chip_mutex);
			return its_msi_chip->chip;
		}
	}
	mutex_unlock(&iort_pci_msi_chip_mutex);

	return NULL;
}
EXPORT_SYMBOL_GPL(iort_pci_find_msi_chip_by_id);

static struct acpi_iort_header *
iort_find_root_node(struct acpi_iort_header *node)
{
	struct acpi_iort_id *id_map;

	if (!node)
		return NULL;

	/* Root node has no ID map */
	while (node->ref_to_ids) {
		id_map = ACPI_ADD_PTR(struct acpi_iort_id,
				      node, node->ref_to_ids);

		/* Firmware bug! */
		if (!id_map->output_ref) {
			pr_err(IORT_PFX FW_BUG "[node %p type %d] ID map has invalid parent reference\n",
			       node, node->type);
			return NULL;
		}

		node = ACPI_ADD_PTR(struct acpi_iort_header,
					 iort_table, id_map->output_ref);
	}

	return node;
}

static struct acpi_iort_header *
iort_find_node_type(int type, iort_find_node_callback callback, void *context)
{
	struct acpi_iort_header *iort_node, *iort_end;

	/* Skip IORT header */
	iort_node = ACPI_ADD_PTR(struct acpi_iort_header, iort_table,
				 sizeof(struct acpi_table_iort));
	iort_end = ACPI_ADD_PTR(struct acpi_iort_header, iort_table,
				iort_table->length);

	while (iort_node < iort_end) {
		if (iort_node->type == type || type == -1) {
			if (ACPI_SUCCESS(callback(iort_node, context)))
				return iort_node;
		}

		iort_node = ACPI_ADD_PTR(struct acpi_iort_header,
					  iort_node, iort_node->length);
	}

	return NULL;
}

static acpi_status
iort_find_pci_rc_callback(struct acpi_iort_header *node, void *context)
{
	int segment = *(int *)context;
	struct acpi_iort_root_complex *pci_rc;

	pci_rc = ACPI_ADD_PTR(struct acpi_iort_root_complex, node,
			      sizeof(struct acpi_iort_header));

	if (pci_rc->segment == segment)
		return AE_OK;

	return AE_NOT_FOUND;
}

static struct acpi_iort_header *
iort_find_pci_rc(int segment)
{

	if (!iort_table)
		return NULL;

	return iort_find_node_type(ACPI_IORT_TYPE_ROOT_COMPLEX,
				   iort_find_pci_rc_callback, &segment);
}

struct msi_chip *iort_find_pci_msi_chip(int segment, unsigned int idx)
{
	struct acpi_iort_its *its_node;
	struct acpi_iort_header *node;
	struct msi_chip *msi_chip;

	if (!iort_table)
		return NULL;

	node = iort_find_pci_rc(segment);
	if (!node) {
		pr_err(IORT_PFX "can not find node related to PCI host bridge [segment %d]\n",
		       segment);
		return NULL;
	}

	node = iort_find_root_node(node);
	if (!node || node->type != ACPI_IORT_TYPE_ITS_GROUP) {
		pr_err(IORT_PFX "can not find ITS node parent for PCI host bridge [segment %d]\n",
		       segment);
		return NULL;
	}

	/* Move to ITS specific data */
	its_node = ACPI_ADD_PTR(struct acpi_iort_its, node,
				sizeof(struct acpi_iort_header));

	if (idx > its_node->number_of_its) {
		pr_err(IORT_PFX "requested ITS ID index [%d] is greater than available ITS IDs [%d]\n",
		       idx, its_node->number_of_its);
		return NULL;
	}

	msi_chip = iort_pci_find_msi_chip_by_id(its_node->its_id[idx]);
	if (!msi_chip)
		pr_err(IORT_PFX "can not find ITS chip ID:%d, not registered\n",
		       its_node->its_id[idx]);

	return msi_chip;
}
EXPORT_SYMBOL_GPL(iort_find_pci_msi_chip);

static acpi_status
iort_find_node_idx_callback(struct acpi_iort_header *node,
			    void *context)
{
	unsigned int *count = context;

	if ((*count)--)
		return AE_NOT_FOUND;

	return AE_OK;
}

static struct acpi_iort_header *
iort_find_node(int type, unsigned int idx)
{
	unsigned int count = idx;

	if (!iort_table)
		return NULL;

	return iort_find_node_type(type, iort_find_node_idx_callback, &count);
}

static acpi_status
iort_find_children_idx_callback(struct acpi_iort_header *node,
				void *context)
{
	struct iort_priv_ctx *info = context;
	struct acpi_iort_id *id;
	struct acpi_iort_header *parent;
	int i, found = 0;

	/* Move to ID section */
	id = ACPI_ADD_PTR(struct acpi_iort_id, node,
			  node->ref_to_ids);
	for (i = 0; i < node->number_of_ids; i++) {
		parent = ACPI_ADD_PTR(struct acpi_iort_header,
				      iort_table, id->output_ref);
		if (parent == info->parent) {
			found = 1;
			break;
		}
		id++;
	}

	if (!found || info->index--)
		return AE_NOT_FOUND;

	return AE_OK;
}

struct acpi_iort_header *
iort_find_child(struct acpi_iort_header *parent,
			unsigned int idx)
{
	struct iort_priv_ctx info;

	info.parent = parent;
	info.index = idx;

	return iort_find_node_type(-1, iort_find_children_idx_callback, &info);
}
EXPORT_SYMBOL_GPL(iort_find_child);


int
iort_find_endpoint_id(struct acpi_iort_header *node, u32 *streamids)
{
	struct acpi_iort_id *id;
	int i, num_streamids = 0;

	/* Move to ID section */
	id = ACPI_ADD_PTR(struct acpi_iort_id, node,
			  node->ref_to_ids);
	/* Hunt for endpoint ID map */
	for (i = 0; i < node->number_of_ids &&
	     i < (sizeof(streamids) / sizeof(*streamids)); i++)
		if (id[i].flags & IORT_ID_SINGLE_MAPPING)
			streamids[num_streamids++] = id[i].output_base;

	return num_streamids;
}
EXPORT_SYMBOL_GPL(iort_find_endpoint_id);

int
iort_map_pcidev_to_streamid(struct pci_dev *pdev, u32 req_id, u32 *stream_id)
{
	struct acpi_iort_header *node;
	struct acpi_iort_id *id;
	int i;

	node = iort_find_pci_rc(pci_domain_nr(pdev->bus));
	if (!node) {
		pr_err(IORT_PFX "can not find node related to PCI host bridge [segment %d]\n",
		       pci_domain_nr(pdev->bus));
		return -ENODEV;
	}

	/* Move to ID section */
	id = ACPI_ADD_PTR(struct acpi_iort_id, node,
			  node->ref_to_ids);

	/* Look for request ID to stream ID map */
	for (i = 0; i < node->number_of_ids; i++, id++) {


		if (id->flags & IORT_ID_SINGLE_MAPPING)
			continue;

		if (req_id < id->input_base ||
		    (req_id > id->input_base + id->length))
			continue;

		*stream_id = id->output_base + (req_id - id->input_base);
		return 0;
	}

	return -ENXIO;
}
EXPORT_SYMBOL_GPL(iort_map_pcidev_to_streamid);

static acpi_status
match_segment(acpi_handle handle, u32 lvl, void *context, void **ret_val)
{
	int *segment = context;
	struct acpi_pci_root *root;
	struct acpi_device *adev;
	struct acpi_buffer string = { ACPI_ALLOCATE_BUFFER, NULL };
	int err;

	if (!acpi_is_root_bridge(handle))
		return AE_OK;

	root = acpi_pci_find_root(handle);
	if (!root)
		return AE_OK;

	if (root->segment != *segment)
		return AE_OK;

	err = acpi_bus_get_device(handle, &adev);
	if (err) {
		if (ACPI_FAILURE(acpi_get_name(handle, ACPI_FULL_PATHNAME, &string)))
			pr_warn(IORT_PFX "Invalid link device, error %d\n",
				err);
		else {
			pr_warn(IORT_PFX "Invalid link for %s device\n",
				(char *)string.pointer);
			kfree(string.pointer);
		}
		return AE_OK;
	}

	*ret_val = &adev->dev;
	return AE_CTRL_TERMINATE;
}

struct device *
iort_find_node_device(struct acpi_iort_header *node)
{
	struct acpi_iort_named_component *acpi_dev;
	struct acpi_iort_root_complex *pci_rc;
	struct acpi_device *adev;
	struct device *device = NULL;
	acpi_handle handle;
	char *device_path;
	int segment;

	switch (node->type) {
	case ACPI_IORT_TYPE_NAMED_NODE:
		acpi_dev = ACPI_ADD_PTR(
			struct acpi_iort_named_component,
			node, sizeof(struct acpi_iort_header));

		device_path = acpi_dev->device_name;
		if (ACPI_FAILURE(acpi_get_handle(ACPI_ROOT_OBJECT, device_path,
						 &handle))) {
			pr_warn(IORT_PFX "Failed to find handle for ACPI object %s\n",
				device_path);
			break;
		}

		if (acpi_bus_get_device(handle, &adev)) {
			pr_warn(IORT_PFX "Failed to get device for ACPI object %s\n",
			       device_path);
			break;
		}

		device = &adev->dev;
		break;
	case ACPI_IORT_TYPE_ROOT_COMPLEX:
		pci_rc = ACPI_ADD_PTR(
			struct acpi_iort_root_complex,
			node, sizeof(struct acpi_iort_header));
		segment = pci_rc->segment;
		acpi_get_devices("PNP0A03", match_segment, &segment, (void **)&device);
		break;
	default:
		pr_err(IORT_PFX "can not find device for node type %d\n",
		       node->type);
		return NULL;
	}

	return device;
}
EXPORT_SYMBOL_GPL(iort_find_node_device);

static void iort_add_smmu_platform_device(struct acpi_iort_header *node)
{
	struct acpi_iort_smmu_v12 *smmu;
	struct platform_device_info pdevinfo;
	struct platform_device *pdev = NULL;
	struct resource resources;

	/* Move to SMMU1/2 specific data */
	smmu = ACPI_ADD_PTR(struct acpi_iort_smmu_v12, node,
				sizeof(struct acpi_iort_header));

	memset(&pdevinfo, 0, sizeof(pdevinfo));
	pdevinfo.parent = NULL;
	pdevinfo.name = "arm-smmu";
	pdevinfo.id = PLATFORM_DEVID_AUTO;

	memset(&resources, 0, sizeof(resources));
	resources.start = smmu->base_address;
	resources.end = smmu->base_address + smmu->span - 1;
	resources.flags = IORESOURCE_MEM;

	pdevinfo.res = &resources;
	pdevinfo.num_res = 1;

	pdevinfo.data = &node;
	pdevinfo.size_data = sizeof(node);

	pdev = platform_device_register_full(&pdevinfo);
	if (IS_ERR(pdev))
		pr_err("platform device creation failed: %ld\n",
			PTR_ERR(pdev));
	else
		pr_debug("Platform device arm-smmu created\n");
}

static int iort_add_smmu_devices(void)
{
	struct acpi_iort_header *iort_node = NULL;
	unsigned int idx = 0;

	while (1) {
		 iort_node = iort_find_node(ACPI_IORT_TYPE_SMMU_V12, idx++);
		 if (!iort_node)
			 break;

		 iort_add_smmu_platform_device(iort_node);
	}

	return 0;
}

static int __init iort_init(void)
{
	struct acpi_table_header *table;
	acpi_status status;

	if (acpi_disabled)
		return -ENODEV;

	status = acpi_get_table(ACPI_SIG_IORT, 0, &table);
	if (status == AE_NOT_FOUND)
		return -ENODEV;
	else if (ACPI_FAILURE(status)) {
		const char *msg = acpi_format_exception(status);
		pr_err(IORT_PFX "Failed to get table, %s\n", msg);
		return -EINVAL;
	}

	if (!table->length) {
		pr_err(IORT_PFX FW_BUG "0 length table\n");
		return -EINVAL;
	}

	iort_table = table;

	if(IS_ENABLED(CONFIG_ARM_SMMU))
		iort_add_smmu_devices();

	return 0;
}

static void __exit iort_exit(void)
{
	iort_table = NULL;
}

arch_initcall(iort_init);
module_exit(iort_exit);

MODULE_DESCRIPTION("IORT (I/O remapping ACPI table) parsing helpers");
MODULE_AUTHOR("Tomasz Nowicki <tomasz.nowicki@linaro.org>");
MODULE_LICENSE("GPL v2");
