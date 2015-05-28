/*
 *  Copyright Cavium, Inc. (C) 2015. All rights reserved.
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
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/pci.h>
#include <linux/pci_ids.h>
#include <linux/edac.h>
#include <linux/interrupt.h>

#include "edac_core.h"
#include "edac_module.h"

#ifndef PCI_DEVICE_ID_THUNDER_OCX
#define PCI_DEVICE_ID_THUNDER_OCX 0xa013
#endif

#define OCX_INTS		4

#define OCX_COM_INT		0x100
#define OCX_COM_INT_W1S		0x108
#define OCX_COM_INT_ENA_W1S	0x110
#define OCX_COM_INT_ENA_W1C	0x118

#define OCX_COM_LINKX_INT(x)		(0x120 + (x) * 8)
#define OCX_COM_LINKX_INT_W1S(x)	(0x140 + (x) * 8)
#define OCX_COM_LINKX_INT_ENA_W1S(x)	(0x160 + (x) * 8)
#define OCX_COM_LINKX_INT_ENA_W1C(x)	(0x180 + (x) * 8)

#define OCX_COM_INT_ENA_ALL	((0x1fULL << 50) | (0xffffffULL))

#define OCX_COM_LINKX_INT_ENA_ALL	((3 << 12) | (7 << 7) | (0x3f))

static int edac_ocx_idx;

struct thunderx_ocx {
	void __iomem *regs;
	struct pci_dev *pdev;
	struct edac_device_ctl_info *edac_dev;

	struct msix_entry msix_ent[OCX_INTS];

	int int_id[OCX_INTS];
};

static irqreturn_t thunderx_ocx_com_isr(int irq, void *irq_id)
{
	int *int_id = irq_id;
	struct thunderx_ocx *ocx = container_of(int_id, struct thunderx_ocx,
						int_id[*int_id]);

	u64 ocx_com_int = readq(ocx->regs + OCX_COM_INT);

	dev_info(&ocx->pdev->dev, "OCX_COM_INT: %016llx\n", ocx_com_int);

	writeq(ocx_com_int, ocx->regs + OCX_COM_INT);

	edac_device_handle_ue(ocx->edac_dev, 0, 0, ocx->edac_dev->ctl_name);

	return IRQ_HANDLED;
}

static irqreturn_t thunderx_ocx_lnk_isr(int irq, void *irq_id)
{
	int *int_id = irq_id;

	struct thunderx_ocx *ocx = container_of(int_id, struct thunderx_ocx,
						int_id[*int_id]);

	u64 ocx_com_link_int = readq(ocx->regs + OCX_COM_LINKX_INT(*int_id));

	dev_info(&ocx->pdev->dev, "OCX_COM_LINK_INT[%d]: %016llx\n",
		 *int_id, ocx_com_link_int);

	writeq(ocx_com_link_int, ocx->regs + OCX_COM_LINKX_INT(*int_id));

	edac_device_handle_ue(ocx->edac_dev, 0, 0, ocx->edac_dev->ctl_name);

	return IRQ_HANDLED;
}


static const struct pci_device_id thunderx_ocx_pci_tbl[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, PCI_DEVICE_ID_THUNDER_OCX) },
	{ 0, },
};


static int thunderx_ocx_probe(struct pci_dev *pdev,
			      const struct pci_device_id *id)
{
	struct thunderx_ocx *ocx;
	struct edac_device_ctl_info *edac_dev;
	int err, i, irq_num;

	edac_dev = edac_device_alloc_ctl_info(sizeof(struct thunderx_ocx),
					      "OCX", 1, "CCPI", 1, 0, NULL, 0,
					      edac_ocx_idx);
	if (!edac_dev) {
		dev_err(&pdev->dev, "Cannot allocate EDAC device\n");
		return -ENOMEM;
	}

	err = pci_enable_device(pdev);
	if (err) {
		dev_err(&pdev->dev, "Cannot enable PCI device, aborting\n");
		goto err_free_mem;
	}

	err = pci_request_regions(pdev, "thunderx_ocx");
	if (err) {
		dev_err(&pdev->dev, "Cannot obtain PCI resources, aborting\n");
		goto err_dis_pdev;
	}

	ocx = edac_dev->pvt_info;
	ocx->edac_dev = edac_dev;

	ocx->regs = pci_ioremap_bar(pdev, 0);

	if (!ocx->regs) {
		dev_err(&pdev->dev, "Cannot remap BAR0");
		err = -ENODEV;
		goto err_release;
	}

	ocx->pdev = pdev;

	for (i = 0; i < OCX_INTS; i++) {
		ocx->int_id[i] = i;
		ocx->msix_ent[i].entry = i;
		ocx->msix_ent[i].vector = 0;
	}

	err = pci_enable_msix(pdev, ocx->msix_ent, OCX_INTS);
	if (err < 0) {
		dev_err(&pdev->dev, "Cannot enable interrupt\n");
		goto err_unmap;
	}


	for (i = 0; i < OCX_INTS; i++) {
		err = request_irq(ocx->msix_ent[i].vector,
				  (i == 0) ? thunderx_ocx_com_isr :
					     thunderx_ocx_lnk_isr,
				  0, "[EDAC] ThunderX OCX",
				  &ocx->int_id[i]);
		irq_num = i;

		if (err < 0)
			goto err_free_irq;
	}

	edac_dev->dev = &pdev->dev;
	edac_dev->dev_name = dev_name(&pdev->dev);
	edac_dev->mod_name = "thunderx-ocx";
	edac_dev->ctl_name = "thunderx-ocx-err";

	err = edac_device_add_device(edac_dev);
	if (err) {
		dev_err(&pdev->dev, "Cannot add EDAC device\n");
		goto err_free_irq;
	}

	pci_set_drvdata(pdev, edac_dev);

	writeq(OCX_COM_INT_ENA_ALL, ocx->regs + OCX_COM_INT_ENA_W1S);

	for (i = 0; i < OCX_INTS; i++) {
		writeq(OCX_COM_LINKX_INT_ENA_ALL,
		       ocx->regs + OCX_COM_LINKX_INT_ENA_W1S(i));
	}

	return 0;

err_free_irq:
	for (i = 0; i < irq_num; i++)
		free_irq(ocx->msix_ent[i].vector, &ocx->int_id[i]);

	pci_disable_msix(pdev);
err_unmap:
	iounmap(ocx->regs);
err_release:
	pci_release_regions(pdev);

err_dis_pdev:
	pci_disable_device(pdev);

err_free_mem:
	edac_device_free_ctl_info(edac_dev);

	return err;
}


static void thunderx_ocx_remove(struct pci_dev *pdev)
{
	struct edac_device_ctl_info *edac_dev = pci_get_drvdata(pdev);
	struct thunderx_ocx *ocx = edac_dev->pvt_info;
	int i;

	writeq(OCX_COM_INT_ENA_ALL, ocx->regs + OCX_COM_INT_ENA_W1C);

	for (i = 0; i < OCX_INTS; i++) {
		writeq(OCX_COM_LINKX_INT_ENA_ALL,
		       ocx->regs + OCX_COM_LINKX_INT_ENA_W1C(i));
	}


	edac_device_del_device(&pdev->dev);

	for (i = 0; i < OCX_INTS; i++)
		free_irq(ocx->msix_ent[i].vector, &ocx->int_id[i]);

	pci_disable_msix(pdev);

	pci_disable_device(pdev);

	iounmap(ocx->regs);

	pci_release_regions(pdev);

	edac_device_free_ctl_info(edac_dev);
}

MODULE_DEVICE_TABLE(pci, thunderx_ocx_pci_tbl);

static struct pci_driver thunderx_ocx_driver = {
	.name     = "thunderx_ocx_edac",
	.probe    = thunderx_ocx_probe,
	.remove   = thunderx_ocx_remove,
	.id_table = thunderx_ocx_pci_tbl,
};

module_pci_driver(thunderx_ocx_driver);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Cavium, Inc.");
MODULE_DESCRIPTION("EDAC Driver for Cavium ThunderX");
