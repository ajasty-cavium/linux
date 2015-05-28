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
#include <linux/ctype.h>

#include "edac_core.h"
#include "edac_module.h"

#ifndef PCI_DEVICE_ID_THUNDER_LMC
#define PCI_DEVICE_ID_THUNDER_LMC 0xa022
#endif

#define LMC_FADR	0x20
#define LMC_FADR_FCID(x)	((x >> 40) & 0x7)
#define LMC_FADR_FILL_ORDER(x)	((x >> 38) & 0x3)
#define LMC_FADR_FDIMM(x)	((x >> 37) & 0x1)
#define LMC_FADR_FBUNK(x)	((x >> 36) & 0x1)
#define LMC_FADR_FBANK(x)	((x >> 32) & 0xf)
#define LMC_FADR_FROW(x)	((x >> 17) & 0xfffe)
#define LMC_FADR_FCOL(x)	((x >> 17) & 0x1fff)


#define LMC_NXM_FADR	0x28
#define LMC_ECC_SYND	0x38

#define LMC_ECC_PARITY_TEST	0x108

#define LMC_INT_W1S	0x150
#define LMC_INT_ENA_W1C	0x158
#define LMC_INT_ENA_W1S	0x160

#define LMC_INT_EN	0x1E8
#define LMC_INT		0x1F0

#define LMC_SCRAM_FADR	0x330

#define LMC_INT_MACRAM_DED_ERR	(1 << 13)
#define LMC_INT_MACRAM_SEC_ERR	(1 << 12)
#define LMC_INT_DDR_ERR		(1 << 11)
#define LMC_INT_DLCRAM_DED_ERR	(1 << 10)
#define LMC_INT_DLCRAM_SEC_ERR	(1 << 9)
#define LMC_INT_DED_ERR(x)	((x >> 5) & 0xf)
#define LMC_INT_SEC_ERR(x)	((x >> 1) & 0xf)
#define LMC_INT_NXM_WR_MASK	(1 << 0)

#define LMC_INT_EN_DDR_ERROR_ALERT_ENA	(1 << 5)
#define LMC_INT_EN_DLCRAM_DED_ERR	(1 << 4)
#define LMC_INT_EN_DLCRAM_SEC_ERR	(1 << 3)
#define LMC_INT_INTR_DED_ENA		(1 << 2)
#define LMC_INT_INTR_SEC_ENA		(1 << 1)
#define LMC_INT_INTR_NXM_WR_ENA		(1 << 0)

#define LMC_INT_EN_ALL			0x3f
#define LMC_INT_ENA_ALL			0x1fff

#define LMC_DDR_PLL_CTL		0x258
#define LMC_DDR_PLL_CTL_DDR4	(1 << 29)

#define LMC_CONTROL		0x190
#define LMC_CONTROL_RDIMM	(1 << 0)

struct thunderx_lmc {
	void __iomem *regs;
	struct pci_dev *pdev;

	struct msix_entry msix_ent;

	int edac_mc_idx;
};

#define to_mci(k) container_of(k, struct mem_ctl_info, dev)

static int edac_mc_idx;

static ssize_t thunderx_lmc_inject_ecc_show(struct device *dev,
					    struct device_attribute *mattr,
					    char *data)
{
	struct mem_ctl_info *mci = to_mci(dev);
	struct thunderx_lmc *lmc = mci->pvt_info;

	return sprintf(data, "0x%016llx",
		       readq(lmc->regs + LMC_ECC_PARITY_TEST));
}


static ssize_t thunderx_lmc_inject_ecc_store(struct device *dev,
					     struct device_attribute *mattr,
					     const char *data, size_t count)
{
	struct mem_ctl_info *mci = to_mci(dev);
	struct thunderx_lmc *lmc = mci->pvt_info;

	if (count < 3 || data[0] != '0')
		return 0;

	if (tolower(data[1]) == 'x' && isxdigit(data[2])) {
		writeq(simple_strtoul(data, NULL, 0),
				lmc->regs + LMC_ECC_PARITY_TEST);
		return count;
	}
	return 0;
}

DEVICE_ATTR(inject, S_IRUGO | S_IWUSR,
	    thunderx_lmc_inject_ecc_show, thunderx_lmc_inject_ecc_store);


static ssize_t thunderx_lmc_inject_int_show(struct device *dev,
					    struct device_attribute *mattr,
					    char *data)
{
	struct mem_ctl_info *mci = to_mci(dev);
	struct thunderx_lmc *lmc = mci->pvt_info;

	return sprintf(data, "0x%016llx",
		       readq(lmc->regs + LMC_INT_W1S));
}


static ssize_t thunderx_lmc_inject_int_store(struct device *dev,
					     struct device_attribute *mattr,
					     const char *data, size_t count)
{
	struct mem_ctl_info *mci = to_mci(dev);
	struct thunderx_lmc *lmc = mci->pvt_info;

	if (count < 3 || data[0] != '0')
		return 0;
	if (tolower(data[1]) == 'x' && isxdigit(data[2])) {
		writeq(simple_strtoul(data, NULL, 0),
				lmc->regs + LMC_INT_W1S);
		return count;
	}
	return 0;
}

DEVICE_ATTR(inject_ecc, S_IRUGO | S_IWUSR,
	    thunderx_lmc_inject_ecc_show, thunderx_lmc_inject_ecc_store);
DEVICE_ATTR(inject_int, S_IRUGO | S_IWUSR,
	    thunderx_lmc_inject_int_show, thunderx_lmc_inject_int_store);


static int thunderx_create_sysfs_attrs(struct mem_ctl_info *mci)
{
	int rc;

	rc = device_create_file(&mci->dev, &dev_attr_inject_ecc);
	if (rc < 0)
		return rc;

	rc = device_create_file(&mci->dev, &dev_attr_inject_int);
	if (rc < 0)
		return rc;


	return 0;
}

static void thunderx_remove_sysfs_attrs(struct mem_ctl_info *mci)
{
	device_remove_file(&mci->dev, &dev_attr_inject_int);
	device_remove_file(&mci->dev, &dev_attr_inject_ecc);
}

static irqreturn_t thunderx_lmc_err_isr(int irq, void *dev_id)
{
	struct mem_ctl_info *mci = dev_id;
	struct thunderx_lmc *lmc = mci->pvt_info;
	char msg[64];

	u64 lmc_int = readq(lmc->regs + LMC_INT);
	u64 lmc_fadr = readq(lmc->regs + LMC_FADR);
	u64 lmc_nxm_fadr = readq(lmc->regs + LMC_NXM_FADR);
	u64 lmc_scram_fadr = readq(lmc->regs + LMC_SCRAM_FADR);


	dev_info(&lmc->pdev->dev, "LMC_INT: %016llx\n", lmc_int);
	dev_info(&lmc->pdev->dev, "LMC_FADR: %016llx\n", lmc_fadr);
	dev_info(&lmc->pdev->dev, "LMC_NXM_FADR: %016llx\n", lmc_nxm_fadr);
	dev_info(&lmc->pdev->dev, "LMC_SCRAM_FADR: %016llx\n", lmc_scram_fadr);


	snprintf(msg, sizeof(msg),
		 "DIMM %lld rank %lld bank %lld row %lld col %lld",
		 LMC_FADR_FDIMM(lmc_fadr), LMC_FADR_FBUNK(lmc_fadr),
		 LMC_FADR_FBANK(lmc_fadr), LMC_FADR_FROW(lmc_fadr),
		 LMC_FADR_FCOL(lmc_fadr));

	writeq(lmc_int, lmc->regs + LMC_INT);

	if (LMC_INT_SEC_ERR(lmc_int))
		edac_mc_handle_error(HW_EVENT_ERR_CORRECTED, mci, 1, 0, 0, 0,
				     -1, -1, -1, msg, "");

	if (LMC_INT_SEC_ERR(lmc_int))
		edac_mc_handle_error(HW_EVENT_ERR_UNCORRECTED, mci, 1, 0, 0, 0,
				     -1, -1, -1, msg, "");

	return IRQ_HANDLED;
}


static const struct pci_device_id thunderx_lmc_pci_tbl[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, PCI_DEVICE_ID_THUNDER_LMC) },
	{ 0, },
};


static int thunderx_lmc_probe(struct pci_dev *pdev,
				const struct pci_device_id *id)
{
	struct thunderx_lmc *lmc;
	struct edac_mc_layer layer;
	struct mem_ctl_info *mci;
	u64 lmc_control, lmc_ddr_pll_ctl;
	int err;
	u64 lmc_int;

	layer.type = EDAC_MC_LAYER_CHANNEL;
	layer.size = 1;
	layer.is_virt_csrow = false;

	mci = edac_mc_alloc(edac_mc_idx, 1, &layer,
				sizeof(struct thunderx_lmc));

	if (!mci)
		return -ENOMEM;

	mci->pdev = &pdev->dev;
	lmc = mci->pvt_info;

	pci_set_drvdata(pdev, mci);

	err = pci_enable_device(pdev);
	if (err) {
		dev_err(&pdev->dev, "Cannot enable PCI device, aborting\n");
		goto err_kfree;
	}

	err = pci_request_regions(pdev, "thunderx_lmc");
	if (err) {
		dev_err(&pdev->dev, "Cannot obtain PCI resources, aborting\n");
		goto err_dis_pdev;
	}

	lmc->regs = pci_ioremap_bar(pdev, 0);

	if (!lmc->regs) {
		dev_err(&pdev->dev, "Cannot remap BAR0");
		err = -ENODEV;
		goto err_free_reg;
	}

	lmc_control = readq(lmc->regs + LMC_CONTROL);
	lmc_ddr_pll_ctl = readq(lmc->regs + LMC_DDR_PLL_CTL);

	if (lmc_control & LMC_CONTROL_RDIMM) {
		mci->mtype_cap = (lmc_ddr_pll_ctl & LMC_DDR_PLL_CTL_DDR4) ?
				MEM_RDDR4 : MEM_RDDR3;
	} else {
		mci->mtype_cap = (lmc_ddr_pll_ctl & LMC_DDR_PLL_CTL_DDR4) ?
				MEM_DDR4 : MEM_DDR3;
	}

	mci->mtype_cap = MEM_RDDR4 | MEM_RDDR3 | MEM_DDR4 | MEM_DDR3;
	mci->edac_ctl_cap = EDAC_FLAG_NONE | EDAC_FLAG_SECDED;
	mci->edac_cap = EDAC_FLAG_SECDED;

	mci->mod_name = "thunderx-lmc";
	mci->mod_ver = "1";
	mci->ctl_name = "thunderx-lmc-err";
	mci->dev_name = dev_name(&pdev->dev);
	mci->scrub_mode = SCRUB_SW_SRC;

	lmc->edac_mc_idx = edac_mc_idx++;

#if 0
	/* Only a single 4GB DIMM is supported */
	dimm = *mci->dimms;
	dimm->nr_pages = (~0UL >> PAGE_SHIFT) + 1;
	dimm->grain = 8;
	dimm->dtype = DEV_X8;
	dimm->mtype = MEM_DDR3;
	dimm->edac_mode = EDAC_SECDED;
#endif

	err = edac_mc_add_mc(mci);
	if (err < 0)
		goto err_unmap;

	if (thunderx_create_sysfs_attrs(mci)) {
		dev_err(&pdev->dev, "Cannot add device attrs\n");
		goto err_del_mc;
	}


	lmc->pdev = pdev;

	lmc->msix_ent.entry = 0;
	lmc->msix_ent.vector = 0;


	err = pci_enable_msix(pdev, &lmc->msix_ent, 1);
	if (err < 0) {
		dev_err(&pdev->dev, "Cannot enable interrupt\n");
		goto err_del_attrs;
	}

	err = request_irq(lmc->msix_ent.vector,
			  thunderx_lmc_err_isr, 0,
			  "[EDAC] ThunderX LMC",
			  mci);


	writeq(LMC_INT_EN_ALL, lmc->regs + LMC_INT_EN);
	writeq(LMC_INT_ENA_ALL, lmc->regs + LMC_INT_ENA_W1S);

	lmc_int = readq(lmc->regs + LMC_INT);
	writeq(lmc_int, lmc->regs + LMC_INT);

	return 0;

err_del_attrs:
	thunderx_remove_sysfs_attrs(mci);
err_del_mc:
	edac_mc_del_mc(mci->pdev);
err_unmap:
	iounmap(lmc->regs);
err_free_reg:
	pci_release_regions(pdev);
err_dis_pdev:
	pci_disable_device(pdev);
err_kfree:
	kfree(mci);

	return err;
}


static void thunderx_lmc_remove(struct pci_dev *pdev)
{
	struct mem_ctl_info *mci = pci_get_drvdata(pdev);
	struct thunderx_lmc *lmc = mci->pvt_info;

	writeq(0, lmc->regs + LMC_INT_EN);
	writeq(LMC_INT_ENA_ALL, lmc->regs + LMC_INT_ENA_W1C);


	edac_mc_del_mc(&pdev->dev);
	thunderx_remove_sysfs_attrs(mci);

	free_irq(lmc->msix_ent.vector, mci);
	pci_disable_msix(pdev);

	pci_disable_device(pdev);

	iounmap(lmc->regs);
	pci_release_regions(pdev);

	edac_mc_free(mci);
}

MODULE_DEVICE_TABLE(pci, thunderx_lmc_pci_tbl);

static struct pci_driver thunderx_lmc_driver = {
	.name     = "thunderx_lmc_edac",
	.probe    = thunderx_lmc_probe,
	.remove   = thunderx_lmc_remove,
	.id_table = thunderx_lmc_pci_tbl,
};

module_pci_driver(thunderx_lmc_driver);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Cavium, Inc.");
MODULE_DESCRIPTION("EDAC Driver for Cavium ThunderX");
