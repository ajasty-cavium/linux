/*
 * PCIe host controller driver for Cavium Thunder SOC
 *
 * Copyright (C) 2014, Cavium Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/of_irq.h>
#include <linux/of_pci.h>
#include <linux/pci.h>
#include <linux/platform_device.h>
#include <linux/msi.h>

#define PCI_DEVICE_ID_THUNDER_BRIDGE	0xa002

#define THUNDER_PCIE_BUS_SHIFT		20
#define THUNDER_PCIE_DEV_SHIFT		15
#define THUNDER_PCIE_FUNC_SHIFT		12

#define THUNDER_ECAM0_CFG_BASE		0x848000000000
#define THUNDER_ECAM1_CFG_BASE		0x849000000000
#define THUNDER_ECAM2_CFG_BASE		0x84a000000000
#define THUNDER_ECAM3_CFG_BASE		0x84b000000000

struct thunder_pcie {
	struct device_node	*node;
	struct device		*dev;
	void __iomem		*cfg_base;
	struct msi_chip		*msi;
	int 			ecam;
};

/*
 * This bridge is just for the sake of supporting ARI for
 * downstream devices. No resources are attached to it.
 * Copy upstream root bus resources to bridge which aide in
 * resource claiming for downstream devices
 */
static void pci_bridge_resource_fixup(struct pci_dev *dev)
{
	struct pci_bus *bus;
	int resno;

	bus = dev->subordinate;
	for (resno = 0; resno < PCI_BRIDGE_RESOURCE_NUM; resno++) {
		bus->resource[resno] = pci_bus_resource_n(bus->parent,
			PCI_BRIDGE_RESOURCE_NUM + resno);
	}

	for (resno = PCI_BRIDGE_RESOURCES;
		resno <= PCI_BRIDGE_RESOURCE_END; resno++) {
		dev->resource[resno].start = dev->resource[resno].end = 0;
		dev->resource[resno].flags = 0;
	}
}
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_CAVIUM, PCI_DEVICE_ID_THUNDER_BRIDGE,
			pci_bridge_resource_fixup);

/*
 * All PCIe devices in Thunder have fixed resources, shouldn't be reassigned.
 * Also claim the device's valid resources to set 'res->parent' hierarchy.
 */
static void pci_dev_resource_fixup(struct pci_dev *dev)
{
	struct resource *res;
	int resno;

	for (resno = 0; resno < PCI_NUM_RESOURCES; resno++)
		dev->resource[resno].flags |= IORESOURCE_PCI_FIXED;

	for (resno = 0; resno < PCI_BRIDGE_RESOURCES; resno++) {
		res = &dev->resource[resno];
		if (res->parent || !(res->flags & IORESOURCE_MEM))
			continue;
		pci_claim_resource(dev, resno);
	}
}
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_CAVIUM, PCI_ANY_ID,
			pci_dev_resource_fixup);

static int thunder_pcie_check_cfg_access(int ecam, unsigned int bus,
					 unsigned int devfn)
{
	int supported = 0;
	uint16_t bdf = (bus << 8) | devfn;

	if (ecam == 0) {
		switch (bdf) {
			case 0x008:   /* RSL bridge */
			case 0x010:   /* SMMU */
			case 0x030:   /* GPIO */
			case 0x038:   /* MPI */
			case 0x0A0:   /* RAD bridge */
			case 0x0A8:   /* ZIP bridge */
			case 0x0B0:   /* DFA bridge */
			case 0x100:   /* MRML */
			case 0x101:   /* RST */
			case 0x103:   /* FUS */
			case 0x104:   /* FUSF */
			case 0x109:   /* L2C */
			case 0x10A:   /* SGPIO */
			case 0x10C:   /* EMM */
			case 0x10D:   /* KEY */
			case 0x10e:   /* MIO_BOOT */
			case 0x180:   /* BGX0 */
			case 0x181:   /* BGX1 */
			case 0x1E2:   /* GSER2 */
			case 0x1E3:   /* GSER3 */
			case 0x1E6:   /* GSER6 */
			case 0x1E7:   /* GSER7 */
				supported = 1;
				break;
			default:
				supported = 0;
		}
	} else if (ecam == 1) {
		switch (bdf) {
			case 0x008:   /* SMMU */
			case 0x020:   /* AHCI0*/
			//case 0x028:   /* AHCI1 */
			//case 0x030:   /* AHCI2 */
			//case 0x038:   /* AHCI3 */
			//case 0x040:   /* AHCI4 */
			//case 0x048:   /* AHCI5 */
			//case 0x050:   /* AHCI5 */
			//case 0x058:   /* AHCI7 */
			//case 0x080:   /* PCIRC0 */
			//case 0x098:   /* PCIRC1 */
			//case 0x0A8:   /* PCIRC2 */
				supported = 1;
				break;
			default:
				supported = 0;
		}
	} else if (ecam == 2) {
		switch (bdf) {
			case 0x008:   /* SMMU */
			case 0x010:   /* NIC Bridge */
			case 0x100:   /* NIC PF */
			case 0x101:   /* NIC VF */
			case 0x102:   /* NIC VF */
			case 0x103:   /* NIC VF */
			case 0x104:   /* NIC VF */
			case 0x105:   /* NIC VF */
			case 0x106:   /* NIC VF */
			case 0x107:   /* NIC VF */
			case 0x108:   /* NIC VF */
			case 0x109:   /* NIC VF */
			case 0x10A:   /* NIC VF */
			case 0x10B:   /* NIC VF */
			case 0x10C:   /* NIC VF */
			case 0x10D:   /* NIC VF */
			case 0x10E:   /* NIC VF */
			case 0x110:   /* NIC VF */
				supported = 1;
				break;
			default:
				supported = 0;
		}
	} else if (ecam == 3) {
		switch (bdf) {
			case 0x008:   /* SMMU */
		//	case 0x018:   /* AHCI8 */
		//	case 0x020:   /* AHCI9*/
		//	case 0x028:   /* AHCI10 */
		//	case 0x030:   /* AHCI11 */
		//	case 0x038:   /* AHCI12 */
		//	case 0x040:   /* AHCI13 */
		//	case 0x048:   /* AHCI14 */
		//	case 0x050:   /* AHCI15 */
			//case 0x080:   /* PCIRC3 */
			//case 0x098:   /* PCIRC4 */
			//case 0x0A8:   /* PCIRC5 */
				supported = 1;
				break;
			default:
				supported = 0;
		}
	}
	return supported;
}

static void __iomem *thunder_pcie_cfg_base(struct thunder_pcie *pcie,
				 unsigned int bus, unsigned int devfn)
{
	return  pcie->cfg_base + ((bus << THUNDER_PCIE_BUS_SHIFT)
		| (PCI_SLOT(devfn) << THUNDER_PCIE_DEV_SHIFT)
		| (PCI_FUNC(devfn) << THUNDER_PCIE_FUNC_SHIFT));
}

static int thunder_pcie_read_config(struct pci_bus *bus, unsigned int devfn,
				  int reg, int size, u32 *val)
{
	struct thunder_pcie *pcie = bus->sysdata;
	void __iomem *addr;
	unsigned int busnr = bus->number;
	int supported;

	if (busnr > 255 || devfn > 255 || reg > 4095)
		return PCIBIOS_DEVICE_NOT_FOUND;

	addr = thunder_pcie_cfg_base(pcie, busnr, devfn) + reg;

	supported = thunder_pcie_check_cfg_access(pcie->ecam, busnr, devfn);

	switch (size) {
	case 1:
		if (!supported) 
			*val = 0xff;
		else 
			*val = readb(addr);
		break;
	case 2:
		if (!supported)
			*val = 0xffff;
		else 
			*val = readw(addr);
		break;
	case 4:
		if (!supported)
			*val = 0xffffffff;
		else 
			*val = readl(addr);
		break;
	default:
		return PCIBIOS_BAD_REGISTER_NUMBER;
	}

	return PCIBIOS_SUCCESSFUL;
}

static int thunder_pcie_write_config(struct pci_bus *bus, unsigned int devfn,
				  int reg, int size, u32 val)
{
	struct thunder_pcie *pcie = bus->sysdata;
	void __iomem *addr;
	unsigned int busnr = bus->number;

	if (busnr > 255 || devfn > 255 || reg > 4095)
		return PCIBIOS_DEVICE_NOT_FOUND;

	addr = thunder_pcie_cfg_base(pcie, busnr, devfn) + reg;

	switch (size) {
	case 1:
		writeb(val, addr);
		break;
	case 2:
		writew(val, addr);
		break;
	case 4:
		writel(val, addr);
		break;
	default:
		return PCIBIOS_BAD_REGISTER_NUMBER;
	}

	return PCIBIOS_SUCCESSFUL;
}

static struct pci_ops thunder_pcie_ops = {
	.read	= thunder_pcie_read_config,
	.write	= thunder_pcie_write_config,
};

static int thunder_pcie_msi_enable(struct thunder_pcie *pcie,
					struct pci_bus *bus)
{
	struct device_node *msi_node;

	msi_node = of_parse_phandle(pcie->node, "msi-parent", 0);
	if (!msi_node)
		return -ENODEV;

	pcie->msi = of_pci_find_msi_chip_by_node(msi_node);
	if (!pcie->msi)
		return -ENODEV;

	pcie->msi->dev = pcie->dev;
	bus->msi = pcie->msi;

	return 0;
}

static int thunder_pcie_probe(struct platform_device *pdev)
{
	struct thunder_pcie *pcie;
	struct resource *cfg_base;
	struct pci_bus *bus;
	int ret;
	LIST_HEAD(res);

	pcie = devm_kzalloc(&pdev->dev, sizeof(*pcie), GFP_KERNEL);
	if (!pcie)
		return -ENOMEM;

	pcie->node = of_node_get(pdev->dev.of_node);
	pcie->dev = &pdev->dev;

	/* Get controller's configuration space range */
	cfg_base = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	switch(cfg_base->start) {
		case THUNDER_ECAM0_CFG_BASE:
			pcie->ecam = 0;
			break;
		case THUNDER_ECAM1_CFG_BASE:
			pcie->ecam = 1;
			break;
		case THUNDER_ECAM2_CFG_BASE:
			pcie->ecam = 2;
			break;
		case THUNDER_ECAM3_CFG_BASE:
			pcie->ecam = 3;
			break;
	}
	pr_err("%s: ECAM%d CFG BASE 0x%llx\n",__func__, pcie->ecam, (uint64_t)cfg_base->start);

	pcie->cfg_base = devm_ioremap_resource(&pdev->dev, cfg_base);
	if (IS_ERR(pcie->cfg_base)) {
		ret = PTR_ERR(pcie->cfg_base);
		goto err_ioremap;
	}

	ret = of_pci_get_host_bridge_resources(pdev->dev.of_node,
					       0, 255, &res, NULL);
	if (ret)
		goto err_get_host;

	bus = pci_create_root_bus(&pdev->dev, 0, &thunder_pcie_ops, pcie, &res);
	if (!bus) {
		ret = -ENODEV;
		goto err_root_bus;
	}

	/* Set reference to MSI chip */
	ret = thunder_pcie_msi_enable(pcie, bus);
	if (ret)
		goto err_msi;

	platform_set_drvdata(pdev, pcie);

	pci_scan_child_bus(bus);
	pci_bus_add_devices(bus);

	return 0;
err_msi:
	pci_remove_root_bus(bus);
err_root_bus:
	pci_free_resource_list(&res);
err_get_host:
	devm_ioremap_release(pcie->dev, pcie->cfg_base);
err_ioremap:
	of_node_put(pcie->node);
	kfree(pcie);
	return ret;
}

static const struct of_device_id thunder_pcie_of_match[] = {
	{ .compatible = "cavium,thunder-pcie", },
	{},
};
MODULE_DEVICE_TABLE(of, thunder_pcie_of_match);

static struct platform_driver thunder_pcie_driver = {
	.driver = {
		.name = "thunder-pcie",
		.owner = THIS_MODULE,
		.of_match_table = thunder_pcie_of_match,
	},
	.probe = thunder_pcie_probe,
};
module_platform_driver(thunder_pcie_driver);

MODULE_AUTHOR("Sunil Goutham");
MODULE_DESCRIPTION("Cavium Thunder PCIe host controller driver");
MODULE_LICENSE("GPL v2");
