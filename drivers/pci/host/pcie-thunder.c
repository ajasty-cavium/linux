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

struct thunder_pcie {
	struct device_node	*node;
	struct device		*dev;
	void __iomem		*cfg_base;
	struct msi_chip		*msi;
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

	if (busnr > 255 || devfn > 255 || reg > 4095)
		return PCIBIOS_DEVICE_NOT_FOUND;

	addr = thunder_pcie_cfg_base(pcie, busnr, devfn) + reg;

	switch (size) {
	case 1:
		*val = readb(addr);
		break;
	case 2:
		*val = readw(addr);
		break;
	case 4:
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
