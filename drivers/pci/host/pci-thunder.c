/*
 * PCIe host controller driver for Cavium Thunder SOC
 *
 * Copyright (C) 2013, Cavium Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/delay.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/of_pci.h>
#include <linux/pci.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/msi.h>

#define THUNDER_PCIE_BUS_SHIFT          20
#define THUNDER_PCIE_DEV_SHIFT          15
#define THUNDER_PCIE_FUNC_SHIFT         12

struct thunder_pcie {
	struct device_node	*node;
	struct device		*dev;
	void __iomem		*cfg_base;
	struct msi_chip 	*msi;
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
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_CAVIUM, PCI_DEVICE_ID_8XXX_BRIDGE, 
						pci_bridge_resource_fixup);

/*
 * All PCIe devices in Thunder have fixed resources, shouldn't be reassigned.
 * Also claim the device's valid resources to set 'res->parent' hierarchy.
 */
static void pci_dev_resource_fixup(struct pci_dev *dev)
{
        struct resource *res;
        int resno;

        for (resno = 0; resno <= PCI_NUM_RESOURCES; resno++) {
                dev->resource[resno].flags |= IORESOURCE_PCI_FIXED;
        }

        for (resno = 0; resno < PCI_BRIDGE_RESOURCES; resno++) {
                res = &dev->resource[resno];
                if (res->parent || !(res->flags & IORESOURCE_MEM))
                        continue;
                pci_claim_resource(dev, resno);
        }
}
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_CAVIUM, PCI_ANY_ID, 
						pci_dev_resource_fixup);

static void __iomem *thunder_pcie_build_config_addr(struct thunder_pcie *pcie,
					 int bus, int dev, int fn, int reg)
{
        void __iomem *cfg_addr = NULL;

        cfg_addr =  pcie->cfg_base + 
			((bus << THUNDER_PCIE_BUS_SHIFT) |
        		(dev << THUNDER_PCIE_DEV_SHIFT) |
        		(fn  << THUNDER_PCIE_FUNC_SHIFT) |
			(reg & ~0x3));

        return cfg_addr;
}

static int thunder_pcie_read_config(struct pci_bus *bus, unsigned int devfn,
				  int reg, int size, u32 *val)
{
	struct thunder_pcie *pcie = bus->sysdata;
	void __iomem *addr;

	addr = thunder_pcie_build_config_addr(pcie, bus->number, 
				devfn >> 3,  devfn & 0x7, reg);
	*val = readl(addr);

	if (size == 1) 
		*val = (*val >> (8 * (reg & 3))) & 0xff;
	else if (size == 2)
		*val = (*val >> (8 * (reg & 3))) & 0xffff;
	
	return PCIBIOS_SUCCESSFUL;
}

static int thunder_pcie_write_config(struct pci_bus *bus, unsigned int devfn,
				  int reg, int size, u32 val)
{
	struct thunder_pcie *pcie = bus->sysdata;
	void __iomem *addr;
	u32 cur_val, final_val;

	addr = thunder_pcie_build_config_addr(pcie, bus->number, 
				devfn >> 3,  devfn & 0x7, reg);
	cur_val = readl(addr);

	switch (size) {
	case 1:
		val = ((val & 0xff) << (8 * (reg & 3)));
		cur_val = cur_val & ~(0xff << (8 * (reg & 3)));
		break;
	case 2:
		val = ((val & 0xffff) << (8 * (reg & 3)));
		cur_val = cur_val & ~(0xffff << (8 * (reg & 3)));
		break;
	case 4:
		cur_val = 0;
		break;
	default:
		return PCIBIOS_FUNC_NOT_SUPPORTED;	
	}

	final_val = cur_val | val;
	writel(final_val, addr);
	
	return PCIBIOS_SUCCESSFUL;
}

static struct pci_ops thunder_pcie_ops = {
	.read = thunder_pcie_read_config,
	.write = thunder_pcie_write_config
};

static void thunder_pcie_msi_enable(struct thunder_pcie *pcie, 
					struct pci_bus *bus)
{
	struct device_node *msi_node;

	msi_node = of_parse_phandle(pcie->node, "msi-parent", 0);
	if (!msi_node)
		return;
	
	pcie->msi = of_pci_find_msi_chip_by_node(msi_node);

	if (pcie->msi)
		pcie->msi->dev = pcie->dev;
	bus->msi = pcie->msi;
}

struct device_node *pcibios_get_phb_of_node(struct pci_bus *bus)
{
	struct thunder_pcie *pcie = (struct thunder_pcie *)bus->sysdata;
	return of_node_get(pcie->node);
}

static int thunder_pcie_probe(struct platform_device *pdev)
{
	struct device_node *np = of_node_get(pdev->dev.of_node);
	struct thunder_pcie *pcie;
	struct resource *cfg_base;
	struct pci_host_bridge *bridge;
	resource_size_t lastbus;

	pcie = devm_kzalloc(&pdev->dev, sizeof(*pcie), GFP_KERNEL);
	if (!pcie)
		return -ENOMEM;

	pcie->dev = &pdev->dev;
	pcie->node = np;

	/* Get controller's configuration space range */
	cfg_base = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	pcie->cfg_base = devm_ioremap_resource(&pdev->dev, cfg_base);
	if (IS_ERR(pcie->cfg_base))
		return PTR_ERR(pcie->cfg_base);

	bridge = of_create_pci_host_bridge(&pdev->dev, &thunder_pcie_ops, pcie);
	if (IS_ERR_OR_NULL(bridge))
		return PTR_ERR(bridge);

	/* Set reference to MSI chip */
	thunder_pcie_msi_enable(pcie, bridge->bus);

	platform_set_drvdata(pdev, pcie);

	lastbus = pci_scan_child_bus(bridge->bus);
	pci_bus_add_devices(bridge->bus);
	pci_bus_update_busn_res_end(bridge->bus, lastbus);

	return 0;
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
MODULE_DESCRIPTION("Cavium Thunder PCIe driver");
MODULE_LICENSE("GPLv2");
