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
#define THUNDER_ECAM4_CFG_BASE		0x948000000000
#define THUNDER_ECAM5_CFG_BASE		0x949000000000
#define THUNDER_ECAM6_CFG_BASE		0x94a000000000
#define THUNDER_ECAM7_CFG_BASE		0x94b000000000

#define THUNDER_PEM0_REG_BASE      (0x87e0c0000000 | (0 << 24))
#define THUNDER_PEM1_REG_BASE      (0x87e0c0000000 | (1 << 24))
#define THUNDER_PEM2_REG_BASE      (0x87e0c0000000 | (2 << 24))
#define THUNDER_PEM3_REG_BASE      (0x87e0c0000000 | (3 << 24))
#define THUNDER_PEM4_REG_BASE      (0x87e0c0000000 | (4 << 24))
#define THUNDER_PEM5_REG_BASE      (0x87e0c0000000 | (5 << 24))

#define THUNDER_GSER_N0_BASE        0x87e090000000
#define THUNDER_GSER_SIZE           0xd000000

#define THUNDER_GSER_PCIE_MASK  0x1
#define THUNDER_GSER_BGX_MASK   0x4
#define THUNDER_GSER_SATA_MASK  0x20


void __iomem      *gser_base = NULL;

enum thunder_pcie_device_type {
    THUNDER_ECAM,
    THUNDER_PEM,
};

struct thunder_pcie {
	struct device_node	*node;
	struct device		*dev;
	void __iomem		*cfg_base;
	void __iomem		*pem_base;
	void __iomem		*pem_sli_base;
	struct msi_chip		*msi;
    int                 device_type;
	int			    ecam;
    int                 pem;
};


struct sli_mem_addr {
	uint64_t addr:32;
	uint64_t region:8;
	uint64_t did_hi:4;
	uint64_t node:2;
	uint64_t reserved_46_46:1;
	uint64_t io:1;
	uint64_t reserved_48_63:16;
};



int pci_requester_id(struct pci_dev *dev)
{
	struct thunder_pcie *pcie = dev->bus->sysdata;

    if(pcie->device_type == THUNDER_ECAM) {
        /* this is easy case */
        return ((pci_domain_nr(dev->bus) << 16) | ((dev)->bus->number << 8) | (dev)->devfn);
    }
    else {
        if(pcie->pem < 3 ) {
            return ((1 << 16) | ((dev)->bus->number << 8) | (dev)->devfn);
        }
        else {
            return ((3 << 16) | ((dev)->bus->number << 8) | (dev)->devfn);
        }

    }


}
EXPORT_SYMBOL(pci_requester_id);


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

static uint64_t thunder_get_gser_cfg_addr(int qlm)
{
    return ((uint64_t)gser_base) + 0x80 + (0x1000000 * qlm);
}

static int thunder_pcie_check_ecam_cfg_access(int ecam, unsigned int bus,
					 unsigned int devfn)
{
	int supported = 0;
	uint16_t bdf = (bus << 8) | devfn;
    uint64_t gser_cfg;


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
				supported = 1;
				break;
			case 0x180:   /* BGX0 */
                gser_cfg = *(uint64_t *)thunder_get_gser_cfg_addr(0);
                if(gser_cfg & THUNDER_GSER_BGX_MASK)
                    supported = 1;
				break;
			case 0x181:   /* BGX1 */
                gser_cfg = *(uint64_t *)thunder_get_gser_cfg_addr(1);
                if(gser_cfg & THUNDER_GSER_BGX_MASK)
                    supported = 1;
				break;
			default:
				supported = 0;
		}
	} else if (ecam == 1) {
		switch (bdf) {
			case 0x008:   /* SMMU */
			case 0x020:   /* AHCI0*/
			case 0x028:   /* AHCI1 */
			case 0x030:   /* AHCI2 */
			case 0x038:   /* AHCI3 */
                gser_cfg = *(uint64_t *)thunder_get_gser_cfg_addr(2);
                if(gser_cfg & THUNDER_GSER_SATA_MASK)
                    supported = 1;
                break;
			case 0x040:   /* AHCI4 */
			case 0x048:   /* AHCI5 */
			case 0x050:   /* AHCI5 */
			case 0x058:   /* AHCI7 */
                gser_cfg = *(uint64_t *)thunder_get_gser_cfg_addr(3);
                if(gser_cfg & THUNDER_GSER_SATA_MASK)
                    supported = 1;
                break;
			//case 0x080:   /* PCIRC0 */
			//case 0x098:   /* PCIRC1 */
			//case 0x0A8:   /* PCIRC2 */
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
                supported = 1;
                break;
			case 0x018:   /* AHCI8 */
			case 0x020:   /* AHCI9*/
			case 0x028:   /* AHCI10 */
			case 0x030:   /* AHCI11 */
                gser_cfg = *(uint64_t *)thunder_get_gser_cfg_addr(6);
                if(gser_cfg & THUNDER_GSER_SATA_MASK)
                    supported = 1;
                break;
			case 0x038:   /* AHCI12 */
			case 0x040:   /* AHCI13 */
			case 0x048:   /* AHCI14 */
			case 0x050:   /* AHCI15 */
                gser_cfg = *(uint64_t *)thunder_get_gser_cfg_addr(7);
                if(gser_cfg & THUNDER_GSER_SATA_MASK)
                    supported = 1;
                break;
			//case 0x080:   /* PCIRC3 */
			//case 0x098:   /* PCIRC4 */
			//case 0x0A8:   /* PCIRC5 */
				break;
			default:
				supported = 0;
		}
	}
	return supported;
}


static int thunder_pcie_check_pem_cfg_access(int pem, unsigned int bus,
					 unsigned int devfn)
{
	int supported = 0;
    uint64_t gser_cfg;

    //TODO: 8 lane config needs to be handled supperately.
    //Hoping it should work..

    if(devfn)
        return supported;

    switch (pem) {
    case 0:
        gser_cfg = *(uint64_t *)thunder_get_gser_cfg_addr(2);
        if(gser_cfg & THUNDER_GSER_PCIE_MASK)
            supported = 1;
        break;
    case 1:
        gser_cfg = *(uint64_t *)thunder_get_gser_cfg_addr(3);
        if(gser_cfg & THUNDER_GSER_PCIE_MASK)
            supported = 1;
        break;
    case 2:
        gser_cfg = *(uint64_t *)thunder_get_gser_cfg_addr(4);
        if(gser_cfg & THUNDER_GSER_PCIE_MASK)
            supported = 1;
        break;
    case 3:
        gser_cfg = *(uint64_t *)thunder_get_gser_cfg_addr(5);
        if(gser_cfg & THUNDER_GSER_PCIE_MASK)
            supported = 1;
        break;
    case 4:
        gser_cfg = *(uint64_t *)thunder_get_gser_cfg_addr(6);
        if(gser_cfg & THUNDER_GSER_PCIE_MASK)
            supported = 1;
        break;
    case 5:
        gser_cfg = *(uint64_t *)thunder_get_gser_cfg_addr(7);
        if(gser_cfg & THUNDER_GSER_PCIE_MASK)
            supported = 1;
        break;
    }

    return supported;
}

int first_bar0_read = 0;
int first_bar1_read = 0;

static int thunder_pcierc_config_read(void __iomem *pem_base, int reg, int size)
{
	void __iomem *addr;
	unsigned int val;

	if (reg == 0x10) /* BAR 0 */ {
		if (!first_bar0_read)
			val = 0xC0000004;
		else
			val = 0xffff800f;
		first_bar0_read = 1;
		return val;
	}

	if (reg == 0x14) /* BAR 1 */ {
		if (!first_bar1_read)
			val = 0x87E0;
		else
			val = 0xffffffff;
		first_bar1_read = 1;
		return val;
	}


	if (reg == 0x38) /* ROM */
		return 0x00;

	addr = pem_base + 0x30; /* RD_CFG reg */
	writeq(reg & ~3, addr);
	val = readq(addr) >> 32;

	if (size == 1)
		val = (val >> (8 * (reg & 3))) & 0xff;
	else if (size == 2)
		val = (val >> (8 * (reg & 3))) & 0xffff;

	return val;
}

static void thunder_pcierc_config_write(void __iomem *pem_base, int reg,
					int size, u64 val)
{
	void __iomem *addr;
	u32 mask = 0;
	u64 tmp;

	addr = pem_base + 0x28; /* WR_CFG reg */

	if (size == 4) {
		writeq(((val << 32) | reg), addr);
		return;
	}

	if (size == 2)
		mask = ~(0xffff << ((reg & 0x3) * 8));
	else if (size == 1)
		mask = ~(0xff << ((reg & 0x3) * 8));

	tmp = thunder_pcierc_config_read(pem_base, reg, size) & mask;
	tmp |= val << ((reg & 0x3) * 8);
	writeq((tmp << 32) | reg, addr);
}

static void __iomem *thunder_pcie_external_addr(struct thunder_pcie *pcie,
						unsigned int bus, unsigned int devfn, int reg)
{
	return pcie->pem_sli_base + ((bus << 24)  | (devfn << 16) | reg);
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

    if(pcie->device_type == THUNDER_ECAM) {
	supported = thunder_pcie_check_ecam_cfg_access(pcie->ecam, busnr, devfn);
    }
    else if(pcie->device_type == THUNDER_PEM) {
	supported = thunder_pcie_check_pem_cfg_access(pcie->pem, busnr, devfn);
		addr = thunder_pcie_external_addr(pcie, busnr, devfn, reg);
    }
    else {
        supported = 0;
    }

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
	int supported;

	if (busnr > 255 || devfn > 255 || reg > 4095)
		return PCIBIOS_DEVICE_NOT_FOUND;

    if(pcie->device_type == THUNDER_ECAM) {
	supported = thunder_pcie_check_ecam_cfg_access(pcie->ecam, busnr, devfn);
	    addr = thunder_pcie_cfg_base(pcie, busnr, devfn) + reg;
    }
    else if(pcie->device_type == THUNDER_PEM) {
	supported = thunder_pcie_check_pem_cfg_access(pcie->pem, busnr, devfn);
		addr = thunder_pcie_external_addr(pcie, busnr, devfn, reg);
    }
    else {
        supported = 0;
    }

    if(!supported)
	    return PCIBIOS_SUCCESSFUL;

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

#define PCIERC_CFG002 0x08
#define PCIERC_CFG006 0x18

static void thunder_pcierc_config_init(struct thunder_pcie *pcie)
{
	uint64_t pem_addr;
	uint64_t region;
    uint64_t sli;
    uint64_t node =0; //TODO find out from pem numbers

	/* device class as bridge */
	//thunder_pcierc_config_write(pcie->pem_base, PCIERC_CFG006, 4, 0xff0100);

    sli= (pcie->pem < 3) ? 8ULL : 9ULL;
	region = ((pcie->pem << 6) | (0ULL << 4)) << 32; /* PEM number and access type */;
	pem_addr = (1ULL << 47) | (node << 44) | (sli << 40) | region;
	pcie->pem_sli_base = ioremap(pem_addr, (0xFFULL << 24) - 1);
}

static int thunder_pcie_probe(struct platform_device *pdev)
{
	struct thunder_pcie *pcie;
	struct resource *cfg_base;
	struct pci_bus *bus;
	resource_size_t iobase = 0;
	int ret;
    int primary_bus = 0;
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
            pcie->device_type = THUNDER_ECAM;
			pcie->ecam = 0;
			break;
		case THUNDER_ECAM1_CFG_BASE:
            pcie->device_type = THUNDER_ECAM;
			pcie->ecam = 1;
			break;
		case THUNDER_ECAM2_CFG_BASE:
            pcie->device_type = THUNDER_ECAM;
			pcie->ecam = 2;
			break;
		case THUNDER_ECAM3_CFG_BASE:
            pcie->device_type = THUNDER_ECAM;
			pcie->ecam = 3;
			break;
		case THUNDER_ECAM4_CFG_BASE:
            pcie->device_type = THUNDER_ECAM;
			pcie->ecam = 0;
			break;
		case THUNDER_ECAM5_CFG_BASE:
            pcie->device_type = THUNDER_ECAM;
			pcie->ecam = 1;
			break;
		case THUNDER_ECAM6_CFG_BASE:
            pcie->device_type = THUNDER_ECAM;
			pcie->ecam = 2;
			break;
		case THUNDER_ECAM7_CFG_BASE:
            pcie->device_type = THUNDER_ECAM;
			pcie->ecam = 3;
			break;
        case THUNDER_PEM0_REG_BASE:
            pcie->device_type = THUNDER_PEM;
			pcie->pem = 0;
            break;
        case THUNDER_PEM1_REG_BASE:
            pcie->device_type = THUNDER_PEM;
			pcie->pem = 1;
            break;
        case THUNDER_PEM2_REG_BASE:
            pcie->device_type = THUNDER_PEM;
			pcie->pem = 2;
            break;
        case THUNDER_PEM3_REG_BASE:
            pcie->device_type = THUNDER_PEM;
			pcie->pem = 3;
            break;
        case THUNDER_PEM4_REG_BASE:
            pcie->device_type = THUNDER_PEM;
			pcie->pem = 4;
            break;
        case THUNDER_PEM5_REG_BASE:
            pcie->device_type = THUNDER_PEM;
			pcie->pem = 5;
            break;
	}

	if (gser_base == NULL)
		gser_base = devm_ioremap(&pdev->dev,
					 THUNDER_GSER_N0_BASE,
					 THUNDER_GSER_SIZE);

    if(pcie->device_type == THUNDER_ECAM) {
	pcie->cfg_base = devm_ioremap_resource(&pdev->dev, cfg_base);
	    if (IS_ERR(pcie->cfg_base) || IS_ERR(gser_base)) {
		    ret = PTR_ERR(pcie->cfg_base);
		    goto err_ioremap;
	    }
	    pr_err("%s: ECAM%d CFG BASE 0x%llx gser_base:%llx\n", __func__,
	        pcie->ecam, (uint64_t)cfg_base->start, (uint64_t)gser_base);
	    ret = of_pci_get_host_bridge_resources(pdev->dev.of_node,
					       0, 255, &res, NULL);
    }
    else {
		pcie->pem_base = ioremap(cfg_base->start, 0x500);
		if (!pcie->pem_base) {
			pr_err("Unable to map PEM2 CFG registers\n");
			goto err_ioremap;
		}
		thunder_pcierc_config_init(pcie);
        primary_bus = thunder_pcierc_config_read(pcie->pem_base, PCIERC_CFG006,0x4);
	    pr_err("%s: PEM%d CFG BASE 0x%llx gser_base:%llx primary_bus:%x\n", __func__,
	        pcie->pem, (uint64_t)cfg_base->start, (uint64_t)gser_base,primary_bus);
        primary_bus = ( primary_bus >>  0x8) & 0xff;
		ret = of_pci_get_host_bridge_resources(pdev->dev.of_node,
						       primary_bus, 255, &res, &iobase);
    }


	if (ret)
		goto err_get_host;


	bus = pci_scan_root_bus(&pdev->dev, primary_bus, &thunder_pcie_ops, pcie, &res);
    /*
	bus = pci_create_root_bus(&pdev->dev, 0, &thunder_pcie_ops, pcie, &res);
	if (!bus) {
		ret = -ENODEV;
		goto err_root_bus;
	}*/

	/* Set reference to MSI chip */
	ret = thunder_pcie_msi_enable(pcie, bus);
	if (ret)
		goto err_msi;

	platform_set_drvdata(pdev, pcie);
    /*
	pci_scan_child_bus(bus);
	pci_bus_add_devices(bus);
    */
	if (pcie->device_type == THUNDER_PEM) {
		//pci_bus_update_busn_res_end(bus, 1);
		//pci_assign_unassigned_bridge_resources(bus->parent->self);
		pci_assign_unassigned_root_bus_resources(bus);
	}
	return 0;
err_msi:
	//pci_remove_root_bus(bus);
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
