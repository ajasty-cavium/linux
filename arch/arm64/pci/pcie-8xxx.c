/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2013 Cavium, Inc.
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/pci.h>
#include <linux/interrupt.h>
#include <linux/time.h>
#include <linux/delay.h>
#include <linux/module.h>
#include <linux/swab.h>
#include <linux/of_platform.h>
#include <linux/of_gpio.h>
#include <linux/of_irq.h>
#include <linux/of_pci.h>
#include <linux/of_address.h>

#include <asm/cacheflush.h>
#include "pcie-8xxx.h"

#define PCI_FAKE_BRIDGE 

static int thunder_pcie0_read_config(struct pci_bus *bus, unsigned int devfn,
				    int reg, int size, u32 *val);
static int thunder_pcie0_write_config(struct pci_bus *bus, unsigned int devfn,
				     int reg, int size, u32 val);
static int thunder_pcie1_read_config(struct pci_bus *bus, unsigned int devfn,
				    int reg, int size, u32 *val);
static int thunder_pcie1_write_config(struct pci_bus *bus, unsigned int devfn,
				     int reg, int size, u32 val);

static struct resource thunder_pcie0_mem_resource;
static struct resource thunder_pcie0_io_resource;
static struct resource thunder_pcie0_bus_resource = {
	.start = 0,
	.end = 255,
	.flags = IORESOURCE_BUS,
};

static struct pci_ops thunder_pcie0_ops = {
	thunder_pcie0_read_config,
	thunder_pcie0_write_config,
};

static struct pci_controller thunder_pcie0_controller = {
	.pci_ops = &thunder_pcie0_ops,
	.mem_resource = &thunder_pcie0_mem_resource,
	.io_resource = &thunder_pcie0_io_resource,
	.bus_resource = &thunder_pcie0_bus_resource,
};

static struct resource thunder_pcie1_mem_resource;
static struct resource thunder_pcie1_io_resource;

static struct pci_ops thunder_pcie1_ops = {
	thunder_pcie1_read_config,
	thunder_pcie1_write_config,
};

static struct pci_controller thunder_pcie1_controller = {
	.pci_ops = &thunder_pcie1_ops,
	.mem_resource = &thunder_pcie1_mem_resource,
	.io_resource = &thunder_pcie1_io_resource,
	.bus_resource = &thunder_pcie0_bus_resource,
};

/* VNIC BARS have fixed resources, shouldn't be reallocated */
static void pci_fixed_bar_fixup(struct pci_dev *dev)
{
	struct pci_bus *bus = dev->bus;
	int i;

	for (i = 0; i <= PCI_NUM_RESOURCES; i++) {
		dev->resource[i].flags |= IORESOURCE_PCI_FIXED;
	}
	
	if ((dev->vendor == PCI_VENDOR_ID_CAVIUM) && 
			(dev->device == PCI_DEVICE_ID_8XXX_VNIC_PF)) {
			bus->resource[0] = &bus->self->resource[0];
	}
}
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_CAVIUM, 0x00, pci_fixed_bar_fixup);
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_CAVIUM, PCI_DEVICE_ID_8XXX_VNIC_PF, pci_fixed_bar_fixup);
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_CAVIUM, PCI_DEVICE_ID_8XXX_VNIC_VF, pci_fixed_bar_fixup);

/* Fake host-bridge config space */
#define  PCIE_CAP_LIST_OFFSET 0x40
struct host_bridge_config {
	u32 class_rev;
	u16 pci_status;
	u16 pci_command;
	u32 primary_bus;
	u8  secondary_bus;
	u8  subordinate_bus;
	u16 bridge_control;
	u32 dev_capability2;

	u32 mem_bar0;
	u32 mem_bar1;
	u64 mem_size;
};
struct host_bridge_config *host_bridge_config_regs;

static void thunder_pcie_host_bridge_config_init(struct pci_controller *hose)
{
	struct resource *res = NULL;

	host_bridge_config_regs->class_rev = PCI_CLASS_BRIDGE_PCI << 16;
	host_bridge_config_regs->pci_status = PCI_STATUS_CAP_LIST;
	host_bridge_config_regs->primary_bus = 0x00010100;
	host_bridge_config_regs->secondary_bus = 1;
	host_bridge_config_regs->subordinate_bus = 0;
	host_bridge_config_regs->bridge_control = 0;
	host_bridge_config_regs->dev_capability2 = PCI_EXP_DEVCAP2_ARI;

	res = hose->mem_resource;
	host_bridge_config_regs->mem_bar0 =  (res->start & ~0x00UL) | 
						PCI_BASE_ADDRESS_SPACE_MEMORY | 
						PCI_BASE_ADDRESS_MEM_TYPE_64;
	host_bridge_config_regs->mem_bar1 =  ((hose->mem_resource->start >> 32) & ~0x00UL);
	host_bridge_config_regs->mem_size =  res->end - res->start + 1;
}

static uint32_t thunder_pcie_host_bridge_read(int reg)
{
	if (reg >= PCIE_CAP_LIST_OFFSET) {
		reg = reg - PCIE_CAP_LIST_OFFSET;
		switch (reg) {
		case PCI_CAP_LIST_ID:
			return PCI_CAP_ID_EXP;
		case PCI_EXP_FLAGS:
			return ((PCI_EXP_TYPE_PCI_BRIDGE << 4) | 0x2);
		case PCI_EXP_DEVCAP2:
			return host_bridge_config_regs->dev_capability2;
		default:
			return 0;
		}
	}

	switch (reg) {
	case PCI_VENDOR_ID:
		return PCI_VENDOR_ID_CAVIUM;
	case PCI_STATUS:
		return host_bridge_config_regs->pci_status;
	case PCI_HEADER_TYPE:
		return PCI_HEADER_TYPE_BRIDGE;
	case PCI_CLASS_REVISION:
		return host_bridge_config_regs->class_rev;
	case PCI_PRIMARY_BUS:
		return host_bridge_config_regs->primary_bus;
	case PCI_CAPABILITY_LIST:
		return PCIE_CAP_LIST_OFFSET;
	case PCI_BRIDGE_CONTROL:
		return host_bridge_config_regs->bridge_control;
	case PCI_BASE_ADDRESS_0:
		return host_bridge_config_regs->mem_bar0;
	case PCI_BASE_ADDRESS_1:
		return host_bridge_config_regs->mem_bar1;
	default:
		return 0;	
	}
	return 0;
}

static void thunder_pcie_host_bridge_write(int reg, uint32_t val)
{
	switch (reg) {
	case PCI_CLASS_REVISION:
		host_bridge_config_regs->class_rev = val;
		break;
	case PCI_PRIMARY_BUS:
		host_bridge_config_regs->primary_bus = val;
		break;
	case PCI_BRIDGE_CONTROL:
		host_bridge_config_regs->bridge_control = val;;
		break;;
	case PCI_EXP_DEVCAP2:
		host_bridge_config_regs->dev_capability2 = val;;
		break;
	case PCI_BASE_ADDRESS_0:
		if ((val == 0xFFFFFFFF) && (host_bridge_config_regs->mem_size & ~0x00UL))
			host_bridge_config_regs->mem_bar0 |= (u32)host_bridge_config_regs->mem_size;
		break;
	case PCI_BASE_ADDRESS_1:
		if ((val == 0xFFFFFFFF) && ((host_bridge_config_regs->mem_size >> 32) & ~0x00UL))
			host_bridge_config_regs->mem_bar1 |= (u32)(host_bridge_config_regs->mem_size >> 32);
		break;
	default:
		return;	
	}
}
/**
 * Build a PCIe config space request address for a device
 *
 * @cfg_base: PCIe port's config space base address
 * @bus:       Sub bus
 * @dev:       Device ID
 * @fn:        Device sub function
 * @reg:       Register to access
 *
 * Returns 64bit address
 */
static inline uint64_t thunder_pcie_build_config_addr(uint64_t cfg_base, int bus,
						     int dev, int fn, int reg)
{
	uint64_t cfg_addr = 0;

	cfg_addr |= (bus << THUNDER_PCIE_BUS_SHIFT);
	cfg_addr |= (dev << THUNDER_PCIE_DEV_SHIFT);
	cfg_addr |= (fn  << THUNDER_PCIE_FUNC_SHIFT);

	cfg_addr |= reg;

	return cfg_addr + cfg_base;
}

/**
 * Read 8bits from a Device's config space
 *
 * @cfg_base: PCIe port's config space base address
 * @bus:       Sub bus
 * @dev:       Device ID
 * @fn:        Device sub function
 * @reg:       Register to access
 *
 * Returns Result of the read
 */
static uint8_t thunder_pcie_config_read8(uint64_t cfg_base, int bus, 
						int dev, int fn, int reg)
{
	uint64_t address =
	    thunder_pcie_build_config_addr(cfg_base, bus, dev, fn, reg);

	if (address)
		return *((uint8_t *)address);
	else
		return 0xff;
}

/**
 * Read 16bits from a Device's config space
 *
 * @cfg_base: PCIe port's config space base address
 * @bus:       Sub bus
 * @dev:       Device ID
 * @fn:        Device sub function
 * @reg:       Register to access
 *
 * Returns Result of the read
 */
static uint16_t thunder_pcie_config_read16(uint64_t cfg_base, int bus, 
						int dev, int fn, int reg)
{
	uint64_t address =
	    thunder_pcie_build_config_addr(cfg_base, bus, dev, fn, reg);
	
	if (address)
		return le16_to_cpu(*(uint16_t *)address);
	else
		return 0xffff;
}

/**
 * Read 32bits from a Device's config space
 *
 * @cfg_base: PCIe port's config space base address
 * @bus:       Sub bus
 * @dev:       Device ID
 * @fn:        Device sub function
 * @reg:       Register to access
 *
 * Returns Result of the read
 */
static uint32_t thunder_pcie_config_read32(uint64_t cfg_base, int bus, 
						int dev, int fn, int reg)
{
	uint64_t address =
	    thunder_pcie_build_config_addr(cfg_base, bus, dev, fn, reg);
   
	if (address)
		return le32_to_cpu(*((uint32_t *)address));
	else
		return 0xffffffff;
}

/**
 * Write 8bits to a Device's config space
 *
 * @cfg_base: PCIe port's config space base address
 * @bus:       Sub bus
 * @dev:       Device ID
 * @fn:        Device sub function
 * @reg:       Register to access
 * @val:       Value to write
 */
static void thunder_pcie_config_write8(uint64_t cfg_base, int bus, int dev, 
						int fn, int reg, uint8_t val)
{
	uint64_t address =
	    thunder_pcie_build_config_addr(cfg_base, bus, dev, fn, reg);
	if (address)
		*((uint8_t *)address) = val;              
}

/**
 * Write 16bits to a Device's config space
 *
 * @cfg_base: PCIe port's config space base address
 * @bus:       Sub bus
 * @dev:       Device ID
 * @fn:        Device sub function
 * @reg:       Register to access
 * @val:       Value to write
 */
static void thunder_pcie_config_write16(uint64_t cfg_base, int bus, int dev, 
					int fn, int reg, uint16_t val)
{
	uint64_t address =
	    thunder_pcie_build_config_addr(cfg_base, bus, dev, fn, reg);
	if (address)
		*((uint16_t *)address) = cpu_to_le16(val);              
}

/**
 * Write 32bits to a Device's config space
 *
 * @cfg_base: PCIe port's config space base address
 * @bus:       Sub bus
 * @dev:       Device ID
 * @fn:        Device sub function
 * @reg:       Register to access
 * @val:       Value to write
 */
static void thunder_pcie_config_write32(uint64_t cfg_base, int bus, int dev, 
						int fn, int reg, uint32_t val)
{
	uint64_t address =
	    thunder_pcie_build_config_addr(cfg_base, bus, dev, fn, reg);
	if (address)
		*((uint32_t *)address) = cpu_to_le32(val);              
}

/*
 * Read a value from configuration space
 *
 */
static int thunder_pcie_read_config(uint64_t cfg_base, struct pci_bus *bus,
				   unsigned int devfn, int reg, int size,
				   u32 *val)
{
	int bus_number = bus->number;

	if (bus->parent == NULL)
		bus_number = 0;

	pr_debug("pcie_cfg_rd bus=%d devfn=0x%03x reg=0x%03x size=%d ", 
					bus_number, devfn, reg, size);
	switch (size) {
	case 4:
		*val = thunder_pcie_config_read32(cfg_base, bus_number,
			devfn >> 3, devfn & 0x7, reg);
	break;
	case 2:
		*val = thunder_pcie_config_read16(cfg_base, bus_number,
			devfn >> 3, devfn & 0x7, reg);
	break;
	case 1:
		*val = thunder_pcie_config_read8(cfg_base, bus_number,
			devfn >> 3, devfn & 0x7, reg);
	break;
	default:
		return PCIBIOS_FUNC_NOT_SUPPORTED;
	}

	pr_debug("val=%08x\n", *val);
	return PCIBIOS_SUCCESSFUL;
}

static int thunder_pcie0_read_config(struct pci_bus *bus, unsigned int devfn,
						int reg, int size, u32 *val)
{
       return thunder_pcie_read_config(thunder_pcie0_controller.cfg_base, 
						bus, devfn, reg, size, val);
}

static int thunder_pcie1_read_config(struct pci_bus *bus, unsigned int devfn,
				    int reg, int size, u32 *val)
{
	struct pci_bus pbus; 

	memcpy((void *)&pbus, bus, sizeof(struct pci_bus));
#ifdef PCI_FAKE_BRIDGE
	if ((pbus.number == 0) && (devfn == 0)) {
		*val = thunder_pcie_host_bridge_read(reg);
		return PCIBIOS_SUCCESSFUL;
	} else {
		pbus.number = pbus.number - 1;
	}
#endif
	return thunder_pcie_read_config(thunder_pcie1_controller.cfg_base, 
						&pbus, devfn, reg, size, val);
}

/*
 * Write a value to PCIe configuration space
 */
static int thunder_pcie_write_config(uint64_t cfg_base, struct pci_bus *bus,
				    unsigned int devfn, int reg,
				    int size, u32 val)
{
	int bus_number = bus->number;

	if (bus->parent == NULL)
		bus_number = 0;

	pr_debug("pcie_cfg_wr bus=%d devfn=0x%03x reg=0x%03x size=%d val=%08x\n",
					 bus_number, devfn, reg, size, val);

	switch (size) {
	case 4:
		thunder_pcie_config_write32(cfg_base, bus_number, 
                                         devfn >> 3, devfn & 0x7, reg, val);
		break;
	case 2:
		thunder_pcie_config_write16(cfg_base, bus_number, 
                                         devfn >> 3, devfn & 0x7, reg, val);
		break;
	case 1:
		thunder_pcie_config_write8(cfg_base, bus_number, 
                                        devfn >> 3, devfn & 0x7, reg, val);
		break;
	default:
		return PCIBIOS_FUNC_NOT_SUPPORTED;
	}
	return PCIBIOS_SUCCESSFUL;
}

static int thunder_pcie0_write_config(struct pci_bus *bus, unsigned int devfn,
						int reg, int size, u32 val)
{
	return thunder_pcie_write_config(thunder_pcie0_controller.cfg_base, 
						bus, devfn, reg, size, val);
}

static int thunder_pcie1_write_config(struct pci_bus *bus, unsigned int devfn,
				     int reg, int size, u32 val)
{
	struct pci_bus pbus;

	memcpy((void *)&pbus, bus, sizeof(struct pci_bus));
#ifdef PCI_FAKE_BRIDGE
	if ((pbus.number == 0) && (devfn == 0)) {
		thunder_pcie_host_bridge_write(reg, val);
		return PCIBIOS_SUCCESSFUL;
	} else {
		pbus.number = pbus.number - 1;
	}
#endif
	return thunder_pcie_write_config(thunder_pcie1_controller.cfg_base, 
						&pbus, devfn, reg, size, val);
}

static int pci_load_of_ranges(struct pci_controller *hose, 
			      struct device_node *node, uint32_t pcie_port)
{
	const __be32 *ranges;
	int start;
	int rlen;
	int nac = of_n_addr_cells(node);
	int nsc = of_n_size_cells(node);
	int np;

	np = nac + nsc + 1;

	pr_info("PCI host bridge %s ranges:\n", node->full_name);
	ranges = of_get_property(node, "ranges", &rlen);
	if (ranges == NULL)
		return 0;
	hose->of_node = node;
	start = pcie_port * ((nac + nsc + 1) * 2);

	ranges = ranges + start;
	rlen = np * 2; /* IO + Mem resource */
	while (rlen > 0) {
		u32 pci_space;
		struct resource *res = NULL;
		u64 addr, size;

		pci_space = be32_to_cpup(&ranges[0]);
		addr = of_translate_address(node, ranges + 1);
		size = of_read_number(ranges + nac + 1, nsc);
		ranges += np;
		switch (pci_space) {
		case 0:		/* PCIe IO space */
			pr_info("  IO 0x%016llx..0x%016llx\n",
					addr, addr + size - 1);
			res = hose->io_resource;
			res->flags = IORESOURCE_IO;
			ioport_resource.end = addr + size; 
			break;
		case 1:		/* PCIe 64 bits Memory space */
			pr_info(" MEM 0x%016llx..0x%016llx\n",
					addr, addr + size - 1);
			res = hose->mem_resource;
			res->flags = IORESOURCE_MEM;
			break;
		}
		if (res != NULL) {
			res->start = addr;
			res->name = node->full_name;
			res->end = res->start + size - 1;
			res->parent = NULL;
			res->sibling = NULL;
			res->child = NULL;
		}
		rlen -= np;
	}
	return 1;
}

/**
 * Initialize PCIe controllers
 */
static int thunder_pcie_setup(struct platform_device *pdev)
{
	struct resource res;

	if (of_address_to_resource(pdev->dev.of_node, 0, &res)) {
		return -EINVAL;
	}

	pr_notice("PCIe: Register port 0 \n");
	if (!request_mem_region(res.start, resource_size(&res), "pcie-thunder")) {
		pr_notice("PCIe0: couldn't request %pR\n", &res);
		return -EBUSY;
	}

        /* Map PCIe config space */
	thunder_pcie0_controller.cfg_base = 
		(uint64_t)ioremap_nocache(res.start, resource_size(&res));
        if (!thunder_pcie0_controller.cfg_base) {
		pr_err("PCIe: Failed to map port 0 res.start 0x%llx\n", (uint64_t)res.start);
            return -ENOMEM;
        }

	pci_load_of_ranges(&thunder_pcie0_controller, pdev->dev.of_node, 0);
	register_pci_controller(&thunder_pcie0_controller);

	if (!of_address_to_resource(pdev->dev.of_node, 1, &res)) {
		pr_notice("PCIe: Register port 1\n");
		if (!request_mem_region(res.start, resource_size(&res), "pcie-thunder1")) {
			pr_notice("PCIe1: couldn't request %pR\n", &res);
			return -EBUSY;
		}

		thunder_pcie1_controller.cfg_base =
			(uint64_t)ioremap_nocache(res.start, resource_size(&res));
		if (!thunder_pcie1_controller.cfg_base) {
			pr_err("PCIe: Failed to map port 1 res.start 0x%llx\n", (uint64_t)res.start);
			return -ENOMEM;
		}
		thunder_pcie1_controller.index = 1;
		pci_load_of_ranges(&thunder_pcie1_controller, pdev->dev.of_node, 1);
		#ifdef PCI_FAKE_BRIDGE
			/* Init fake host bridge */
			host_bridge_config_regs = kmalloc(sizeof (struct host_bridge_config), GFP_KERNEL);
			thunder_pcie_host_bridge_config_init(&thunder_pcie1_controller);
		#endif
		register_pci_controller(&thunder_pcie1_controller);
	}

	return 0;
}

static const struct of_device_id thunder_pcie[] = {
        { .compatible = "pcie-8xxx" },
        {},
};
MODULE_DEVICE_TABLE(of, thunder_pcie);

static struct platform_driver thunder_pcie_driver = {
        .probe = thunder_pcie_setup,
        .driver = {
                .name = "8xxx-pcie",
                .owner = THIS_MODULE,
                .of_match_table = thunder_pcie,
        },
};

int __init thunder_pcie_init(void)
{
        int ret = platform_driver_register(&thunder_pcie_driver);
        if (ret)
                pr_err("Thunder pcie: Error registering platform driver!");
        return ret;
}
arch_initcall(thunder_pcie_init);


