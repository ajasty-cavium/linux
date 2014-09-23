#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_pci.h>
#include <linux/slab.h>

#include "of_private.h"

static inline int __of_pci_pci_compare(struct device_node *node,
				       unsigned int data)
{
	int devfn;

	devfn = of_pci_get_devfn(node);
	if (devfn < 0)
		return 0;

	return devfn == data;
}

struct device_node *of_pci_find_child_device(struct device_node *parent,
					     unsigned int devfn)
{
	struct device_node *node, *node2;

	for_each_child_of_node(parent, node) {
		if (__of_pci_pci_compare(node, devfn))
			return node;
		/*
		 * Some OFs create a parent node "multifunc-device" as
		 * a fake root for all functions of a multi-function
		 * device we go down them as well.
		 */
		if (!strcmp(node->name, "multifunc-device")) {
			for_each_child_of_node(node, node2) {
				if (__of_pci_pci_compare(node2, devfn)) {
					of_node_put(node);
					return node2;
				}
			}
		}
	}
	return NULL;
}
EXPORT_SYMBOL_GPL(of_pci_find_child_device);

/**
 * of_pci_get_devfn() - Get device and function numbers for a device node
 * @np: device node
 *
 * Parses a standard 5-cell PCI resource and returns an 8-bit value that can
 * be passed to the PCI_SLOT() and PCI_FUNC() macros to extract the device
 * and function numbers respectively. On error a negative error code is
 * returned.
 */
int of_pci_get_devfn(struct device_node *np)
{
	unsigned int size;
	const __be32 *reg;

	reg = of_get_property(np, "reg", &size);

	if (!reg || size < 5 * sizeof(__be32))
		return -EINVAL;

	return (be32_to_cpup(reg) >> 8) & 0xff;
}
EXPORT_SYMBOL_GPL(of_pci_get_devfn);

/**
 * of_pci_parse_bus_range() - parse the bus-range property of a PCI device
 * @node: device node
 * @res: address to a struct resource to return the bus-range
 *
 * Returns 0 on success or a negative error-code on failure.
 */
int of_pci_parse_bus_range(struct device_node *node, struct resource *res)
{
	const __be32 *values;
	int len;

	values = of_get_property(node, "bus-range", &len);
	if (!values || len < sizeof(*values) * 2)
		return -EINVAL;

	res->name = node->name;
	res->start = be32_to_cpup(values++);
	res->end = be32_to_cpup(values);
	res->flags = IORESOURCE_BUS;

	return 0;
}
EXPORT_SYMBOL_GPL(of_pci_parse_bus_range);

static atomic_t of_domain_nr = ATOMIC_INIT(-1);

/*
 * Get the maximum value for a domain number from the device tree
 */
static int of_get_max_pci_domain_nr(void)
{
	struct alias_prop *app;
	int max_domain = -1;

	mutex_lock(&of_mutex);
	list_for_each_entry(app, &aliases_lookup, link) {
		if (strncmp(app->stem, "pci-domain", 10) != 0)
			continue;

		max_domain = max(max_domain, app->id);
	}
	mutex_unlock(&of_mutex);

	return max_domain;
}

/**
 * This function will try to obtain the host bridge domain number by
 * using of_alias_get_id() call with "pci-domain" as a stem.  If that
 * fails, a local allocator will be used.  The local allocator can
 * be requested to return a new domain_nr if the information is missing
 * from the device tree.
 *
 * @node: device tree node with the domain information
 * @allocate_if_missing: if DT lacks information about the domain nr,
 * allocate a new number.
 *
 * Returns the associated domain number from DT, or a new domain number
 * if DT information is missing and @allocate_if_missing is true.  If
 * @allocate_if_missing is false then the last allocated domain number
 * will be returned.
 */
int of_pci_get_domain_nr(struct device_node *node, bool allocate_if_missing)
{
	int domain;

	domain = atomic_read(&of_domain_nr);
	if (domain == -1) {
		/* first run, get max defined domain nr in device tree */
		domain = of_get_max_pci_domain_nr();
		/* then set the start value for allocator to be max + 1 */
		atomic_set(&of_domain_nr, domain + 1);
	}
	domain = of_alias_get_id(node, "pci-domain");
	if (domain == -ENODEV) {
		domain = atomic_read(&of_domain_nr);
		if (allocate_if_missing)
			atomic_inc(&of_domain_nr);
	}

	return domain;
}
EXPORT_SYMBOL_GPL(of_pci_get_domain_nr);

/**
 * of_pci_get_host_bridge_resources - Parse PCI host bridge resources from DT
 * @dev: device node of the host bridge having the range property
 * @busno: bus number associated with the bridge root bus
 * @bus_max: maximum number of buses for this bridge
 * @resources: list where the range of resources will be added after DT parsing
 * @io_base: pointer to a variable that will contain on return the physical
 * address for the start of the I/O range.
 *
 * It is the callers job to free the @resources list.
 *
 * This function will parse the "ranges" property of a PCI host bridge device
 * node and setup the resource mapping based on its content. It is expected
 * that the property conforms with the Power ePAPR document.
 *
 * It returns zero if the range parsing has been successful or a standard error
 * value if it failed.
 */
int of_pci_get_host_bridge_resources(struct device_node *dev,
			unsigned char busno, unsigned char bus_max,
			struct list_head *resources, resource_size_t *io_base)
{
	struct resource *res;
	struct resource *bus_range;
	struct of_pci_range range;
	struct of_pci_range_parser parser;
	char range_type[4];
	int err;

	if (!io_base)
		return -EINVAL;
	*io_base = OF_BAD_ADDR;

	bus_range = kzalloc(sizeof(*bus_range), GFP_KERNEL);
	if (!bus_range)
		return -ENOMEM;

	pr_info("PCI host bridge %s ranges:\n", dev->full_name);

	err = of_pci_parse_bus_range(dev, bus_range);
	if (err) {
		bus_range->start = busno;
		bus_range->end = bus_max;
		bus_range->flags = IORESOURCE_BUS;
		pr_info("  No bus range found for %s, using %pR\n",
			dev->full_name, &bus_range);
	} else {
		if (bus_range->end > bus_range->start + bus_max)
			bus_range->end = bus_range->start + bus_max;
	}
	pci_add_resource(resources, bus_range);

	/* Check for ranges property */
	err = of_pci_range_parser_init(&parser, dev);
	if (err)
		goto parse_failed;

	pr_debug("Parsing ranges property...\n");
	for_each_of_pci_range(&parser, &range) {
		/* Read next ranges element */
		if ((range.flags & IORESOURCE_TYPE_BITS) == IORESOURCE_IO)
			snprintf(range_type, 4, " IO");
		else if ((range.flags & IORESOURCE_TYPE_BITS) == IORESOURCE_MEM)
			snprintf(range_type, 4, "MEM");
		else
			snprintf(range_type, 4, "err");
		pr_info("  %s %#010llx..%#010llx -> %#010llx\n", range_type,
			range.cpu_addr, range.cpu_addr + range.size - 1,
			range.pci_addr);

		/*
		 * If we failed translation or got a zero-sized region
		 * then skip this range
		 */
		if (range.cpu_addr == OF_BAD_ADDR || range.size == 0)
			continue;

		res = kzalloc(sizeof(struct resource), GFP_KERNEL);
		if (!res) {
			err = -ENOMEM;
			goto parse_failed;
		}

		err = of_pci_range_to_resource(&range, dev, res);
		if (err) {
			kfree(res);
			goto parse_failed;
		}

		if (resource_type(res) == IORESOURCE_IO) {
			if (*io_base != OF_BAD_ADDR)
				pr_warn("More than one I/O resource converted. CPU offset for old range lost!\n");
			*io_base = range.cpu_addr;
		}

		pci_add_resource_offset(resources, res,	res->start - range.pci_addr);
	}

	return 0;

parse_failed:
	pci_free_resource_list(resources);
	return err;
}
EXPORT_SYMBOL_GPL(of_pci_get_host_bridge_resources);

#ifdef CONFIG_PCI_MSI

static LIST_HEAD(of_pci_msi_chip_list);
static DEFINE_MUTEX(of_pci_msi_chip_mutex);

int of_pci_msi_chip_add(struct msi_chip *chip)
{
	if (!of_property_read_bool(chip->of_node, "msi-controller"))
		return -EINVAL;

	mutex_lock(&of_pci_msi_chip_mutex);
	list_add(&chip->list, &of_pci_msi_chip_list);
	mutex_unlock(&of_pci_msi_chip_mutex);

	return 0;
}
EXPORT_SYMBOL_GPL(of_pci_msi_chip_add);

void of_pci_msi_chip_remove(struct msi_chip *chip)
{
	mutex_lock(&of_pci_msi_chip_mutex);
	list_del(&chip->list);
	mutex_unlock(&of_pci_msi_chip_mutex);
}
EXPORT_SYMBOL_GPL(of_pci_msi_chip_remove);

struct msi_chip *of_pci_find_msi_chip_by_node(struct device_node *of_node)
{
	struct msi_chip *c;

	mutex_lock(&of_pci_msi_chip_mutex);
	list_for_each_entry(c, &of_pci_msi_chip_list, list) {
		if (c->of_node == of_node) {
			mutex_unlock(&of_pci_msi_chip_mutex);
			return c;
		}
	}
	mutex_unlock(&of_pci_msi_chip_mutex);

	return NULL;
}
EXPORT_SYMBOL_GPL(of_pci_find_msi_chip_by_node);

#endif /* CONFIG_PCI_MSI */
