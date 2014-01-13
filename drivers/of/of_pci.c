#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_pci.h>

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

/**
 * pci_host_bridge_of_get_ranges - Parse PCI host bridge resources from DT
 * @dev: device node of the host bridge having the range property
 * @resources: list where the range of resources will be added after DT parsing
 * @io_base: pointer to a variable that will contain the physical address for
 * the start of the I/O range.
 *
 * It is the callers job to free the @resources list if an error is returned.
 *
 * This function will parse the "ranges" property of a PCI host bridge device
 * node and setup the resource mapping based on its content. It is expected
 * that the property conforms with the Power ePAPR document.
 *
 * Each architecture is then offered the chance of applying their own
 * filtering of pci_host_bridge_windows based on their own restrictions by
 * calling pcibios_fixup_bridge_ranges(). The filtered list of windows
 * can then be used when creating a pci_host_bridge structure.
 */
static int pci_host_bridge_of_get_ranges(struct device_node *dev,
		struct list_head *resources, resource_size_t *io_base)
{
	struct resource *res;
	struct of_pci_range range;
	struct of_pci_range_parser parser;
	int err;

	pr_info("PCI host bridge %s ranges:\n", dev->full_name);

	/* Check for ranges property */
	err = of_pci_range_parser_init(&parser, dev);
	if (err)
		return err;

	pr_debug("Parsing ranges property...\n");
	for_each_of_pci_range(&parser, &range) {
		/* Read next ranges element */
		pr_debug("pci_space: 0x%08x pci_addr:0x%016llx cpu_addr:0x%016llx size:0x%016llx\n",
			range.pci_space, range.pci_addr, range.cpu_addr, range.size);

		/*
		 * If we failed translation or got a zero-sized region
		 * then skip this range
		 */
		if (range.cpu_addr == OF_BAD_ADDR || range.size == 0)
			continue;

		res = kzalloc(sizeof(struct resource), GFP_KERNEL);
		if (!res)
			return -ENOMEM;

		err = of_pci_range_to_resource(&range, dev, res);
		if (err)
			return err;

		if (resource_type(res) == IORESOURCE_IO)
			*io_base = range.cpu_addr;

		pci_add_resource_offset(resources, res,
				res->start - range.pci_addr);
	}

	/* Apply architecture specific fixups for the ranges */
	return pcibios_fixup_bridge_ranges(resources);
}

static atomic_t domain_nr = ATOMIC_INIT(-1);

/**
 * of_create_pci_host_bridge - Create a PCI host bridge structure using
 * information passed in the DT.
 * @parent: device owning this host bridge
 * @ops: pci_ops associated with the host controller
 * @host_data: opaque data structure used by the host controller.
 *
 * returns a pointer to the newly created pci_host_bridge structure, or
 * NULL if the call failed.
 *
 * This function will try to obtain the host bridge domain number by
 * using of_alias_get_id() call with "pci-domain" as a stem. If that
 * fails, a local allocator will be used that will put each host bridge
 * in a new domain.
 */
struct pci_host_bridge *
of_create_pci_host_bridge(struct device *parent, struct pci_ops *ops, void *host_data)
{
	int err, domain, busno;
	struct resource *bus_range;
	struct pci_bus *root_bus;
	struct pci_host_bridge *bridge;
	resource_size_t io_base = 0;
	LIST_HEAD(res);

	bus_range = kzalloc(sizeof(*bus_range), GFP_KERNEL);
	if (!bus_range)
		return ERR_PTR(-ENOMEM);

	domain = of_alias_get_id(parent->of_node, "pci-domain");
	if (domain == -ENODEV)
		domain = atomic_inc_return(&domain_nr);

	err = of_pci_parse_bus_range(parent->of_node, bus_range);
	if (err) {
		dev_info(parent, "No bus range for %s, using default [0-255]\n",
			parent->of_node->full_name);
		bus_range->start = 0;
		bus_range->end = 255;
		bus_range->flags = IORESOURCE_BUS;
	}
	busno = bus_range->start;
	pci_add_resource(&res, bus_range);

	/* now parse the rest of host bridge bus ranges */
	err = pci_host_bridge_of_get_ranges(parent->of_node, &res, &io_base);
	if (err)
		goto err_create;

	/* then create the root bus */
	root_bus = pci_create_root_bus_in_domain(parent, domain, busno,
						ops, host_data, &res);
	if (IS_ERR(root_bus)) {
		err = PTR_ERR(root_bus);
		goto err_create;
	}

	bridge = to_pci_host_bridge(root_bus->bridge);
	bridge->io_base = io_base;

	return bridge;

err_create:
	pci_free_resource_list(&res);
	return ERR_PTR(err);
}
EXPORT_SYMBOL_GPL(of_create_pci_host_bridge);

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
