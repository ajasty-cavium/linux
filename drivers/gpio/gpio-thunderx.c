/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2015 Cavium Inc.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/pci.h>
#include <linux/i2c.h>
#include <linux/gpio.h>
#include <linux/io.h>
#include <linux/of.h>

#define DRV_NAME	"gpio-thunderx"
#define DRV_VERSION	"1.0"

#define RX_DAT		0x00
#define TX_SET		0x08
#define TX_CLEAR	0x10
#define BIT_CFG(bit)	(0x400 + (bit * 0x8))
#define INTR(bit)	(0x800 + (bit * 0x8))

#define CFG_TX_OE	0x1
#define CFG_PIN_XOR	0x2
#define CFG_INT_EN	0x4
#define CFG_INT_TYPE	0x8

#define INTR_INTR	0x1
#define INTR_ENA_W1C	0x4
#define INTR_ENA_W1S	0x8


#define PCI_CFG_REG_BAR_NUM	0
#define PCI_DEVICE_ID_THUNDER_GPIO	0xa00a

#define GPIO_NAME_LEN	20
#define NUM_GPIOS	51
#define MAX_INT_GPIO	20
#define IRQ_NAME_LEN	20

#define GPIO_MSIX_VEC(gpio)	(0x30 + ((gpio) * 0x2))

struct thunderx_gpio;

struct thunderx_gpio_irq {
	struct thunderx_gpio *gpio;
	int gpiox;
	uint8_t irq_allocated;
	uint8_t irq_enable;
	uint16_t intr_type;
	int gpio_lirq;
	char irq_name[IRQ_NAME_LEN];
};

struct thunderx_gpio {
	struct gpio_chip chip;
	void __iomem *gpio_base;
	struct pci_dev *pdev;
	struct irq_domain *irq_dom;
	char gpio_name[GPIO_NAME_LEN];
	uint8_t soc_node;

	/* MSI-X */
	bool			msix_enabled;
	uint16_t		num_vec;
	struct	msix_entry	msix_entries[MAX_INT_GPIO];
	struct thunderx_gpio_irq irq_entries[MAX_INT_GPIO];
};

static const struct pci_device_id thunderx_gpio_id_table[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, PCI_DEVICE_ID_THUNDER_GPIO) },
	{ 0, }  /* end of table */
};

MODULE_DEVICE_TABLE(pci, thunderx_gpio_id_table);

struct thunderx_gpio_irq *gpio_to_gpio_irq(struct thunderx_gpio *gpio,
					   int gpiox)
{
	int irqx;

	for (irqx = 0; irqx < MAX_INT_GPIO; irqx++) {
		if (gpio->irq_entries[irqx].gpiox == gpiox)
			return &gpio->irq_entries[irqx];
	}
	return NULL;
}

static int thunderx_gpio_wr_xor(struct thunderx_gpio *gpio, unsigned offset,
				uint8_t val)
{
	u64 cfg_val;

	cfg_val = readq(gpio->gpio_base + BIT_CFG(offset));
	if (val)
		cfg_val |= CFG_PIN_XOR;
	else
		cfg_val &= ~(u64)CFG_PIN_XOR;
	writeq(cfg_val, gpio->gpio_base + BIT_CFG(offset));
	return 0;
}

static int thunderx_gpio_wr_int_type(struct thunderx_gpio *gpio,
				     unsigned offset, uint8_t val)
{
	u64 cfg_val;

	cfg_val = readq(gpio->gpio_base + BIT_CFG(offset));
	if (val)
		cfg_val |= CFG_INT_TYPE;
	else
		cfg_val &= ~(u64)CFG_INT_TYPE;
	writeq(cfg_val, gpio->gpio_base + BIT_CFG(offset));
	return 0;
}

static int thunderx_gpio_dir_in(struct gpio_chip *chip, unsigned offset)
{
	struct thunderx_gpio *gpio =
		container_of(chip, struct thunderx_gpio, chip);
	u64 cfg_val;

	cfg_val = readq(gpio->gpio_base + BIT_CFG(offset));
	cfg_val &= ~(u64)CFG_TX_OE;
	writeq(cfg_val, gpio->gpio_base + BIT_CFG(offset));
	return 0;
}

static void thunderx_gpio_set(struct gpio_chip *chip, unsigned offset,
			      int value)
{
	struct thunderx_gpio *gpio =
		container_of(chip, struct thunderx_gpio, chip);
	u64 mask = 1ull << offset;
	void *reg = gpio->gpio_base + (value ? TX_SET : TX_CLEAR);

	writeq(mask, reg);
}

static int thunderx_gpio_dir_out(struct gpio_chip *chip, unsigned offset,
			       int value)
{
	struct thunderx_gpio *gpio =
		container_of(chip, struct thunderx_gpio, chip);
	u64 cfg_val;

	thunderx_gpio_set(chip, offset, value);

	cfg_val = readq(gpio->gpio_base + BIT_CFG(offset));
	cfg_val |= CFG_TX_OE;
	writeq(cfg_val, gpio->gpio_base + BIT_CFG(offset));
	return 0;
}

static int thunderx_gpio_read(struct thunderx_gpio *gpio, unsigned offset)
{
	u64 read_bits = readq(gpio->gpio_base + RX_DAT);

	return ((1ull << offset) & read_bits) != 0;
}

static int thunderx_gpio_get(struct gpio_chip *chip, unsigned offset)
{
	struct thunderx_gpio *gpio =
		container_of(chip, struct thunderx_gpio, chip);
	return thunderx_gpio_read(gpio, offset);
}

static int is_level_intr(uint16_t type)
{
	return ((type & (IRQ_TYPE_LEVEL_HIGH | IRQ_TYPE_LEVEL_LOW)) != 0);
}

static int is_edge_intr(uint16_t type)
{
	return ((type & (IRQ_TYPE_EDGE_RISING | IRQ_TYPE_EDGE_FALLING)) != 0);
}

static void thunderx_gpio_int_enable(struct thunderx_gpio *gpio, int gpiox)
{
	u64 cfg_val = readq(gpio->gpio_base + BIT_CFG(gpiox));
	struct thunderx_gpio_irq *gpio_irq = gpio_to_gpio_irq(gpio, gpiox);

	if (gpio_irq == NULL)
		return;
	cfg_val |= CFG_INT_EN;
	writeq(cfg_val, gpio->gpio_base + BIT_CFG(gpiox));
	writeq(INTR_ENA_W1S, gpio->gpio_base + INTR(gpiox));
	gpio_irq->irq_enable = 1;
}

static void thunderx_gpio_int_disable(struct thunderx_gpio *gpio, int gpiox)
{
	u64 cfg_val = readq(gpio->gpio_base + BIT_CFG(gpiox));
	struct thunderx_gpio_irq *gpio_irq = gpio_to_gpio_irq(gpio, gpiox);

	if (gpio_irq == NULL)
		return;
	cfg_val &= ~(u64)CFG_INT_EN;
	writeq(cfg_val, gpio->gpio_base + BIT_CFG(gpiox));
	writeq(INTR_ENA_W1C, gpio->gpio_base + INTR(gpiox));
	gpio_irq->irq_enable = 0;
}

static void thunderx_gpio_int_ack(struct thunderx_gpio *gpio, int gpiox)
{
	writeq(INTR_INTR, gpio->gpio_base + INTR(gpiox));
}

static irqreturn_t thunderx_gpio_intr_handler (int irq, void *irq_param)
{
	struct thunderx_gpio_irq *gpio_irq = irq_param;
	struct thunderx_gpio *gpio = gpio_irq->gpio;

	/* ack edge intr */
	if (is_edge_intr(gpio_irq->intr_type))
		thunderx_gpio_int_ack(gpio, gpio_irq->gpiox);

	generic_handle_irq(gpio_irq->gpio_lirq);
	return IRQ_HANDLED;
}

/* Return num ints or -1 if err */
static int thunderx_gpio_enable_msix(struct thunderx_gpio *gpio)
{
	int ret;
	int gpiox;
	int irqx;
	struct thunderx_gpio_irq *gpio_irq;

	for (irqx = 0; irqx < MAX_INT_GPIO; irqx++) {
		gpio_irq = &gpio->irq_entries[irqx];
		gpiox = gpio_irq->gpiox;
		if (!gpio_irq->intr_type)
			break;
		gpio->msix_entries[irqx].entry = GPIO_MSIX_VEC(gpiox);
		snprintf(gpio_irq->irq_name, IRQ_NAME_LEN,
			 "irq-gpio%d", gpio_irq->gpiox);
		gpio_irq->irq_allocated = 0;
	}
	gpio->num_vec = irqx;

	if (gpio->num_vec) {
		ret = pci_enable_msix(gpio->pdev, gpio->msix_entries,
				      gpio->num_vec);
		if (ret) {
			dev_err(&gpio->pdev->dev ,
				"Request for #%d msix vectors failed\n",
				gpio->num_vec);
			return ret;
		}
		gpio->msix_enabled = 1;
	}
	return gpio->num_vec;
}

static void thunderx_gpio_disable_msix(struct thunderx_gpio *gpio)
{
	if (gpio->msix_enabled) {
		pci_disable_msix(gpio->pdev);
		gpio->msix_enabled = 0;
		gpio->num_vec = 0;
	}
}

static int thunderx_gpio_to_irq(struct gpio_chip *chip, unsigned offset)
{
	struct thunderx_gpio *gpio =
		container_of(chip, struct thunderx_gpio, chip);
	int irqx;

	for (irqx = 0; irqx < gpio->num_vec; irqx++) {
		if ((gpio->irq_entries[irqx].gpiox == offset) &&
		    (gpio->irq_entries[irqx].gpio_lirq >= 0))
			return gpio->irq_entries[irqx].gpio_lirq;
	}
	return -ENXIO;
}


static void thunderx_irq_mask(struct irq_data *data)
{
	struct thunderx_gpio_irq *gpio_irq = irq_data_get_irq_chip_data(data);
	struct thunderx_gpio *gpio = gpio_irq->gpio;
	int gpiox = gpio_irq->gpiox;

	thunderx_gpio_int_disable(gpio, gpiox);
}

static void thunderx_irq_unmask(struct irq_data *data)
{
	struct thunderx_gpio_irq *gpio_irq = irq_data_get_irq_chip_data(data);
	struct thunderx_gpio *gpio = gpio_irq->gpio;
	int gpiox = gpio_irq->gpiox;

	thunderx_gpio_int_enable(gpio, gpiox);
}

static void thunderx_irq_ack(struct irq_data *data)
{
	/* underlying gpio source ints are acked in local handler */
}

static int thunderx_gpio_irq_set_type(struct thunderx_gpio *gpio, int irqx,
				      unsigned int flow_type)
{
	struct thunderx_gpio_irq *gpio_irq = &gpio->irq_entries[irqx];
	int gpiox = gpio_irq->gpiox;
	int intr_type;
	int intr_xor;

	switch (flow_type) {
	case IRQ_TYPE_LEVEL_HIGH:
		intr_type = 0;
		intr_xor = 0;
		break;
	case IRQ_TYPE_LEVEL_LOW:
		intr_type = 0;
		intr_xor = 1;
		break;
	case IRQ_TYPE_EDGE_RISING:
		intr_type = 1;
		intr_xor = 0;
		break;
	case IRQ_TYPE_EDGE_FALLING:
		intr_type = 1;
		intr_xor = 1;
		break;
	default:
		dev_err(&gpio->pdev->dev,
			"only support one edge or level interrupts\n");
		return -EINVAL;
	}
	thunderx_gpio_wr_int_type(gpio, gpiox, intr_type);
	thunderx_gpio_wr_xor(gpio, gpiox, intr_xor);
	gpio_irq->intr_type = (u16)flow_type;

	return 0;
}

static int thunderx_irq_set_type(struct irq_data *data, unsigned int flow_type)
{
	struct thunderx_gpio_irq *gpio_irq = irq_data_get_irq_chip_data(data);
	struct thunderx_gpio *gpio = gpio_irq->gpio;
	int irqx = irqd_to_hwirq(data);

	return thunderx_gpio_irq_set_type(gpio, irqx, flow_type);
}

static struct irq_chip thunderx_gpio_irq_chip = {
	.name = "gpio-thunderx",
	.irq_mask = thunderx_irq_mask,
	.irq_unmask = thunderx_irq_unmask,
	.irq_ack = thunderx_irq_ack,
	.irq_set_type = thunderx_irq_set_type,
};

static int thunderx_gpio_irq_map(struct irq_domain *d, unsigned int irq,
				 irq_hw_number_t hwirq)
{
	int ret;
	struct thunderx_gpio *gpio = d->host_data;
	struct thunderx_gpio_irq *gpio_irq = &gpio->irq_entries[hwirq];

	ret = irq_set_chip_data(irq, gpio_irq);
	if (ret < 0)
		return ret;
	irq_set_chip_and_handler(irq, &thunderx_gpio_irq_chip,
				 is_level_intr(gpio_irq->intr_type) ?
				 handle_level_irq : handle_edge_irq);
	return 0;
}

static void thunderx_gpio_irq_unmap(struct irq_domain *d, unsigned int irq)
{
	irq_set_chip_and_handler(irq, NULL, NULL);
	irq_set_chip_data(irq, NULL);
}

static struct irq_domain_ops thunderx_irq_ops = {
	.map = thunderx_gpio_irq_map,
	.unmap = thunderx_gpio_irq_unmap,
};

static int thunderx_gpio_irq_setup(struct thunderx_gpio *gpio)
{
	int result;
	int intx;

	for (intx = 0; intx < gpio->num_vec; intx++) {
		thunderx_gpio_irq_set_type(gpio, intx,
					   gpio->irq_entries[intx].intr_type);
		result = devm_request_irq(&gpio->pdev->dev,
					  gpio->msix_entries[intx].vector,
					  thunderx_gpio_intr_handler, 0,
					  gpio->irq_entries[intx].irq_name,
					  &gpio->irq_entries[intx]);
		if (result < 0) {
			dev_err(&gpio->pdev->dev,
				"failed to attach interrupt\n");
			return result;
		}
		gpio->irq_entries[intx].gpio_lirq =
			irq_create_mapping(gpio->irq_dom, intx);
		gpio->irq_entries[intx].irq_allocated = 1;
	}
	return 0;
}

static void thunderx_gpio_irq_cleanup(struct thunderx_gpio *gpio)
{
	int intx;

	for (intx = 0; intx < gpio->num_vec; intx++) {
		struct thunderx_gpio_irq *irq_ent =
			&gpio->irq_entries[intx];
		if (!irq_ent->irq_allocated)
			continue;
		thunderx_gpio_int_disable(gpio, irq_ent->gpiox);
		irq_dispose_mapping(irq_ent->gpio_lirq);
		devm_free_irq(&gpio->pdev->dev,
			      gpio->msix_entries[intx].vector,
			      irq_ent);
		irq_ent->irq_allocated = 0;
	}
}

static int thunderx_gpio_probe(struct pci_dev *pdev,
			       const struct pci_device_id *ent)
{
	struct thunderx_gpio *gpio;
	struct gpio_chip *chip;
	struct device *dev = &pdev->dev;
	int err = 0;
	int num_int;
	struct device_node *np;
	char gpio_name[10];
	int intx = 0;
	int iprop;
	int gpiox;
	int intr_type;

	gpio = devm_kzalloc(dev, sizeof(*gpio), GFP_KERNEL);
	if (!gpio)
		return -ENOMEM;
	gpio->pdev = pdev;
	pci_set_drvdata(pdev, gpio);
	chip = &gpio->chip;

	err = pci_enable_device(pdev);
	if (err)
		goto out;
	err = pci_request_regions(pdev, DRV_NAME);
	if (err)
		goto out_disable_device;

	gpio->gpio_base = pci_ioremap_bar(pdev, PCI_CFG_REG_BAR_NUM);
	if (!gpio->gpio_base) {
		err = -ENOMEM;
		goto out_release_regions;
	}
	gpio->soc_node = (pci_resource_start(pdev, PCI_CFG_REG_BAR_NUM) >> 44)
			 & 0x3;
	snprintf(gpio->gpio_name, sizeof(gpio->gpio_name), "%s-%d",
		 DRV_NAME, gpio->soc_node);

	pdev->dev.platform_data = chip;
	chip->label = gpio->gpio_name;
	chip->dev = dev;
	chip->owner = THIS_MODULE;
	chip->base = gpio->soc_node * NUM_GPIOS;
	chip->can_sleep = false;
	chip->ngpio = NUM_GPIOS;
	chip->direction_input = thunderx_gpio_dir_in;
	chip->get = thunderx_gpio_get;
	chip->direction_output = thunderx_gpio_dir_out;
	chip->set = thunderx_gpio_set;
	chip->to_irq = thunderx_gpio_to_irq;
	err = gpiochip_add(chip);
	if (err)
		goto out_unmap;
	snprintf(gpio_name, 10, "gpio%d", gpio->soc_node);
	np = of_find_node_by_name(NULL, gpio_name);
	if (!np) {
		dev_warn(dev, "No DT node for %s\n", gpio_name);
		goto nodt;
	}

	for (iprop = 0;; iprop += 2) {
		if (of_property_read_u32_index(np, "gpio-intr", iprop, &gpiox))
			break;
		if (of_property_read_u32_index(np, "gpio-intr", iprop+1,
					       &intr_type))
			break;
		if (intx < MAX_INT_GPIO) {
			gpio->irq_entries[intx].gpio = gpio;
			gpio->irq_entries[intx].gpiox = gpiox;
			gpio->irq_entries[intx].intr_type = intr_type;
			intx++;
		} else {
			dev_err(dev, "Too many gpios as interrupts\n");
			break;
		}
	}
	if (intx) {
		num_int = thunderx_gpio_enable_msix(gpio);
		if (num_int < 0) {
			dev_err(dev, "Unable to enable MSI-X\n");
			err = num_int;
			goto out_gpiochip;
		} else if (num_int > 0) {
			gpio->irq_dom = irq_domain_add_linear(dev->of_node,
							      num_int,
							      &thunderx_irq_ops,
							      gpio);
			if (!gpio->irq_dom) {
				dev_err(chip->dev,
					"not able to add gpio irq domain\n");
				goto out_msix;
			}

			err = thunderx_gpio_irq_setup(gpio);
			if (err) {
				dev_err(chip->dev, "irq setup failed\n");
				goto out_msix;
			}
		}
	}
nodt:
	dev_info(dev, "ThunderX GPIO driver probed.\n");
	return 0;
out_msix:
	thunderx_gpio_disable_msix(gpio);
out_gpiochip:
	gpiochip_remove(chip);
out_unmap:
	iounmap(gpio->gpio_base);
out_release_regions:
	pci_release_regions(pdev);
out_disable_device:
	pci_disable_device(pdev);
out:
	devm_kfree(dev, gpio);
	return err;
}

static void thunderx_gpio_remove(struct pci_dev *pdev)
{
	struct thunderx_gpio *gpio = pci_get_drvdata(pdev);
	struct gpio_chip *chip = pdev->dev.platform_data;

	if (gpio->msix_enabled) {
		thunderx_gpio_irq_cleanup(gpio);
		thunderx_gpio_disable_msix(gpio);
		irq_domain_remove(gpio->irq_dom);
	}
	gpiochip_remove(chip);
	if (gpio->gpio_base)
		iounmap(gpio->gpio_base);
	pci_release_regions(pdev);
	pci_disable_device(pdev);
}

static struct pci_driver thunderx_gpio_driver = {
	.name		= DRV_NAME,
	.id_table	= thunderx_gpio_id_table,
	.probe		= thunderx_gpio_probe,
	.remove		= thunderx_gpio_remove,
};

module_pci_driver(thunderx_gpio_driver);

MODULE_DESCRIPTION("Cavium ThunderX GPIO Driver");
MODULE_AUTHOR("Cavium, Inc.");
MODULE_LICENSE("GPL");
MODULE_VERSION(DRV_VERSION);

