#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/blkdev.h>
#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/dma-mapping.h>
#include <linux/device.h>
#include <linux/dmi.h>
#include <linux/gfp.h>
#include <linux/msi.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_cmnd.h>
#include <linux/libata.h>

void thunder_mmc_irq_request(struct msix_entry *entry);

static int temp_probe(struct pci_dev *pdev,
				    const struct pci_device_id *id)
{
	
	int rc, nvec;
	struct msix_entry entry[9]={{0,0}, {0,1}, {0,2}, {0,3}, {0, 4}, {0, 5}, {0, 6}, {0, 7}, {0,8}};

	pci_enable_device(pdev);

	/* check if msix is supported */
	nvec = pci_msix_vec_count(pdev);
	if (nvec <= 0)
		return 0;

	rc = pci_enable_msix(pdev, entry, 9);
	if (rc < 0)
		return rc;

	thunder_mmc_irq_request(entry);

	return 0;
}

static struct pci_device_id temp_ids[] = {
        {PCI_DEVICE(0x177d, 0xa010)},
        { }
};

static struct pci_driver temp_driver = {
        .name = "TEMP",
        .id_table = temp_ids,
        .probe = temp_probe,
};

module_pci_driver(temp_driver);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TEMP driver");
MODULE_DEVICE_TABLE(pci, temp_ids);
