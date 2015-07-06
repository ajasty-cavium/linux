#include <linux/acpi.h>
#include <linux/percpu.h>
#include <linux/slab.h>
#include <linux/kvm.h>
#include <linux/kvm_host.h>
#include <linux/iommu.h>
#include <linux/irq.h>
#include <linux/interrupt.h>
#include <linux/irqchip/arm-gic-v3.h>
#include <linux/vfio.h>
#include <linux/module.h>

#include <asm/cacheflush.h>
#include <asm/cputype.h>
#include <asm/exception.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_arm.h>
#include <asm/kvm_mmu.h>

#include "vgic.h"

struct msi_master {

	struct list_head	entry;
	struct pci_bus		*bus;
	struct msi_chip		msi;
	struct msi_chip		*real_msi;
};

LIST_HEAD(msi_masters);

struct vits_pirq {

	struct list_head	entry;
	uint32_t		pirq;
	struct vgic_its_device *vits_dev;
};


LIST_HEAD(vits_pirqs);

int pci_requester_id(struct pci_dev *dev);
static DEFINE_SPINLOCK(vits_lock);

static struct its_node *get_its_node(struct pci_dev *pdev)
{
	struct msi_master *master = container_of(pdev->bus->msi,
					struct msi_master, msi);
	return container_of(master->real_msi, struct its_node, msi_chip);

}

static u64 vgic_its_get_host_translator_addr(struct pci_dev *pdev)
{
	if (!pdev)
		return (unsigned long)NULL;

	return get_its_node(pdev)->phys_base + GITS_TRANSLATER - 0x40;
}

static u64 vgic_its_get_vm_translator_addr(struct kvm *kvm)
{
	if (!kvm)
		return (unsigned long)NULL;

	return kvm->arch.vgic.vgic_its_base + GITS_TRANSLATER - 0x40;

}

struct vgic_its_device *get_vgic_its_dev(struct vgic_its *its, int vdev_id)
{
	struct vgic_its_device *its_dev;

	list_for_each_entry(its_dev, &its->its_devices, entry) {
		if (its_dev->vdev_id == vdev_id)
			return its_dev;
	}

	return NULL;
}

struct vgic_its_irq *get_vgic_its_irq(struct vgic_its_device *vits_dev,
					int pirq, int ID, bool irqbased)
{
	struct vgic_its_irq *vits_irq;

	list_for_each_entry(vits_irq, &(vits_dev->pirq_list), entry) {
		if (irqbased) {
			if( vits_irq->pirq == pirq) {
			return vits_irq;
			}
		}
		else if (vits_irq->ID == ID) {
			return vits_irq;
		}
	}

	return NULL;
}

static irqreturn_t vgic_its_handle_interrupt(int irq, void *dev)
{
	struct vgic_its_device *vits_dev = dev;
	struct vgic_its_irq *vits_irq;
	unsigned long flag;

	spin_lock_irqsave(&vits_lock, flag);

	vits_irq = get_vgic_its_irq(vits_dev, irq, -1, true);
	if (!vits_irq || vits_irq->virq < 8192) {
		spin_unlock_irqrestore(&vits_lock, flag);
		return IRQ_NONE;
	}
	kvm_vgic_inject_irq(vits_dev->kvm, vits_irq->vcol_id,
			vits_irq->virq, 1);
	spin_unlock_irqrestore(&vits_lock, flag);
	return IRQ_HANDLED;
}

static inline bool is_offset_legal(u64 base, int size, int offset)
{
	return ((base + offset) < (base + size)) ? true : false;
}

static void convert_mapc(struct kvm_vcpu *vcpu, struct its_cmd_block *cmd)
{
}

static void convert_mapd(struct kvm_vcpu *vcpu, struct its_cmd_block *cmd)
{
	u8 valid = (u8) (cmd->raw_cmd[2] >> 63);
	u32 vdev_id = (u32) (cmd->raw_cmd[0] >> 32);
	u8 size  = (u8) (cmd->raw_cmd[1] & 0x1f);
	struct vgic_its *its;
	struct vgic_its_device *vits_dev;
	u32 pdev_id;

	its = &vcpu->kvm->arch.vgic.its;
	if(!its)
		return;
	vits_dev = get_vgic_its_dev(its, vdev_id);
	if(!vits_dev)
		return;
	pdev_id= vits_dev->pdev_id;

	size = 1UL <<  (size + 1);

	if (valid && !vits_dev->pits_dev) {
		vits_dev->pits_dev = its_create_device(get_its_node(vits_dev->pdev), pdev_id, size);
		if (IS_ENABLED(CONFIG_PCI_MSI)) {
			vits_dev->pdev->msidata = vits_dev;
			vits_dev->pdev->num_enabled_msi = 0;
		}
	}
	else {
		if (IS_ENABLED(CONFIG_PCI_MSI)) {
			vits_dev->pdev->msidata = NULL;
			vits_dev->pdev->num_enabled_msi = 0;
		}
	}
}

static void convert_mapi(struct kvm_vcpu *vcpu, struct its_cmd_block *cmd)
{
}

static void convert_mapvi(struct kvm_vcpu *vcpu, struct its_cmd_block *cmd)
{
	u32 vdev_id = (u32) (cmd->raw_cmd[0] >> 32);
	u32 virq = (u32) (cmd->raw_cmd[1] >> 32);
	u32 ID = (u32) cmd->raw_cmd[1];
	u16 collection = (u16) cmd->raw_cmd[2];
	struct vgic_its *its;
	struct vgic_its_device *vits_dev;
	struct vgic_its_irq *vits_irq;
	struct vgic_its_cpu *its_cpu = &vcpu->arch.vgic_cpu.its_cpu;
	u32 pirq = 0, hwirq;
	struct irq_data *d;

	its = &vcpu->kvm->arch.vgic.its;
	if(!its || !its_cpu)
		return;
	vits_dev = get_vgic_its_dev(its, vdev_id);
	if(!vits_dev)
		return;

	if (!vits_dev->pits_dev)
		return;

	vits_irq = get_vgic_its_irq(vits_dev, -1, ID, false);
	if (vits_irq)
		goto skip_allocation;

	vits_irq = kzalloc(sizeof(struct vgic_its_irq),	GFP_KERNEL);
	if (!vits_irq)
		return;

	its_alloc_device_irq(vits_dev->pits_dev,
				ID, &hwirq, &pirq);
	INIT_LIST_HEAD(&(vits_irq->entry));

	list_add(&(vits_irq->entry), &(vits_dev->pirq_list));
	vits_dev->pdev->num_enabled_msi++;
	vits_irq->pirq = pirq;
	vits_irq->hwirq = hwirq;
	vits_irq->ID = ID;
skip_allocation:
	vits_irq->virq = virq;
	vits_irq->vcol_id = collection;
	vits_irq->pcol_id = its_cpu->pcollection;

	d = irq_get_irq_data(vits_irq->pirq);
	if(d && d->msi_desc)
		unmask_msi_irq(d);
}

static void convert_movi(struct kvm_vcpu *vcpu, struct its_cmd_block *cmd)
{
	u32 vdev_id = (u32) (cmd->raw_cmd[0] >> 32);
	u32 ID = (u32) cmd->raw_cmd[1];
	u16 collection = (u16) cmd->raw_cmd[2];
	struct vgic_its *its = &vcpu->kvm->arch.vgic.its;
	struct vgic_its_device *vits_dev;
	struct vgic_its_irq *vits_irq;

	vits_dev = get_vgic_its_dev(its, vdev_id);
	if (!vits_dev)
		return;
	vits_irq = get_vgic_its_irq(vits_dev, -1, ID, false);
	if (!vits_irq)
		return;
	vits_irq->vcol_id = collection;
}

static void convert_discard(struct kvm_vcpu *vcpu, struct its_cmd_block *cmd)
{
	u32 vdev_id = (u32) (cmd->raw_cmd[0] >> 32);
	u32 ID = (u32) cmd->raw_cmd[1];
	struct vgic_its *its = &vcpu->kvm->arch.vgic.its;
	struct vgic_its_irq *vits_irq;
	struct vgic_its_device *vits_dev = get_vgic_its_dev(its, vdev_id);
	struct irq_data *d;

	if(!vits_dev)
		return;

	vits_irq = get_vgic_its_irq(vits_dev, -1, ID, false);
	if (vits_irq) {
		vits_irq->virq = 0;
		d = irq_get_irq_data(vits_irq->pirq);
		if(d && d->msi_desc)
			mask_msi_irq(d);

	}
}

static void convert_inv(struct kvm_vcpu *vcpu, struct its_cmd_block *cmd)
{
}

static void convert_movall(struct kvm_vcpu *vcpu, struct its_cmd_block *cmd)
{
}

static void convert_invall(struct kvm_vcpu *vcpu, struct its_cmd_block *cmd)
{
}

static void convert_int(struct kvm_vcpu *vcpu, struct its_cmd_block *cmd)
{
}

static void convert_clear(struct kvm_vcpu *vcpu, struct its_cmd_block *cmd)
{
}

static void convert_sync(struct kvm_vcpu *vcpu, struct its_cmd_block *cmd)
{
}

int vgic_its_handle_guest_commands(struct kvm_vcpu *vcpu, u64 cq_base,
		int cq_size, int write_offset, int read_offset)
{
	gpa_t gpa = (cq_base << 12);
	bool read_agin = (read_offset <= write_offset) ? false : true;
	struct its_cmd_block *user_cq;
	int size, user_cq_size, num_cmds, i;
	u8 cmd;
	unsigned long flag;

	if (!is_offset_legal(cq_base, cq_size, read_offset))
		return -ENXIO;
	if (!is_offset_legal(cq_base, cq_size, write_offset))
		return -ENXIO;

	if (read_agin)
		size = cq_size - read_offset;
	else
		size = write_offset - read_offset;
	user_cq_size = (read_agin) ? (size+write_offset) : size;

	if (user_cq_size == 0)
		return 0;

	/* TODO : replace this by directly working on guest cq.
	 * do the easy thing for now.
	 */
	user_cq = kmalloc(user_cq_size, GFP_KERNEL);
	if (!user_cq)
		return -ENOMEM;

	kvm_read_guest(vcpu->kvm, gpa + read_offset, (void *)user_cq, size);
	if (read_agin)
		kvm_read_guest(vcpu->kvm, gpa,
				((u8 *)user_cq)+size, write_offset);

	num_cmds = user_cq_size / sizeof(struct its_cmd_block);

	spin_lock_irqsave(&vits_lock, flag);
	for (i = 0; i < num_cmds; i++) {
		cmd = *(u8 *)(user_cq + i);

		switch (cmd) {
		case GITS_CMD_MAPD:
			convert_mapd(vcpu, user_cq + i);
			break;
		case GITS_CMD_MAPC:
			convert_mapc(vcpu, user_cq + i);
			break;
		case GITS_CMD_MAPI:
			convert_mapi(vcpu, user_cq + i);
			break;
		case GITS_CMD_MAPVI:
			convert_mapvi(vcpu, user_cq + i);
			break;
		case GITS_CMD_MOVI:
			convert_movi(vcpu, user_cq + i);
			break;
		case GITS_CMD_DISCARD:
			convert_discard(vcpu, user_cq + i);
			break;
		case GITS_CMD_INV:
			convert_inv(vcpu, user_cq + i);
			break;
		case GITS_CMD_MOVALL:
			convert_movall(vcpu, user_cq + i);
			break;
		case GITS_CMD_INVALL:
			convert_invall(vcpu, user_cq + i);
			break;
		case GITS_CMD_INT:
			convert_int(vcpu, user_cq + i);
			break;
		case GITS_CMD_CLEAR:
			convert_clear(vcpu, user_cq + i);
			break;
		case GITS_CMD_SYNC:
			convert_sync(vcpu, user_cq + i);
			break;
		default:
			printk("Unknown ITS command ..\n");

		}
	}
	/* flush this writes before releasing lock */
	mb();
	mb();
	spin_unlock_irqrestore(&vits_lock, flag);
	kfree(user_cq);
	return 0;
}

int vgic_its_create_device(struct  kvm *kvm, u32 vdev_id, struct pci_dev *pdev,
			   struct vfio_device *vfio)
{
	struct vgic_its_device *its_dev;
	struct vgic_its *its = &kvm->arch.vgic.its;
	unsigned long flag;

	if (!pdev)
		return -ENXIO;
	spin_lock_irqsave(&vits_lock, flag);
	its_dev = get_vgic_its_dev(its, vdev_id);
	if(its_dev) {
		spin_lock_irqsave(&vits_lock, flag);
		goto skip_list_add;
	}
	else {
		its_dev = kzalloc(sizeof(struct vgic_its_device), GFP_KERNEL);
	}
	if (!its_dev) {
		spin_unlock_irqrestore(&vits_lock, flag);
		return -ENOMEM;
	}
	INIT_LIST_HEAD(&(its_dev->entry));
	list_add(&(its_dev->entry), &(its->its_devices));
skip_list_add:
	INIT_LIST_HEAD(&(its_dev->pirq_list));
	its_dev->vdev_id = vdev_id;
	its_dev->pdev_id = pci_requester_id(pdev);
	its_dev->pdev = pdev;
	its_dev->kvm = kvm;
	its_dev->vfio = vfio;
	/* take MSI owner ship of this pdev */
	if (IS_ENABLED(CONFIG_PCI_MSI)) {
		pdev->msidata = its_dev;
		pdev->num_enabled_msi = 0;
	}
	mb();
	spin_unlock_irqrestore(&vits_lock, flag);
	return 0;
}


int vgic_its_cpu_init(struct kvm_vcpu *vcpu)
{
	struct vgic_its_cpu *its_cpu = &vcpu->arch.vgic_cpu.its_cpu;
	struct its_node *its;
	int cpu = get_cpu();
	struct vgic_its_device *vits_dev =  NULL;
	struct vgic_its *vits = &vcpu->kvm->arch.vgic.its;
	int (*map_dev)(struct vfio_device *dev, unsigned long iova,
			unsigned long phyaddr, size_t size);
	unsigned long its_size = 0x10000;
	unsigned long iova;
	phys_addr_t phys_addr;
	unsigned long flag;

	spin_lock_irqsave(&vits_lock, flag);

	its = list_first_entry_or_null(&its_nodes, struct its_node , entry);
	if (!its)
		return -ENXIO;

	if (vcpu->kvm->arch.vgic.vgic_its_base == VGIC_ADDR_UNDEF)
		return -ENXIO;

	its_cpu->vcid = vcpu->vcpu_id;
	its_cpu->pcid = cpu;
	its_cpu->pcollection = its_get_collection(its, cpu);
	its_cpu->ptarget_address = its_get_target_address(its,
			cpu);

	/* if i am the first vcpu, take some additional responsability
	 * and add ITS transaltion entry to all iommu groups that belongs to us
	 */

	if (vcpu->vcpu_id == 0) {
		list_for_each_entry(vits_dev, &(vits->its_devices), entry) {
			/* map ITS_TRANSLATOR in to vm space */
			iova = vgic_its_get_vm_translator_addr(vcpu->kvm);
			phys_addr = vgic_its_get_host_translator_addr(
								vits_dev->pdev);
			map_dev = symbol_get(vfio_device_map_dev_space);
			if (map_dev) {
				map_dev(vits_dev->vfio, iova,
					phys_addr, its_size);
				symbol_put(vfio_device_map_dev_space);
			}
		}
	}

	spin_unlock_irqrestore(&vits_lock, flag);
	put_cpu();
	return 0;

}

int vgic_its_init(struct kvm *kvm)
{
	struct vgic_its *vits = &kvm->arch.vgic.its;
	struct its_node *its;

	its = list_first_entry_or_null(&its_nodes, struct its_node , entry);
	if (!its)
		return -ENXIO;
	INIT_LIST_HEAD(&vits->its_devices);

	return 0;

}


void vgic_its_free(struct kvm *kvm)
{
	struct vgic_its *its = &kvm->arch.vgic.its;
	struct vgic_its_device *vits_dev =  NULL;
	struct vgic_its_irq *vits_irq = NULL;
	struct vits_pirq *pirq_entry, *tmp;
	unsigned long flag;

	if (kvm->arch.vgic.vgic_its_base == VGIC_ADDR_UNDEF)
		return;

	spin_lock_irqsave(&vits_lock, flag);
	vits_dev = list_first_entry_or_null(&(its->its_devices),
					struct vgic_its_device, entry);

	while (vits_dev) {
		vits_irq = list_first_entry_or_null(
					&(vits_dev->pirq_list),
					struct vgic_its_irq, entry);
		while (vits_irq) {
			/* Stop the delivery of interrupts */
			if (vits_dev->pits_dev) {
				free_irq(vits_irq->pirq, vits_dev);
				its_send_discard(vits_dev->pits_dev,
						 vits_irq->ID);
			}
			list_del(&vits_irq->entry);
			kfree(vits_irq);
			vits_irq = list_first_entry_or_null(
						&(vits_dev->pirq_list),
						struct vgic_its_irq, entry);
		}

		list_for_each_entry_safe(pirq_entry, tmp, &vits_pirqs, entry) {
			if(pirq_entry->vits_dev != vits_dev)
				continue;

			list_del(&(pirq_entry->entry));
			kfree(pirq_entry);
		}

		list_del(&vits_dev->entry);
		vits_dev->pdev->msidata = NULL;
		vits_dev->pdev->num_enabled_msi = 0;
		kfree(vits_dev);
		vits_dev = list_first_entry_or_null(&(its->its_devices),
						struct vgic_its_device, entry);
	}
	mb();
	spin_unlock_irqrestore(&vits_lock, flag);
}

static inline u16 vits_msi_get_entry_nr(struct msi_desc *desc)
{
	return desc->msi_attrib.entry_nr;
}

static int vits_msi_setup_irq(struct msi_chip *chip,
			     struct pci_dev *pdev,
			     struct msi_desc *desc)
{
	struct msi_master *master = container_of(chip,
					struct msi_master, msi);
	u32 vec_nr;
	struct msi_msg msg;
	struct vgic_its_device *its_dev = pdev->msidata;
	u64 addr;
	int ret;
	unsigned long flag;
	unsigned int irq = 0;
	struct vgic_its_irq *vits_irq;
	struct vits_pirq *pirq_entry;

	spin_lock_irqsave(&vits_lock, flag);
	if (IS_ENABLED(CONFIG_PCI_MSI)) {
		vec_nr = vits_msi_get_entry_nr(desc);
		if (pdev->msidata) {
			vits_irq = get_vgic_its_irq(its_dev, -1, vec_nr, false);
			if (!vits_irq)
				goto end;
			irq = vits_irq->pirq;
			irq_set_msi_desc(irq, desc);

			addr = vgic_its_get_vm_translator_addr(its_dev->kvm);
			addr += 0x40;
			msg.address_lo		= (u32)addr;
			msg.address_hi		= (u32)(addr >> 32);
			msg.data		= vec_nr;
			write_msi_msg(irq, &msg);
			irq_set_handler_data(irq, its_dev->pits_dev);
			ret = request_irq(irq, vgic_its_handle_interrupt,
				0, "vits-mapvi-int", its_dev);
			if (IS_ERR_VALUE(ret))
				goto end;
			pirq_entry = kzalloc(sizeof(*pirq_entry), GFP_KERNEL);
			if(!pirq_entry)
				goto end;
			INIT_LIST_HEAD(&(pirq_entry)->entry);
			pirq_entry->pirq = irq;
			pirq_entry->vits_dev = its_dev;

			list_add(&(pirq_entry->entry), &vits_pirqs);
			mb();
			spin_unlock_irqrestore(&vits_lock, flag);
			return 0;
		}
	}
	spin_unlock_irqrestore(&vits_lock, flag);
	return master->real_msi->setup_irq(master->real_msi, pdev, desc);
end:
	spin_unlock_irqrestore(&vits_lock, flag);
	return -EINVAL;
}

static void vits_msi_teardown_irq(struct msi_chip *chip, unsigned int irq)
{
	struct msi_master *master = container_of(chip,
					struct msi_master, msi);
	struct vits_pirq *pirq_entry, *tmp;
	struct vgic_its_device *vits_dev = NULL;
	struct vgic_its_irq *vits_irq;
	unsigned long flag;

	spin_lock_irqsave(&vits_lock, flag);
	list_for_each_entry_safe(pirq_entry, tmp, &vits_pirqs, entry) {
		if(pirq_entry->pirq != irq)
			continue;
		vits_dev = pirq_entry->vits_dev;
		if(!vits_dev)
			continue;

		vits_irq = get_vgic_its_irq(vits_dev, irq, -1, true);
		if (vits_irq) {
			free_irq(vits_irq->pirq, vits_dev);
			list_del(&(vits_irq->entry));
			kfree(vits_irq);
			mb();
		}
		list_del(&(pirq_entry->entry));
		kfree(pirq_entry);

	}
	spin_unlock_irqrestore(&vits_lock, flag);
	master->real_msi->teardown_irq(master->real_msi, irq);
}


/**
 *Every thing that follows this is a Temp HACK for providing
 *Device IRQ_DOMAIN, as this is already merged to 3.19
 *Taking this short cut here
 **/


struct msi_chip *vgic_its_get_msi_node(struct pci_bus *bus,
						struct msi_chip *msi)
{
	struct msi_master *master;

	if (IS_ENABLED(CONFIG_PCI_MSI)) {
		master = kzalloc(sizeof(*master), GFP_KERNEL);
		if (!master)
			return msi;

		master->msi.setup_irq		= vits_msi_setup_irq;
		master->msi.teardown_irq	= vits_msi_teardown_irq;
		master->real_msi		= msi;
		master->bus			= bus;
		INIT_LIST_HEAD(&(master->entry));
		list_add(&master->entry, &msi_masters);
		return &master->msi;
	}
	return msi;
}
EXPORT_SYMBOL(vgic_its_get_msi_node);
