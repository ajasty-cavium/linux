#include <linux/acpi.h>
#include <linux/percpu.h>
#include <linux/slab.h>
#include <linux/kvm.h>
#include <linux/kvm_host.h>
#include <linux/iommu.h>
#include <linux/irq.h>
#include <linux/interrupt.h>
#include <linux/irqchip/arm-gic-v3.h>

#include <asm/cacheflush.h>
#include <asm/cputype.h>
#include <asm/exception.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_arm.h>
#include <asm/kvm_mmu.h>

#include "vgic.h"



static DEFINE_SPINLOCK(vits_lock);


static irqreturn_t vgic_its_handle_interrupt(int irq, void *dev)
{
	struct vgic_its_device *vits_dev = dev;
	struct vgic_its_irq *vits_irq;
	unsigned long flag;
	struct vgic_its_device *its_dev;
	struct vgic_its *its;

	spin_lock_irqsave(&vits_lock, flag);

	list_for_each_entry(vits_irq, &(vits_dev->pirq_list), entry) {
		if (vits_irq->pirq == irq)
			break;
	}
	if (!vits_irq) {
		spin_unlock_irqrestore(&vits_lock, flag);
		return IRQ_NONE;
	}

	/* TODO :find vcpu number from col_id */
	kvm_vgic_inject_irq(vits_dev->kvm, vits_irq->vcol_id,
			vits_irq->virq, 1);
	spin_unlock_irqrestore(&vits_lock, flag);
	return IRQ_HANDLED;
}

static struct its_node *get_its_node(struct pci_dev *pdev)
{
	return container_of(pdev->bus->msi, struct its_node, msi_chip);

}

static int get_physical_dev_id(struct vgic_its *its, int vdev_id)
{
	struct vgic_its_device *its_dev =  NULL;
	unsigned long flag;

	list_for_each_entry(its_dev, &(its->its_devices), entry) {
		if (its_dev->vdev_id == vdev_id)
			return its_dev->pdev_id;
	}

	return -1;
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

static inline bool is_offset_legal(u64 base, int size, int offset)
{
	return ((base + offset) < (base + size)) ? true : false;
}

static void convert_mapc(struct kvm_vcpu *vcpu, struct its_cmd_block *cmd)
{
	u16 collection = (u16)(cmd->raw_cmd[2] & 0xffff);
	u8 valid = (u8)(cmd->raw_cmd[2] >> 63);
	u32 target_vcpu = (u32)((cmd->raw_cmd[2] >> 16) & 0xffffffff);
	struct vgic_its_cpu *its_cpu = &vcpu->arch.vgic_cpu.its_cpu;

	if (valid)
		its_cpu->vcollection = collection;
	else
		its_cpu->vcollection = -1;
	/**
	 * do i need to send a MAPC down?, I don't think that is needed.
	 **/
}

static void convert_mapd(struct kvm_vcpu *vcpu, struct its_cmd_block *cmd)
{
	u8 valid = (u8) (cmd->raw_cmd[2] >> 63);
	u32 vdev_id = (u32) (cmd->raw_cmd[0] >> 32);
	phys_addr_t itt_address = (phys_addr_t) cmd->raw_cmd[2];
	u8 size  = (u8) (cmd->raw_cmd[1] & 0x1f);
	struct vgic_its *its = &vcpu->kvm->arch.vgic.its;
	struct vgic_its_device *vits_dev = get_vgic_its_dev(its, vdev_id);
	u32 pdev_id = vits_dev->pdev_id;

	size = 1UL <<  (size + 1);
	if (valid) {
		vits_dev->pits_dev = its_create_device(
						get_its_node(vits_dev->pdev),
							pdev_id, size);
	} else if (vits_dev->pits_dev) {
		its_free_device(vits_dev->pits_dev);
		vits_dev->pits_dev = NULL;
	}
}

static void convert_mapi(struct kvm_vcpu *vcpu, struct its_cmd_block *cmd)
{
	u32 vdev_id = (u32) (cmd->raw_cmd[0] >> 32);
	u32 ID = (u32) cmd->raw_cmd[1];
	u16 collection = (u16) cmd->raw_cmd[2];
	struct vgic_its *its = &vcpu->kvm->arch.vgic.its;
	u32 pdev_id = get_physical_dev_id(its, vdev_id);
}

static void convert_mapvi(struct kvm_vcpu *vcpu, struct its_cmd_block *cmd)
{
	u32 vdev_id = (u32) (cmd->raw_cmd[0] >> 32);
	u32 virq = (u32) (cmd->raw_cmd[1] >> 32);
	u32 ID = (u32) cmd->raw_cmd[1];
	u16 collection = (u16) cmd->raw_cmd[2];
	struct vgic_its *its = &vcpu->kvm->arch.vgic.its;
	struct vgic_its_device *vits_dev = get_vgic_its_dev(its, vdev_id);
	u32 pdev_id = vits_dev->pdev_id;
	u32 pirq = 0, hwirq;
	struct vgic_its_irq *vits_irq;
	struct vgic_its_cpu *its_cpu = &vcpu->arch.vgic_cpu.its_cpu;
	int ret;

	if (!vits_dev->pits_dev)
		return;

	vits_irq = kzalloc(sizeof(struct vgic_its_irq), GFP_KERNEL);
	if (!vits_irq)
		return;

	ret = its_alloc_device_irq(vits_dev->pits_dev, ID, &hwirq, &pirq);
	if (ret)
		return;
	irq_set_handler_data(pirq, vits_dev->pits_dev);
	vits_irq->pirq = pirq;
	vits_irq->virq = virq;
	vits_irq->hwirq = hwirq;
	vits_irq->vcol_id = collection;
	vits_irq->pcol_id = its_cpu->pcollection;
	vits_irq->ID = ID;
	ret = request_irq(pirq, vgic_its_handle_interrupt, IRQF_PERCPU,
			  "vits-mapvi-int", vits_dev);


	if (IS_ERR_VALUE(ret))
		return;
	list_add(&(vits_irq->entry), &(vits_dev->pirq_list));
}

static void convert_movi(struct kvm_vcpu *vcpu, struct its_cmd_block *cmd)
{
	u32 vdev_id = (u32) (cmd->raw_cmd[0] >> 32);
	u32 ID = (u32) cmd->raw_cmd[1];
	u16 collection = (u16) cmd->raw_cmd[2];
	struct vgic_its *its = &vcpu->kvm->arch.vgic.its;
	u32 pdev_id = get_physical_dev_id(its, vdev_id);
}

static void convert_discard(struct kvm_vcpu *vcpu, struct its_cmd_block *cmd)
{
	u32 vdev_id = (u32) (cmd->raw_cmd[0] >> 32);
	u32 ID = (u32) cmd->raw_cmd[1];
	struct vgic_its *its = &vcpu->kvm->arch.vgic.its;
	u32 pdev_id = get_physical_dev_id(its, vdev_id);
	struct vgic_its_irq *vits_irq;
	struct vgic_its_device *vits_dev = get_vgic_its_dev(its, vdev_id);

	list_for_each_entry(vits_irq, &(vits_dev->pirq_list), entry) {
		if (vits_irq->ID == ID)
			break;
	}

	if (vits_irq) {
		its_send_discard(vits_dev->pits_dev, vits_irq->ID);
		list_del(&(vits_irq->entry));
		free_irq(vits_irq->pirq, vits_dev);
		kfree(vits_irq);
	}
}

static void convert_inv(struct kvm_vcpu *vcpu, struct its_cmd_block *cmd)
{
	u32 vdev_id = (u32) (cmd->raw_cmd[0] >> 32);
	u32 ID = (u32) cmd->raw_cmd[1];
	struct vgic_its *its = &vcpu->kvm->arch.vgic.its;
	u32 pdev_id = get_physical_dev_id(its, vdev_id);
}

static void convert_movall(struct kvm_vcpu *vcpu, struct its_cmd_block *cmd)
{
	u32 old_vcpu = (u32) (cmd->raw_cmd[2] >> 16);
	u32 new_vcpu = (u32) (cmd->raw_cmd[3] >> 16);
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
	spin_unlock_irqrestore(&vits_lock, flag);
	kfree(user_cq);
	return 0;
}

u64 vgic_its_get_phys_base(struct kvm_device *dev, u32 vdev_id)
{
	struct vgic_its *its = &dev->kvm->arch.vgic.its;
	struct vgic_its_device *vits_dev = get_vgic_its_dev(its, vdev_id);

	if (!vits_dev)
		return 0;

	return get_its_node(vits_dev->pdev)->phys_base;
}

int vgic_its_create_device(struct  kvm *kvm, u32 vdev_id, u32 pdev_id)
{
	int domain = (pdev_id >> 16) & 0x3;
	int bus = (pdev_id >> 8) & 0xff;
	int func = pdev_id & 0xff;
	struct pci_dev *pdev;
	struct vgic_its_device *its_dev;
	struct vgic_its *its = &kvm->arch.vgic.its;
	unsigned long flag;

	pdev = pci_get_domain_bus_and_slot(domain, bus, func);
	if (!pdev)
		return -ENXIO;

	its_dev = kzalloc(sizeof(struct vgic_its_device), GFP_KERNEL);
	if (!its_dev)
		return -ENOMEM;


	INIT_LIST_HEAD(&(its_dev->pirq_list));
	INIT_LIST_HEAD(&(its_dev->entry));
	its_dev->vdev_id = vdev_id;
	its_dev->pdev_id = pdev_id;
	its_dev->pdev = pdev;
	its_dev->kvm = kvm;
	list_add(&(its_dev->entry), &(its->its_devices));
	return 0;
}


int vgic_its_cpu_init(struct kvm_vcpu *vcpu)
{
	struct vgic_its_cpu *its_cpu = &vcpu->arch.vgic_cpu.its_cpu;
	struct its_node *its;
	int cpu = get_cpu();

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
	unsigned long flag;

	if (kvm->arch.vgic.vgic_its_base == VGIC_ADDR_UNDEF)
		return;

	spin_lock_irqsave(&vits_lock, flag);
	vits_dev = list_first_entry_or_null(&(its->its_devices),
					struct vgic_its_device, entry);

	while (vits_dev) {
		while (vits_irq) {
			/* Stop the delivery of interrupts */
			if (vits_dev->pits_dev)
				its_send_discard(vits_dev->pits_dev,
						 vits_irq->ID);
			free_irq(vits_irq->pirq, vits_dev);
			list_del(&vits_irq->entry);
			kfree(vits_irq);
			vits_irq = list_first_entry_or_null(
						&(vits_dev->pirq_list),
						struct vgic_its_irq, entry);
		}
		if (vits_dev->pits_dev)
			its_free_device(vits_dev->pits_dev);
		list_del(&vits_dev->entry);
		kfree(vits_dev);
		vits_dev = list_first_entry_or_null(&(its->its_devices),
						struct vgic_its_device, entry);
	}
	spin_unlock_irqrestore(&vits_lock, flag);
}
