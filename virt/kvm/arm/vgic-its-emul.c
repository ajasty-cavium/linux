#include <linux/acpi.h>
#include <linux/percpu.h>
#include <linux/slab.h>
#include <linux/kvm.h>
#include <linux/kvm_host.h>
#include <linux/iommu.h>
#include <linux/irqchip/arm-gic-v3.h>
#include <linux/uaccess.h>

#include <asm/cacheflush.h>
#include <asm/cputype.h>
#include <asm/exception.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_arm.h>
#include <asm/kvm_mmu.h>

#include "vgic.h"




static bool handle_mmio_misc(struct kvm_vcpu *vcpu,
			     struct kvm_exit_mmio *mmio, phys_addr_t offset)
{

	u32 reg = 0;
	u32 word_offset = offset & 3;
	struct vgic_its *its = &vcpu->kvm->arch.vgic.its;

	switch (offset & ~7) {
	case GITS_CTLR:
		if (its->enabled)
			reg = 0x1;
		vgic_reg_access(mmio, &reg, word_offset,
				ACCESS_READ_VALUE | ACCESS_WRITE_VALUE);
		if (mmio->is_write) {
			its->enabled =  !!(reg & 0x1);
			vgic_update_state(vcpu->kvm);
			return true;
		}

		break;
	case GITS_IIDR:
		reg = (PRODUCT_ID_KVM << 24) | (IMPLEMENTER_ARM << 0);
		vgic_reg_access(mmio, &reg, word_offset,
				ACCESS_READ_VALUE | ACCESS_WRITE_IGNORED);
		break;
	case GITS_TYPER:
		/* Set PTA to 0 , Target Addresses are
		 * vcpu numbers, its easy that way.
		 */

		if (its->idbits == 0) {
			its->idbits = 15;
			its->devbits = 5;
		}
		if (!word_offset) {
			/* set number of bytes per entry to (8-1) */
			reg |= (0x7 << 4);
			/* set the number of devbits to configured value */
			reg |= (its->devbits << 13);
			/* set the number of idbits to configured value */
			reg |= (its->idbits << 8);
		}
		vgic_reg_access(mmio, &reg, word_offset,
				ACCESS_READ_VALUE | ACCESS_WRITE_IGNORED);

		break;
	}

	return false;
}

static bool handle_mmio_cq_base(struct kvm_vcpu *vcpu,
				struct kvm_exit_mmio *mmio, phys_addr_t offset)
{
	u32 reg = 0;
	u32 flags = ACCESS_READ_VALUE;
	struct vgic_its *its = &vcpu->kvm->arch.vgic.its;

	/* Ignore writes if ITS is already enabled */
	if (its->enabled)
		flags |= ACCESS_WRITE_IGNORED;
	else
		flags |= ACCESS_WRITE_VALUE;

	if (!(offset & ~3)) {
		reg  = its->cq_size;
		reg |= ((u32)its->cq_shared << 10);
		reg |= ((u32)its->cq_base << 12);
	} else {
		reg |= ((u32)its->cq_cachable << 27);
		reg |= ((u32)its->cq_valid << 31);
		reg |= ((u32)0x1 << 24);
		reg |= ((u32)its->cq_base >> 20);
	}


	vgic_reg_access(mmio, &reg, offset & 3, flags);

	if (mmio->is_write) {
		if (!(offset & ~3)) {
			its->cq_size = (reg & 0xff);
			its->cq_shared = ((reg >> 10) & 0x3);
			its->cq_base |= ((reg >> 12) & 0xfffff);
		} else {
			its->cq_cachable = ((reg >> 27) & 0x7);
			its->cq_valid = ((reg >> 31) & 0x1);
			its->cq_base |= ((u64)(reg & 0xffff)) << 20;
		}
		if (its->cq_valid) {
			/* clear read offset, may be re enabling*/
			its->cq_read_offset = 0;
		}
		return true;
	}

	return false;
}

static bool handle_mmio_cq_write(struct kvm_vcpu *vcpu,
				 struct kvm_exit_mmio *mmio, phys_addr_t offset)
{
	u32 reg = 0;
	struct vgic_its *its = &vcpu->kvm->arch.vgic.its;
	int flags = ACCESS_READ_VALUE;

	if (!its->enabled)
		flags |= ACCESS_WRITE_IGNORED;
	else
		flags |= ACCESS_WRITE_VALUE;

	reg = (its->cq_write_offset << 5);

	vgic_reg_access(mmio, &reg, offset & 3, flags);

	/* do the majic if thise write is to modify write_offset */
	if (mmio->is_write && !(offset & ~3)) {
		its->cq_write_offset = reg & 0x7fffffff;
		vgic_its_handle_guest_commands(vcpu, its->cq_base,
				(its->cq_size+1)*SZ_4K, its->cq_write_offset,
				its->cq_read_offset);
		its->cq_read_offset = its->cq_write_offset;
		return false;
	}

	return false;
}

static bool handle_mmio_cq_read(struct kvm_vcpu *vcpu,
				struct kvm_exit_mmio *mmio, phys_addr_t offset)
{

	u32 reg = 0;
	struct vgic_its *its = &vcpu->kvm->arch.vgic.its;

	reg = (its->cq_read_offset << 5);

	vgic_reg_access(mmio, &reg, offset & 3,
			ACCESS_READ_VALUE | ACCESS_WRITE_IGNORED);
	return false;
}

static bool handle_mmio_pidr(struct kvm_vcpu *vcpu,
			     struct kvm_exit_mmio *mmio, phys_addr_t offset)
{
	u32 reg = 0;

	reg |= (0x3 << 4);
	vgic_reg_access(mmio, &reg, offset & 3,
			ACCESS_READ_VALUE | ACCESS_WRITE_IGNORED);
	return false;
}


const struct kvm_mmio_range vgic_its_ranges[] = {
	{
		.base            = GITS_CTLR,
		.len             = 16,
		.handle_mmio     = handle_mmio_misc,
	},
	{
		.base            = GITS_CBASER,
		.len             = 8,
		.handle_mmio     = handle_mmio_cq_base,
	},
	{
		.base            = GITS_BASER,
		.len             = 0x40,
		.handle_mmio     = handle_mmio_raz_wi,
	},
	{
		.base            = GITS_CWRITER,
		.len             = 8,
		.handle_mmio     = handle_mmio_cq_write,
	},
	{
		.base            = GITS_CREADR,
		.len             = 8,
		.handle_mmio     = handle_mmio_cq_read,
	},
	{
		.base            = GITS_PIDR2,
		.len             = 4,
		.handle_mmio     = handle_mmio_pidr,
	},
	{},

};

/**
 *its_lpi_create : creates its lpi emulation device
 **/

int its_lpi_create(void)
{
	return 0;
}

int vgic_its_has_attr(struct kvm_device *dev,
		      struct kvm_device_attr *attr)
{
	return -ENXIO;
}

int vgic_its_set_attr(struct kvm_device *dev,
		      struct kvm_device_attr *attr)
{
	return -ENXIO;
}

int vgic_its_get_attr(struct kvm_device *dev,
		      struct kvm_device_attr *attr)
{
	return -ENXIO;
}
