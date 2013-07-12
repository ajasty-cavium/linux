/*
 * Copyright (C) 2013 ARM Limited, All Rights Reserved.
 * Author: Marc Zyngier <marc.zyngier@arm.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/cpu.h>
#include <linux/kvm.h>
#include <linux/kvm_host.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>

#include <linux/irqchip/arm-gic-v3.h>

#include <asm/kvm_emulate.h>
#include <asm/kvm_arm.h>
#include <asm/kvm_mmu.h>

/* These are for GICv2 emulation only */
#define GICH_LR_VIRTUALID		(0x3ffUL << 0)
#define GICH_LR_PHYSID_CPUID_SHIFT	(10)
#define GICH_LR_PHYSID_CPUID		(7UL << GICH_LR_PHYSID_CPUID_SHIFT)

static u32 ich_vtr_el2;

static struct vgic_lr vgic_v3_get_lr(const struct kvm_vcpu *vcpu, int lr)
{
	struct vgic_lr lr_desc;
	u64 val = vcpu->arch.vgic_cpu.vgic_v3.vgic_lr[lr];

	lr_desc.irq	= val & GICH_LR_VIRTUALID;
	lr_desc.source	= (val >> GICH_LR_PHYSID_CPUID_SHIFT) & 0xff;
	lr_desc.state	= 0;

	if (val & GICH_LR_PENDING_BIT)
		lr_desc.state |= LR_STATE_PENDING;
	if (val & GICH_LR_ACTIVE_BIT)
		lr_desc.state |= LR_STATE_ACTIVE;
	if (val & GICH_LR_EOI)
		lr_desc.state |= LR_EOI_INT;

	return lr_desc;
}

#define MK_LR_PEND(src, irq)	\
	(GICH_LR_PENDING_BIT | \
	 (((u32)(src)) << GICH_LR_PHYSID_CPUID_SHIFT) | (irq))

static void vgic_v3_set_lr(struct kvm_vcpu *vcpu, int lr,
			   struct vgic_lr lr_desc)
{
	u64 lr_val = MK_LR_PEND(lr_desc.source, lr_desc.irq);

	if (lr_desc.state & LR_STATE_PENDING)
		lr_val |= GICH_LR_PENDING_BIT;
	if (lr_desc.state & LR_STATE_ACTIVE)
		lr_val |= GICH_LR_ACTIVE_BIT;
	if (lr_desc.state & LR_EOI_INT)
		lr_val |= GICH_LR_EOI;

	vcpu->arch.vgic_cpu.vgic_v3.vgic_lr[lr] = lr_val;

	/*
	 * Despite being EOIed, the LR may not have been marked as
	 * empty.
	 */
	if (!(lr_val & GICH_LR_STATE))
		vcpu->arch.vgic_cpu.vgic_v3.vgic_elrsr |= (1U << lr);
}

static u64 vgic_v3_get_elrsr(const struct kvm_vcpu *vcpu)
{
	return vcpu->arch.vgic_cpu.vgic_v3.vgic_elrsr;
}

static u64 vgic_v3_get_eisr(const struct kvm_vcpu *vcpu)
{
	return vcpu->arch.vgic_cpu.vgic_v3.vgic_eisr;
}

static u32 vgic_v3_get_interrupt_status(const struct kvm_vcpu *vcpu)
{
	u32 misr = vcpu->arch.vgic_cpu.vgic_v3.vgic_misr;
	u32 ret = 0;

	if (misr & GICH_MISR_EOI)
		ret |= INT_STATUS_EOI;
	if (misr & GICH_MISR_U)
		ret |= INT_STATUS_UNDERFLOW;

	return ret;
}

static void vgic_v3_get_vmcr(struct kvm_vcpu *vcpu, struct vgic_vmcr *vmcrp)
{
	u32 vmcr = vcpu->arch.vgic_cpu.vgic_v2.vgic_vmcr;

	vmcrp->ctlr = (vmcr & GICH_VMCR_CTLR_MASK) >> GICH_VMCR_CTLR_SHIFT;
	vmcrp->abpr = (vmcr & GICH_VMCR_BPR1_MASK) >> GICH_VMCR_BPR1_SHIFT;
	vmcrp->bpr  = (vmcr & GICH_VMCR_BPR0_MASK) >> GICH_VMCR_BPR0_SHIFT;
	vmcrp->pmr  = (vmcr & GICH_VMCR_PMR_MASK) >> GICH_VMCR_PMR_SHIFT;
}

static void vgic_v3_clear_underflow(struct kvm_vcpu *vcpu)
{
	vcpu->arch.vgic_cpu.vgic_v3.vgic_hcr &= ~GICH_HCR_UIE;
}

static void vgic_v3_set_vmcr(struct kvm_vcpu *vcpu, struct vgic_vmcr *vmcrp)
{
	u32 vmcr;

	vmcr  = (vmcrp->ctlr << GICH_VMCR_CTLR_SHIFT) & GICH_VMCR_CTLR_MASK;
	vmcr |= (vmcrp->abpr << GICH_VMCR_BPR1_SHIFT) & GICH_VMCR_BPR1_MASK;
	vmcr |= (vmcrp->bpr << GICH_VMCR_BPR0_SHIFT) & GICH_VMCR_BPR0_MASK;
	vmcr |= (vmcrp->pmr << GICH_VMCR_PMR_SHIFT) & GICH_VMCR_PMR_MASK;

	vcpu->arch.vgic_cpu.vgic_v2.vgic_vmcr = vmcr;
}

static void vgic_v3_set_underflow(struct kvm_vcpu *vcpu)
{
	vcpu->arch.vgic_cpu.vgic_v3.vgic_hcr |= GICH_HCR_UIE;
}

static void vgic_v3_enable(struct kvm_vcpu *vcpu)
{
	/*
	 * By forcing VMCR to zero, the GIC will restore the binary
	 * points to their reset values. Anything else resets to zero
	 * anyway.
	 */
	vcpu->arch.vgic_cpu.vgic_v3.vgic_vmcr = 0;

	/* Get the show on the road... */
	vcpu->arch.vgic_cpu.vgic_v3.vgic_hcr = GICH_HCR_EN;
}

static const struct vgic_ops vgic_v3_ops = {
	.get_lr			= vgic_v3_get_lr,
	.set_lr			= vgic_v3_set_lr,
	.get_elrsr		= vgic_v3_get_elrsr,
	.get_eisr		= vgic_v3_get_eisr,
	.get_interrupt_status	= vgic_v3_get_interrupt_status,
	.set_underflow		= vgic_v3_set_underflow,
	.clear_underflow	= vgic_v3_clear_underflow,
	.get_vmcr		= vgic_v3_get_vmcr,
	.set_vmcr		= vgic_v3_set_vmcr,
	.enable			= vgic_v3_enable,
};

static struct vgic_params vgic_v3_params;

int vgic_v3_probe(const struct vgic_ops **ops,
		  const struct vgic_params **params)
{
	int ret = 0;
	u32 gicv_idx;
	struct resource vcpu_res;
	struct device_node *vgic_node;
	struct vgic_params *vgic = &vgic_v3_params;

	vgic_node = of_find_compatible_node(NULL, NULL, "arm,gic-v3");
	if (!vgic_node) {
		kvm_err("error: no compatible GICv3 node in DT\n");
		return -ENODEV;
	}

	vgic->maint_irq = irq_of_parse_and_map(vgic_node, 0);
	if (!vgic->maint_irq) {
		kvm_err("error getting vgic maintenance irq from DT\n");
		ret = -ENXIO;
		goto out;
	}

	ich_vtr_el2 = kvm_call_hyp(__vgic_v3_get_ich_vtr_el2);

	/*
	 * The ListRegs field is 5 bits, but there is a architectural
	 * maximum of 16 list registers. Just ignore bit 4...
	 */
	vgic->nr_lr = (ich_vtr_el2 & 0xf) + 1;

	if (of_property_read_u32(vgic_node, "#redistributor-regions", &gicv_idx))
		gicv_idx = 1;

	gicv_idx += 3; /* Also skip GICD, GICC, GICH */
	if (of_address_to_resource(vgic_node, gicv_idx, &vcpu_res)) {
		kvm_err("Cannot obtain GICV region\n");
		ret = -ENXIO;
		goto out;
	}
	vgic->vcpu_base = vcpu_res.start;
	vgic->vctrl_base = (void *)(-1);
	vgic->type = VGIC_V3;

	kvm_info("%s@%llx IRQ%d\n", vgic_node->name,
		 vcpu_res.start, vgic->maint_irq);

	*ops = &vgic_v3_ops;
	*params = vgic;

out:
	of_node_put(vgic_node);
	return ret;
}
