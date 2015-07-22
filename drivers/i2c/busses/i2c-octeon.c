/*
 * (C) Copyright 2009-2010
 * Nokia Siemens Networks, michael.lawnick.ext@nsn.com
 *
 * Portions Copyright (C) 2010 - 2015 Cavium, Inc.
 *
 * This is a driver for the i2c adapter in Cavium Networks' OCTEON processors.
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#include <linux/platform_device.h>
#include <linux/interrupt.h>
#include <linux/atomic.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of_i2c.h>
#include <linux/delay.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/i2c.h>
#include <linux/io.h>
#include <linux/of.h>
#include <linux/gpio.h>
#include <linux/i2c-smbus.h>

#ifdef CONFIG_ARCH_THUNDER
#include <linux/pci.h>
#else
#include <asm/octeon/octeon.h>
#endif

#define DRV_NAME "i2c-octeon"

/* The previous out-of-tree version was implicitly version 1.0. */
#define DRV_VERSION	"2.5"

/* register offsets */
#ifdef CONFIG_ARCH_THUNDER
#define SW_TWSI			0x1000
#define TWSI_INT		0x1010
#define SW_TWSI_EXT		0x1018
#define TWSI_INT_ENA_W1C	0x1028
#define TWSI_INT_ENA_W1S	0x1030
#else
#define SW_TWSI		0x00
#define TWSI_INT	0x10
#define SW_TWSI_EXT	0x18
#endif

/* Int ena value */
#define INT_ENA_ST	0x1
#define INT_ENA_TS	0x2
#define INT_ENA_CORE	0x4

/* Controller command patterns */
#define SW_TWSI_V               0x8000000000000000ull
#define SW_TWSI_EIA		(1ull << 61)
#define SW_TWSI_R		(1ull << 56)
#define SW_TWSI_SOVR		(1ull << 55)
#define SW_TWSI_OP_7		(0ull << 57)
#define SW_TWSI_OP_7_IA		(1ull << 57)
#define SW_TWSI_OP_10		(2ull << 57)
#define SW_TWSI_OP_10_IA	(3ull << 57)
#define SW_TWSI_SIZE_SHIFT	52
#define SW_TWSI_A_SHIFT		40
#define SW_TWSI_IA_SHIFT	32
#define SW_TWSI_EOP_TWSI_DATA   0x0C00000100000000ull
#define SW_TWSI_EOP_TWSI_CTL    0x0C00000200000000ull
#define SW_TWSI_EOP_TWSI_CLKCTL 0x0C00000300000000ull
#define SW_TWSI_EOP_TWSI_STAT   0x0C00000300000000ull
#define SW_TWSI_EOP_TWSI_RST    0x0C00000700000000ull
#define SW_TWSI_OP_TWSI_CLK     0x0800000000000000ull

/* Controller command and status bits */
#define TWSI_CTL_CE   0x80
#define TWSI_CTL_ENAB 0x40
#define TWSI_CTL_STA  0x20
#define TWSI_CTL_STP  0x10
#define TWSI_CTL_IFLG 0x08
#define TWSI_CTL_AAK  0x04

/* Some status values */
#define STAT_START      0x08
#define STAT_RSTART     0x10
#define STAT_TXADDR_ACK 0x18
#define STAT_TXDATA_ACK 0x28
#define STAT_RXADDR_ACK 0x40
#define STAT_RXDATA_ACK 0x50
#define STAT_IDLE       0xF8

/* PCI */

#define PCI_CFG_REG_BAR_NUM	0
#define PCI_DEVICE_ID_THUNDER_TWSI 0xa012

/* Thunder RST */
#define TWSI_DFL_RATE		100000
#define REF_CLOCK_RATE          50000000ul
#define RST_BASE                0x87e006000000ull
#define RST_SIZE                0x2000
#define RST_BOOT                0x1600
#define RST_PNR_MUL_MASK        0x007e00000000ull
#define RST_PNR_MUL_SHIFT       33


struct octeon_i2c {
	wait_queue_head_t queue;
	struct i2c_adapter adap;
	int irq;
	int hlc_irq;		/* For cn7890 only */
	u32 twsi_freq;
	int sys_freq;
	void __iomem *twsi_base;
	struct device *dev;
	int broken_irq_mode;
	bool octeon_i2c_hlc_enabled;
	int cvmx_channel;
	void (*int_en)(struct octeon_i2c *);
	void (*int_dis)(struct octeon_i2c *);
	void (*hlc_int_en)(struct octeon_i2c *);
	void (*hlc_int_dis)(struct octeon_i2c *);
	atomic_t int_en_cnt;
	atomic_t hlc_int_en_cnt;
#ifdef CONFIG_ARCH_THUNDER
	struct	msix_entry i2c_msix;
#endif
	struct i2c_smbus_alert_setup alert_data;
	struct i2c_client *ara;
};

/**
 * octeon_i2c_write_sw - write an I2C core register.
 * @i2c: The struct octeon_i2c.
 * @eop_reg: Register selector.
 * @data: Value to be written.
 *
 * The I2C core registers are accessed indirectly via the SW_TWSI CSR.
 */
static void octeon_i2c_write_sw(struct octeon_i2c *i2c,
				u64 eop_reg,
				u8 data)
{
	u64 tmp;

	__raw_writeq(SW_TWSI_V | eop_reg | data, i2c->twsi_base + SW_TWSI);
	do {
		tmp = __raw_readq(i2c->twsi_base + SW_TWSI);
	} while ((tmp & SW_TWSI_V) != 0);
}

/**
 * octeon_i2c_read_sw - write an I2C core register.
 * @i2c: The struct octeon_i2c.
 * @eop_reg: Register selector.
 *
 * Returns the data.
 *
 * The I2C core registers are accessed indirectly via the SW_TWSI CSR.
 */
static u8 octeon_i2c_read_sw(struct octeon_i2c *i2c, u64 eop_reg)
{
	u64 tmp;

	__raw_writeq(SW_TWSI_V | eop_reg | SW_TWSI_R, i2c->twsi_base + SW_TWSI);
	do {
		tmp = __raw_readq(i2c->twsi_base + SW_TWSI);
	} while ((tmp & SW_TWSI_V) != 0);

	return tmp & 0xFF;
}

/**
 * octeon_i2c_write_int - write the TWSI_INT register
 * @i2c: The struct octeon_i2c.
 * @data: Value to be written.
 */
static void octeon_i2c_write_int(struct octeon_i2c *i2c, u64 data)
{
	__raw_writeq(data, i2c->twsi_base + TWSI_INT);
	__raw_readq(i2c->twsi_base + TWSI_INT);
}

#ifdef CONFIG_ARCH_THUNDER
/**
 * thunder_i2c_int_enable - enable the CORE interrupt.
 * @i2c: The struct octeon_i2c.
 *
 * The interrupt will be asserted when there is non-STAT_IDLE state in
 * the SW_TWSI_EOP_TWSI_STAT register.
 */
static void thunder_i2c_int_enable(struct octeon_i2c *i2c)
{
	__raw_writeq(INT_ENA_CORE, i2c->twsi_base + TWSI_INT_ENA_W1S);
	__raw_readq(i2c->twsi_base + TWSI_INT_ENA_W1S);
}

/**
 * thunder_i2c_int_disable - disable the CORE interrupt.
 * @i2c: The struct octeon_i2c.
 */
static void thunder_i2c_int_disable(struct octeon_i2c *i2c)
{
	__raw_writeq(INT_ENA_CORE, i2c->twsi_base + TWSI_INT_ENA_W1C);
	__raw_readq(i2c->twsi_base + TWSI_INT_ENA_W1C);
}

#else	/* !CONFIG_ARCH_THUNDER */

/**
 * octeon_i2c_int_enable - enable the CORE interrupt.
 * @i2c: The struct octeon_i2c.
 *
 * The interrupt will be asserted when there is non-STAT_IDLE state in
 * the SW_TWSI_EOP_TWSI_STAT register.
 */
static void octeon_i2c_int_enable(struct octeon_i2c *i2c)
{
	octeon_i2c_write_int(i2c, 0x40);
}

/**
 * octeon_i2c_int_disable - disable the CORE interrupt.
 * @i2c: The struct octeon_i2c.
 */
static void octeon_i2c_int_disable(struct octeon_i2c *i2c)
{
	octeon_i2c_write_int(i2c, 0);
}

/**
 * octeon_i2c_int_enable78 - enable the CORE interrupt.
 * @i2c: The struct octeon_i2c.
 *
 * The interrupt will be asserted when there is non-STAT_IDLE state in
 * the SW_TWSI_EOP_TWSI_STAT register.
 */
static void octeon_i2c_int_enable78(struct octeon_i2c *i2c)
{
	atomic_inc_return(&i2c->int_en_cnt);
	enable_irq(i2c->irq);
}

/**
 * octeon_i2c_int_disable78 - disable the CORE interrupt.
 * @i2c: The struct octeon_i2c.
 */
static void octeon_i2c_int_disable78(struct octeon_i2c *i2c)
{
	/*
	 * The interrupt can be disabled in two places, but we only
	 * want to make the disable_irq_nosync() call once, so keep
	 * track with the atomic variable.
	 */
	int c = atomic_dec_if_positive(&i2c->int_en_cnt);
	if (c >= 0)
		disable_irq_nosync(i2c->irq);
}

/**
 * octeon_i2c_hlc_int_enable78 - enable the ST interrupt.
 * @i2c: The struct octeon_i2c.
 *
 * The interrupt will be asserted when there is non-STAT_IDLE state in
 * the SW_TWSI_EOP_TWSI_STAT register.
 */
static void octeon_i2c_hlc_int_enable78(struct octeon_i2c *i2c)
{
	atomic_inc_return(&i2c->hlc_int_en_cnt);
	enable_irq(i2c->hlc_irq);
}

/**
 * octeon_i2c_hlc_int_disable78 - disable the ST interrupt.
 * @i2c: The struct octeon_i2c.
 */
static void octeon_i2c_hlc_int_disable78(struct octeon_i2c *i2c)
{
	/*
	 * The interrupt can be disabled in two places, but we only
	 * want to make the disable_irq_nosync() call once, so keep
	 * track with the atomic variable.
	 */
	int c = atomic_dec_if_positive(&i2c->hlc_int_en_cnt);
	if (c >= 0)
		disable_irq_nosync(i2c->hlc_irq);
}
#endif

/**
 * octeon_i2c_unblock - unblock the bus.
 * @i2c: The struct octeon_i2c.
 *
 * If there was a reset while a device was driving 0 to bus,
 * bus is blocked. We toggle it free manually by some clock
 * cycles and send a stop.
 */
static void octeon_i2c_unblock(struct octeon_i2c *i2c)
{
	int i;

	dev_dbg(i2c->dev, "%s\n", __func__);
	for (i = 0; i < 9; i++) {
		octeon_i2c_write_int(i2c, 0x0);
		udelay(5);
		octeon_i2c_write_int(i2c, 0x200);
		udelay(5);
	}
	octeon_i2c_write_int(i2c, 0x300);
	udelay(5);
	octeon_i2c_write_int(i2c, 0x100);
	udelay(5);
	octeon_i2c_write_int(i2c, 0x0);
}

/**
 * octeon_i2c_isr - the interrupt service routine.
 * @int: The irq, unused.
 * @dev_id: Our struct octeon_i2c.
 */
static irqreturn_t octeon_i2c_isr(int irq, void *dev_id)
{
	struct octeon_i2c *i2c = dev_id;

	i2c->int_dis(i2c);
	wake_up(&i2c->queue);

	return IRQ_HANDLED;
}

#ifndef CONFIG_ARCH_THUNDER
/**
 * octeon_hlc_i2c_isr78 - the interrupt service routine.
 * @int: The irq, unused.
 * @dev_id: Our struct octeon_i2c.
 */
static irqreturn_t octeon_i2c_hlc_isr78(int irq, void *dev_id)
{
	struct octeon_i2c *i2c = dev_id;

	i2c->hlc_int_dis(i2c);
	wake_up(&i2c->queue);

	return IRQ_HANDLED;
}
#endif

static int octeon_i2c_test_iflg(struct octeon_i2c *i2c)
{
	return (octeon_i2c_read_sw(i2c, SW_TWSI_EOP_TWSI_CTL) & TWSI_CTL_IFLG) != 0;
}

/**
 * octeon_i2c_wait - wait for the IFLG to be set.
 * @i2c: The struct octeon_i2c.
 *
 * Returns 0 on success, otherwise a negative errno.
 */
static int octeon_i2c_wait(struct octeon_i2c *i2c)
{
	int result;

	if (i2c->broken_irq_mode) {
		/*
		 * Some chip revisions seem to not assert the irq in
		 * the interrupt controller.  So we must poll for the
		 * IFLG change.
		 */
		u64 end = get_jiffies_64() + i2c->adap.timeout;

		while (!octeon_i2c_test_iflg(i2c) && get_jiffies_64() <= end)
			udelay(50);

		return octeon_i2c_test_iflg(i2c) ? 0 : -ETIMEDOUT;
	}

	i2c->int_en(i2c);

	result = wait_event_timeout(i2c->queue,
					octeon_i2c_test_iflg(i2c),
					i2c->adap.timeout);

	i2c->int_dis(i2c);


	if (result <= 0 && octeon_i2c_test_iflg(i2c)) {
		dev_err(i2c->dev, "broken irq connection detected, switching to polling mode.\n");
		i2c->broken_irq_mode = 1;
		return 0;
	}

	if (result < 0) {
		dev_dbg(i2c->dev, "%s: wait interrupted\n", __func__);
		return result;
	} else if (result == 0) {
		dev_dbg(i2c->dev, "%s: timeout\n", __func__);
		return -ETIMEDOUT;
	}

	return 0;
}

static int octeon_i2c_enable_hlc(struct octeon_i2c *i2c)
{
	if (i2c->octeon_i2c_hlc_enabled)
		return 0;

	octeon_i2c_write_sw(i2c, SW_TWSI_EOP_TWSI_CTL,
			    TWSI_CTL_CE | TWSI_CTL_ENAB);

	i2c->octeon_i2c_hlc_enabled = true;
	return 0;
}

static bool octeon_i2c_lost_arb(u64 code)
{
	switch (code & 0xffull) {
	/* Arbitration lost in address or data byte */
	case 0x38:
	/*
	 * Arbitration lost in address as master, slave address +
	 * write bit received, ACK transmitted.
	 */
	case 0x68:
	/*
	 * Arbitration lost in address as master, general call address
	 * received, ACK transmitted.
	 */
	case 0x78:
	/*
	 * Arbitration lost in address as master, slave address + read
	 * bit received, ACK transmitted.
	 */
	case 0xb0:
		return true;
	default:
		return false;
	}
}

/**
 * octeon_i2c_start - send START to the bus.
 * @i2c: The struct octeon_i2c.
 *
 * Returns 0 on success, otherwise a negative errno.
 */
static int octeon_i2c_start(struct octeon_i2c *i2c)
{
	u8 data;
	int result;

	i2c->octeon_i2c_hlc_enabled = false;

	octeon_i2c_write_sw(i2c, SW_TWSI_EOP_TWSI_CTL,
				TWSI_CTL_ENAB | TWSI_CTL_STA);

	result = octeon_i2c_wait(i2c);
	if (result) {
		if (octeon_i2c_read_sw(i2c, SW_TWSI_EOP_TWSI_STAT) == STAT_IDLE) {
			/*
			 * Controller refused to send start flag May
			 * be a client is holding SDA low - let's try
			 * to free it.
			 */
			octeon_i2c_unblock(i2c);
			octeon_i2c_write_sw(i2c, SW_TWSI_EOP_TWSI_CTL,
					    TWSI_CTL_ENAB | TWSI_CTL_STA);

			result = octeon_i2c_wait(i2c);
		}
		if (result)
			return result;
	}

	data = octeon_i2c_read_sw(i2c, SW_TWSI_EOP_TWSI_STAT);
	if ((data != STAT_START) && (data != STAT_RSTART)) {
		dev_err(i2c->dev, "%s: bad status (0x%x)\n", __func__, data);
		return -EIO;
	}

	return 0;
}

/**
 * octeon_i2c_stop - send STOP to the bus.
 * @i2c: The struct octeon_i2c.
 *
 * Returns 0 on success, otherwise a negative errno.
 */
static int octeon_i2c_stop(struct octeon_i2c *i2c)
{
	u8 data;

	octeon_i2c_write_sw(i2c, SW_TWSI_EOP_TWSI_CTL,
			    TWSI_CTL_ENAB | TWSI_CTL_STP);

	data = octeon_i2c_read_sw(i2c, SW_TWSI_EOP_TWSI_STAT);

	if (data != STAT_IDLE) {
		dev_err(i2c->dev, "%s: bad status(0x%x)\n", __func__, data);
		return -EIO;
	}
	return 0;
}

/**
 * octeon_i2c_write - send data to the bus.
 * @i2c: The struct octeon_i2c.
 * @target: Target address.
 * @data: Pointer to the data to be sent.
 * @length: Length of the data.
 * @phase: which phase of a combined operation.
 *
 * The address is sent over the bus, then the data.
 *
 * Returns 0 on success, otherwise a negative errno.
 */
static int octeon_i2c_write(struct octeon_i2c *i2c, int target,
			    const u8 *data, int length, int phase)
{
	int i, result;
	u8 tmp;

restart:
	result = octeon_i2c_start(i2c);
	if (result)
		return result;

	octeon_i2c_write_sw(i2c, SW_TWSI_EOP_TWSI_DATA, target << 1);
	octeon_i2c_write_sw(i2c, SW_TWSI_EOP_TWSI_CTL, TWSI_CTL_ENAB);

	result = octeon_i2c_wait(i2c);
	if (result)
		return result;

	for (i = 0; i < length; i++) {
		tmp = octeon_i2c_read_sw(i2c, SW_TWSI_EOP_TWSI_STAT);
		if (phase == 0 && octeon_i2c_lost_arb(tmp))
			goto restart;

		if ((tmp != STAT_TXADDR_ACK) && (tmp != STAT_TXDATA_ACK)) {
			dev_err(i2c->dev,
				"%s: bad status before write (0x%x)\n",
				__func__, tmp);
			return -EIO;
		}

		octeon_i2c_write_sw(i2c, SW_TWSI_EOP_TWSI_DATA, data[i]);
		octeon_i2c_write_sw(i2c, SW_TWSI_EOP_TWSI_CTL, TWSI_CTL_ENAB);

		result = octeon_i2c_wait(i2c);
		if (result)
			return result;
	}

	return 0;
}

/**
 * octeon_i2c_read - receive data from the bus.
 * @i2c: The struct octeon_i2c.
 * @target: Target address.
 * @data: Pointer to the location to store the datae .
 * @length: Length of the data.
 * @phase: which phase of a combined operation.
 *
 * The address is sent over the bus, then the data is read.
 *
 * Returns 0 on success, otherwise a negative errno.
 */
static int octeon_i2c_read(struct octeon_i2c *i2c, int target,
			   u8 *data, __u16 *rlength, int phase, bool recv_len)
{
	int i, result;
	u8 tmp;
	int length = *rlength;

	if (length < 1)
		return -EINVAL;

restart:
	result = octeon_i2c_start(i2c);
	if (result)
		return result;

	octeon_i2c_write_sw(i2c, SW_TWSI_EOP_TWSI_DATA, (target<<1) | 1);
	octeon_i2c_write_sw(i2c, SW_TWSI_EOP_TWSI_CTL, TWSI_CTL_ENAB);

	result = octeon_i2c_wait(i2c);
	if (result)
		return result;

	for (i = 0; i < length; i++) {
		tmp = octeon_i2c_read_sw(i2c, SW_TWSI_EOP_TWSI_STAT);
		if (phase == 0 && octeon_i2c_lost_arb(tmp))
			goto restart;

		if ((tmp != STAT_RXDATA_ACK) && (tmp != STAT_RXADDR_ACK)) {
#if 0	/* TODO: maybe not print msg for every NACK? */
			dev_err(i2c->dev,
				"%s: bad status before read (0x%x)\n",
				__func__, tmp);
#endif
			return -EIO;
		}

		if ((i+1 < length) || (recv_len && i == 0))
			octeon_i2c_write_sw(i2c, SW_TWSI_EOP_TWSI_CTL,
						TWSI_CTL_ENAB | TWSI_CTL_AAK);
		else
			octeon_i2c_write_sw(i2c, SW_TWSI_EOP_TWSI_CTL,
						TWSI_CTL_ENAB);

		result = octeon_i2c_wait(i2c);
		if (result)
			return result;

		data[i] = octeon_i2c_read_sw(i2c, SW_TWSI_EOP_TWSI_DATA);
		if (recv_len && i == 0) {
			if (data[i] > I2C_SMBUS_BLOCK_MAX + 1) {
				dev_err(i2c->dev,
					"%s: read len > I2C_SMBUS_BLOCK_MAX %d\n",
					__func__, data[i]);
				return -EIO;
			} else {
				length += data[i];
			}
		}
	}
	*rlength = length;
	return 0;
}

static bool octeon_i2c_hlc_test_ready(struct octeon_i2c *i2c)
{
	u64 v = __raw_readq(i2c->twsi_base + SW_TWSI);
	return (v & SW_TWSI_V) == 0;
}

#ifdef CONFIG_ARCH_THUNDER
static void thunder_i2c_hlc_int_enable(struct octeon_i2c *i2c)
{
	__raw_writeq(INT_ENA_ST | INT_ENA_TS, i2c->twsi_base + TWSI_INT_ENA_W1S);
	__raw_readq(i2c->twsi_base + TWSI_INT_ENA_W1S);
}

static void thunder_i2c_hlc_int_disable(struct octeon_i2c *i2c)
{
	__raw_writeq(INT_ENA_ST | INT_ENA_TS, i2c->twsi_base + TWSI_INT_ENA_W1C);
	__raw_readq(i2c->twsi_base + TWSI_INT_ENA_W1C);
}

#else

static void octeon_i2c_hlc_int_enable(struct octeon_i2c *i2c)
{
	octeon_i2c_write_int(i2c, 0x10);
}
#endif

static void octeon_i2c_hlc_int_clear(struct octeon_i2c *i2c)
{
	octeon_i2c_write_int(i2c, 0x3);
}

/**
 * octeon_i2c_hlc_wait - wait for an HLC operation to complete.
 * @i2c: The struct octeon_i2c.
 *
 * Returns 0 on success, otherwise a negative errno.
 */
static int octeon_i2c_hlc_wait(struct octeon_i2c *i2c)
{
	int result;

	if (i2c->broken_irq_mode) {
		/*
		 * Some chip revisions seem to not assert the irq in
		 * the interrupt controller.  So we must poll for the
		 * IFLG change.
		 */
		u64 end = get_jiffies_64() + i2c->adap.timeout;

		while (!octeon_i2c_hlc_test_ready(i2c) && get_jiffies_64() <= end)
			udelay(50);

		return octeon_i2c_hlc_test_ready(i2c) ? 0 : -ETIMEDOUT;
	}

	i2c->hlc_int_en(i2c);

	result = wait_event_interruptible_timeout(i2c->queue,
						  octeon_i2c_hlc_test_ready(i2c),
						  i2c->adap.timeout);
	i2c->hlc_int_dis(i2c);
	octeon_i2c_hlc_int_clear(i2c);


	if (result <= 0 && octeon_i2c_hlc_test_ready(i2c)) {
		dev_err(i2c->dev, "broken irq connection detected, switching to polling mode.\n");
		i2c->broken_irq_mode = 1;
		return 0;
	}

	if (result < 0) {
		dev_dbg(i2c->dev, "%s: wait interrupted\n", __func__);
		return result;
	} else if (result == 0) {
		dev_dbg(i2c->dev, "%s: timeout\n", __func__);
		return -ETIMEDOUT;
	}

	return 0;
}

static int octeon_i2c_simple_read(struct octeon_i2c *i2c, struct i2c_msg *msgs)
{
	u64 cmd;
	int i, j;
	int ret = 0;

	octeon_i2c_enable_hlc(i2c);
retry:
	cmd = SW_TWSI_V | SW_TWSI_R | SW_TWSI_SOVR;
	/* SIZE */
	cmd |= (u64)(msgs[0].len - 1) << SW_TWSI_SIZE_SHIFT;
	/* A */
	cmd |= (u64)(msgs[0].addr & 0x7full) << SW_TWSI_A_SHIFT;

	if (msgs[0].flags & I2C_M_TEN)
		cmd |= SW_TWSI_OP_10;
	else
		cmd |= SW_TWSI_OP_7;

	octeon_i2c_hlc_int_clear(i2c);
	__raw_writeq(cmd, i2c->twsi_base + SW_TWSI);

	ret = octeon_i2c_hlc_wait(i2c);

	if (ret)
		goto err;

	cmd = __raw_readq(i2c->twsi_base + SW_TWSI);

	if ((cmd & SW_TWSI_R) == 0) {
		if (octeon_i2c_lost_arb(cmd))
			goto retry;
		ret = -EIO;
		goto err;
	}

	for (i = 0, j = msgs[0].len - 1; i  < msgs[0].len && i < 4; i++, j--)
		msgs[0].buf[j] = (cmd >> (8 * i)) & 0xff;

	if (msgs[0].len >= 4) {
		cmd = __raw_readq(i2c->twsi_base + SW_TWSI_EXT);
		for (i = 0; i  < msgs[0].len - 4 && i < 4; i++, j--)
			msgs[0].buf[j] = (cmd >> (8 * i)) & 0xff;
	}

err:
	return ret;
}

static int octeon_i2c_simple_write(struct octeon_i2c *i2c, struct i2c_msg *msgs)
{
	u64 cmd;
	int i, j;
	int ret = 0;

	octeon_i2c_enable_hlc(i2c);

retry:
	cmd = SW_TWSI_V | SW_TWSI_SOVR;
	/* SIZE */
	cmd |= (u64)(msgs[0].len - 1) << SW_TWSI_SIZE_SHIFT;
	/* A */
	cmd |= (u64)(msgs[0].addr & 0x7full) << SW_TWSI_A_SHIFT;

	if (msgs[0].flags & I2C_M_TEN)
		cmd |= SW_TWSI_OP_10;
	else
		cmd |= SW_TWSI_OP_7;

	for (i = 0, j = msgs[0].len - 1; i  < msgs[0].len && i < 4; i++, j--)
		cmd |= (u64)msgs[0].buf[j] << (8 * i);

	if (msgs[0].len >= 4) {
		u64 ext = 0;
		for (i = 0; i < msgs[0].len - 4 && i < 4; i++, j--)
			ext |= (u64)msgs[0].buf[j] << (8 * i);
		__raw_writeq(ext, i2c->twsi_base + SW_TWSI_EXT);
	}

	octeon_i2c_hlc_int_clear(i2c);
	__raw_writeq(cmd, i2c->twsi_base + SW_TWSI);

	ret = octeon_i2c_hlc_wait(i2c);

	if (ret)
		goto err;

	cmd = __raw_readq(i2c->twsi_base + SW_TWSI);

	if ((cmd & SW_TWSI_R) == 0) {
		if (octeon_i2c_lost_arb(cmd))
			goto retry;
		ret = -EIO;
		goto err;
	}

err:
	return ret;
}

static int octeon_i2c_ia_read(struct octeon_i2c *i2c, struct i2c_msg *msgs)
{
	u64 cmd;
	int i, j;
	int ret = 0;

	octeon_i2c_enable_hlc(i2c);

retry:
	cmd = SW_TWSI_V | SW_TWSI_R | SW_TWSI_SOVR;
	/* SIZE */
	cmd |= (u64)(msgs[1].len - 1) << SW_TWSI_SIZE_SHIFT;
	/* A */
	cmd |= (u64)(msgs[0].addr & 0x7full) << SW_TWSI_A_SHIFT;

	if (msgs[0].flags & I2C_M_TEN)
		cmd |= SW_TWSI_OP_10_IA;
	else
		cmd |= SW_TWSI_OP_7_IA;

	if (msgs[0].len == 2) {
		u64 ext = 0;
		cmd |= SW_TWSI_EIA;
		ext = (u64)msgs[0].buf[0] << SW_TWSI_IA_SHIFT;
		cmd |= (u64)msgs[0].buf[1] << SW_TWSI_IA_SHIFT;
		__raw_writeq(ext, i2c->twsi_base + SW_TWSI_EXT);
	} else {
		cmd |= (u64)msgs[0].buf[0] << SW_TWSI_IA_SHIFT;
	}

	octeon_i2c_hlc_int_clear(i2c);
	__raw_writeq(cmd, i2c->twsi_base + SW_TWSI);

	ret = octeon_i2c_hlc_wait(i2c);

	if (ret)
		goto err;

	cmd = __raw_readq(i2c->twsi_base + SW_TWSI);

	if ((cmd & SW_TWSI_R) == 0) {
		if (octeon_i2c_lost_arb(cmd))
			goto retry;
		ret = -EIO;
		goto err;
	}

	for (i = 0, j = msgs[1].len - 1; i  < msgs[1].len && i < 4; i++, j--)
		msgs[1].buf[j] = (cmd >> (8 * i)) & 0xff;

	if (msgs[1].len >= 4) {
		cmd = __raw_readq(i2c->twsi_base + SW_TWSI_EXT);
		for (i = 0; i  < msgs[1].len - 4 && i < 4; i++, j--)
			msgs[1].buf[j] = (cmd >> (8 * i)) & 0xff;
	}

err:
	return ret;
}

static int octeon_i2c_ia_write(struct octeon_i2c *i2c, struct i2c_msg *msgs)
{
	u64 cmd;
	int i, j;
	int ret = 0;
	u64 ext = 0;
	bool set_ext = false;

	octeon_i2c_enable_hlc(i2c);

retry:
	cmd = SW_TWSI_V | SW_TWSI_SOVR;
	/* SIZE */
	cmd |= (u64)(msgs[1].len - 1) << SW_TWSI_SIZE_SHIFT;
	/* A */
	cmd |= (u64)(msgs[0].addr & 0x7full) << SW_TWSI_A_SHIFT;

	if (msgs[0].flags & I2C_M_TEN)
		cmd |= SW_TWSI_OP_10_IA;
	else
		cmd |= SW_TWSI_OP_7_IA;

	if (msgs[0].len == 2) {
		cmd |= SW_TWSI_EIA;
		ext |= (u64)msgs[0].buf[0] << SW_TWSI_IA_SHIFT;
		set_ext = true;
		cmd |= (u64)msgs[0].buf[1] << SW_TWSI_IA_SHIFT;
	} else {
		cmd |= (u64)msgs[0].buf[0] << SW_TWSI_IA_SHIFT;
	}
	for (i = 0, j = msgs[1].len - 1; i  < msgs[1].len && i < 4; i++, j--)
		cmd |= (u64)msgs[1].buf[j] << (8 * i);

	if (msgs[1].len >= 4) {
		for (i = 0; i < msgs[1].len - 4 && i < 4; i++, j--)
			ext |= (u64)msgs[1].buf[j] << (8 * i);
		set_ext = true;
	}
	if (set_ext)
		__raw_writeq(ext, i2c->twsi_base + SW_TWSI_EXT);

	octeon_i2c_hlc_int_clear(i2c);
	__raw_writeq(cmd, i2c->twsi_base + SW_TWSI);

	ret = octeon_i2c_hlc_wait(i2c);

	if (ret)
		goto err;

	cmd = __raw_readq(i2c->twsi_base + SW_TWSI);

	if ((cmd & SW_TWSI_R) == 0) {
		if (octeon_i2c_lost_arb(cmd))
			goto retry;
		ret = -EIO;
		goto err;
	}

err:
	return ret;
}

/**
 * octeon_i2c_xfer - The driver's master_xfer function.
 * @adap: Pointer to the i2c_adapter structure.
 * @msgs: Pointer to the messages to be processed.
 * @num: Length of the MSGS array.
 *
 * Returns the number of messages processed, or a negative errno on
 * failure.
 */
static int octeon_i2c_xfer(struct i2c_adapter *adap,
			   struct i2c_msg *msgs,
			   int num)
{
	struct i2c_msg *pmsg;
	int i;
	int ret = 0;
	struct octeon_i2c *i2c = i2c_get_adapdata(adap);

	if (num == 1) {
		if (msgs[0].len > 0 && msgs[0].len <= 8) {
			if (msgs[0].flags & I2C_M_RD)
				ret = octeon_i2c_simple_read(i2c, msgs);
			else
				ret = octeon_i2c_simple_write(i2c, msgs);
			goto out;
		}
	} else if (num == 2) {
		if ((msgs[0].flags & I2C_M_RD) == 0 &&
		    (msgs[1].flags & I2C_M_RECV_LEN) == 0 &&
		    msgs[0].len > 0 && msgs[0].len <= 2 &&
		    msgs[1].len > 0 && msgs[1].len <= 8 &&
		    msgs[0].addr == msgs[1].addr) {
			if (msgs[1].flags & I2C_M_RD)
				ret = octeon_i2c_ia_read(i2c, msgs);
			else
				ret = octeon_i2c_ia_write(i2c, msgs);
			goto out;
		}
	}

	for (i = 0; ret == 0 && i < num; i++) {
		pmsg = &msgs[i];
		dev_dbg(i2c->dev,
			"Doing %s %d byte(s) to/from 0x%02x - %d of %d messages\n",
			 pmsg->flags & I2C_M_RD ? "read" : "write",
			 pmsg->len, pmsg->addr, i + 1, num);
		if (pmsg->flags & I2C_M_RD)
			ret = octeon_i2c_read(i2c, pmsg->addr, pmsg->buf,
					      &pmsg->len, i, pmsg->flags & I2C_M_RECV_LEN);
		else
			ret = octeon_i2c_write(i2c, pmsg->addr, pmsg->buf,
					       pmsg->len, i);
	}
	octeon_i2c_stop(i2c);
out:
	return (ret != 0) ? ret : num;
}

static u32 octeon_i2c_functionality(struct i2c_adapter *adap)
{
	return I2C_FUNC_I2C | I2C_FUNC_SMBUS_EMUL;
}

static const struct i2c_algorithm octeon_i2c_algo = {
	.master_xfer = octeon_i2c_xfer,
	.functionality = octeon_i2c_functionality,
};

static struct i2c_adapter octeon_i2c_ops = {
	.owner = THIS_MODULE,
	.name = "OCTEON adapter",
	.algo = &octeon_i2c_algo,
};

/**
 * octeon_i2c_setclock - Calculate and set clock divisors.
 */
static int octeon_i2c_setclock(struct octeon_i2c *i2c)
{
	int tclk, thp_base, inc, thp_idx, mdiv_idx, ndiv_idx, foscl, diff;
	int thp = 0x18, mdiv = 2, ndiv = 0, delta_hz = 1000000;

	for (ndiv_idx = 0; ndiv_idx < 8 && delta_hz != 0; ndiv_idx++) {
		/*
		 * An mdiv value of less than 2 seems to not work well
		 * with ds1337 RTCs, so we constrain it to larger
		 * values.
		 */
		for (mdiv_idx = 15; mdiv_idx >= 2 && delta_hz != 0; mdiv_idx--) {
			/*
			 * For given ndiv and mdiv values check the
			 * two closest thp values.
			 */
			tclk = i2c->twsi_freq * (mdiv_idx + 1) * 10;
			tclk *= (1 << ndiv_idx);
			thp_base = (i2c->sys_freq / (tclk * 2)) - 1;
			for (inc = 0; inc <= 1; inc++) {
				thp_idx = thp_base + inc;
				if (thp_idx < 5 || thp_idx > 0xff)
					continue;

				foscl = i2c->sys_freq / (2 * (thp_idx + 1));
				foscl = foscl / (1 << ndiv_idx);
				foscl = foscl / (mdiv_idx + 1) / 10;
				diff = abs(foscl - i2c->twsi_freq);
				if (diff < delta_hz) {
					delta_hz = diff;
					thp = thp_idx;
					mdiv = mdiv_idx;
					ndiv = ndiv_idx;
				}
			}
		}
	}
	octeon_i2c_write_sw(i2c, SW_TWSI_OP_TWSI_CLK, thp);
	octeon_i2c_write_sw(i2c, SW_TWSI_EOP_TWSI_CLKCTL, (mdiv << 3) | ndiv);

	return 0;
}

static int octeon_i2c_initlowlevel(struct octeon_i2c *i2c)
{
	u8 status;
	int tries;

	/* reset controller */
	octeon_i2c_write_sw(i2c, SW_TWSI_EOP_TWSI_RST, 0);

	status = 0;
	for (tries = 10; tries && status != STAT_IDLE; tries--) {
		udelay(1);
		status = octeon_i2c_read_sw(i2c, SW_TWSI_EOP_TWSI_STAT);
	}

	if (status != STAT_IDLE) {
		dev_err(i2c->dev, "%s: TWSI_RST failed! (0x%x)\n",
			__func__, status);
		return -EIO;
	}


	/* disable high level controller, enable bus access */
	octeon_i2c_write_sw(i2c, SW_TWSI_EOP_TWSI_CTL, TWSI_CTL_ENAB);

	return 0;
}

static int octeon_i2c_cvmx_map[2] = {-ENODEV, -ENODEV};

int octeon_i2c_cvmx2i2c(unsigned int cvmx_twsi_bus_num)
{
	if (cvmx_twsi_bus_num < ARRAY_SIZE(octeon_i2c_cvmx_map))
		return octeon_i2c_cvmx_map[cvmx_twsi_bus_num];
	else
		return -ENODEV;
}
EXPORT_SYMBOL(octeon_i2c_cvmx2i2c);

#ifdef CONFIG_ARCH_THUNDER

static u32 get_io_clock_rate(struct device *dev)
{
	void __iomem *rst_base;
	u64 io_clock_scale;
	u32 io_clock_rate = 0;

	rst_base = devm_ioremap(dev, RST_BASE, RST_SIZE);
	if (!rst_base) {
		dev_err(dev, "Cannot map RST\n");
		goto clk_err;
	}
	io_clock_scale = (__raw_readq(rst_base + RST_BOOT) & RST_PNR_MUL_MASK) >> RST_PNR_MUL_SHIFT;
	io_clock_rate = (u32)io_clock_scale * REF_CLOCK_RATE;
	devm_iounmap(dev, rst_base);
clk_err:
	return io_clock_rate;
}

static int octeon_i2c_probe_pci(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	int result = 0;
	struct device *dev = &pdev->dev;
	struct octeon_i2c *i2c;
	u8 soc_node;
	u8 i2c_bus_id;
	struct device_node *np = NULL;
	char i2c_name[10];
	u32 test_val;
	u32 alert_gpio[2];

	i2c = devm_kzalloc(&pdev->dev, sizeof(*i2c), GFP_KERNEL);
	if (!i2c) {
		dev_err(&pdev->dev, "kzalloc failed\n");
		return -ENOMEM;
	}

	i2c->dev = dev;
	pci_set_drvdata(pdev, i2c);
	result = pci_enable_device(pdev);
	if (result) {
		dev_err(dev, "Failed to enable PCI device\n");
		goto out_free_i2c;
	}

	result = pci_request_regions(pdev, DRV_NAME);
	if (result) {
		dev_err(dev, "PCI request regions failed 0x%x\n", result);
		goto out_disable_device;
	}

	i2c->twsi_base = pci_ioremap_bar(pdev, PCI_CFG_REG_BAR_NUM);
	if (!i2c->twsi_base) {
		dev_err(dev, "I2C: Cannot map CSR memory space, aborting\n");
		result = -ENOMEM;
		goto out_release_regions;
	}

	soc_node = (pci_resource_start(pdev, PCI_CFG_REG_BAR_NUM) >> 44) & 0x3;
	i2c_bus_id = (pci_resource_start(pdev, PCI_CFG_REG_BAR_NUM) >> 24) & 0x7;
	snprintf(i2c_name, 10, "i2c%d", soc_node * 6 + i2c_bus_id);
	np = of_find_node_by_name(NULL, i2c_name);

	if (np == NULL || of_property_read_u32(np, "clock-frequency", &i2c->twsi_freq))
		i2c->twsi_freq = TWSI_DFL_RATE;
	i2c->sys_freq = get_io_clock_rate(dev);
	if (!i2c->sys_freq) {
		dev_err(dev, "Didn't get I/O clock rate\n");
		goto out_unmap;
	}
	init_waitqueue_head(&i2c->queue);

	result = octeon_i2c_initlowlevel(i2c);
	if (result) {
		dev_err(dev, "init low level failed\n");
		goto out_unmap;
	}

	result = octeon_i2c_setclock(i2c);
	if (result) {
		dev_err(dev, "clock init failed\n");
		goto out_unmap;
	}

	/* Enable MSI-X */
	i2c->i2c_msix.entry = 0;
	if (pci_enable_msix(pdev, &i2c->i2c_msix, 1)) {
		dev_err(dev, "I2C: Unable to enable MSI-X\n");
		goto out_unmap;
	}

	result = devm_request_irq(dev, i2c->i2c_msix.vector, octeon_i2c_isr,
				  0, DRV_NAME, i2c);
	if (result < 0) {
		dev_err(dev, "failed to attach i2c interrupt\n");
		goto out_msix;
	}
	i2c->int_en = thunder_i2c_int_enable;
	i2c->int_dis = thunder_i2c_int_disable;
	i2c->hlc_int_en = thunder_i2c_hlc_int_enable;
	i2c->hlc_int_dis = thunder_i2c_hlc_int_disable;

	i2c->adap = octeon_i2c_ops;
	i2c->adap.class = I2C_CLASS_HWMON | I2C_CLASS_SPD;
	i2c->adap.timeout = HZ / 50;
	i2c->adap.dev.parent = &pdev->dev;
	i2c->adap.dev.of_node = pdev->dev.of_node;
	snprintf(i2c->adap.name, sizeof(i2c->adap.name),
		 "thunderx-i2c-%d.%d", soc_node, i2c_bus_id);
	i2c_set_adapdata(&i2c->adap, i2c);
	result = i2c_add_adapter(&i2c->adap);
	if (result < 0) {
		dev_err(dev, "failed to add adapter\n");
		goto out_irq;
	}
	if (!of_property_read_u32_array(np, "alert-gpio", alert_gpio, 2)) {
		dev_info(dev, "DT alert-gpio is:%d,%d\n",
			 alert_gpio[0], alert_gpio[1]);
	} else {
		goto noalert;
	}
	result = devm_gpio_request_one(dev, alert_gpio[0], GPIOF_DIR_IN, "smbalert");
	if (result < 0) {
		dev_err(dev, "failed to get gpio\n");
		goto noalert;
	}
	i2c->alert_data.alert_edge_triggered = 0;
	i2c->alert_data.irq = gpio_to_irq(alert_gpio[0]);
	i2c->ara = i2c_setup_smbus_alert(&i2c->adap, &i2c->alert_data);
	if (!i2c->ara) {
		dev_err(dev, "failed to setup smbalert\n");
	}
noalert:
	dev_info(dev, "version %s\n", DRV_VERSION);
	return 0;

out_irq:
	devm_free_irq(dev, i2c->i2c_msix.vector, i2c);
out_msix:
	pci_disable_msix(pdev);
out_unmap:
	iounmap(i2c->twsi_base);
out_release_regions:
	pci_release_regions(pdev);
out_disable_device:
	pci_disable_device(pdev);
out_free_i2c:
	pci_set_drvdata(pdev, NULL);
	devm_kfree(dev, i2c);
	return result;
};


static void octeon_i2c_remove_pci(struct pci_dev *pdev)
{
	struct octeon_i2c *i2c = pci_get_drvdata(pdev);
	struct device *dev;

	if (!i2c)
		return;
	dev = i2c->dev;
	if (i2c->ara)
		i2c_unregister_device(i2c->ara);
	i2c_del_adapter(&i2c->adap);
	devm_free_irq(dev, i2c->i2c_msix.vector, i2c);
	pci_disable_msix(pdev);
	iounmap(i2c->twsi_base);
	pci_release_regions(pdev);
	pci_disable_device(pdev);
	pci_set_drvdata(pdev, NULL);
};

#else

static int octeon_i2c_probe(struct platform_device *pdev)
{
	int irq, hlc_irq = 0, result = 0;
	struct octeon_i2c *i2c;
	struct resource *res_mem;
	struct device_node *node = pdev->dev.of_node;
	bool cn78xx_style;

	cn78xx_style = of_device_is_compatible(node, "cavium,octeon-7890-twsi");

	if (cn78xx_style) {
		hlc_irq = platform_get_irq(pdev, 0);
		if (hlc_irq < 0)
			return hlc_irq;

		irq = platform_get_irq(pdev, 2);
		if (irq < 0)
			return irq;
	} else {
		/* All adaptors have an irq.  */
		irq = platform_get_irq(pdev, 0);
		if (irq < 0)
			return irq;
	}

	i2c = devm_kzalloc(&pdev->dev, sizeof(*i2c), GFP_KERNEL);
	if (!i2c) {
		dev_err(&pdev->dev, "kzalloc failed\n");
		result = -ENOMEM;
		goto out;
	}
	i2c->cvmx_channel = -1;
	i2c->dev = &pdev->dev;

	res_mem = platform_get_resource(pdev, IORESOURCE_MEM, 0);

	if (res_mem == NULL) {
		dev_err(i2c->dev, "found no memory resource\n");
		result = -ENXIO;
		goto out;
	}

	/*
	 * "clock-rate" is a legacy binding, the official binding is
	 * "clock-frequency".  Try the official one first and then
	 * fall back if it doesn't exist.
	 */
	if (of_property_read_u32(node,
				 "clock-frequency", &i2c->twsi_freq) &&
	    of_property_read_u32(node,
				 "clock-rate", &i2c->twsi_freq)) {
		dev_err(i2c->dev,
			"no I2C 'clock-rate' or 'clock-frequency' property\n");
		result = -ENXIO;
		goto out;
	}

	i2c->sys_freq = octeon_get_io_clock_rate();

	switch (res_mem->start) {
	case 0x1180000001000:
		i2c->cvmx_channel = 0;
		break;
	case 0x1180000001200:
		i2c->cvmx_channel = 1;
		break;
	default:
		break;
	}

	if (!devm_request_mem_region(&pdev->dev, res_mem->start, resource_size(res_mem),
				     res_mem->name)) {
		dev_err(i2c->dev, "request_mem_region failed\n");
		goto out;
	}
	i2c->twsi_base = devm_ioremap(&pdev->dev, res_mem->start, resource_size(res_mem));

	init_waitqueue_head(&i2c->queue);

	i2c->irq = irq;

	if (cn78xx_style) {
		i2c->hlc_irq = hlc_irq;

		i2c->int_en = octeon_i2c_int_enable78;
		i2c->int_dis = octeon_i2c_int_disable78;
		i2c->hlc_int_en = octeon_i2c_hlc_int_enable78;
		i2c->hlc_int_dis = octeon_i2c_hlc_int_disable78;

		irq_set_status_flags(i2c->irq, IRQ_NOAUTOEN);
		irq_set_status_flags(i2c->hlc_irq, IRQ_NOAUTOEN);

		result = devm_request_irq(&pdev->dev, i2c->irq,
					  octeon_i2c_isr, 0, DRV_NAME, i2c);

		if (result < 0) {
			dev_err(i2c->dev, "failed to attach interrupt\n");
			goto out;
		}
		result = devm_request_irq(&pdev->dev, i2c->hlc_irq,
					  octeon_i2c_hlc_isr78, 0, DRV_NAME, i2c);

		if (result < 0) {
			dev_err(i2c->dev, "failed to attach interrupt\n");
			goto out;
		}
	} else {
		i2c->int_en = octeon_i2c_int_enable;
		i2c->int_dis = octeon_i2c_int_disable;
		i2c->hlc_int_en = octeon_i2c_hlc_int_enable;
		i2c->hlc_int_dis = octeon_i2c_int_disable;

		result = devm_request_irq(&pdev->dev, i2c->irq,
					  octeon_i2c_isr, 0, DRV_NAME, i2c);
		if (result < 0) {
			dev_err(i2c->dev, "failed to attach interrupt\n");
			goto out;
		}
	}

	result = octeon_i2c_initlowlevel(i2c);
	if (result) {
		dev_err(i2c->dev, "init low level failed\n");
		goto  out;
	}

	result = octeon_i2c_setclock(i2c);
	if (result) {
		dev_err(i2c->dev, "clock init failed\n");
		goto  out;
	}

	i2c->adap = octeon_i2c_ops;
	i2c->adap.timeout = msecs_to_jiffies(50);
	i2c->adap.dev.parent = &pdev->dev;
	i2c->adap.dev.of_node = node;
	i2c_set_adapdata(&i2c->adap, i2c);
	platform_set_drvdata(pdev, i2c);

	result = i2c_add_adapter(&i2c->adap);
	if (result < 0) {
		dev_err(i2c->dev, "failed to add adapter\n");
		goto out;
	}
	dev_info(i2c->dev, "version %s\n", DRV_VERSION);

	of_i2c_register_devices(&i2c->adap);
	if (i2c->cvmx_channel >= 0)
		octeon_i2c_cvmx_map[i2c->cvmx_channel] = i2c->adap.nr;

	return 0;

out:
	return result;
};

static int octeon_i2c_remove(struct platform_device *pdev)
{
	struct octeon_i2c *i2c = platform_get_drvdata(pdev);

	if (i2c->cvmx_channel >= 0)
		octeon_i2c_cvmx_map[i2c->cvmx_channel] = -ENODEV;
	i2c_del_adapter(&i2c->adap);
	return 0;
};

static struct of_device_id octeon_i2c_match[] = {
	{
		.compatible = "cavium,octeon-3860-twsi",
	},
	{
		.compatible = "cavium,octeon-7890-twsi",
	},
	{},
};
MODULE_DEVICE_TABLE(of, octeon_i2c_match);
#endif

#ifdef CONFIG_ARCH_THUNDER

static const struct pci_device_id octeon_i2c_pci_id_table[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, PCI_DEVICE_ID_THUNDER_TWSI) },
	{ 0, }  /* end of table */
};

MODULE_DEVICE_TABLE(pci, octeon_i2c_pci_id_table);

static struct pci_driver octeon_i2c_pci_driver = {
	.name		= DRV_NAME,
	.id_table	= octeon_i2c_pci_id_table,
	.probe		= octeon_i2c_probe_pci,
	.remove		= octeon_i2c_remove_pci,
};

module_pci_driver(octeon_i2c_pci_driver)

#else

static struct platform_driver octeon_i2c_driver = {
	.probe		= octeon_i2c_probe,
	.remove		= octeon_i2c_remove,
	.driver		= {
		.owner	= THIS_MODULE,
		.name	= DRV_NAME,
		.of_match_table = octeon_i2c_match,
	},
};

module_platform_driver(octeon_i2c_driver);
#endif

MODULE_AUTHOR("Michael Lawnick <michael.lawnick.ext@nsn.com>");
MODULE_DESCRIPTION("I2C-Bus adapter for Cavium OCTEON processors");
MODULE_LICENSE("GPL");
MODULE_VERSION(DRV_VERSION);
