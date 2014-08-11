/*
 * Copyright (C) 2014 Cavium, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 */

/* ETHTOOL Support for VNIC_VF Device*/

#include <linux/pci.h>

#include "nic_reg.h"
#include "nic.h"

#define DRV_NAME	"thunder-nicvf"
#define DRV_VERSION     "1.0"

struct nicvf_stat {
	char name[ETH_GSTRING_LEN];
	unsigned int index;
};

#define NICVF_HW_STAT(stat) { \
	.name = #stat, \
	.index = offsetof(struct nicvf_hw_stats, stat) / sizeof(u64) \
}

#define NICVF_DRV_STAT(stat) { \
	.name = #stat, \
	.index = offsetof(struct nicvf_drv_stats, stat) / sizeof(u64) \
}

static const struct nicvf_stat nicvf_hw_stats[] = {
	NICVF_HW_STAT(rx_bytes_ok),
	NICVF_HW_STAT(rx_ucast_frames_ok),
	NICVF_HW_STAT(rx_bcast_frames_ok),
	NICVF_HW_STAT(rx_mcast_frames_ok),
	NICVF_HW_STAT(rx_fcs_errors),
	NICVF_HW_STAT(rx_l2_errors),
	NICVF_HW_STAT(rx_drop_red),
	NICVF_HW_STAT(rx_drop_red_bytes),
	NICVF_HW_STAT(rx_drop_overrun),
	NICVF_HW_STAT(rx_drop_overrun_bytes),
	NICVF_HW_STAT(rx_drop_bcast),
	NICVF_HW_STAT(rx_drop_mcast),
	NICVF_HW_STAT(rx_drop_l3_bcast),
	NICVF_HW_STAT(rx_drop_l3_mcast),
	NICVF_HW_STAT(tx_bytes_ok),
	NICVF_HW_STAT(tx_ucast_frames_ok),
	NICVF_HW_STAT(tx_bcast_frames_ok),
	NICVF_HW_STAT(tx_mcast_frames_ok),
};

static const struct nicvf_stat nicvf_drv_stats[] = {
	NICVF_DRV_STAT(rx_frames_ok),
	NICVF_DRV_STAT(rx_frames_64),
	NICVF_DRV_STAT(rx_frames_127),
	NICVF_DRV_STAT(rx_frames_255),
	NICVF_DRV_STAT(rx_frames_511),
	NICVF_DRV_STAT(rx_frames_1023),
	NICVF_DRV_STAT(rx_frames_1518),
	NICVF_DRV_STAT(rx_frames_jumbo),
	NICVF_DRV_STAT(rx_drops),
	NICVF_DRV_STAT(tx_frames_ok),
	NICVF_DRV_STAT(tx_busy),
	NICVF_DRV_STAT(tx_tso),
	NICVF_DRV_STAT(tx_drops),
};

static const unsigned int nicvf_n_hw_stats = ARRAY_SIZE(nicvf_hw_stats);
static const unsigned int nicvf_n_drv_stats = ARRAY_SIZE(nicvf_drv_stats);

static int nicvf_get_settings(struct net_device *netdev,
			     struct ethtool_cmd *cmd)
{
	cmd->supported = (SUPPORTED_1000baseT_Full |
			SUPPORTED_100baseT_Full |
			SUPPORTED_10baseT_Full |
			SUPPORTED_10000baseT_Full | SUPPORTED_FIBRE);

	cmd->advertising = (ADVERTISED_1000baseT_Full |
			ADVERTISED_100baseT_Full |
			ADVERTISED_10baseT_Full |
			ADVERTISED_10000baseT_Full | ADVERTISED_FIBRE);

	cmd->port = PORT_FIBRE;
	cmd->transceiver = XCVR_EXTERNAL;
	if (netif_carrier_ok(netdev)) {
		ethtool_cmd_speed_set(cmd, SPEED_10000);
		cmd->duplex = DUPLEX_FULL;
	} else {
		ethtool_cmd_speed_set(cmd, -1);
		cmd->duplex = -1;
	}

	cmd->autoneg = AUTONEG_DISABLE;
	ethtool_cmd_speed_set(cmd, SPEED_1000);
	return 0;
}

static int nicvf_set_settings(struct net_device *netdev,
			     struct ethtool_cmd *cmd)
{
	return -EOPNOTSUPP;

	/* 10G full duplex setting supported only */
	if (cmd->autoneg == AUTONEG_ENABLE)
		return -EOPNOTSUPP;

	if (ethtool_cmd_speed(cmd) != SPEED_10000)
		return -EOPNOTSUPP;

	if (cmd->duplex != DUPLEX_FULL)
		return -EOPNOTSUPP;

	return 0;
}

static void nicvf_get_drvinfo(struct net_device *netdev,
			     struct ethtool_drvinfo *info)
{
	struct nicvf *nic = netdev_priv(netdev);

	strlcpy(info->driver, DRV_NAME, sizeof(info->driver));
	strlcpy(info->version, DRV_VERSION, sizeof(info->version));
	strlcpy(info->bus_info, pci_name(nic->pdev), sizeof(info->bus_info));
}

static void nicvf_get_strings(struct net_device *netdev, u32 stringset,
			     u8 *data)
{
	int stats;

	for (stats = 0; stats < nicvf_n_hw_stats; stats++) {
		memcpy(data, nicvf_hw_stats[stats].name, ETH_GSTRING_LEN);
		data += ETH_GSTRING_LEN;
	}
	for (stats = 0; stats < nicvf_n_drv_stats; stats++) {
		memcpy(data, nicvf_drv_stats[stats].name, ETH_GSTRING_LEN);
		data += ETH_GSTRING_LEN;
	}
}

static int nicvf_get_sset_count(struct net_device *netdev, int sset)
{
	return nicvf_n_hw_stats + nicvf_n_drv_stats;
}

static void nicvf_get_ethtool_stats(struct net_device *netdev,
				   struct ethtool_stats *stats, u64 *data)
{
	struct nicvf *nic = netdev_priv(netdev);
	int stat;

	nicvf_update_stats(nic);

	for (stat = 0; stat < nicvf_n_hw_stats; stat++)
		*(data++) = ((u64 *)&nic->stats)
				[nicvf_hw_stats[stat].index];
	for (stat = 0; stat < nicvf_n_drv_stats; stat++)
		*(data++) = ((u64 *)&nic->drv_stats)
				[nicvf_drv_stats[stat].index];
}

static const struct ethtool_ops nicvf_ethtool_ops = {
	.get_settings		= nicvf_get_settings,
	.set_settings		= nicvf_set_settings,
	.get_link		= ethtool_op_get_link,
	.get_drvinfo		= nicvf_get_drvinfo,
	.get_strings		= nicvf_get_strings,
	.get_sset_count		= nicvf_get_sset_count,
	.get_ethtool_stats	= nicvf_get_ethtool_stats,
	.get_ts_info		= ethtool_op_get_ts_info
#if 0
	.get_coalesce		= nicvf_get_coalesce,
	.set_coalesce		= nicvf_set_coalesce,
	.get_ringparam		= nicvf_get_ringparam,
	.set_ringparam		= nicvf_set_ringparam,
#endif
};

void nicvf_set_ethtool_ops(struct net_device *netdev)
{
	netdev->ethtool_ops = &nicvf_ethtool_ops;
}

