/****************************************************************************
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 * 
 * Copyright (C) 2013 Cavium, Inc. 
 ******************************************************************************/

/* ETHTOOL Support for VNIC_VF Device*/

#include <linux/pci.h>
#include "vnic.h"

#define DRV_NAME        "vnic-vf"
#define DRV_VERSION     "1.0"

struct vnic_stat {
	char name[ETH_GSTRING_LEN];
	unsigned int index;
};

#define VNIC_TX_STAT(stat) { \
	.name = #stat, \
	.index = offsetof(struct vnic_tx_stats, stat) / sizeof(u64) \
}

#define VNIC_RX_STAT(stat) { \
	.name = #stat, \
	.index = offsetof(struct vnic_rx_stats, stat) / sizeof(u64) \
}

static const struct vnic_stat vnic_tx_stats[] = {
	VNIC_TX_STAT(tx_frames_ok),
	VNIC_TX_STAT(tx_unicast_frames_ok),
	VNIC_TX_STAT(tx_multicast_frames_ok),
	VNIC_TX_STAT(tx_broadcast_frames_ok),
	VNIC_TX_STAT(tx_bytes_ok),
	VNIC_TX_STAT(tx_unicast_bytes_ok),
	VNIC_TX_STAT(tx_multicast_bytes_ok),
	VNIC_TX_STAT(tx_broadcast_bytes_ok),
	VNIC_TX_STAT(tx_drops),
	VNIC_TX_STAT(tx_errors),
	VNIC_TX_STAT(tx_tso),
};

static const struct vnic_stat vnic_rx_stats[] = {
	VNIC_RX_STAT(rx_frames_ok),
	VNIC_RX_STAT(rx_frames_total),
	VNIC_RX_STAT(rx_unicast_frames_ok),
	VNIC_RX_STAT(rx_multicast_frames_ok),
	VNIC_RX_STAT(rx_broadcast_frames_ok),
	VNIC_RX_STAT(rx_bytes_ok),
	VNIC_RX_STAT(rx_unicast_bytes_ok),
	VNIC_RX_STAT(rx_multicast_bytes_ok),
	VNIC_RX_STAT(rx_broadcast_bytes_ok),
	VNIC_RX_STAT(rx_drop),
	VNIC_RX_STAT(rx_no_bufs),
	VNIC_RX_STAT(rx_errors),
	VNIC_RX_STAT(rx_rss),
	VNIC_RX_STAT(rx_crc_errors),
	VNIC_RX_STAT(rx_frames_64),
	VNIC_RX_STAT(rx_frames_127),
	VNIC_RX_STAT(rx_frames_255),
	VNIC_RX_STAT(rx_frames_511),
	VNIC_RX_STAT(rx_frames_1023),
	VNIC_RX_STAT(rx_frames_1518),
	VNIC_RX_STAT(rx_frames_to_max),
};

static const unsigned int vnic_n_tx_stats = ARRAY_SIZE(vnic_tx_stats);
static const unsigned int vnic_n_rx_stats = ARRAY_SIZE(vnic_rx_stats);

static int vnic_get_settings(struct net_device *netdev, 
	     		     struct ethtool_cmd *cmd)
{
	struct vnic *vnic = netdev_priv(netdev);

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
	if (netif_carrier_ok(vnic->netdev)) {
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

static int vnic_set_settings(struct net_device *netdev,
			     struct ethtool_cmd *cmd)
{
	return -EOPNOTSUPP;

	/* 10G full duplex setting supported only */
	if (cmd->autoneg == AUTONEG_ENABLE)
		return -EOPNOTSUPP; else {
			if ((ethtool_cmd_speed(cmd) == SPEED_10000)
					&& (cmd->duplex == DUPLEX_FULL))
				return 0;
		}

	return -EOPNOTSUPP;
}

static void vnic_get_drvinfo(struct net_device *netdev,
	    		     struct ethtool_drvinfo *info)
{
	struct vnic *vnic = netdev_priv(netdev);

	strlcpy(info->driver, DRV_NAME, sizeof(info->driver));
	strlcpy(info->version, DRV_VERSION, sizeof(info->version));
	strlcpy(info->bus_info, pci_name(vnic->pdev), sizeof(info->bus_info));
}

static void vnic_get_strings(struct net_device *netdev, u32 stringset, 
			     u8 *data)
{
	int stats;

	for (stats = 0; stats < vnic_n_tx_stats; stats++) {
		memcpy(data, vnic_tx_stats[stats].name, ETH_GSTRING_LEN);
		data += ETH_GSTRING_LEN;
	}
	for (stats = 0; stats < vnic_n_rx_stats; stats++) {
		memcpy(data, vnic_rx_stats[stats].name, ETH_GSTRING_LEN);
		data += ETH_GSTRING_LEN;
	}
}

static int vnic_get_sset_count(struct net_device *netdev, int sset)
{
	return vnic_n_tx_stats + vnic_n_rx_stats;
}

static void vnic_get_ethtool_stats(struct net_device *netdev, 
				   struct ethtool_stats *stats, u64 *data)
{
	int stat;
	struct eth_stats vstats;

	memset(&vstats, 0, sizeof(struct eth_stats));
	vstats.tx.tx_frames_ok = netdev->stats.tx_packets;
	vstats.tx.tx_bytes_ok = netdev->stats.tx_bytes;
	vstats.tx.tx_errors = netdev->stats.tx_errors;
	vstats.tx.tx_drops = netdev->stats.tx_dropped;
	vstats.rx.rx_frames_ok = netdev->stats.rx_packets;
	vstats.rx.rx_bytes_ok = netdev->stats.rx_bytes;
	vstats.rx.rx_errors = netdev->stats.rx_errors;
	vstats.rx.rx_drop = netdev->stats.rx_dropped;

	for (stat = 0; stat < vnic_n_tx_stats; stat++)
		*(data++) = ((u64 *)&vstats.tx)[vnic_tx_stats[stat].index];
	for (stat = 0; stat < vnic_n_rx_stats; stat++)
		*(data++) = ((u64 *)&vstats.rx)[vnic_rx_stats[stat].index];
}

static const struct ethtool_ops vnic_ethtool_ops = {
	.get_settings		= vnic_get_settings,
	.set_settings		= vnic_set_settings,
	.get_link		= ethtool_op_get_link,
	.get_drvinfo		= vnic_get_drvinfo,
	.get_strings		= vnic_get_strings,
	.get_sset_count		= vnic_get_sset_count,
	.get_ethtool_stats	= vnic_get_ethtool_stats,
	.get_ts_info		= ethtool_op_get_ts_info
#if 0	
	.get_coalesce		= vnic_get_coalesce,
	.set_coalesce		= vnic_set_coalesce,
	.get_ringparam		= vnic_get_ringparam,
	.set_ringparam		= vnic_set_ringparam,
#endif
};

void vnic_set_ethtool_ops(struct net_device *netdev)
{
	SET_ETHTOOL_OPS(netdev, &vnic_ethtool_ops);
}

