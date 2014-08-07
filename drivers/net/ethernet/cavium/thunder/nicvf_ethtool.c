/****************************************************************************
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2013 Cavium, Inc.
 ******************************************************************************/

/* ETHTOOL Support for VNIC_VF Device*/

#include <linux/pci.h>
#include "nic.h"

#define DRV_NAME	"thunder-nicvf"
#define DRV_VERSION     "1.0"

struct nicvf_stat {
	char name[ETH_GSTRING_LEN];
	unsigned int index;
};

#define NICVF_TX_STAT(stat) { \
	.name = #stat, \
	.index = offsetof(struct nicvf_tx_stats, stat) / sizeof(u64) \
}

#define NICVF_RX_STAT(stat) { \
	.name = #stat, \
	.index = offsetof(struct nicvf_rx_stats, stat) / sizeof(u64) \
}

static const struct nicvf_stat nicvf_tx_stats[] = {
	NICVF_TX_STAT(tx_frames_ok),
	NICVF_TX_STAT(tx_unicast_frames_ok),
	NICVF_TX_STAT(tx_multicast_frames_ok),
	NICVF_TX_STAT(tx_broadcast_frames_ok),
	NICVF_TX_STAT(tx_bytes_ok),
	NICVF_TX_STAT(tx_unicast_bytes_ok),
	NICVF_TX_STAT(tx_multicast_bytes_ok),
	NICVF_TX_STAT(tx_broadcast_bytes_ok),
	NICVF_TX_STAT(tx_drops),
	NICVF_TX_STAT(tx_errors),
	NICVF_TX_STAT(tx_tso),
};

static const struct nicvf_stat nicvf_rx_stats[] = {
	NICVF_RX_STAT(rx_frames_ok),
	NICVF_RX_STAT(rx_frames_total),
	NICVF_RX_STAT(rx_unicast_frames_ok),
	NICVF_RX_STAT(rx_multicast_frames_ok),
	NICVF_RX_STAT(rx_broadcast_frames_ok),
	NICVF_RX_STAT(rx_bytes_ok),
	NICVF_RX_STAT(rx_unicast_bytes_ok),
	NICVF_RX_STAT(rx_multicast_bytes_ok),
	NICVF_RX_STAT(rx_broadcast_bytes_ok),
	NICVF_RX_STAT(rx_drop),
	NICVF_RX_STAT(rx_no_bufs),
	NICVF_RX_STAT(rx_errors),
	NICVF_RX_STAT(rx_rss),
	NICVF_RX_STAT(rx_crc_errors),
	NICVF_RX_STAT(rx_frames_64),
	NICVF_RX_STAT(rx_frames_127),
	NICVF_RX_STAT(rx_frames_255),
	NICVF_RX_STAT(rx_frames_511),
	NICVF_RX_STAT(rx_frames_1023),
	NICVF_RX_STAT(rx_frames_1518),
	NICVF_RX_STAT(rx_frames_jumbo),
};

static const unsigned int nicvf_n_tx_stats = ARRAY_SIZE(nicvf_tx_stats);
static const unsigned int nicvf_n_rx_stats = ARRAY_SIZE(nicvf_rx_stats);

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

	for (stats = 0; stats < nicvf_n_tx_stats; stats++) {
		memcpy(data, nicvf_tx_stats[stats].name, ETH_GSTRING_LEN);
		data += ETH_GSTRING_LEN;
	}
	for (stats = 0; stats < nicvf_n_rx_stats; stats++) {
		memcpy(data, nicvf_rx_stats[stats].name, ETH_GSTRING_LEN);
		data += ETH_GSTRING_LEN;
	}
}

static int nicvf_get_sset_count(struct net_device *netdev, int sset)
{
	return nicvf_n_tx_stats + nicvf_n_rx_stats;
}

static void nicvf_get_ethtool_stats(struct net_device *netdev,
				   struct ethtool_stats *stats, u64 *data)
{
	struct nicvf *nic = netdev_priv(netdev);
	struct eth_stats vstats = nic->vstats;
	int stat;

	memset(&vstats, 0, sizeof(struct eth_stats));

	nic->vstats.tx.tx_frames_ok = netdev->stats.tx_packets;
	nic->vstats.tx.tx_bytes_ok = netdev->stats.tx_bytes;
	nic->vstats.tx.tx_errors = netdev->stats.tx_errors;
	nic->vstats.tx.tx_drops = netdev->stats.tx_dropped;
	nic->vstats.rx.rx_frames_ok = netdev->stats.rx_packets;
	nic->vstats.rx.rx_bytes_ok = netdev->stats.rx_bytes;
	nic->vstats.rx.rx_errors = netdev->stats.rx_errors;
	nic->vstats.rx.rx_drop = netdev->stats.rx_dropped;

	for (stat = 0; stat < nicvf_n_tx_stats; stat++)
		*(data++) = ((u64 *)&nic->vstats.tx)
				[nicvf_tx_stats[stat].index];
	for (stat = 0; stat < nicvf_n_rx_stats; stat++)
		*(data++) = ((u64 *)&nic->vstats.rx)
				[nicvf_rx_stats[stat].index];
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

