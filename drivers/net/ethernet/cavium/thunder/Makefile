#
# Makefile for Cavium's Thunder ethernet device 
#

obj-$(CONFIG_THUNDER_NIC_PF) += nicpf.o
obj-$(CONFIG_THUNDER_NIC_VF) += nicvf.o
obj-$(CONFIG_THUNDER_BGX) += thunder_bgx.o

nicpf-y := nic_main.o 
nicvf-y := nicvf_main.o nicvf_queues.o 
#ifdef NICVF_ETHTOOL_ENABLE
nicvf-y += nicvf_ethtool.o
#endif
