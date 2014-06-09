#
# Cavium Virtual NIC driver 
#

obj-$(CONFIG_CN88XX_VNIC_PF) += vnicpf.o
obj-$(CONFIG_CN88XX_VNIC_VF) += vnicvf.o
obj-$(CONFIG_CN88XX_BGX) += cn88xx_bgx.o

vnicpf-y := vnic_main.o 
vnicvf-y := vnic_vf.o vnic_reg.o vnic_queues.o 
#ifdef VNIC_ETHTOOL_ENABLE
vnicvf-y += vnic_ethtool.o
#endif
