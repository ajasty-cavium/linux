#
# Makefile for Thunder PCIe specific kernel interface routines under Linux.
#
# This file is subject to the terms and conditions of the GNU General Public
# License.  See the file "COPYING" in the main directory of this archive
# for more details.
#
# Copyright (C) 2013 Cavium, Inc.
#

obj-y				+= pci.o

ifdef CONFIG_PCI
obj-y				+= pcie-8xxx.o
obj-y				+= pcie-8xxx_msix.o
endif

