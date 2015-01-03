#ifndef _ASM_ARM64_NUMA_H
#define _ASM_ARM64_NUMA_H

#include <linux/nodemask.h>
#include <asm/topology.h>

#ifdef CONFIG_NUMA

#define NR_NODE_MEMBLKS		(MAX_NUMNODES * 2)
#define ZONE_ALIGN (1UL << (MAX_ORDER + PAGE_SHIFT))

/* currently, arm64 implements flat NUMA topology */
#define parent_node(node)	(node)

/* dummy definitions for pci functions */
#define pcibus_to_node(node)	0
#define cpumask_of_pcibus(bus)	0

const struct cpumask *cpumask_of_node(int node);
/* Mappings between node number and cpus on that node. */
extern cpumask_var_t node_to_cpumask_map[MAX_NUMNODES];

void __init arm64_numa_init(void);
int __init numa_add_memblk(u32 nodeid, u64 start, u64 end);
void numa_store_cpu_info(int cpu);
void numa_set_node(int cpu, int node);
void numa_clear_node(int cpu);
void numa_add_cpu(int cpu);
void numa_remove_cpu(int cpu);
#else	/* CONFIG_NUMA */
static inline void arm64_numa_init(void);
static inline void numa_store_cpu_info(int cpu)	{ }
static inline void arm64_numa_init()			{ }
#endif	/* CONFIG_NUMA */
#endif	/* _ASM_ARM64_NUMA_H */
