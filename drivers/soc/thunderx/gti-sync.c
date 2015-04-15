/*
 * Copyright (C) 2014 Cavium, Inc.
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License rev 2 and
 * only rev 2 as published by the free Software foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or fITNESS fOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/compiler.h>

#define DRV_NAME		"thunderx-gti"
#define DRV_VERSION		"1.0"
#define ATF_RT_SVC_GTI_SYNC	0x43000401

static noinline int invoke_gti_fn_smc(u64 function_id, u64 arg0, u64 arg1,
					 u64 arg2)
{
	register long _x0 asm ("x0");
	register long _x1 asm ("x1");
	register long _x2 asm ("x2");
	register long _x3 asm ("x3");
	_x0 = function_id;
	_x1 = arg0;
	_x2 = arg1;
	_x3 = arg2;

	asm volatile("smc    #0\n"
			: "+r" (_x0)
			: "r" (_x1), "r" (_x2), "r" (_x3));

	return _x0;
}

/*
 * Body of kthread that handles gti sync.
 */
static int __noreturn gti_sync_kthread(void *arg)
{
	int iter;

	/* sync gti periodically */
	for (;;) {

		pr_debug("gti sync\n");

		/* Make smc call to ATF to do gti sync across nodes */
		invoke_gti_fn_smc(ATF_RT_SVC_GTI_SYNC, 0, 0, 0);

		for (iter = 0; iter < CONFIG_THUNDERX_GTI_SYNC_PERIOD; iter++) {
			/*sleep for a minute*/
			msleep(60000);
		}
	}
}

static int __init gti_init_module(void)
{
	struct task_struct *tsk;

	pr_info("gti: %s, ver %s\n", DRV_NAME, DRV_VERSION);
	tsk = kthread_run(gti_sync_kthread, NULL, "%s", "gti_sync");
	BUG_ON(IS_ERR(tsk));
	return 0;
}

static void __exit gti_cleanup_module(void)
{
	pr_info("gti: %s, ver %s\n", DRV_NAME, DRV_VERSION);
}

module_init(gti_init_module);
module_exit(gti_cleanup_module);

MODULE_AUTHOR("Cavium Inc");
MODULE_DESCRIPTION("Cavium Thunder GTI sync Driver");
MODULE_LICENSE("GPL v2");
MODULE_VERSION(DRV_VERSION);
