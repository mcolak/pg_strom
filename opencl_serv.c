/*
 * opencl_serv.o
 *
 * Server implementation to manage OpenCL devices and compute given
 * requests.
 *
 * --
 * Copyright 2013 (c) PG-Strom Development Team
 * Copyright 2011-2012 (c) KaiGai Kohei <kaigai@kaigai.gr.jp>
 *
 * This software is an extension of PostgreSQL; You can use, copy,
 * modify or distribute it under the terms of 'LICENSE' included
 * within this package.
 */
#include "postgres.h"
#include "fmgr.h"
#include "miscadmin.h"
#include "postmaster/bgworker.h"
#include "storage/ipc.h"
#include "storage/latch.h"
#include "storage/proc.h"
#include "pg_strom.h"

static bool clserv_running = true;

static void
pgstrom_opencl_sigterm(SIGNAL_ARGS)
{
	int		save_errno = errno;

	clserv_running = false;
	if (MyProc)
		SetLatch(&MyProc->procLatch);

	errno = save_errno;
}

static void
pgstrom_opencl_sighup(SIGNAL_ARGS)
{
	elog(LOG, "OpenCL Server got sighup");
	if (MyProc)
		SetLatch(&MyProc->procLatch);
}

static void
pgstrom_opencl_main(void *arg)
{
	/* We're now ready to receive signals */
	BackgroundWorkerUnblockSignals();

	while (clserv_running)
	{
		int		rc;

		rc = WaitLatch(&MyProc->procLatch,
					   WL_LATCH_SET | WL_TIMEOUT | WL_POSTMASTER_DEATH,
					   600 * 1000);
		ResetLatch(&MyProc->procLatch);

		/* emergency bailout if postmaster has died */
		if (rc & WL_POSTMASTER_DEATH)
			proc_exit(1);
	}
	proc_exit(0);
}

void
pgstrom_opencl_server_init(void)
{
	BackgroundWorker    worker;

	worker.bgw_name = "PG-Strom OpenCL Server";
	worker.bgw_flags = BGWORKER_SHMEM_ACCESS;
	worker.bgw_start_time = BgWorkerStart_RecoveryFinished;
	worker.bgw_restart_time = 5;
	worker.bgw_main = pgstrom_opencl_main;
	worker.bgw_main_arg = NULL;
	worker.bgw_sighup = pgstrom_opencl_sighup;
	worker.bgw_sigterm = pgstrom_opencl_sigterm;

	RegisterBackgroundWorker(&worker);
}
