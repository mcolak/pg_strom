/*
 * columnizer.c
 *
 * Columnizer implementation to move data chunks between row-store and
 * column-store in background jobs.
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
#include "miscadmin.h"
#include "postmaster/bgworker.h"
#include "storage/ipc.h"
#include "storage/latch.h"
#include "storage/proc.h"
#include "pg_strom.h"

static bool	got_sigterm = false;

static void
columnizer_sigterm(SIGNAL_ARGS)
{
	int		save_errno = errno;

	got_sigterm = true;
	if (MyProc)
		SetLatch(&MyProc->procLatch);

	errno = save_errno;
}

static void
columnizer_sighup(SIGNAL_ARGS)
{
	elog(LOG, "columnizer got sighup!");
	if (MyProc)
		SetLatch(&MyProc->procLatch);
}

static void
columnizer_main(void *arg)
{
	/* We're now ready to receive signals */
	BackgroundWorkerUnblockSignals();

	while (!got_sigterm)
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
pgstrom_columnizer_init(void)
{
	BackgroundWorker	worker;

	worker.bgw_name = "PG-Strom Columnizer";
	worker.bgw_flags = BGWORKER_SHMEM_ACCESS;
	worker.bgw_start_time = BgWorkerStart_RecoveryFinished;
	worker.bgw_restart_time = BGW_NEVER_RESTART;
	worker.bgw_main = columnizer_main;
	worker.bgw_main_arg = NULL;
	worker.bgw_sighup = columnizer_sighup;
    worker.bgw_sigterm = columnizer_sigterm;

	RegisterBackgroundWorker(&worker);
}
