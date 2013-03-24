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
#include "utils/guc.h"
#include "pg_strom.h"

/* local declarations */
static bool	 columnizer_running = true;
static bool  allow_manual_columnize = false;
static char *columnizer_next_database = NULL;
static int   columnizer_interval = 0;
static shmem_startup_hook_type shmem_startup_hook_next = NULL;

/*
 *
 *
 *
 *
 */
static int64
columuize_next_rowid(Relation rmap_rel, Relation rmap_idx)
{
	IndexScanDesc	scan;
	HeapTuple		tuple;
	int64			result = 0;

	scan = index_beginscan(rmap_rel, rmap_idx,
						   GetActiveSnapshot(), 0, 0);
	index_rescan(scan, NULL, 0, NULL, 0);

	tuple = index_getnext(scan, BackwardScanDirection);
	if (HeapTupleIsValid(tuple))
	{
		Datum	values[Natts_pg_strom_rmap];
		bool	isnull[Natts_pg_strom_rmap];

		heap_deform_tuple(tuple, RelationGetDescr(rmap_rel),
						  values, isnull);
		Assert(!isnull[Anum_pg_strom_rmap_rowid - 1]);
		result = DatumGetInt64(values[Anum_pg_strom_rmap_rowid - 1]);
	}
	index_endscan(scan);

	return result + PGSTROM_CHUNK_SIZE;
}

static void
columnize_one_chunk(Relation frel, Relation rmap_rel, Relation cs_rel,
					int64 rowid, Datum **cs_values, bool **is_isnull)
{





}

Datum
pgstrom_columnize(PG_FUNCTION_ARGS)
{
	Oid				frel_oid = PG_GETARG_OID(0);
	Relation		frel;
	Relation		rmap_rel;
	Relation		rmap_idx;
	Relation		cs_rel;
	Relation		rs_rel;
	HeapTuple	   *rs_tuples;
	Datum		   *rs_values;
	bool		   *rs_isnull;
	Datum		  **cs_values;
	bool		  **cs_isnull;
	int64			rowid;
	HeapScanDesc	scan;
	HeapTuple		tuple;
	MemoryContext	oldcxt;
	MemoryContext	tmpcxt;
	int				i, j, nattrs;

	if (!DatumGetBool(DirectFunctionCall1(pgstrom_managed_relation,
										  ObjectIdGetDatum(frel_oid))))
		ereport(ERROR,
				(errcode(ERRCODE_WRONG_OBJECT_TYPE),
				 errmsg("foreign table \"%u\" is not managed by PG-Strom",
						frel_oid)));

	frel = heap_open(PG_GETARG_OID(0), RowExclusiveLock);
	nattrs = RelationGetNumberOfAttributes(frel);

	rmap_rel = pgstrom_open_shadow_rmap(frel, RowExclusiveLock);
	rmap_idx = pgstrom_open_shadow_rmap_index(frel, RowExclusiveLock);
	cs_rel = pgstrom_open_shadow_cstore(frel, RowExclusiveLock);
	rs_rel = pgstrom_open_shadow_cstore(frel, RowExclusiveLock);

	/* foreign-table and row-store must have compatible layout */
	if (!pgstrom_check_relation_compatible(frel, rs_rel))
		elog(ERROR, "Bug? \"%s\" and \"%s\" has incompatible layout",
			 RelationGetRelationName(frel),
			 RelationGetRelationName(rs_rel));

	tmpcxt = AllocSetContextCreate(CurrentMemoryContext,
								   "per-chunk memory context",
								   ALLOCSET_SMALL_MINSIZE,
								   ALLOCSET_SMALL_INITSIZE,
								   ALLOCSET_SMALL_MAXSIZE);

	/* Buffers to scan row-store */
	rs_tuple  = palloc0(sizeof(HeapTuple) * PGSTROM_CHUNK_SIZE);
	rs_values = palloc0(sizeof(Datum) * nattrs);
	rs_isnull = palloc0(sizeof(bool) * nattrs);
	cs_values = palloc0(sizeof(Datum *) * nattrs);
	cs_isnull = palloc0(sizeof(bool *) * nattrs);
	for (i=0; i < nattrs; i++)
	{
		cs_values[i] = palloc0(sizeof(Datum) * PGSTROM_CHUNK_SIZE);
		cs_isnull[i] = palloc0(sizeof(bool) * PGSTROM_CHUNK_SIZE);
	}
	rowid = columnize_next_rowid(rmap_rel, rmap_idx);

	/* Scan the row-store */
	scan = heap_beginscan(rs_rel, GetActiveSnapshot(), 0, NULL);
	oldcxt = MemoryContextSwitchTo(tmpcxt);
	j = 0;
	while (HeapTupleIsValid(tuple = heap_getnext(scan, ForwardScanDirection)))
	{
		rs_tuple[j] = heap_copytuple(tuple);

		heap_deform_tuple(tuple, RelationGetDescr(rs_rel),
						  rs_value, rs_isnull);
		for (i=0; i < nattrs; i++)
		{
			cs_values[i][j] = rs_values[i];
			cs_isnull[i][j] = rs_isnull[i];
		}

		if (++j == PGSTROM_CHUNK_SIZE)
		{
			columnize_one_chunk(frel, rmap_rel, cs_rel,
								rowid, cs_values, cs_isnull);

			for (j=0; j < PGSTROM_CHUNK_SIZE; j++)
				simple_heap_delete(rs_rel, &rs_tuples[j]->t_self);
			j = 0;
			rowid += PGSTROM_CHUNK_SIZE;
			MemoryContextReset(tmpcxt);
		}
	}
	MemoryContextSwitchTo(oldcxt);
	heap_endscan(scan);

	/* Release buffers */
	pfree(rs_tuples);
	pfree(rs_values);
	pfree(rs_isnull);
	for (i=0; i < nattrs; i++)
	{
		pfree(cs_values[i]);
		pfree(cs_isnull[i]);
	}
	pfree(cs_values);
	pfree(cs_isnull);

	MemoryContextDelete(tmpcxt);

	relation_close(rs_rel, RowExclusiveLock);
	relation_close(cs_rel, RowExclusiveLock);
	relation_close(rmap_idx, RowExclusiveLock);
	relation_close(rmap_rel, RowExclusiveLock);

	heap_close(frel);

	PG_RETURN_VOID();
}
PG_FUNCTION_INFO_V1(pgstrom_columnize);

/*
 * pgstrom_rowstore_count
 *
 * It returns number of tuples in shadow row-store.
 *
 * XXX - Do we have any good idea to utilize index to know number of
 *       tuples in shasow row store?
 */
Datum
pgstrom_rowstore_count(PG_FUNCTION_ARGS)
{
	Relation		frel;
	Relation		rstore;
	HeapScanDesc	scan;
	HeapTuple		tup;
	int64			result = 0;

	frel = heap_open(PG_GETARG_OID(0), AccessShareLock);
	rstore = pgstrom_open_shadow_rstore(frel, AccessShareLock);

	scan = heap_beginscan(rstore, GetActiveSnapshot(), 0, NULL);
	while (HeapTupleIsValid(tup = heap_getnext(scan, ForwardScanDirection)))
		result++;
	heap_endscan(scan);

	heap_close(rstore, AccessShareLock);
	heap_close(frel, AccessShareLock);

	PG_RETURN_INT64(result);
}
PG_FUNCTION_INFO_V1(pgstrom_rowstore_count);

/*
 * pgstrom_colstore_count
 *
 * It returns number of tuples in shadow column-store.
 */
Datum
pgstrom_colstore_count(PG_FUNCTION_ARGS)
{
	elog(ERROR, "%s is not implemented now", __FUNCTION__);
}
PG_FUNCTION_INFO_V1(pgstrom_colstore_count);

/*
 * refresh_next_database
 *
 * It updates columnizer_next_database for next invocation of this
 * background worker process.
 */
static void
refresh_next_database(void)
{
	StringInfoData	sql;
	int		rc;
	bool	has_retried = false;

	initStringInfo(&sql);
	appendStringInfo(&sql,
					 "SELECT datname "
					 "FROM pg_catalog.pg_database "
					 "WHERE datname > '%s' AND NOT datistemplate "
					 "ORDER BY datname",
					 quote_identifier(columnizer_next_database));
retry:
	rc = SPI_execute(sql.data, true, 1);
	if (rc != SPI_OK_SELECT)
		elog(FATAL, "could not run - %s : error code (%s)",
			 sql.data, SPI_result_code_string(rc));
	if (SPI_processed > 0)
	{
		SPITupleTable  *tuptable = SPI_tuptable;
		TupleDescj	   *tupdesc = tuptable->tupdesc;
		const char	   *datname;

		Assert(SPI_processed == 1);

		datname = SPI_getvalue(tuptable->vals[0], tuptable->tupdesc, 1);
		Assert(datname != NULL);

		strncpy(columnizer_next_database, datname, NAMEDATALEN + 1);

		return;
	}
	Assert(!has_retried);
	resetStringInfo(&sql);
	appendStringInfo(&sql,
					 "SELECT datname "
					 "FROM pg_catalog.pg_database "
					 "WHERE NOT datistemplate "
					 "ORDER BY datname");
	has_retried = true;
	goto retry;
}








static void
columnizer_sigterm(SIGNAL_ARGS)
{
	int		save_errno = errno;

	columnizer_running = false;
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
	sigjmp_buf	local_sigjmp_buf;

	/* Connect to the next candidate database */
	BackgroundWorkerInitializeConnection(columnizer_next_database, NULL);

	/*
	 * If an exception is encountered, processing resumes here.
	 *
	 * See notes in postgres.c about the design of this coding.
	 */
	if (sigsetjmp(local_sigjmp_buf, 1) != 0)
	{
		/* Since not using PG_TRY, must reset error stack by hand */
		error_context_stack = NULL;

		/* Prevent interrupts while cleaning up */
		HOLD_INTERRUPTS();

		/* Report the error to the server log */
		EmitErrorReport();

		/*
		 * We can now go away, but status code is zero for restarting.
		 * Note that because we called InitProcess, a callback was
		 * registered to do ProcKill, which will clean up necessary state.
		 */
        proc_exit(0);
	}

	/* We can now handle ereport(ERROR) */
    PG_exception_stack = &local_sigjmp_buf;

	/* We're now ready to receive signals */
	BackgroundWorkerUnblockSignals();

	elog(LOG, "PG-Strom columnizer connected to \"%s\"",
		 columnizer_next_database);

	/*
	 * Start a transactional commands
	 */
	StartTransactionCommand();
	SPI_connect();
	PushActiveSnapshot(GetTransactionSnapshot());

	/*
	 * Refresh next database to be connected to
	 */
	refresh_next_database();

	/*
	 * Do the jobs
	 */
	initStringInfo(&sql);
	appendStringInfo(&sql,
					 "SELECT oid, relname "
					 "FROM pg_catalog.pg_class "
					 "WHERE relkind = 'f' AND "
					 "      pgstrom_managed_relation(oid) AND "
					 "      pgstrom_rowstore_count(oid) > %lu",
					 PGSTROM_CHUNK_SIZE);

	rc = SPI_execute(sql.data, true, 0);
	if (rc != SPI_OK_SELECT)
		elog(FATAL, "could not run query - %s : error code (%s)",
			 sql.data, SPI_result_code_string(rc));

	for (i=0; i < SPI_processed && columnizer_running; i++)
	{
		Datum	value;
		bool	isnull;

		value = SPI_getbinval(SPI_tuptable->vals[i],
							  SPI_tuptable->tupdesc,
							  1, &isnull);
		Assert(!isnull);

		(void) DirectFunctionCall1(pgstrom_columnize,
								   DatumGetObjectId(value));
	}

	/*
	 * Commit current transaction
	 */
	PopActiveSnapshot();
	SPI_finish();
    CommitTransactionCommand();

	proc_exit(0);
}

static void
columnizer_shmem_startup(void)
{
	bool	found;

	columnizer_next_database
		= ShmemInitStruct("next target database of columnizer",
						  sizeof(char) * (NAMEDATALEN + 1));
	Assert(!found);

	/*
	 * XXX - we assume "template1" database never dropped
	 */
	strcpy(columnizer_next_database, "template1");
}

void
pgstrom_columnizer_init(void)
{
	BackgroundWorker	worker;

	/* GUC */
    DefineCustomIntVariable("pg_strom.columnizer_interval",
                            "interval in seconds to launch columnizer",
                            NULL,
                            &columnizer_interval,
							30,
							2,
							INT_MAX,
							PGC_POSTMASTER,
							0,
							NULL, NULL, NULL);
	DefineCustomBoolVariable("pg_strom.allow_manual_columnize",
							 "allows backend to execute columnization",
							 NULL,
							 &allow_manual_columnize,
							 false,
							 PGC_POSTMASTER,
							 0,
							 NULL, NULL, NULL);

	/* register share memory startup hook */
	shmem_startup_hook_next = shmem_startup_hook;
	shmem_startup_hook = columnizer_shmem_startup;

	/* register a background worker process */
	worker.bgw_name = "PG-Strom Columnizer";
	worker.bgw_flags
		= BGWORKER_SHMEM_ACCESS | BGWORKER_BACKEND_DATABASE_CONNECTION;
	worker.bgw_start_time = BgWorkerStart_RecoveryFinished;
	worker.bgw_restart_time = columnizer_interval;
	worker.bgw_main = columnizer_main;
	worker.bgw_main_arg = NULL;
	worker.bgw_sighup = columnizer_sighup;
	worker.bgw_sigterm = columnizer_sigterm;

	RegisterBackgroundWorker(&worker);
}
