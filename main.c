/*
 * main.c
 *
 * Entrypoint of the PG-Strom extension
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
#include "foreign/foreign.h"
#include "miscadmin.h"
#include "utils/rel.h"
#include "pg_strom.h"

PG_MODULE_MAGIC;

/*
 * Local declarations
 */
void		_PG_init(void);

static FdwRoutine	PgStromFdwHandlerData;

/*
 * pgstrom_fdw_handler - FDW Handler function of PG-Strom
 */
Datum
pgstrom_fdw_handler(PG_FUNCTION_ARGS)
{
	PG_RETURN_POINTER(&PgStromFdwHandlerData);
}
PG_FUNCTION_INFO_V1(pgstrom_fdw_handler);

bool
is_pgstrom_managed_server(const char *serv_name)
{
	ForeignServer	   *serv = GetForeignServerByName(serv_name, false);
	ForeignDataWrapper *fdw = GetForeignDataWrapper(serv->fdwid);

	if (GetFdwRoutine(fdw->fdwhandler) == &PgStromFdwHandlerData)
		return true;
	return false;
}

bool
is_pgstrom_managed_relation(Relation relation)
{
	Oid		relid = RelationGetRelid(relation);

	if (GetFdwRoutineByRelId(relid) == &PgStromFdwHandlerData)
		return true;
	return false;
}

void
_PG_init(void)
{
	/*
	 * PG-Strom has to be loaded using shared_preload_libraries option
	 */
	if (!process_shared_preload_libraries_in_progress)
		ereport(ERROR,
				(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
		errmsg("PG-Strom must be loaded via shared_preload_libraries")));

	/* initialize planner/executor stuff */
	memset(&PgStromFdwHandlerData, 0, sizeof(FdwRoutine));
	PgStromFdwHandlerData.type = T_FdwRoutine;
	pgstrom_planner_init(&PgStromFdwHandlerData);
	pgstrom_executor_init(&PgStromFdwHandlerData);

	/* initialize OpenCL computing server */
	pgstrom_opencl_init();

	/* initialize asynchronous columnizer worker */
	pgstrom_columnizer_init();

	/* register utility commands hooks */
	pgstrom_utilcmds_init();
}
