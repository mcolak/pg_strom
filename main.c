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
#include "access/reloptions.h"
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
 * pgstrom_fdw_handler
 *
 * It is provider of FDW routines of PG-Strom
 */
Datum
pgstrom_fdw_handler(PG_FUNCTION_ARGS)
{
	PG_RETURN_POINTER(&PgStromFdwHandlerData);
}
PG_FUNCTION_INFO_V1(pgstrom_fdw_handler);

/*
 * pgstrom_fdw_validator
 *
 * FDW option validator of PG-Strom, even though no options are
 * not supported right now.
 */
Datum
pgstrom_fdw_validator(PG_FUNCTION_ARGS)
{
	Datum		rawopts = PG_GETARG_DATUM(0);
	List	   *options_list;
	ListCell   *cell;

	options_list = untransformRelOptions(rawopts);
	foreach (cell, options_list)
	{
		DefElem *defel = lfirst(cell);

		ereport(ERROR,
				(errcode(ERRCODE_FDW_INVALID_OPTION_NAME),
				 errmsg("invalid option \"%s\"", defel->defname)));
	}
	PG_RETURN_VOID();
}
PG_FUNCTION_INFO_V1(pgstrom_fdw_validator);

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

	/* Initialize shared memory management */
	pgstrom_shmem_init();

	/* Initialize FDW stuff */
	memset(&PgStromFdwHandlerData, 0, sizeof(FdwRoutine));
	PgStromFdwHandlerData.type = T_FdwRoutine;
	pgstrom_fdw_plan_init(&PgStromFdwHandlerData);
	pgstrom_fdw_scan_init(&PgStromFdwHandlerData);
	pgstrom_fdw_modify_init(&PgStromFdwHandlerData);

	/* Initialize OpenCL relevant stuff */
	pgstrom_opencl_entry_init();
	pgstrom_opencl_server_init();

	/* Registration of utility command hooks */
	pgstrom_utilcmds_init();

	/* Initialize vacuum stuff */
	pgstrom_vacuum_init();
}
