/*
 * modify.c
 *
 * Routines for FDW executor relevant to writer side
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
#include "access/sysattr.h"
#include "catalog/pg_type.h"
#include "nodes/makefuncs.h"
#include "pg_strom.h"

static void
pgstrom_add_foreign_update_targets(Query *parsetree,
								   RangeTblEntry *target_rte,
								   Relation target_relation)
{
	Var		    *var;
	TargetEntry	*tle;

	/* make a junk target-entry to reference ctid system column */
	var = makeVar(parsetree->resultRelation,
				  SelfItemPointerAttributeNumber,
				  TIDOID,
				  -1,
				  InvalidOid,
				  0);
	tle = makeTargetEntry((Expr *) var,
						  list_length(parsetree->targetList) + 1,
						  pstrdup("ctid"),
						  true);
	/* ... and add it to the query's targetlist */
	parsetree->targetList = lappend(parsetree->targetList, tle);
}

static List *
pgstrom_plan_foreign_modify(PlannerInfo *root,
							ModifyTable *plan,
							Index resultRelation,
							int subplan_index)
{
	return NIL;
}

static void
pgstrom_begin_foreign_modify(ModifyTableState *mtstate,
							 ResultRelInfo *rinfo,
							 List *fdw_private,
							 int subplan_index,
							 int eflags)
{}

static TupleTableSlot *
pgstrom_exec_foreign_insert(EState *estate,
							ResultRelInfo *rinfo,
							TupleTableSlot *slot,
							TupleTableSlot *planSlot)
{
	return NULL;
}

static TupleTableSlot *
pgstrom_exec_foreign_update(EState *estate,
							ResultRelInfo *rinfo,
							TupleTableSlot *slot,
							TupleTableSlot *planSlot)
{
	return NULL;
}

static TupleTableSlot *
pgstrom_exec_foreign_delete(EState *estate,
							ResultRelInfo *rinfo,
							TupleTableSlot *slot,
							TupleTableSlot *planSlot)
{
	return NULL;
}

static void
pgstrom_end_foreign_modify(EState *estate,
						   ResultRelInfo *rinfo)
{}

static void
pgstrom_explain_foreign_modify(ModifyTableState *mtstate,
							   ResultRelInfo *rinfo,
							   List *fdw_private,
							   int subplan_index,
							   struct ExplainState *es)
{}

void
pgstrom_fdw_modify_init(FdwRoutine *fdw_routine)
{
	fdw_routine->AddForeignUpdateTargets = pgstrom_add_foreign_update_targets;
	fdw_routine->PlanForeignModify = pgstrom_plan_foreign_modify;
	fdw_routine->BeginForeignModify = pgstrom_begin_foreign_modify;
	fdw_routine->ExecForeignInsert = pgstrom_exec_foreign_insert;
	fdw_routine->ExecForeignUpdate = pgstrom_exec_foreign_update;
	fdw_routine->ExecForeignDelete = pgstrom_exec_foreign_delete;
	fdw_routine->EndForeignModify = pgstrom_end_foreign_modify;
	fdw_routine->ExplainForeignModify = pgstrom_explain_foreign_modify;
}
