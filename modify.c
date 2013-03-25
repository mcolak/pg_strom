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
#include "catalog/indexing.h"
#include "catalog/pg_type.h"
#include "executor/executor.h"
#include "nodes/makefuncs.h"
#include "utils/fmgroids.h"
#include "utils/rel.h"
#include "pg_strom.h"
#include <inttypes.h>

typedef struct {
	/* planner's information */
	AttrNumber		ctid_attno;

	/* relevant relations and scans */
	Relation		frel;
	Relation		rmap_rel;
	Relation		rmap_idx;
	Relation		rs_rel;
	Relation		rs_idx;
	IndexScanDesc	rmap_scan;
	IndexScanDesc	rs_scan;
	Datum		   *rs_values;
	bool		   *rs_isnull;

	/* current rowmap we're sticked on */
	HeapTuple		curr_tuple;
	int64			curr_rowid;
	int32			curr_nitems;
	bytea		   *curr_rowmap;
} StromModifyState;

/*
 * pgstrom_add_foreign_update_targets
 *
 * It adds a junk target entry to reference ctid system column
 */
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
	/*
	 * Right now, nothing special for modify plan
	 */
	return NIL;
}

static void
pgstrom_begin_foreign_modify(ModifyTableState *mtstate,
							 ResultRelInfo *rinfo,
							 List *fdw_private,
							 int subplan_index,
							 int eflags)
{
	StromModifyState *smstate;
	EState	   *estate = mtstate->ps.state;
	Relation	frel = rinfo->ri_RelationDesc;
	LOCKMODE	lockmode = RowExclusiveLock;
	int			nattrs;

	/* Do nothing in EXPLAIN (no ANALYZE) case */
	if (eflags & EXEC_FLAG_EXPLAIN_ONLY)
		return;
	/*
	 * Construction of StromModifyState
	 */
	smstate = palloc0(sizeof(StromModifyState));
	smstate->frel = frel;
	if (mtstate->operation == CMD_UPDATE ||
		mtstate->operation == CMD_DELETE)
	{
		/* Find the ctid resjunk column in the subplan's result */
		Plan   *subplan = mtstate->mt_plans[subplan_index]->plan;

		smstate->ctid_attno
			= ExecFindJunkAttributeInTlist(subplan->targetlist, "ctid");
		if (!AttributeNumberIsValid(smstate->ctid_attno))
			elog(ERROR, "could not find junk ctid column");

		smstate->rmap_rel = pgstrom_open_shadow_rmap(frel, lockmode);
		smstate->rmap_idx = pgstrom_open_shadow_rmap_index(frel, lockmode);
		smstate->rmap_scan = index_beginscan(smstate->rmap_rel,
											 smstate->rmap_idx,
											 estate->es_snapshot,
											 1, 0);
	}
	smstate->rs_rel = pgstrom_open_shadow_rstore(frel, lockmode);
	smstate->rs_idx = pgstrom_open_shadow_rstore_index(frel, lockmode);
	smstate->rs_scan = index_beginscan(smstate->rs_rel,
									   smstate->rs_idx,
									   estate->es_snapshot,
									   1, 0);
	if (!pgstrom_check_relation_compatible(frel, smstate->rs_rel))
		elog(ERROR, "Bug? PG-Strom foreign-table and its underlying row-store has incompatible format");

	/* working memory */
	nattrs = RelationGetNumberOfAttributes(frel);
	smstate->rs_values = palloc0(sizeof(Datum) * nattrs);
	smstate->rs_isnull = palloc0(sizeof(bool) * nattrs);

	/* rowid cache */
	smstate->curr_tuple = NULL;
	smstate->curr_rowid = -1;
	smstate->curr_nitems = 0;
	smstate->curr_rowmap = NULL;

	rinfo->ri_FdwState = smstate;
}

/*
 * row_delete_from_cstore
 *
 * It clears a rowmap entry being specified with rowid.
 * If a negative rowid given, it does not try to clear any entries, but
 * save the cached values.
 */
static void
row_delete_from_cstore(EState *estate, StromModifyState *smstate, int64 rowid)
{
	TupleDesc	tupdesc = RelationGetDescr(smstate->rmap_rel);
	Datum		values[Natts_pg_strom_rmap];
	bool		isnull[Natts_pg_strom_rmap];
	bool		replaces[Natts_pg_strom_rmap];

	if (HeapTupleIsValid(smstate->curr_tuple) &&
		(rowid < smstate->curr_rowid ||
		 rowid >= smstate->curr_rowid + smstate->curr_nitems))
	{
		HeapTuple	newtup;

		memset(values, 0, sizeof(values));
		memset(isnull, 0, sizeof(values));
		memset(replaces, 0, sizeof(replaces));

		values[Anum_pg_strom_rmap_rowmap - 1]
			= PointerGetDatum(smstate->curr_rowmap);
		replaces[Anum_pg_strom_rmap_rowmap - 1] = true;

		newtup = heap_modifytuple(smstate->curr_tuple,
								  tupdesc,
								  values, isnull, replaces);
		/*
		 * Note: we don't expect concurrent updates because scan.c always
		 * acquires tuple-lock on reader side when UPDATE or DELETE command
		 * were given.
		 *
		 * TODO: add feature to remove all the relevant column store when
		 * all the entries of rowmap gets cleared.
		 */
		simple_heap_update(smstate->rmap_rel,
						   &smstate->curr_tuple->t_self,
						   newtup);
		CatalogUpdateIndexes(smstate->rmap_rel, newtup);

		/* Reset old status */
		pfree(smstate->curr_tuple);
		pfree(smstate->curr_rowmap);
		smstate->curr_tuple = NULL;
		smstate->curr_rowid = -1;
		smstate->curr_nitems = 0;
		smstate->curr_rowmap = NULL;
	}

	if (rowid > 0)
	{
		int		index;

		if (!HeapTupleIsValid(smstate->curr_tuple))
		{
			ScanKeyData	skey;
			HeapTuple	tuple;
			int64		new_rowid;
			int32		new_nitems;
			MemoryContext oldcxt;

			ScanKeyInit(&skey,
						Anum_pg_strom_rmap_rowid,
						BTLessEqualStrategyNumber, F_INT8LE,
						Int64GetDatum(rowid));

			index_rescan(smstate->rmap_scan, &skey, 1, NULL, 0);
			tuple = index_getnext(smstate->rmap_scan, BackwardScanDirection);
			if (!HeapTupleIsValid(tuple))
				elog(ERROR, "failed to lookup rowmap for rowid=%" PRIu64,
					 rowid);

			heap_deform_tuple(tuple, tupdesc, values, isnull);
			Assert(!isnull[Anum_pg_strom_rmap_rowid - 1] &&
				   !isnull[Anum_pg_strom_rmap_nitems - 1] &&
				   !isnull[Anum_pg_strom_rmap_rowmap - 1]);
			new_rowid = DatumGetInt64(values[Anum_pg_strom_rmap_rowid-1]);
			new_nitems = DatumGetInt32(values[Anum_pg_strom_rmap_nitems-1]);
			if (rowid < new_rowid || rowid >= new_rowid + new_nitems)
				elog(ERROR, "failed to lookup rowmap with rowid=%" PRIu64,
					 rowid);

			oldcxt = MemoryContextSwitchTo(estate->es_query_cxt);
			smstate->curr_rowid = new_rowid;
			smstate->curr_nitems = new_nitems;
			smstate->curr_rowmap
				= DatumGetByteaPP(values[Anum_pg_strom_rmap_rowmap - 1]);
			smstate->curr_tuple = heap_copytuple(tuple);
			MemoryContextSwitchTo(oldcxt);
		}
		index = rowid - smstate->curr_rowid;
		Assert(index >= 0 && index < smstate->curr_nitems);
		Assert(sizeof(bool) * index < VARSIZE_ANY_EXHDR(smstate->curr_rowmap));

		((bool *)VARDATA(smstate->curr_rowmap))[index] = false;
	}
}

static void
row_insert_into_rstore(EState *estate, StromModifyState *smstate,
					   TupleTableSlot *slot)
{
	HeapTuple	tuple = ExecMaterializeSlot(slot);
	HeapTuple	newtup;
	Oid			newId;

	heap_deform_tuple(tuple, slot->tts_tupleDescriptor,
					  smstate->rs_values,
					  smstate->rs_isnull);

	newtup = heap_form_tuple(RelationGetDescr(smstate->rs_rel),
							 smstate->rs_values,
							 smstate->rs_isnull);

	newId = simple_heap_insert(smstate->rs_rel, newtup);
	CatalogUpdateIndexes(smstate->rs_rel, newtup);

	Assert(OidIsValid(newId));
}

static void
row_update_on_rstore(EState *estate, StromModifyState *smstate,
					 Oid rowid_oid, TupleTableSlot *slot)
{
	ScanKeyData		skey;
	HeapTuple		oldtup;
	HeapTuple		newtup;

	ScanKeyInit(&skey,
				ObjectIdAttributeNumber,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(rowid_oid));
	index_rescan(smstate->rs_scan, &skey, 1, NULL, 0);

	oldtup = index_getnext(smstate->rs_scan, ForwardScanDirection);
	if (!HeapTupleIsValid(oldtup))
		elog(ERROR, "failed to fetch a row-store tuple with oid=%u",
			 rowid_oid);

	heap_deform_tuple(oldtup, slot->tts_tupleDescriptor,
					  smstate->rs_values,
					  smstate->rs_isnull);

	newtup = heap_form_tuple(RelationGetDescr(smstate->rs_rel),
							 smstate->rs_values,
							 smstate->rs_isnull);

	simple_heap_update(smstate->rs_rel, &oldtup->t_self, newtup);
	CatalogUpdateIndexes(smstate->rs_rel, newtup);
}

static TupleTableSlot *
pgstrom_exec_foreign_insert(EState *estate,
							ResultRelInfo *rinfo,
							TupleTableSlot *slot,
							TupleTableSlot *planSlot)
{
	StromModifyState *smstate = rinfo->ri_FdwState;

	row_insert_into_rstore(estate, smstate, slot);

	return slot;
}

static TupleTableSlot *
pgstrom_exec_foreign_update(EState *estate,
							ResultRelInfo *rinfo,
							TupleTableSlot *slot,
							TupleTableSlot *planSlot)
{
	StromModifyState *smstate = rinfo->ri_FdwState;
	Datum		datum;
	bool		isnull;
	int64		rowid;
	ItemPointerData temp;

	/* Get the ctid being passed up as a resjunk column */
	datum = ExecGetJunkAttribute(planSlot,
								 smstate->ctid_attno,
								 &isnull);
	if (isnull)
		elog(ERROR, "Bug? ctid is NULL");

	ItemPointerCopy((ItemPointer)DatumGetPointer(datum), &temp);
	rowid = (((int64)temp.ip_blkid.bi_hi) << 32 |
			 ((int64)temp.ip_blkid.bi_lo) << 16 |
			 ((int64)temp.ip_posid));
	Assert(rowid >= PGSTROM_CHUNK_SIZE);

	if (rowid <= OID_MAX)
		row_update_on_rstore(estate, smstate, (Oid)rowid, slot);
	else
	{
		row_delete_from_cstore(estate, smstate, rowid);
		row_insert_into_rstore(estate, smstate, slot);
	}
	return slot;
}

static TupleTableSlot *
pgstrom_exec_foreign_delete(EState *estate,
							ResultRelInfo *rinfo,
							TupleTableSlot *slot,
							TupleTableSlot *planSlot)
{
	StromModifyState *smstate = rinfo->ri_FdwState;
	Datum		datum;
	bool		isnull;
	int64		rowid;
	ItemPointerData temp;

	/* Get the ctid being passed up as a resjunk column */
	datum = ExecGetJunkAttribute(planSlot,
								 smstate->ctid_attno,
								 &isnull);
	if (isnull)
		elog(ERROR, "Bug? ctid is NULL");

	ItemPointerCopy((ItemPointer)DatumGetPointer(datum), &temp);
	rowid = (((int64)temp.ip_blkid.bi_hi) << 32 |
			 ((int64)temp.ip_blkid.bi_lo) << 16 |
			 ((int64)temp.ip_posid));
	Assert(rowid >= PGSTROM_CHUNK_SIZE);

	row_delete_from_cstore(estate, smstate, rowid);

	return slot;
}

static void
pgstrom_end_foreign_modify(EState *estate,
						   ResultRelInfo *rinfo)
{
	StromModifyState *smstate = rinfo->ri_FdwState;

	if (!smstate)
		return;

	/* flush cached rowmap */
	if (HeapTupleIsValid(smstate->curr_tuple))
		row_delete_from_cstore(estate, smstate, -1);

	/* end index-scan and close relations */
	if (smstate->rmap_scan)
	{
		index_endscan(smstate->rmap_scan);
		index_close(smstate->rmap_idx, NoLock);
		heap_close(smstate->rmap_rel, NoLock);
	}
	index_endscan(smstate->rs_scan);
	index_close(smstate->rs_idx, NoLock);
	heap_close(smstate->rs_rel, NoLock);

	pfree(smstate);
}

static void
pgstrom_explain_foreign_modify(ModifyTableState *mtstate,
							   ResultRelInfo *rinfo,
							   List *fdw_private,
							   int subplan_index,
							   struct ExplainState *es)
{
	elog(ERROR, "no implemented yet");
}

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
