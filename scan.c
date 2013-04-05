/*
 * scan.c
 *
 * Routines for FDW executor relevant to reader side
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
#include "access/xact.h"
#include "executor/executor.h"
#include "lib/stringinfo.h"
#include "miscadmin.h"
#include "storage/bufmgr.h"
#include "utils/fmgroids.h"
#include "utils/guc.h"
#include "utils/lsyscache.h"
#include "utils/memutils.h"
#include "utils/rel.h"
#include "pg_strom.h"
#include <limits.h>

/*
 * TODO: description of data structure here
 *
 */
typedef struct {
	EState		   *estate;
	Snapshot		snapshot;
	StromQueue	   *recvq;
	KernelParams   *kernel_params;
	dlist_head		chunk_ready_list;
	dlist_head		chunk_free_list;
	int				num_total_chunks;
	int				num_running_chunks;

	/* planner's information */
	text		   *kernel_quals;	/* only for EXPLAIN */
	List		   *kernel_cols;
	List		   *result_cols;
	List		   *varlena_cols;
	List		   *host_cols;
	uint32			vlbuf_size;
	bool			needs_ctid;
	bool			parallel_load;

	/* relevant relations and scans */
	Relation		frel;
	Relation		rmap_rel;
	Relation		rmap_idx;
	Relation		cs_rel;
	Relation		cs_idx;
	Relation		rs_rel;
	HeapScanDesc	rmap_scan;
	IndexScanDesc  *cs_scan;
	HeapScanDesc	rs_scan;

	LOCKMODE		lockmode;
	bool			lockmode_nowait;

	/* current cstore window of this scan */
	int				curr_index;
	int64		   *curr_cs_rowid;
	int32		   *curr_cs_nitems;
	bytea		  **curr_cs_isnull;
	bytea		  **curr_cs_values;
	ChunkBuffer	   *curr_chunk;
	VarlenaBuffer  *curr_vlbuf;
} StromExecState;

/*
 * Local declarations
 */
static int	pgstrom_max_async_chunks;

/*
 * extract_kernel_params
 *
 * It extracts the supplied kernel source and parameters to the on-chunk
 * format and copies it on the shared memory segment.
 * It should be available to reference during this table scan.
 */
static KernelParams *
extract_kernel_params(EState *estate,
					  bytea *kernel_source, List *kernel_params)
{
	StringInfoData	str;
	KernelParams   *result;
	bytea		   *params;
	uint32			nparams;
	int				needed;
	int				base_offset;
	int				pindex = 0;
	Datum			zero = 0;
	ListCell	   *cell;

	if (!kernel_source)
		return NULL;

	initStringInfo(&str);
	str.len += sizeof(bytea *);

	/*
	 * Planner should already construct kernek_flags and kernel_digest,
	 * not only kernel_source.
	 */
	appendBinaryStringInfo(&str,
						   VARDATA(kernel_source),
						   VARSIZE_ANY_EXHDR(kernel_source));
	if (str.len != MAXALIGN(str.len))
		appendBinaryStringInfo(&str, (char *)&zero,
							   MAXALIGN(str.len) - str.len);

	*((bytea **)str.data) = params = (bytea *)(str.data + str.len);
	base_offset = str.len;

	/* region for params_num, params_isnull and params_values */
	nparams = list_length(kernel_params);
	needed = MAXALIGN(VARHDRSZ +
					  sizeof(uint32) +
					  MAXALIGN(sizeof(bool) * nparams) +
					  MAXALIGN(sizeof(Datum) * nparams));
	enlargeStringInfo(&str, needed);
	str.len += needed;

	/* number of parameters */
	*((uint32 *)VARDATA(params)) = nparams;

	/*
	 * params->data can be adjusted later if enlargeStringInfo()
	 * re-allocates the buffer of StringInfo, so we need to use macro
	 * to ensure both of params_isnull and params_values are always
	 * valid pointers.
	 */
#define params_isnull ((bool *)(VARDATA(params) + sizeof(uint32)))
#define params_values ((Datum *)(VARDATA(params) + sizeof(uint32) + \
								 MAXALIGN(sizeof(bool) * nparams)))
	memset(params_isnull, -1, sizeof(bool) * nparams);
	memset(params_values,  0, sizeof(Datum) * nparams);

	foreach (cell, kernel_params)
	{
		if (IsA(lfirst(cell), Const))
		{
			Const  *c = (Const *) lfirst(cell);

			if (!c->constisnull)
			{
				if (c->constbyval)
					params_values[pindex] = c->constvalue;
				else
				{
					params_values[pindex] = str.len - base_offset;
					if (c->constlen > 0)
						appendBinaryStringInfo(&str,
											   DatumGetPointer(c->constvalue),
											   c->constlen);
					else
						appendBinaryStringInfo(&str,
										(char *)DatumGetByteaPP(c->constvalue),
										VARSIZE_ANY(c->constvalue));
				}
				params_isnull[pindex] = false;
			}
		}
		else if (IsA(lfirst(cell), Param))
		{
			Param  *p = (Param *) lfirst(cell);
			ParamListInfo	 pinfo = estate->es_param_list_info;
			ParamExternData *ped;

			Assert(p->paramid < pinfo->numParams);
			ped = &pinfo->params[p->paramid];
			if (!ped->isnull)
			{
				int16	typlen;
				bool	typbyval;

				Assert(p->paramtype == ped->ptype);
				get_typlenbyval(ped->ptype, &typlen, &typbyval);

				if (typbyval)
					params_values[pindex] = ped->value;
				else
				{
					params_values[pindex] = str.len - base_offset;
					if (typlen > 0)
						appendBinaryStringInfo(&str,
											   DatumGetPointer(ped->value),
											   typlen);
					else
						appendBinaryStringInfo(&str,
										(char *)DatumGetByteaPP(ped->value),
										VARSIZE_ANY(ped->value));
				}
				params_isnull[pindex] = false;
			}
		}
		else
			elog(ERROR, "unexpected node: %d", nodeTag(lfirst(cell)));

		/* adjust offset alignment */
		needed = MAXALIGN(str.len) - str.len;
		if (needed > 0)
			appendBinaryStringInfo(&str, (char *)&zero, needed);
		pindex++;
	}
	Assert(pindex == nparams);
#undef param_isnull
#undef param_values
	SET_VARSIZE(params, str.len - base_offset);

	/*
	 * Copy it on KernelParams structure on the shared memory segment
	 */
	result = pgstrom_kernel_params_alloc(str.len, true);
	memcpy(result, str.data, str.len);

	pfree(str.data);

	return result;
}

static void
refresh_chunk_buffer(StromExecState *sestate, ChunkBuffer *chunk,
					 uint64 rowid, uint32 nitems)
{
	TupleDesc	tupdesc = RelationGetDescr(sestate->frel);
	uint32		offset = chunk->offset_results;
	int			nfields = chunk->nresults + chunk->nargs;
	int			aindex = 0;
	ListCell   *cell;
	dlist_mutable_iter  iter;

	Assert(nitems <= PGSTROM_CHUNK_SIZE);

	/* Release all the relevant older varlena-buffers */
	dlist_foreach_modify(iter, &chunk->vlbuf_list)
	{
		VarlenaBuffer  *vlbuf
			= dlist_container(VarlenaBuffer, chain, iter.cur);

		pgstrom_varlena_buffer_free(vlbuf);
	}
	Assert(dlist_is_empty(&chunk->vlbuf_list));

	/*
	 * Format of the variable length area is used as follows:
	 *
	 * | ChunkBuffer                  |
	 * +------------------------------+
	 * |        :                     |
	 * | Fixed Length Variables       |
	 * |        :                     |
	 * +------------------------------+
	 * | Datum data[...]              |
	 * |        :                     |
	 * | Variavle Length Field        |
	 * |        :                     |
	 * | <---- (char *)chunk->data + offset_results ---+
	 * |        :                     |                |
	 * | Fields to be write back      |                |
	 * | to host from device.         |                |
	 * | (output of kernel execution) |                |
	 * |        :                     |                |
	 * | <---- (char *)chunk->data + offset_nargs --+  |
	 * | bool  cb_rowmap[nitems]      |             |  |
	 * | <------------------------------------------|--+
	 * |        :                     |             |
	 * | Fields to be sent to OpenCL  |             |
	 * | device for calculation       |             |
	 * | (input of kernel execution)  |             |
	 * |        :                     |             |
	 * +------------------------------+ <-----------+
	 */
	memset(chunk->cb_isnull, 0, sizeof(bool *) * tupdesc->natts);
	memset(chunk->cb_isnull, 0, sizeof(void *) * tupdesc->natts);
	memset(chunk->offset_isnull, 0, sizeof(uint32) * nfields);
	memset(chunk->offset_values, 0, sizeof(uint32) * nfields);

	/*
	 * XXX - code to assign result buffer should be here
	 */
	Assert(list_length(sestate->result_cols) == 0);
	chunk->offset_args = offset;
	chunk->cb_rowmap = ((char *)chunk->data) + offset;
	offset += MAXALIGN(sizeof(bool) * nitems);
	chunk->length_results = offset - chunk->offset_results;

	foreach (cell, sestate->kernel_cols)
	{
		Form_pg_attribute attr;
		AttrNumber j = lfirst_int(cell);

		Assert(j >= 0 && j < tupdesc->natts);
		attr = tupdesc->attrs[j];
		if (!attr->attnotnull)
		{
			chunk->offset_isnull[aindex] = offset - chunk->offset_args;
			chunk->cb_isnull[j] = (bool *)(((char *)chunk->data) + offset);
			offset += MAXALIGN(sizeof(bool) * nitems);
		}

		chunk->offset_values[aindex] = offset - chunk->offset_args;
		chunk->cb_values[j] = (void *)(((char *)chunk->data) + offset);
		if (attr->attlen > 0)
			offset += MAXALIGN(attr->attlen * nitems);
		else
			offset += MAXALIGN(sizeof(uint32) * nitems);
	}
	chunk->length_args = offset - chunk->offset_args;

	chunk->rowid = rowid;
	chunk->nitems = nitems;
	chunk->error_code = 0;
}

/*
 * create_chunk_buffer
 *
 * It allocates a chunk-buffer on shared memory segment with possible
 * maximum length (that will be capable to load a case of nitems == 
 * PGSTROM_CHUNK_SIZE), however, it does not initialize some variables
 * that depends on the given nitems.
 * So, be careful to refresh the chunk prior to use.
 */
static ChunkBuffer *
create_chunk_buffer(StromExecState *sestate, bool abort_on_error)
{
	ChunkBuffer	   *chunk;
	TupleDesc		tupdesc = RelationGetDescr(sestate->frel);
	int				nargs = list_length(sestate->kernel_cols);
	int				nresults = list_length(sestate->result_cols);
	int				nfields = nresults + nargs;
	int				aindex;
	size_t			offset;
	size_t			length;
	ListCell	   *cell;

	length = offsetof(ChunkBuffer, data);
	length += MAXALIGN((sizeof(Oid) +
						sizeof(FormData_pg_attribute) * nfields +
						sizeof(uint32) * nfields +
						sizeof(uint32) * nfields +
						sizeof(bool *) * tupdesc->natts +
						sizeof(void *) * tupdesc->natts));
	/*
	 * XXX - Right now, interface of PostgreSQL does not support to off-load
	 * calculation results into external computing resources. Once it gets
	 * supported, we also allocate region to back the calculation results
	 * from OpenCL calculation server.
	 */
	Assert(nresults == 0);

	/* For rowid map */
	length += MAXALIGN(sizeof(bool) * PGSTROM_CHUNK_SIZE);

	/* For kernel arguments */
	foreach (cell, sestate->kernel_cols)
	{
		Form_pg_attribute attr;
		AttrNumber	j = lfirst_int(cell) - 1;

		Assert(j >= 0 && j < tupdesc->natts);
		attr = tupdesc->attrs[j];

		if (attr->attlen > 0)
			length += MAXALIGN(attr->attlen * PGSTROM_CHUNK_SIZE);
		else
			length += MAXALIGN(sizeof(uint32) * PGSTROM_CHUNK_SIZE);
	}

	/*
	 * Allocation on the shared memory segment
	 */
	chunk = pgstrom_chunk_buffer_alloc(length, abort_on_error);
	if (!chunk)
		return NULL;

	/*
	 * Initialization of persistent fields independent from rowid and
	 * nitems to be loaded.
	 *
	 * NOTE: lock, cond and vlbuf_list shall be initialized on allocation.
	 * NULL shall be set on recvq and kernel_params. False shall be set
	 * on is_loaded and is_running.
	 */
	chunk->nargs = nargs;
	chunk->nresults = nresults;
	chunk->nvarlena = 0;
	chunk->cb_databaseid = MyDatabaseId;
	chunk->error_code = 0;
	chunk->rs_cache = NULL;
	chunk->rs_memcxt = NULL;

	/*
	 * variable length field
	 */
	offset = 0;
	chunk->cb_isnull = (bool **)(((char *)chunk->data) + offset);
	offset += MAXALIGN(sizeof(bool *) * tupdesc->natts);
	chunk->cb_values = (void **)(((char *)chunk->data) + offset);
	offset += MAXALIGN(sizeof(void *) * tupdesc->natts);
	chunk->cb_attrs = (Form_pg_attribute)(((char *)chunk->data) + offset);
	offset += MAXALIGN(sizeof(ATTRIBUTE_FIXED_PART_SIZE) * nfields);
	chunk->offset_isnull = (uint32 *)(((char *)chunk->data) + offset);
	offset += MAXALIGN(sizeof(uint32) * nfields);
	chunk->offset_values = (uint32 *)(((char *)chunk->data) + offset);
	offset += MAXALIGN(sizeof(uint32) * nfields);
	chunk->offset_results = offset;
	chunk->offset_args = 0;		/* to be set on refresh */

	/*
	 * Copy of FormData_pg_attribute, because it is never changed during
	 * a particular foreign table scan.
	 *
	 * XXX - needs to add code when result_cols gets supported
	 */
	aindex = 0;
	foreach (cell, sestate->kernel_cols)
	{
		Form_pg_attribute attr = tupdesc->attrs[lfirst_int(cell) - 1];

		memcpy(&chunk->cb_attrs[aindex], attr, ATTRIBUTE_FIXED_PART_SIZE);
		aindex++;
	}
	Assert(aindex == nfields);

	return chunk;
}

static void
pgstrom_begin_foreign_scan(ForeignScanState *fss, int eflags)
{
	ForeignScan	   *fscan = (ForeignScan *) fss->ss.ps.plan;
	Relation		frel = fss->ss.ss_currentRelation;
	TupleDesc		tupdesc = RelationGetDescr(frel);
	bytea		   *kernel_source = NULL;
	text		   *kernel_quals = NULL;
	List		   *kernel_params = NIL;
	List		   *kernel_cols = NIL;
	List		   *varlena_cols = NIL;
	List		   *host_cols = NIL;
	List		   *union_cols = NIL;
	uint32			vlbuf_size = 65536;	/* 64MB */
	LOCKMODE		lockmode = AccessShareLock;
	bool			lockmode_nowait = false;
	bool			needs_ctid = false;
	bool			parallel_load = false;
	StromExecState *sestate;
	ChunkBuffer	   *chunk;
	int				nattrs;
	ListCell	   *cell;

	/* Do nothing for EXPLAIN or ANALYZE case */
	if (eflags & EXEC_FLAG_EXPLAIN_ONLY)
		return;

	/*
	 * Fetch planner's information
	 */
	foreach (cell, fscan->fdw_private)
	{
		DefElem	   *defel = (DefElem *) lfirst(cell);

		if (strcmp(defel->defname, "kernel_source") == 0)
			kernel_source = DatumGetByteaP(((Const *)defel->arg)->constvalue);
		else if (strcmp(defel->defname, "kernel_quals") == 0)
			kernel_quals = DatumGetTextP(((Const *)defel->arg)->constvalue);
		else if (strcmp(defel->defname, "kernel_params") == 0)
			kernel_params = lappend(kernel_params, defel->arg);
		else if (strcmp(defel->defname, "kernel_cols") == 0)
		{
			Form_pg_attribute attr;
			AttrNumber	attnum = intVal(defel->arg);

			if (attnum < 1 || attnum > tupdesc->natts)
				elog(ERROR, "columns referenced by kernel out of range: %d",
					 attnum);
			attr = tupdesc->attrs[attnum - 1];
			Assert(!attr->attisdropped);
			kernel_cols = lappend_int(kernel_cols, attr->attnum);
			if (attr->attlen < 0)
				varlena_cols = lappend_int(varlena_cols, attr->attnum);
		}
		else if (strcmp(defel->defname, "host_cols") == 0)
		{
			AttrNumber	attnum = intVal(defel->arg);

			if (attnum > tupdesc->natts)
				elog(ERROR, "columns referenced by host out of range: %d",
					 attnum);
			if (attnum > 0)
				host_cols = lappend_int(host_cols, attnum);
			else if (attnum == SelfItemPointerAttributeNumber)
				needs_ctid = true;
		}
		else if (strcmp(defel->defname, "vlbuf_size") == 0)
			vlbuf_size = intVal(defel->arg);
		else if (strcmp(defel->defname, "lockmode") == 0)
		{
			if (strcmp(strVal(defel->arg), "nolock") == 0)
				lockmode = AccessShareLock;
			else if (strcmp(strVal(defel->arg), "shared") == 0)
				lockmode = RowShareLock;
			else if (strcmp(strVal(defel->arg), "exclusive") == 0)
				lockmode = RowExclusiveLock;
			else
				elog(ERROR, "unexpected lockmode: %s", strVal(defel->arg));
		}
		else if (strcmp(defel->defname, "lockmode-nowait") == 0)
			lockmode_nowait = intVal(defel->arg);
		else
			elog(ERROR, "PG-Strom: unsupported planner option: %s",
				 defel->defname);
	}

	/*
	 * Construction of StromExecState
	 */
	sestate = palloc0(sizeof(StromExecState));
	sestate->estate = fss->ss.ps.state;
	sestate->snapshot = sestate->estate->es_snapshot;
	sestate->recvq = pgstrom_queue_alloc(true);
	sestate->kernel_params = extract_kernel_params(sestate->estate,
												   kernel_source,
												   kernel_params);
	dlist_init(&sestate->chunk_ready_list);
	dlist_init(&sestate->chunk_free_list);
	sestate->num_total_chunks = 0;
	sestate->num_running_chunks = 0;

	sestate->kernel_quals = kernel_quals;
	sestate->kernel_cols = kernel_cols;
	sestate->result_cols = NIL;
	sestate->varlena_cols = varlena_cols;
	sestate->host_cols = host_cols;
	sestate->vlbuf_size = vlbuf_size;
	sestate->lockmode = lockmode;
	sestate->lockmode_nowait = lockmode_nowait;
	sestate->needs_ctid = needs_ctid;
	sestate->parallel_load = parallel_load;

	/* Open the shadow relations */
	nattrs = tupdesc->natts;
	sestate->frel = frel;
	sestate->rmap_rel = pgstrom_open_shadow_rmap(frel, lockmode);
	sestate->rmap_idx = pgstrom_open_shadow_rmap_index(frel, lockmode);
	sestate->cs_rel = pgstrom_open_shadow_cstore(frel, AccessShareLock);
	sestate->cs_idx = pgstrom_open_shadow_cstore_index(frel, AccessShareLock);
	sestate->rs_rel = pgstrom_open_shadow_rstore(frel, lockmode);
	sestate->cs_scan = palloc0(sizeof(IndexScanDesc) * nattrs);

	/* Construction of column-store scan window */
	sestate->curr_cs_rowid = palloc0(sizeof(int64) * nattrs);
	sestate->curr_cs_nitems = palloc0(sizeof(int32) * nattrs);
	sestate->curr_cs_isnull = palloc0(sizeof(bytea *) * nattrs);
	sestate->curr_cs_values = palloc0(sizeof(bytea *) * nattrs);
	sestate->curr_chunk = NULL;
	sestate->curr_vlbuf = NULL;
	memset(sestate->curr_cs_rowid, -1, sizeof(int64) * nattrs);

	/* Begin to scan on the shadow relations */
	sestate->rmap_scan = heap_beginscan(sestate->rmap_rel,
										sestate->snapshot, 0, NULL);
	sestate->rs_scan = heap_beginscan(sestate->rs_rel,
									  sestate->snapshot, 0, NULL);
	union_cols = list_concat_unique_int(kernel_cols, host_cols);
	foreach (cell, union_cols)
	{
		AttrNumber	j = lfirst_int(cell) - 1;

		sestate->cs_scan[j] = index_beginscan(sestate->cs_rel,
											  sestate->cs_idx,
											  sestate->snapshot,
											  2, 0);
	}
	list_free(union_cols);

	/* Allocate a chunk-buffer */
	chunk = create_chunk_buffer(sestate, true);
	dlist_push_tail(&sestate->chunk_free_list, &chunk->chain);
	sestate->num_total_chunks++;

	/* Save the StromExecState */
	fss->fdw_state = sestate;
}

static inline void
pgstrom_invalidate_window(StromExecState *sestate, AttrNumber attnum)
{
	AttrNumber	j = attnum - 1;

	if (sestate->curr_cs_values[j])
	{
		pfree(sestate->curr_cs_values[j]);
		sestate->curr_cs_values[j] = NULL;
	}
	if (sestate->curr_cs_isnull[j])
	{
		pfree(sestate->curr_cs_isnull[j]);
		sestate->curr_cs_isnull[j] = NULL;
	}
	sestate->curr_cs_rowid[j] = -1;
	sestate->curr_cs_nitems[j] = 0;
}

static bool
pgstrom_do_seek_window(StromExecState *sestate,
					   AttrNumber attnum, int64 rowid)
{
	MemoryContext	oldcxt;
	TupleDesc		tupdesc = RelationGetDescr(sestate->cs_rel);
	HeapTuple		tuple = NULL;
	ScanKeyData		skeys[2];
	Datum			values[Natts_pg_strom_cs];
	bool			isnull[Natts_pg_strom_cs];
	AttrNumber		new_attnum;
	int64			new_rowid;
	int32			new_nitems;
	AttrNumber		j = attnum - 1;
	bool			might_neighbor = false;

	if (sestate->curr_cs_rowid[j] >= 0 &&
		rowid < (sestate->curr_cs_rowid[j] + 2 * sestate->curr_cs_nitems[j]))
		might_neighbor = true;

	/* Clear the cached values */
	pgstrom_invalidate_window(sestate, attnum);

	if (might_neighbor)
	{
		tuple = index_getnext(sestate->cs_scan[j], ForwardScanDirection);
		if (HeapTupleIsValid(tuple))
		{
			heap_deform_tuple(tuple, tupdesc, values, isnull);

			new_attnum = DatumGetInt16(values[Anum_pg_strom_cs_attnum - 1]);
			new_rowid = DatumGetInt64(values[Anum_pg_strom_cs_rowid - 1]);
			new_nitems = DatumGetInt32(values[Anum_pg_strom_cs_nitems - 1]);
			Assert(attnum == new_attnum);

			if (rowid < new_rowid || rowid >= new_rowid + new_nitems)
				tuple = NULL;
		}
	}

	if (!HeapTupleIsValid(tuple))
	{
		ScanKeyInit(&skeys[0],
					Anum_pg_strom_cs_attnum,
					BTEqualStrategyNumber, F_INT2EQ,
					Int16GetDatum(attnum));
		ScanKeyInit(&skeys[1],
					Anum_pg_strom_cs_rowid,
					BTLessEqualStrategyNumber, F_INT8LE,
					Int64GetDatum(rowid));
		index_rescan(sestate->cs_scan[j], skeys, 2, NULL, 0);

		tuple = index_getnext(sestate->cs_scan[j], BackwardScanDirection);
		if (!HeapTupleIsValid(tuple))
			return false;

		heap_deform_tuple(tuple, tupdesc, values, isnull);
		Assert(!isnull[Anum_pg_strom_cs_attnum - 1] &&
			   !isnull[Anum_pg_strom_cs_rowid - 1] &&
			   !isnull[Anum_pg_strom_cs_nitems - 1]);

		new_attnum = DatumGetInt16(values[Anum_pg_strom_cs_attnum - 1]);
		new_rowid = DatumGetInt64(values[Anum_pg_strom_cs_rowid - 1]);
		new_nitems = DatumGetInt32(values[Anum_pg_strom_cs_nitems - 1]);

		/*
		 * Even we tried to fetch a tuple with biggest rowid in the
		 * condition: tuple.attnum = attnum AND tuple.rowid <= rowid,
		 * the fetched tuple does not contain what we want to do see.
		 * It means nothing are between rowid and new_rowid - 1
		 * in this column-store.
		 */
		if (rowid < new_rowid || rowid >= new_rowid + new_nitems)
			return false;

		/*
		 * Due to the data structure, index-scan has backward direction.
		 * It needs to be fixed to the forward direction for the next
		 * neighbor fetch.
		 */
		ScanKeyInit(&skeys[0],
					Anum_pg_strom_cs_attnum,
					BTEqualStrategyNumber, F_INT2EQ,
					Int16GetDatum(attnum));
		ScanKeyInit(&skeys[1],
					Anum_pg_strom_cs_rowid,
					BTGreaterStrategyNumber, F_INT8GT,
					Int64GetDatum(new_rowid + new_nitems));
		index_rescan(sestate->cs_scan[j], skeys, 2, NULL, 0);
	}
	Assert(HeapTupleIsValid(tuple));

	oldcxt = MemoryContextSwitchTo(sestate->estate->es_query_cxt);
	sestate->curr_cs_rowid[j] = new_rowid;
	sestate->curr_cs_nitems[j] = new_nitems;
	sestate->curr_cs_isnull[j]
		= (!isnull[Anum_pg_strom_cs_isnull - 1]
		   ? DatumGetByteaPP(values[Anum_pg_strom_cs_isnull - 1])
		   : NULL);
	sestate->curr_cs_values[j]
		= DatumGetByteaPP(values[Anum_pg_strom_cs_values - 1]);
	MemoryContextSwitchTo(oldcxt);

	return true;
}

static inline bool
pgstrom_seek_window(StromExecState *sestate, AttrNumber attnum, int64 rowid)
{
	Assert(attnum > 0 &&
		   attnum <= RelationGetNumberOfAttributes(sestate->frel));
	if (rowid >= sestate->curr_cs_rowid[attnum - 1] &&
		rowid < (sestate->curr_cs_rowid[attnum - 1] +
				 sestate->curr_cs_nitems[attnum - 1]))
		return true;
	return pgstrom_do_seek_window(sestate, attnum, rowid);
}

static inline void
pgstrom_load_column_store(StromExecState *sestate, ChunkBuffer *chunk,
						  Form_pg_attribute attr)
{
	ScanKeyData	skeys[2];
	TupleDesc	tupdesc = RelationGetDescr(sestate->cs_rel);
	HeapTuple	tuple;
	int64		rowid = chunk->rowid;
	int32		nitems = chunk->nitems;
	AttrNumber	j = attr->attnum - 1;
	bool	   *cb_isnull = chunk->cb_isnull[j];
	char	   *cb_values = chunk->cb_values[j];

	/* might conflict with column-store window */
	pgstrom_invalidate_window(sestate, attr->attnum);

	ScanKeyInit(&skeys[0],
				Anum_pg_strom_cs_attnum,
				BTEqualStrategyNumber, F_INT2EQ,
				Int16GetDatum(attr->attnum));
	ScanKeyInit(&skeys[1],
				Anum_pg_strom_cs_rowid,
				BTGreaterEqualStrategyNumber, F_INT8GE,
				Int64GetDatum(chunk->rowid));

	index_rescan(sestate->cs_scan[j], skeys, 2, NULL, 0);

	if (cb_isnull)
		memset(cb_isnull, -1, sizeof(bool) * nitems);

	while (HeapTupleIsValid(tuple = index_getnext(sestate->cs_scan[j],
												  ForwardScanDirection)))
	{
		Datum	values[Natts_pg_strom_cs];
		bool	isnull[Natts_pg_strom_cs];
		int64	curr_rowid;
		int32	curr_nitems;
		Datum	curr_isnull;
		Datum	curr_values;

		heap_deform_tuple(tuple, tupdesc, values, isnull);
		Assert(!isnull[Anum_pg_strom_cs_attnum - 1] &&
			   !isnull[Anum_pg_strom_cs_rowid - 1] &&
			   !isnull[Anum_pg_strom_cs_nitems - 1] &&
			   !isnull[Anum_pg_strom_cs_values - 1]);

		curr_rowid = DatumGetInt64(values[Anum_pg_strom_cs_rowid - 1]);
		curr_nitems = DatumGetInt32(values[Anum_pg_strom_cs_nitems - 1]);

		/* Is it overrun? (if tailer block of this chunk is missing) */
		if (curr_rowid >= rowid + nitems)
			break;
		Assert(curr_rowid >= rowid &&
			   curr_rowid + curr_nitems <= rowid + nitems);

		if (cb_isnull)
		{
			if (!isnull[Anum_pg_strom_cs_isnull - 1])
			{
				curr_isnull = values[Anum_pg_strom_cs_isnull - 1];

				toast_extract_datum(cb_isnull + (curr_rowid - rowid),
									(bytea *)DatumGetPointer(curr_isnull),
									sizeof(bool) * curr_nitems);
			}
			else
			{
				memset(cb_isnull + (curr_rowid - rowid),
					   0,
					   sizeof(bool) * curr_nitems);
			}
		}
		Assert(attr->attlen > 0);

		curr_values = values[Anum_pg_strom_cs_values - 1];

		toast_extract_datum(cb_values +
							attr->attlen * (curr_rowid - rowid),
							(bytea *)DatumGetPointer(curr_values),
							attr->attlen * curr_nitems);

		if (curr_rowid + curr_nitems == rowid + nitems)
			break;
	}
}

static inline void
pgstrom_load_varlena(StromExecState *sestate, ChunkBuffer *chunk,
					 int index, bool *rs_isnull, Datum *rs_values)
{
	VarlenaBuffer *vlbuf;
	int64		curr_rowid = chunk->rowid + index;
	int32		curr_usage;
	ListCell   *cell;

	/*
	 * If this row is already removed, no need to load varlena data.
	 * So, simply mark these values as NULL and return.
	 */
	if (!chunk->cb_rowmap[index])
	{
		foreach (cell, sestate->varlena_cols)
		{
			AttrNumber	j = lfirst_int(cell) - 1;

			chunk->cb_isnull[j][index] = true;
			((uint32 *)chunk->cb_values[j])[index] = 0xffffffff;
		}
		return;
	}

	/*
	 * Note: all the varlena values for a particular rowid must be put
	 * on same VarlenaBuffer. OpenCL server will transfer a regular
	 * chunk-buffer and an optional varlena-buffer at once. In case when
	 * multiple varlena-buffers are chained, kernel shall be executed
	 * for each varlena-buffers repeatedly (because GPU DRAM is usually
	 * less than host RAM, so need to avoid too much consumption).
	 */
	if (!dlist_is_empty(&chunk->vlbuf_list))
	{
		vlbuf = dlist_container(VarlenaBuffer, chain,
								dlist_tail_node(&chunk->vlbuf_list));
		curr_usage = vlbuf->usage;
	}
	else
	{
		vlbuf = NULL;
		curr_usage = 0;
	}
	
retry:
	foreach (cell, sestate->varlena_cols)
	{
		AttrNumber	j = lfirst_int(cell) - 1;
		bytea	   *v_body = NULL;
		Size		v_size;

		if (rs_values)
		{
			/*
			 * In case of row-store, just fetch rs_isnull and rs_values
			 * array.
			 */
			if (!rs_isnull || !rs_isnull[j])
				v_body = (bytea *)DatumGetPointer(rs_values[j]);
		}
		else
		{
			if (pgstrom_seek_window(sestate, j+1, curr_rowid))
			{
				bytea  *curr_isnull = sestate->curr_cs_isnull[j];
				bytea  *curr_values = sestate->curr_cs_values[j];
				int		windex = curr_rowid - sestate->curr_cs_rowid[j];

				if (!curr_isnull ||
					!(((bool *)VARDATA(curr_isnull))[windex]))
				{
					uint16 *v_offset = (uint16 *)VARDATA(curr_values);

					v_body = (bytea *)(((char *)v_offset) + v_offset[windex]);
				}
			}
		}

		if (!v_body)
		{
			v_size = toast_raw_datum_size(PointerGetDatum(v_body));
			if (!vlbuf)
			{
				vlbuf = pgstrom_varlena_buffer_alloc(sestate->vlbuf_size,
													 true);
				vlbuf->rowid = curr_rowid;
				vlbuf->nitems = 0;
				curr_usage = vlbuf->usage;

				dlist_push_tail(&chunk->vlbuf_list, &vlbuf->chain);
				chunk->nvarlena++;
			}

			/*
			 * In case when this varlena value may overrun the current
			 * varlena-buffer, we try to acquire a new one. If no rows
			 * are on this buffer, it enlarged the buffer size then try
			 * it again.
			 */
			if (vlbuf->length < curr_usage + MAXALIGN(v_size))
			{
				if (vlbuf->nitems == 0)
				{
					while (sestate->vlbuf_size < (curr_usage +
												  MAXALIGN(v_size)))
						sestate->vlbuf_size *= 2;

					chunk->nvarlena--;
					dlist_delete(&vlbuf->chain);
					pgstrom_varlena_buffer_free(vlbuf);
				}
				vlbuf = NULL;
				goto retry;
			}
			chunk->cb_isnull[j][index] = false;
			((uint32 *)(chunk->cb_values[j]))[index] = curr_usage;
			toast_extract_datum(vlbuf->data + curr_usage,
								v_body,
								v_size);
			curr_usage += MAXALIGN(v_size);
		}
		else
		{
			chunk->cb_isnull[j][index] = true;
			((uint32 *)chunk->cb_values[j])[index] = 0xffffffff;
		}
	}
	if (vlbuf)
	{
		Assert(curr_usage <= vlbuf->length);
		vlbuf->usage = curr_usage;
		vlbuf->nitems++;
	}
}

static bool
pgstrom_load_column_rowmap(StromExecState *sestate, ChunkBuffer *chunk)
{
	HeapTuple	tuple;
	TupleDesc	tupdesc;
	uint64		rowid;
	uint32		nitems;
	Datum		rowmap;
	Datum		values[Natts_pg_strom_rmap];
	bool		isnull[Natts_pg_strom_rmap];
	ListCell   *cell;
	int			i;

	Assert(sestate->rmap_scan != NULL);

	tuple = heap_getnext(sestate->rmap_scan, ForwardScanDirection);
	if (!HeapTupleIsValid(tuple))
	{
		heap_endscan(sestate->rmap_scan);
		sestate->rmap_scan = NULL;
		return false;
	}

	tupdesc = RelationGetDescr(sestate->rmap_rel);
	heap_deform_tuple(tuple, tupdesc, values, isnull);
	Assert(!isnull[Anum_pg_strom_rmap_rowid - 1] &&
		   !isnull[Anum_pg_strom_rmap_nitems - 1] &&
		   !isnull[Anum_pg_strom_rmap_rowmap - 1]);
	rowid = DatumGetInt64(values[Anum_pg_strom_rmap_rowid - 1]);
	nitems = DatumGetInt64(values[Anum_pg_strom_rmap_nitems - 1]);
	rowmap = values[Anum_pg_strom_rmap_rowmap - 1];

	refresh_chunk_buffer(sestate, chunk, rowid, nitems);
	toast_extract_datum(chunk->cb_rowmap,
						(bytea *)DatumGetPointer(rowmap),
						sizeof(bool) * nitems);
	ItemPointerCopy(&tuple->t_self, &chunk->cs_ctid);

	/* no need to load any more columns if parallel loading enabled */
	if (sestate->parallel_load)
		return true;

	/*
	 * Note: unlike fixed-length values, all the varlena values within
	 * same row must be loaded on the same varlena-buffer, because one
	 * varlena-buffer can be transfered to the OpenCL calculation device
	 * at most.
	 */
	foreach (cell, sestate->kernel_cols)
	{
		Form_pg_attribute attr
			= tupdesc->attrs[lfirst_int(cell) - 1];
		if (attr->attlen > 0)
			pgstrom_load_column_store(sestate, chunk, attr);
	}
	if (sestate->varlena_cols != NULL)
	{
		for (i=0; i < nitems; i++)
			pgstrom_load_varlena(sestate, chunk, i, NULL, NULL);
	}
	chunk->is_loaded = true;

	return true;
}

static bool
pgstrom_load_row_store(StromExecState *sestate, ChunkBuffer *chunk)
{
	MemoryContext oldcxt;
	TupleDesc	tupdesc;
	HeapTuple	tuple;
	int			i, nitems;
	bool	   *rs_isnull;
	Datum	   *rs_values;
	ListCell   *cell;

	if (!chunk->rs_cache)
	{
		chunk->rs_memcxt
			= AllocSetContextCreate(sestate->estate->es_query_cxt,
									"cache of row-store",
									ALLOCSET_DEFAULT_MINSIZE,
									ALLOCSET_DEFAULT_INITSIZE,
									ALLOCSET_DEFAULT_MAXSIZE);
		chunk->rs_cache
			= MemoryContextAllocZero(sestate->estate->es_query_cxt,
									 sizeof(HeapTuple) * PGSTROM_CHUNK_SIZE);
	}
	else
	{
		MemoryContextReset(chunk->rs_memcxt);
		memset(chunk->rs_cache, 0, sizeof(HeapTuple) * PGSTROM_CHUNK_SIZE);
	}

	for (nitems = 0; nitems < PGSTROM_CHUNK_SIZE; nitems++)
	{
		tuple = heap_getnext(sestate->rs_scan, ForwardScanDirection);
		if (!HeapTupleIsValid(tuple))
		{
			heap_endscan(sestate->rs_scan);
			sestate->rs_scan = NULL;
			break;
		}
		oldcxt = MemoryContextSwitchTo(chunk->rs_memcxt);
		chunk->rs_cache[nitems] = heap_copytuple(tuple);
		MemoryContextSwitchTo(oldcxt);
	}
	if (nitems == 0)
		return false;

	/* to avoid rowid == 0, using PGSTROM_CHUNK_SIZE instead */
	refresh_chunk_buffer(sestate, chunk, PGSTROM_CHUNK_SIZE, nitems);

	/*
	 * organize the fetched tuples according to the manner
	 * of column-oriented chunk buffer.
	 */
	tupdesc = RelationGetDescr(sestate->rs_rel);
	rs_isnull = palloc(sizeof(bool) * tupdesc->natts);
	rs_values = palloc(sizeof(Datum) * tupdesc->natts);

	memset(chunk->cb_rowmap, -1, sizeof(bool) * nitems);
	if (sestate->kernel_cols == NIL)
		return true;

	for (i=0; i < nitems; i++)
	{
		heap_deform_tuple(chunk->rs_cache[i], tupdesc,
						  rs_values, rs_isnull);

		foreach (cell, sestate->kernel_cols)
		{
			AttrNumber			j = lfirst_int(cell) - 1;
			Form_pg_attribute	attr = tupdesc->attrs[j];
			bool			   *cb_isnull = (bool *)chunk->cb_isnull[j];
			char			   *cb_values = (char *)chunk->cb_values[j];

			if (attr->attlen < 0)
				continue;

			cb_isnull[i] = rs_isnull[j];
			if (attr->attbyval)
				store_att_byval(cb_values + attr->attlen * i,
								rs_values[j], attr->attlen);
			else
				memcpy(cb_values + attr->attlen * i,
					   DatumGetPointer(rs_values[j]), attr->attlen);
		}
		if (sestate->varlena_cols != NIL)
			pgstrom_load_varlena(sestate, chunk, i, rs_isnull, rs_values);
	}
	chunk->is_loaded = true;

	return true;
}

static bool
pgstrom_shadow_locktuple(StromExecState *sestate, int index)
{
	EState		   *estate = sestate->estate;
	ChunkBuffer	   *chunk = sestate->curr_chunk;
	Relation		relation;
	HeapTupleData	tuple;
	HeapTuple		oldtup;
	HeapTuple		newtup;
	LockTupleMode	locktupmode;
	Buffer			buffer;
	HTSU_Result		result;
	MemoryContext	oldcxt;
	HeapUpdateFailureData hufd;

	if (index < 0)
	{
		relation = sestate->rmap_rel;
		ItemPointerCopy(&chunk->cs_ctid, &tuple.t_self);
	}
	else
	{
		relation = sestate->rs_rel;
		oldtup = chunk->rs_cache[index];
		ItemPointerCopy(&oldtup->t_self, &tuple.t_self);
	}

	Assert(sestate->lockmode > AccessShareLock);
	if (sestate->lockmode == RowShareLock)
		locktupmode = LockTupleShare;
	else
		locktupmode = LockTupleExclusive;

	result = heap_lock_tuple(relation,
							 &tuple,
							 estate->es_output_cid,
							 locktupmode,
							 sestate->lockmode_nowait,
							 true, &buffer, &hufd);
	ReleaseBuffer(buffer);

	Assert(result == HeapTupleSelfUpdated ||	/* updated by myself */
		   result == HeapTupleMayBeUpdated ||	/* successfully locked */
		   result == HeapTupleUpdated);			/* updated by someone */

	if (result == HeapTupleSelfUpdated)
	{
		/* to avoid "Halloween problem" ? */
		return false;
	}
	else if (result == HeapTupleUpdated)
	{
		if (IsolationUsesXactSnapshot())
			ereport(ERROR,
					(errcode(ERRCODE_T_R_SERIALIZATION_FAILURE),
			errmsg("could not serialize access due to concurrent update")));

		/* tuple was deleted, so don't return it */
		if (ItemPointerEquals(&hufd.ctid, &tuple.t_self))
			return false;

		/* updated, so fetch and lock the updated version */
		newtup = EvalPlanQualFetch(estate, relation, locktupmode,
								   &hufd.ctid, hufd.xmax);

		/* tuple was deleted, so don't return it */
		if (!HeapTupleIsValid(newtup))
			return false;

		if (index < 0)
		{
			/*
			 * In case when current chunk loads the contents of column-
			 * store, only row-maps are updatable, even if someone run
			 * UPDATE or DELETE command concurrently. So, calculation
			 * results towards the column-store contents are still valid,
			 * but some rows might be dropped due to the concurrent
			 * commands. (Please note that PG-Strom implements UPDATE
			 * command using a couple of operations; (1) drops a boolean
			 * relevant to the target row on row-map, (2) insert a new
			 * tuple into row-store.)
			 * So, all we need to do when this chunk is updated is to
			 * mask row-map using old rowmap (being already calculated)
			 * AND new rowmap.
			 */
			TupleDesc	tupdesc = RelationGetDescr(relation);
			Datum		values[Natts_pg_strom_rmap];
			bool		isnull[Natts_pg_strom_rmap];
			int64		new_rowid;
			int32		new_nitems;
			bytea	   *new_rowmap;
			Datum	   *oldmap;
			Datum	   *newmap;
			Datum	   *endmap;

			heap_deform_tuple(newtup, tupdesc, values, isnull);
			new_rowid = DatumGetInt64(values[Anum_pg_strom_rmap_rowid-1]);
			new_nitems = DatumGetInt32(values[Anum_pg_strom_rmap_nitems-1]);

			if (chunk->rowid != new_rowid || chunk->nitems != new_nitems)
				elog(ERROR, "bug? rowid/nitems of shadow rmap updated");

			new_rowmap = DatumGetByteaPP(values[Anum_pg_strom_rmap_rowmap-1]);
			newmap = (Datum *)VARDATA(new_rowmap);
			oldmap = (Datum *)chunk->cb_rowmap;
			endmap = (Datum *)(chunk->cb_rowmap + chunk->nitems);
			while (oldmap < endmap)
			{
				*oldmap &= *newmap;
				oldmap++;
				newmap++;
			}
		}
		else
		{
			HeapTuple	oldtup = chunk->rs_cache[index];

			if (HeapTupleGetOid(oldtup) != HeapTupleGetOid(newtup))
				elog(ERROR, "bug? oid of shadow row-store updated");

			oldcxt = MemoryContextSwitchTo(chunk->rs_memcxt);
			chunk->rs_cache[index] = heap_copytuple(newtup);
			MemoryContextSwitchTo(oldcxt);
		}
	}
	return true;
}

static bool
pgstrom_getnext(StromExecState *sestate, TupleTableSlot *slot)
{
	ChunkBuffer	   *chunk = sestate->curr_chunk;
	TupleDesc		tupdesc = slot->tts_tupleDescriptor;
	HeapTuple		tuple;
	int				curr_index  = sestate->curr_index;
	int64			curr_rowid;
	ListCell	   *cell;

	if (!chunk)
		return false;

	/*
	 * XXX - OpenCL calculation server will return an array of
	 * index on a particular chunk-buffer.
	 * need to implement this feature later.
	 */
	while (curr_index < chunk->nitems)
	{
		if (!chunk->cb_rowmap[curr_index])
		{
			curr_index++;
			continue;
		}

		/*
		 * If this chunk-buffer loads contents come from row-store,
		 * no need to have data re-organization because row-store
		 * has compatible format with the main foreign table, except
		 * for oid system column to be used for row identification
		 * on the writer stuff.
		 */
		if (chunk->rs_cache)
		{
			/* Row-level lock on the shadow row-store */
			if (sestate->lockmode > AccessShareLock &&
				!pgstrom_shadow_locktuple(sestate, curr_index))
			{
				curr_index++;
				continue;
			}

			/* OK, let's back this tuple */
			heap_deform_tuple(chunk->rs_cache[curr_index],
							  slot->tts_tupleDescriptor,
							  slot->tts_values,
							  slot->tts_isnull);
			slot = ExecStoreVirtualTuple(slot);
			if (sestate->needs_ctid)
			{
				tuple = ExecMaterializeSlot(slot);
				ItemPointerSetForRowid(tuple, HeapTupleGetOid(tuple));
			}
			sestate->curr_index = curr_index + 1;
			return true;
		}
		/* current rowid */
		curr_rowid = chunk->rowid + curr_index;

		/*
		 * In case when chunk has one or more varlena buffers, a relevant
		 * buffer for the current-rowid has to be rotated and appeared on
		 * the top.
		 */
		if (sestate->curr_vlbuf)
		{
			while (curr_rowid > (sestate->curr_vlbuf->rowid +
								 sestate->curr_vlbuf->nitems))
			{
				dlist_node *dnode;

				if (!dlist_has_next(&chunk->vlbuf_list,
									&sestate->curr_vlbuf->chain))
				{
					sestate->curr_vlbuf = NULL;
					break;
				}
				dnode = dlist_next_node(&chunk->vlbuf_list,
										&sestate->curr_vlbuf->chain);
				sestate->curr_vlbuf
					= dlist_container(VarlenaBuffer, chain, dnode);
			}
		}

		memset(slot->tts_isnull, -1, sizeof(bool) * tupdesc->natts);
		memset(slot->tts_values,  0, sizeof(Datum) * tupdesc->natts);

		foreach (cell, sestate->host_cols)
		{
			AttrNumber	j = lfirst_int(cell) - 1;

			if (chunk->cb_isnull[j] && chunk->cb_isnull[j][curr_index])
				continue;

			/*
			 * We don't need to scan the relation again, if it is already
			 * loaded on the chunk-buffer for calculation in OpenCL server.
			 * Elsewhere, we seek window of the require attribute on the
			 * current focusing rowid, then fetch fixed- or variable-
			 * length datum.
			 */
			if (chunk->cb_values[j])
			{
				Form_pg_attribute	attr = tupdesc->attrs[j];

				slot->tts_isnull[j] = false;
				if (attr->attlen > 0)
				{
					slot->tts_values[j]
						= fetchatt(attr, ((char *)chunk->cb_values[j] +
										  attr->attlen * curr_index));
				}
				else
				{
					uint32	offset;
					char   *vlbuf_base;

					Assert(sestate->curr_vlbuf);
					Assert(curr_rowid >= sestate->curr_vlbuf->rowid &&
						   curr_rowid < (sestate->curr_vlbuf->rowid +
										 sestate->curr_vlbuf->nitems));
					offset = ((uint32 *)chunk->cb_values[j])[curr_index];
					vlbuf_base = (char *)sestate->curr_vlbuf->data;
					slot->tts_values[j]
						= PointerGetDatum((bytea *)(vlbuf_base + offset));
				}
			}
			else if (pgstrom_seek_window(sestate, j+1, curr_rowid))
			{
				int		i = curr_rowid - sestate->curr_cs_rowid[j];
				bytea  *cs_isnull = sestate->curr_cs_isnull[j];
				bytea  *cs_values = sestate->curr_cs_values[j];

				if (!cs_isnull || !((bool *)VARDATA(cs_isnull))[i])
				{
					Form_pg_attribute attr = tupdesc->attrs[j];

					slot->tts_isnull[j] = false;
					if (attr->attlen > 0)
					{
						slot->tts_values[j]
							= fetchatt(attr, (VARDATA(cs_values) +
											  attr->attlen * i));
					}
					else
					{
						uint16 *cs_offset = (uint16 *)VARDATA(cs_values);
						void   *cs_varlena;

						cs_varlena = VARDATA(cs_values) + cs_offset[i];
						slot->tts_values[j] = PointerGetDatum(cs_varlena);
					}
				}
			}
		}
		slot = ExecStoreVirtualTuple(slot);

		/*
		 * Also return an rowid, if required.
		 */
		if (sestate->needs_ctid)
		{
			tuple = ExecMaterializeSlot(slot);
			ItemPointerSetForRowid(tuple, curr_rowid);
		}
		sestate->curr_index = curr_index + 1;
		return true;
	}
	return false;
}

static TupleTableSlot *
pgstrom_iterate_foreign_scan(ForeignScanState *fss)
{
	StromExecState *sestate = (StromExecState *) fss->fdw_state;
	TupleTableSlot *slot = fss->ss.ss_ScanTupleSlot;

	ExecClearTuple(slot);

	while (!pgstrom_getnext(sestate, slot))
	{
		ChunkBuffer	*chunk;
		dlist_node	*dnode;

	next_chunk:
		/*
		 * Release varlena buffers being associated with the chunk-buffer
		 * on which we already fetched, however, we don't release this
		 * chunk-buffer itself for re-use.
		 */
		if (sestate->curr_chunk)
		{
			dlist_mutable_iter	iter;

			chunk = sestate->curr_chunk;
			dlist_foreach_modify(iter, &chunk->vlbuf_list)
			{
				VarlenaBuffer  *vlbuf
					= dlist_container(VarlenaBuffer, chain, iter.cur);

				pgstrom_varlena_buffer_free(vlbuf);
			}
			Assert(dlist_is_empty(&chunk->vlbuf_list));

			dlist_push_tail(&sestate->chunk_free_list, &chunk->chain);
		}
		sestate->curr_chunk = NULL;

		/*
		 * Try to dequeue a chunk from the receive queue to the ready list,
		 * if any. No need to block at this stage.
		 */
		while ((dnode = pgstrom_queue_try_dequeue(sestate->recvq)) != NULL)
		{
			chunk = dlist_container(ChunkBuffer, chain, dnode);
			Assert(!chunk->is_running);
			sestate->num_running_chunks--;
			if (chunk->error_code != 0)
				ereport(ERROR, (chunk->error_code,
								errmsg("OpenCL Runtime: %s",
									   (char *)chunk->data)));
			dlist_push_tail(&sestate->chunk_ready_list, &chunk->chain);
		}

		/*
		 * Scan one or more chunks if we still don't reach end of the scan
		 * on the column-/row-store unless number of running chunks are
		 * less than pgstrom_max_async_chunks.
		 */
		while (sestate->rmap_scan != NULL || sestate->rs_scan != NULL)
		{
			/*
			 * Fetch a chunk-buffer to be used to load next chunk from
			 * the column-/row-store. If we could not allocate more
			 * chunk buffers, it simply gives up further multiplicity,
			 * intead of raising an error.
			 */
			if (dlist_is_empty(&sestate->chunk_free_list))
			{
				if (sestate->num_total_chunks >= pgstrom_max_async_chunks)
					break;

				chunk = create_chunk_buffer(sestate, false);
				if (!chunk)
					break;
				sestate->num_total_chunks++;
			}
			else
			{
				dnode = dlist_pop_head_node(&sestate->chunk_free_list);
				chunk = dlist_container(ChunkBuffer, chain, dnode);
			}
			Assert(chunk != NULL);

			/*
			 * Load the next chunk. If no chunks to read any more,
			 * current chunk-buffer shall be back to free.
			 */
			if ((sestate->rmap_scan != NULL
				 ? pgstrom_load_column_rowmap(sestate, chunk)
				 : pgstrom_load_row_store(sestate, chunk)))
			{
				/*
				 * XXX - right now, kernel-execution is not implemented
				 * yet. So, we simply add it to ready_list.
				 * It should be pushed to OpenCL calculation queue, or
				 * parallel load queue if available
				 */
				if (!sestate->kernel_params)
					dlist_push_tail(&sestate->chunk_ready_list,
									&chunk->chain);
				else
				{
					// enqueue either calculation or io queue
					// chunk->is_running = true;
					// sestate->num_running_chunks++;
					elog(ERROR, "kernel-execution - not implemented yet!");
				}
			}
			else
				dlist_push_tail(&sestate->chunk_free_list, &chunk->chain);

			/*
			 * If some chunk-buffer that was running get finished to run
			 * the kernel, we move then to ready-list, and don't continue
			 * to scan chunks any more.
			 */
			while ((dnode = pgstrom_queue_try_dequeue(sestate->recvq)) != NULL)
			{
				chunk = dlist_container(ChunkBuffer, chain, dnode);
				Assert(!chunk->is_running);
				sestate->num_running_chunks--;
				if (chunk->error_code != 0)
					ereport(ERROR, (chunk->error_code,
									errmsg("OpenCL Runtime: %s",
										   (char *)chunk->data)));
				dlist_push_tail(&sestate->chunk_free_list, &chunk->chain);
			}
			if (!dlist_is_empty(&sestate->chunk_ready_list))
				break;
		}

		/*
		 * In case when no chunk-buffers were completed yet and number of
		 * running chunks get to pgstrom_max_async_chunks, we need to wait
		 * for completion of a chunk that is running now.
		 */
		if (dlist_is_empty(&sestate->chunk_ready_list))
		{
			if (sestate->num_running_chunks == 0)
				break;

			/* synchronized dequeue */
			dnode = pgstrom_queue_dequeue(sestate->recvq, 0);
			chunk = dlist_container(ChunkBuffer, chain, dnode);
			Assert(!chunk->is_running);
			sestate->num_running_chunks--;
			if (chunk->error_code != 0)
				ereport(ERROR, (chunk->error_code,
								errmsg("OpenCL Runtime: %s",
									   (char *)chunk->data)));
			dlist_push_tail(&sestate->chunk_ready_list, &chunk->chain);
		}
		Assert(!dlist_is_empty(&sestate->chunk_ready_list));
		dnode = dlist_pop_head_node(&sestate->chunk_ready_list);
		sestate->curr_chunk = dlist_container(ChunkBuffer, chain, dnode);
		sestate->curr_index = 0;

		/*
		 * Acquire tuple-level lock, if needed. In case when this chunk
		 * loads contents from the shadow column-store, it is not capable
		 * to lock them per rows guranuality because of its data format.
		 * If row-store, it acquires locks per rows as literal.
		 */
		if (sestate->lockmode > AccessShareLock &&
			!sestate->curr_chunk->rs_cache &&
			!pgstrom_shadow_locktuple(sestate, -1))
			goto next_chunk;
	}
	return slot;
}

static void
pgstrom_rescan_foreign_scan(ForeignScanState *fss)
{
	/*
	 * XXX - needs to reset chunk->rs_cache and chunk->rs_memcxt to
	 * avoid pgstrom_getnext handles chunks with column-store as if
	 * chunks with row-store. (Probably, it makes SIGSEGV)
	 */
	elog(ERROR, "not implemented yet");
}

static void
pgstrom_end_foreign_scan(ForeignScanState *fss)
{
	StromExecState *sestate = (StromExecState *)fss->fdw_state;
	TupleDesc		tupdesc = RelationGetDescr(sestate->frel);
	dlist_mutable_iter iter;
	dlist_node	   *dnode;
	ChunkBuffer	   *chunk;
	int				j;

	/*
	 * Release chunk-buffers
	 */
	if (sestate->curr_chunk)
	{
		pgstrom_chunk_buffer_free(sestate->curr_chunk);
		sestate->num_total_chunks--;
		sestate->curr_chunk = NULL;
	}

	dlist_foreach_modify(iter, &sestate->chunk_free_list)
	{
		chunk = dlist_container(ChunkBuffer, chain, iter.cur);
		pgstrom_chunk_buffer_free(chunk);
		sestate->num_total_chunks--;
	}
	dlist_foreach_modify(iter, &sestate->chunk_ready_list)
	{
		chunk = dlist_container(ChunkBuffer, chain, iter.cur);
		pgstrom_chunk_buffer_free(chunk);
		sestate->num_total_chunks--;
	}
	Assert(sestate->num_total_chunks == sestate->num_running_chunks);

	while (sestate->num_running_chunks > 0)
	{
		dnode = pgstrom_queue_dequeue(sestate->recvq, 0);
		chunk = dlist_container(ChunkBuffer, chain, dnode);
		Assert(!chunk->is_running);
		sestate->num_running_chunks--;
		if (chunk->error_code != 0)
			ereport(ERROR,
					(chunk->error_code,
					 errmsg("OpenCL Runtime: %s", (char *)chunk->data)));
		pgstrom_chunk_buffer_free(chunk);
		sestate->num_total_chunks--;
	}
	/* release kernel-params object */
	if (sestate->kernel_params)
		pgstrom_kernel_params_free(sestate->kernel_params);

	/* release receive queue */
	pgstrom_queue_free(sestate->recvq);

	/* scan cleanup */
	if (sestate->rmap_scan != NULL)
		heap_endscan(sestate->rmap_scan);
	for (j=0; j < tupdesc->natts; j++)
	{
		if (sestate->cs_scan[j])
			index_endscan(sestate->cs_scan[j]);
	}
	if (sestate->rs_scan != NULL)
		heap_endscan(sestate->rs_scan);

	/* close relations */
	heap_close(sestate->rs_rel, NoLock);
	index_close(sestate->cs_idx, NoLock);
	heap_close(sestate->cs_rel, NoLock);
	index_close(sestate->rmap_idx, NoLock);
	heap_close(sestate->rmap_rel, NoLock);

	/* release sestate */
	pfree(sestate);
}

static void
pgstrom_explain_foreign_scan(ForeignScanState *node,
							 struct ExplainState *es)
{
	elog(ERROR, "not implemented yet");
}

void
pgstrom_fdw_scan_init(FdwRoutine *fdw_routine)
{
	DefineCustomIntVariable("pg_strom.max_async_chunks",
							"max number of chunks to be executed concurrently",
							NULL,
							&pgstrom_max_async_chunks,
							32,
							1,
							INT_MAX,
							PGC_USERSET,
							0,
							NULL, NULL, NULL);

	fdw_routine->BeginForeignScan = pgstrom_begin_foreign_scan;
	fdw_routine->IterateForeignScan = pgstrom_iterate_foreign_scan;
	fdw_routine->ReScanForeignScan = pgstrom_rescan_foreign_scan;
	fdw_routine->EndForeignScan = pgstrom_end_foreign_scan;
	fdw_routine->ExplainForeignScan = pgstrom_explain_foreign_scan;
}
