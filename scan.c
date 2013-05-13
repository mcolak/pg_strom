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
#include "catalog/heap.h"
#include "catalog/pg_type.h"
#include "commands/explain.h"
#include "executor/executor.h"
#include "lib/stringinfo.h"
#include "miscadmin.h"
#include "storage/bufmgr.h"
#include "utils/builtins.h"
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
	List		   *kernel_cols;
	List		   *result_cols;
	List		   *varlena_cols;
	List		   *host_cols;
	size_t			vlbuf_size;
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
static int	pgstrom_base_addr_align = -1;

static void
init_base_addr_align(void)
{
	DeviceProperty *devprop;

	pgstrom_device_property_lock(false);
	PG_TRY();
	{
		pgstrom_base_addr_align
			= sizeof(cl_long) * PGSTROM_UNITSZ * BITS_PER_BYTE;

		for (devprop = pgstrom_device_property_next(NULL);
			 devprop != NULL;
			 devprop = pgstrom_device_property_next(devprop))
		{
			if (devprop->is_local &&
				devprop->dev_host_unified_memory &&
				pgstrom_base_addr_align < devprop->dev_mem_base_addr_align)
				pgstrom_base_addr_align = devprop->dev_mem_base_addr_align;
		}
		pgstrom_base_addr_align /= BITS_PER_BYTE;
	}
	PG_CATCH();
	{
		pgstrom_device_property_unlock();
		PG_RE_THROW();
	}
	PG_END_TRY();
	pgstrom_device_property_unlock();
}

/*
 * extract_kernel_params
 *
 * It extracts the supplied kernel source and parameters to the on-chunk
 * format and copies it on the shared memory segment.
 * It should be available to reference during this table scan.
 */
static KernelParams *
extract_kernel_params(EState *estate,
					  text *kernel_source,
					  bytea *kernel_md5,
					  List *kernel_params,
					  cl_device_type kernel_devtype,
					  const char *vector_preference)
{
	StringInfoData	str;
	kern_params_t  *kparams;
	cl_int			p_index;
	size_t			length;
	KernelParams   *result;
	ListCell	   *cell;

	if (!kernel_source)
		return NULL;

	Assert(kernel_md5 != NULL);

	/*
	 * Construct kernel parameters
	 */
	initStringInfo(&str);
	kparams = (kern_params_t *)str.data;
	kparams->p_nums = list_length(kernel_params);
	length = offsetof(kern_params_t, p_offset[kparams->p_nums]);
	enlargeStringInfo(&str, length);
	str.len = length;

	p_index = 0;
	foreach (cell, kernel_params)
	{
		Node   *node = lfirst(cell);

		if (IsA(node, Const))
		{
			Const  *c = (Const *) lfirst(cell);

			if (c->constisnull)
				kparams->p_offset[p_index] = 0;
			else
			{
				/* force alignment */
				if (c->constlen > 0)
					str.len = (str.len + c->constlen - 1) & ~(c->constlen - 1);
				else
					str.len = (str.len + VARHDRSZ - 1) & ~(VARHDRSZ - 1);
				enlargeStringInfo(&str, 0);
				kparams->p_offset[p_index] = str.len;

				if (c->constbyval)
					appendBinaryStringInfo(&str,
										   (char *)&c->constvalue,
										   c->constlen);
				else if (c->constlen > 0)
					appendBinaryStringInfo(&str,
										   DatumGetPointer(c->constvalue),
										   c->constlen);
				else
					appendBinaryStringInfo(&str,
										   DatumGetPointer(c->constvalue),
										   VARSIZE_ANY(c->constvalue));
			}
		}
		else if (IsA(node, Param))
		{
			Param  *p = (Param *) lfirst(cell);
			ParamListInfo	 pinfo = estate->es_param_list_info;
			ParamExternData	*ped;

			Assert(p->paramid < pinfo->numParams);
			ped = &pinfo->params[p->paramid];
			if (ped->isnull)
				kparams->p_offset[p_index] = 0;
			else
			{
				int16	typlen;
				bool	typbyval;

				Assert(p->paramtype == ped->ptype);
				get_typlenbyval(ped->ptype, &typlen, &typbyval);

				/* force alignment */
				if (typlen > 0)
					str.len = (str.len + typlen - 1) & ~(typlen - 1);
				else
					str.len = (str.len + VARHDRSZ - 1) & ~(VARHDRSZ - 1);
				enlargeStringInfo(&str, 0);
				kparams->p_offset[p_index] = str.len;

				if (typbyval)
					appendBinaryStringInfo(&str,
										   (char *)&ped->value,
										   typlen);
				else if (typlen > 0)
					appendBinaryStringInfo(&str,
										   DatumGetPointer(ped->value),
										   typlen);
				else
					appendBinaryStringInfo(&str,
										   (char *)DatumGetByteaP(ped->value),
										   VARSIZE_ANY(ped->value));
			}
		}
		else
			elog(ERROR, "unexpected node: %d", nodeTag(node));

		p_index++;
	}
	Assert(kparams->p_nums == p_index);

	/*
	 * copy them on KernelParams structure allocated on shared memory
	 * segment.
	 */
	result = pgstrom_kernel_params_alloc(sizeof(KernelParams) +
										 VARSIZE(kernel_source) +
										 pgstrom_base_addr_align +
										 MAXALIGN(str.len), true);
	memcpy(result->kernel_md5, VARDATA(kernel_md5), MD5_SIZE);
	memcpy(&result->kernel_source,
		   kernel_source,
		   VARSIZE(kernel_source));
	result->kparams =
		(kern_params_t *)TYPEALIGN(pgstrom_base_addr_align,
								   (intptr_t)result +
								   offsetof(KernelParams,
											kernel_source) +
								   VARSIZE(kernel_source));
	memcpy(result->kparams, kparams, str.len);
	result->kparams_size = str.len;

	/* we expect cpu, gpu or accelerator */
	Assert(kernel_devtype != 0 &&
		   (kernel_devtype & ~(CL_DEVICE_TYPE_CPU |
							   CL_DEVICE_TYPE_GPU |
							   CL_DEVICE_TYPE_ACCELERATOR)) != 0);
	result->kernel_devtype = kernel_devtype;

	/* preferred vector width */
	if (strcmp(vector_preference, "char") == 0)
		result->vector_preference = CL_DEVICE_PREFERRED_VECTOR_WIDTH_CHAR;
	else if (strcmp(vector_preference, "short") == 0)
		result->vector_preference = CL_DEVICE_PREFERRED_VECTOR_WIDTH_SHORT;
	else if (strcmp(vector_preference, "long") == 0)
		result->vector_preference = CL_DEVICE_PREFERRED_VECTOR_WIDTH_LONG;
	else if (strcmp(vector_preference, "float") == 0)
		result->vector_preference = CL_DEVICE_PREFERRED_VECTOR_WIDTH_FLOAT;
	else if (strcmp(vector_preference, "double") == 0)
		result->vector_preference = CL_DEVICE_PREFERRED_VECTOR_WIDTH_DOUBLE;
	else
		result->vector_preference = CL_DEVICE_PREFERRED_VECTOR_WIDTH_INT;

	pfree(str.data);

	return result;
}

static void
refresh_chunk_buffer(StromExecState *sestate, ChunkBuffer *chunk,
					 uint64 rowid, uint32 nitems)
{
	TupleDesc		tupdesc = RelationGetDescr(sestate->frel);
	kern_args_t	   *kargs = chunk->cb_kargs;
	int				index;
	size_t			offset;
	ListCell	   *cell;
	dlist_mutable_iter iter;

	Assert(nitems <= PGSTROM_CHUNK_SIZE);

	/* Release all the relevant older varlena-buffers */
	dlist_foreach_modify(iter, &chunk->vlbuf_list)
	{
		VarlenaBuffer  *vlbuf
			= dlist_container(VarlenaBuffer, chain, iter.cur);

		pgstrom_varlena_buffer_free(vlbuf);
		chunk->nvarlena--;
	}
	Assert(dlist_is_empty(&chunk->vlbuf_list));
	Assert(chunk->nvarlena == 0);

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
	 * |+-----------------------------+
	 * || bool   *cb_isnull[nattrs]   |
	 * || void   *cb_values[nattrs]   |
	 * || FormData_pg_attribute       |
	 * ||         cb_attrs[nargs]     |
	 * || <---- (char *)chunk->cb_kargs + dma_send_start --+
	 * || kern_args_t  kargs          |                    |
	 * ||        :                    |                    |
	 * || Fields to be sent to the    |                    |
	 * || device as input of kernel   |                    |
	 * || execution                   |                    |
	 * ||        :                    |                    |
	 * || <-- (char *)chunk->cb_kargs + dma_recv_start --+ |
	 * || bool  cb_rowmap[nitems]     |                  | |
	 * || <------------------------------------------------+
	 * ||        :                    |                  |
	 * || Fields to be received from  |                  |
	 * || the device as output of     |                  |
	 * || kernel execution            |                  |
	 * ||        :                    |                  |
	 * ++-----------------------------+ <----------------+
	 */
	memset(chunk->cb_isnull, 0, sizeof(bool *) * tupdesc->natts);
	memset(chunk->cb_values, 0, sizeof(void *) * tupdesc->natts);

	chunk->dma_send_start = 0;
	offset = offsetof(kern_args_t, offset[kargs->nargs]);

	index = 0;
	foreach (cell, sestate->kernel_cols)
	{
		Form_pg_attribute attr;
        AttrNumber	j = lfirst_int(cell) - 1;
		int			unitlen;

		Assert(j >= 0 && j < tupdesc->natts);
		attr = tupdesc->attrs[j];
		if (attr->attnotnull)
			kargs->offset[index].isnull = 0;	/* always not null */
		else
		{
			offset = PGSTROM_ALIGN(sizeof(bool) * PGSTROM_UNITSZ, offset);
			kargs->offset[index].isnull = offset;
			chunk->cb_isnull[j] = (bool *)((char *)kargs + offset);
			offset += sizeof(bool) * nitems;
		}

		unitlen = attr->attlen > 0 ? attr->attlen : sizeof(uint32);
		offset = PGSTROM_ALIGN(unitlen * PGSTROM_UNITSZ, offset);
		kargs->offset[index].values = offset;
		chunk->cb_values[j] = (void *)((char *)kargs + offset);
		offset += unitlen * nitems;

		index++;
	}
	chunk->dma_recv_start = offset;
	Assert(kargs->i_rowmap == index);

	offset = TYPEALIGN(sizeof(bool) * PGSTROM_UNITSZ, offset);
	kargs->offset[index].isnull = 0;
	kargs->offset[index].values = offset;
	chunk->cb_rowmap = (bool *)((char *)kargs + offset);
	offset += sizeof(bool) * nitems;
	chunk->dma_send_end = offset;
	index++;
	/*
	 * XXX - result buffer shall be assigned here
	 */
	chunk->dma_recv_end = offset;
	Assert(kargs->nargs == index);

	Assert((uintptr_t)chunk->cb_kargs + offset
		   <= (uintptr_t)chunk + chunk->cb_length);

	kargs->nargs = index;
	kargs->nitems = nitems;

	/* misc fields refresh */
	chunk->is_loaded = false;
	chunk->is_running = false;
	chunk->nvarlena = 0;
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
	int				nsend = list_length(sestate->kernel_cols);
	int				nrecv = list_length(sestate->result_cols);
	int				nargs = nsend + 1 + nrecv;
	int				index;
	size_t			length;
	size_t			offset;
	ListCell	   *cell;
	Form_pg_attribute attr;
	static FormData_pg_attribute rowmap_attr = {
		0, {"rowid"}, BOOLOID, 0, sizeof(bool), 0,
		InvalidAttrNumber, 0, -1, -1,
		true, 'p', 'c', true, false, false, true, 0
	};

	length = offsetof(ChunkBuffer, data)
		+ MAXALIGN(sizeof(bool *) * tupdesc->natts)
		+ MAXALIGN(sizeof(void *) * tupdesc->natts)
		+ MAXALIGN(sizeof(FormData_pg_attribute) * nargs)
		+ pgstrom_base_addr_align
		+ MAXALIGN(offsetof(kern_args_t, offset[nargs]));
	/*
	 * XXX - Right now, interface of PostgreSQL does not support to
	 * offload calculation results into external computing resources.
	 * Once it gets supported, we also allocate region to back the
	 * calculation results from OpenCL calculation server.
	 */
	Assert(nrecv == 0);

	/* For kernel arguments */
	foreach (cell, sestate->kernel_cols)
	{
		AttrNumber	j = lfirst_int(cell) - 1;

		Assert(j >= 0 && j < tupdesc->natts);
		attr = tupdesc->attrs[j];

		if (!attr->attnotnull)
			length = PGSTROM_ALIGN(sizeof(bool) * PGSTROM_UNITSZ,
								sizeof(bool) * PGSTROM_CHUNK_SIZE + length);
		if (attr->attlen > 0)
			length = PGSTROM_ALIGN(attr->attlen * PGSTROM_UNITSZ,
								attr->attlen * PGSTROM_CHUNK_SIZE + length);
		else
			length = PGSTROM_ALIGN(sizeof(uint32) * PGSTROM_UNITSZ,
								sizeof(uint32) * PGSTROM_CHUNK_SIZE + length);
	}
	/* For rowmap */
	length = PGSTROM_ALIGN(sizeof(bool) * PGSTROM_UNITSZ,
						   sizeof(bool) * PGSTROM_CHUNK_SIZE + length);

	/*
	 * Allocation on the shared memory segment
	 */
	chunk = pgstrom_chunk_buffer_alloc(length, abort_on_error);
	if (!chunk)
		return NULL;
	chunk->cb_length = length;

	/*
	 * Initialization of persistent fields independent from rowid and
	 * nitems to be loaded.
	 *
	 * NOTE: lock, cond and vlbuf_list shall be initialized on allocation.
	 * NULL shall be set on recvq and kernel_params. False shall be set
	 * on is_loaded and is_running.
	 */
	chunk->recvq = sestate->recvq;
	chunk->kernel_params = sestate->kernel_params;
	dlist_init(&chunk->vlbuf_list);
	chunk->cb_databaseid = MyDatabaseId;
	chunk->cb_nattrs = tupdesc->natts;
	chunk->error_code = 0;
	chunk->rs_cache = NULL;
	chunk->rs_memcxt = NULL;
	ItemPointerSetInvalid(&chunk->cs_ctid);

	/*
	 * variable length field
	 */
	offset = 0;
	chunk->cb_isnull = (bool **)(chunk->data + offset);
	offset += MAXALIGN(sizeof(bool *) * tupdesc->natts);
	chunk->cb_values = (void **)(chunk->data + offset);
	offset += MAXALIGN(sizeof(void *) * tupdesc->natts);
	chunk->cb_attrs = (Form_pg_attribute)(chunk->data + offset);
	offset += MAXALIGN(sizeof(ATTRIBUTE_FIXED_PART_SIZE) * nargs);

	/*
	 * Copy of FormData_pg_attribute, because it is never changed during
	 * a particular foreign table scan.
	 */
	index = 0;
	foreach (cell, sestate->kernel_cols)
	{
		attr = tupdesc->attrs[lfirst_int(cell) - 1];

		memcpy(&chunk->cb_attrs[index++], attr, ATTRIBUTE_FIXED_PART_SIZE);
	}
	Assert(index == nsend);

	memcpy(&chunk->cb_attrs[index++], &rowmap_attr, ATTRIBUTE_FIXED_PART_SIZE);
	/*
	 * XXX - put here for attribute of result (pseudo) columns
	 */
	Assert(index == nargs);

	/*
	 * cb_kargs has to be aligned to pgstrom_base_addr_align, because
	 * it may be used to opencl memory buffer if device supports host
	 * unified memory.
	 */
	chunk->cb_kargs = (kern_args_t *)PGSTROM_ALIGN(pgstrom_base_addr_align,
												   chunk->data + offset);
	chunk->cb_kargs->nargs = nargs;
	chunk->cb_kargs->nitems = -1;		/* to be set later */
	chunk->cb_kargs->i_rowmap = nsend;

	return chunk;
}

static void
fetch_planners_info(Relation frel,
					List *fdw_private,
					text **p_kernel_source,
					bytea **p_kernel_md5,
					char **p_kernel_quals,
					List **p_kernel_params,
					List **p_kernel_cols,
					List **p_varlena_cols,
					List **p_host_cols,
					bool *p_needs_ctid,
					cl_device_type *p_kernel_devtype,
					char **p_vector_preference,
					size_t *p_vlbuf_size,
					LOCKMODE *p_lockmode,
					bool *p_lockmode_nowait)
{
	TupleDesc		tupdesc = RelationGetDescr(frel);
	text		   *kernel_source = NULL;
	bytea		   *kernel_md5 = NULL;
	char		   *kernel_quals = NULL;
	List		   *kernel_params = NIL;
	List		   *kernel_cols = NIL;
	List		   *varlena_cols = NIL;
	List		   *host_cols = NIL;
	bool			needs_ctid = false;
	cl_device_type	kernel_devtype = CL_DEVICE_TYPE_ALL;
	char		   *vector_preference = "int";
	size_t			vlbuf_size = 65536;	/* 64MB */
	LOCKMODE		lockmode = AccessShareLock;
	bool			lockmode_nowait = false;
	ListCell	   *cell;

	/*
	 * Fetch planner's information
	 */
	foreach (cell, fdw_private)
	{
		DefElem	   *defel = (DefElem *) lfirst(cell);

		if (strcmp(defel->defname, "kernel_source") == 0)
			kernel_source = DatumGetTextP(((Const *)defel->arg)->constvalue);
		else if (strcmp(defel->defname, "kernel_md5") == 0)
			kernel_md5 = DatumGetByteaP(((Const *)defel->arg)->constvalue);
		else if (strcmp(defel->defname, "kernel_quals") == 0)
			kernel_quals = strVal(defel->arg);
		else if (strcmp(defel->defname, "kernel_params") == 0)
			kernel_params = lappend(kernel_params, defel->arg);
		else if (strcmp(defel->defname, "kernel_cols") == 0)
		{
			Form_pg_attribute attr;
			AttrNumber	attnum = intVal(defel->arg);

			if (attnum < 1 || attnum > tupdesc->natts)
				elog(ERROR, "kernel column out of range: %d", attnum);
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
				elog(ERROR, "host column out of range: %d", attnum);
			if (attnum > 0)
				host_cols = lappend_int(host_cols, attnum);
			else if (attnum == SelfItemPointerAttributeNumber)
				needs_ctid = true;
		}
		else if (strcmp(defel->defname, "kernel_devtype") == 0)
			kernel_devtype = intVal(defel->arg);
		else if (strcmp(defel->defname, "vector_preference") == 0)
			vector_preference = strVal(defel->arg);
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
	/* write back to the caller */
	if (p_kernel_source)
		*p_kernel_source = kernel_source;
	if (p_kernel_md5)
		*p_kernel_md5 = kernel_md5;
	if (p_kernel_quals)
		*p_kernel_quals = kernel_quals;
	if (p_kernel_params)
		*p_kernel_params = kernel_params;
	if (p_kernel_cols)
		*p_kernel_cols = kernel_cols;
	if (p_varlena_cols)
		*p_varlena_cols = varlena_cols;
	if (p_host_cols)
		*p_host_cols = host_cols;
	if (p_needs_ctid)
		*p_needs_ctid = needs_ctid;
	if (p_kernel_devtype)
		*p_kernel_devtype = kernel_devtype;
	if (p_vector_preference)
		*p_vector_preference = vector_preference;
	if (p_vlbuf_size)
		*p_vlbuf_size = vlbuf_size;
	if (p_lockmode)
		*p_lockmode = lockmode;
	if (p_lockmode_nowait)
		*p_lockmode_nowait = lockmode_nowait;
}

static void
pgstrom_begin_foreign_scan(ForeignScanState *fss, int eflags)
{
	ForeignScan	   *fscan = (ForeignScan *) fss->ss.ps.plan;
	Relation		frel = fss->ss.ss_currentRelation;
	TupleDesc		tupdesc = RelationGetDescr(frel);
	text		   *kernel_source;
	bytea		   *kernel_md5;
	List		   *kernel_params;
	cl_device_type	kernel_devtype;
	char		   *vector_preference;
	List		   *union_cols;
	StromExecState *sestate;
	ChunkBuffer	   *chunk;
	int				nattrs;
	ListCell	   *cell;

	/* Do nothing for EXPLAIN or ANALYZE case */
	if (eflags & EXEC_FLAG_EXPLAIN_ONLY)
		return;

	/*
	 * Calculation of base address alignment - In case when opencl device
	 * support host unified memory space, we map shared memory segment as
	 * buffer object of opencl as-is, thus, any objects that can perform
	 * as kernel argument needs to be aligned.
	 */
	if (pgstrom_base_addr_align < 0)
		init_base_addr_align();

	/*
	 * Construction of StromExecState
	 */
	sestate = palloc0(sizeof(StromExecState));
	fetch_planners_info(frel,
						fscan->fdw_private,
						&kernel_source,
						&kernel_md5,
						NULL,
						&kernel_params,
						&sestate->kernel_cols,
						&sestate->varlena_cols,
						&sestate->host_cols,
						&sestate->needs_ctid,
						&kernel_devtype,
						&vector_preference,
						&sestate->vlbuf_size,
						&sestate->lockmode,
						&sestate->lockmode_nowait);
	sestate->estate = fss->ss.ps.state;
	sestate->snapshot = sestate->estate->es_snapshot;
	sestate->recvq = pgstrom_queue_alloc(true);
	sestate->kernel_params = extract_kernel_params(sestate->estate,
												   kernel_source,
												   kernel_md5,
												   kernel_params,
												   kernel_devtype,
												   vector_preference);
	dlist_init(&sestate->chunk_ready_list);
	dlist_init(&sestate->chunk_free_list);
	sestate->num_total_chunks = 0;
	sestate->num_running_chunks = 0;

	/* Open the shadow relations */
	nattrs = tupdesc->natts;
	sestate->frel = frel;
	sestate->rmap_rel = pgstrom_open_shadow_rmap(frel, sestate->lockmode);
	sestate->rmap_idx
		= pgstrom_open_shadow_rmap_index(frel, sestate->lockmode);
	sestate->cs_rel = pgstrom_open_shadow_cstore(frel, AccessShareLock);
	sestate->cs_idx = pgstrom_open_shadow_cstore_index(frel, AccessShareLock);
	sestate->rs_rel = pgstrom_open_shadow_rstore(frel, sestate->lockmode);
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
	union_cols = list_concat_unique_int(list_copy(sestate->kernel_cols),
										list_copy(sestate->host_cols));
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
pgstrom_invalidate_window(StromExecState *sestate, AttrNumber j,
						  bool should_free)
{
	if (sestate->curr_cs_values[j])
	{
		if (should_free)
			pfree(sestate->curr_cs_values[j]);
		sestate->curr_cs_values[j] = NULL;
	}
	if (sestate->curr_cs_isnull[j])
	{
		if (should_free)
			pfree(sestate->curr_cs_isnull[j]);
		sestate->curr_cs_isnull[j] = NULL;
	}
	sestate->curr_cs_rowid[j] = -1;
	sestate->curr_cs_nitems[j] = 0;
}

/*
 * pgstrom_seek_window
 *
 * It moves current window of the column-store to focus on the supplied
 * rowid, then set copied values on curr_cs_isnull and curr_cs_values.
 * Older values shall be released if should_free is true, elsewhere caller
 * has to release them.
 */
static bool
pgstrom_seek_window(StromExecState *sestate, AttrNumber j, int64 rowid, 
					bool should_free)
{
	MemoryContext	oldcxt;
	TupleDesc		tupdesc = RelationGetDescr(sestate->cs_rel);
	Form_pg_attribute attr = tupdesc->attrs[j];
	HeapTuple		tuple = NULL;
	ScanKeyData		skeys[2];
	Datum			values[Natts_pg_strom_cs];
	bool			isnull[Natts_pg_strom_cs];
	AttrNumber		new_attnum;
	int64			new_rowid;
	int32			new_nitems;
	bool			might_neighbor = false;

	/* caller needs to check rowid points out of window */
	Assert(rowid <  sestate->curr_cs_rowid[j] ||
		   rowid >= sestate->curr_cs_rowid[j] + sestate->curr_cs_nitems[j]);

	if (sestate->curr_cs_rowid[j] >= 0 &&
		rowid < (sestate->curr_cs_rowid[j] + 2 * sestate->curr_cs_nitems[j]))
		might_neighbor = true;

	/* Clear the cached values */
	pgstrom_invalidate_window(sestate, j, should_free);

	if (might_neighbor)
	{
		tuple = index_getnext(sestate->cs_scan[j], ForwardScanDirection);
		if (HeapTupleIsValid(tuple))
		{
			heap_deform_tuple(tuple, tupdesc, values, isnull);

			new_attnum = DatumGetInt16(values[Anum_pg_strom_cs_attnum - 1]);
			new_rowid = DatumGetInt64(values[Anum_pg_strom_cs_rowid - 1]);
			new_nitems = DatumGetInt32(values[Anum_pg_strom_cs_nitems - 1]);
			Assert(new_attnum == attr->attnum);

			if (rowid < new_rowid || rowid >= new_rowid + new_nitems)
				tuple = NULL;
		}
	}

	if (!HeapTupleIsValid(tuple))
	{
		ScanKeyInit(&skeys[0],
					Inum_pg_strom_cs_attnum,
					BTEqualStrategyNumber, F_INT2EQ,
					Int16GetDatum(attr->attnum));
		ScanKeyInit(&skeys[1],
					Inum_pg_strom_cs_rowid,
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
					Inum_pg_strom_cs_attnum,
					BTEqualStrategyNumber, F_INT2EQ,
					Int16GetDatum(attr->attnum));
		ScanKeyInit(&skeys[1],
					Inum_pg_strom_cs_rowid,
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
		   ? DatumGetByteaPCopy(values[Anum_pg_strom_cs_isnull - 1])
		   : NULL);
	sestate->curr_cs_values[j]
		= DatumGetByteaPCopy(values[Anum_pg_strom_cs_values - 1]);
	MemoryContextSwitchTo(oldcxt);

	return true;
}

static inline Datum
pgstrom_fetch_cs_datum(StromExecState *sestate,
					   AttrNumber j, int64 rowid, bool *p_isnull,
					   bool should_free)
{
	TupleDesc	tupdesc = RelationGetDescr(sestate->frel);
	bytea	   *curr_isnull;
	bytea	   *curr_values;
	int			i;

	Assert(j >= 0 && j < tupdesc->natts);
	if (rowid <  sestate->curr_cs_rowid[j] ||
		rowid >= sestate->curr_cs_rowid[j] + sestate->curr_cs_nitems[j])
	{
		if (!pgstrom_seek_window(sestate, j, rowid, should_free))
			goto out_null;
	}
	curr_isnull = sestate->curr_cs_isnull[j];
	curr_values = sestate->curr_cs_values[j];
	i = rowid - sestate->curr_cs_rowid[j];

	if (!curr_isnull || !(((bool *)VARDATA(curr_isnull))[i]))
	{
		Form_pg_attribute attr = tupdesc->attrs[j];

		*p_isnull = false;
		if (attr->attlen > 0)
			return fetchatt(attr, (VARDATA(curr_values) + attr->attlen * i));
		else
		{
			uint16 *vl_offset = (uint16 *)VARDATA(curr_values);

			return PointerGetDatum(VARDATA(curr_values) + vl_offset[i]);
		}
	}
out_null:
	*p_isnull = true;
	return PointerGetDatum(NULL);
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
	pgstrom_invalidate_window(sestate, j, true);

	ScanKeyInit(&skeys[0],
				Inum_pg_strom_cs_attnum,
				BTEqualStrategyNumber, F_INT2EQ,
				Int16GetDatum(attr->attnum));
	ScanKeyInit(&skeys[1],
				Inum_pg_strom_cs_rowid,
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
pgstrom_load_varlena_column_store(StromExecState *sestate,
								  ChunkBuffer *chunk)
{
	VarlenaBuffer  *vlbuf = NULL;
	ListCell	   *cell;
	bytea		  **vl_cache;
	int				i, j, k, l;

	vl_cache = palloc(sizeof(bytea *) * PGSTROM_UNITSZ *
					  list_length(sestate->varlena_cols));

	for (i=0; i < chunk->nitems; i+=PGSTROM_UNITSZ)
	{
		int64	curr_rowid = chunk->rowid + i;
		Size	vl_length = 0;
		List   *should_free = NIL;

		/* calculation of estimated data length */
		l = 0;
		foreach (cell, sestate->varlena_cols)
		{
			bytea  *prev_values;
			bytea  *prev_isnull;
			bool	isnull;
			Datum	datum;

			j = lfirst_int(cell) - 1;
			prev_values = sestate->curr_cs_values[j];
			prev_isnull = sestate->curr_cs_isnull[j];

			for (k=0; k < PGSTROM_UNITSZ; k++)
			{
				datum = pgstrom_fetch_cs_datum(sestate, j, curr_rowid + k,
											   &isnull, false);
				if (isnull)
					vl_cache[l * PGSTROM_UNITSZ + k] = NULL;
				else
				{
					vl_cache[l * PGSTROM_UNITSZ + k] = (bytea *)datum;
					vl_length += INTALIGN(toast_raw_datum_size(datum));
				}

				if (prev_isnull != sestate->curr_cs_isnull[j])
				{
					if (prev_isnull)
						should_free = lappend(should_free, prev_isnull);
					prev_isnull = sestate->curr_cs_isnull[j];
				}
				if (prev_values != sestate->curr_cs_values[j])
				{
					if (prev_values)
						should_free = lappend(should_free, prev_values);
					prev_values = sestate->curr_cs_values[j];
				}
			}
			l++;
		}

		/*
		 * In case when this unit of varlena values may overrun the
		 * current varlena-buffer, we try to acquire a new one. If
		 * no rows are on this buffer, it has to be enlarged to try
		 * again.
		 */
		if (vlbuf == NULL ||
			vlbuf->kvlbuf->length + vl_length > vlbuf->vlbuf_size)
		{
			Assert(!vlbuf || vlbuf->kvlbuf->nitems > 0);

			if (vlbuf && chunk->varlena_sz < vlbuf->kvlbuf->length)
				chunk->varlena_sz = vlbuf->kvlbuf->length;

			/*
			 * XXX - sestate->vlbuf_size needs to be smaller than
			 * max memory allocation size of opencl device, to be
			 * checked.
			 */
			while (sestate->vlbuf_size < vl_length * (PGSTROM_CHUNK_SIZE /
													  PGSTROM_UNITSZ / 3))
				sestate->vlbuf_size *= 2;

			vlbuf = pgstrom_varlena_buffer_alloc(sestate->vlbuf_size,
											pgstrom_base_addr_align, true);
			vlbuf->kvlbuf->index = i;
			vlbuf->kvlbuf->nitems = 0;
			dlist_push_tail(&chunk->vlbuf_list, &vlbuf->chain);
			chunk->nvarlena++;
		}

		/*
		 * Copy the flatten varlena on the varlena buffer.
		 */
		l = 0;
		foreach (cell, sestate->varlena_cols)
		{
			j = lfirst_int(cell) - 1;

			for (k=0; k < PGSTROM_UNITSZ; k++)
			{
				bytea  *vl_body;
				Size	vl_size;
				char   *vl_ptr;

				vl_body = (bytea *)vl_cache[l * PGSTROM_UNITSZ + k];
				if (!vl_body)
				{
					Assert(chunk->cb_isnull[j] != NULL);
					chunk->cb_isnull[j][i+k] = -1;
					((uint32 *)chunk->cb_values[j])[i+k] = 0;
				}
				else
				{
					if (chunk->cb_isnull[j] != NULL)
						chunk->cb_isnull[j][i+k] = 0;
					((uint32 *)chunk->cb_values[j])[i+k]
						= vlbuf->kvlbuf->length;
					vl_ptr = ((char *)&vlbuf->kvlbuf) + vlbuf->kvlbuf->length;
					vl_size = toast_raw_datum_size(PointerGetDatum(vl_body));
					toast_extract_datum(vl_ptr, vl_body, vl_size);
					vlbuf->kvlbuf->length += INTALIGN(vl_size);
					Assert(vlbuf->kvlbuf->length <= vlbuf->vlbuf_size);
				}
			}
		}
		vlbuf->kvlbuf->nitems += PGSTROM_UNITSZ;
		list_free_deep(should_free);
	}
	if (vlbuf && chunk->varlena_sz < vlbuf->kvlbuf->length)
		chunk->varlena_sz = vlbuf->kvlbuf->length;

	pfree(vl_cache);
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
	tupdesc = RelationGetDescr(sestate->frel);
	foreach (cell, sestate->kernel_cols)
	{
		Form_pg_attribute attr
			= tupdesc->attrs[lfirst_int(cell) - 1];
		if (attr->attlen > 0)
			pgstrom_load_column_store(sestate, chunk, attr);
	}
	if (sestate->varlena_cols != NULL)
		pgstrom_load_varlena_column_store(sestate, chunk);

	chunk->is_loaded = true;

	return true;
}

static inline void
pgstrom_load_varlena_row_store(StromExecState *sestate,
							   ChunkBuffer *chunk)
{
	TupleDesc		tupdesc = RelationGetDescr(sestate->rs_rel);
	HeapTuple	   *rs_cache = chunk->rs_cache;
	VarlenaBuffer  *vlbuf = NULL;
	ListCell	   *cell;
	int				i, k;

	Assert(rs_cache != NULL);
	for (i=0; i < chunk->nitems; i+=PGSTROM_UNITSZ)
	{
		Size	vl_length = 0;
		Size	vl_size;
		Datum	vl_body;
		bool	vl_isnull;
		char   *vl_ptr;

		/* calculate varlena size to be added */
		for (k=0; k < PGSTROM_UNITSZ; k++)
		{
			if (!chunk->cb_rowmap[i+k])
				continue;

			foreach (cell, sestate->varlena_cols)
			{
				AttrNumber	attnum = lfirst_int(cell);

				vl_body = fastgetattr(rs_cache[i+k], attnum,
									  tupdesc, &vl_isnull);
				if (!vl_isnull)
					vl_length += INTALIGN(toast_raw_datum_size(vl_body));
			}
		}

		/* allocate varlena buffer, if needed */
		if (!vlbuf ||
			vlbuf->kvlbuf->length + vl_length > vlbuf->vlbuf_size)
		{
			Assert(!vlbuf || vlbuf->kvlbuf->nitems > 0);

			if (vlbuf && chunk->varlena_sz > vlbuf->kvlbuf->length)
				chunk->varlena_sz = vlbuf->kvlbuf->length;

			/* adjust length of varlena-buffer */
			while (sestate->vlbuf_size < vl_length * (PGSTROM_CHUNK_SIZE /
													  PGSTROM_UNITSZ / 3))
				sestate->vlbuf_size *= 2;

			vlbuf = pgstrom_varlena_buffer_alloc(sestate->vlbuf_size,
											pgstrom_base_addr_align, true);
			vlbuf->kvlbuf->index = i;
			vlbuf->kvlbuf->nitems = 0;
			dlist_push_tail(&chunk->vlbuf_list, &vlbuf->chain);
			chunk->nvarlena++;
		}

		/* copy varlena values onto VarlenaBuffer */
		foreach (cell, sestate->varlena_cols)
		{
			AttrNumber	j = lfirst_int(cell) - 1;
			bool	   *cb_isnull = chunk->cb_isnull[j];
			uint32	   *cb_values = chunk->cb_values[j];

			for (k=0; k < PGSTROM_UNITSZ; k++)
			{
				/*
				 * If this row is already deleted, no need to load varlena
				 * data here. So, we simply mark them as NULL.
				 */
				if (!chunk->cb_rowmap[i+k])
				{
					cb_isnull[i+k] = -1;
					cb_values[i+k] = 0;
					continue;
				}

				vl_body = fastgetattr(rs_cache[i+k], j+1,
									  tupdesc, &vl_isnull);
				if (vl_isnull)
				{
					cb_isnull[i+k] = -1;
					cb_values[i+k] = 0;
				}
				else
				{
					cb_isnull[i+k] = 0;
					cb_values[i+k] = vlbuf->kvlbuf->length;
					vl_size = toast_raw_datum_size(vl_body);
					vl_ptr = (char *)&vlbuf->kvlbuf + vlbuf->kvlbuf->length;
					toast_extract_datum(vl_ptr, (bytea *)vl_body, vl_size);
					vlbuf->kvlbuf->length += INTALIGN(vl_size);
				}
			}
		}
		vlbuf->kvlbuf->nitems += PGSTROM_UNITSZ;
	}

	if (chunk->varlena_sz > vlbuf->kvlbuf->length)
		chunk->varlena_sz = vlbuf->kvlbuf->length;
}

static bool
pgstrom_load_row_store(StromExecState *sestate, ChunkBuffer *chunk)
{
	MemoryContext oldcxt;
	TupleDesc	tupdesc = RelationGetDescr(sestate->rs_rel);
	HeapTuple	tuple;
	int			i, nitems, nitems_ex;
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
	/* expand nitems to the alignment size of PGSTROM_UNITSZ */
	nitems_ex = TYPEALIGN(PGSTROM_UNITSZ, nitems);
	Assert(nitems_ex <= PGSTROM_CHUNK_SIZE);

	/* to avoid rowid == 0, using PGSTROM_CHUNK_SIZE instead */
	refresh_chunk_buffer(sestate, chunk, PGSTROM_CHUNK_SIZE, nitems_ex);

	/*
	 * organize the fetched tuples according to the manner
	 * of column-oriented chunk buffer.
	 */
	memset(chunk->cb_rowmap, 0, sizeof(bool) * nitems);
	if (nitems_ex != nitems)
		memset(chunk->cb_rowmap + nitems, -1,
			   sizeof(bool) * (nitems_ex - nitems));

	if (sestate->kernel_cols == NIL)
		return true;

	Assert(nitems_ex <= PGSTROM_CHUNK_SIZE);
	foreach (cell, sestate->kernel_cols)
	{
		AttrNumber	attnum = lfirst_int(cell);
		Form_pg_attribute attr = tupdesc->attrs[attnum - 1];
		char	   *cb_values;
		bool	   *cb_isnull;
		Datum		rs_value;
		bool		rs_isnull;

		if (attr->attlen < 0)
			continue;

		cb_values = chunk->cb_values[attnum - 1];
		cb_isnull = chunk->cb_isnull[attnum - 1];
		for (i=0; i < nitems; i++)
		{
			rs_value = fastgetattr(chunk->rs_cache[i],
								   attnum, tupdesc, &rs_isnull);
			cb_isnull[i] = (rs_isnull ? -1 : 0);
			if (attr->attbyval)
				store_att_byval(cb_values + attr->attlen * i,
								rs_value, attr->attlen);
			else
				memcpy(cb_values + attr->attlen * i,
					   DatumGetPointer(rs_value), attr->attlen);
		}
	}
	if (sestate->varlena_cols != NIL)
		pgstrom_load_varlena_row_store(sestate, chunk);

	/*
	 * Put some dummy data if original 'nitem' is not a multiple number
	 * of PGSTROM_UNITSZ; to ensure vector load / store operation is
	 * available around boundary.
	 */
	if (nitems_ex > nitems)
	{
		int		drift = nitems_ex - nitems;

		foreach (cell, sestate->kernel_cols)
		{
			AttrNumber	j = lfirst_int(cell) - 1;
			bool	   *cb_isnull = (bool *)chunk->cb_isnull[j];
			char	   *cb_values = (char *)chunk->cb_values[j];
			Form_pg_attribute attr = tupdesc->attrs[j];

			memset(cb_isnull + nitems, -1, sizeof(bool) * drift);
			if (attr->attbyval)
				memset(cb_values + attr->attlen * nitems,
					   0, attr->attlen * drift);
			else
				memset(cb_values + sizeof(int) * nitems,
					   0, sizeof(uint32) * drift);
		}
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
			Datum		temp;

			heap_deform_tuple(newtup, tupdesc, values, isnull);
			new_rowid = DatumGetInt64(values[Anum_pg_strom_rmap_rowid-1]);
			new_nitems = DatumGetInt32(values[Anum_pg_strom_rmap_nitems-1]);

			if (chunk->rowid != new_rowid || chunk->nitems != new_nitems)
				elog(ERROR, "bug? rowid/nitems of shadow rmap updated");

			temp = values[Anum_pg_strom_rmap_rowmap - 1];
			new_rowmap = DatumGetByteaPCopy(temp);
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
		int		rowmap = chunk->cb_rowmap[curr_index];

		if (rowmap == STROMCL_ERRCODE_ROW_MASKED)
		{
			curr_index++;
			continue;
		}
		else if (rowmap != STROMCL_ERRCODE_SUCCESS)
		{
			switch (rowmap)
			{
				case STROMCL_ERRCODE_DIV_BY_ZERO:
					ereport(ERROR,
							(errcode(ERRCODE_DIVISION_BY_ZERO),
							 errmsg("division by zero")));
					break;

				case STROMCL_ERRCODE_OUT_OF_RANGE:
					ereport(ERROR,
							(errcode(ERRCODE_NUMERIC_VALUE_OUT_OF_RANGE),
							 errmsg("value out of range")));
					break;

				default:	/* STROMCL_ERRCODE_INTERNAL */
					ereport(ERROR,
							(errcode(ERRCODE_INTERNAL_ERROR),
						errmsg("opencl server internal error (code: %d)",
							   rowmap)));
					break;
			}
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
				Oid		rs_rowid;

				rs_rowid = HeapTupleGetOid(chunk->rs_cache[curr_index]);
				tuple = ExecMaterializeSlot(slot);
				ItemPointerSetForRowid(tuple, rs_rowid);
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
			while (curr_index > (sestate->curr_vlbuf->kvlbuf->index +
								 sestate->curr_vlbuf->kvlbuf->nitems))
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
					Assert(curr_index >= sestate->curr_vlbuf->kvlbuf->index &&
						   curr_index < (sestate->curr_vlbuf->kvlbuf->index +
										 sestate->curr_vlbuf->kvlbuf->nitems));
					offset = ((uint32 *)chunk->cb_values[j])[curr_index];
					vlbuf_base = (char *)&sestate->curr_vlbuf->kvlbuf;
					slot->tts_values[j]
						= PointerGetDatum((bytea *)(vlbuf_base + offset));
				}
			}
			else
			{
				slot->tts_values[j]
					= pgstrom_fetch_cs_datum(sestate, j, curr_rowid,
											 slot->tts_isnull + j,
											 true);
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

				dlist_delete(&vlbuf->chain);
				pgstrom_varlena_buffer_free(vlbuf);
			}
			Assert(dlist_is_empty(&chunk->vlbuf_list));
			chunk->nvarlena = 0;

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
				elog(INFO, "in rowmap = %016lx", ((uint64 *)chunk->cb_rowmap)[0]);
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
					Assert(!chunk->is_running);
					Assert(chunk->is_loaded);
					chunk->is_running = true;

					clserv_enqueue_chunk(chunk);
					sestate->num_running_chunks++;
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

		elog(INFO, "out rowmap = %016lx", ((uint64 *)sestate->curr_chunk->cb_rowmap)[0]);

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
	TupleDesc		tupdesc;
	dlist_mutable_iter iter;
	dlist_node	   *dnode;
	ChunkBuffer	   *chunk;
	int				j;

	/* if sestate is NULL, we are in EXPLAIN; nothing to do */
	if (sestate == NULL)
		return;

	/*
	 * Release chunk-buffers
	 *
	 * NOTE: no need to release rs_memcxt and rs_cache of chunk-buffer,
	 * because both of local memory should be acquired within per-query
	 * memory context, thus, it shall be released automatically.
	 */
	if (sestate->curr_chunk)
	{
		pgstrom_chunk_buffer_free(sestate->curr_chunk);
		sestate->num_total_chunks--;
	}
	dlist_foreach_modify(iter, &sestate->chunk_ready_list)
	{
		chunk = dlist_container(ChunkBuffer, chain, iter.cur);
		pgstrom_chunk_buffer_free(chunk);
		sestate->num_total_chunks--;
	}
	dlist_foreach_modify(iter, &sestate->chunk_free_list)
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

	tupdesc = RelationGetDescr(sestate->frel);
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
pgstrom_explain_foreign_scan(ForeignScanState *fss,
							 struct ExplainState *es)
{
	ForeignScan	   *fscan = (ForeignScan *)fss->ss.ps.plan;
	Relation		frel = fss->ss.ss_currentRelation;
	TupleDesc		tupdesc = RelationGetDescr(frel);
	text		   *kernel_source;
	bytea		   *kernel_md5;
	char		   *kernel_quals;
	List		   *kernel_params;
	List		   *kernel_cols;
	List		   *host_cols;
	bool			needs_ctid;
	cl_device_type	kernel_devtype;
	char		   *vector_preference;
	StringInfoData	buf;
	ListCell	   *cell;

	/*
     * Fetch planner's information
     */
	fetch_planners_info(frel,
						fscan->fdw_private,
                        &kernel_source,
                        &kernel_md5,
						&kernel_quals,
                        &kernel_params,
                        &kernel_cols,
                        NULL,	/* varlena_cols */
                        &host_cols,
                        &needs_ctid,
                        &kernel_devtype,
                        &vector_preference,
                        NULL,	/* vlbuf_size */
                        NULL,	/* lockmode */
                        NULL);	/* lockmode_nowait */

	/* Dump kernel columns */
	initStringInfo(&buf);
	foreach (cell, kernel_cols)
	{
		AttrNumber	attnum = lfirst_int(cell);
		Form_pg_attribute attr = (attnum > 0 ?
								  tupdesc->attrs[attnum - 1] :
								  SystemAttributeDefinition(attnum, true));
		appendStringInfo(&buf, "%s%s",
						 buf.len > 0 ? ", " : "",
						 NameStr(attr->attname));
	}
	ExplainPropertyText("Internal", buf.data, es);

	if (kernel_source)
	{
		/* dump kernel quals (not verbose) */
		if (!es->verbose)
			ExplainPropertyText("Kernel quals", kernel_quals, es);

		/* dump kernel device */
		resetStringInfo(&buf);
		if (kernel_devtype & CL_DEVICE_TYPE_CPU)
			appendStringInfo(&buf, "%s%s",
							 buf.len > 0 ? ", " : "", "CPU");
		if (kernel_devtype & CL_DEVICE_TYPE_GPU)
			appendStringInfo(&buf, "%s%s",
							 buf.len > 0 ? ", " : "", "GPU");
		if (kernel_devtype & CL_DEVICE_TYPE_ACCELERATOR)
			appendStringInfo(&buf, "%s%s",
							 buf.len > 0 ? ", " : "", "Accelerator");
		ExplainPropertyText("Device types", buf.data, es);

		if (es->verbose)
		{
			static const char *hex = "0123456789abcdef";
			char	strbuf[2 * MD5_SIZE + 1];
			char   *source = text_to_cstring(kernel_source);
			char   *head;
			char   *pos;
			int		lineno = 1;
			int		c, i, j;

			/* dump kernel_md5 in human readable form */
			Assert(kernel_md5 != NULL);
			head = VARDATA(kernel_md5);
			for (i=0, j=0; i < MD5_SIZE; i++)
			{
				strbuf[j++] = hex[(head[i] >> 4) & 0x0f];
				strbuf[j++] = hex[ head[i]       & 0x0f];
			}
			strbuf[j++] = '\0';

			ExplainPropertyText("Source md5", strbuf, es);

			/* output kernel source per line */
			head = pos = source;
			while (true)
			{
				c = *pos++;

				if (c == '\n' || c == '\0')
				{
					snprintf(strbuf, sizeof(strbuf), "% 4d", lineno++);
					pos[-1] = '\0';
					ExplainPropertyText(strbuf, head, es);
					if (c == '\0')
						break;
					head = pos;
				}
			}
		}
	}
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
