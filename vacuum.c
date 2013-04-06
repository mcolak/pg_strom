/*
 * vacuum.c
 *
 * Routines to maintain column- and row-store of PG-Strom; its concept
 * is similar to vacuuming tables in the core PostgreSQL.
 * It wipes out rows in less-density chunks into row-store, then moves
 * them back to column store with a unit of PGSTROM_CHUNK_SIZE.
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
#include "catalog/indexing.h"
#include "catalog/pg_class.h"
#include "lib/stringinfo.h"
#include "storage/itemptr.h"
#include "utils/fmgroids.h"
#include "utils/guc.h"
#include "utils/memutils.h"
#include "utils/rel.h"
#include "utils/snapmgr.h"
#include "utils/tqual.h"
#include "pg_strom.h"

/*
 * TODO: pgstrom_vacuum shall perform as background worker to eliminate
 * necessity of explicit invocations.
 */

/* Local declarations */
static double	pgstrom_vacuum_threshold;
#ifdef PGSTROM_AUTOVACUUM
static bool		pgstrom_autovacuum_enabled;
#endif

typedef struct {
	Relation		frel;
	Relation		rmap_rel;
	Relation		rmap_idx;
	Relation		cs_rel;
	Relation		cs_idx;
	Relation		rs_rel;
	HeapScanDesc	rmap_scan;
	IndexScanDesc	cs_scan;
	HeapScanDesc	rs_scan;
	CatalogIndexState rmap_idxst;
	CatalogIndexState cs_idxst;
	CatalogIndexState rs_idxst;
	bool		   *cs_rowmap;
	int				cs_nitems;
	bool		  **cs_isnull;
	Datum		  **cs_values;
	ItemPointerData	rs_ctids[PGSTROM_CHUNK_SIZE];
	int64			rowid_cache[64];
	int				rowid_usage;
	MemoryContext	memcxt;
} VacuumState;

/* macros for convenience */
#define toast_compress_bytea(value)										\
	((bytea *)DatumGetPointer(toast_compress_datum(PointerGetDatum(value))))

static inline bool
chunk_needs_reclaimed(int64 cs_rowid, int32 cs_nitems, bytea *cs_rowmap)
{
	bool   *map = VARDATA(cs_rowmap);
	int		threshold;
	int		i, count;

	if (sizeof(bool) * cs_nitems != VARSIZE_ANY_EXHDR(cs_rowmap))
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED),
				 errmsg("Bug? nitems (%u) doesn't match length of rowmap (%u)",
						cs_nitems, VARSIZE_ANY_EXHDR(cs_rowmap))));

	threshold = (int)(pgstrom_vacuum_threshold *
					  (double)PGSTROM_CHUNK_SIZE / 100.0);
	for (i=0, count=0; i < cs_nitems; i++)
	{
		if (map[i])
			count++;
	}
	if (count >= threshold)
		return false;

	return true;
}

static int64
get_new_rowid(VacuumState *vstate)
{
	if (vstate->rowid_usage <= 0)
	{
		SnapshotData	snapshotDirty;
		IndexScanDesc	scan;
		ScanKeyData		skey;
		TupleDesc		tupdesc = RelationGetDescr(vstate->rmap_rel);
		HeapTuple		tuple;
		int64			next_rowid;
		int64			curr_rowid;
		int64			last_rowid;
		int				usage;
		Datum			value;
		bool			isnull;

		InitDirtySnapshot(snapshotDirty);

		scan = index_beginscan(vstate->rmap_rel,
							   vstate->rmap_idx,
							   &snapshotDirty, 1, 0);
		if (vstate->rowid_usage < 0)
		{
			ScanKeyInit(&skey,
						Inum_pg_strom_rmap_rowid,
						BTLessEqualStrategyNumber, F_INT8LE,
						Int64GetDatum(PGSTROM_ROWID_MAX));
			index_rescan(scan, &skey, 1, NULL, 0);

			tuple = index_getnext(scan, BackwardScanDirection);
			if (!HeapTupleIsValid(tuple))
				last_rowid = PGSTROM_ROWID_MIN;
			else
			{
				value = heap_getattr(tuple,
									 Anum_pg_strom_rmap_rowid,
									 tupdesc, &isnull);
				Assert(!isnull);
				last_rowid = DatumGetInt64(value);
			}
		}
		else
			last_rowid = vstate->rowid_cache[0];

		ScanKeyInit(&skey,
					Inum_pg_strom_rmap_rowid,
					BTGreaterStrategyNumber, F_INT8GT,
					Int64GetDatum(last_rowid));
		index_rescan(scan, &skey, 1, NULL, 0);

		usage = lengthof(vstate->rowid_cache);
		while (usage > 0)
		{
			tuple = index_getnext(scan, ForwardScanDirection);
			if (!HeapTupleIsValid(tuple))
				next_rowid = PGSTROM_ROWID_MAX;
			else
			{
				value = heap_getattr(tuple,
									 Anum_pg_strom_rmap_rowid,
									 tupdesc, &isnull);
				Assert(!isnull);
				next_rowid = DatumGetInt64(value);
			}

			for (curr_rowid = last_rowid + PGSTROM_CHUNK_SIZE;
				 curr_rowid <= next_rowid && usage > 0;
				 curr_rowid += PGSTROM_CHUNK_SIZE)
			{
				vstate->rowid_cache[--usage] = curr_rowid;
			}

			if (next_rowid == PGSTROM_ROWID_MAX && usage > 0)
			{
				ScanKeyInit(&skey,
							Inum_pg_strom_rmap_rowid,
							BTGreaterEqualStrategyNumber, F_INT8GE,
							Int64GetDatum(PGSTROM_ROWID_MIN));
				index_rescan(scan, &skey, 1, NULL, 0);
			}
		}
		vstate->rowid_usage = lengthof(vstate->rowid_cache);

		index_endscan(scan);
	}
	return vstate->rowid_cache[--vstate->rowid_usage];
}

static void
flush_numeric_to_column_store(VacuumState *vstate, Form_pg_attribute attr,
							  int64 new_rowid, int32 new_nitems)
{
	int64		cs_rowid;
	int32		cs_nitems;
	bytea	   *cs_isnull;
	bytea	   *cs_values;
	bytea	   *uncompress;
	size_t		length;
	Datum		values[Natts_pg_strom_cs];
	bool		isnull[Natts_pg_strom_cs];
	TupleDesc	tupdesc = RelationGetDescr(vstate->cs_rel);
	HeapTuple	tuple;
	int			i, k;
	AttrNumber	j = attr->attnum - 1;

	for (i=0; i < new_nitems; i += cs_nitems)
	{
		cs_rowid  = new_rowid + i;

		/*
		 * At first, we estimate a possible cs_nitems with assumption that
		 * cs_isnull[i] ... cs_isnull[i + cs_nitems - 1] contains no NULLs.
		 * If assumption was not true, we adjust cs_nitems later.
		 */
		cs_nitems = PGSTROM_CSTORE_DATASZ / attr->attlen;

		if (cs_rowid + cs_nitems > new_rowid + new_nitems)
			cs_nitems = new_rowid - cs_rowid + new_nitems;

		cs_isnull = NULL;
		if (!attr->attnotnull)
		{
			for (k=0; k < cs_nitems; k++)
			{
				if (vstate->cs_isnull[j][i+k])
				{
					/*
					 * If here is one or NULL on this region, cs_nitems
					 * gets shorten to save null-map.
					 */
					cs_nitems = PGSTROM_CSTORE_DATASZ / (attr->attlen +
														 sizeof(bool));
					if (cs_rowid + cs_nitems > new_rowid + new_nitems)
						cs_nitems = new_rowid - cs_rowid + new_nitems;

					length = VARHDRSZ + sizeof(bool) * cs_nitems;
					uncompress = palloc(length);
					memcpy(VARDATA(uncompress),
						   vstate->cs_isnull[j] + i,
						   sizeof(bool) * cs_nitems);
					SET_VARSIZE(uncompress, length);

					cs_isnull = toast_compress_bytea(uncompress);
					if (!cs_isnull)
						cs_isnull = uncompress;
					break;
				}
			}
		}

		length = VARHDRSZ + attr->attlen * cs_nitems;
		uncompress = palloc(length);
		for (k=0; k < cs_nitems; k++)
		{
			if (attr->attbyval)
				store_att_byval(VARDATA(uncompress) + attr->attlen * k,
								vstate->cs_values[j][i + k],
								attr->attlen);
			else
				memcpy(VARDATA(uncompress) + attr->attlen * k,
					   DatumGetPointer(vstate->cs_values[j][i + k]),
					   attr->attlen);
		}
		SET_VARSIZE(uncompress, length);

		cs_values = toast_compress_bytea(uncompress);
		if (!cs_values)
			cs_values = uncompress;

		/*
		 * Insert a tuple of column-store
		 */
		memset(isnull, 0, sizeof(isnull));
		values[Anum_pg_strom_cs_attnum - 1] = Int16GetDatum(attr->attnum);
		values[Anum_pg_strom_cs_rowid - 1] = Int64GetDatum(cs_rowid);
		values[Anum_pg_strom_cs_nitems - 1] = Int32GetDatum(cs_nitems);
		if (!cs_isnull)
			isnull[Anum_pg_strom_cs_isnull - 1] = true;
		else
			values[Anum_pg_strom_cs_isnull - 1] = PointerGetDatum(cs_isnull);
		values[Anum_pg_strom_cs_values - 1] = PointerGetDatum(cs_values);

		tuple = heap_form_tuple(tupdesc, values, isnull);
		simple_heap_insert(vstate->cs_rel, tuple);
		CatalogIndexInsert(vstate->cs_idxst, tuple);
	}
}

static void
flush_varlena_to_column_store(VacuumState *vstate, Form_pg_attribute attr,
							  int64 new_rowid, int32 new_nitems)
{
	bytea	   *cs_isnull;
	bytea	   *cs_values;
	bytea	   *uncompress;
	TupleDesc	tupdesc = RelationGetDescr(vstate->cs_rel);
	HeapTuple	tuple;
	Datum		values[Natts_pg_strom_cs];
	bool		isnull[Natts_pg_strom_cs];
	bool		has_null = false;
	bool		v_isnull[PGSTROM_CHUNK_SIZE];
	uint16		v_offset[PGSTROM_CHUNK_SIZE];
	int			i, k, base, shift;
	AttrNumber	j = attr->attnum - 1;
	StringInfoData buf;

	initStringInfo(&buf);
	cs_isnull = palloc(VARHDRSZ + sizeof(bool) * new_nitems);

	for (i=0, base=0; i <= new_nitems; i++)
	{
		bytea  *v_body;
		int		nitems = i - base;

		/*
		 * Note: in case of i == curr_nitems is a dummy, to flush remaining
		 * contents in this chunk to column-store.
		 */
		if (i == new_nitems || vstate->cs_isnull[j][i])
			v_body = NULL;
		else
		{
			uncompress = DatumGetByteaPCopy(vstate->cs_values[j][i]);
			if (VARSIZE(uncompress) > TOAST_TUPLE_THRESHOLD)
			{
				v_body = toast_save_bytea(vstate->cs_rel,
										  uncompress, NULL, 0);
			}
			else
				v_body = uncompress;
		}

		if (i == new_nitems ||
			MAXALIGN((has_null || !v_body) ? sizeof(bool) * (nitems + 1) : 0)
			+ MAXALIGN(sizeof(uint16) * (nitems + 1))
			+ MAXALIGN(!v_body ? 0 : VARSIZE_ANY(v_body))
			+ buf.len > PGSTROM_CSTORE_DATASZ)
		{
			size_t	length;

			memset(isnull, 0, sizeof(isnull));
			memset(values, 0, sizeof(values));
			values[Anum_pg_strom_cs_attnum - 1]
				= Int16GetDatum(attr->attnum);
			values[Anum_pg_strom_cs_rowid - 1]
				= Int64GetDatum(new_rowid + base);
			values[Anum_pg_strom_cs_nitems - 1]
				= Int32GetDatum(nitems);
			if (!has_null)
				isnull[Anum_pg_strom_cs_isnull - 1] = true;
			else
			{
				length = VARHDRSZ + sizeof(bool) * nitems;
				uncompress = palloc(length);
				memcpy(VARDATA(uncompress), v_isnull, length);
				SET_VARSIZE(uncompress, length);
				cs_isnull = toast_compress_bytea(uncompress);
				if (!cs_isnull)
					cs_isnull = uncompress;
				else if (VARSIZE(cs_isnull) > length / 2)
					cs_isnull = uncompress;

				values[Anum_pg_strom_cs_isnull - 1]
					= PointerGetDatum(cs_isnull);
			}

			shift = MAXALIGN(sizeof(uint16) * nitems);
			for (k=0; k < nitems; k++)
				v_offset[k] += shift;
			length = VARHDRSZ + MAXALIGN(sizeof(uint16) * nitems) + buf.len;

			uncompress = palloc(length);
			memcpy(VARDATA(uncompress), v_offset, sizeof(uint16) * nitems);
			if (sizeof(uint16) * nitems != shift)
				memset(VARDATA(uncompress) + sizeof(uint16) * nitems,
					   0,
					   shift - sizeof(uint16) * nitems);
			memcpy(VARDATA(uncompress) + shift, buf.data, buf.len);

			SET_VARSIZE(uncompress, length);
			cs_values = toast_compress_bytea(uncompress);
			if (!cs_values)
				cs_values = uncompress;
			else if (VARSIZE(cs_values) > length / 2)
				cs_values = uncompress;

			values[Anum_pg_strom_cs_values - 1] = PointerGetDatum(cs_values);

			tuple = heap_form_tuple(tupdesc, values, isnull);
			Assert(tuple->t_len <= MaximumBytesPerTuple(1));
			simple_heap_insert(vstate->cs_rel, tuple);
			CatalogIndexInsert(vstate->cs_idxst, tuple);

			if (i == new_nitems)
				break;

			has_null = false;
			base = i;
			nitems = 0;
			resetStringInfo(&buf);
		}

		if (!v_body)
		{
			v_isnull[nitems] = true;
			v_offset[nitems] = 0;
			has_null = true;
		}
		else
		{
			v_isnull[nitems] = false;
			v_offset[nitems] = buf.len;
			appendBinaryStringInfo(&buf, (char *)v_body, VARSIZE_ANY(v_body));
		}
	}
}

static void
flush_vstate_to_column_store(VacuumState *vstate)
{
	int64		new_rowid;
	int32		new_nitems;
	bytea	   *uncompress;
	bytea	   *new_rowmap;
	TupleDesc	tupdesc;
	HeapTuple	newtup;
	Datum		values[Natts_pg_strom_rmap];
	bool		isnull[Natts_pg_strom_rmap];
	int			i, j;
	size_t		length;
	StringInfoData buf;

	Assert(vstate->cs_nitems == PGSTROM_CHUNK_SIZE);
	initStringInfo(&buf);

	/*
	 * Insert a new rowmap
	 */
	new_rowid = get_new_rowid(vstate);
	new_nitems = vstate->cs_nitems;
	length = VARHDRSZ + sizeof(bool) * new_nitems;
	uncompress = palloc(length);
	SET_VARSIZE(uncompress, length);
	memset(VARDATA(uncompress), -1, sizeof(bool) * new_nitems);
	new_rowmap = toast_compress_bytea(uncompress);
	if (!new_rowmap)
		new_rowmap = uncompress;

	memset(isnull, 0, sizeof(isnull));
	values[Anum_pg_strom_rmap_rowid - 1] = Int64GetDatum(new_rowid);
	values[Anum_pg_strom_rmap_nitems - 1] = Int32GetDatum(new_nitems);
	values[Anum_pg_strom_rmap_rowmap - 1] = PointerGetDatum(new_rowmap);

	tupdesc = RelationGetDescr(vstate->rmap_rel);
	newtup = heap_form_tuple(tupdesc, values, isnull);
	simple_heap_insert(vstate->rmap_rel, newtup);
	CatalogIndexInsert(vstate->rmap_idxst, newtup);

	/*
	 * Insert new column-store entries
	 */
	tupdesc = RelationGetDescr(vstate->frel);
	for (j=0; j < tupdesc->natts; j++)
	{
		Form_pg_attribute attr = tupdesc->attrs[j];

		if (attr->attisdropped)
			continue;

		if (attr->attlen > 0)
			flush_numeric_to_column_store(vstate, attr, new_rowid, new_nitems);
		else
			flush_varlena_to_column_store(vstate, attr, new_rowid, new_nitems);
	}

	/*
	 * Delete source tuples if came from row-store
	 */
	for (i=0; i < vstate->cs_nitems; i++)
	{
		if (ItemPointerIsValid(&vstate->rs_ctids[i]))
			simple_heap_delete(vstate->rs_rel, &vstate->rs_ctids[i]);
	}
}

static int
flush_vstate_to_row_store(VacuumState *vstate)
{
	TupleDesc	rs_tupdesc = RelationGetDescr(vstate->rs_rel);
	Datum	   *rs_values = palloc(sizeof(Datum) * rs_tupdesc->natts);
	bool	   *rs_isnull = palloc(sizeof(bool) * rs_tupdesc->natts);
	HeapTuple	tuple;
	int			count = 0;
	int			i, j;

	for (i=0; i < vstate->cs_nitems; i++)
	{
		/*
		 * In case when this row come from row-store, we don't need to 
		 * write it back to row-store anyway.
		 */
		if (ItemPointerIsValid(&vstate->rs_ctids[i]))
			continue;

		for (j=0; j < rs_tupdesc->natts; j++)
		{
			if (vstate->cs_isnull[j][i])
			{
				rs_isnull[j] = true;
				rs_values[j] = (Datum)0;
			}
			else
			{
				rs_isnull[j] = false;
				rs_values[j] = vstate->cs_values[j][i];
			}
		}
		tuple = heap_form_tuple(rs_tupdesc, rs_values, rs_isnull);
		simple_heap_insert(vstate->rs_rel, tuple);
		CatalogIndexInsert(vstate->rs_idxst, tuple);
		count++;
	}
	return count;
}

static int
reclaim_column_store(VacuumState *vstate,
					 int64 curr_rowid, int32 curr_nitems, bool *curr_rowmap)
{
	TupleDesc	frel_tupdesc = RelationGetDescr(vstate->frel);
	TupleDesc	this_tupdesc = RelationGetDescr(vstate->cs_rel);
	AttrNumber	j, nattrs = frel_tupdesc->natts;
	ScanKeyData	skeys[3];
	HeapTuple	tuple;
	bool	  **cb_isnull;
	Datum	  **cb_values;
	int			i, count = 0;

	cb_isnull = palloc0(sizeof(bool *) * nattrs);
	cb_values = palloc0(sizeof(Datum *) * nattrs);
	for (j=0; j < nattrs; j++)
	{
		Form_pg_attribute attr = frel_tupdesc->attrs[j];

		ScanKeyInit(&skeys[0],
					Inum_pg_strom_cs_attnum,
					BTEqualStrategyNumber, F_INT2EQ,
					Int16GetDatum(attr->attnum));
		ScanKeyInit(&skeys[1],
					Inum_pg_strom_cs_rowid,
					BTGreaterEqualStrategyNumber, F_INT8GE,
					Int64GetDatum(curr_rowid));
		ScanKeyInit(&skeys[2],
					Inum_pg_strom_cs_rowid,
					BTLessStrategyNumber, F_INT8LT,
					Int64GetDatum(curr_rowid + curr_nitems));
		index_rescan(vstate->cs_scan, skeys, 3, NULL, 0);

		/* buffer allocation */
		cb_isnull[j] = palloc(sizeof(bool) * curr_nitems);
		cb_values[j] = palloc(sizeof(Datum) * curr_nitems);
		memset(cb_isnull[j], 0, sizeof(bool) * curr_nitems);
		memset(cb_values[j], 0, sizeof(Datum) * curr_nitems);

		while (HeapTupleIsValid(tuple = index_getnext(vstate->cs_scan,
													  ForwardScanDirection)))
		{
			Datum	this_values[Natts_pg_strom_cs];
			bool	this_isnull[Natts_pg_strom_cs];
			int64	cs_rowid;
			int32	cs_nitems;
			bytea  *cs_isnull;
			bytea  *cs_values;
			Datum	temp;
			int		shift;

			heap_deform_tuple(tuple, this_tupdesc, this_values, this_isnull);
			Assert(!this_isnull[Anum_pg_strom_cs_attnum - 1] &&
				   !this_isnull[Anum_pg_strom_cs_rowid - 1] &&
				   !this_isnull[Anum_pg_strom_cs_nitems - 1] &&
				   !this_isnull[Anum_pg_strom_cs_values - 1]);

			cs_rowid = DatumGetInt64(this_values[Anum_pg_strom_cs_rowid-1]);
			cs_nitems = DatumGetInt32(this_values[Anum_pg_strom_cs_nitems-1]);
			Assert(cs_rowid >= curr_rowid &&
				   cs_rowid + cs_nitems <= curr_rowid + curr_nitems);
			shift = cs_rowid - curr_rowid;

			/* Put NULL map on buffer */
			if (this_isnull[Anum_pg_strom_cs_isnull - 1])
				memset(cb_isnull[j] + shift, 0, sizeof(bool) * cs_nitems);
			else
			{
				temp = this_values[Anum_pg_strom_cs_isnull - 1];
				cs_isnull = DatumGetByteaPCopy(temp);
				if (VARSIZE_ANY_EXHDR(cs_isnull) != sizeof(bool) * cs_nitems)
					ereport(ERROR,
							(errcode(ERRCODE_DATA_CORRUPTED),
							 errmsg("Bug? length of cs_isnull is corrupted")));
				memcpy(cb_isnull[j] + shift,
					   VARDATA(cs_isnull),
					   sizeof(bool) * cs_nitems);
			}

			/* Put values on buffer */
			temp = this_values[Anum_pg_strom_cs_values - 1];
			cs_values = DatumGetByteaPP(temp);
			for (i=0; i < cs_nitems; i++)
			{
				if (attr->attlen > 0)
				{
					cb_values[j][shift + i]
						= fetchatt(attr, (VARDATA(cs_values) +
										  i * attr->attlen));
				}
				else
				{
					uint16 *v_offset = (uint16 *)VARDATA(cs_values);
					bytea  *v_body = (bytea *)(VARDATA(cs_values) +
											   v_offset[i]);

					cb_values[j][shift + i]
						= PointerGetDatum(PG_DETOAST_DATUM_PACKED(v_body));

					/* Also drop external Toast, if needed */
					toast_delete_bytea(vstate->cs_rel, v_body);
				}
			}
			/* Drop this item */
			simple_heap_delete(vstate->cs_rel, &tuple->t_self);
		}
	}

	/*
	 * Save it on VacuumState
	 */
	for (i=0; i < curr_nitems; i++)
	{
		/* skip, if it was removed */
		if (!curr_rowmap[i])
			continue;

		for (j=0; j < nattrs; j++)
		{
			Form_pg_attribute attr = frel_tupdesc->attrs[j];

			vstate->cs_isnull[j][vstate->cs_nitems] = cb_isnull[j][i];
			if (attr->attbyval)
				vstate->cs_isnull[j][vstate->cs_nitems] = cb_isnull[j][i];
			else
			{
				MemoryContext	oldcxt
					= MemoryContextSwitchTo(vstate->memcxt);
				if (attr->attlen > 0)
				{
					void   *src = DatumGetPointer(cb_values[j][i]);
					void   *dst = palloc(attr->attlen);

					memcpy(dst, src, attr->attlen);
					vstate->cs_values[j][vstate->cs_nitems]
						= PointerGetDatum(dst);
				}
				else
				{
					bytea  *temp = PG_DETOAST_DATUM_COPY(cb_values[j][i]);

					vstate->cs_values[j][vstate->cs_nitems]
						= PointerGetDatum(temp);
				}
				MemoryContextSwitchTo(oldcxt);
			}
		}
		ItemPointerSetInvalid(&vstate->rs_ctids[vstate->cs_nitems]);

		vstate->cs_nitems++;
		if (vstate->cs_nitems == PGSTROM_CHUNK_SIZE)
		{
			flush_vstate_to_column_store(vstate);

			MemoryContextReset(vstate->memcxt);
			count += vstate->cs_nitems;
			vstate->cs_nitems = 0;
		}
	}
	return count;
}

static int
columnize_row_store(VacuumState *vstate, MemoryContext work_cxt)
{
	TupleDesc	tupdesc = RelationGetDescr(vstate->rs_rel);
	HeapTuple	tuple;
	Datum	   *rs_values;
	bool	   *rs_isnull;
	int			count = 0;
	AttrNumber	j;

	Assert(vstate->cs_nitems < PGSTROM_CHUNK_SIZE);

	rs_values = palloc0(sizeof(Datum) * tupdesc->natts);
	rs_isnull = palloc0(sizeof(bool) * tupdesc->natts);
	while (HeapTupleIsValid(tuple = heap_getnext(vstate->rs_scan,
                                                 ForwardScanDirection)))
	{
		MemoryContext	oldcxt = MemoryContextSwitchTo(work_cxt);

		heap_deform_tuple(tuple, tupdesc, rs_values, rs_isnull);

		for (j=0; j < tupdesc->natts; j++)
		{
			Form_pg_attribute	attr = tupdesc->attrs[j];

			if (attr->attisdropped || rs_isnull[j])
			{
				vstate->cs_isnull[j][vstate->cs_nitems] = true;
				vstate->cs_values[j][vstate->cs_nitems] = (Datum)0;
			}
			else if (attr->attbyval)
			{
				vstate->cs_isnull[j][vstate->cs_nitems] = false;
				vstate->cs_values[j][vstate->cs_nitems] = rs_values[j];
			}
			else
			{
				size_t	length = (attr->attlen > 0
								  ? attr->attlen
								  : VARSIZE_ANY(rs_values[j]));
				char   *temp = MemoryContextAlloc(vstate->memcxt, length);

				memcpy(temp, DatumGetPointer(rs_values[j]), length);
				vstate->cs_isnull[j][vstate->cs_nitems] = false;
				vstate->cs_values[j][vstate->cs_nitems]
					= PointerGetDatum(temp);
			}
		}
		/* save the source item pointer */
		ItemPointerCopy(&tuple->t_self,
						&vstate->rs_ctids[vstate->cs_nitems]);
		vstate->cs_nitems++;

		if (vstate->cs_nitems == PGSTROM_CHUNK_SIZE)
		{
			flush_vstate_to_column_store(vstate);

			MemoryContextSwitchTo(oldcxt);
			MemoryContextReset(vstate->memcxt);
			MemoryContextReset(work_cxt);
			count += vstate->cs_nitems;
			vstate->cs_nitems = 0;
		}
		else
			MemoryContextSwitchTo(oldcxt);
	}
	return count;
}

static int
pgstrom_vacuum_relation(Relation relation)
{
	TupleDesc		tupdesc = RelationGetDescr(relation);
	VacuumState	   *vstate;
	LOCKMODE		lockmode;
	Snapshot		snapshot;
	HeapTuple		tuple;
	MemoryContext	work_cxt;
	MemoryContext	oldcxt;
	int				count = 0;
	int				j;

	/*
	 * Set up vacuum state
	 */
	vstate = palloc0(sizeof(VacuumState));

	lockmode = ShareUpdateExclusiveLock;
	snapshot = GetActiveSnapshot();
	vstate->frel = relation;
	vstate->rmap_rel = pgstrom_open_shadow_rmap(relation, lockmode);
	vstate->rmap_idx = pgstrom_open_shadow_rmap_index(relation, lockmode);
	vstate->cs_rel = pgstrom_open_shadow_cstore(relation, lockmode);
	vstate->cs_idx = pgstrom_open_shadow_cstore_index(relation, lockmode);
	vstate->rs_rel = pgstrom_open_shadow_rstore(relation, lockmode);

	vstate->rmap_scan = heap_beginscan(vstate->rmap_rel,
									   snapshot, 0, NULL);
	vstate->cs_scan = index_beginscan(vstate->cs_rel,
									  vstate->cs_idx,
									  snapshot, 3, 0);
	vstate->rs_scan = heap_beginscan(vstate->rs_rel,
									 snapshot, 0, NULL);

	vstate->rmap_idxst = CatalogOpenIndexes(vstate->rmap_rel);
	vstate->cs_idxst = CatalogOpenIndexes(vstate->cs_rel);
	vstate->rs_idxst = CatalogOpenIndexes(vstate->rs_rel);

	vstate->cs_rowmap = palloc0(sizeof(bool) * PGSTROM_CHUNK_SIZE);
	vstate->cs_nitems = 0;
	vstate->cs_isnull = palloc0(sizeof(bool *) * tupdesc->natts);
	vstate->cs_values = palloc0(sizeof(Datum *) * tupdesc->natts);
	for (j=0; j < tupdesc->natts; j++)
	{
		if (tupdesc->attrs[j]->attisdropped)
			continue;
		vstate->cs_isnull[j] = palloc0(sizeof(bool) * PGSTROM_CHUNK_SIZE);
		vstate->cs_values[j] = palloc0(sizeof(Datum) * PGSTROM_CHUNK_SIZE);
	}
	vstate->memcxt = AllocSetContextCreate(CurrentMemoryContext,
										   "PG-Strom vacuum state",
										   ALLOCSET_DEFAULT_MINSIZE,
										   ALLOCSET_DEFAULT_INITSIZE,
										   ALLOCSET_DEFAULT_MAXSIZE);
	work_cxt = AllocSetContextCreate(CurrentMemoryContext,
									 "PG-Strom vacuum working memory",
									 ALLOCSET_DEFAULT_MINSIZE,
									 ALLOCSET_DEFAULT_INITSIZE,
									 ALLOCSET_DEFAULT_MAXSIZE);
	vstate->rowid_usage = -1;

	/*
	 * Scan the underlying column-store
	 */
	tupdesc = RelationGetDescr(vstate->rmap_rel);
	while (HeapTupleIsValid(tuple = heap_getnext(vstate->rmap_scan,
												 ForwardScanDirection)))
	{
		Datum	values[Natts_pg_strom_rmap];
		bool	isnull[Natts_pg_strom_rmap];
		int64	cs_rowid;
		int32	cs_nitems;
		bytea  *cs_rowmap;

		oldcxt = MemoryContextSwitchTo(work_cxt);

		heap_deform_tuple(tuple, tupdesc, values, isnull);
		cs_rowid = DatumGetInt64(values[Anum_pg_strom_rmap_rowid - 1]);
		cs_nitems = DatumGetInt32(values[Anum_pg_strom_rmap_nitems - 1]);
		cs_rowmap = DatumGetByteaPCopy(values[Anum_pg_strom_rmap_rowmap - 1]);
		Assert(cs_nitems == VARSIZE_ANY_EXHDR(cs_rowmap) / sizeof(bool));

		if (chunk_needs_reclaimed(cs_rowid, cs_nitems, cs_rowmap))
		{
			count += reclaim_column_store(vstate, cs_rowid, cs_nitems,
										  (bool *)VARDATA(cs_rowmap));

			simple_heap_delete(vstate->rmap_rel, &tuple->t_self);
		}
		MemoryContextSwitchTo(oldcxt);
	}

	/*
	 * Scan the underlying row-store
	 */
	count += columnize_row_store(vstate, work_cxt);
	if (vstate->cs_nitems > 0)
		count += flush_vstate_to_row_store(vstate);

	/*
	 * Cleanup resources
	 */
	MemoryContextDelete(work_cxt);
	MemoryContextDelete(vstate->memcxt);

	CatalogCloseIndexes(vstate->rs_idxst);
	CatalogCloseIndexes(vstate->cs_idxst);
	CatalogCloseIndexes(vstate->rmap_idxst);

	heap_endscan(vstate->rs_scan);
	index_endscan(vstate->cs_scan);
	heap_endscan(vstate->rmap_scan);

	heap_close(vstate->rs_rel, NoLock);
	index_close(vstate->cs_idx, NoLock);
	heap_close(vstate->cs_rel, NoLock);
	index_close(vstate->rmap_idx, NoLock);
	heap_close(vstate->rmap_rel, NoLock);

	for (j=0; j < tupdesc->natts; j++)
	{
		if (vstate->cs_isnull[j])
			pfree(vstate->cs_isnull[j]);
		if (vstate->cs_values[j])
			pfree(vstate->cs_values[j]);
	}
	pfree(vstate->cs_values);
	pfree(vstate->cs_isnull);
	pfree(vstate->cs_rowmap);

	return count;
}

Datum
pgstrom_vacuum(PG_FUNCTION_ARGS)
{
	Oid			relid = PG_GETARG_OID(0);
	Relation	relation;
	int			count;

	/*
	 * Is this relation a foreign table managed by PG-Strom?
	 */
	relation = heap_open(relid, ShareUpdateExclusiveLock);
	if (RelationGetForm(relation)->relkind != RELKIND_FOREIGN_TABLE)
		ereport(ERROR,
				(errcode(ERRCODE_WRONG_OBJECT_TYPE),
				 errmsg("\"%s\" is not a foreign table",
						RelationGetRelationName(relation))));

	if (!is_pgstrom_managed_relation(relation))
		ereport(ERROR,
				(errcode(ERRCODE_WRONG_OBJECT_TYPE),
				 errmsg("\"%s\" is not managed by PG-Strom",
						RelationGetRelationName(relation))));

	/* do the job */
	count = pgstrom_vacuum_relation(relation);

	heap_close(relation, NoLock);

	PG_RETURN_INT32(count);
}
PG_FUNCTION_INFO_V1(pgstrom_vacuum);

void
pgstrom_vacuum_init(void)
{
#ifdef PGSTROM_AUTOVACUUM
	BackgroundWorker	worker;
#endif

	/* GUC */
	DefineCustomRealVariable("pg_strom.vacuum_threshold",
							 "threshold percentage to vacuum a chunk",
							 NULL,
							 &pgstrom_vacuum_threshold,
							 90.00,		/*  90.00% */
							 10.00,		/*  10.00% */
							 100.00,	/* 100.00% */
							 PGC_USERSET,
							 GUC_NOT_IN_SAMPLE,
							 NULL, NULL, NULL);
#ifdef PGSTROM_AUTOVACUUM
	DefineCustomBoolVariable("pg_strom.autovacuum_enabled",
							 "tuen on/off PG-Strom's autovacuum feature",
							 NULL,
							 &pgstrom_autovacuum_enabled,
							 false,
							 PGC_POSTMASTER,
							 GUC_NOT_IN_SAMPLE,
							 NULL, NULL, NULL);
	if (!pgstrom_autovacuum_enabled)
		return;

	/* registration of background worker process */
	worker.bgw_name = "PG-Strom autovacuumer/columnizer";
	worker.bgw_flags
		= BGWORKER_SHMEM_ACCESS | BGWORKER_BACKEND_DATABASE_CONNECTION;
	worker.bgw_start_time = BgWorkerStart_RecoveryFinished;
	worker.bgw_restart_time = 20;
	worker.bgw_main = pgstrom_vacuum_main;
	worker.bgw_main_arg = NULL;
	worker.bgw_sighup = pgstrom_vacuum_sighup;
	worker.bgw_sigterm = pgstrom_vacuum_sigterm;

	RegisterBackgroundWorker(&worker);
#endif
}
