/*
 * utilcmds.c
 *
 * routines to manage shadow tables/indexes on DDL commands
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
#include "access/htup_details.h"
#include "access/xact.h"
#include "catalog/heap.h"
#include "catalog/index.h"
#include "catalog/namespace.h"
#include "catalog/pg_attribute.h"
#include "catalog/pg_authid.h"
#include "catalog/pg_namespace.h"
#include "catalog/pg_type.h"
#include "catalog/toasting.h"
#include "commands/defrem.h"
//#include "commands/sequence.h"
#include "commands/tablecmds.h"
#include "miscadmin.h"
#include "nodes/makefuncs.h"
#include "utils/builtins.h"
#include "utils/fmgroids.h"
#include "utils/lsyscache.h"
#include "utils/rel.h"
#include "utils/syscache.h"
#include "utils/tqual.h"
#include "tcop/utility.h"
#include "pg_strom.h"

/* secondary hook entry */
static ProcessUtility_hook_type next_process_utility_hook = NULL;

#define ShadowRmapFmt			"shadow_%u_rmap"
#define ShadowCstoreFmt			"shadow_%u_cstore"
#define ShadowRstoreFmt			"shadow_%u_rstore"
#define ShadowRmapIndexFmt		"shadow_%u_rmap_index"
#define ShadowCstoreIndexFmt	"shadow_%u_cstore_index"

static Relation
open_shadow_relation(Relation frel, LOCKMODE lockmode,
					 const char *shadow_fmt, bool is_index)
{
	char		namebuf[NAMEDATALEN + 1];
	RangeVar   *range;
	Relation	relation;

	snprintf(namebuf, sizeof(namebuf), shadow_fmt, RelationGetRelid(frel));

	range = makeRangeVar(PGSTROM_SCHEMA_NAME, namebuf, -1);
	relation = relation_openrv(range, lockmode);

	if (!is_index)
	{
		if (RelationGetForm(relation)->relkind != RELKIND_RELATION)
			ereport(ERROR,
					(errcode(ERRCODE_WRONG_OBJECT_TYPE),
					 errmsg("\"%s\" is not a relation",
							RelationGetRelationName(relation))));
	}
	else
	{
		if (RelationGetForm(relation)->relkind != RELKIND_INDEX)
			ereport(ERROR,
                    (errcode(ERRCODE_WRONG_OBJECT_TYPE),
                     errmsg("\"%s\" is not an index",
                            RelationGetRelationName(relation))));
	}
	pfree(range);

	return relation;
}

Relation
pgstrom_open_shadow_rmap(Relation frel, LOCKMODE lockmode)
{
	return open_shadow_relation(frel, lockmode, ShadowRmapFmt, false);
}

Relation
pgstrom_open_shadow_rmap_index(Relation frel, LOCKMODE lockmode)
{
	return open_shadow_relation(frel, lockmode, ShadowRmapIndexFmt, true);
}

Relation
pgstrom_open_shadow_cstore(Relation frel, LOCKMODE lockmode)
{
	return open_shadow_relation(frel, lockmode, ShadowCstoreFmt, false);
}

Relation
pgstrom_open_shadow_cstore_index(Relation frel, LOCKMODE lockmode)
{
	return open_shadow_relation(frel, lockmode, ShadowCstoreIndexFmt, true);
}

Relation
pgstrom_open_shadow_rstore(Relation frel, LOCKMODE lockmode)
{
	return open_shadow_relation(frel, lockmode, ShadowRstoreFmt, false);
}

bool
pgstrom_check_relation_compatible(Relation rel1, Relation rel2)
{
	TupleDesc	tupdesc1 = RelationGetDescr(rel1);
	TupleDesc	tupdesc2 = RelationGetDescr(rel2);
	int			i;

	if (tupdesc1->natts != tupdesc2->natts ||
		tupdesc1->tdhasoid != tupdesc2->tdhasoid)
		return false;

	for (i=0; i < tupdesc1->natts; i++)
	{
		Form_pg_attribute attr1 = tupdesc1->attrs[i];
		Form_pg_attribute attr2 = tupdesc2->attrs[i];

		if (strcmp(NameStr(attr1->attname), NameStr(attr2->attname)) != 0 ||
			attr1->atttypid != attr2->atttypid ||
			attr1->attlen != attr2->attlen ||
			attr1->attndims != attr2->attndims ||
			attr1->atttypmod != attr2->atttypmod ||
			attr1->attbyval != attr2->attbyval ||
			attr1->attalign != attr2->attalign ||
			attr1->attnotnull != attr2->attnotnull ||
			attr1->attisdropped != attr2->attisdropped ||
			attr1->attcollation != attr2->attcollation)
			return false;
	}
	return true;
}

/*
 * pgstrom_create_shadow_index
 *
 * It creates an index relevant to shadow rowid-map or column-store.
 */
static void
pgstrom_create_shadow_index(Relation frel, Relation shadow_rel, bool is_cstore)
{
	char		idx_name[NAMEDATALEN + 1];
	IndexInfo  *idx_info;
	Oid			collationId[2];
	Oid			opclassId[2];
	int16		colOptions[2];
	List	   *indexColNames = NIL;

	snprintf(idx_name, sizeof(idx_name),
			 !is_cstore ? ShadowRmapIndexFmt : ShadowCstoreIndexFmt,
			 RelationGetRelid(frel));
	idx_info = makeNode(IndexInfo);
	idx_info->ii_Expressions = NIL;
	idx_info->ii_ExpressionsState = NIL;
	idx_info->ii_Predicate = NIL;
	idx_info->ii_PredicateState = NIL;
	idx_info->ii_ExclusionOps = NULL;
	idx_info->ii_ExclusionProcs = NULL;
	idx_info->ii_ExclusionStrats = NULL;
	idx_info->ii_Unique = true;
	idx_info->ii_ReadyForInserts = true;
	idx_info->ii_Concurrent = false;
	idx_info->ii_BrokenHotChain = false;
	if (!is_cstore)
	{
		idx_info->ii_NumIndexAttrs = 1;
		idx_info->ii_KeyAttrNumbers[0] = Anum_pg_strom_rmap_rowid;
		opclassId[0] = GetDefaultOpClass(INT8OID, BTREE_AM_OID);
		if (!OidIsValid(opclassId[0]))
			elog(ERROR, "no default operator class found on (int8, btree)");
		indexColNames = list_make1("rowid");
	}
	else
	{
		idx_info->ii_NumIndexAttrs = 2;
		idx_info->ii_KeyAttrNumbers[0] = Anum_pg_strom_cs_attnum;
		idx_info->ii_KeyAttrNumbers[1] = Anum_pg_strom_cs_rowid;
		opclassId[0] = GetDefaultOpClass(INT2OID, BTREE_AM_OID);
		if (!OidIsValid(opclassId[0]))
			elog(ERROR, "no default operator class found on (int2, btree)");
		opclassId[1] = GetDefaultOpClass(INT8OID, BTREE_AM_OID);
		if (!OidIsValid(opclassId[1]))
			elog(ERROR, "no default operator class found on (int8, btree)");
		indexColNames = list_make2("attnum", "rowid");
	}
	memset(collationId, 0, sizeof(collationId));
	memset(colOptions, 0, sizeof(colOptions));

	index_create(shadow_rel,		/* heapRelation */
				 idx_name,			/* indexRelationName */
				 InvalidOid,		/* indexRelationId */
				 InvalidOid,		/* relFileNode */
				 idx_info,			/* indexInfo */
				 indexColNames,		/* indexColNames */
				 BTREE_AM_OID,		/* accessMethodObjectId */
				 shadow_rel->rd_rel->reltablespace, /* tableSpaceId */
				 collationId,		/* collationObjectId */
				 opclassId,			/* OpClassObjectId */
				 colOptions,		/* coloptions */
				 (Datum) 0,			/* reloptions */
				 true,				/* isprimary */
				 false,				/* isconstraint */
				 false,				/* deferrable */
				 false,				/* initdeferred */
				 false,				/* allow_system_table_mods */
				 false,				/* skip_build */
				 false,				/* concurrent */
				 true);				/* is_internal */
}

/*
 * pgstrom_create_shadow_rmap
 *
 * creates a shadow rowid-map table being associated with the given
 * foreign table.
 */
static void
pgstrom_create_shadow_rmap(Relation frel)
{
	TupleDesc	tupdesc;
	Oid			namespaceId;
	Oid			rmap_relid;
	char		rmap_name[NAMEDATALEN + 1];
	Relation	rmap_rel;
	ObjectAddress	base;
	ObjectAddress	this;

	namespaceId = get_namespace_oid(PGSTROM_SCHEMA_NAME, false);
	snprintf(rmap_name, sizeof(rmap_name), ShadowRmapFmt,
			 RelationGetRelid(frel));

	tupdesc = CreateTemplateTupleDesc(Natts_pg_strom_rmap, false);
	TupleDescInitEntry(tupdesc, Anum_pg_strom_rmap_rowid,
					   "rowid", INT8OID, -1, 0);
	TupleDescInitEntry(tupdesc, Anum_pg_strom_rmap_nitems,
					   "nitems", INT4OID, -1, 0);
	TupleDescInitEntry(tupdesc, Anum_pg_strom_rmap_rowmap,
					   "rowmap", BYTEAOID, -1, 0);
	tupdesc->attrs[Anum_pg_strom_rmap_rowmap - 1]->attstorage = 'm';

	rmap_relid = heap_create_with_catalog(rmap_name,
										  namespaceId,
										  InvalidOid,	/* tablespace */
										  InvalidOid,	/* relationId */
										  InvalidOid,	/* reltypeId */
										  InvalidOid,	/* reloftypeid */
										  frel->rd_rel->relowner,
										  tupdesc,
										  NIL,		/* constraints */
										  RELKIND_RELATION,
										  frel->rd_rel->relpersistence,
										  false,	/* shared? */
										  false,	/* mapped? */
										  true,		/* oid is local? */
										  0,		/* oidinhcount */
										  ONCOMMIT_NOOP,
										  (Datum) 0,/* reloptions */
										  false, /* use_user_acl */
										  false, /* allow_system_table_mods? */
										  true); /* is_internal? */
	Assert(OidIsValid(rmap_relid));

	/* dependency registration */
	this.classId = RelationRelationId;
	this.objectId = rmap_relid;
	this.objectSubId = 0;
	base.classId  = RelationRelationId;
	base.objectId = RelationGetRelid(frel);
	base.objectSubId = 0;
	recordDependencyOn(&this, &base, DEPENDENCY_INTERNAL);

	/* make the new shadow table visible */
	CommandCounterIncrement();

	/* create a unique index on the "rowid" column */
	rmap_rel = heap_open(rmap_relid, NoLock);
	pgstrom_create_shadow_index(frel, rmap_rel, false);
	heap_close(rmap_rel, NoLock);

	/* also, create a toast relation */
	AlterTableCreateToastTable(rmap_relid, (Datum) 0);

	/* make this change visible */
	CommandCounterIncrement();
}

/*
 * pgstrom_create_shadow_cstore
 *
 * creates a shadow column-store
 */
static void
pgstrom_create_shadow_cstore(Relation frel)
{
	TupleDesc	tupdesc;
	Oid			namespaceId;
	Oid			cs_relid;
	char		cs_name[NAMEDATALEN + 1];
	Relation	cs_rel;
	ObjectAddress	base;
	ObjectAddress	this;

	namespaceId = get_namespace_oid(PGSTROM_SCHEMA_NAME, false);
	snprintf(cs_name, sizeof(cs_name), ShadowCstoreFmt,
			 RelationGetRelid(frel));

	tupdesc = CreateTemplateTupleDesc(Natts_pg_strom_cs, false);
	TupleDescInitEntry(tupdesc, Anum_pg_strom_cs_attnum,
					   "attnum", INT2OID, -1, 0);
	TupleDescInitEntry(tupdesc, Anum_pg_strom_cs_rowid,
					   "rowid", INT8OID, -1, 0);
	TupleDescInitEntry(tupdesc, Anum_pg_strom_cs_nitems,
					   "nitems", INT4OID, -1, 0);
	TupleDescInitEntry(tupdesc, Anum_pg_strom_cs_isnull,
					   "isnull", BYTEAOID, -1, 0);
	TupleDescInitEntry(tupdesc, Anum_pg_strom_cs_values,
					   "values", BYTEAOID, -1, 0);
	tupdesc->attrs[Anum_pg_strom_cs_isnull - 1]->attstorage = 'm';
	tupdesc->attrs[Anum_pg_strom_cs_values - 1]->attstorage = 'm';

	cs_relid = heap_create_with_catalog(cs_name,
										namespaceId,
										InvalidOid,	/* tablespace */
										InvalidOid,	/* relationId */
										InvalidOid,	/* reltypeId */
										InvalidOid,	/* reloftypeid */
										frel->rd_rel->relowner,
										tupdesc,
										NIL,		/* constraints */
										RELKIND_RELATION,
										frel->rd_rel->relpersistence,
										false,	/* shared? */
										false,	/* mapped? */
										true,		/* oid is local? */
										0,		/* oidinhcount */
										ONCOMMIT_NOOP,
										(Datum) 0,/* reloptions */
										false, /* use_user_acl */
										false, /* allow_system_table_mods? */
										true); /* is_internal? */
	Assert(OidIsValid(cs_relid));

	/* dependency registration */
	this.classId = RelationRelationId;
	this.objectId = cs_relid;
	this.objectSubId = 0;
	base.classId  = RelationRelationId;
	base.objectId = RelationGetRelid(frel);
	base.objectSubId = 0;
	recordDependencyOn(&this, &base, DEPENDENCY_INTERNAL);

	/* make the new shadow table visible */
	CommandCounterIncrement();

	/* create a unique index on the "rowid" column */
	cs_rel = heap_open(cs_relid, NoLock);
	pgstrom_create_shadow_index(frel, cs_rel, true);
	heap_close(cs_rel, NoLock);

	/* also, create a toast relation */
	AlterTableCreateToastTable(cs_relid, (Datum) 0);

	/* make this change visible */
	CommandCounterIncrement();
}

/*
 * pgstrom_create_shadow_rstore
 *
 * creates a shadow row-store
 */
static void
pgstrom_create_shadow_rstore(Relation frel)
{
	Oid		namespaceId;
	char	rs_name[NAMEDATALEN + 1];
	Oid		rs_relid;
	ObjectAddress	base;
	ObjectAddress	this;

	namespaceId = get_namespace_oid(PGSTROM_SCHEMA_NAME, false);
	snprintf(rs_name, sizeof(rs_name), ShadowRstoreFmt,
			 RelationGetRelid(frel));

	rs_relid = heap_create_with_catalog(rs_name,
										namespaceId,
										InvalidOid,	/* tablespace */
										InvalidOid,	/* relationId */
										InvalidOid,	/* reltypeId */
										InvalidOid,	/* reloftypeid */
										frel->rd_rel->relowner,
										RelationGetDescr(frel),
										NIL,		/* constraints */
										RELKIND_RELATION,
										frel->rd_rel->relpersistence,
										false,		/* shared? */
										false,		/* mapped? */
										true,		/* oid is local? */
										0,			/* oidinhcount */
										ONCOMMIT_NOOP,
										(Datum) 0,	/* reloptions */
										false,		/* use_user_acl */
										false,	/* allow_system_table_mods? */
										true);	/* is_internal? */
	Assert(OidIsValid(rs_relid));

	/* dependency registration */
	this.classId = RelationRelationId;
	this.objectId = rs_relid;
	this.objectSubId = 0;
	base.classId  = RelationRelationId;
	base.objectId = RelationGetRelid(frel);
	base.objectSubId = 0;
	recordDependencyOn(&this, &base, DEPENDENCY_INTERNAL);

	/* make the new shadow table visible */
	CommandCounterIncrement();

	/* also, create a toast relation */
	AlterTableCreateToastTable(rs_relid, (Datum) 0);
}

static void
pgstrom_post_create_relation(CreateForeignTableStmt *stmt)
{
	Relation	frel;
	Oid			namespaceId;
	Oid			save_userid;
	int			save_seccxt;

	/* Ensure the base relation being visible */
	CommandCounterIncrement();

	/* switch current credential of database users */
	GetUserIdAndSecContext(&save_userid, &save_seccxt);
	SetUserIdAndSecContext(BOOTSTRAP_SUPERUSERID,
						   save_seccxt | SECURITY_LOCAL_USERID_CHANGE);

	/*
	 * Ensure existence of the schema for PG-Strom's shadow relations.
	 * If not found, create it anyway prior to other jobs.
	 */
	namespaceId = get_namespace_oid(PGSTROM_SCHEMA_NAME, true);
    if (!OidIsValid(namespaceId))
	{
		GrantStmt  *grant;
		AccessPriv *priv;

		namespaceId = NamespaceCreate(PGSTROM_SCHEMA_NAME,
									  BOOTSTRAP_SUPERUSERID, false);
		CommandCounterIncrement();

		/* GRANT USAGE ON SCHEMA pg_strom TO public */
		priv = makeNode(AccessPriv);
		priv->priv_name = "usage";
		priv->cols = NIL;

		grant = makeNode(GrantStmt);
		grant->is_grant = true;
		grant->targtype = ACL_TARGET_OBJECT;
		grant->objtype = ACL_OBJECT_NAMESPACE;
		grant->objects = list_make1(makeString(PGSTROM_SCHEMA_NAME));
		grant->privileges = list_make1(priv);
		grant->grantees = list_make1(makeNode(PrivGrantee));
		grant->grant_option = false;
		ExecuteGrantStmt(grant);

		CommandCounterIncrement();
	}

	/*
	 * Open the base foreign-table; exclusive lock should be already
	 * acquired, so we can use NoLock instead.
	 */
	frel = heap_openrv(stmt->base.relation, NoLock);

	/* create shadow rowid, cstore, rstore */
	pgstrom_create_shadow_rmap(frel);
	pgstrom_create_shadow_cstore(frel);
	pgstrom_create_shadow_rstore(frel);

	/* restore security setting and close the base relation */
	SetUserIdAndSecContext(save_userid, save_seccxt);
	heap_close(frel, NoLock);
}

static void
cstore_post_change_owner(Relation frel)
{
	char	namebuf[NAMEDATALEN + 1];
	Oid		namespaceId = get_namespace_oid(PGSTROM_SCHEMA_NAME, false);
	Oid		new_owner = RelationGetForm(frel)->relowner;
	Oid		shadow_relid;
	AttrNumber	i, nattrs;

	snprintf(namebuf, sizeof(namebuf), "csmap_%u",
			 RelationGetRelid(frel));
	shadow_relid = get_relname_relid(namebuf, namespaceId);
	if (!OidIsValid(shadow_relid))
		elog(ERROR, "cache lookup failed for relation \"%s\"", namebuf);
	ATExecChangeOwner(shadow_relid, new_owner, true, AccessExclusiveLock);

	nattrs = RelationGetNumberOfAttributes(frel);
	for (i=0; i < nattrs; i++)
	{
		Form_pg_attribute	attr = RelationGetDescr(frel)->attrs[i];

		if (attr->attisdropped)
			continue;

		snprintf(namebuf, sizeof(namebuf), "csdata_%u_%d",
				 RelationGetRelid(frel), attr->attnum);
		shadow_relid = get_relname_relid(namebuf, namespaceId);
		if (!OidIsValid(shadow_relid))
			elog(ERROR, "cache lookup failed for relation \"%s\"", namebuf);
		ATExecChangeOwner(shadow_relid, new_owner, true, AccessExclusiveLock);
	}
	/*
	 * XXX - ownership of indexes and sequence are also updated because of
	 * dependency with column-store relations by ATExecChangeOwner.
	 */
}

static void
cstore_post_drop_column(Relation frel, const char *colname)
{
	Relation		cs_rel;
	Relation		cs_idx;
	IndexScanDesc	iscan;
	ScanKeyData		ikey;
	HeapTuple		tuple;
	AttrNumber		attnum;

	tuple = SearchSysCache2(ATTNAME,
							ObjectIdGetDatum(RelationGetRelid(frel)),
							CStringGetDatum(colname));
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for column \"%s\" of relation \"%s\"",
			 colname, RelationGetRelationName(frel));
	attnum = ((Form_pg_attribute) GETSTRUCT(tuple))->attnum;
	ReleaseSysCache(tuple);

	/*
	 * Remove all the relevant tuples in cstore
	 */
	cs_rel = pgstrom_open_shadow_cstore(frel, RowExclusiveLock);
	cs_idx = pgstrom_open_shadow_cstore_index(frel, RowExclusiveLock);

	ScanKeyInit(&ikey,
				Anum_pg_strom_cs_attnum,
				BTEqualStrategyNumber, F_INT2EQ,
				Int16GetDatum(attnum));

	iscan = index_beginscan(cs_rel, cs_idx, SnapshotNow, 1, 0);
	index_rescan(iscan, &ikey, 1, NULL, 0);

	while ((tuple = index_getnext(iscan, ForwardScanDirection)) != NULL)
		simple_heap_delete(cs_rel, &tuple->t_self);

	index_endscan(iscan);
	heap_close(cs_idx, NoLock);
	heap_close(cs_rel, NoLock);
}

static void
pgstrom_post_alter_relation(Relation frel, AlterTableStmt *stmt,
							const char *queryString, ParamListInfo params)
{
	List	   *rscmds = NIL;
	ListCell   *cell;

	foreach (cell, stmt->cmds)
	{
		AlterTableCmd  *cmd = lfirst(cell);

		switch (cmd->subtype)
		{
			case AT_AddColumn:
				rscmds = lappend(rscmds, copyObject(cmd));
				break;

			case AT_DropColumn:
				cstore_post_drop_column(frel, cmd->name);
				rscmds = lappend(rscmds, copyObject(cmd));
				break;

			case AT_ChangeOwner:
				cstore_post_change_owner(frel);
				rscmds = lappend(rscmds, cmd);
				break;

			case AT_GenericOptions:
			case AT_AlterColumnGenericOptions:
				/* do nothing */
				break;

			case AT_DropNotNull:
			case AT_SetNotNull:
			case AT_SetOptions:
			case AT_ResetOptions:
			case AT_AlterColumnType:
				elog(ERROR, "not supported yet");
				break;

			default:
				elog(ERROR, "unexpected ALTER command onto foreign tables");
				break;
		}
	}

	if (rscmds != NIL)
	{
		AlterTableStmt *rs_stmt = makeNode(AlterTableStmt);
		char		rs_name[NAMEDATALEN + 1];

		snprintf(rs_name, sizeof(rs_name), ShadowRstoreFmt,
				 RelationGetRelid(frel));
		rs_stmt->relation = makeRangeVar(PGSTROM_SCHEMA_NAME, rs_name, -1);
		rs_stmt->cmds = rscmds;
		rs_stmt->relkind = OBJECT_TABLE;
		rs_stmt->missing_ok = false;	/* already skipped, if missing */

		standard_ProcessUtility((Node *)rs_stmt,
								queryString,
								params,
								None_Receiver,
								NULL,
								PROCESS_UTILITY_GENERATED);
	}
}

/*
 * pgstrom_cstore_utilcmd
 *
 * Entrypoint of the ProcessUtility hook to handle post DDL operations
 */
static void
pgstrom_cstore_utilcmds(Node *parsetree,
						const char *queryString,
						ParamListInfo params,
						DestReceiver *dest,
						char *completionTag,
						ProcessUtilityContext context)
{
	/*
	 * Call the original ProcessUtility
	 */
	if (next_process_utility_hook)
		(*next_process_utility_hook)(parsetree, queryString, params,
									 dest, completionTag, context);
	else
		standard_ProcessUtility(parsetree, queryString, params,
								dest, completionTag, context);

	/*
	 * Post ProcessUtility stuff
	 */
	switch (nodeTag(parsetree))
	{
		case T_CreateForeignTableStmt:
			{
				CreateForeignTableStmt *stmt
					= (CreateForeignTableStmt *) parsetree;

				/* Is this relation a foreignt table managed by PG-Strom? */
				if (is_pgstrom_managed_server(stmt->servername))
					pgstrom_post_create_relation(stmt);
			}
			break;

		case T_AlterTableStmt:
			{
				AlterTableStmt *stmt = (AlterTableStmt *) parsetree;
				Relation		frel;

				/*
				 * Is this relation a foreignt table managed by PG-Strom?
				 *
				 * XXX - we assume ALTER command already acquires proper
				 * lock on the target relation, thus it does not specify
				 * any kind of lock level.
				 *
				 * XXX - AlterTableStmt never changes object name or its
				 * namespace, thus we don't care about a scenarios that
				 * user specified relation name is already changed.
				 */
				frel = relation_openrv(stmt->relation, NoLock);
				if (is_pgstrom_managed_relation(frel))
					pgstrom_post_alter_relation(frel, stmt,
												queryString, params);
				heap_close(frel, NoLock);
			}
			break;

		default:
			/* do nothing */
			break;
	}
}

/*
 * pgstrom_utilcmds_init - Registration of ProcessUtility hook
 */
void
pgstrom_utilcmds_init(void)
{
	next_process_utility_hook = ProcessUtility_hook;
	ProcessUtility_hook = pgstrom_cstore_utilcmds;
}
