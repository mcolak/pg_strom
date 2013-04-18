/*
 * plan.c
 *
 * Routines for FDW planenr
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
#include "catalog/pg_class.h"
#include "catalog/pg_type.h"
#include "libpq/md5.h"
#include "nodes/makefuncs.h"
#include "nodes/nodeFuncs.h"
#include "optimizer/cost.h"
#include "optimizer/pathnode.h"
#include "optimizer/planmain.h"
#include "optimizer/var.h"
#include "parser/parsetree.h"
#include "utils/builtins.h"
#include "utils/lsyscache.h"
#include "utils/syscache.h"
#include "pg_strom.h"

/*
 * is_opencl_executable_qual
 *
 * returns true, if supplied expression tree is executable on opencl
 * device. elsewhere, it has to be run on the host device.
 */
typedef struct {
	RelOptInfo	   *baserel;
} is_opencl_executable_qual_context;

static bool
is_opencl_executable_qual_walker(Node *node, void *context)
{
	is_opencl_executable_qual_context *cxt = context;
	clTypeInfo	   *tinfo;
	clFuncInfo	   *finfo;

	if (node == NULL)
		return false;
	if (IsA(node, Const))
	{
		Const	   *c = (Const *)node;

		tinfo = pgstrom_cltype_lookup(c->consttype);
		if (!tinfo)
			return true;
	}
	else if (IsA(node, Param))
	{
		Param	   *p = (Param *)node;

		tinfo = pgstrom_cltype_lookup(p->paramtype);
		if (!tinfo)
			return true;
	}
	else if (IsA(node, Var))
	{
		Var		   *var = (Var *)node;

		if (var->varno != cxt->baserel->relid)
			return true;	/* should not happen */
		if (var->varlevelsup != 0)
			return true;	/* should not happen */
		if (var->varattno < 1)
			return true;	/* system columns are not supported */

		tinfo = pgstrom_cltype_lookup(var->vartype);
		if (!tinfo)
			return true;
	}
	else if (IsA(node, FuncExpr))
	{
		FuncExpr	   *f = (FuncExpr *)node;

		finfo = pgstrom_clfunc_lookup(f->funcid);
		if (!finfo)
			return true;
	}
	else if (IsA(node, OpExpr) ||
			 IsA(node, DistinctExpr))
	{
		OpExpr	   *op = (OpExpr *)node;

		finfo = pgstrom_clfunc_lookup(get_opcode(op->opno));
		if (!finfo)
			return true;
	}
	else if (IsA(node, BoolExpr))
	{
		BoolExpr   *b = (BoolExpr *)node;

		Assert(b->boolop == AND_EXPR ||
			   b->boolop == OR_EXPR ||
			   b->boolop == NOT_EXPR);
	}
	else
		return true;

	return expression_tree_walker(node,
								  is_opencl_executable_qual_walker,
								  context);
}

static bool
is_opencl_executable_qual(RelOptInfo *baserel, RestrictInfo *rinfo)
{
	is_opencl_executable_qual_context cxt;

	if (bms_membership(rinfo->clause_relids) == BMS_MULTIPLE)
		return false;

	cxt.baserel = baserel;
	return !is_opencl_executable_qual_walker((Node *)rinfo->clause, &cxt);
}

static void
pgstrom_get_foreign_rel_size(PlannerInfo *root,
							 RelOptInfo *baserel,
							 Oid foreigntableid)
{
	AttrNumber	i, attno;
	int			width = baserel->width;

	for (i = baserel->min_attr; i <= baserel->max_attr; i++)
	{
		attno = i - baserel->min_attr;

		if (attno > 0 && !bms_is_empty(baserel->attr_needed[attno]))
			width += get_attavgwidth(foreigntableid, attno);
	}

	/*
	 * TODO: we will put here more practical estimation
	 */
	baserel->rows = 10000.0;
	baserel->width = width;
}

static void
pgstrom_get_foreign_paths(PlannerInfo *root,
						  RelOptInfo *baserel,
						  Oid foreigntableid)
{
	ListCell	   *cell;
	Cost			startup_cost = 0.0;
	Cost			total_cost = 0.0;
	ForeignPath	   *fpath;

	foreach (cell, baserel->baserestrictinfo)
	{
		RestrictInfo   *rinfo = lfirst(cell);
		QualCost		qcost;

		cost_qual_eval(&qcost, list_make1(rinfo->clause), root);
		/*
		 * cost discount towards quals that can run on OpenCL server
		 *
		 * XXX - discount rate should be more practical according to
		 * the resource installation.
		 */
		if (is_opencl_executable_qual(baserel, rinfo))
			qcost.per_tuple /= 1000;
		baserel->baserestrictcost.startup += qcost.startup;
		baserel->baserestrictcost.per_tuple += qcost.per_tuple;
	}

	/*
	 * construction of ForeignPath
	 */
	startup_cost = baserel->baserestrictcost.startup;
	total_cost = baserel->baserestrictcost.startup +
		baserel->baserestrictcost.per_tuple * baserel->rows;

	fpath = create_foreignscan_path(root, baserel,
									baserel->rows,
									startup_cost,
									total_cost,
									NIL,	/* no pathkeys */
									NULL,	/* no outer rel either */
									NULL);
	add_path(baserel, (Path *) fpath);
}

static Bitmapset *
fixup_whole_row_reference(PlannerInfo *root, Index rtindex, Bitmapset *columns)
{
	RangeTblEntry  *rte;
	HeapTuple		tup;
	AttrNumber		attno, nattrs;

	attno = InvalidAttrNumber - FirstLowInvalidHeapAttributeNumber;
	if (!bms_is_member(attno, columns))
		return columns;

	rte = root->simple_rte_array[rtindex];

	tup = SearchSysCache1(RELOID, ObjectIdGetDatum(rte->relid));
	if (!HeapTupleIsValid(tup))
		elog(ERROR, "cache lookup failed for relation %u", rte->relid);
	nattrs = ((Form_pg_class) GETSTRUCT(tup))->relnatts;
	ReleaseSysCache(tup);

	columns = bms_del_member(columns, attno);
	for (attno = 1; attno <= nattrs; attno++)
	{
		tup = SearchSysCache2(ATTNUM,
							  ObjectIdGetDatum(rte->relid),
							  Int16GetDatum(attno));
		if (!HeapTupleIsValid(tup))
			elog(ERROR, "cache lookup failed for attribute %d of relation %u",
				 attno, rte->relid);
		if (!((Form_pg_attribute) GETSTRUCT(tup))->attisdropped)
			columns = bms_add_member(columns, attno);
		ReleaseSysCache(tup);
	}
	return columns;
}

static ForeignScan *
pgstrom_get_foreign_plan(PlannerInfo *root,
						 RelOptInfo *baserel,
						 Oid foreigntableid,
						 ForeignPath *best_path,
						 List *tlist,
						 List *scan_clauses)
{
	List	   *fdw_private = NIL;
	List	   *kernel_quals = NIL;
	List	   *host_quals = NIL;
	Bitmapset  *host_cols = NULL;
	ListCell   *cell;
	AttrNumber	attno;
	DefElem	   *defel;
	char	   *lockmode = NULL;

	foreach (cell, baserel->baserestrictinfo)
	{
		RestrictInfo   *rinfo = lfirst(cell);

		if (is_opencl_executable_qual(baserel, rinfo))
			kernel_quals = lappend(kernel_quals, copyObject(rinfo->clause));
		else
			host_quals = lappend(host_quals, copyObject(rinfo->clause));
	}

	if (kernel_quals != NIL)
	{
		Node	   *kernel_expr;
		text	   *kernel_source;
		char		kernel_md5[VARHDRSZ + 16];	/* MD5 has 128bit length */
		List	   *kernel_params = NIL;
		List	   *kernel_cols = NIL;
		List	   *dpcxt;
		char	   *dpsrc;
		text	   *dptxt;
		HeapTuple	tuple;
		Form_pg_class relform;

		/* generate kernel source */
		if (list_length(kernel_quals) == 1)
			kernel_expr = linitial(kernel_quals);
		else
			kernel_expr = (Node *)makeBoolExpr(AND_EXPR, kernel_quals, -1);

		kernel_source = pgstrom_codegen_qual(root, baserel, kernel_expr,
											 &kernel_params, &kernel_cols);
		defel = makeDefElem("kernel_source",
							(Node *)makeConst(TEXTOID,
											  -1,
											  InvalidOid,
											  VARSIZE(kernel_source),
											  PointerGetDatum(kernel_source),
											  false,
											  false));
		fdw_private = lappend(fdw_private, defel);

		/* calculation of MD5 digest */
		if (!pg_md5_binary(VARDATA(kernel_source),
						   VARSIZE_ANY_EXHDR(kernel_source),
						   kernel_md5 + VARHDRSZ))
			elog(ERROR, "internal error on calculation of MD5");
		SET_VARSIZE(kernel_md5, sizeof(kernel_md5));

		defel = makeDefElem("kernel_md5",
							(Node *)makeConst(BYTEAOID,
											  -1,
											  InvalidOid,
											  sizeof(kernel_md5),
											  PointerGetDatum(kernel_md5),
											  false,
											  false));
		fdw_private = lappend(fdw_private, defel);

		/* save the parameters referenced by kernel */
		foreach (cell, kernel_params)
		{
			Node   *node = lfirst(cell);

			Assert(IsA(node, Const) || IsA(node, Param));
			defel = makeDefElem("kernel_params", node);
			fdw_private = lappend(fdw_private, defel);
		}

		/* save the column numbers referenced by kernel */
		foreach (cell, kernel_cols)
		{
			AttrNumber	attnum = lfirst_int(cell);

			Assert(attnum > 0);
			defel = makeDefElem("kernel_cols", (Node *)makeInteger(attnum));
			fdw_private = lappend(fdw_private, defel);
		}

		/* human readable representation for EXPLAIN */
		tuple = SearchSysCache1(RELOID, ObjectIdGetDatum(foreigntableid));
		if (!HeapTupleIsValid(tuple))
			elog(ERROR, "cache lookup failed for relation %u", foreigntableid);
		relform = (Form_pg_class) GETSTRUCT(tuple);

		dpcxt = deparse_context_for(NameStr(relform->relname),
									relform->relnamespace);
		dpsrc = deparse_expression(kernel_expr, dpcxt, false, false);
		dptxt = cstring_to_text(dpsrc);
		defel = makeDefElem("kernel_quals",
							(Node *)makeConst(TEXTOID,
											  -1,
											  InvalidOid,
											  VARSIZE(dptxt),
											  PointerGetDatum(dptxt),
											  false,
											  false));
		fdw_private = lappend(fdw_private, defel);

		ReleaseSysCache(tuple);
	}
	/* save the column numbers referenced by host */
	pull_varattnos((Node *)host_quals, baserel->relid, &host_cols);
	pull_varattnos((Node *)baserel->reltargetlist, baserel->relid, &host_cols);
	host_cols = fixup_whole_row_reference(root, baserel->relid, host_cols);
	while ((attno = bms_first_member(host_cols)) >= 0)
	{
		attno += FirstLowInvalidHeapAttributeNumber;
		defel = makeDefElem("host_cols", (Node *)makeInteger(attno));
		fdw_private = lappend(fdw_private, defel);
	}

	/*
	 * Choose an appropriate lock level on shadow table scan
	 */
	if (baserel->relid == root->parse->resultRelation &&
		(root->parse->commandType == CMD_UPDATE ||
		 root->parse->commandType == CMD_DELETE))
		lockmode = "exclusive";
	else
	{
		RowMarkClause *rowmark = get_parse_rowmark(root->parse,
												   baserel->relid);
		if (rowmark)
		{
			switch (rowmark->strength)
			{
				case LCS_FORKEYSHARE:
				case LCS_FORSHARE:
					lockmode = "shared";
					break;
				case LCS_FORNOKEYUPDATE:
				case LCS_FORUPDATE:
					lockmode = "exclusive";
					break;
			}
			if (lockmode && rowmark->noWait)
			{
				defel = makeDefElem("lockmode-nowait",
									(Node *) makeInteger(true));
				fdw_private = lappend(fdw_private, defel);
			}
		}
	}
	if (lockmode)
	{
		defel = makeDefElem("lockmode", (Node *) makeString(lockmode));
		fdw_private = lappend(fdw_private, defel);
	}

	return make_foreignscan(tlist,
							host_quals,
							baserel->relid,
							kernel_quals,
							fdw_private);
}

void
pgstrom_fdw_plan_init(FdwRoutine *fdw_routine)
{
	fdw_routine->GetForeignRelSize	= pgstrom_get_foreign_rel_size;
	fdw_routine->GetForeignPaths	= pgstrom_get_foreign_paths;
	fdw_routine->GetForeignPlan		= pgstrom_get_foreign_plan;
}
