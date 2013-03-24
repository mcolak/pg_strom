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
#include "nodes/makefuncs.h"
#include "optimizer/cost.h"
#include "optimizer/pathnode.h"
#include "optimizer/planmain.h"
#include "optimizer/var.h"
#include "utils/lsyscache.h"
#include "utils/syscache.h"
#include "pg_strom.h"


static bool
is_opencl_executable_qual(RelOptInfo *baserel, RestrictInfo *rinfo)
{
	if (bms_membership(rinfo->clause_relids) == BMS_MULTIPLE)
		return false;
	/*
	 * XXX - add practical checks here
	 */
	return false;
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
	if (bms_is_member(attno, columns))
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
	List	   *host_quals = NIL;
	List	   *kernel_quals = NIL;
	Bitmapset  *host_cols = NULL;
	Bitmapset  *kernel_cols = NULL;
	ListCell   *cell;
	AttrNumber	attno;
	DefElem	   *defel;

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
		// TODO: code generation of kernel_quals,
		// and "kernel_source" should be added here

	}

	pull_varattnos((Node *)kernel_quals, baserel->relid, &kernel_cols);
	kernel_cols = fixup_whole_row_reference(root, baserel->relid, kernel_cols);
	while ((attno = bms_first_member(kernel_cols)) >= 0)
	{
		attno += FirstLowInvalidHeapAttributeNumber;
		if (attno > 0)
		{
			defel = makeDefElem("kernel_cols", (Node *)makeInteger(attno));
			fdw_private = lappend(fdw_private, defel);
		}
	}

	pull_varattnos((Node *)host_quals, baserel->relid, &host_cols);
    pull_varattnos((Node *)tlist, baserel->relid, &host_cols);
	host_cols = fixup_whole_row_reference(root, baserel->relid, host_cols);
	while ((attno = bms_first_member(host_cols)) >= 0)
	{
		attno += FirstLowInvalidHeapAttributeNumber;
		if (attno > 0)
		{
			defel = makeDefElem("host_cols", (Node *)makeInteger(attno));
			fdw_private = lappend(fdw_private, defel);
		}
		else if (attno == SelfItemPointerAttributeNumber)
			defel = makeDefElem("needs_ctid", (Node *) makeInteger(true));
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


#if 0
#include "access/sysattr.h"
#include "catalog/pg_type.h"
#include "commands/sequence.h"
#include "nodes/makefuncs.h"
#include "nodes/nodeFuncs.h"
#include "utils/lsyscache.h"
#include "utils/rel.h"
#include "utils/syscache.h"
#include "optimizer/cost.h"
#include "optimizer/planmain.h"
#include "optimizer/pathnode.h"
#include "optimizer/restrictinfo.h"
#include "optimizer/var.h"
#include "pg_strom.h"
#include "cuda_cmds.h"

static bool
is_gpu_executable_qual_walker(Node *node, void *context)
{
	if (node == NULL)
		return false;
	if (IsA(node, Const))
	{
		Const  *c = (Const *) node;

		/* is it a supported data type by GPU? */
		if (!pgstrom_gpu_type_lookup(c->consttype))
			return true;
	}
	else if (IsA(node, Var))
	{
		RelOptInfo *baserel = (RelOptInfo *) context;
		Var		   *v = (Var *) node;

		if (v->varno != baserel->relid)
			return true;	/* should not happen */
		if (v->varlevelsup != 0)
			return true;	/* should not happen */
		if (v->varattno < 1)
			return true;	/* system columns are not supported */

		/* is it a supported data type by GPU? */
		if (!pgstrom_gpu_type_lookup(v->vartype))
			return true;
	}
	else if (IsA(node, FuncExpr))
	{
		FuncExpr   *f = (FuncExpr *) node;

		/* is it a supported function/operator? */
		if (!pgstrom_gpu_func_lookup(f->funcid))
			return true;
	}
	else if (IsA(node, OpExpr) ||
			 IsA(node, DistinctExpr))
	{
		OpExpr	   *op = (OpExpr *) node;

		/* is it a supported function/operator? */
		if (!pgstrom_gpu_func_lookup(get_opcode(op->opno)))
			return true;
	}
	else if (IsA(node, BoolExpr))
	{
		BoolExpr   *b = (BoolExpr *) node;

		if (b->boolop != AND_EXPR &&
			b->boolop != OR_EXPR &&
			b->boolop != NOT_EXPR)
			return true;
	}
	else
		return true;

	return expression_tree_walker(node,
								  is_gpu_executable_qual_walker,
								  context);
}

static bool
is_gpu_executable_qual(RelOptInfo *baserel, RestrictInfo *rinfo)
{
	if (bms_membership(rinfo->clause_relids) == BMS_MULTIPLE)
		return false;	/* should not happen */

	if (is_gpu_executable_qual_walker((Node *) rinfo->clause,
									  (void *) baserel))
		return false;

	return true;
}

static void make_gpu_commands_walker(Node *node, StringInfo cmds, int regidx,
									 Bitmapset **gpu_cols);

static void push_cmd1(StringInfo cmds, int cmd1)
{
	appendBinaryStringInfo(cmds, (const char *)&cmd1, sizeof(cmd1));
}

static void push_cmd2(StringInfo cmds, int cmd1, int cmd2)
{
	appendBinaryStringInfo(cmds, (const char *)&cmd1, sizeof(cmd1));
	appendBinaryStringInfo(cmds, (const char *)&cmd2, sizeof(cmd2));
}

static void push_cmd3(StringInfo cmds, int cmd1, int cmd2, int cmd3)
{
	appendBinaryStringInfo(cmds, (const char *)&cmd1, sizeof(cmd1));
	appendBinaryStringInfo(cmds, (const char *)&cmd2, sizeof(cmd2));
	appendBinaryStringInfo(cmds, (const char *)&cmd3, sizeof(cmd3));
}

static void push_cmd4(StringInfo cmds, int cmd1, int cmd2, int cmd3, int cmd4)
{
	appendBinaryStringInfo(cmds, (const char *)&cmd1, sizeof(cmd1));
	appendBinaryStringInfo(cmds, (const char *)&cmd2, sizeof(cmd2));
	appendBinaryStringInfo(cmds, (const char *)&cmd3, sizeof(cmd3));
	appendBinaryStringInfo(cmds, (const char *)&cmd4, sizeof(cmd4));
}

static void
make_gpu_func_commands(Oid func_oid, List *func_args,
					   StringInfo cmds, int regidx, Bitmapset **gpu_cols)
{
	GpuTypeInfo	   *gtype;
	GpuFuncInfo	   *gfunc;
	ListCell	   *cell;
	int			   *regargs;
	int				i = 0;

	gfunc = pgstrom_gpu_func_lookup(func_oid);
	Assert(gfunc != NULL);

	regargs = alloca(sizeof(int) * (1 + gfunc->func_nargs));

	gtype = pgstrom_gpu_type_lookup(gfunc->func_rettype);
	Assert(gtype != NULL);

	/*
	 * XXX - 64bit variables have to be stored on the virtual registed
	 * indexed with even number, because unaligned access makes run-
	 * time error on device side.
	 */
	if (gtype->type_x2regs)
	{
		regidx = (regidx + 1) & ~(0x0001);
		regargs[i++] = regidx;
		regidx += 2;
	}
	else
	{
		regargs[i++] = regidx;
		regidx++;
	}

	i = 1;
	foreach (cell, func_args)
	{
		Assert(exprType(lfirst(cell)) == gfunc->func_argtypes[i-1]);
		gtype = pgstrom_gpu_type_lookup(exprType(lfirst(cell)));
		Assert(gtype != NULL);
		if (gtype->type_x2regs)
			regidx = (regidx + 1) & ~(0x0001);

		make_gpu_commands_walker(lfirst(cell), cmds, regidx, gpu_cols);
		regargs[i] = regidx;

		regidx += (gtype->type_x2regs ? 2 : 1);
		i++;
	}
	Assert(gfunc->func_nargs == i - 1);

	push_cmd1(cmds, gfunc->func_cmd);
	for (i=0; i <= gfunc->func_nargs; i++)
		push_cmd1(cmds, regargs[i]);
}

static void
make_gpu_commands_walker(Node *node, StringInfo cmds, int regidx,
						 Bitmapset **gpu_cols)
{
	GpuTypeInfo	   *gtype;
	ListCell	   *cell;
	union {
		uint32	reg32[2];
		uint64	reg64;
	} xreg;

	if (node == NULL)
		return;
	if (IsA(node, Const))
	{
		Const  *c = (Const *) node;

		gtype = pgstrom_gpu_type_lookup(c->consttype);
		Assert(gtype != NULL);

		if (c->constisnull)
			push_cmd2(cmds, GPUCMD_CONREF_NULL, regidx);
		else if (!gtype->type_x2regs)
			push_cmd3(cmds,
					  gtype->type_conref, regidx,
					  DatumGetInt32(c->constvalue));
		else
		{
			xreg.reg64 = DatumGetInt64(c->constvalue);
			push_cmd4(cmds,
					  gtype->type_conref, regidx,
					  xreg.reg32[0], xreg.reg32[1]);
		}
	}
	else if (IsA(node, Var))
	{
		Var	   *v = (Var *) node;

		gtype = pgstrom_gpu_type_lookup(v->vartype);
		Assert(gtype != NULL);

		push_cmd3(cmds,
				  gtype->type_varref, regidx, v->varattno - 1);
		*gpu_cols = bms_add_member(*gpu_cols, v->varattno);
	}
	else if (IsA(node, FuncExpr))
	{
		FuncExpr   *f = (FuncExpr *) node;

		make_gpu_func_commands(f->funcid, f->args, cmds, regidx, gpu_cols);
	}
	else if (IsA(node, OpExpr) ||
			 IsA(node, DistinctExpr))
	{
		OpExpr	   *op = (OpExpr *) node;

		make_gpu_func_commands(get_opcode(op->opno),
							   op->args, cmds, regidx, gpu_cols);
	}
	else if (IsA(node, BoolExpr))
	{
		BoolExpr   *bx = (BoolExpr *) node;

		if (bx->boolop == NOT_EXPR)
		{
			Assert(list_length(bx->args) == 1);
			Assert(exprType(linitial(bx->args)) == BOOLOID);

			make_gpu_commands_walker(linitial(bx->args), cmds, regidx+1,
									 gpu_cols);
			push_cmd2(cmds, GPUCMD_BOOLOP_NOT, regidx);
		}
		else if (bx->boolop == AND_EXPR || bx->boolop == OR_EXPR)
		{
			int		shift = 0;

			Assert(list_length(bx->args) > 1);
			foreach (cell, bx->args)
			{
				Assert(exprType(lfirst(cell)) == BOOLOID);

				make_gpu_commands_walker(lfirst(cell), cmds, regidx + shift,
										 gpu_cols);
				shift++;
			}
			Assert(list_length(bx->args) == shift);
			while (shift >= 2)
			{
				push_cmd3(cmds,
						  (bx->boolop == AND_EXPR ?
						   GPUCMD_BOOLOP_AND : GPUCMD_BOOLOP_OR),
						  regidx + shift - 2, regidx + shift - 1);
				shift--;
			}			
		}
		else
			elog(ERROR, "PG-Strom: unexpected BoolOp %d", (int) bx->boolop);
	}
	else
		elog(ERROR, "PG-Strom: unexpected node type: %d", nodeTag(node));
}

static bytea *
make_gpu_commands(List *gpu_quals, Bitmapset **gpu_cols)
{
	StringInfoData	cmds;
	RestrictInfo   *rinfo;
	int				code;

	initStringInfo(&cmds);
	appendStringInfoSpaces(&cmds, VARHDRSZ);

	Assert(list_length(gpu_quals) > 0);
	if (list_length(gpu_quals) == 1)
	{
		rinfo = linitial(gpu_quals);
		make_gpu_commands_walker((Node *)rinfo->clause, &cmds, 0, gpu_cols);
	}
	else
	{
		List	   *quals = NIL;
		ListCell   *cell;

		foreach (cell, gpu_quals)
		{
			rinfo = lfirst(cell);
			quals = lappend(quals, rinfo->clause);
		}
		make_gpu_commands_walker((Node *)makeBoolExpr(AND_EXPR, quals, -1),
								 &cmds, 0, gpu_cols);
	}
	code = GPUCMD_TERMINAL_COMMAND;
	appendBinaryStringInfo(&cmds, (const char *)&code, sizeof(code));
	SET_VARSIZE(cmds.data, cmds.len);
	return (bytea *)cmds.data;
}

static bool
is_cpu_executable_qual(RelOptInfo *baserel, RestrictInfo *rinfo)
{
	return false;
}

static bytea *
make_cpu_commands(List *cpu_quals, Bitmapset **cpu_cols)
{
	return NULL;
}

void
pgstrom_get_foreign_rel_size(PlannerInfo *root,
							 RelOptInfo *baserel,
							 Oid ftableOid)
{
	AttrNumber	attno;
	int			width = 0;

	for (attno = baserel->min_attr; attno <= baserel->max_attr; attno++)
	{
		int		index = attno - baserel->min_attr;

		if (attno > 0 && !bms_is_empty(baserel->attr_needed[index]))
		{
			width += get_attavgwidth(ftableOid, attno);
		}
	}
	/*
	 * TODO: need more practical estimation
	 */
	baserel->rows = 10000.0;
	baserel->width = width;
}

void
pgstrom_get_foreign_paths(PlannerInfo *root,
						  RelOptInfo *baserel,
						  Oid foreigntableid)
{
	List	   *host_quals = NIL;
	List	   *gpu_quals = NIL;
	List	   *cpu_quals = NIL;
	List	   *private = NIL;
	Bitmapset  *required_cols = NULL;
	ListCell   *cell;
	AttrNumber	attno;
	bytea	   *cmds_bytea;
	Const	   *cmds_const;
	int			gpu_cmds_len = 0;
	int			cpu_cmds_len = 0;
	DefElem	   *defel;
	Cost		startup_cost;
	Cost		total_cost;
	ForeignPath *fdwpath;

	/*
	 * check whether GPU/CPU executable qualifier, or not
	 */
	foreach (cell, baserel->baserestrictinfo)
	{
		RestrictInfo   *rinfo = lfirst(cell);

		if (is_gpu_executable_qual(baserel, rinfo))
			gpu_quals = lappend(gpu_quals, rinfo);
		else if (is_cpu_executable_qual(baserel, rinfo))
			cpu_quals = lappend(cpu_quals, rinfo);
		else
		{
			pull_varattnos((Node *)rinfo->clause,
						   baserel->relid, &required_cols);
			host_quals = lappend(host_quals, rinfo);
		}
	}
	baserel->baserestrictinfo = host_quals;

	/*
	 * Generate command series executed with GPU/CPU, if any
	 */
	if (gpu_quals)
	{
		Bitmapset  *gpu_cols = NULL;

		cmds_bytea = make_gpu_commands(gpu_quals, &gpu_cols);
		cmds_const = makeConst(BYTEAOID, -1, InvalidOid,
							   VARSIZE(cmds_bytea),
							   PointerGetDatum(cmds_bytea),
							   false, false);
		defel = makeDefElem("gpu_cmds", (Node *) cmds_const);
		private = lappend(private, defel);

		gpu_cmds_len = VARSIZE_ANY_EXHDR(cmds_bytea) / sizeof(int);

		while ((attno = bms_first_member(gpu_cols)) >= 0)
		{
			defel = makeDefElem("gpu_cols", (Node *) makeInteger(attno));
			private = lappend(private, defel);
		}
		bms_free(gpu_cols);
	}
	if (cpu_quals)
	{
		Bitmapset  *cpu_cols = NULL;

		cmds_bytea = make_cpu_commands(cpu_quals, &cpu_cols);
		cmds_const = makeConst(BYTEAOID, -1, InvalidOid,
							   VARSIZE(cmds_bytea),
							   PointerGetDatum(cmds_bytea),
							   false, false);
		defel = makeDefElem("cpu_cmds", (Node *) cmds_const);
		private = lappend(private, defel);

		cpu_cmds_len = VARSIZE_ANY_EXHDR(cmds_bytea) / sizeof(int);

		while ((attno = bms_first_member(cpu_cols)) >= 0)
		{
			defel = makeDefElem("cpu_cols", (Node *) makeInteger(attno));
			private = lappend(private, defel);
		}
		bms_free(cpu_cols);
	}

	/*
	 * Save the referenced columns with both of targetlist and host quals
	 */
	for (attno = baserel->min_attr; attno <= baserel->max_attr; attno++)
	{
		if (!bms_is_empty(baserel->attr_needed[attno - baserel->min_attr]))
			required_cols = bms_add_member(required_cols,
						attno - FirstLowInvalidHeapAttributeNumber);
	}

	while ((attno = bms_first_member(required_cols)) >= 0)
	{
		attno += FirstLowInvalidHeapAttributeNumber;
		if (attno < 0)
			continue;
		defel = makeDefElem("required_cols", (Node *) makeInteger(attno));
		private = lappend(private, defel);
	}
	bms_free(required_cols);

	/*
	 * Cost estimations
	 *
	 * TODO: this logic should be revised later
	 */
	cost_qual_eval(&baserel->baserestrictcost,
				   baserel->baserestrictinfo, root);

	startup_cost = baserel->baserestrictcost.startup;
	total_cost = baserel->baserestrictcost.per_tuple * baserel->rows
		+ 0.01 * gpu_cmds_len * baserel->rows / PGSTROM_CHUNK_SIZE
		+ 0.01 * cpu_cmds_len * baserel->rows / PGSTROM_CHUNK_SIZE;

	/*
	 * Construct Plan object
	 */
	fdwpath = create_foreignscan_path(root, baserel,
									  baserel->rows,
									  startup_cost,
									  total_cost,
									  NIL,
									  NULL,
									  private);
	add_path(baserel, (Path *) fdwpath);
}

ForeignScan *
pgstrom_get_foreign_plan(PlannerInfo *root,
						 RelOptInfo *baserel,
						 Oid foreigntableid,
						 ForeignPath *best_path,
						 List *tlist,
						 List *scan_clauses)
{
	Index	scan_relid = baserel->relid;

	/* it should be a base rel... */
	Assert(scan_relid > 0);
	Assert(best_path->path.parent->rtekind == RTE_RELATION);

	/*
	 * Reduce RestrictInfo list to bare expressions;
	 * ignore pseudoconstants
	 */
	scan_clauses = extract_actual_clauses(scan_clauses, false);

	/* Create the ForeignScan node */
	return make_foreignscan(tlist,
							scan_clauses,
							scan_relid,
							NIL,
							best_path->fdw_private);
}

/*
 * pgstrom_explain_foreign_scan
 *
 * implementation of EXPLAIN
 */
void
pgstrom_explain_foreign_scan(ForeignScanState *fss,
							 ExplainState *es)
{
	ForeignScan	   *fscan = (ForeignScan *) fss->ss.ps.plan;
	Relation		relation = fss->ss.ss_currentRelation;
	Const		   *gpu_cmds = NULL;
	Const		   *cpu_cmds = NULL;
	Bitmapset	   *gpu_cols = NULL;
	Bitmapset	   *cpu_cols = NULL;
	Bitmapset	   *required_cols = NULL;
	ListCell	   *cell;
	StringInfoData	str;
	AttrNumber		attno;
	Form_pg_attribute attr;

	foreach (cell, fscan->fdw_private)
	{
		DefElem	   *defel = (DefElem *) lfirst(cell);

		if (strcmp(defel->defname, "gpu_cmds") == 0)
			gpu_cmds = (Const *) defel->arg;
		else if (strcmp(defel->defname, "cpu_cmds") == 0)
			cpu_cmds = (Const *) defel->arg;
		else if (strcmp(defel->defname, "gpu_cols") == 0)
			gpu_cols = bms_add_member(gpu_cols, intVal(defel->arg));
		else if (strcmp(defel->defname, "cpu_cols") == 0)
			cpu_cols = bms_add_member(cpu_cols, intVal(defel->arg));
		else if (strcmp(defel->defname, "required_cols") == 0)
			required_cols = bms_add_member(required_cols, intVal(defel->arg));
		else
			elog(ERROR, "unexpected parameter: %s", defel->defname);
	}
	initStringInfo(&str);

	if (!bms_is_empty(required_cols))
	{
		resetStringInfo(&str);
		while ((attno = bms_first_member(required_cols)) > 0)
		{
			attr = RelationGetDescr(relation)->attrs[attno - 1];
			appendStringInfo(&str, "%s%s",
							 str.len > 0 ? ", " : "",
							 NameStr(attr->attname));
		}
		ExplainPropertyText("Required cols ", str.data, es);
	}

	if (!bms_is_empty(gpu_cols))
	{
		resetStringInfo(&str);
		while ((attno = bms_first_member(gpu_cols)) > 0)
		{
			attr = RelationGetDescr(relation)->attrs[attno - 1];
			appendStringInfo(&str, "%s%s",
							 str.len > 0 ? ", " : "",
							 NameStr(attr->attname));
		}
		ExplainPropertyText("GPU load cols ", str.data, es);
	}

	if (!bms_is_empty(cpu_cols))
	{
		resetStringInfo(&str);
		while ((attno = bms_first_member(cpu_cols)) > 0)
		{
			attr = RelationGetDescr(relation)->attrs[attno - 1];
			appendStringInfo(&str, "%s%s",
							 str.len > 0 ? ", " : "",
							 NameStr(attr->attname));
		}
		ExplainPropertyText("CPU load cols ", str.data, es);
	}

	if (gpu_cmds != NULL)
	{
		char	temp[1024];
		int	   *cmds;
		int		skip;
		bool	first = true;

		Assert(IsA(gpu_cmds, Const));

		cmds = (int *)VARDATA((bytea *)(gpu_cmds->constvalue));
		for (skip = 0; skip >= 0; cmds += skip)
		{
			skip = pgstrom_gpu_command_string(RelationGetRelid(relation),
											  cmds, temp, sizeof(temp));
			if (first)
				ExplainPropertyText("CUDA commands ", temp, es);
			else
				ExplainPropertyText("              ", temp, es);
			first = false;
		}
	}

	if (cpu_cmds != NULL)
	{
		/*
		 * XXX - add OpenMP commands
		 */
	}
}
#endif
