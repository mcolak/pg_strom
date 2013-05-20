/*
 * codegen.c
 *
 * code generator for OpenCL execution
 *
 * --
 * Copyright 2013 (c) PG-Strom Development Team
 * Copyright 2011-2013 (c) KaiGai Kohei <kaigai@kaigai.gr.jp>
 *
 * This software is an extension of PostgreSQL; You can use, copy,
 * modify or distribute it under the terms of 'LICENSE' included
 * within this package.
 */
#include "postgres.h"
#include "access/hash.h"
#include "access/sysattr.h"
#include "catalog/pg_namespace.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_type.h"
#include "lib/stringinfo.h"
#include "nodes/makefuncs.h"
#include "nodes/nodeFuncs.h"
#include "optimizer/var.h"
#include "utils/builtins.h"
#include "utils/inval.h"
#include "utils/lsyscache.h"
#include "utils/memutils.h"
#include "utils/syscache.h"
#include "pg_strom.h"

static dlist_head	cltype_info_slot[128];
static dlist_head	clfunc_info_slot[1024];


/* ------------------------------------------------------------
 *
 * Catalog of OpenCL Types
 *
 * ------------------------------------------------------------
 */
#define CLTYPE_KIND_NATIVE		'n'
#define CLTYPE_KIND_SIMPLE		's'
#define CLTYPE_KIND_VARLENA		'v'

static struct {
	/* OID of host type */
	Oid		type_oid;
	/* base type on device */
	char   *type_base;
	/* callback on construction of reletive clTypeInfo */
	void  (*type_callback)(clTypeInfo *type_info,
						   MemoryContext memcxt);
	/* true, if type can perform as vector type */
	bool	type_kind;
} opencl_type_catalog[] = {
	/* built-in native types */
	{ BOOLOID,   "char",   NULL, CLTYPE_KIND_NATIVE },
	{ INT2OID,   "short",  NULL, CLTYPE_KIND_NATIVE },
	{ INT4OID,   "int",    NULL, CLTYPE_KIND_NATIVE },
	{ INT8OID,   "long",   NULL, CLTYPE_KIND_NATIVE },
	{ FLOAT4OID, "float",  NULL, CLTYPE_KIND_NATIVE },
	{ FLOAT8OID, "double", NULL, CLTYPE_KIND_NATIVE },
	/* built-in simple types */
	/* built-in varlena types */
	{ TEXTOID,   "__global varlena *", NULL, CLTYPE_KIND_VARLENA },
	{ BYTEAOID,  "__global varlena *", NULL, CLTYPE_KIND_VARLENA },
};

clTypeInfo *
pgstrom_cltype_lookup(Oid type_oid)
{
	dlist_iter	iter;
	clTypeInfo *tinfo;
	uint32		hash;
	char		strbuf[512];
	int			i, j;

	hash = GetSysCacheHashValue1(TYPEOID, ObjectIdGetDatum(type_oid));
	i = hash % lengthof(cltype_info_slot);

	dlist_foreach(iter, &cltype_info_slot[i])
	{
		tinfo = dlist_container(clTypeInfo, chain, iter.cur);
		if (tinfo->type_oid == type_oid)
		{
			if (!tinfo->type_ident)
				return NULL;	/* negative cache */
			return tinfo;
		}
	}

	/* not found, so construct a new one */
	tinfo = MemoryContextAllocZero(CacheMemoryContext,
								   sizeof(clTypeInfo));
	tinfo->hash = hash;
	tinfo->type_oid = type_oid;
	for (j=0; j < lengthof(opencl_type_catalog); j++)
	{
		if (opencl_type_catalog[j].type_oid == type_oid)
		{
			HeapTuple		tuple;
			Form_pg_type	typform;
			MemoryContext	oldcxt;

			tuple = SearchSysCache1(TYPEOID,
									ObjectIdGetDatum(type_oid));
			if (!HeapTupleIsValid(tuple))
				elog(ERROR, "cache lookup failed for type %u", type_oid);
			typform = (Form_pg_type) GETSTRUCT(tuple);

			oldcxt = MemoryContextSwitchTo(CacheMemoryContext);

			tinfo->type_name = pstrdup(NameStr(typform->typname));

			snprintf(strbuf, sizeof(strbuf), "pg_%s_v",
					 NameStr(typform->typname));
			tinfo->type_ident = pstrdup(strbuf);

			if (opencl_type_catalog[j].type_kind == CLTYPE_KIND_NATIVE)
			{
				snprintf(strbuf, sizeof(strbuf), "pg_convert_%s_v",
						 opencl_type_catalog[j].type_base);
				tinfo->type_conv = pstrdup(strbuf);
			}
			tinfo->type_length = typform->typlen;
			if (opencl_type_catalog[j].type_kind == CLTYPE_KIND_NATIVE)
			{
				tinfo->type_is_native = true;
				snprintf(strbuf, sizeof(strbuf),
						 "STROMCL_NATIVE_TYPE_TEMPLATE(%s,%s)",
						 tinfo->type_name,
						 opencl_type_catalog[j].type_base);
				tinfo->type_define = pstrdup(strbuf);
			}
			else if (opencl_type_catalog[j].type_kind == CLTYPE_KIND_VARLENA)
			{
				tinfo->type_is_varlena = true;
				snprintf(strbuf, sizeof(strbuf),
						 "STROMCL_VARLENA_TYPE_TEMPLATE(%s)",
						 tinfo->type_name);
				tinfo->type_define = pstrdup(strbuf);
			}
			else
			{
				snprintf(strbuf, sizeof(strbuf),
						 "STROMCL_SIMPLE_TYPE_TEMPLATE(%s,%s)",
						 tinfo->type_name,
						 opencl_type_catalog[j].type_base);
				tinfo->type_define = pstrdup(strbuf);
			}

			MemoryContextSwitchTo(oldcxt);
			ReleaseSysCache(tuple);

			if (opencl_type_catalog[j].type_callback)
				(*opencl_type_catalog[j].type_callback)(tinfo,
														CacheMemoryContext);
			break;
		}
	}
	dlist_push_tail(&cltype_info_slot[i], &tinfo->chain);

	if (!tinfo->type_ident)
		return NULL;
	return tinfo;
}

static void
pgstrom_typeinfo_invalidate(Datum arg, int cacheid, uint32 hashvalue)
{
	int			i, min, max;

	if (hashvalue == 0)
	{
		min = 0;
		max = lengthof(cltype_info_slot) - 1;
	}
	else
	{
		min = max = (hashvalue % lengthof(cltype_info_slot));
	}

	for (i=min; i <= max; i++)
	{
		dlist_mutable_iter iter;

		dlist_foreach_modify(iter, &cltype_info_slot[i])
		{
			clTypeInfo *tinfo = dlist_container(clTypeInfo, chain, iter.cur);

			if (hashvalue == 0 || tinfo->hash == hashvalue)
			{
				dlist_delete(&tinfo->chain);

				if (tinfo->type_name)
					pfree(tinfo->type_name);
				if (tinfo->type_ident)
					pfree(tinfo->type_ident);
			}
		}
	}
}

/* ------------------------------------------------------------
 *
 * Catalog of OpenCL Functions
 *
 * ------------------------------------------------------------
 */
static void
clfunc_cb_native_cast(clFuncInfo *finfo,
					  const char *func_data,
					  MemoryContext memcxt)
{
	MemoryContext	oldcxt = MemoryContextSwitchTo(memcxt);
	StringInfoData	str;
	char			namebuf[2 * NAMEDATALEN + 20];

	Assert(finfo->func_nargs == 1);
	Assert(finfo->func_rettype->type_is_native &&
		   finfo->func_argtypes[0]->type_is_native);
	/* overwrite function identifier */
	snprintf(namebuf, sizeof(namebuf), "pg_convert_%s_to_%s",
			 finfo->func_argtypes[0]->type_name,
			 finfo->func_rettype->type_name);
	finfo->func_ident = pstrdup(namebuf);

	/* construct function definition */
	initStringInfo(&str);
	appendStringInfo(
		&str,
		"static inline %s\n"
		"%s(__private char_v *rmap, %s arg)\n"
		"{\n"
		"  %s result;\n"
		"\n"
		"  result.isnull = arg.isnull;\n"
		"  result.value = %s(arg.value);\n"
		"\n"
		"  return result;\n"
		"}\n",
		finfo->func_rettype->type_ident,
		finfo->func_ident,
		finfo->func_argtypes[0]->type_ident,
		finfo->func_rettype->type_ident,
		finfo->func_rettype->type_conv);
	MemoryContextSwitchTo(oldcxt);

	finfo->func_define = str.data;
}

static void
clfunc_cb_both_oper(clFuncInfo *finfo,
					const char *func_data,
					MemoryContext memcxt)
{
	MemoryContext	oldcxt = MemoryContextSwitchTo(memcxt);
	StringInfoData	str;
	clTypeInfo	   *rettype = finfo->func_rettype;
	clTypeInfo	   *arg1type = finfo->func_argtypes[0];
	clTypeInfo	   *arg2type = finfo->func_argtypes[1];

	Assert(finfo->func_nargs == 2);
	Assert(rettype->type_is_native &&
		   arg1type->type_is_native &&
		   arg2type->type_is_native);

	/* use default func_ident, so construct its definition */
	initStringInfo(&str);
	appendStringInfo(
		&str,
		"static inline %s\n"
		"%s(__private char_v *rmap, %s arg1, %s arg2)\n"
		"{\n"
		"  %s result;\n"
		"\n",
		rettype->type_ident,
		finfo->func_ident,
		arg1type->type_ident,
		arg2type->type_ident,
		rettype->type_ident);

	if (arg1type == arg2type)
	{
		appendStringInfo(
			&str,
			"  result.isnull = (arg1.isnull | arg2.isnull);\n"
			"  result.value = %s(arg1.value %s arg2.value);\n",
			rettype == arg1type ? "" : rettype->type_conv,
			func_data);
	}
	else if (arg1type->type_length > arg2type->type_length)
	{
		appendStringInfo(
			&str,
			"  result.isnull = (arg1.isnull | arg2.isnull);\n"
			"  result.value = %s(arg1.value %s %s(arg2.value));\n",
			rettype == arg1type ? "" : rettype->type_conv,
			func_data,
			arg1type->type_conv);
	}
	else
	{
		appendStringInfo(
			&str,
			"  result.isnull = (arg1.isnull | arg2.isnull);\n"
			"  result.value = %s(%s(arg1.value) %s arg2.value);\n",
			rettype == arg2type ? "" : rettype->type_conv,
			arg2type->type_conv,
			func_data);
	}

	/*
	 * Some operators need additional checks
	 *
	 * TODO: add overflow checks on +, -, * and /
	 */
	if (strcmp(func_data, "/") == 0 || strcmp(func_data, "%") == 0)
	{
		appendStringInfo(
			&str,
			"  *rmap |= (*rmap == (char)0)\n"
			"        & pg_convert_char_v(arg2.value == %s(%s))\n"
			"        & STROMCL_ERRCODE_DIV_BY_ZERO;\n",
			arg2type->type_conv,
			strncmp(finfo->func_name, "float", 5) == 0 ? "0.0" : "0");
	}
	appendStringInfo(&str,
					 "\n"
					 "  return result;\n"
					 "}\n");

	MemoryContextSwitchTo(oldcxt);

	finfo->func_define = str.data;
}

static void
clfunc_cb_left_oper(clFuncInfo *finfo,
					const char *func_data,
					MemoryContext memcxt)
{
	MemoryContext	oldcxt = MemoryContextSwitchTo(memcxt);
	StringInfoData	str;
	clTypeInfo	   *rettype = finfo->func_rettype;
	clTypeInfo	   *argtype = finfo->func_argtypes[0];

	Assert(finfo->func_nargs == 1);
	Assert(rettype->type_is_native && argtype->type_is_native);

	/* use default func_ident, so construct its definition */
	initStringInfo(&str);
	appendStringInfo(
		&str,
		"static inline %s\n"
		"%s(__private char_v *rmap, %s arg1)\n"
		"{\n"
		"  %s result;\n"
		"\n"
		"  result.isnull = arg1.isnull;\n"
		"  result.value = %s(%s(arg1.value));\n"
		"\n"
		"  return result;\n"
		"}\n",
		rettype->type_ident,
		finfo->func_ident,
		argtype->type_ident,
		rettype->type_ident,
		rettype == argtype ? "" : rettype->type_conv,
		func_data);

	MemoryContextSwitchTo(oldcxt);

	finfo->func_define = str.data;
}

static void
clfunc_cb_builtin_math(clFuncInfo *finfo,
					   const char *func_data,
					   MemoryContext memcxt)
{
	MemoryContext	oldcxt = MemoryContextSwitchTo(memcxt);
	StringInfoData	str;
	clTypeInfo	   *rettype = finfo->func_rettype;
	int				i;

	Assert(!rettype->type_is_varlena);

	/* use default func_ident, so construct its definition */
	initStringInfo(&str);
	appendStringInfo(&str,
					 "static inline %s\n"
					 "%s(__private char_v *rmap",
					 rettype->type_ident,
					 finfo->func_ident);
	for (i=0; i < finfo->func_nargs; i++)
		appendStringInfo(&str, ", %s arg%d",
						 finfo->func_argtypes[i]->type_ident,
						 i + 1);
	appendStringInfo(&str,
					 ")\n"
					 "{\n"
					 "  %s result;\n"
					 "\n",
					 rettype->type_ident);
	if (finfo->func_nargs == 0)
		appendStringInfo(&str, "  result.isnull = (char)0;\n");
	else
	{
		appendStringInfo(&str, "  result.isnull = (");
		for (i=0; i < finfo->func_nargs; i++)
			appendStringInfo(&str, "%sarg%d.isnull",
							 i == 0 ? "" : " | ",
							 i + 1);
		appendStringInfo(&str, ");\n");
	}

	if (func_data[0] == 'c' && func_data[1] == ':')
	{
		Assert(finfo->func_nargs == 0);
		appendStringInfo(&str, "  result.value = %s(%s);\n",
						 func_data + 2,
						 rettype->type_conv);
	}
	else if (func_data[0] == 'f' && func_data[1] == ':')
	{
		appendStringInfo(&str, "  result.value = %s(", func_data + 2);
		for (i=0; i < finfo->func_nargs; i++)
			appendStringInfo(&str, "%sarg%d.value",
							 i == 0 ? "" : ", ",
							 i + 1);
		appendStringInfo(&str, ");\n");
	}
	else
		elog(ERROR, "unexpected catalog description '%s' for clFunInfo %s",
			 func_data, finfo->func_ident);

	appendStringInfo(&str,
					 "  return result;\n"
					 "}\n");
	MemoryContextSwitchTo(oldcxt);

	finfo->func_define = str.data;
}

static void
clfunc_cb_bool_expr(clFuncInfo *finfo,
					MemoryContext memcxt,
					const char *func_cb_data)
{
	MemoryContext	oldcxt = MemoryContextSwitchTo(memcxt);
	StringInfoData	str;
	int				i;

	Assert(!finfo->func_ident);
	Assert(finfo->func_nargs > 0);

	/* assign function identifier */
	finfo->func_ident = pstrdup(finfo->func_name);

	/* construct function definition */
	initStringInfo(&str);
	Assert(finfo->func_rettype->type_oid == BOOLOID);
	appendStringInfo(&str, "static inline %s\n%s(",
					 finfo->func_rettype->type_ident,
					 finfo->func_ident);
	for (i=0; i < finfo->func_nargs; i++)
	{
		Assert(finfo->func_argtypes[i]->type_oid == BOOLOID);
		appendStringInfo(&str, "%s%s arg%d",
						 i == 0 ? "" : ", ",
						 finfo->func_argtypes[i]->type_ident,
						 i+1);
	}
	appendStringInfo(&str,
					 ")\n"
					 "{\n"
					 "  %s result;\n"
					 "\n",
					 finfo->func_rettype->type_ident);
	appendStringInfo(&str, "  result.isnull");
	for (i=0; i < finfo->func_nargs; i++)
		appendStringInfo(&str, " %s arg%d",
						 i == 0 ? "=" : "|", i+1);
	appendStringInfo(&str, ";\n");

	if (strcmp(func_cb_data, "&") == 0 || strcmp(func_cb_data, "|") == 0)
	{
		appendStringInfo(&str, "  result.value");
		for (i=0; i < finfo->func_nargs; i++)
			appendStringInfo(&str, " %s arg%d",
							 i == 0 ? "=" : func_cb_data, i+1);
		appendStringInfo(&str, ";\n");
	}
	else
	{
		Assert(strcmp(func_cb_data, "~") == 0);
		Assert(finfo->func_nargs == 1);
		appendStringInfo(&str, "  result.value = ~arg1.value;\n");
	}
	appendStringInfo(&str,
					 "\n"
					 "  return result;\n"
					 "}\n");
	MemoryContextSwitchTo(oldcxt);

	finfo->func_define = str.data;
}

#define CLFUNC_MAX_ARGS		6	/* tentasively */

static struct {
	/*
	 * signature of SQL function; that allows to identify a particular
	 * pg_proc catalog entry.
	 */
	char   *func_name;
	int		func_nargs;
	Oid		func_argtypes[CLFUNC_MAX_ARGS];

	/* true, if this function can handle/return vector values */
	bool	func_is_vector;

	/* mask of CL_DEVICE_TYPE_* where function can run */
	cl_device_type func_devtype;

	/* static definition of this function */
	char   *func_define;

	/* callback on construction of reletive clTypeInfo */
	void  (*func_callback)(clFuncInfo *func_info,
						   const char *func_data,
						   MemoryContext memcxt);
	/* data for callback */
	const char	   *func_data;
} opencl_func_catalog[] = {
	/* cast of data types */
	{ "int2",   1, {INT4OID},   true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_native_cast, NULL },
	{ "int2",   1, {INT8OID},   true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_native_cast, NULL },
	{ "int2",   1, {FLOAT4OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_native_cast, NULL },
	{ "int2",   1, {FLOAT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_native_cast, NULL },
	{ "int4",   1, {INT2OID},   true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_native_cast, NULL },
	{ "int4",   1, {INT8OID},   true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_native_cast, NULL },
	{ "int4",   1, {FLOAT4OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_native_cast, NULL },
	{ "int4",   1, {FLOAT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_native_cast, NULL },
	{ "int8",   1, {INT4OID},   true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_native_cast, NULL },
	{ "int8",   1, {INT8OID},   true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_native_cast, NULL },
	{ "int8",   1, {FLOAT4OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_native_cast, NULL },
	{ "int8",   1, {FLOAT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_native_cast, NULL },
	{ "float4", 1, {INT2OID},   true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_native_cast, NULL },
	{ "float4", 1, {INT4OID},   true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_native_cast, NULL },
	{ "float4", 1, {INT8OID},   true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_native_cast, NULL },
	{ "float4", 1, {FLOAT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_native_cast, NULL },
	{ "float8", 1, {INT2OID},   true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_native_cast, NULL },
	{ "float8", 1, {INT4OID},   true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_native_cast, NULL },
	{ "float8", 1, {INT8OID},   true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_native_cast, NULL },
	{ "float8", 1, {FLOAT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_native_cast, NULL },

	/* '+' : add operators */
	{ "int2pl",  2, {INT2OID, INT2OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "+" },
	{ "int24pl", 2, {INT2OID, INT4OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "+" },
	{ "int28pl", 2, {INT2OID, INT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "+" },
	{ "int42pl", 2, {INT4OID, INT2OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "+" },
	{ "int4pl",  2, {INT4OID, INT4OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "+" },
	{ "int48pl", 2, {INT4OID, INT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "+" },
	{ "int82pl", 2, {INT8OID, INT2OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "+" },
	{ "int84pl", 2, {INT8OID, INT4OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "+" },
	{ "int8pl",  2, {INT8OID, INT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "+" },
	{ "float4pl",  2, {FLOAT4OID, FLOAT4OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "+" },
	{ "float48pl", 2, {FLOAT4OID, FLOAT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "+" },
	{ "float84pl", 2, {FLOAT8OID, FLOAT4OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "+" },
	{ "float8pl",  2, {FLOAT8OID, FLOAT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "+" },

	/* '-' : substract operators */
	{ "int2mi",  2, {INT2OID, INT2OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "-" },
	{ "int24mi", 2, {INT2OID, INT4OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "-" },
	{ "int28mi", 2, {INT2OID, INT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "-" },
	{ "int42mi", 2, {INT4OID, INT2OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "-" },
	{ "int4mi",  2, {INT4OID, INT4OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "-" },
	{ "int48mi", 2, {INT4OID, INT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "-" },
	{ "int82mi", 2, {INT8OID, INT2OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "-" },
	{ "int84mi", 2, {INT8OID, INT4OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "-" },
	{ "int8mi",  2, {INT8OID, INT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "-" },
	{ "float4mi",  2, {FLOAT4OID, FLOAT4OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "-" },
	{ "float48mi", 2, {FLOAT4OID, FLOAT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "-" },
	{ "float84mi", 2, {FLOAT8OID, FLOAT4OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "-" },
	{ "float8mi",  2, {FLOAT8OID, FLOAT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "-" },

	/* '*' : multiply operators */
	{ "int2mul",  2, {INT2OID, INT2OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "*" },
	{ "int24mul", 2, {INT2OID, INT4OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "*" },
	{ "int28mul", 2, {INT2OID, INT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "*" },
	{ "int42mul", 2, {INT4OID, INT2OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "*" },
	{ "int4mul",  2, {INT4OID, INT4OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "*" },
	{ "int48mul", 2, {INT4OID, INT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "*" },
	{ "int82mul", 2, {INT8OID, INT2OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "*" },
	{ "int84mul", 2, {INT8OID, INT4OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "*" },
	{ "int8mul",  2, {INT8OID, INT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "*" },
	{ "float4mul",  2, {FLOAT4OID, FLOAT4OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "*" },
	{ "float48mul", 2, {FLOAT4OID, FLOAT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "*" },
	{ "float84mul", 2, {FLOAT8OID, FLOAT4OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "*" },
	{ "float8mul",  2, {FLOAT8OID, FLOAT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "*" },

	/* '/' : divide operators */
	{ "int2div",  2, {INT2OID, INT2OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "/" },
	{ "int24div", 2, {INT2OID, INT4OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "/" },
	{ "int28div", 2, {INT2OID, INT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "/" },
	{ "int42div", 2, {INT4OID, INT2OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "/" },
	{ "int4div",  2, {INT4OID, INT4OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "/" },
	{ "int48div", 2, {INT4OID, INT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "/" },
	{ "int82div", 2, {INT8OID, INT2OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "/" },
	{ "int84div", 2, {INT8OID, INT4OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "/" },
	{ "int8div",  2, {INT8OID, INT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "/" },
	{ "float4div",  2, {FLOAT4OID, FLOAT4OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "/" },
	{ "float48div", 2, {FLOAT4OID, FLOAT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "/" },
	{ "float84div", 2, {FLOAT8OID, FLOAT4OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "/" },
	{ "float8div",  2, {FLOAT8OID, FLOAT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "/" },

	/* '%' : reminder operators */
	{ "int2mod", 2, {INT2OID, INT2OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "%" },
	{ "int4mod", 2, {INT4OID, INT4OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "%" },
	{ "int8mod", 2, {INT8OID, INT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "%" },

	/* '+' : unary plus operators */
	{ "int2up", 1, {INT2OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_left_oper, "+" },
	{ "int4up", 1, {INT4OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_left_oper, "+" },
	{ "int8up", 1, {INT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_left_oper, "+" },
	{ "float4up", 1, {FLOAT4OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_left_oper, "+" },
	{ "float8up", 1, {FLOAT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_left_oper, "+" },

	/* '-' : unary minus operators */
	{ "int2um", 1, {INT2OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_left_oper, "-" },
	{ "int2um", 1, {INT4OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_left_oper, "-" },
	{ "int2um", 1, {INT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_left_oper, "-" },
	{ "float4um", 1, {FLOAT4OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_left_oper, "-" },
	{ "float8um", 1, {FLOAT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_left_oper, "-" },

	/* '@' : absolute value operators */
	{ "int2abs",   1, {INT2OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_left_oper, "abs" },
	{ "int4abs",   1, {INT4OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_left_oper, "abs" },
	{ "int8abs",   1, {INT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_left_oper, "abs" },
	{ "float4abs", 1, {FLOAT4OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_left_oper, "abs" },
	{ "float8abs", 1, {FLOAT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_left_oper, "abs" },

	/* '=' : equal operators */
	{ "int2eq",  2, {INT2OID, INT2OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "==" },
	{ "int24eq", 2, {INT2OID, INT4OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "==" },
	{ "int28eq", 2, {INT2OID, INT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "==" },
	{ "int42eq", 2, {INT4OID, INT2OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "==" },
	{ "int4eq",  2, {INT4OID, INT4OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "==" },
	{ "int48eq", 2, {INT4OID, INT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "==" },
	{ "int82eq", 2, {INT8OID, INT2OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "==" },
	{ "int84eq", 2, {INT8OID, INT4OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "==" },
	{ "int8eq",  2, {INT8OID, INT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "==" },
	{ "float4eq",  2, {FLOAT4OID, FLOAT4OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "==" },
	{ "float48eq", 2, {FLOAT4OID, FLOAT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "==" },
	{ "float84eq", 2, {FLOAT8OID, FLOAT4OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "==" },
	{ "float8eq",  2, {FLOAT8OID, FLOAT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "==" },

	/* '<>' : not equal operators */
	{ "int2ne",  2, {INT2OID, INT2OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "!=" },
	{ "int24ne", 2, {INT2OID, INT4OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "!=" },
	{ "int28ne", 2, {INT2OID, INT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "!=" },
	{ "int42ne", 2, {INT4OID, INT2OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "!=" },
	{ "int4ne",  2, {INT4OID, INT4OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "!=" },
	{ "int48ne", 2, {INT4OID, INT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "!=" },
	{ "int82ne", 2, {INT8OID, INT2OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "!=" },
	{ "int84ne", 2, {INT8OID, INT4OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "!=" },
	{ "int8ne",  2, {INT8OID, INT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "!=" },
	{ "float4ne",  2, {FLOAT4OID, FLOAT4OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "!=" },
	{ "float48ne", 2, {FLOAT4OID, FLOAT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "!=" },
	{ "float84ne", 2, {FLOAT8OID, FLOAT4OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "!=" },
	{ "float8ne",  2, {FLOAT8OID, FLOAT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "!=" },

	/* '>'  : relational greater-than */
	{ "int2gt",  2, {INT2OID, INT2OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, ">" },
	{ "int24gt", 2, {INT2OID, INT4OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, ">" },
	{ "int28gt", 2, {INT2OID, INT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, ">" },
	{ "int42gt", 2, {INT4OID, INT2OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, ">" },
	{ "int4gt",  2, {INT4OID, INT4OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, ">" },
	{ "int48gt", 2, {INT4OID, INT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, ">" },
	{ "int82gt", 2, {INT8OID, INT2OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, ">" },
	{ "int84gt", 2, {INT8OID, INT4OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, ">" },
	{ "int8gt",  2, {INT8OID, INT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, ">" },
	{ "float4gt",  2, {FLOAT4OID, FLOAT4OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, ">" },
	{ "float48gt", 2, {FLOAT4OID, FLOAT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, ">" },
	{ "float84gt", 2, {FLOAT8OID, FLOAT4OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, ">" },
	{ "float8gt",  2, {FLOAT8OID, FLOAT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, ">" },

	/* '<'  : relational less-than */
	{ "int2lt",  2, {INT2OID, INT2OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "<" },
	{ "int24lt", 2, {INT2OID, INT4OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "<" },
	{ "int28lt", 2, {INT2OID, INT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "<" },
	{ "int42lt", 2, {INT4OID, INT2OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "<" },
	{ "int4lt",  2, {INT4OID, INT4OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "<" },
	{ "int48lt", 2, {INT4OID, INT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "<" },
	{ "int82lt", 2, {INT8OID, INT2OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "<" },
	{ "int84lt", 2, {INT8OID, INT4OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "<" },
	{ "int8lt",  2, {INT8OID, INT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "<" },
	{ "float4lt",  2, {FLOAT4OID, FLOAT4OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "<" },
	{ "float48lt", 2, {FLOAT4OID, FLOAT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "<" },
	{ "float84lt", 2, {FLOAT8OID, FLOAT4OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "<" },
	{ "float8lt",  2, {FLOAT8OID, FLOAT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "<" },

	/* '>=' : relational greater-than or equal-to */
	{ "int2ge",  2, {INT2OID, INT2OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, ">=" },
	{ "int24ge", 2, {INT2OID, INT4OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, ">=" },
	{ "int28ge", 2, {INT2OID, INT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, ">=" },
	{ "int42ge", 2, {INT4OID, INT2OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, ">=" },
	{ "int4ge",  2, {INT4OID, INT4OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, ">=" },
	{ "int48ge", 2, {INT4OID, INT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, ">=" },
	{ "int82ge", 2, {INT8OID, INT2OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, ">=" },
	{ "int84ge", 2, {INT8OID, INT4OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, ">=" },
	{ "int8ge",  2, {INT8OID, INT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, ">=" },
	{ "float4ge",  2, {FLOAT4OID, FLOAT4OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, ">=" },
	{ "float48ge", 2, {FLOAT4OID, FLOAT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, ">=" },
	{ "float84ge", 2, {FLOAT8OID, FLOAT4OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, ">=" },
	{ "float8ge",  2, {FLOAT8OID, FLOAT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, ">=" },

	/* '<=' : relational less-than or equal to */
	{ "int2le",  2, {INT2OID, INT2OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "<=" },
	{ "int24le", 2, {INT2OID, INT4OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "<=" },
	{ "int28le", 2, {INT2OID, INT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "<=" },
	{ "int42le", 2, {INT4OID, INT2OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "<=" },
	{ "int4le",  2, {INT4OID, INT4OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "<=" },
	{ "int48le", 2, {INT4OID, INT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "<=" },
	{ "int82le", 2, {INT8OID, INT2OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "<=" },
	{ "int84le", 2, {INT8OID, INT4OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "<=" },
	{ "int8le",  2, {INT8OID, INT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "<=" },
	{ "float4le",  2, {FLOAT4OID, FLOAT4OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "<=" },
	{ "float48le", 2, {FLOAT4OID, FLOAT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "<=" },
	{ "float84le", 2, {FLOAT8OID, FLOAT4OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "<=" },
	{ "float8le",  2, {FLOAT8OID, FLOAT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "<=" },

	/* '&'  : bitwise and */
	{ "int2and", 2, {INT2OID, INT2OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "&" },
	{ "int4and", 2, {INT4OID, INT4OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "&" },
	{ "int8and", 2, {INT8OID, INT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "&" },

	/* '|'  : bitwise or */
	{ "int2or", 2, {INT2OID, INT2OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "|" },
	{ "int4or", 2, {INT4OID, INT4OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "|" },
	{ "int8or", 2, {INT8OID, INT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "|" },

	/* '#'  : bitwise xor */
	{ "int2xor", 2, {INT2OID, INT2OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "^" },
	{ "int4xor", 2, {INT4OID, INT4OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "^" },
	{ "int8xor", 2, {INT8OID, INT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "^" },

	/* '~'  : bitwise not operators */
	{ "int2not", 1, {INT2OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_left_oper, "~" },
	{ "int4not", 1, {INT4OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_left_oper, "~" },
	{ "int8not", 1, {INT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_left_oper, "~" },

	/* '>>' : right shift */
	{ "int2shr", 2, {INT2OID, INT4OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, ">>" },
	{ "int4shr", 2, {INT4OID, INT4OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, ">>" },
	{ "int8shr", 2, {INT8OID, INT4OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, ">>" },

	/* '<<' : left shift */
	{ "int2shl", 2, {INT2OID, INT4OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "<<" },
	{ "int4shl", 2, {INT4OID, INT4OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "<<" },
	{ "int8shl", 2, {INT8OID, INT4OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_both_oper, "<<" },

	/* Mathmatical functions */
	{ "cbrt", 1, {FLOAT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_builtin_math, "f:cbrt" },
	{ "ceil", 1, {FLOAT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_builtin_math, "f:ceil" },
	{ "exp", 1, {FLOAT8OID},  true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_builtin_math, "f:exp" },
	{ "floor", 1, {FLOAT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_builtin_math, "f:floor" },
	{ "ln", 1, {FLOAT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_builtin_math, "f:log" },
	{ "log", 1, {FLOAT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_builtin_math, "f:log10" },
	{ "pi", 1, {FLOAT8OID}, false, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_builtin_math, "c:3.14159265358979323846" },
	{ "power", 2, {FLOAT8OID, FLOAT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_builtin_math, "f:pow" },
	{ "pow", 2, {FLOAT8OID, FLOAT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_builtin_math, "f:pow" },
	{ "dpow", 2, {FLOAT8OID, FLOAT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_builtin_math, "f:pow" },
	{ "round", 1, {FLOAT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_builtin_math, "f:round" },
	{ "sign", 1, {FLOAT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_builtin_math, "f:sign" },
	{ "sqrt", 1, {FLOAT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_builtin_math, "f:sqrt" },
	{ "dsqrt", 1, {FLOAT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_builtin_math, "f:sqrt" },
	{ "trunc", 1, {FLOAT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_builtin_math, "f:trunc" },
	{ "dtrunc", 1, {FLOAT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_builtin_math, "f:trunc" },

	/* Trigonometric function */
	{ "acos",  1, {FLOAT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_builtin_math, "f:acos" },
	{ "asin",  1, {FLOAT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_builtin_math, "f:asin" },
	{ "atan",  1, {FLOAT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_builtin_math, "f:atan" },
	{ "atan2", 2, {FLOAT8OID, FLOAT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_builtin_math, "f:atan2" },
	{ "cos",   1, {FLOAT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_builtin_math, "f:cos" },
	{ "cot",   1, {FLOAT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_builtin_math, "f:cot" },
	{ "sin",   1, {FLOAT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_builtin_math, "f:sin" },
	{ "tan",   1, {FLOAT8OID}, true, CL_DEVICE_TYPE_ALL,
	  NULL, clfunc_cb_builtin_math, "f:tan" },
};

static inline void
clfunc_increment_type_usecnt(clFuncInfo *finfo, const clTypeInfo *tinfo)
{
	if (!tinfo->type_is_native)
		return;

	switch (tinfo->type_oid)
	{
		case BOOLOID:
			finfo->func_usecnt_char += 2;
			break;
		case INT2OID:
			finfo->func_usecnt_short += 2;
			break;
		case INT4OID:
			finfo->func_usecnt_int += 2;
			finfo->func_usecnt_float++;
			break;
		case INT8OID:
			finfo->func_usecnt_long += 2;
			finfo->func_usecnt_double++;
			break;
		case FLOAT4OID:
			finfo->func_usecnt_float += 2;
			finfo->func_usecnt_int++;
			break;
		case FLOAT8OID:
			finfo->func_usecnt_double += 2;
			finfo->func_usecnt_long++;
			break;
		default:
			/* do nothing */
			break;
	}
}

static clFuncInfo *
pgstrom_clfunc_lookup_raw(const char *func_name,
						  Oid func_rettype,
						  oidvector *func_argtypes,
						  Oid func_namespace,
						  void (*func_cb_construct)(clFuncInfo *finfo,
													MemoryContext memcxt,
													const char *func_cb_data),
						  const char *func_cb_data)
{
	dlist_iter		iter;
	clFuncInfo	   *finfo;
	uint32			hash;
	int				i, j, k;

	hash = GetSysCacheHashValue3(PROCNAMEARGSNSP,
								 CStringGetDatum(func_name),
								 PointerGetDatum(func_argtypes),
								 ObjectIdGetDatum(func_namespace));
	i = hash % lengthof(cltype_info_slot);

	dlist_foreach(iter, &clfunc_info_slot[i])
	{
		finfo = dlist_container(clFuncInfo, chain, iter.cur);
		if (finfo->func_namespace == func_namespace &&
			strcmp(finfo->func_name, func_name) == 0 &&
			finfo->func_nargs == func_argtypes->dim1 &&
			memcmp(finfo->func_argtypes_oid,
				   func_argtypes->values,
				   sizeof(Oid) * func_argtypes->dim1) == 0)
		{
			if (!finfo->func_ident)
				return NULL;	/* negative cache */
			return finfo;
		}
	}
	/* not found, so construct a new one */
	finfo = MemoryContextAllocZero(CacheMemoryContext,
								   sizeof(clFuncInfo) +
								   sizeof(Oid) * func_argtypes->dim1 +
								   sizeof(clTypeInfo *) * func_argtypes->dim1);
	finfo->hash = hash;
	finfo->func_name = MemoryContextStrdup(CacheMemoryContext, func_name);
	finfo->func_namespace = func_namespace;
	finfo->func_usecnt_int = 1;	/* give small advantage on int-vector */
	finfo->func_nargs = func_argtypes->dim1;
	finfo->func_argtypes_oid = (Oid *)(finfo->func_argtypes +
									   func_argtypes->dim1);
	finfo->func_rettype = pgstrom_cltype_lookup(func_rettype);
	if (!finfo->func_rettype)
		elog(ERROR, "failed to lookup clTypeInfo of %s",
			 format_type_be(func_rettype));
	clfunc_increment_type_usecnt(finfo, finfo->func_rettype);

	for (k=0; k < func_argtypes->dim1; k++)
	{
		finfo->func_argtypes[k] =
			pgstrom_cltype_lookup(func_argtypes->values[k]);
		if (!finfo->func_argtypes[k])
			elog(ERROR, "failed to lookup clTypeInfo of %s",
				 format_type_be(func_argtypes->values[k]));
		clfunc_increment_type_usecnt(finfo, finfo->func_argtypes[k]);
		finfo->func_argtypes_oid[k] = finfo->func_argtypes[k]->type_oid;
	}
	if (func_namespace != PG_CATALOG_NAMESPACE)
		goto skip;

	for (j=0; j < lengthof(opencl_func_catalog); j++)
	{
		if (strcmp(opencl_func_catalog[j].func_name, func_name) == 0 &&
			opencl_func_catalog[j].func_nargs == func_argtypes->dim1 &&
			memcmp(opencl_func_catalog[j].func_argtypes,
				   func_argtypes->values,
				   sizeof(Oid) * func_argtypes->dim1) == 0)
		{
			char			namebuf[NAMEDATALEN + 20]; 
			const char	   *func_data;
			MemoryContext	oldcxt;

			/*
			 * Right now, we assume all the functions in catalog needs
			 * just one processor per call, and don't need no special
			 * working memory.
			 */
			oldcxt = MemoryContextSwitchTo(CacheMemoryContext);
			finfo->func_nprocs = (Expr *) makeConst(INT4OID,
													-1,
													InvalidOid,
													sizeof(int32),
													Int32GetDatum(1),
													false,
													true);
			finfo->func_memsz = NULL;
			MemoryContextSwitchTo(oldcxt);

			/* available device types */
			finfo->func_devtype = opencl_func_catalog[j].func_devtype;

			/*
			 * opencl function name shall be pg_##NAME##(arg1, ...) in
			 * default, but can be fixed up on callback
			 */
			snprintf(namebuf, sizeof(namebuf), "pg_%s", finfo->func_name);
			finfo->func_ident = MemoryContextStrdup(CacheMemoryContext,
													namebuf);
			finfo->func_define = opencl_func_catalog[j].func_define;

			/* callback to fixup this clFuncInfo */
			func_data = opencl_func_catalog[j].func_data;
			if (opencl_func_catalog[j].func_callback)
				(*opencl_func_catalog[j].func_callback)(finfo,
														func_data,
														CacheMemoryContext);
			if (!finfo->func_define)
				elog(ERROR, "opencl function %s (SQL: %s) has no definition",
					 finfo->func_ident, finfo->func_name);

			/* copy the definition if static definition as is */
			if (finfo->func_define == opencl_func_catalog[j].func_define)
				finfo->func_define = MemoryContextStrdup(CacheMemoryContext,
														 finfo->func_define);
			break;
		}
	}
skip:
	/* callback on finfo construction */
	if (func_cb_construct != NULL)
		(*func_cb_construct)(finfo, CacheMemoryContext, func_cb_data);

	/* function must have its definition unless it's not a negative cache */
	Assert(!finfo->func_ident || finfo->func_define != NULL);

	dlist_push_tail(&clfunc_info_slot[i], &finfo->chain);
	if (!finfo->func_ident)
		return NULL;
	return finfo;
}

clFuncInfo *
pgstrom_clfunc_lookup(Oid func_oid)
{
	HeapTuple		tuple;
	Form_pg_proc	proform;
	clFuncInfo	   *finfo;

	tuple = SearchSysCache1(PROCOID, ObjectIdGetDatum(func_oid));
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for function %u", func_oid);
	proform = (Form_pg_proc) GETSTRUCT(tuple);

	finfo = pgstrom_clfunc_lookup_raw(NameStr(proform->proname),
									  proform->prorettype,
									  &proform->proargtypes,
									  proform->pronamespace,
									  NULL, NULL);
	ReleaseSysCache(tuple);

	return finfo;
}

static void
pgstrom_funcinfo_invalidate(Datum arg, int cacheid, uint32 hashvalue)
{
	int		i, min, max;

	if (hashvalue == 0)
	{
		min = 0;
		max = lengthof(clfunc_info_slot) - 1;
	}
	else
	{
		min = max = (hashvalue % lengthof(clfunc_info_slot));
	}

	for (i=min; i <= max; i++)
	{
		dlist_mutable_iter iter;

		dlist_foreach_modify(iter, &clfunc_info_slot[i])
		{
			clFuncInfo *finfo = dlist_container(clFuncInfo, chain, iter.cur);

			if (hashvalue == 0 || finfo->hash == hashvalue)
			{
				dlist_delete(&finfo->chain);

				pfree(finfo->func_ident);
				pfree(finfo->func_define);
				pfree(finfo);
			}
		}
	}
}

/*
 * __kernel void
 * kernel_qual(__global kern_params_t *kparams,
 *             __global kern_args_t   *kargs,
 *             __global char          *kvlbuf,
 *             __global char          *kwkmem)
 */
typedef struct {
	List		   *type_list;
	List		   *func_list;
	List		   *kernel_params;
	cl_device_type	allowed_devtype;
	int				usecnt_char;
	int				usecnt_short;
	int				usecnt_int;
	int				usecnt_long;
	int				usecnt_float;
	int				usecnt_double;
	AttrNumber		nattrs;
	FormData_pg_attribute *attrs;
	StringInfoData	kernel_qual;
	StringInfoData	kparams_alias;
	StringInfoData	kargs_alias;
} codegen_context;

static void
codegen_kernel_expr(codegen_context *context, Node *expr);

static void
codegen_kernel_func(codegen_context *context,
					Oid func_oid, List *func_args)
{
	clFuncInfo *finfo;
	ListCell   *cell;
	int			index = 0;

	finfo = pgstrom_clfunc_lookup(func_oid);
	if (!finfo)
		elog(ERROR, "clFuncInfo lookup failed for function: %s",
			 format_procedure(func_oid));
	context->func_list = list_append_unique(context->func_list, finfo);

	if (finfo->func_rettype->type_oid != get_func_rettype(func_oid))
		elog(ERROR, "Bug? unexpected argument type (%s, %s)",
			 format_type_be(finfo->func_rettype->type_oid),
			 format_type_be(get_func_rettype(func_oid)));
	context->type_list = list_append_unique(context->type_list,
											finfo->func_rettype);

	appendStringInfo(&context->kernel_qual,
					 "%s(&rmap", finfo->func_ident);
	index = 0;
	foreach (cell, func_args)
	{
		Node   *expr = lfirst(cell);

		if (finfo->func_argtypes[index]->type_oid != exprType(expr))
			elog(ERROR, "Bug? unexpected argument type (%s, %s)",
				 format_type_be(finfo->func_argtypes[index]->type_oid),
				 format_type_be(exprType(expr)));
		context->type_list = list_append_unique(context->type_list,
												finfo->func_argtypes[index]);
		appendStringInfo(&context->kernel_qual, ", ");
		codegen_kernel_expr(context, expr);
		index++;
	}
	appendStringInfo(&context->kernel_qual, ")");

	/* adjust planner hint */
	context->allowed_devtype &= finfo->func_devtype;
	context->usecnt_char     += finfo->func_usecnt_char;
	context->usecnt_short    += finfo->func_usecnt_short;
	context->usecnt_int      += finfo->func_usecnt_int;
	context->usecnt_long     += finfo->func_usecnt_long;
	context->usecnt_float    += finfo->func_usecnt_float;
	context->usecnt_double   += finfo->func_usecnt_double;
}

static void
codegen_kernel_bool(codegen_context *context,
					BoolExprType boolop, List *args)
{
	clFuncInfo *finfo;
	ListCell   *cell;
	char		namebuf[NAMEDATALEN + 20];
	Oid		   *argtypes;
	const char *func_cb_data;
	int			i;

	switch (boolop)
	{
		case AND_EXPR:
			snprintf(namebuf, sizeof(namebuf),
					 "pg_bool_and%d_expr", list_length(args));
			func_cb_data = "&";
			break;
		case OR_EXPR:
			snprintf(namebuf, sizeof(namebuf),
					 "pg_bool_or%d_expr", list_length(args));
			func_cb_data = "|";
			break;
		case NOT_EXPR:
			Assert(list_length(args) == 1);
			snprintf(namebuf, sizeof(namebuf),
					 "pg_bool_not_expr");
			func_cb_data = "~";
			break;
		default:
			elog(ERROR, "unexpected BoolExpr: %d", (int)boolop);
			break;
	}
	argtypes = palloc0(sizeof(Oid) * list_length(args));
	for (i=0; i < list_length(args); i++)
		argtypes[i] = BOOLOID;

	finfo = pgstrom_clfunc_lookup_raw(namebuf,
									  BOOLOID,
									  buildoidvector(argtypes,
													 list_length(args)),
									  InvalidOid,	/* device only func */
									  clfunc_cb_bool_expr,
									  func_cb_data);
	if (!finfo)
		elog(ERROR, "clFuncInfo lookup failed for function: %s", namebuf);
	context->func_list = list_append_unique(context->func_list, finfo);

	context->type_list = list_append_unique(context->type_list,
											finfo->func_rettype);

	appendStringInfo(&context->kernel_qual,
					 "%s(&rmap", finfo->func_ident);
	foreach (cell, args)
	{
		Node   *expr = lfirst(cell);

		if (exprType(expr) != BOOLOID)
			elog(ERROR, "Bug? BoolExpr takes non-bool argument");

		appendStringInfo(&context->kernel_qual, ", ");
		codegen_kernel_expr(context, expr);
	}
	appendStringInfo(&context->kernel_qual, ")");
}

static void
codegen_kernel_expr(codegen_context *context, Node *expr)
{
	clTypeInfo	   *tinfo;

	if (expr == NULL)
		return;

	if (IsA(expr, Const))
	{
		Const  *c = (Const *) expr;

		tinfo = pgstrom_cltype_lookup(c->consttype);
		if (!tinfo)
			elog(ERROR, "clTypeInfo lookup failed for type: %s",
				 format_type_be(c->consttype));

		context->type_list = list_append_unique(context->type_list, tinfo);
		context->kernel_params = lappend(context->kernel_params, c);

		appendStringInfo(&context->kparams_alias,
						 "#define PG_PARAM%d pg_%s_pref(%d,kparams)\n",
						 list_length(context->kernel_params),
						 tinfo->type_name,
						 list_length(context->kernel_params) - 1);
		appendStringInfo(&context->kernel_qual,
						 "PG_PARAM%d",
						 list_length(context->kernel_params));
	}
	else if (IsA(expr, Param))
	{
		Param  *param = (Param *) expr;

		tinfo = pgstrom_cltype_lookup(param->paramtype);
		if (!tinfo)
			elog(ERROR, "clTypeInfo lookup failed for type: %s",
				 format_type_be(param->paramtype));

		context->type_list = list_append_unique(context->type_list, tinfo);
		context->kernel_params = lappend(context->kernel_params, param);

		appendStringInfo(&context->kparams_alias,
						 "#define PG_PARAM%d pg_%s_pref(%d,kparams)\n",
						 list_length(context->kernel_params),
						 tinfo->type_name,
						 list_length(context->kernel_params) - 1);
		appendStringInfo(&context->kernel_qual,
						 "PG_PARAM%d",
						 list_length(context->kernel_params));
	}
	else if (IsA(expr, Var))
	{
		Var	   *var = (Var *) expr;
		Form_pg_attribute attr;

		Assert(var->varattno <= context->nattrs);
		attr = &context->attrs[var->varattno - 1];

		tinfo = pgstrom_cltype_lookup(var->vartype);
		if (!tinfo)
			elog(ERROR, "clTypeInfo lookup failed for type: %s",
				 format_type_be(var->vartype));

		context->type_list = list_append_unique(context->type_list, tinfo);
		appendStringInfo(&context->kernel_qual,
						 "PG_ARGV%d", attr->attnum);
	}
	else if (IsA(expr, FuncExpr))
	{
		FuncExpr   *f = (FuncExpr *)expr;

		codegen_kernel_func(context, f->funcid, f->args);
	}
	else if (IsA(expr, OpExpr) ||
			 IsA(expr, DistinctExpr))
	{
		OpExpr	   *op = (OpExpr *)expr;

		codegen_kernel_func(context, op->opfuncid, op->args);
	}
	else if (IsA(expr, BoolExpr))
	{
		BoolExpr   *b = (BoolExpr *)expr;

		codegen_kernel_bool(context, b->boolop, b->args);
	}
	else
		elog(ERROR, "unexpected node: %s", nodeToString(expr));
}

text *
pgstrom_codegen_qual(PlannerInfo *root,
					 RelOptInfo *baserel,
					 Node *kernel_expr,
					 List **p_kernel_params,			/* out */
					 List **p_kernel_cols,				/* out */
					 cl_device_type *p_allowed_devtype,	/* out */
					 char **p_vector_preference)			/* out */
{
	codegen_context	context;
	RangeTblEntry  *rte = root->simple_rte_array[baserel->relid];
	Bitmapset	   *varattnos = NULL;
	HeapTuple		tuple;
	int				attnum;
	int				attidx;
	const char	   *vector_curr;
	int				usecnt_curr;
	ListCell	   *cell;
	List		   *kernel_cols = NIL;
	bool			has_varlena = false;
	StringInfoData	kern_body;

	Assert(kernel_expr != NULL);
	if (exprType(kernel_expr) != BOOLOID)
		elog(ERROR, "Bug? kernel_expr has non-bool type");

	initStringInfo(&kern_body);
	kern_body.len = VARHDRSZ;

	/*
	 * Setup walker's context
	 */
	memset(&context, 0, sizeof(codegen_context));
	context.allowed_devtype = CL_DEVICE_TYPE_ALL;
	context.nattrs = baserel->max_attr;
	context.attrs = palloc0(sizeof(FormData_pg_attribute) *
							baserel->max_attr);
	initStringInfo(&context.kernel_qual);
	initStringInfo(&context.kparams_alias);
	initStringInfo(&context.kargs_alias);

	pull_varattnos((Node *)kernel_expr, baserel->relid, &varattnos);
	attidx = 0;
	while ((attnum = bms_first_member(varattnos)) >= 0)
	{
		clTypeInfo *tinfo;

		attnum += FirstLowInvalidHeapAttributeNumber;
		/* Var referencing system column should not be in kernel_quals */
		Assert(attnum > 0);

		kernel_cols = lappend_int(kernel_cols, attnum);

		tuple = SearchSysCache2(ATTNUM,
								ObjectIdGetDatum(rte->relid),
								Int16GetDatum(attnum));
		if (!HeapTupleIsValid(tuple))
			elog(ERROR, "cache lookup failed for attribute %d of relation %u",
				 attnum, rte->relid);

		memcpy(context.attrs + attnum - 1,
			   (Form_pg_attribute) GETSTRUCT(tuple),
			   ATTRIBUTE_FIXED_PART_SIZE);
		/*
		 * An abuse of attr->attnum that is redirected to point attribute
		 * index in OpenCL kernel code, because we only copies attribute's
		 * metadata being in use, thus, an alternative index number is
		 * necessary!
		 */
		context.attrs[attnum - 1].attnum = ++attidx;

		/*
		 * In case when we need to move varlena variables to kernel,
		 * nitems value shall be informed via kern_vlbuf_t, instead of
		 * kern_args_t.
		 */
		if (context.attrs[attnum - 1].attlen < 0)
			has_varlena = true;

		/*
		 * Add definition of shortcut to the variable reference on
		 * kernel argument.
		 */
		tinfo = pgstrom_cltype_lookup(context.attrs[attnum - 1].atttypid);
		if (!tinfo)
			elog(ERROR, "clTypeInfo lookup failed for type: %s",
				 format_type_be(tinfo->type_oid));

		context.type_list = list_append_unique(context.type_list, tinfo);
		appendStringInfo(&context.kargs_alias,
						 "#define PG_ARGV%d\t\\\n"
						 "  pg_%s_vref(%d,%s,kargs,kvlbuf)\n",
						 attidx,
						 tinfo->type_name,
						 attidx - 1,
						 tinfo->type_is_varlena ?
						 "get_global_id(1) - get_global_offset(1)" :
						 "get_global_id(1)");

		ReleaseSysCache(tuple);
	}

	/*
	 * Generate a kernel expression from an expression tree
	 */
	codegen_kernel_expr(&context, kernel_expr);

	/* add type definition */
	foreach (cell, context.type_list)
	{
		clTypeInfo *tinfo = lfirst(cell);

		appendStringInfo(&kern_body, "%s\n", tinfo->type_define);
	}
	appendStringInfoChar(&kern_body, '\n');

	/* add function definition */
	foreach (cell, context.func_list)
	{
		clFuncInfo *finfo = lfirst(cell);

		appendStringInfo(&kern_body, "%s\n", finfo->func_define);
	}

	/* shortcut for kparams/kargs */
	appendStringInfo(&kern_body, "%s%s\n",
					 context.kparams_alias.data,
					 context.kargs_alias.data);

	/*
	 * XXX - Logic needs to be adjusted once we support multiple computing
	 * units per row. A computing unit is mapped per row right now, so we
	 * assume all the calculation shall be done in sindle-thread.
	 */
	appendStringInfo(
		&kern_body,
		"__kernel void kernel_qual(\n"
		"  __global kern_params_t *kparams,\n"
		"  __global kern_args_t   *kargs,\n"
		"  __global kern_vlbuf_t  *kvlbuf,\n"
		"  __global char          *gwkmem)\n"
		"{\n"
		"  int nitems = %s->nitems;\n"
		"  char_v rmap;\n"
		"  pg_bool_v result;\n"
		"\n"
		"  if (get_global_id(1) -\n"
		"      get_global_offset(1) >= nitems / STROMCL_VECTOR_WIDTH)\n"
		"    return;\n"
		"\n"
		"  rmap = pg_vload(get_global_id(1), ROWMAP_BASE(kargs));\n"
		"  result = %s;\n"
		"#if STROMCL_VECTOR_WIDTH > 1\n"
		"  rmap |= (rmap == (char)0) & ((result.isnull != (char)0) |\n"
		"                               (result.value  == (char)0)) &\n"
		"          STROMCL_ERRCODE_ROW_MASKED;\n"
		"#else\n"
		"  if (rmap == (char)0 && (result.isnull != (char)0 ||\n"
		"                          result.value == (char)0))\n"
		"    rmap = STROMCL_ERRCODE_ROW_MASKED;\n"
		"#endif\n"
		"  pg_vstore(rmap, get_global_id(1), ROWMAP_BASE(kargs));\n"
		"}\n",
		has_varlena ? "kvlbuf" : "kargs",
		context.kernel_qual.data);
	SET_VARSIZE(kern_body.data, kern_body.len);

	*p_kernel_cols = kernel_cols;
	*p_kernel_params = context.kernel_params;
	*p_allowed_devtype = context.allowed_devtype;

	/* which type is dominative in this calculation? */
	usecnt_curr = context.usecnt_int;
	vector_curr = "int";
	if (context.usecnt_char > usecnt_curr)
	{
		usecnt_curr = context.usecnt_char;
		vector_curr = "char";
	}
	if (context.usecnt_short > usecnt_curr)
	{
		usecnt_curr = context.usecnt_short;
		vector_curr = "short";
	}
	if (context.usecnt_long > usecnt_curr)
	{
		usecnt_curr = context.usecnt_long;
		vector_curr = "long";
	}
	if (context.usecnt_float > usecnt_curr)
	{
		usecnt_curr = context.usecnt_float;
		vector_curr = "float";
	}
	if (context.usecnt_double > usecnt_curr)
	{
		usecnt_curr = context.usecnt_double;
		vector_curr = "double";
	}
	*p_vector_preference = pstrdup(vector_curr);

	return (text *)kern_body.data;
}

void
pgstrom_codegen_init(void)
{
	int		i;

	for (i=0; i < lengthof(cltype_info_slot); i++)
		dlist_init(&cltype_info_slot[i]);
	for (i=0; i < lengthof(clfunc_info_slot); i++)
		dlist_init(&clfunc_info_slot[i]);

	CacheRegisterSyscacheCallback(TYPEOID,
								  pgstrom_typeinfo_invalidate, 0);
	CacheRegisterSyscacheCallback(PROCNAMEARGSNSP,
								  pgstrom_funcinfo_invalidate, 0);
}
