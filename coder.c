/*
 * coder.c
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
#include "catalog/pg_proc.h"
#include "catalog/pg_type.h"
#include "lib/stringinfo.h"
#include "nodes/makefuncs.h"
#include "utils/builtins.h"
#include "utils/inval.h"
#include "utils/memutils.h"
#include "utils/syscache.h"
#include "pg_strom.h"

#define cltype_is_vector(tinfo)		((tinfo)->type_scalar != NULL)
#define clfunc_is_vector(finfo)		cltype_is_vector((finfo)->func_rettype)

typedef struct clTypeInfo {
	dlist_node	chain;
	uint32		hash;
	/* oid of SQL type */
	Oid			type_oid;
	/* type identifier */
	char	   *type_ident;
	/* type definition, or NULL if built-in */
	char	   *type_define;
	/* underlying scalar type, if type is vectorized. elsewhere, NULL */
	struct clTypeInfo *type_scalar;
} clTypeInfo;

typedef struct {
	dlist_node	chain;
	uint32		hash;
	/* oid of SQL function */
	Oid			func_oid;
	/* function identifier */
	char	   *func_ident;
	/* function definition, or NULL if built-in */
	char	   *func_define;
	/* see commens in opencl_func_catalog. one of these characters. */
	char		func_kind;
	/* number of processors this function requires per row */
	Expr	   *func_nproc;
	/* size of required working memory, if needed */
	Expr	   *func_memsz;
	/* function result type */
	clTypeInfo *func_rettype;
	/* function arguments type */
	int			func_nargs;
	bool	   *func_argisvec;
	clTypeInfo *func_argtypes[0];
} clFuncInfo;

extern clTypeInfo *pgstrom_cltype_lookup(Oid type_oid, bool is_vector);
extern clFuncInfo *pgstrom_clfunc_lookup(Oid func_oid, int nargs, bool argisvec[]);

static dlist_head	cltype_info_slot[128];
static dlist_head	clfunc_info_slot[1024];

#if 0
/* common opencl runtime header */
typedef struct
{
	uint	vl_len;
	char	vl_dat[1];
} varlena;
#define VARHDRSZ			((int) sizeof(uint))
#define VARDATA(ptr)		((ptr)->vl_dat)
#define VARSIZE(ptr)		((ptr)->vl_len)
#define VARSIZE_EXHDR(ptr)	((ptr)->vl_len - VARHDRSZ)

#define STROMCL_VECTOR_WIDTH				... // set on runtime
#define STROMCL_ERRCODE_SUCCESS				0x00
#define STROMCL_ERRCODE_ROW_DELETED			0x01
#define STROMCL_ERRCODE_DIV_BY_ZERO			0x02
#define STROMCL_ERRCODE_OUT_OF_RANGE		0x03
#define STROMCL_ERRCODE_INTERNAL_ERROR		0xff

#endif

/* ------------------------------------------------------------
 *
 * Catalog of OpenCL Types
 *
 * ------------------------------------------------------------
 */
static void
cltype_cb_vectorizer(clTypeInfo *tinfo, MemoryContext memcxt)
{
	char	namebuf[256];

	if (!cltype_is_vector(tinfo))
		return;

	snprintf(namebuf, sizeof(namebuf),
			 "%s#STROMCL_VECTOR_WIDTH",
			 tinfo->type_ident);
	tinfo->type_ident = MemoryContextStrdup(memcxt, namebuf);
}

static struct {
	/* OID of host type */
	Oid		type_oid;
	/* type identifier on device */
	char   *type_ident;
	/* static type definition on device */
	char   *type_define;
	/* callback on construction of reletive clTypeInfo */
	void  (*type_callback)(clTypeInfo *type_info,
						   MemoryContext memcxt);
	/* true, if type can perform as vector type */
	bool	type_can_vector;
} opencl_type_catalog[] = {
	/* built-in scalar (also, vectorizable) */
	{ BOOLOID,   "uchar",  NULL, cltype_cb_vectorizer, true },
	{ INT2OID,   "short",  NULL, cltype_cb_vectorizer, true },
	{ INT4OID,   "int",    NULL, cltype_cb_vectorizer, true },
	{ INT8OID,   "long",   NULL, cltype_cb_vectorizer, true },
	{ FLOAT4OID, "float",  NULL, cltype_cb_vectorizer, true },
	{ FLOAT8OID, "double", NULL, cltype_cb_vectorizer, true },
	/* varlena types */
	{ TEXTOID,   "varlena", NULL, NULL, false },
	{ BYTEAOID,  "varlena", NULL, NULL, false },
};

clTypeInfo *
pgstrom_cltype_lookup(Oid type_oid, bool is_vector)
{
	dlist_iter	iter;
	clTypeInfo *tinfo;
	int			i, j;

	i = (hash_any((unsigned char *)&type_oid, sizeof(Oid)) +
		 (is_vector ? 1 : 0))
		% lengthof(cltype_info_slot);

	dlist_foreach(iter, &cltype_info_slot[i])
	{
		tinfo = dlist_container(clTypeInfo, chain, iter.cur);
		if (tinfo->type_oid == type_oid &&
			(is_vector ? cltype_is_vector(tinfo) : !cltype_is_vector(tinfo)))
		{
			if (!tinfo->type_ident)
				return NULL;	/* negative cache */
			return tinfo;
		}
	}

	/* not found, so construct a new one */
	tinfo = MemoryContextAllocZero(CacheMemoryContext,
								   sizeof(clTypeInfo));
	tinfo->hash = GetSysCacheHashValue1(TYPEOID, ObjectIdGetDatum(type_oid));
	tinfo->type_oid = type_oid;
	for (j=0; j < lengthof(opencl_type_catalog); j++)
	{
		if (opencl_type_catalog[j].type_oid == type_oid)
		{
			/* is this type vectorizable? */
			if (is_vector && !opencl_type_catalog[j].type_can_vector)
				continue;

			tinfo->type_ident = opencl_type_catalog[j].type_ident;
			tinfo->type_define = opencl_type_catalog[j].type_define;
			if (!is_vector)
				tinfo->type_scalar = NULL;
			else
			{
				tinfo->type_scalar = pgstrom_cltype_lookup(type_oid, false);
				if (!tinfo->type_scalar)
					elog(ERROR, "failed to lookup scalar clTypeInfo of %s",
						 format_type_be(tinfo->type_oid));
			}
			if (opencl_type_catalog[j].type_callback)
				(*opencl_type_catalog[j].type_callback)(tinfo,
														CacheMemoryContext);
			/* cstrings is copied to CacheMemoryContext */
			if (tinfo->type_ident != NULL &&
				tinfo->type_ident == opencl_type_catalog[j].type_ident)
				tinfo->type_ident = MemoryContextStrdup(CacheMemoryContext,
														tinfo->type_ident);
			if (tinfo->type_define != NULL &&
				tinfo->type_define == opencl_type_catalog[j].type_define)
				tinfo->type_define = MemoryContextStrdup(CacheMemoryContext,
														 tinfo->type_define);
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
	int			i;

	for (i=0; i < lengthof(cltype_info_slot); i++)
	{
		dlist_mutable_iter iter;

		dlist_foreach_modify(iter, &cltype_info_slot[i])
		{
			clTypeInfo *tinfo = dlist_container(clTypeInfo, chain, iter.cur);

			if (hashvalue == 0 || tinfo->hash == hashvalue)
			{
				dlist_delete(&tinfo->chain);

				if (tinfo->type_ident)
					pfree(tinfo->type_ident);
				if (tinfo->type_define)
					pfree(tinfo->type_define);
				pfree(tinfo);
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
clfunc_cb_inline_cast(clFuncInfo *finfo, MemoryContext memcxt)
{
	char		namebuf[256];

	Assert(finfo->func_nargs == 1);
	Assert(strncmp(finfo->func_ident, "convert_", 8) != 0);

	snprintf(namebuf, sizeof(namebuf),
			 finfo->func_ident,
			 clfunc_is_vector(finfo) ? "#STROMCL_VECTOR_WIDTH" : "");
	finfo->func_ident = MemoryContextStrdup(memcxt, namebuf);
}

static void
clfunc_cb_oper_fixup(clFuncInfo *finfo, MemoryContext memcxt)
{
	StringInfoData str;
	char	   *opname;
	char	   *func_ident;

	/* two terms operator? */
	Assert(finfo->func_nargs == 2);

	/* either of argument has same type with result type */
	Assert(finfo->func_rettype == finfo->func_argtypes[0] ||
		   finfo->func_rettype == finfo->func_argtypes[1]);

	/* function is scalar, nothing to do */
	if (!clfunc_is_vector(finfo))
	{
		Assert(!cltype_is_vector(finfo->func_argtypes[0]));
		Assert(!cltype_is_vector(finfo->func_argtypes[1]));
		return;
	}

	/*
	 * nothing to do, if all the arguments are same vector type or
	 * either of arguments is scalar.
	 */
	if (finfo->func_argtypes[0] == finfo->func_argtypes[1] ||
		!cltype_is_vector(finfo->func_argtypes[0]) ||
		!cltype_is_vector(finfo->func_argtypes[1]))
		return;

	/*
	 * Elsewhere, it is case to generate a vector result from two
	 * vector arguments but different types.
	 */
	if (strcmp(finfo->func_ident, "+") == 0)
		opname = "add";
	else if (strcmp(finfo->func_ident, "-") == 0)
		opname = "sub";
	else if (strcmp(finfo->func_ident, "*") == 0)
		opname = "mul";
	else if (strcmp(finfo->func_ident, "==") == 0)
		opname = "eq";
	else if (strcmp(finfo->func_ident, "!=") == 0)
		opname = "ne";
	else if (strcmp(finfo->func_ident, ">") == 0)
		opname = "gt";
	else if (strcmp(finfo->func_ident, "<") == 0)
		opname = "lt";
	else if (strcmp(finfo->func_ident, ">=") == 0)
		opname = "ge";
	else if (strcmp(finfo->func_ident, "<=") == 0)
		opname = "le";
	else
		elog(ERROR, "%s does not support \"%s\" operator",
			 __FUNCTION__, finfo->func_ident);

	initStringInfo(&str);
	appendStringInfo(&str, "%s_%s_%s",
					 finfo->func_argtypes[0]->type_ident,
					 opname,
					 finfo->func_argtypes[1]->type_ident);
	func_ident = MemoryContextStrdup(memcxt, str.data);

	resetStringInfo(&str);
	appendStringInfo(&str,
					 "static inline %s\n"
					 "%s(%s x, %s y)\n"
					 "{\n",
					 finfo->func_rettype->type_ident,
					 func_ident,
					 finfo->func_argtypes[0]->type_ident,
					 finfo->func_argtypes[1]->type_ident);
	if (finfo->func_rettype == finfo->func_argtypes[0])
		appendStringInfo(&str, "  return x %s convert_%s(y);\n",
						 finfo->func_ident,
						 finfo->func_rettype->type_ident);
	else
		appendStringInfo(&str, "  return convert_%s(x) %s y;\n",
						 finfo->func_rettype->type_ident,
						 finfo->func_ident);
	appendStringInfo(&str, "}\n");

	finfo->func_ident = func_ident;
	finfo->func_define = MemoryContextStrdup(memcxt, str.data);
}

static void
clfunc_cb_divide_oper(clFuncInfo *finfo, MemoryContext memcxt)
{
	MemoryContext	oldcxt;
	StringInfoData	str;
	clTypeInfo	   *cltype_bool;

	/* add _vec suffix if vector function */
	if (clfunc_is_vector(finfo))
	{
		char	namebuf[256];

		snprintf(namebuf, sizeof(namebuf), "%s_vec", finfo->func_ident);
		finfo->func_ident = MemoryContextStrdup(memcxt, namebuf);
	}

	/* two terms operator? */
	Assert(finfo->func_nargs == 2);

	/* either of argument has same type with result type */
	Assert(finfo->func_rettype == finfo->func_argtypes[0] ||
		   finfo->func_rettype == finfo->func_argtypes[1]);

	cltype_bool = pgstrom_cltype_lookup(BOOLOID, clfunc_is_vector(finfo));
	if (!cltype_bool)
		elog(ERROR, "failed to lookup clTypeInfo of %s",
			 format_type_be(BOOLOID));

	oldcxt = MemoryContextSwitchTo(memcxt);
	initStringInfo(&str);

	appendStringInfo(&str,
					 "static inline %s\n"
					 "%s(uchar *rowmap, %s x, %s y)\n"
					 "{\n"
					 "  %s result;\n"
					 "  %s mask = 0;\n"
					 "\n",
					 finfo->func_rettype->type_ident,
					 finfo->func_ident,
					 finfo->func_argtypes[0]->type_ident,
					 finfo->func_argtypes[1]->type_ident,
					 finfo->func_rettype->type_ident,
					 cltype_bool->type_ident);
	/* division by zero check */
	appendStringInfo(&str,
					 "  mask = convert_%s((y == %s) &\n"
					 "                    STROMCL_ERRCODE_DIV_BY_ZERO);\n",
					 cltype_bool->type_ident,
					 strncmp(finfo->func_ident,
							 "float", 5) == 0 ? "0.0" : "0");
	/* do the division */
	if (finfo->func_argtypes[0] == finfo->func_argtypes[1] ||
		!cltype_is_vector(finfo->func_argtypes[0]) ||
		!cltype_is_vector(finfo->func_argtypes[1]))
		appendStringInfo(&str, "  result = x / y;\n\n");
	else if (finfo->func_rettype == finfo->func_argtypes[0])
		appendStringInfo(&str, "  result = x / convert_%s(y);\n\n",
						 finfo->func_rettype->type_ident);
	else
		appendStringInfo(&str, "  result = convert_%s(x) / y;\n\n",
						 finfo->func_rettype->type_ident);
	/* out of range checks */
	if (strncmp(finfo->func_ident, "float", 5) == 0)
	{
		appendStringInfo(&str,
				"  mask |= (mask == 0) &\n"
				"    (convert_%s((!isinf(x) & !isinf(y) & isinf(result)) |\n"
				"                (x == 0.0 & result == 0.0))\n"
				"     & STROMCL_ERRCODE_OUT_OF_RANGE);\n\n",
						 cltype_bool->type_ident);
	}
	appendStringInfo(&str,
					 "  return result;\n"
					 "}\n");
	MemoryContextSwitchTo(oldcxt);

	finfo->func_define = str.data;
}

static void
clfunc_cb_reminder_oper(clFuncInfo *finfo, MemoryContext memcxt)
{
	MemoryContext	oldcxt;
	StringInfoData	str;
	clTypeInfo	   *cltype_bool;

	if (clfunc_is_vector(finfo))
	{
		char	namebuf[256];

		snprintf(namebuf, sizeof(namebuf), "%s_vec", finfo->func_ident);
		finfo->func_ident = MemoryContextStrdup(memcxt, namebuf);
	}

	cltype_bool = pgstrom_cltype_lookup(BOOLOID, clfunc_is_vector(finfo));
	if (!cltype_bool)
		elog(ERROR, "failed to lookup clTypeInfo of %s",
			 format_type_be(BOOLOID));

	oldcxt = MemoryContextSwitchTo(memcxt);
	initStringInfo(&str);

	appendStringInfo(&str,
					 "static inline %s\n"
					 "%s(uchar *rowmap, %s x, %s y)\n"
					 "{\n"
					 "  %s result;\n"
					 "  %s mask = 0;\n"
					 "\n",
					 finfo->func_rettype->type_ident,
					 finfo->func_ident,
					 finfo->func_argtypes[0]->type_ident,
					 finfo->func_argtypes[1]->type_ident,
					 finfo->func_rettype->type_ident,
					 cltype_bool->type_ident);
	/* division by zero check */
	appendStringInfo(&str,
					 "  mask = (y == 0) &\n"
					 "    convert_%s(STROMCL_ERRCODE_DIV_BY_ZERO);\n\n",
					 cltype_bool->type_ident);
	/* do the modulo job */
	if (finfo->func_argtypes[0] == finfo->func_argtypes[1] ||
		!cltype_is_vector(finfo->func_argtypes[0]) ||
		!cltype_is_vector(finfo->func_argtypes[1]))
		appendStringInfo(&str, "  result = x %% y;\n\n");
	else if (finfo->func_rettype == finfo->func_argtypes[0])
		appendStringInfo(&str, "  result = x %% convert_%s(y);\n\n",
						 finfo->func_rettype->type_ident);
	else
		appendStringInfo(&str, "  result = convert_%s(x) %% y;\n\n",
						 finfo->func_rettype->type_ident);
	appendStringInfo(&str,
					 "  return result;\n"
					 "}\n");
	MemoryContextSwitchTo(oldcxt);
	finfo->func_define = str.data;
}


#define CLFUNC_MAX_ARGS		4	/* tentasively */

static struct {
	/*
	 * signature of SQL function; that allows to identify a particular
	 * pg_proc catalog entry.
	 */
	char   *func_name;
	int		func_nargs;
	Oid		func_argtypes[CLFUNC_MAX_ARGS];

	/*
	 * kind of device function and its identifier to be described as:
	 * <func_kind>:<func_ident>
	 *
	 * <func_kind> is one of the following characters:
	 *  'c', 'l', 'r', 'b', 'f' or 'F'
	 * 
	 * 'c' means SQL function is written as a constant value on device.
	 *
	 * 'l' means SQL function that takes one argument is written as
	 * left-operator, like "-(12.34)" in case when <func_ident> is '-'
	 * and the argument is 12.34. Also, it is used to write inline
	 * type-case, like "(double)(12.34)" if <func_ident> is '(double)'
	 *
	 * 'r' means SQL function with one argument is written as right-
	 * operator on device.
	 *
	 * 'b' means SQL function with two arguments is written as both-
	 * operators on device, being extracted as:
	 *  ( <arg1> <func_ident> <arg2> )
	 *
	 * 'f' and 'F' means SQL function is written as device function
	 * on device. Only different between 'f' and 'F' is, device
	 * function with 'F' takes result rowmap array as first argument
	 * in addition to the arguments in this catalog. Functions with
	 * 'f' is written according to the catalog.
	 */
	char   *func_ident;

	/* true, if this function can handle vector input/output */
	bool	func_can_vector;

	/* static definition of device function */
	char   *func_define;

	/* callback on construction of reletive clTypeInfo */
	void  (*func_callback)(clFuncInfo *func_info, MemoryContext memcxt);

	/* device types that function can run on */
	cl_device_type	func_devs;
} opencl_func_catalog[] = {
	/*
	 * cast of data types
	 */
	{ "int2", 1, {INT4OID},     "f:convert_short%s",   true,
	  NULL, clfunc_cb_inline_cast, CL_DEVICE_TYPE_ALL },
	{ "int2", 1, {INT8OID},     "f:convert_short%s",   true,
	  NULL, clfunc_cb_inline_cast, CL_DEVICE_TYPE_ALL },
	{ "int2", 1, {FLOAT4OID},   "f:convert_short%s",   true,
	  NULL, clfunc_cb_inline_cast, CL_DEVICE_TYPE_ALL },
	{ "int2", 1, {FLOAT8OID},   "f:convert_short%s",   true,
	  NULL, clfunc_cb_inline_cast, CL_DEVICE_TYPE_ALL },
	{ "int4", 1, {INT2OID},     "f:convert_int%s",     true,
	  NULL, clfunc_cb_inline_cast, CL_DEVICE_TYPE_ALL },
	{ "int4", 1, {INT8OID},     "f:convert_int%s",     true,
	  NULL, clfunc_cb_inline_cast, CL_DEVICE_TYPE_ALL },
	{ "int4", 1, {FLOAT4OID},   "f:convert_int%s",     true,
	  NULL, clfunc_cb_inline_cast, CL_DEVICE_TYPE_ALL },
	{ "int4", 1, {FLOAT8OID},   "f:convert_int%s",     true,
	  NULL, clfunc_cb_inline_cast, CL_DEVICE_TYPE_ALL },
	{ "int8", 1, {INT2OID},     "f:convert_long%s",    true,
	  NULL, clfunc_cb_inline_cast, CL_DEVICE_TYPE_ALL },
	{ "int8", 1, {INT4OID},     "f:convert_long%s",    true,
	  NULL, clfunc_cb_inline_cast, CL_DEVICE_TYPE_ALL },
	{ "int8", 1, {FLOAT4OID},   "f:convert_long%s",    true,
	  NULL, clfunc_cb_inline_cast, CL_DEVICE_TYPE_ALL },
	{ "int8", 1, {FLOAT8OID},   "f:convert_long%s",    true,
	  NULL, clfunc_cb_inline_cast, CL_DEVICE_TYPE_ALL },
	{ "float4", 1, {INT2OID},   "f:convert_float%s",   true,
	  NULL, clfunc_cb_inline_cast, CL_DEVICE_TYPE_ALL },
	{ "float4", 1, {INT4OID},   "f:convert_float%s",   true,
	  NULL, clfunc_cb_inline_cast, CL_DEVICE_TYPE_ALL },
	{ "float4", 1, {INT8OID},   "f:convert_float%s",   true,
	  NULL, clfunc_cb_inline_cast, CL_DEVICE_TYPE_ALL },
	{ "float4", 1, {FLOAT8OID}, "f:convert_float%s",   true,
	  NULL, clfunc_cb_inline_cast, CL_DEVICE_TYPE_ALL },
	{ "float8", 1, {INT2OID},   "f:convert_double%s",  true,
	  NULL, clfunc_cb_inline_cast, CL_DEVICE_TYPE_ALL },
	{ "float8", 1, {INT4OID},   "f:convert_double%s",  true,
	  NULL, clfunc_cb_inline_cast, CL_DEVICE_TYPE_ALL },
	{ "float8", 1, {INT8OID},   "f:convert_double%s",  true,
	  NULL, clfunc_cb_inline_cast, CL_DEVICE_TYPE_ALL },
	{ "float8", 1, {FLOAT4OID}, "f:convert_double%s",  true,
	  NULL, clfunc_cb_inline_cast, CL_DEVICE_TYPE_ALL },

	/* '+' : add operators */
	{ "int2pl",  2, {INT2OID, INT2OID}, "b:+", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "int24pl", 2, {INT2OID, INT4OID}, "b:+", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL},
	{ "int28pl", 2, {INT2OID, INT8OID}, "b:+", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL},
	{ "int42pl", 2, {INT4OID, INT2OID}, "b:+", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL},
	{ "int4pl",  2, {INT4OID, INT4OID}, "b:+", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL},
	{ "int48pl", 2, {INT4OID, INT8OID}, "b:+", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL},
	{ "int82pl", 2, {INT8OID, INT2OID}, "b:+", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL},
	{ "int84pl", 2, {INT8OID, INT4OID}, "b:+", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL},
	{ "int8pl",  2, {INT8OID, INT8OID}, "b:+", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL},
	{ "float4pl",  2, {FLOAT4OID, FLOAT4OID}, "b:+", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL},
	{ "float48pl", 2, {FLOAT4OID, FLOAT8OID}, "b:+", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL},
	{ "float84pl", 2, {FLOAT8OID, FLOAT4OID}, "b:+", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL},
	{ "float8pl",  2, {FLOAT8OID, FLOAT8OID}, "b:+", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL},

	/* '-' : substract operators */
	{ "int2mi",  2, {INT2OID, INT2OID}, "b:-", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL},
	{ "int24mi", 2, {INT2OID, INT4OID}, "b:-", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL},
	{ "int28mi", 2, {INT2OID, INT8OID}, "b:-", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL},
	{ "int42mi", 2, {INT4OID, INT2OID}, "b:-", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL},
	{ "int4mi",  2, {INT4OID, INT4OID}, "b:-", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL},
	{ "int48mi", 2, {INT4OID, INT8OID}, "b:-", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL},
	{ "int82mi", 2, {INT8OID, INT2OID}, "b:-", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL},
	{ "int84mi", 2, {INT8OID, INT4OID}, "b:-", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL},
	{ "int8mi",  2, {INT8OID, INT8OID}, "b:-", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL},
	{ "float4mi",  2, {FLOAT4OID, FLOAT4OID}, "b:-", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL},
	{ "float48mi", 2, {FLOAT4OID, FLOAT8OID}, "b:-", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL},
	{ "float84mi", 2, {FLOAT8OID, FLOAT4OID}, "b:-", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL},
	{ "float8mi",  2, {FLOAT8OID, FLOAT8OID}, "b:-", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL},

	/* '*' : multiply operators */
	{ "int2mul",  2, {INT2OID, INT2OID}, "b:*", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL},
	{ "int24mul", 2, {INT2OID, INT4OID}, "b:*", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL},
	{ "int28mul", 2, {INT2OID, INT8OID}, "b:*", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL},
	{ "int42mul", 2, {INT4OID, INT2OID}, "b:*", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL},
	{ "int4mul",  2, {INT4OID, INT4OID}, "b:*", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL},
	{ "int48mul", 2, {INT4OID, INT8OID}, "b:*", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL},
	{ "int82mul", 2, {INT8OID, INT2OID}, "b:*", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL},
	{ "int84mul", 2, {INT8OID, INT4OID}, "b:*", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL},
	{ "int8mul",  2, {INT8OID, INT8OID}, "b:*", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL},
	{ "float4mul",  2, {FLOAT4OID, FLOAT4OID}, "b:*", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL},
	{ "float48mul", 2, {FLOAT4OID, FLOAT8OID}, "b:*", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL},
	{ "float84mul", 2, {FLOAT8OID, FLOAT4OID}, "b:*", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL},
	{ "float8mul",  2, {FLOAT8OID, FLOAT8OID}, "b:*", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL},

	/* '/' : divide operators */
	{ "int2div",  2, {INT2OID, INT2OID}, "F:int2div", true,
	  NULL, clfunc_cb_divide_oper, CL_DEVICE_TYPE_ALL},
	{ "int24div", 2, {INT2OID, INT4OID}, "F:int24div", true,
	  NULL, clfunc_cb_divide_oper, CL_DEVICE_TYPE_ALL},
	{ "int28div", 2, {INT2OID, INT8OID}, "F:int28div", true,
	  NULL, clfunc_cb_divide_oper, CL_DEVICE_TYPE_ALL},
	{ "int42div", 2, {INT4OID, INT2OID}, "F:int42div", true,
	  NULL, clfunc_cb_divide_oper, CL_DEVICE_TYPE_ALL},
	{ "int4div",  2, {INT4OID, INT4OID}, "F:int4div", true,
	  NULL, clfunc_cb_divide_oper, CL_DEVICE_TYPE_ALL},
	{ "int48div", 2, {INT4OID, INT8OID}, "F:int48div", true,
	  NULL, clfunc_cb_divide_oper, CL_DEVICE_TYPE_ALL},
	{ "int82div", 2, {INT8OID, INT2OID}, "F:int82div", true,
	  NULL, clfunc_cb_divide_oper, CL_DEVICE_TYPE_ALL},
	{ "int84div", 2, {INT8OID, INT4OID}, "F:int84div", true,
	  NULL, clfunc_cb_divide_oper, CL_DEVICE_TYPE_ALL},
	{ "int8div",  2, {INT8OID, INT8OID}, "F:int8div", true,
	  NULL, clfunc_cb_divide_oper, CL_DEVICE_TYPE_ALL},
	{ "float4div",  2, {FLOAT4OID, FLOAT4OID}, "F:float4div", true,
	  NULL, clfunc_cb_divide_oper, CL_DEVICE_TYPE_ALL},
	{ "float48div", 2, {FLOAT4OID, FLOAT8OID}, "F:float48div", true,
	  NULL, clfunc_cb_divide_oper, CL_DEVICE_TYPE_ALL},
	{ "float84div", 2, {FLOAT8OID, FLOAT4OID}, "F:float84div", true,
	  NULL, clfunc_cb_divide_oper, CL_DEVICE_TYPE_ALL},
	{ "float8div",  2, {FLOAT8OID, FLOAT8OID}, "F:float8div", true,
	  NULL, clfunc_cb_divide_oper, CL_DEVICE_TYPE_ALL},

	/* '%' : reminder operators */
	{ "int2mod", 2, {INT2OID, INT2OID}, "F:int2mod", true,
	  NULL, clfunc_cb_reminder_oper, CL_DEVICE_TYPE_ALL},
	{ "int4mod", 2, {INT4OID, INT4OID}, "F:int4mod", true,
	  NULL, clfunc_cb_reminder_oper, CL_DEVICE_TYPE_ALL},
	{ "int8mod", 2, {INT8OID, INT8OID}, "F:int8mod", true,
	  NULL, clfunc_cb_reminder_oper, CL_DEVICE_TYPE_ALL},

	/* '+' : unary plus operators */
	{ "int2up", 1, {INT2OID}, "l:+", true,
	  NULL, NULL, CL_DEVICE_TYPE_ALL },
	{ "int4up", 1, {INT4OID}, "l:+", true,
	  NULL, NULL, CL_DEVICE_TYPE_ALL },
	{ "int8up", 1, {INT8OID}, "l:+", true,
	  NULL, NULL, CL_DEVICE_TYPE_ALL },
	{ "float4up", 1, {FLOAT4OID}, "l:+", true,
	  NULL, NULL, CL_DEVICE_TYPE_ALL },
	{ "float8up", 1, {FLOAT8OID}, "l:+", true,
	  NULL, NULL, CL_DEVICE_TYPE_ALL },

	/* '-' : unary minus operators */
	{ "int2um", 1, {INT2OID}, "l:-", true,
	  NULL, NULL, CL_DEVICE_TYPE_ALL },
	{ "int2um", 1, {INT4OID}, "l:-", true,
	  NULL, NULL, CL_DEVICE_TYPE_ALL },
	{ "int2um", 1, {INT8OID}, "l:-", true,
	  NULL, NULL, CL_DEVICE_TYPE_ALL },
	{ "float4um", 1, {FLOAT4OID}, "l:-", true,
	  NULL, NULL, CL_DEVICE_TYPE_ALL },
	{ "float8um", 1, {FLOAT8OID}, "l:-", true,
	  NULL, NULL, CL_DEVICE_TYPE_ALL },

	/* '@' : absolute value operators */
	{ "int2abs",   1, {INT2OID}, "f:abs", true,
	  NULL, NULL, CL_DEVICE_TYPE_ALL},
	{ "int4abs",   1, {INT4OID}, "f:abs", true,
	  NULL, NULL, CL_DEVICE_TYPE_ALL},
	{ "int8abs",   1, {INT8OID}, "f:abs", true,
	  NULL, NULL, CL_DEVICE_TYPE_ALL},
	{ "float4abs", 1, {FLOAT4OID}, "f:fabs", true,
	  NULL, NULL, CL_DEVICE_TYPE_ALL},
	{ "float8abs", 1, {FLOAT8OID}, "f:fabs", true,
	  NULL, NULL, CL_DEVICE_TYPE_ALL},

	/* '=' : equal operators */
	{ "int2eq",  2, {INT2OID, INT2OID}, "b:==", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "int24eq", 2, {INT2OID, INT4OID}, "b:==", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "int28eq", 2, {INT2OID, INT8OID}, "b:==", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "int42eq", 2, {INT4OID, INT2OID}, "b:==", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "int4eq",  2, {INT4OID, INT4OID}, "b:==", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "int48eq", 2, {INT4OID, INT8OID}, "b:==", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "int82eq", 2, {INT8OID, INT2OID}, "b:==", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "int84eq", 2, {INT8OID, INT4OID}, "b:==", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "int8eq",  2, {INT8OID, INT8OID}, "b:==", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "float4eq",  2, {FLOAT4OID, FLOAT4OID}, "b:==", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "float48eq", 2, {FLOAT4OID, FLOAT8OID}, "b:==", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "float84eq", 2, {FLOAT8OID, FLOAT4OID}, "b:==", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "float8eq",  2, {FLOAT8OID, FLOAT8OID}, "b:==", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },

	/* '<>' : not equal operators */
	{ "int2ne",  2, {INT2OID, INT2OID}, "b:!=", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "int24ne", 2, {INT2OID, INT4OID}, "b:!=", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "int28ne", 2, {INT2OID, INT8OID}, "b:!=", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "int42ne", 2, {INT4OID, INT2OID}, "b:!=", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "int4ne",  2, {INT4OID, INT4OID}, "b:!=", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "int48ne", 2, {INT4OID, INT8OID}, "b:!=", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "int82ne", 2, {INT8OID, INT2OID}, "b:!=", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "int84ne", 2, {INT8OID, INT4OID}, "b:!=", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "int8ne",  2, {INT8OID, INT8OID}, "b:!=", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "float4ne",  2, {FLOAT4OID, FLOAT4OID}, "b:!=", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "float48ne", 2, {FLOAT4OID, FLOAT8OID}, "b:!=", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "float84ne", 2, {FLOAT8OID, FLOAT4OID}, "b:!=", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "float8ne",  2, {FLOAT8OID, FLOAT8OID}, "b:!=", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },

	/* '>'  : relational greater-than */
	{ "int2gt",  2, {INT2OID, INT2OID}, "b:>", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "int24gt", 2, {INT2OID, INT4OID}, "b:>", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "int28gt", 2, {INT2OID, INT8OID}, "b:>", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "int42gt", 2, {INT4OID, INT2OID}, "b:>", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "int4gt",  2, {INT4OID, INT4OID}, "b:>", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "int48gt", 2, {INT4OID, INT8OID}, "b:>", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "int82gt", 2, {INT8OID, INT2OID}, "b:>", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "int84gt", 2, {INT8OID, INT4OID}, "b:>", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "int8gt",  2, {INT8OID, INT8OID}, "b:>", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "float4gt",  2, {FLOAT4OID, FLOAT4OID}, "b:>", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "float48gt", 2, {FLOAT4OID, FLOAT8OID}, "b:>", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "float84gt", 2, {FLOAT8OID, FLOAT4OID}, "b:>", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "float8gt",  2, {FLOAT8OID, FLOAT8OID}, "b:>", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },

	/* '<'  : relational less-than */
	{ "int2lt",  2, {INT2OID, INT2OID}, "b:<", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "int24lt", 2, {INT2OID, INT4OID}, "b:<", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "int28lt", 2, {INT2OID, INT8OID}, "b:<", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "int42lt", 2, {INT4OID, INT2OID}, "b:<", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "int4lt",  2, {INT4OID, INT4OID}, "b:<", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "int48lt", 2, {INT4OID, INT8OID}, "b:<", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "int82lt", 2, {INT8OID, INT2OID}, "b:<", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "int84lt", 2, {INT8OID, INT4OID}, "b:<", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "int8lt",  2, {INT8OID, INT8OID}, "b:<", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "float4lt",  2, {FLOAT4OID, FLOAT4OID}, "b:<", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "float48lt", 2, {FLOAT4OID, FLOAT8OID}, "b:<", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "float84lt", 2, {FLOAT8OID, FLOAT4OID}, "b:<", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "float8lt",  2, {FLOAT8OID, FLOAT8OID}, "b:<", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },

	/* '>=' : relational greater-than or equal-to */
	{ "int2ge",  2, {INT2OID, INT2OID}, "b:>=", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "int24ge", 2, {INT2OID, INT4OID}, "b:>=", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "int28ge", 2, {INT2OID, INT8OID}, "b:>=", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "int42ge", 2, {INT4OID, INT2OID}, "b:>=", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "int4ge",  2, {INT4OID, INT4OID}, "b:>=", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "int48ge", 2, {INT4OID, INT8OID}, "b:>=", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "int82ge", 2, {INT8OID, INT2OID}, "b:>=", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "int84ge", 2, {INT8OID, INT4OID}, "b:>=", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "int8ge",  2, {INT8OID, INT8OID}, "b:>=", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "float4ge",  2, {FLOAT4OID, FLOAT4OID}, "b:>=", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "float48ge", 2, {FLOAT4OID, FLOAT8OID}, "b:>=", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "float84ge", 2, {FLOAT8OID, FLOAT4OID}, "b:>=", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "float8ge",  2, {FLOAT8OID, FLOAT8OID}, "b:>=", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },

	/* '<=' : relational less-than or equal to */
	{ "int2le",  2, {INT2OID, INT2OID}, "b:<=", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "int24le", 2, {INT2OID, INT4OID}, "b:<=", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "int28le", 2, {INT2OID, INT8OID}, "b:<=", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "int42le", 2, {INT4OID, INT2OID}, "b:<=", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "int4le",  2, {INT4OID, INT4OID}, "b:<=", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "int48le", 2, {INT4OID, INT8OID}, "b:<=", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "int82le", 2, {INT8OID, INT2OID}, "b:<=", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "int84le", 2, {INT8OID, INT4OID}, "b:<=", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "int8le",  2, {INT8OID, INT8OID}, "b:<=", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "float4le",  2, {FLOAT4OID, FLOAT4OID}, "b:<=", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "float48le", 2, {FLOAT4OID, FLOAT8OID}, "b:<=", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "float84le", 2, {FLOAT8OID, FLOAT4OID}, "b:<=", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },
	{ "float8le",  2, {FLOAT8OID, FLOAT8OID}, "b:<=", true,
	  NULL, clfunc_cb_oper_fixup, CL_DEVICE_TYPE_ALL },

	/* '&'  : bitwise and */
	{ "int2and", 2, {INT2OID, INT2OID}, "b:&", true,
	  NULL, NULL, CL_DEVICE_TYPE_ALL },
	{ "int4and", 2, {INT4OID, INT4OID}, "b:&", true,
	  NULL, NULL, CL_DEVICE_TYPE_ALL },
	{ "int8and", 2, {INT8OID, INT8OID}, "b:&", true,
	  NULL, NULL, CL_DEVICE_TYPE_ALL },

	/* '|'  : bitwise or */
	{ "int2or", 2, {INT2OID, INT2OID}, "b:|", true,
	  NULL, NULL, CL_DEVICE_TYPE_ALL },
	{ "int4or", 2, {INT4OID, INT4OID}, "b:|", true,
	  NULL, NULL, CL_DEVICE_TYPE_ALL },
	{ "int8or", 2, {INT8OID, INT8OID}, "b:|", true,
	  NULL, NULL, CL_DEVICE_TYPE_ALL },

	/* '#'  : bitwise xor */
	{ "int2xor", 2, {INT2OID, INT2OID}, "b:^", true,
	  NULL, NULL, CL_DEVICE_TYPE_ALL },
	{ "int4xor", 2, {INT4OID, INT4OID}, "b:^", true,
	  NULL, NULL, CL_DEVICE_TYPE_ALL },
	{ "int8xor", 2, {INT8OID, INT8OID}, "b:^", true,
	  NULL, NULL, CL_DEVICE_TYPE_ALL },

	/* '~'  : bitwise not operators */
	{ "int2not", 1, {INT2OID}, "b:~", true,
	  NULL, NULL, CL_DEVICE_TYPE_ALL },
	{ "int4not", 1, {INT4OID}, "b:~", true,
	  NULL, NULL, CL_DEVICE_TYPE_ALL },
	{ "int8not", 1, {INT8OID}, "b:~", true,
	  NULL, NULL, CL_DEVICE_TYPE_ALL },

	/* '>>' : right shift */
	{ "int2shr", 2, {INT2OID, INT4OID}, "b:>>", true,
	  NULL, NULL, CL_DEVICE_TYPE_ALL },
	{ "int4shr", 2, {INT4OID, INT4OID}, "b:>>", true,
	  NULL, NULL, CL_DEVICE_TYPE_ALL },
	{ "int8shr", 2, {INT8OID, INT4OID}, "b:>>", true,
	  NULL, NULL, CL_DEVICE_TYPE_ALL },

	/* '<<' : left shift */
	{ "int2shl", 2, {INT2OID, INT4OID}, "b:<<", true,
	  NULL, NULL, CL_DEVICE_TYPE_ALL },
	{ "int4shl", 2, {INT4OID, INT4OID}, "b:<<", true,
	  NULL, NULL, CL_DEVICE_TYPE_ALL },
	{ "int8shl", 2, {INT8OID, INT4OID}, "b:<<", true,
	  NULL, NULL, CL_DEVICE_TYPE_ALL },

	/* Mathmatical functions */
	{ "cbrt", 1, {FLOAT8OID}, "f:cbrt", true,
	  NULL, NULL, CL_DEVICE_TYPE_ALL },
	{ "ceil", 1, {FLOAT8OID}, "f:ceil", true,
	  NULL, NULL, CL_DEVICE_TYPE_ALL },
	{ "exp", 1, {FLOAT8OID}, "f:exp", true,
	  NULL, NULL, CL_DEVICE_TYPE_ALL },
	{ "floor", 1, {FLOAT8OID}, "f:floor", true,
	  NULL, NULL, CL_DEVICE_TYPE_ALL },
	{ "ln", 1, {FLOAT8OID}, "f:log", true,
	  NULL, NULL, CL_DEVICE_TYPE_ALL },
	{ "log", 1, {FLOAT8OID}, "f:log10", true,
	  NULL, NULL, CL_DEVICE_TYPE_ALL },
	{ "pi", 1, {FLOAT8OID}, "c:3.14159265358979323846", false,
	  NULL, NULL, CL_DEVICE_TYPE_ALL },
	{ "power", 2, {FLOAT8OID, FLOAT8OID}, "f:pow", true,
	  NULL, NULL, CL_DEVICE_TYPE_ALL },
	{ "pow", 2, {FLOAT8OID, FLOAT8OID}, "f:pow", true,
	  NULL, NULL, CL_DEVICE_TYPE_ALL },
	{ "dpow", 2, {FLOAT8OID, FLOAT8OID}, "f:pow", true,
	  NULL, NULL, CL_DEVICE_TYPE_ALL },
	{ "round", 1, {FLOAT8OID}, "f:round", true,
	  NULL, NULL, CL_DEVICE_TYPE_ALL },
	{ "sign", 1, {FLOAT8OID}, "f:sign", true,
	  NULL, NULL, CL_DEVICE_TYPE_ALL },
	{ "sqrt", 1, {FLOAT8OID}, "f:sqrt", true,
	  NULL, NULL, CL_DEVICE_TYPE_ALL },
	{ "dsqrt", 1, {FLOAT8OID}, "f:sqrt", true,
	  NULL, NULL, CL_DEVICE_TYPE_ALL },
	{ "trunc", 1, {FLOAT8OID}, "f:trunc", true,
	  NULL, NULL, CL_DEVICE_TYPE_ALL },
	{ "dtrunc", 1, {FLOAT8OID}, "f:trunc", true,
	  NULL, NULL, CL_DEVICE_TYPE_ALL },

	/* Trigonometric function */
	{ "acos", 1, {FLOAT8OID}, "f:acos", true,
	  NULL, NULL, CL_DEVICE_TYPE_ALL },
	{ "asin", 1, {FLOAT8OID}, "f:asin", true,
	  NULL, NULL, CL_DEVICE_TYPE_ALL },
	{ "atan", 1, {FLOAT8OID}, "f:atan", true,
	  NULL, NULL, CL_DEVICE_TYPE_ALL },
	{ "atan2", 2, {FLOAT8OID, FLOAT8OID}, "f:atan2", true,
	  NULL, NULL, CL_DEVICE_TYPE_ALL },
	{ "cos", 1, {FLOAT8OID}, "f:cos", true,
	  NULL, NULL, CL_DEVICE_TYPE_ALL },
	{ "cot", 1, {FLOAT8OID}, "f:cot", true,
	  NULL, NULL, CL_DEVICE_TYPE_ALL },
	{ "sin", 1, {FLOAT8OID}, "f:sin", true,
	  NULL, NULL, CL_DEVICE_TYPE_ALL },
	{ "tan", 1, {FLOAT8OID}, "f:tan", true,
	  NULL, NULL, CL_DEVICE_TYPE_ALL },
};

clFuncInfo *
pgstrom_clfunc_lookup(Oid func_oid, int nargs, bool argisvec[])
{
	dlist_iter		iter;
	clFuncInfo	   *finfo;
	HeapTuple		tuple;
	Form_pg_proc	proc;
	bool			has_vector;
	int				i, j, k;

	i = (hash_any((unsigned char *)&func_oid, sizeof(Oid)) ^
		 hash_any((unsigned char *)argisvec, sizeof(bool) * nargs))
		% lengthof(clfunc_info_slot);

	dlist_foreach(iter, &clfunc_info_slot[i])
	{
		finfo = dlist_container(clFuncInfo, chain, iter.cur);
		if (finfo->func_oid == func_oid &&
			memcmp(finfo->func_argisvec, argisvec,
				   sizeof(bool) * nargs) == 0)
		{
			Assert(finfo->func_nargs == nargs);

			if (!finfo->func_ident)
				return NULL;	/* negative cache */
			return finfo;
		}
	}

	/* Not found, so construct a new one */
	tuple = SearchSysCache1(PROCOID, ObjectIdGetDatum(func_oid));
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for function %u", func_oid);
	proc = (Form_pg_proc) GETSTRUCT(tuple);
	Assert(proc->pronargs == nargs);

	finfo = MemoryContextAllocZero(CacheMemoryContext,
								   sizeof(clFuncInfo) +
								   sizeof(clTypeInfo) * nargs +
								   sizeof(int) * nargs);
	finfo->func_argisvec = (bool *)(finfo->func_argtypes + nargs);

	finfo->hash = GetSysCacheHashValue1(PROCOID, ObjectIdGetDatum(func_oid));
	finfo->func_oid = func_oid;
	finfo->func_nargs = nargs;
	memcpy(finfo->func_argisvec, argisvec, sizeof(bool) * nargs);

	/* do arguments have any vector type? */
	has_vector = false;
	for (k=0; k < nargs; k++)
	{
		if (argisvec[k])
		{
			has_vector = true;
			break;
		}
	}

	for (j=0; j < lengthof(opencl_func_catalog); j++)
	{
		char   *cat_func_name = opencl_func_catalog[j].func_name;
		int		cat_func_nargs = opencl_func_catalog[j].func_nargs;
		Oid    *cat_func_argtypes = opencl_func_catalog[j].func_argtypes;

		if (strcmp(NameStr(proc->proname), cat_func_name) == 0 &&
			proc->pronargs == cat_func_nargs &&
			memcmp(proc->proargtypes.values, cat_func_argtypes,
				   sizeof(Oid) * cat_func_nargs) == 0)
		{
			MemoryContext	oldcxt;

			/* is this function support vector type? */
			if (has_vector && !opencl_func_catalog[j].func_can_vector)
				continue;

			finfo->func_rettype = pgstrom_cltype_lookup(proc->prorettype,
														has_vector);
			if (!finfo->func_rettype)
				elog(ERROR, "failed to lookup clTypeInfo of %s",
					 format_type_be(proc->prorettype));

			for (k=0; k < nargs; k++)
			{
				finfo->func_argtypes[k] =
					pgstrom_cltype_lookup(proc->proargtypes.values[k],
										  argisvec[k]);
				if (!finfo->func_argtypes[k])
					elog(ERROR, "failed to lookup clTypeInfo of %s",
						 format_type_be(proc->prorettype));
			}

			finfo->func_kind = opencl_func_catalog[j].func_ident[0];
			if (strchr("clrbfF", finfo->func_kind) == NULL ||
				opencl_func_catalog[j].func_ident[1] != ':')
				elog(ERROR, "opencl_func_catalog is corrupted for %s",
					 format_procedure(finfo->func_oid));

			finfo->func_ident = opencl_func_catalog[j].func_ident + 2;
			finfo->func_define = opencl_func_catalog[j].func_define;

			/*
			 * XXX - Right now, we assume all the functions in catalog
			 * needs one processor per call, and no special working
			 * memory is not needed.
			 */
			oldcxt = MemoryContextSwitchTo(CacheMemoryContext);
			finfo->func_nproc = (Expr *) makeConst(INT4OID,
												   -1,
												   InvalidOid,
												   sizeof(int32),
												   Int32GetDatum(1),
												   false,
												   true);
			finfo->func_memsz = NULL;
			MemoryContextSwitchTo(oldcxt);

			/* callback to fixup this clFuncInfo */
			if (opencl_func_catalog[j].func_callback)
				(*opencl_func_catalog[j].func_callback)(finfo,
														CacheMemoryContext);

			/* copy strings to the proper memory context */
			if (finfo->func_ident != NULL &&
				finfo->func_ident == opencl_func_catalog[j].func_ident + 2)
				finfo->func_ident = MemoryContextStrdup(CacheMemoryContext,
														finfo->func_ident);
			if (finfo->func_define != NULL &&
				finfo->func_define == opencl_func_catalog[j].func_define)
				finfo->func_define = MemoryContextStrdup(CacheMemoryContext,
														 finfo->func_define);
			break;
		}
	}
	ReleaseSysCache(tuple);

	dlist_push_tail(&clfunc_info_slot[i], &finfo->chain);

	if (!finfo->func_ident)
		return NULL;
	return finfo;
}

static void
pgstrom_funcinfo_invalidate(Datum arg, int cacheid, uint32 hashvalue)
{
	int			i;

	for (i=0; i < lengthof(clfunc_info_slot); i++)
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

void
pgstrom_coder_init(void)
{
	int		i;

	for (i=0; i < lengthof(cltype_info_slot); i++)
		dlist_init(&cltype_info_slot[i]);
	for (i=0; i < lengthof(clfunc_info_slot); i++)
		dlist_init(&clfunc_info_slot[i]);

	CacheRegisterSyscacheCallback(TYPEOID, pgstrom_typeinfo_invalidate, 0);
	CacheRegisterSyscacheCallback(PROCOID, pgstrom_funcinfo_invalidate, 0);
}
