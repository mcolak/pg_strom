/*
 * pg_strom.h
 *
 * Header file of pg_strom module
 *
 * --
 * Copyright 2013 (c) PG-Strom development team
 * Copyright 2011-2012 (c) KaiGai Kohei <kaigai@kaigai.gr.jp>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the 'LICENSE' included within
 * this package.
 */
#ifndef PG_STROM_H
#define PG_STROM_H
#include "access/tuptoaster.h"
#include "lib/ilist.h"
#include "foreign/fdwapi.h"
#include "utils/resowner.h"
#include <limits.h>
#include <pthread.h>
#include <CL/cl.h>
#include <CL/cl_ext.h>

/* debug messages */
#ifdef PGSTROM_PRINT_DEBUG
extern bool pgstrom_print_debug;
#define dlog(fmt, ...)									\
	do {												\
		if (pgstrom_print_debug)						\
			elog(INFO, "%s:%d" fmt,						\
				 __FUNCTION__, __LINE__, __VAR_ARGS__); \
	} while(0)
#else
#define dlog(fmt, ...)
#endif

/* container macro */
#define container_of(type, field, ptr)			\
	((type *)((char *)(ptr) - offsetof(type, field)))

/* definition of shadow tables */
#define PGSTROM_SCHEMA_NAME			"pg_strom"
#define Natts_pg_strom_rmap			3
#define Anum_pg_strom_rmap_rowid	1
#define Anum_pg_strom_rmap_nitems	2
#define Anum_pg_strom_rmap_rowmap	3

#define Natts_pg_strom_cs			5
#define Anum_pg_strom_cs_attnum		1
#define Anum_pg_strom_cs_rowid		2
#define Anum_pg_strom_cs_nitems		3
#define Anum_pg_strom_cs_isnull		4
#define Anum_pg_strom_cs_values		5

/* index of shadow rmap(rowid) */
#define Inum_pg_strom_rmap_rowid	1
/* index of shadow column-store(attnum,rowid) */
#define Inum_pg_strom_cs_attnum		1
#define Inum_pg_strom_cs_rowid		2
/* index of shadow row-store(oid) */
#define Inum_pg_strom_rs_oid		1

#define PGSTROM_ALIGN_SIZE		32
#define PGSTROM_CHUNK_SIZE								\
	((MaximumBytesPerTuple(1)							\
	  - MAXALIGN(offsetof(HeapTupleHeaderData, t_bits))	\
	  - sizeof(int64)									\
	  - sizeof(int32)									\
	  - VARHDRSZ) & ~(PGSTROM_ALIGN_SIZE - 1))

/* data length that can be used to save isnull/values */
#define PGSTROM_CSTORE_DATASZ										\
	MAXALIGN_DOWN(MaximumBytesPerTuple(1)							\
				  - MAXALIGN(offsetof(HeapTupleHeaderData, t_bits))	\
				  - sizeof(int16)									\
				  - sizeof(int64)									\
				  - sizeof(int32)									\
				  - VARHDRSZ										\
				  - VARHDRSZ)

#define PGSTROM_ROWID_MIN	\
	(PGSTROM_CHUNK_SIZE * ((0x100000000ULL / PGSTROM_CHUNK_SIZE) + 1))
#define PGSTROM_ROWID_MAX	\
	(PGSTROM_CHUNK_SIZE * (0x1000000000000ULL / PGSTROM_CHUNK_SIZE))

static inline void
ItemPointerSetForRowid(HeapTuple tuple, int64 rowid)
{
	Assert((rowid >> 48) == 0);
	ItemPointerSet(&tuple->t_self,
				   (rowid >> 16) & 0xffffffffUL,
				   (rowid & 0x0000ffffUL));
}

typedef struct {
	dlist_head		head;
	pthread_mutex_t	lock;
	pthread_cond_t	cond;
	bool			is_shutdown;
} StromQueue;

typedef struct {
	bytea		   *params;
	uint32			kernel_flags;
	uint8			kernel_digest[16];	/* MD5 */
	text			kernel_source;
	/*
	 * uint32       va_header of kernel_source
	 * char         va_data[...] of kernel_source
	 *   :
	 * uint32       va_header of params
	 * uint32		params_num; 
	 * bool			params_isnull[params_num];
	 * Datum		params_values[params_num];
	 * char         data[...]
	 */
} KernelParams;

typedef struct {
	dlist_node		chain;
	pthread_mutex_t	lock;
	pthread_cond_t	cond;
	StromQueue	   *recvq;

	KernelParams   *kernel_params;
	dlist_head		vlbuf_list;

	Oid				cb_databaseid;
	bool		   *cb_rowmap;
	bool		  **cb_isnull;
	void		  **cb_values;
	FormData_pg_attribute *cb_attrs;
	uint32		   *offset_isnull;
	uint32		   *offset_values;
	int				error_code;

	HeapTuple	   *rs_cache;	/* !!private!! array for cache of row-store */
	MemoryContext	rs_memcxt;	/* !!private!! memory for cache of row-store */
	ItemPointerData	cs_ctid;	/* !!private!! ctid copy of this rowmap */

	/*
	 * Below fields may be transfered to another host
	 */
	bool			is_loaded;	/* true, if this chunk is fully loaded */
	bool			is_running;	/* true, if this chunk is running */
	uint16			nargs;		/* number of arguments field */
	uint16			nresults;	/* number of results field */
	uint16			nvarlena;	/* number of varlena buffers */
	uint64			rowid;		/* head of rowid in this chunk */
	uint32			nitems;		/* number of items in this chunk */
	uint32			offset_results;
	uint32			length_results;
	uint32			offset_args;
	uint32			length_args;
	Datum			data[1024];	/* minimum 1KB for error messages */
	/*
	 * ---- data[0] ----
	 * bool        *cb_isnull[nattrs]
	 * void        *cb_values[nattrs]
	 * FormData_pg_attribute cb_attrs[nargs + nresults];
	 * uint32       offset_isnull[nargs + nresults];
	 * uint32       offset_values[nargs + nresults];
	 *   :
	 * <variable buffer for calculation results>
	 *   :
	 * bool         cb_rowmap[sizeof(bool) * nitems];
	 *   :
	 * <variable buffer for calculation arguments>
	 *   :
	 *
	 * Note: offset_isnull/_values for result-columns are represented
	 * as relative offset from the offset_results. Also, ones for
	 * argument-columns are represented as relative offset from the
	 * offset_args.
	 */
} ChunkBuffer;

typedef struct {
	dlist_node			chain;
	uint32				length;
	uint32				usage;
	uint64				rowid;
	uint32				nitems;
	char				data[0];
} VarlenaBuffer;

typedef struct {
	dlist_node		chain;
	bool			is_local;
	/* platform information */
	char		   *pf_profile;
	char		   *pf_vendor;
	char		   *pf_name;
	char		   *pf_version;
	char		   *pf_extensions;
	/* device information */
	cl_device_type	dev_type;
	char		   *dev_profile;
	char		   *dev_vendor;
	cl_uint			dev_vendor_id;
	char		   *dev_name;
	char		   *dev_version;
	char		   *dev_driver;
	char		   *dev_opencl_c_version;
	char		   *dev_extensions;
	cl_uint			dev_address_bits;
	cl_bool			dev_available;
	cl_bool			dev_compiler_available;
	cl_device_fp_config dev_double_fp_config;
	cl_bool			dev_endian_little;
	cl_ulong		dev_global_mem_cache_size;
	cl_device_mem_cache_type dev_global_mem_cache_type;
	cl_uint			dev_global_mem_cacheline_size;
	cl_ulong		dev_global_mem_size;
	cl_bool			dev_host_unified_memory;
	cl_ulong		dev_local_mem_size;
	cl_device_local_mem_type dev_local_mem_type;
	cl_uint			dev_max_clock_frequency;
	cl_uint			dev_max_compute_units;
	cl_uint			dev_max_constant_args;
	cl_ulong		dev_max_constant_buffer_size;
	cl_ulong		dev_max_mem_alloc_size;
	size_t			dev_max_parameter_size;
	size_t			dev_max_work_group_size;
	cl_uint			dev_max_work_item_dimensions;
	size_t			dev_max_work_item_sizes[3];
	cl_uint			dev_mem_base_addr_align;
	cl_uint			dev_native_vector_width_char;
	cl_uint			dev_native_vector_width_short;
	cl_uint			dev_native_vector_width_int;
	cl_uint			dev_native_vector_width_long;
	cl_uint			dev_native_vector_width_float;
	cl_uint			dev_native_vector_width_double;
	cl_uint			dev_preferred_vector_width_char;
	cl_uint			dev_preferred_vector_width_short;
	cl_uint			dev_preferred_vector_width_int;
	cl_uint			dev_preferred_vector_width_long;
	cl_uint			dev_preferred_vector_width_float;
	cl_uint			dev_preferred_vector_width_double;
	size_t			dev_profiling_timer_resolution;
	cl_command_queue_properties dev_queue_properties;
	cl_device_fp_config dev_single_fp_config;
	char			data[0];
} DeviceProperty;

/*
 * clTypeInfo - cache for properties of OpenCL data-type
 */
typedef struct clTypeInfo {
	dlist_node	chain;
	uint32		hash;
	/* oid of SQL type */
	Oid			type_oid;
	/* name of SQL type */
	char	   *type_name;
	/* name of opencl type */
	char	   *type_ident;
	/* definition of opencl type */
	char	   *type_define;
	/* function name to convert this type */
	char	   *type_conv;
	/* misc properties of this type */
	int16		type_length;
	bool		type_is_native;
	bool		type_is_varlena;
} clTypeInfo;

/*
 * clFuncInfo - cache for properties of OpenCL functions
 */
typedef struct {
	dlist_node	chain;
	uint32		hash;
	/* namespace of SQL function, or InvalidOid if device only */
	Oid			func_namespace;
	/* name of SQL function */
	char	   *func_name;
	/* name of opencl function */
	char	   *func_ident;
	/* definition of opencl function */
	char	   *func_define;
	/* number of processors this function requires per row */
	Expr	   *func_nprocs;
	/* size of required working memory, if needed */
	Expr	   *func_memsz;
	/* function result type */
	clTypeInfo *func_rettype;
	/* function arguments type */
	int			func_nargs;
	Oid		   *func_argtypes_oid;
	clTypeInfo *func_argtypes[0];
} clFuncInfo;

/* opencl_serv.c */
extern void pgstrom_opencl_server_init(void);

/* opencl_entry.c */
extern void pgstrom_opencl_entry_init(void);

/* plan.c */
extern void pgstrom_fdw_plan_init(FdwRoutine *fdw_routine);

/* scan.c */
extern void pgstrom_fdw_scan_init(FdwRoutine *fdw_routine);

/* modify.c */
extern void pgstrom_fdw_modify_init(FdwRoutine *fdw_routine);

/* shmem.c */
extern bool pgstrom_mutex_init(pthread_mutex_t *mutex);
extern bool pgstrom_rwlock_init(pthread_rwlock_t *rwlock);
extern bool pgstrom_cond_init(pthread_cond_t *cond, pthread_mutex_t *mutex);
extern bool pgstrom_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex,
							  unsigned int timeout);
extern StromQueue *pgstrom_queue_alloc(bool abort_on_error);
extern void pgstrom_queue_free(StromQueue *queue);
extern bool pgstrom_queue_enqueue(StromQueue *queue, dlist_node *chain);
extern dlist_node *pgstrom_queue_dequeue(StromQueue *queue,
										 unsigned int timeout);
extern dlist_node *pgstrom_queue_try_dequeue(StromQueue *queue);
extern bool pgstrom_queue_is_empty(StromQueue *queue);
extern void pgstrom_queue_shutdown(StromQueue *queue);
extern KernelParams *pgstrom_kernel_params_alloc(Size total_length,
												 bool abort_on_error);
extern void pgstrom_kernel_params_free(KernelParams *kernel_params);
extern ChunkBuffer *pgstrom_chunk_buffer_alloc(Size total_length,
											   bool abort_on_error);
extern void pgstrom_chunk_buffer_free(ChunkBuffer *chunk);
extern VarlenaBuffer *pgstrom_varlena_buffer_alloc(Size total_length,
												   bool abort_on_error);
extern void pgstrom_varlena_buffer_free(VarlenaBuffer *vlbuf);
extern DeviceProperty *pgstrom_device_property_alloc(DeviceProperty *templ,
													 bool abort_on_error);
extern void pgstrom_device_property_free(DeviceProperty *devprop);
extern void pgstrom_device_property_lock(bool write_lock);
extern void pgstrom_device_property_unlock(void);
extern DeviceProperty *pgstrom_device_property_next(DeviceProperty *devprop);
extern Datum pgstrom_opencl_devices(PG_FUNCTION_ARGS);

extern void pgstrom_shmem_init(void);
extern void pgstrom_shmem_range(uintptr_t *start, uintptr_t *end);
extern Datum pgstrom_shmem_dump(PG_FUNCTION_ARGS);

/* codegen.c */
extern clTypeInfo *pgstrom_cltype_lookup(Oid type_oid);
extern clFuncInfo *pgstrom_clfunc_lookup(Oid func_oid);
extern text *pgstrom_codegen_qual(PlannerInfo *root,
								  RelOptInfo *baserel,
								  Node *kernel_expr,
								  List **kernel_params,	/* out */
								  List **kernel_cols);	/* out */
extern void pgstrom_codegen_init(void);

/* utilcmds.c */
extern Relation pgstrom_open_shadow_rmap(Relation frel, LOCKMODE lockmode);
extern Relation pgstrom_open_shadow_cstore(Relation frel, LOCKMODE lockmode);
extern Relation pgstrom_open_shadow_rstore(Relation frel, LOCKMODE lockmode);
extern Relation pgstrom_open_shadow_rmap_index(Relation frel,
											   LOCKMODE lockmode);
extern Relation pgstrom_open_shadow_cstore_index(Relation frel,
												 LOCKMODE lockmode);
extern Relation pgstrom_open_shadow_rstore_index(Relation frel,
												 LOCKMODE lockmode);
extern bool pgstrom_check_relation_compatible(Relation rel1, Relation rel2);
extern void pgstrom_utilcmds_init(void);

/* toast.c */
extern bytea *toast_save_bytea(Relation rel, bytea *value,
							   struct varlena * oldexternal, int options);
extern void toast_delete_bytea(Relation rel, bytea *value);
extern void toast_extract_datum(void *dest, struct varlena *value,
								int32 length_be);
/* vacuum.c */
extern Datum pgstrom_vacuum(PG_FUNCTION_ARGS);
extern void pgstrom_vacuum_init(void);

/* main.c */
extern bool is_pgstrom_managed_server(const char *serv_name);
extern bool is_pgstrom_managed_relation(Relation relation);
extern Datum pgstrom_fdw_handler(PG_FUNCTION_ARGS);
extern Datum pgstrom_fdw_validator(PG_FUNCTION_ARGS);

#endif	/* PG_STROM_H */
