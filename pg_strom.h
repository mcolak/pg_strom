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
#include "opencl_common.h"

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

/*
 * NOTE: we assume *every* chunk has aligned number of items, even if
 * nitems is less than PGSTROM_UNITSZ, to ensure vectore load / store
 * operation is safe to access.
 * 
 * things to be considers:
 * - Nvidia has idea of warp that runs 32 of concurrent thread in parallel,
 *   thus multiple numbers of 32 is reasonable choice.
 * - Intel Xeon Phi has 512bit SIMD ALU that can run 16 of concurrent single
 *   floating-point operations, thus nitems must be multiple numbers of 16
 *   to ensure vload / vstore working safety.
 */
#define PGSTROM_UNITSZ			32

#define PGSTROM_CHUNK_SIZE								\
	((MaximumBytesPerTuple(1)							\
	  - MAXALIGN(offsetof(HeapTupleHeaderData, t_bits))	\
	  - sizeof(int64)									\
	  - sizeof(int32)									\
	  - VARHDRSZ) & ~(PGSTROM_UNITSZ - 1))

/* data length that can be used to save isnull/values */
#define PGSTROM_CSTORE_DATASZ										\
	MAXALIGN_DOWN(MaximumBytesPerTuple(1)							\
				  - MAXALIGN(offsetof(HeapTupleHeaderData, t_bits))	\
				  - sizeof(int16)									\
				  - sizeof(int64)									\
				  - sizeof(int32)									\
				  - VARHDRSZ										\
				  - VARHDRSZ)
/*
 * Unlike TYPEALIGN[_DOWN], it is safe for ALIGN being not a power of 2
 */
#define PGSTROM_ALIGN(ALIGN,LEN)			\
	((((intptr_t)(LEN) + (ALIGN) - 1) / (ALIGN)) * (ALIGN))

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

#define MD5_SIZE	16	/* 128bits */
typedef struct {
	kern_params_t  *kparams;
	uint32			kparams_size;
	cl_device_type	kernel_devtype;		/* OR-mask of CL_DEVICE_TYPE_* */
	cl_device_info	vector_preference;	/* CL_DEVICE_PREFERRED_VECTOR_* */
	char			kernel_md5[MD5_SIZE];
	text			kernel_source;
} KernelParams;

typedef struct {
	dlist_node		chain;
	StromQueue	   *recvq;

	KernelParams   *kernel_params;
	dlist_head		vlbuf_list;

	Oid				cb_databaseid;
	int				cb_nattrs;
	bool		   *cb_rowmap;
	bool		  **cb_isnull;
	void		  **cb_values;
	FormData_pg_attribute *cb_attrs;
	kern_args_t	   *cb_kargs;
	int				error_code;	/* execute status */
	uint32			cb_length;

	HeapTuple	   *rs_cache;	/* !!private!! array for cache of row-store */
	MemoryContext	rs_memcxt;	/* !!private!! memory for cache of row-store */
	ItemPointerData	cs_ctid;	/* !!private!! ctid copy of this rowmap */

	/*
	 * Below fields may be transfered to another host
	 */
	bool			is_loaded;	/* true, if this chunk is fully loaded */
	bool			is_running;	/* true, if this chunk is running */
	uint16			nvarlena;	/* number of varlena buffers */
	uint32			varlena_sz;	/* size of largest varlena buffer */
	uint64			rowid;		/* head rowid of this chunk */
	uint32			nitems;		/* number of items in this chunk */
	uint32			dma_send_start;	/* head of the region to send */
	uint32			dma_send_end;	/* end of the region to send */
	uint32			dma_recv_start;	/* head of the region to receive */
	uint32			dma_recv_end;	/* end of the region to receive */
	char			data[4096];	/* minimum 4KB for error messages */
	/*
	 * ---- data[0] ----
	 * bool        *cb_isnull[nattrs]
	 * void        *cb_values[nattrs]
	 * FormData_pg_attribute cb_attrs[nargs];
	 * kern_args_t  kparams;
	 *   :
	 * <variable buffer for calculation output>
	 *   :
	 * bool         cb_rowmap[sizeof(bool) * nitems];
	 *   :
	 * <variable buffer for calculation input>
	 *   :
	 */
} ChunkBuffer;

typedef struct {
	dlist_node		chain;
	size_t			vlbuf_size;
	kern_vlbuf_t   *kvlbuf;
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
	/* set of CL_DEVICE_TYPE_* */
	cl_device_type func_devtype;
	/* hint to decide vector width */
	int			func_usecnt_char;
	int			func_usecnt_short;
	int			func_usecnt_int;
	int			func_usecnt_long;
	int			func_usecnt_float;
	int			func_usecnt_double;
	/* function result type */
	clTypeInfo *func_rettype;
	/* function arguments type */
	int			func_nargs;
	Oid		   *func_argtypes_oid;
	clTypeInfo *func_argtypes[0];
} clFuncInfo;

/* opencl_common.c */
extern const char *pgstrom_common_clhead;

/* opencl_serv.c */
extern void clserv_enqueue_chunk(ChunkBuffer *chunk);
extern void pgstrom_opencl_server_startup(uintptr_t shmem_start,
										  uintptr_t shmem_end);
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
extern void pgstrom_queue_wakeup(StromQueue *queue, bool is_broadcast);
extern bool pgstrom_queue_is_empty(StromQueue *queue);
extern void pgstrom_queue_shutdown(StromQueue *queue);
extern KernelParams *pgstrom_kernel_params_alloc(Size total_length,
												 bool abort_on_error);
extern void pgstrom_kernel_params_free(KernelParams *kernel_params);
extern ChunkBuffer *pgstrom_chunk_buffer_alloc(Size total_length,
											   bool abort_on_error);
extern void pgstrom_chunk_buffer_free(ChunkBuffer *chunk);
extern void pgstrom_chunk_buffer_return(ChunkBuffer *chunk, int error_code);
extern VarlenaBuffer *pgstrom_varlena_buffer_alloc(Size total_length,
												   Size kernel_align,
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
extern Datum pgstrom_shmem_dump(PG_FUNCTION_ARGS);

/* codegen.c */
extern clTypeInfo *pgstrom_cltype_lookup(Oid type_oid);
extern clFuncInfo *pgstrom_clfunc_lookup(Oid func_oid);
extern text *pgstrom_codegen_qual(PlannerInfo *root,
								  RelOptInfo *baserel,
								  Node *kernel_expr,
								  List **kernel_params,	/* out */
								  List **kernel_cols,   /* out */
								  cl_device_type *p_allowed_devtype, /* out */
								  char **p_applied_vector); /* out */
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
