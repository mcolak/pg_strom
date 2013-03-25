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
#include <pthread.h>

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

#define PGSTROM_ALIGN_SIZE		32
#define PGSTROM_CHUNK_SIZE								\
	((MaximumBytesPerTuple(1)							\
	  - MAXALIGN(offsetof(HeapTupleHeaderData, t_bits))	\
	  - sizeof(int64)									\
	  - sizeof(int32)									\
	  - VARHDRSZ) & ~(PGSTROM_ALIGN_SIZE - 1))

#define PGSTROM_NITEMS_PER_TUPLE(attlen,attnotnull)						\
	MAXALIGN_DOWN((MaximumBytesPerTuple(1)								\
				   - MAXALIGN(offsetof(HeapTupleHeaderData, t_bits)		\
							  + ((attnotnull)							\
								 ? BITMAPLEN(Natts_pg_strom_cs) : 0))	\
				   - sizeof(int16)										\
				   - sizeof(int64)										\
				   - sizeof(int32)										\
				   - VARHDRSZ											\
				   - (((attnotnull) ? 0 : VARHDRSZ)						\
					  / ((attnotnull) ? (attlen) : (attlen) + 1)))

static inline void
ItemPointerSetForRowid(HeapTuple tuple, int64 rowid)
{
	Assert((rowid >> 48) == 0);
	ItemPointerSet(&tuple->t_self,
				   (rowid >> 16) & 0xffffffffUL,
				   (rowid & 0x0000ffffUL));
}

static inline int64
ItemPointerGetForRowid(HeapTuple tuple)
{
	ItemPointerData	temp;

	ItemPointerCopy(&tuple->t_self, &temp);

	return (((int64)temp.ip_blkid.bi_hi) << 32 |
			((int64)temp.ip_blkid.bi_lo) << 16 |
			((int64)temp.ip_posid));
}

typedef struct {
	dlist_head		head;
	pthread_mutex_t	lock;
	pthread_cond_t	cond;
	ResourceOwner	owner;
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
	 * char         cb_rowmap[sizeof(bool) * nitems];
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
	dlist_node	chain;
	/* platform information */
	char	   *pf_vendor;
	char	   *pf_name;
	char	   *pf_version;
	/* device information */
	uint32		dev_type;
	char	   *dev_vendor;
	uint32		dev_vendor_id;
	char	   *dev_name;
	char	   *dev_version;
	char	   *dev_driver;
	char	   *dev_opencl_c_version;
	uint32		dev_address_bits;
	uint32		dev_double_fp_config;
	bool		dev_endian_little;
	char	   *dev_extensions;
	uint64		dev_global_mem_cache_size;
	uint32		dev_global_mem_cache_type;
	uint32		dev_global_mem_cacheline_size;
	uint64		dev_global_mem_size;
	bool		dev_host_unified_memory;
	uint64		dev_local_mem_size;
	uint32		dev_local_mem_type;
	uint32		dev_max_clock_frequency;
	uint32		dev_max_compute_units;
	uint32		dev_max_constant_args;
	uint64		dev_max_constant_buffer_size;
	uint64		dev_max_mem_alloc_size;
	size_t		dev_max_parameter_size;
	size_t		dev_max_work_group_size;
	size_t		dev_max_work_item_sizes[3];
	uint32		dev_mem_base_addr_align;
	uint32		dev_min_data_type_align_size;
	uint32		dev_native_vector_width_char;
	uint32		dev_native_vector_width_short;
	uint32		dev_native_vector_width_int;
	uint32		dev_native_vector_width_long;
	uint32		dev_native_vector_width_float;
	uint32		dev_native_vector_width_double;
	uint32		dev_preferred_vector_width_char;
	uint32		dev_preferred_vector_width_short;
	uint32		dev_preferred_vector_width_int;
	uint32		dev_preferred_vector_width_long;
	uint32		dev_preferred_vector_width_float;
	uint32		dev_preferred_vector_width_double;
	size_t		dev_profiling_timer_resolution;
	uint32		dev_queue_properties;
	uint32		dev_single_fp_config;
	char		data[0];
} DeviceProperty;

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
extern void pgstrom_shmem_dump(void);
extern void pgstrom_shmem_range(uintptr_t *start, uintptr_t *end);
extern StromQueue *pgstrom_queue_alloc(bool abort_on_error);
extern void pgstrom_queue_free(StromQueue *queue);
extern void pgstrom_queue_enqueue(StromQueue *queue, dlist_node *chain);
extern dlist_node *pgstrom_queue_dequeue(StromQueue *queue,
										 unsigned int timeout);
extern dlist_node *pgstrom_queue_try_dequeue(StromQueue *queue);
extern bool pgstrom_queue_is_empty(StromQueue *queue);
extern KernelParams *pgstrom_kernel_params_alloc(Size total_length,
												 bool abort_on_error);
extern void pgstrom_kernel_params_free(KernelParams *kernel_params);
extern ChunkBuffer *pgstrom_chunk_buffer_alloc(Size total_length,
											   bool abort_on_error);
extern void pgstrom_chunk_buffer_free(ChunkBuffer *chunk);
extern VarlenaBuffer *pgstrom_varlena_buffer_alloc(Size total_length,
												   bool abort_on_error);
extern void pgstrom_varlena_buffer_free(VarlenaBuffer *vlbuf);
extern void pgstrom_shmem_init(void);

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
extern Datum toast_save_datum(Relation rel, Datum value,
							  struct varlena * oldexternal, int options);
extern void toast_delete_datum(Relation rel, Datum value);
extern void toast_extract_datum(void *dest, struct varlena *value,
								int32 length_be);

/* main.c */
extern bool is_pgstrom_managed_server(const char *serv_name);
extern bool is_pgstrom_managed_relation(Relation relation);
extern Datum pgstrom_fdw_handler(PG_FUNCTION_ARGS);
extern Datum pgstrom_fdw_validator(PG_FUNCTION_ARGS);

#endif	/* PG_STROM_H */
