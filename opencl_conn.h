/*
 * opencl_conn.h
 *
 * Header file relevant to connection for OpenCL calculation server
 *
 * --
 * Copyright 2013 (c) PG-Strom development team
 * Copyright 2011-2012 (c) KaiGai Kohei <kaigai@kaigai.gr.jp>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the 'LICENSE' included within
 * this package.
 */
#ifndef OPENCL_CONN_H
#define OPENCL_CONN_H

#define STROM_CMD_MAGIC				0xDA1CE100
#define STROM_CMD_LOAD_CHUNK		(STROM_CMD_MAGIC | 0x01)
#define STROM_CMD_EXEC_KERNEL		(STROM_CMD_MAGIC | 0x02)
#define STROM_CMD_VARLENA			(STROM_CMD_MAGIC | 0x03)

/*
 * Common Protocol Header
 */
typedef struct {
	uint32		command;
	uint32		request_id;
	uint32		length;
} StromCmdHead;

typedef struct {
	StromCmdHead head;
	uint16		nfields;
	uint16		nvarlena;
	uint64		rowid;
	uint32		nitems;
	uint32		offset_kernel;
	uint32		offset_params;
	uint32		offset_rowmap;
	Datum		data[0];

	/*
	 * Data format of fully-loaded chunk buffer
	 * (in case of no "conn_string" given)
	 * ---- data[0] ----
	 * uint32   cb_isnull[nfields]
	 * uint32   cb_values[nfields]
	 *
	 * Data format of rowid-mapped chunk buffer
	 * (in case of valid "conn_string" given)
	 * ---- data[0] ----
	 * FormData_pg_attribute
	 *          cb_attrs[nfields];
	 * text     conn_string;
	 *
	 * Below has common data structure
	 * ---- data[offset_kernel] ----
	 * uint8    kernel_digest[16]; // MD5 digest
	 * int32    kernel_length
	 * char     kernel_source[]
	 * ---- data[offset_param] ----
	 * uint32	nparams;
	 * bool     param_isnull[nparams];
	 * uint32   param_values[nparams];
	 * char     param_buffer[0];
	 * ---- data[offset_rowmap] ----
	 * bool     cb_rowmap[...]
	 *       :
	 *       :
	 * ---- data[offset_varlena] ----
	 * StromVarlenaBuffer
	 *          cb_varlena[nvarlena]
	 */
} StromCmdChunkBuffer;

static inline bool *
strom_cb_rowmap(StromCmdChunkBuffer *chunk)
{
	return (bool *)(((char *)chunk->sendbuf.data) + chunk->offset_rowmap);
}

static inline bool *
strom_cb_isnull(StromCmdChunkBuffer *chunk, AttrNumber field_num)
{
	uint32 *cb_isnull = (uint32 *)(chunk->sendbuf.data);
	uint32	cb_offset;

	Assert(chunk->sendbuf.head.command == STROM_CMD_EXEC_KERNEL);
	Assert(field_num >= 0 && field_num < chunk->nfields);

	cb_offset = cb_isnull[field_num];
	if (cb_offset == 0)
		return NULL;
	return (bool *)((char *)strom_cb_rowmap(chunk) + cb_offset);
}

static void *
strom_cb_values(StromCmdChunkBuffer *chunk, AttrNumber field_num)
{
	uint32 *cb_values = (uint32 *)((char *)chunk->sendbuf.data +
								   MAXALIGN(sizeof(uint32) * chunk->nfields));
	uint32	cb_offset;

	Assert(chunk->sendbuf.head.command == STROM_CMD_EXEC_KERNEL);
	Assert(field_num >= 0 && field_num < chunk->nfields);

	cb_offset = cb_values[field_num];
	if (cb_offset == 0)
		return NULL;
	return (void *)((char *)strom_cb_rowmap(chunk) + cb_offset);
}

typedef struct {
	StromCmdHead	head;
	uint64			rowid;
	uint32			nitems;
	Datum			data[0];
} StromCmdVarlenaBuffer;



/*
 * StromDeviceInfo
 *
 * 
 *
 */
typedef struct {
	/* platform information */
	char		platform_vendor[64];
	char		platform_name[64];
	char		platform_version[64];
	/* device information */
	uint32		device_type;
	char		device_vendor[64];
	char		device_name[128];
	char		device_version[64];
	char		driver_version[64];
	uint32		address_bits;
	uint32		double_fp_config;
	bool		endian_little;
	uint64		global_mem_cache_size;
	uint32		global_mem_cache_type;
	uint32		global_mem_cacheline_size;
	uint64		global_mem_size;
	uint32		half_fp_config;
	bool		host_unified_memory;
	uint64		local_mem_size;
	uint32		local_mem_type;
	uint32		max_clock_frequency;
	uint32		max_compute_units;
	uint32		max_constant_args;
	uint64		max_constant_buffer_size;
	uint64		max_mem_alloc_size;
	size_t		max_parameter_size;
	size_t		max_work_group_size;
	size_t		max_work_items_sizes[3];
	uint32		vector_width_char;
	uint32		vector_width_short;
	uint32		vector_width_int;
	uint32		vector_width_long;
	uint32		vector_width_float;
	uint32		vector_width_double;
	uint32		vector_width_half;
	char		opencl_c_version[128];
	uint32		queue_properties;
	uint32		single_fp_config;
} StromDeviceItem;

#define OPENCL_EXT_KHR_ICD								(1<<0)

#define OPENCL_EXT_KHR_FP64								(1<<1)
#define OPENCL_EXT_KHR_INT64_BASE_ATOMICS				(1<<2)
#define OPENCL_EXT_KHR_INT64_EXTENDED_ATOMICS			(1<<3)
#define OPENCL_EXT_KHR_FP16								(1<<4)
#define OPENCL_EXT_KHR_GL_SHARING						(1<<5)
#define OPENCL_EXT_KHR_GL_EVENT							(1<<6)
#define OPENCL_EXT_KHR_D3D10_SHARING					(1<<7)

#define OPENCL_EXT_KHR_GLOBAL_INT32_BASE_ATOMICS		(1<<8)
#define OPENCL_EXT_KHR_GLOBAL_INT32_EXTENDED_ATOMICS	(1<<9)
#define OPENCL_EXT_KHR_LOCAL_INT32_BASE_ATOMICS			(1<<10)
#define OPENCL_EXT_KHR_LOCAL_INT32_EXTENDED_ATOMICS		(1<<11)
#define OPENCL_EXT_KHR_BYTE_ADDRESSABLE_STORE			(1<<12)

typedef struct {
	StromCmdHead	head;
	uint32			num_devices;
	StromDeviceItem	items[0];
} StromDeviceInfo;










#endif
