/*
 * opencl_serv.o
 *
 * Server implementation to manage OpenCL devices and compute given
 * requests.
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
#include "fmgr.h"
#include "miscadmin.h"
#include "postmaster/bgworker.h"
#include "storage/ipc.h"
#include "storage/latch.h"
#include "storage/proc.h"
#include "pg_strom.h"

#define MAX_OPENCL_PLATFORMS	16
#define MAX_OPENCL_DEVICES		64

typedef struct {
	cl_platform_id	platform_id;
	cl_device_id	device_id;
	DeviceProperty	prop;
	DeviceProperty *shmcopy;
} openclDevice;

static bool clserv_running = true;
static const char *opencl_strerror(cl_int errcode);





/*
 * init_opencl_devices
 *
 * It scan all the OpenCL devices installed on the local system, then
 * construct openclDevice object that represents underlying device.
 * Also, it put copy of DeviceProperty on shared memory segment to be
 * referenced by backend planner.
 */
#define CLPF_PARAM(param,field,is_cstring)							\
	{ (param), sizeof(((DeviceProperty *) NULL)->field),			\
			offsetof(DeviceProperty, field), true, (is_cstring) }
#define CLDEV_PARAM(param,field,is_cstring)							\
	{ (param), sizeof(((DeviceProperty *) NULL)->field),			\
			offsetof(DeviceProperty, field), false, (is_cstring) }

static openclDevice *
make_opencl_device_state(cl_platform_id platform_id, cl_device_id device_id)
{
	static struct {
		cl_uint		param;
		size_t		size;
		size_t		offset;
		bool		is_platform;
		bool		is_cstring;
	} catalog[] = {
		CLPF_PARAM(CL_PLATFORM_NAME, pf_name, true),
		CLPF_PARAM(CL_PLATFORM_PROFILE, pf_profile, true),
		CLPF_PARAM(CL_PLATFORM_EXTENSIONS, pf_extensions, true),
		CLPF_PARAM(CL_PLATFORM_VERSION, pf_vendor, true),
		CLPF_PARAM(CL_PLATFORM_VERSION, pf_version, true),
		CLDEV_PARAM(CL_DEVICE_NAME, dev_name, true),
		CLDEV_PARAM(CL_DEVICE_PROFILE, dev_profile, true),
		CLDEV_PARAM(CL_DEVICE_EXTENSIONS, dev_extensions, true),
		CLDEV_PARAM(CL_DEVICE_TYPE, dev_type, false),
		CLDEV_PARAM(CL_DEVICE_VENDOR, dev_vendor, true),
		CLDEV_PARAM(CL_DEVICE_VENDOR_ID, dev_vendor_id, false),
		CLDEV_PARAM(CL_DEVICE_VERSION, dev_version, true),
		CLDEV_PARAM(CL_DRIVER_VERSION, dev_driver, true),
		CLDEV_PARAM(CL_DEVICE_OPENCL_C_VERSION, dev_opencl_c_version, true),
		CLDEV_PARAM(CL_DEVICE_ADDRESS_BITS, dev_address_bits, false),
		CLDEV_PARAM(CL_DEVICE_AVAILABLE, dev_available, false),
		CLDEV_PARAM(CL_DEVICE_COMPILER_AVAILABLE,
					dev_compiler_available, false),
		CLDEV_PARAM(CL_DEVICE_DOUBLE_FP_CONFIG, dev_double_fp_config, false),
		CLDEV_PARAM(CL_DEVICE_ENDIAN_LITTLE, dev_endian_little, false),
		CLDEV_PARAM(CL_DEVICE_GLOBAL_MEM_CACHE_SIZE,
					dev_global_mem_cache_size, false),
		CLDEV_PARAM(CL_DEVICE_GLOBAL_MEM_CACHE_TYPE,
					dev_global_mem_cache_type, false),
		CLDEV_PARAM(CL_DEVICE_GLOBAL_MEM_CACHELINE_SIZE,
					dev_global_mem_cacheline_size, false),
		CLDEV_PARAM(CL_DEVICE_GLOBAL_MEM_SIZE, dev_global_mem_size, false),
		CLDEV_PARAM(CL_DEVICE_HOST_UNIFIED_MEMORY,
					dev_host_unified_memory, false),
		CLDEV_PARAM(CL_DEVICE_LOCAL_MEM_SIZE,
					dev_local_mem_size, false),
		CLDEV_PARAM(CL_DEVICE_LOCAL_MEM_TYPE,
					dev_local_mem_type, false),
		CLDEV_PARAM(CL_DEVICE_MAX_CLOCK_FREQUENCY,
					dev_max_clock_frequency, false),
		CLDEV_PARAM(CL_DEVICE_MAX_COMPUTE_UNITS,
					dev_max_compute_units, false),
		CLDEV_PARAM(CL_DEVICE_MAX_CONSTANT_ARGS,
					dev_max_constant_args, false),
		CLDEV_PARAM(CL_DEVICE_MAX_CONSTANT_BUFFER_SIZE,
					dev_max_constant_buffer_size, false),
		CLDEV_PARAM(CL_DEVICE_MAX_MEM_ALLOC_SIZE,
					dev_max_mem_alloc_size, false),
		CLDEV_PARAM(CL_DEVICE_MAX_PARAMETER_SIZE,
					dev_max_parameter_size, false),
		CLDEV_PARAM(CL_DEVICE_MAX_WORK_GROUP_SIZE,
					dev_max_work_group_size, false),
		CLDEV_PARAM(CL_DEVICE_MAX_WORK_ITEM_DIMENSIONS,
					dev_max_work_item_dimensions, false),
		CLDEV_PARAM(CL_DEVICE_MAX_WORK_ITEM_SIZES,
					dev_max_work_item_sizes, false),
		CLDEV_PARAM(CL_DEVICE_MEM_BASE_ADDR_ALIGN,
					dev_mem_base_addr_align, false),
		CLDEV_PARAM(CL_DEVICE_NATIVE_VECTOR_WIDTH_CHAR,
					dev_native_vector_width_char, false),
		CLDEV_PARAM(CL_DEVICE_NATIVE_VECTOR_WIDTH_SHORT,
					dev_native_vector_width_short, false),
		CLDEV_PARAM(CL_DEVICE_NATIVE_VECTOR_WIDTH_INT,
					dev_native_vector_width_int, false),
		CLDEV_PARAM(CL_DEVICE_NATIVE_VECTOR_WIDTH_LONG,
					dev_native_vector_width_long, false),
		CLDEV_PARAM(CL_DEVICE_NATIVE_VECTOR_WIDTH_FLOAT,
					dev_native_vector_width_float, false),
		CLDEV_PARAM(CL_DEVICE_NATIVE_VECTOR_WIDTH_DOUBLE,
					dev_native_vector_width_double, false),
		CLDEV_PARAM(CL_DEVICE_PREFERRED_VECTOR_WIDTH_CHAR,
					dev_preferred_vector_width_char, false),
		CLDEV_PARAM(CL_DEVICE_PREFERRED_VECTOR_WIDTH_SHORT,
					dev_preferred_vector_width_short, false),
		CLDEV_PARAM(CL_DEVICE_PREFERRED_VECTOR_WIDTH_INT,
					dev_preferred_vector_width_int, false),
		CLDEV_PARAM(CL_DEVICE_PREFERRED_VECTOR_WIDTH_LONG,
					dev_preferred_vector_width_long, false),
		CLDEV_PARAM(CL_DEVICE_PREFERRED_VECTOR_WIDTH_FLOAT,
					dev_preferred_vector_width_float, false),
		CLDEV_PARAM(CL_DEVICE_PREFERRED_VECTOR_WIDTH_DOUBLE,
					dev_preferred_vector_width_double, false),
		CLDEV_PARAM(CL_DEVICE_PROFILING_TIMER_RESOLUTION,
					dev_profiling_timer_resolution, false),
		CLDEV_PARAM(CL_DEVICE_QUEUE_PROPERTIES, dev_queue_properties, false),
		CLDEV_PARAM(CL_DEVICE_SINGLE_FP_CONFIG, dev_single_fp_config, false),
	};
	openclDevice   *cldev;
	cl_int			i, j, rc;
	char			strbuf[2048];

	cldev = malloc(sizeof(openclDevice));
	if (!cldev)
		elog(ERROR, "%s:%d out of memory", __FUNCTION__, __LINE__);
	memset(cldev, 0, sizeof(openclDevice));

	for (i=0; i < lengthof(catalog); i++)
	{
		size_t	value_retsz;
		size_t	value_size;
		void   *value_addr;

		if (!catalog[i].is_cstring)
		{
			value_size = catalog[i].size;
			value_addr = ((char *)&cldev->prop) + catalog[i].offset;
		}
		else
		{
			Assert(catalog[i].size == sizeof(char *));
			value_size = sizeof(strbuf);
			value_addr = strbuf;
		}

		if (catalog[i].is_platform)
		{
			rc = clGetPlatformInfo(platform_id,
								   catalog[i].param,
								   value_size,
								   value_addr,
								   &value_retsz);
			if (rc != CL_SUCCESS)
				elog(ERROR, "failed to get platform info (param=%d, %s)",
					 catalog[i].param, opencl_strerror(rc));
		}
		else
		{
			rc = clGetDeviceInfo(device_id,
								 catalog[i].param,
								 value_size,
								 value_addr,
								 &value_retsz);
			if (rc != CL_SUCCESS)
				elog(ERROR, "failed to get device info (param=%d, %s)",
					 catalog[i].param, opencl_strerror(rc));

			/*
			 * XXX - Device extensions has to be checked earlier than
			 * CL_DEVICE_DOUBLE_FP_CONFIG, because it may cause an error
			 * if clGetDeviceInfo on device without double-fp support. :-(
			 */
			if (catalog[i].param == CL_DEVICE_EXTENSIONS)
			{
				if (!strstr(strbuf, "cl_khr_global_int32_base_atomics") ||
					!strstr(strbuf, "cl_khr_global_int32_extended_atomics") ||
					!strstr(strbuf, "cl_khr_local_int32_base_atomics") ||
					!strstr(strbuf, "cl_khr_local_int32_extended_atomics") ||
					!strstr(strbuf, "cl_khr_byte_addressable_store") ||
					!strstr(strbuf, "cl_khr_fp64"))
				{
					elog(LOG, "\"%s\" does not have minimum capability for OpenCL 1.2 device (extension=%s)",
						 cldev->prop.dev_name, strbuf);
					goto out_clean;
				}
			}
		}
		Assert(value_retsz <= value_size);

		if (catalog[i].is_cstring)
		{
			char  **p_dest = (char **)(((char *)&cldev->prop) +
									   catalog[i].offset);
			/* text triming */
			for (j=value_retsz - 1; j >= 0 && isspace(strbuf[j]); j--)
				strbuf[j] = '\0';
			for (j=0; isspace(strbuf[j]); j++);

			*p_dest = strdup(strbuf + j);
			if (!*p_dest)
				elog(ERROR, "%s:%d out of memory", __FUNCTION__, __LINE__);
		}
	}
	/* It is a local device */
	cldev->prop.is_local = true;

	/*
	 * Check whether the detected device has enough capability we expect.
	 */
	if (strcmp(cldev->prop.pf_profile, "FULL_PROFILE") != 0)
	{
		elog(LOG, "Profile of OpenCL driver \"%s\" is \"%s\", skipped",
			 cldev->prop.pf_name, cldev->prop.pf_profile);
		goto out_clean;
	}
	if (!strstr(cldev->prop.pf_extensions, "cl_khr_icd"))
	{
		elog(LOG, "OpenCL driver \"%s\" does not support \"cl_khr_icd\" extension that allows to use multipla separate vendor's drivers. (extensions: %s)",
			 cldev->prop.pf_name, cldev->prop.pf_extensions);
	}
	if (strcmp(cldev->prop.dev_profile, "FULL_PROFILE") != 0)
	{
		elog(LOG, "Profile of device \"%s\" is \"%s\", skipped",
			 cldev->prop.dev_name, cldev->prop.dev_profile);
		goto out_clean;
	}
	if ((cldev->prop.dev_type & (CL_DEVICE_TYPE_CPU |
								 CL_DEVICE_TYPE_GPU |
								 CL_DEVICE_TYPE_ACCELERATOR)) == 0)
	{
		elog(LOG, "CPU, GPU or Accelerator device are supported, skipped");
		goto out_clean;
	}
	if (!cldev->prop.dev_available)
	{
		elog(LOG, "device \"%s\" is not available, skipped",
			 cldev->prop.dev_name);
		goto out_clean;
	}
	if (!cldev->prop.dev_compiler_available)
	{
		elog(LOG, "OpenCL compiler on device \"%s\" is not available, skipped",
			 cldev->prop.dev_name);
		goto out_clean;
	}
#ifdef WORDS_BIGENDIAN
	if (cldev->prop.dev_endian_little)
	{
		elog(LOG, "device \"%s\" has little endian format, unlike host",
			 cldev->prop.dev_name);
		goto out_clean;
	}
#else
	if (!cldev->prop.dev_endian_little)
	{
		elog(LOG, "device \"%s\" has big endian format, unlike host",
			 cldev->prop.dev_name);
		goto out_clean;
	}
#endif
	if (cldev->prop.dev_max_work_item_dimensions > 3)
	{
		elog(LOG, "max_work_item_dimensions larger than 3 on device \"%s\" is not supported",
			 cldev->prop.dev_name);
		goto out_clean;
	}
	/* put copy on shared memory segment */
	cldev->shmcopy = pgstrom_device_property_alloc(&cldev->prop, true);

	return cldev;

out_clean:
	for (i=0; i < lengthof(catalog); i++)
	{
		if (catalog[i].is_cstring)
		{
			char  **p_string = (char **)(((char *)&cldev->prop) +
										 catalog[i].offset);
			free(*p_string);
		}
	}
	free(cldev);

	return NULL;
}
#undef CLPF_PARAM
#undef CLDEV_PARAM

static void
init_opencl_devices(void)
{
	cl_platform_id	platform_ids[MAX_OPENCL_PLATFORMS];
	cl_device_id	device_ids[MAX_OPENCL_DEVICES];
	cl_uint			n_platforms;
	cl_uint			n_devices;
	cl_uint			n_available = 0;
	cl_int			i, j, rc;
	openclDevice   *cldev;

	rc = clGetPlatformIDs(lengthof(platform_ids),
						  platform_ids, &n_platforms);
	if (rc != CL_SUCCESS)
		elog(ERROR, "failed on clGetPlatformIDs (%s)",
			 opencl_strerror(rc));

	for (i=0; i < n_platforms; i++)
	{
		rc = clGetDeviceIDs(platform_ids[i],
							CL_DEVICE_TYPE_ALL,
							lengthof(device_ids),
							device_ids,
							&n_devices);
		if (rc != CL_SUCCESS)
			elog(ERROR, "failed on clGetDeviceIDs (%s)",
				 opencl_strerror(rc));

		for (j=0; j < n_devices; j++)
		{
			/*
			 * TODO: how to manage openclDevice object?
			 */
			cldev = make_opencl_device_state(platform_ids[i],
											 device_ids[j]);
			if (cldev)
			{
				const char *dev_type;

				if (cldev->prop.dev_type == CL_DEVICE_TYPE_CPU)
					dev_type = "CPU";
				else if (cldev->prop.dev_type == CL_DEVICE_TYPE_GPU)
					dev_type = "GPU";
				else if (cldev->prop.dev_type == CL_DEVICE_TYPE_ACCELERATOR)
					dev_type = "Accelerator";
				else if (cldev->prop.dev_type == CL_DEVICE_TYPE_CUSTOM)
					dev_type = "Custom";
				else
					dev_type = "Unknown";

				elog(LOG,
					 "OpenCL %s device[%u] %s (%u units, %uMHz, %luMB) on %s",
					 dev_type,
					 n_available,
					 cldev->prop.dev_name,
					 cldev->prop.dev_max_compute_units,
					 cldev->prop.dev_max_clock_frequency,
					 cldev->prop.dev_global_mem_size >> 20,
					 cldev->prop.pf_name);
				n_available++;
			}
		}
	}

	if (n_available == 0)
		elog(LOG, "No available OpenCL devices are installed");
}

static void
pgstrom_opencl_sigterm(SIGNAL_ARGS)
{
	int		save_errno = errno;

	clserv_running = false;
	if (MyProc)
		SetLatch(&MyProc->procLatch);

	errno = save_errno;
}

static void
pgstrom_opencl_sighup(SIGNAL_ARGS)
{
	elog(LOG, "OpenCL Server got sighup");
	if (MyProc)
		SetLatch(&MyProc->procLatch);
}

static void
pgstrom_opencl_main(void *arg)
{
	/* We're now ready to receive signals */
	BackgroundWorkerUnblockSignals();

	/* initialize opencl devices */
	init_opencl_devices();

	while (clserv_running)
	{
		int		rc;

		rc = WaitLatch(&MyProc->procLatch,
					   WL_LATCH_SET | WL_TIMEOUT | WL_POSTMASTER_DEATH,
					   600 * 1000);
		ResetLatch(&MyProc->procLatch);

		/* emergency bailout if postmaster has died */
		if (rc & WL_POSTMASTER_DEATH)
			proc_exit(1);
	}
	proc_exit(0);
}

void
pgstrom_opencl_server_init(void)
{
	BackgroundWorker    worker;

	worker.bgw_name = "PG-Strom OpenCL Server";
	worker.bgw_flags = BGWORKER_SHMEM_ACCESS;
	worker.bgw_start_time = BgWorkerStart_RecoveryFinished;
	worker.bgw_restart_time = 5;
	worker.bgw_main = pgstrom_opencl_main;
	worker.bgw_main_arg = NULL;
	worker.bgw_sighup = pgstrom_opencl_sighup;
	worker.bgw_sigterm = pgstrom_opencl_sigterm;

	RegisterBackgroundWorker(&worker);
}

static const char *
opencl_strerror(cl_int errcode)
{
	static char		unknown_buf[256];

    switch (errcode)
    {
		case CL_SUCCESS:
			return "success";
		case CL_DEVICE_NOT_FOUND:
			return "device not found";
		case CL_DEVICE_NOT_AVAILABLE:
			return "device not available";
		case CL_COMPILER_NOT_AVAILABLE:
			return "compiler not available";
		case CL_MEM_OBJECT_ALLOCATION_FAILURE:
			return "memory object allocation failure";
		case CL_OUT_OF_RESOURCES:
			return "out of resources";
		case CL_OUT_OF_HOST_MEMORY:
			return "out of host memory";
		case CL_PROFILING_INFO_NOT_AVAILABLE:
			return "profiling info not available";
		case CL_MEM_COPY_OVERLAP:
			return "memory copy overlap";
		case CL_IMAGE_FORMAT_MISMATCH:
			return "image format mismatch";
		case CL_IMAGE_FORMAT_NOT_SUPPORTED:
			return "image format not supported";
		case CL_BUILD_PROGRAM_FAILURE:
			return "build program failure";
		case CL_MAP_FAILURE:
			return "map failure";
		case CL_MISALIGNED_SUB_BUFFER_OFFSET:
			return "misaligned sub-buffer offset";
		case CL_EXEC_STATUS_ERROR_FOR_EVENTS_IN_WAIT_LIST:
			return "execution status error for event in wait list";
		case CL_INVALID_VALUE:
			return "invalid value";
		case CL_INVALID_DEVICE_TYPE:
			return "invalid device type";
		case CL_INVALID_PLATFORM:
			return "invalid platform";
		case CL_INVALID_DEVICE:
			return "invalid device";
		case CL_INVALID_CONTEXT:
			return "invalid context";
		case CL_INVALID_QUEUE_PROPERTIES:
			return "invalid queue properties";
		case CL_INVALID_COMMAND_QUEUE:
			return "invalid command queue";
		case CL_INVALID_HOST_PTR:
			return "invalid host pointer";
		case CL_INVALID_MEM_OBJECT:
			return "invalid memory object";
		case CL_INVALID_IMAGE_FORMAT_DESCRIPTOR:
			return "invalid image format descriptor";
		case CL_INVALID_IMAGE_SIZE:
			return "invalid image size";
		case CL_INVALID_SAMPLER:
			return "invalid sampler";
		case CL_INVALID_BINARY:
			return "invalid binary";
		case CL_INVALID_BUILD_OPTIONS:
			return "invalid build options";
		case CL_INVALID_PROGRAM:
			return "invalid program";
		case CL_INVALID_PROGRAM_EXECUTABLE:
			return "invalid program executable";
		case CL_INVALID_KERNEL_NAME:
			return "invalid kernel name";
		case CL_INVALID_KERNEL_DEFINITION:
			return "invalid kernel definition";
		case CL_INVALID_KERNEL:
			return "invalid kernel";
		case CL_INVALID_ARG_INDEX:
			return "invalid argument index";
		case CL_INVALID_ARG_VALUE:
			return "invalid argument value";
		case CL_INVALID_ARG_SIZE:
			return "invalid argument size";
		case CL_INVALID_KERNEL_ARGS:
			return "invalid kernel arguments";
		case CL_INVALID_WORK_DIMENSION:
			return "invalid work dimension";
		case CL_INVALID_WORK_GROUP_SIZE:
			return "invalid group size";
		case CL_INVALID_WORK_ITEM_SIZE:
			return "invalid item size";
		case CL_INVALID_GLOBAL_OFFSET:
			return "invalid global offset";
		case CL_INVALID_EVENT_WAIT_LIST:
			return "invalid wait list";
		case CL_INVALID_EVENT:
			return "invalid event";
		case CL_INVALID_OPERATION:
			return "invalid operation";
		case CL_INVALID_GL_OBJECT:
			return "invalid GL object";
		case CL_INVALID_BUFFER_SIZE:
			return "invalid buffer size";
		case CL_INVALID_MIP_LEVEL:
			return "invalid MIP level";
		case CL_INVALID_GLOBAL_WORK_SIZE:
			return "invalid global work size";
		case CL_INVALID_PROPERTY:
			return "invalid property";
	}
	snprintf(unknown_buf, sizeof(unknown_buf),
			 "unknown opencl error (%d)", errcode);
	return unknown_buf;
}
