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
#include "utils/guc.h"
#include "pg_strom.h"
#include <time.h>

/* debug messages */
#define dlog(fmt,...)											\
	do {														\
		if (enable_pgstrom_debug)								\
		{														\
			struct timeval tv;									\
			struct tm t;										\
																\
			gettimeofday(&tv, NULL);							\
			localtime_r(&tv.tv_sec, &t);						\
			fprintf(stderr, "%04d-%02d-%02d %02d:%02d:%02d "	\
					"clserv[worker:%03lu, %s:%d] : " fmt "\n",	\
					t.tm_year, t.tm_mon+1, t.tm_mday,			\
					t.tm_hour, t.tm_mon, t.tm_sec,				\
					clserv_worker_index, __FUNCTION__, __LINE__,\
					##__VA_ARGS__);								\
		}														\
	} while(0)

#define MAX_OPENCL_PLATFORMS	16
#define MAX_OPENCL_DEVICES		64
#define CLPROGRAM_SLOT_SIZE		1024

/*
 * openclContext
 *
 * structure for an opencl context that contains one or more devices
 * that have identical features from perspective of code build.
 */
typedef struct {
	cl_platform_id	platform_id;
	cl_context		context;
	cl_mem			host_shmem;
	dlist_head		dev_list;
	/* common parameters */
	cl_device_type	dev_type;
	cl_uint			vec_width_char;
	cl_uint			vec_width_short;
	cl_uint			vec_width_int;
	cl_uint			vec_width_long;
	cl_uint			vec_width_float;
	cl_uint			vec_width_double;
} openclContext;

/*
 * openclDevice
 *
 * structure for a particular device and relevant command queue
 */
typedef struct {
	dlist_node		chain;	/* link to openclContext::dev_list */
	openclContext  *clcxt;	/* reference to openclContext */
	cl_device_id	device_id;
	cl_command_queue cmdq;
	DeviceProperty	prop;
	DeviceProperty *shmcopy;
} openclDevice;


/*
 * openclProgram
 *
 * structure for a particular kernel program 
 */
typedef struct {
	dlist_node		chain;
	openclContext  *clcxt;
	cl_program		program;
	cl_int			vector_width;
	dlist_head		waitq;
	char			kernel_md5[MD5_SIZE];
} openclProgram;

/*
 * openclKernel
 *
 * structure for a particular kernel execution
 */
typedef struct {
	ChunkBuffer	   *chunk;
	openclDevice   *cldev;
	openclProgram  *clprog;
	cl_int			n_kernels;
	cl_kernel	   *kernels;
	cl_int			n_events;
	cl_event	   *events;
	cl_mem			arg_kparams;
	cl_mem			arg_kargs;
	cl_mem		   *arg_vlbufs;
	cl_mem			arg_wkmem;
	Datum			data[0];
} openclKernel;

/*
 * static declarations
 */
static bool 		clserv_running = true;
static __thread uintptr_t clserv_worker_index;
static int			clserv_num_workers;
static char		   *clserv_opencl_devices;
static openclDevice	*cldev_slot[MAX_OPENCL_DEVICES];
static int			cldev_nums;
static pthread_mutex_t clprog_lock[CLPROGRAM_SLOT_SIZE];
static dlist_head	clprog_slot[CLPROGRAM_SLOT_SIZE];
static StromQueue  *clserv_queue;
static uintptr_t	shmem_start;
static uintptr_t	shmem_end;
static const char  *opencl_strerror(cl_int errcode);

#define chunk_elog(chunk,fmt,...)				\
	snprintf((chunk)->data, sizeof((chunk)->data), "%s:%d " fmt, \
			 __FUNCTION__, __LINE__, ##__VA_ARGS__)

#define chunk_backq(chunk, error_code, fmt, ...)				\
	do {														\
		dlog("chunk(%p) " fmt, (chunk), ##__VA_ARGS__);			\
		if ((error_code) != ERRCODE_SUCCESSFUL_COMPLETION)		\
			chunk_elog(chunk, fmt, ##__VA_ARGS__);				\
		pgstrom_chunk_buffer_return((chunk), (error_code));		\
	} while(0)

#define AssertOnShmem(addr)					   \
	Assert((uintptr_t)(addr) >= shmem_start && \
		   (uintptr_t)(addr) <= shmem_end)

/*
 * clserv_device_scheduler
 *
 * It chooses an opencl device to run the supplied chunk-buffer.
 * Right now, it implements simple round-roubin scheduling.
 */
static openclDevice *
clserv_device_scheduler(ChunkBuffer *chunk)
{
	static volatile sig_atomic_t cldev_index = 0;
	openclDevice   *cldev;
	cl_device_type	kernel_devtype;
	int				first;
	int				index;

	kernel_devtype = chunk->kernel_params->kernel_devtype;
	index = first = __sync_fetch_and_add(&cldev_index, 1) % cldev_nums;
	cldev = cldev_slot[index];
	while ((cldev->prop.dev_type & kernel_devtype) == 0)
	{
		index = (index + 1) % cldev_nums;
		if (index == first)
		{
			chunk_backq(chunk, ERRCODE_INTERNAL_ERROR,
						"No OpenCL device available for this code");
			return NULL;
		}
		cldev = cldev_slot[index];
	}
	return cldev;
}

/*
 * clprog_slot_hash - hash for clprog_slot[]
 */
static inline uint32
clprog_slot_hash(openclContext *clcxt, const char kernel_md5[MD5_SIZE])
{
	uint32	   *hash = (uint32 *)kernel_md5;

	return hash[0] ^ hash[1] ^ hash[2] ^ hash[3] ^
		(((uintptr_t)clcxt) & 0xffffffffUL);
}

/*
 * clserb_cb_build_program
 *
 * callback routine when asynchronous kernel build getting completed.
 * it moves chunks in wait-queue into request queue again.
 */
static void
clserv_cb_build_program(cl_program program, void *user_data)
{
	openclProgram *clprog = user_data;
	dlist_mutable_iter iter;
	int		rc, index;

	Assert(program == clprog->program);
	index = clprog_slot_hash(clprog->clcxt, clprog->kernel_md5)
		% lengthof(clprog_slot);

	if ((rc = pthread_mutex_lock(&clprog_lock[index])) != 0)
		elog(FATAL, "failed on pthread_mutex_lock (%s)", strerror(rc));

	/*
	 * Enqueue chunks in the waiting queue into the request queue again.
	 */
	dlist_foreach_modify(iter, &clprog->waitq)
	{
		ChunkBuffer *chunk = dlist_container(ChunkBuffer, chain, iter.cur);

		dlist_delete(&chunk->chain);
		clserv_enqueue_chunk(chunk);
	}
	pthread_mutex_unlock(&clprog_lock[index]);
}

static openclKernel *
clserv_create_kernel(openclDevice *cldev, ChunkBuffer *chunk)
{	  
	openclProgram  *clprog;
	openclKernel   *clkern;
	KernelParams   *kparams = chunk->kernel_params;
	const char	   *kernel_md5 = kparams->kernel_md5;
	const text	   *kernel_source = &kparams->kernel_source;
	cl_int			index;
	dlist_iter		iter;
	cl_int			rc;
	const char	   *source_str[2];
	size_t			source_len[2];
	char			build_opts[1024];
	const char	   *device_type;

	index = clprog_slot_hash(cldev->clcxt, kernel_md5)
		% lengthof(clprog_slot);

	if ((rc = pthread_mutex_lock(&clprog_lock[index])) != 0)
	{
		chunk_backq(chunk, ERRCODE_INTERNAL_ERROR,
					"failed on pthread_mutex_lock (%s)",
					strerror(rc));
		return NULL;
	}

	dlist_foreach(iter, &clprog_slot[index])
	{
		clprog = dlist_container(openclProgram, chain, iter.cur);

		/*
		 * NOTE: we assume clprog has identical kernel source if its MD5
		 * digest is also identical, unless whole of text comparison.
		 * It is theoreticaly incorrect assumption, but here is performance
		 * tradeoff.
		 */
		if (clprog->clcxt == cldev->clcxt &&
			memcmp(clprog->kernel_md5, kernel_md5, MD5_SIZE) == 0)
		{
			cl_build_status		status;

			if (clGetProgramBuildInfo(clprog->program,
									  cldev->device_id,
									  CL_PROGRAM_BUILD_STATUS,
									  sizeof(cl_build_status),
									  &status,
									  NULL) != CL_SUCCESS)
			{
				pthread_mutex_unlock(&clprog_lock[index]);
				chunk_backq(chunk, ERRCODE_INTERNAL_ERROR,
							"failed on clGetProgramBuildInfo (%s)",
							opencl_strerror(rc));
				return NULL;
			}

			if (status == CL_BUILD_SUCCESS)
			{
				int		n_kernels;
				int		n_events;
				int		i;

				pthread_mutex_unlock(&clprog_lock[index]);

				n_kernels = (chunk->nvarlena > 0 ? chunk->nvarlena : 1);
				n_events = 3 + 2 * n_kernels + 1;
				clkern = calloc(1, offsetof(openclKernel, data) +
								sizeof(cl_kernel) * n_kernels +
								sizeof(cl_event) * n_events +
								sizeof(cl_mem) * n_kernels);
				if (!clkern)
				{
					chunk_backq(chunk, ERRCODE_FDW_OUT_OF_MEMORY,
								"out of memory");
					return NULL;
				}
				clkern->chunk = chunk;
				clkern->cldev = cldev;
				clkern->clprog = clprog;
				clkern->n_kernels = n_kernels;
				clkern->kernels = (cl_kernel *)(clkern->data);
				clkern->events = (cl_event *)(clkern->kernels + n_kernels);
				clkern->arg_vlbufs = (cl_mem *)(clkern->events + n_events);

				for (i=0; i < n_kernels; i++)
				{
					clkern->kernels[i] = clCreateKernel(clprog->program,
														"kernel_qual", &rc);
					if (rc != CL_SUCCESS)
					{
						chunk_backq(chunk, ERRCODE_INTERNAL_ERROR,
									"failed on clCreateKernel (%s)",
									opencl_strerror(rc));
						while (i > 0)
							clReleaseKernel(clkern->kernels[--i]);
						free(clkern);
						return NULL;
					}
				}
				return clkern;
			}

			if (status == CL_BUILD_IN_PROGRESS ||
				status == CL_BUILD_NONE)
			{
				/*
				 * In case when program is under asynchronous building
				 * process, we link this chunk to the waiting list of
				 * this program. Even if build process is not actually
				 * launched yet, it is job of the worker thread that
				 * construct openclProgram object.
				 */
				dlist_push_tail(&clprog->waitq, &chunk->chain);

				pthread_mutex_unlock(&clprog_lock[index]);

				return NULL;
			}
			/*
			 * Elsewhere, program compile was failed.
			 */
			pthread_mutex_unlock(&clprog_lock[index]);
			Assert(status == CL_BUILD_ERROR);

			rc = clGetProgramBuildInfo(clprog->program,
									   cldev->device_id,
									   CL_PROGRAM_BUILD_LOG,
									   sizeof(chunk->data) - 1,
									   chunk->data,
									   NULL);
			if (rc == CL_SUCCESS)
				pgstrom_chunk_buffer_return(chunk, ERRCODE_INTERNAL_ERROR);
			else
				chunk_backq(chunk, ERRCODE_INTERNAL_ERROR,
							"failed on clGetProgramBuildInfo (%s)",
							opencl_strerror(rc));
			return NULL;
		}
	}

	/*
	 * Oh, we could not find a relevant program object, so we need to
	 * create a new one and launch asynchronous build process.
	 */
	clprog = malloc(sizeof(openclProgram));
	if (!clprog)
	{
		pthread_mutex_unlock(&clprog_lock[index]);
		chunk_backq(chunk, ERRCODE_FDW_OUT_OF_MEMORY, "out of memory");
		return NULL;
	}
	clprog->clcxt = cldev->clcxt;
	dlist_init(&clprog->waitq);
	memcpy(clprog->kernel_md5, kernel_md5, MD5_SIZE);
	source_str[0] = pgstrom_common_clhead;
	source_str[1] = VARDATA(kernel_source);
	source_len[0] = strlen(pgstrom_common_clhead);
	source_len[1] = VARSIZE(kernel_source) - VARHDRSZ;
	
	clprog->program = clCreateProgramWithSource(clprog->clcxt->context,
												2,
												source_str,
												source_len,
												&rc);
	if (rc != CL_SUCCESS)
	{
		pthread_mutex_unlock(&clprog_lock[index]);
		chunk_backq(chunk, ERRCODE_INTERNAL_ERROR,
					"clCreateProgramWithSource (%s)",
					opencl_strerror(rc));
		free(clprog);
		return NULL;
	}
	dlist_push_tail(&clprog->waitq, &chunk->chain);
	dlist_push_tail(&clprog_slot[index], &clprog->chain);

	/*
	 * Set up program build options
	 */
	if (clprog->clcxt->dev_type == CL_DEVICE_TYPE_CPU)
		device_type = "CPU";
	else if (clprog->clcxt->dev_type == CL_DEVICE_TYPE_GPU)
		device_type = "GPU";
	else if (clprog->clcxt->dev_type == CL_DEVICE_TYPE_ACCELERATOR)
		device_type = "ACCELERATOR";
	else if (clprog->clcxt->dev_type == CL_DEVICE_TYPE_CUSTOM)
		device_type = "CUSTOM";
	else
		device_type = "UNKNOWN";

	switch (chunk->kernel_params->vector_preference)
	{
		case CL_DEVICE_PREFERRED_VECTOR_WIDTH_CHAR:
			clprog->vector_width = clprog->clcxt->vec_width_char;
			break;
		case CL_DEVICE_PREFERRED_VECTOR_WIDTH_SHORT:
			clprog->vector_width = clprog->clcxt->vec_width_short;
			break;
		case CL_DEVICE_PREFERRED_VECTOR_WIDTH_LONG:
			clprog->vector_width = clprog->clcxt->vec_width_long;
			break;
		case CL_DEVICE_PREFERRED_VECTOR_WIDTH_FLOAT:
			clprog->vector_width = clprog->clcxt->vec_width_float;
			break;
		case CL_DEVICE_PREFERRED_VECTOR_WIDTH_DOUBLE:
			clprog->vector_width = clprog->clcxt->vec_width_double;
			break;
		case CL_DEVICE_PREFERRED_VECTOR_WIDTH_INT:
		default:
			clprog->vector_width = clprog->clcxt->vec_width_int;
			break;
	}
	snprintf(build_opts, sizeof(build_opts),
			 "-Werror -DSTROMCL_DEVICE_TYPE_%s -DSTROMCL_VECTOR_WIDTH=%u",
			 device_type, clprog->vector_width);

	/*
	 * NOTE: The reason why we don't kick clBuildProgram under clprog_lock
	 * is that nvidia's driver don't launch asynchronous program building
	 * even if callback was given, thus, its completion callback will be
	 * invoked prior to return from clBuildProgram in this thread.
	 * It also means the callback blocks forever when it tries to acquire
	 * the same exclusive lock on same slot.
	 */
	pthread_mutex_unlock(&clprog_lock[index]);

	/*
	 * Kick (probably) asynchronous build process
	 */
	rc = clBuildProgram(clprog->program,
						0,
						NULL,
						build_opts,
						clserv_cb_build_program,
						clprog);
	if (rc != CL_SUCCESS)
	{
		cl_build_status		status;

		/*
		 * When clBuildProgram does not return CL_SUCCESS, its build status
		 * has to be CL_BUILD_ERROR to ensure chunks in the waiting queue
		 * returns an error status to the caller.
		 * Please note that current chunk is already in the waiting queue,
		 * and nobody can back it to the caller unless program build status
		 * become either CL_BUILD_SUCCESS or CL_BUILD_ERROR.
		 */
		if (clGetProgramBuildInfo(clprog->program,
								  cldev->device_id,
								  CL_PROGRAM_BUILD_STATUS,
								  sizeof(cl_build_status),
								  &status,
								  NULL) != CL_SUCCESS &&
			status != CL_BUILD_ERROR)
			elog(FATAL, "clBuildProgram returned %s, but build status: %d",
				 opencl_strerror(rc), status);
	}
	return NULL;
}

static void
clserv_release_kernel(openclKernel *clkern)
{
	int		i;

	for (i=0; i < clkern->n_kernels; i++)
		clReleaseKernel(clkern->kernels[i]);
	for (i=0; i < clkern->n_events; i++)
		clReleaseEvent(clkern->events[i]);
	if (clkern->arg_kparams != NULL)
		clReleaseMemObject(clkern->arg_kparams);
	if (clkern->arg_kargs != NULL)
		clReleaseMemObject(clkern->arg_kargs);
	for (i=0; i < clkern->n_kernels; i++)
	{
		if (clkern->arg_vlbufs[i] != NULL)
			clReleaseMemObject(clkern->arg_vlbufs[i]);
	}
	if (clkern->arg_wkmem)
		clReleaseMemObject(clkern->arg_wkmem);
	free(clkern);
}

static void
clserv_cb_chunk_complete(cl_event event, cl_int ev_status, void *user_data)
{
	openclKernel   *clkern = user_data;
	ChunkBuffer	   *chunk = clkern->chunk;
	cl_int			status;
	cl_int			i, rc;

	for (i=0; i < clkern->n_events; i++)
	{
		rc = clGetEventInfo(clkern->events[i],
							CL_EVENT_COMMAND_EXECUTION_STATUS,
							sizeof(status),
							&status,
							NULL);
		if (rc != CL_SUCCESS)
		{
			chunk_backq(chunk, ERRCODE_INTERNAL_ERROR,
						"failed on clGetEventInfo (%s)",
						opencl_strerror(rc));
			goto cleanup;
		}

		Assert(status <= CL_COMPLETE);
		if (status < CL_COMPLETE)
		{
			chunk_backq(chunk, ERRCODE_INTERNAL_ERROR,
						"error on asynchronous event[%d] (%s)",
						i, opencl_strerror(status));
			goto cleanup;
		}
	}

	/* OK, no events returned an error status */
	chunk->is_running = false;
	chunk->error_code = ERRCODE_SUCCESSFUL_COMPLETION;
	AssertOnShmem(chunk->recvq);
	pgstrom_queue_enqueue(chunk->recvq, &chunk->chain);

cleanup:
	/* cleanup resources */
	clserv_release_kernel(clkern);
}

static bool
clserv_alloc_unified_memory(openclKernel *clkern)
{
	ChunkBuffer	   *chunk = clkern->chunk;
	openclDevice   *cldev = clkern->cldev;
	KernelParams   *kparams = chunk->kernel_params;
	cl_mem			host_shmem = cldev->clcxt->host_shmem;
	cl_buffer_region region;
	cl_mem			temp;
	cl_int			rc, i_vlbuf = 0;
	dlist_iter		iter;

	Assert(cldev->prop.dev_host_unified_memory);

	/* assign sub-buffer for kparams */
	Assert((uintptr_t)kparams->kparams >= shmem_start &&
		   (uintptr_t)kparams->kparams + kparams->kparams_size <= shmem_end);
	region.origin = (uintptr_t)kparams->kparams - shmem_start;
	region.size = kparams->kparams_size;
	temp  = clCreateSubBuffer(host_shmem,
							  CL_MEM_READ_WRITE,
							  CL_BUFFER_CREATE_TYPE_REGION,
							  &region,
							  &rc);
	if (rc != CL_SUCCESS)
	{
		chunk_backq(chunk, ERRCODE_FDW_OUT_OF_MEMORY,
					"failed on clCreateSubBuffer (%s) region=(%lu, %lu)",
					opencl_strerror(rc), region.origin, region.size);
		return false;
	}
	clkern->arg_kparams = temp;

	/* assign sub-buffer of kargs */
	Assert((uintptr_t)chunk->cb_kargs + chunk->dma_send_start >= shmem_start &&
		   (uintptr_t)chunk->cb_kargs + chunk->dma_recv_end <= shmem_end);
	region.origin = ((uintptr_t)chunk->cb_kargs +
					 chunk->dma_send_start - shmem_start);
	region.size = chunk->dma_recv_end - chunk->dma_send_start;
	temp = clCreateSubBuffer(host_shmem,
							 CL_MEM_READ_WRITE,
							 CL_BUFFER_CREATE_TYPE_REGION,
							 &region,
							 &rc);
	if (rc != CL_SUCCESS)
	{
		chunk_backq(chunk, ERRCODE_FDW_OUT_OF_MEMORY,
					"failed on clCreateSubBuffer (%s) region=(%lu, %lu)",
					opencl_strerror(rc), region.origin, region.size);
		return false;
	}
	clkern->arg_kargs = temp;

	/* assign sub-buffers of vlbufs */
	if (!dlist_is_empty(&chunk->vlbuf_list))
	{
		dlist_foreach(iter, &chunk->vlbuf_list)
		{
			VarlenaBuffer  *vlbuf
				= dlist_container(VarlenaBuffer, chain, iter.cur);

			region.origin = (uintptr_t)(&vlbuf->kvlbuf) - shmem_start;
			region.size = vlbuf->kvlbuf->length;
			temp = clCreateSubBuffer(host_shmem,
									 CL_MEM_READ_WRITE,
									 CL_BUFFER_CREATE_TYPE_REGION,
									 &region,
									 &rc);
			if (rc != CL_SUCCESS)
			{
				chunk_backq(chunk, ERRCODE_FDW_OUT_OF_MEMORY,
							"failed on clCreateSubBuffer (%s)",
							opencl_strerror(rc));
				return false;
			}
			clkern->arg_vlbufs[i_vlbuf++] = temp;
		}
		Assert(clkern->n_kernels == i_vlbuf);
	}
	else
	{
		Assert(clkern->n_kernels == 1);
		clkern->arg_vlbufs[0] = NULL;
	}

	/*
	 * XXX - working memory is not supported now
	 */
	clkern->arg_wkmem = NULL;

	return true;
}

static bool
clserv_alloc_device_memory(openclKernel *clkern)
{
	ChunkBuffer	   *chunk = clkern->chunk;
	openclDevice   *cldev = clkern->cldev;
	cl_context		context = cldev->clcxt->context;
	KernelParams   *kparams = chunk->kernel_params;
	cl_mem			temp;
	size_t			length;
	dlist_iter		iter;
	cl_int			rc, i_vlbuf = 0;

	Assert(!cldev->prop.dev_host_unified_memory);

	temp = clCreateBuffer(context,
						  CL_MEM_READ_WRITE,
						  kparams->kparams_size,
						  NULL,
						  &rc);
	if (rc != CL_SUCCESS)
	{
		chunk_backq(chunk, ERRCODE_FDW_OUT_OF_MEMORY,
					"failed on clCreateBuffer %u bytes (%s)",
					kparams->kparams_size, opencl_strerror(rc));
		return false;
	}
	clkern->arg_kparams = temp;

	length = chunk->dma_recv_end - chunk->dma_send_start;
	temp = clCreateBuffer(context,
						  CL_MEM_READ_WRITE,
						  length,
						  NULL,
						  &rc);
	if (rc != CL_SUCCESS)
	{
		chunk_backq(chunk, ERRCODE_FDW_OUT_OF_MEMORY,
					"failed on clCreateBuffer %lu bytes (%s)",
					length, opencl_strerror(rc));
		return false;
	}
	clkern->arg_kargs = temp;

	if (dlist_is_empty(&chunk->vlbuf_list))
	{
		Assert(clkern->n_kernels == 1);
        clkern->arg_vlbufs[0] = NULL;
	}
	else
	{
		dlist_foreach(iter, &chunk->vlbuf_list)
		{
			if (i_vlbuf == 0)
			{
				temp = clCreateBuffer(context,
									  CL_MEM_READ_WRITE,
									  chunk->varlena_sz,
									  NULL,
									  &rc);
				if (rc != CL_SUCCESS)
				{
					chunk_backq(chunk, ERRCODE_FDW_OUT_OF_MEMORY,
								"failed on clCreateBuffer %u bytes (%s)",
								chunk->varlena_sz, opencl_strerror(rc));
					return false;
				}
			}
			else
			{
				rc = clRetainMemObject(temp);
				if (rc != CL_SUCCESS)
				{
					chunk_backq(chunk, ERRCODE_INTERNAL_ERROR,
								"failed on clRetainMemObject (%s)",
								opencl_strerror(rc));
					return false;
				}
			}
			clkern->arg_vlbufs[i_vlbuf++] = temp;
		}
		Assert(clkern->n_kernels == i_vlbuf);
	}

	/*
	 * XXX - working memory is not supported now
	 */
	clkern->arg_wkmem = NULL;

	return true;
}

static bool
clserv_enqueue_dma_send(openclKernel *clkern)
{
	openclDevice   *cldev = clkern->cldev;
	ChunkBuffer	   *chunk = clkern->chunk;
	KernelParams   *kparams = chunk->kernel_params;
	char			errmsg[1024];
	cl_int			rc;

	/* to be placed on first */
	Assert(clkern->n_events == 0);

	/* DMA send of kparams */
	rc = clEnqueueWriteBuffer(cldev->cmdq,
							  clkern->arg_kparams,
							  CL_FALSE,
							  0,
							  kparams->kparams_size,
							  kparams->kparams,
							  0,
							  NULL,
							  clkern->events + clkern->n_events);
	if (rc != CL_SUCCESS)
	{
		snprintf(errmsg, sizeof(errmsg),
				 "failed on clEnqueueWriteBuffer for kparams (%s)",
				 opencl_strerror(rc));
		goto error_cleanup;
	}
	clkern->n_events++;

	/* DMA send of kargs */
	rc = clEnqueueWriteBuffer(cldev->cmdq,
							  clkern->arg_kargs,
							  CL_FALSE,
							  0,
							  chunk->dma_send_end - chunk->dma_send_start,
							  (char *)chunk->cb_kargs + chunk->dma_send_start,
							  0,
							  NULL,
							  clkern->events + clkern->n_events);
	if (rc != CL_SUCCESS)
	{
		snprintf(errmsg, sizeof(errmsg),
				 "failed on clEnqueueWriteBuffer for kargs (%s)",
				 opencl_strerror(rc));
		goto error_cleanup;
	}
	clkern->n_events++;

	return true;

error_cleanup:
	if (clkern->n_events > 0)
		clWaitForEvents(clkern->n_events, clkern->events);
	chunk_backq(clkern->chunk, ERRCODE_INTERNAL_ERROR, "%s", errmsg);
	return false;
}

static bool
clserv_enqueue_varlena_send(openclKernel *clkern,
							int index, VarlenaBuffer *vlbuf)
{
	openclDevice   *cldev = clkern->cldev;
	cl_int			rc;

	if (index == 0)
	{
		rc = clEnqueueWriteBuffer(cldev->cmdq,
								  clkern->arg_vlbufs[index],
								  CL_FALSE,
								  0,
								  vlbuf->kvlbuf->length,
								  &vlbuf->kvlbuf,
								  0,
								  NULL,
								  clkern->events + clkern->n_events);
	}
	else
	{
		Assert(clkern->n_events > 0);
		rc = clEnqueueWriteBuffer(cldev->cmdq,
                                  clkern->arg_vlbufs[index],
                                  CL_FALSE,
                                  0,
                                  vlbuf->kvlbuf->length,
                                  &vlbuf->kvlbuf,
								  1,
								  clkern->events + clkern->n_events - 1,
								  clkern->events + clkern->n_events);
	}

	if (rc != CL_SUCCESS)
	{
		clWaitForEvents(clkern->n_events, clkern->events);
		chunk_backq(clkern->chunk, ERRCODE_INTERNAL_ERROR,
					"failed on clEnqueueReadBuffer for vlbuf[%d] (%s)",
					index, opencl_strerror(rc));
		return false;
	}
	clkern->n_events++;
	return true;
}

static bool
clserv_enqueue_dma_recv(openclKernel *clkern)
{
	openclDevice   *cldev = clkern->cldev;
	ChunkBuffer	   *chunk = clkern->chunk;
	size_t			offset;
	cl_int			rc;

	/* should not be first */
	Assert(clkern->n_events > 0);

	offset = chunk->dma_recv_start - chunk->dma_send_start;
	rc = clEnqueueReadBuffer(cldev->cmdq,
							 clkern->arg_kargs,
							 CL_FALSE,
							 offset,
							 chunk->dma_recv_end - chunk->dma_recv_start,
							 (char *)chunk->cb_kargs + chunk->dma_recv_start,
							 1,
							 clkern->events + clkern->n_events - 1,
							 clkern->events + clkern->n_events);
	if (rc != CL_SUCCESS)
	{
		clWaitForEvents(clkern->n_events, clkern->events);
		chunk_backq(clkern->chunk, ERRCODE_INTERNAL_ERROR,
					"failed on clEnqueueReadBuffer for result (%s)",
					opencl_strerror(rc));
		return false;
	}
	clkern->n_events++;
	return true;
}

/*
 * clserv_enqueue_completion_marker
 *
 * In case when opencl device supports host unified memory, it does not
 * take enqueuing dma-recv event being also used for synchronization of
 * all the kernel execution. Note that here is no guarantee the kernel
 * last enqueued is completed last if chunk has multiple varlena buffers.
 * So, clserv_cb_chunk_complete has to be called as callback of this
 * completion marker.
 */
static bool
clserv_enqueue_completion_marker(openclKernel *clkern)
{
	openclDevice   *cldev = clkern->cldev;
	cl_int			rc;

#ifdef CL_VERSION_1_2
	rc = clEnqueueMarkerWithWaitList(cldev->cmdq,
									 clkern->n_events,
									 clkern->events,
									 clkern->events + clkern->n_events);
	if (rc != CL_SUCCESS)
	{
		clWaitForEvents(clkern->n_events, clkern->events);
		chunk_backq(clkern->chunk, ERRCODE_INTERNAL_ERROR,
					"failed on clEnqueueMarkerWithWaitList(%s)",
					opencl_strerror(rc));
		return false;
	}
#else
	/*
	 * clEnqueueMarker was deprecated at OpenCL 1.2, so newer runtime
	 * should use clEnqueueMarkerWithWaitList instead.
	 */
	rc = clEnqueueMarker(cldev->cmdq, clkern->events + clkern->n_events);
	if (rc != CL_SUCCESS)
	{
		clWaitForEvents(clkern->n_events, clkern->events);
		chunk_backq(clkern->chunk, ERRCODE_INTERNAL_ERROR,
					"failed on clEnqueueMarker(%s)",
					opencl_strerror(rc));
		return false;
	}
#endif
	clkern->n_events++;
	return true;
}

static bool
clserv_enqueue_kernel_exec(openclKernel *clkern, int index,
						   cl_int offset, cl_int nitems)
{
	openclDevice   *cldev = clkern->cldev;
	size_t			wkgrp_offset[2];
	size_t			wkgrp_global[2];
	size_t			wkgrp_local[2];
	size_t			wkgrp_maxsz;
	size_t			wkgrp_unitsz;
	char			errmsg[1024];
	cl_int			vector_width = clkern->clprog->vector_width;
	cl_int			rc;

	/* arg[0] : __global kern_params_t *kparams */
	rc = clSetKernelArg(clkern->kernels[index],
						0,
						sizeof(cl_mem),
						&clkern->arg_kparams);
	if (rc != CL_SUCCESS)
	{
		snprintf(errmsg, sizeof(errmsg),
				 "failed on clSetKernelArg of 1st argument (%s)",
				 opencl_strerror(rc));
		goto error_cleanup;
	}

	/* arg[1] : __global kern_args_t *kargs */
	rc = clSetKernelArg(clkern->kernels[index],
						1,
						sizeof(cl_mem),
						&clkern->arg_kargs);
	if (rc != CL_SUCCESS)
	{
		snprintf(errmsg, sizeof(errmsg),
				 "failed on clSetKernelArg of 2nd argument (%s)",
				 opencl_strerror(rc));
		goto error_cleanup;
	}

	/* arg[2] : __global kern_vlbuf_t *vlbuf */
	rc = clSetKernelArg(clkern->kernels[index],
						2,
						sizeof(cl_mem),
						&clkern->arg_vlbufs[index]);
	if (rc != CL_SUCCESS)
	{
		snprintf(errmsg, sizeof(errmsg),
				 "failed on clSetKernelArg of 3rd argument (%s)",
				 opencl_strerror(rc));
		goto error_cleanup;
	}

	/* arg[3] : __global char *gwkmem */
	rc = clSetKernelArg(clkern->kernels[index],
						3,
						sizeof(cl_mem),
						&clkern->arg_wkmem);
	if (rc != CL_SUCCESS)
	{
		snprintf(errmsg, sizeof(errmsg),
				 "failed on clSetKernelArg of 4th argument (%s)",
				 opencl_strerror(rc));
		goto error_cleanup;
	}

	/*
	 * compute an optimal global/local work-item size
	 */
	rc = clGetKernelWorkGroupInfo(clkern->kernels[index],
								  cldev->device_id,
								  CL_KERNEL_WORK_GROUP_SIZE,
								  sizeof(size_t),
								  &wkgrp_maxsz,
								  NULL);
	if (rc != CL_SUCCESS)
	{
		snprintf(errmsg, sizeof(errmsg),
				 "failed on clGetKernelWorkGroupInfo (%s)",
				 opencl_strerror(rc));
		goto error_cleanup;
	}

	/*
	 * NOTE: we use 2-dimensional matrix to map a particular computing
	 * unit a particular row. A row is identified with global Y-axis,
	 * and a row can be handled with multiple computing units.
	 *
	 * XXX - future version will support to run multiple computing units
	 * per row, to handle large varlena datum in typical usage, but not
	 * supported right now. Thus, we assign a computing unit per row
	 * according to the hardwired rule.
	 *
	 * The global Y-axis (that is get_blobal_id(1) in kernel code) always
	 * points a particular row in this chunk, independent from whether
	 * multiple computing units are assigned on a row, or not.
	 * In case when number of computing units consumed per row is greater
	 * than max available number of work-items per group, it takes X-axis
	 * greater than 1, because device does not have capability to handle
	 * such amount of computing units in local one. Thus, please note that
	 * we have no guarantee that all the computing units are handled in
	 * a same work-group even if a kernel executable function required
	 * multiple computing units per row.
	 */
	wkgrp_unitsz = 1;
	wkgrp_offset[0] = 0;
	wkgrp_offset[1] = offset;
	if (wkgrp_unitsz <= wkgrp_maxsz)
	{
		wkgrp_local[0] = wkgrp_unitsz;
		wkgrp_local[1] = wkgrp_maxsz / wkgrp_unitsz;
		wkgrp_global[0] = wkgrp_local[0];
		wkgrp_global[1] = ((nitems / vector_width + wkgrp_local[1] - 1)
						   / wkgrp_local[1]) * wkgrp_local[1];
	}
	else
	{
		wkgrp_local[0] = wkgrp_maxsz;
		wkgrp_local[1] = 1;
		wkgrp_global[0] = ((wkgrp_unitsz + wkgrp_maxsz - 1)
						   / wkgrp_maxsz) * wkgrp_maxsz;
		wkgrp_global[1] = nitems / vector_width;
	}

	dlog("clEnqueueNDRangeKernel : device='%s', nitems=%d, vector-width %d, "
		 "global-offset {%lu,%lu}, global-size {%lu,%lu}, "
		 "local-size {%lu,%lu}",
		 cldev->prop.dev_name, nitems, vector_width,
		 wkgrp_offset[0], wkgrp_offset[1],
		 wkgrp_global[0], wkgrp_global[1],
		 wkgrp_local[0], wkgrp_local[1]);

	/*
	 * If index == 0, it has to wait for completion of asynchronous DMA
	 * transfer of kparams, kargs and vlbuf, to launch kernel execution.
	 * Elsewhere, all we need to synchronize is syncronization of the
	 * previous one event.
	 *
	 * XXX - It might be an idea to set up multiple varlena buffers to
	 * have asynchronous DMA transfer during kernel execution on the
	 * previous buffer!
	 */
	if (cldev->prop.dev_host_unified_memory)
	{
		rc = clEnqueueNDRangeKernel(cldev->cmdq,
									clkern->kernels[index],
									2,	/* 2D-matrix */
									wkgrp_offset,
									wkgrp_global,
									wkgrp_local,
									0,
									NULL,
									clkern->events + clkern->n_events);
	}
	else if (index == 0)
	{
		rc = clEnqueueNDRangeKernel(cldev->cmdq,
									clkern->kernels[index],
									2,	/* 2D-matrix */
									wkgrp_offset,
									wkgrp_global,
									wkgrp_local,
									clkern->n_events,
									clkern->events,
									clkern->events + clkern->n_events);
	}
	else
	{
		rc = clEnqueueNDRangeKernel(cldev->cmdq,
									clkern->kernels[index],
									2,	/* 2D-matrix */
									wkgrp_offset,
									wkgrp_global,
									wkgrp_local,
									1,
									clkern->events + clkern->n_events - 1,
									clkern->events + clkern->n_events);
	}

	if (rc != CL_SUCCESS)
    {
        snprintf(errmsg, sizeof(errmsg),
				 "failed on clEnqueueNDRangeKernel : device='%s', "
				 "global-offset {%lu,%lu}, global-size {%lu,%lu}, "
				 "local-size {%lu,%lu} (%s)",
				 cldev->prop.dev_name,
				 wkgrp_offset[0], wkgrp_offset[1],
				 wkgrp_global[0], wkgrp_global[1],
				 wkgrp_local[0], wkgrp_local[1],
				 opencl_strerror(rc));
		goto error_cleanup;
	}
	clkern->n_events++;

	return true;

error_cleanup:
	if (clkern->n_events > 0)
		clWaitForEvents(clkern->n_events, clkern->events);
	chunk_backq(clkern->chunk, ERRCODE_INTERNAL_ERROR, "%s", errmsg);
	return false;
}

static void *
clserv_worker_main(void *dummy)
{
	dlist_node	   *dnode;
	ChunkBuffer	   *chunk;
	openclDevice   *cldev;
	openclKernel   *clkern;
	cl_int			rc;
	bool			unified_memory;

	/* for debug tracking */
	clserv_worker_index = (uintptr_t)dummy;

	while (clserv_running)
	{
		/* dequeue a chunk-buffer from the queue */
		dnode = pgstrom_queue_dequeue(clserv_queue, 15 * 1000);
		if (!dnode)
			continue;
		chunk = dlist_container(ChunkBuffer, chain, dnode);

		/* check status of chunk buffer */
		Assert(chunk->is_loaded || chunk->nitems == 0);
		Assert(chunk->recvq != NULL && chunk->is_running);

		/* choose an appropriate device */
		cldev = clserv_device_scheduler(chunk);
		if (!cldev)
			continue;

		/*
		 * create a cl_kernel object with supplied kernel source.
		 * Heuristically, we know pre-compiled program object is
		 * ready to use, however, we may have to wait for completion
		 * of asynchronous build process. In this case, the chunk
		 * is keps in wait-queue of the program object, then backed
		 * to the request queue again.
		 */
		clkern = clserv_create_kernel(cldev, chunk);
		if (!clkern)
			continue;

		/*
		 * If chunk has no items (in case when caller wants to check
		 * whether kernel source can be built, or not), chunk shall
		 * be backed to the backend immediately.
		 */
		if (chunk->nitems == 0)
		{
			chunk_backq(chunk, ERRCODE_SUCCESSFUL_COMPLETION, "");
			continue;
		}

		/*
		 * Allocation of either device or unified memory.
		 * In case when device support host unified memory, no need to
		 * take data transfer between host and device memory, thus, we
		 * assign sub-buffer of host shared memory instead of device
		 * memory.
		 *
		 * XXX - does it make sense to wait for completion of concurrent
		 * kernel execution if device memory allocation was failed?
		 */
		unified_memory = cldev->prop.dev_host_unified_memory;
		if (!unified_memory ?
			!clserv_alloc_device_memory(clkern) :
			!clserv_alloc_unified_memory(clkern))
			goto error_cleanup;

		/*
		 * Enqueue a series of kernel execution sequence
		 */
		if (!unified_memory && !clserv_enqueue_dma_send(clkern))
			goto error_cleanup;

		if (dlist_is_empty(&chunk->vlbuf_list))
		{
			if (!clserv_enqueue_kernel_exec(clkern, 0, 0, chunk->nitems))
				goto error_cleanup;
		}
		else
		{
			dlist_iter	iter;
			cl_int		i_vlbuf = 0;

			dlist_foreach(iter, &chunk->vlbuf_list)
			{
				VarlenaBuffer  *vlbuf
					= dlist_container(VarlenaBuffer, chain, iter.cur);

				Assert(vlbuf->kvlbuf->index >= 0 &&
					   (vlbuf->kvlbuf->index +
						vlbuf->kvlbuf->nitems) <= chunk->nitems);
				if (!clserv_enqueue_varlena_send(clkern, i_vlbuf, vlbuf) ||
					!clserv_enqueue_kernel_exec(clkern, i_vlbuf,
												vlbuf->kvlbuf->index,
												vlbuf->kvlbuf->nitems))
					goto error_cleanup;
				i_vlbuf++;
			}
		}

		if (!unified_memory ?
			!clserv_enqueue_dma_recv(clkern) :
			!clserv_enqueue_completion_marker(clkern))
			goto error_cleanup;

		Assert(clkern->n_events > 0);
		rc = clSetEventCallback(clkern->events[clkern->n_events - 1],
								CL_COMPLETE,
								clserv_cb_chunk_complete,
								clkern);
		/*
		 * A series of jobs were successfully queued in, so the registered
		 * callback also enqueue this chunk back to the caller's queue
		 * when these asynchronous jobs were done.
		 * So, this thread can continue to process next chunk.
		 */
		if (rc == CL_SUCCESS)
			continue;

	error_cleanup:
		clserv_release_kernel(clkern);
	}
	return NULL;
}

/*
 * is_available_opencl_device
 *
 * it checks whether the supplied opencl device matches the configured
 * "clserv_opencl_devices" being listed up.
 */
static bool
is_available_opencl_device(openclDevice *cldev)
{
	static int	device_index = 0;
	char	   *copy;
	char	   *tok;
	char	   *pos;


	cldev->prop.index = ++device_index;

	copy = strdup(clserv_opencl_devices);
	if (!copy)
		elog(ERROR, "out of memory");
	tok = strtok_r(copy, " \t", &pos);
	while (tok != NULL)
	{
		if (strcasecmp(tok, "all") == 0)
			goto out_ok;
		else if (strcasecmp(tok, "cpu") == 0)
		{
			if ((cldev->prop.dev_type & CL_DEVICE_TYPE_CPU) != 0)
				goto out_ok;
		}
		else if (strcasecmp(tok, "gpu") == 0)
		{
			if ((cldev->prop.dev_type & CL_DEVICE_TYPE_GPU) != 0)
				goto out_ok;
		}
		else if (strcasecmp(tok, "accelerator") == 0)
		{
			if ((cldev->prop.dev_type & CL_DEVICE_TYPE_ACCELERATOR) != 0)
				goto out_ok;
		}
		else
		{
			int		index = atoi(tok);

			if (index < 1 || errno != 0)
				elog(ERROR, "pg_strom.opencl_devices has to be either "
					 "cpu, gpu, accelerator or index number: %s", tok);
			if (index == cldev->prop.index)
				goto out_ok;
		}
		tok = strtok_r(NULL, " \t", &pos);
	}
	free(copy);
	return false;

out_ok:
	free(copy);
	return true;
}

/*
 * construct_opencl_device
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
construct_opencl_device(cl_platform_id platform_id, cl_device_id device_id)
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

	cldev->device_id = device_id;
	/* XXX - context and cmdq shall be set later */

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

	/* is it an opencl device to be used? */
	if (!is_available_opencl_device(cldev))
		goto out_clean;

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

/*
 * construct_opencl_context
 *
 * It construct opencl contexts on devices. If multiple devices have
 * identical features to be considered on kernel code build, these
 * shall share same context.
 */
static void
construct_opencl_context(cl_platform_id platform_id,
						 dlist_head *dev_list)
{
	openclDevice   *cldev;
	openclContext  *clcxt;
	dlist_node	   *dnode;
	DeviceProperty *dp;
	dlist_mutable_iter iter;
	cl_device_id	device_ids[MAX_OPENCL_DEVICES];
	cl_int			device_idx;
	cl_int			rc;

	while (!dlist_is_empty(dev_list))
	{
		dnode = dlist_pop_head_node(dev_list);
		cldev = dlist_container(openclDevice, chain, dnode);

		clcxt = malloc(sizeof(openclContext));
		if (!clcxt)
			elog(ERROR, "out of memory");

		clcxt->platform_id = platform_id;
		dlist_init(&clcxt->dev_list);

		dp = &cldev->prop;
		clcxt->dev_type = dp->dev_type;
		clcxt->vec_width_char = dp->dev_native_vector_width_char;
		clcxt->vec_width_short = dp->dev_native_vector_width_short;
		clcxt->vec_width_int = dp->dev_native_vector_width_int;
		clcxt->vec_width_long = dp->dev_native_vector_width_long;
		clcxt->vec_width_float = dp->dev_native_vector_width_float;
		clcxt->vec_width_double = dp->dev_native_vector_width_double;

		device_idx = 0;
		dlist_push_tail(&clcxt->dev_list, &cldev->chain);
		cldev->clcxt = clcxt;
		device_ids[device_idx++] = cldev->device_id;

		dlist_foreach_modify(iter, dev_list)
		{
			cldev = dlist_container(openclDevice, chain, iter.cur);

			dp = &cldev->prop;
			if (clcxt->dev_type == dp->dev_type &&
				clcxt->vec_width_char == dp->dev_native_vector_width_char &&
				clcxt->vec_width_short == dp->dev_native_vector_width_short &&
				clcxt->vec_width_int == dp->dev_native_vector_width_int &&
				clcxt->vec_width_long == dp->dev_native_vector_width_long &&
				clcxt->vec_width_float == dp->dev_native_vector_width_float &&
				clcxt->vec_width_double == dp->dev_native_vector_width_double)
			{
				dlist_delete(&cldev->chain);
				dlist_push_tail(&clcxt->dev_list, &cldev->chain);
				cldev->clcxt = clcxt;
				device_ids[device_idx++] = cldev->device_id;
			}
		}
		/* create a relevant context */
		clcxt->context = clCreateContext(NULL,
										 device_idx,
										 device_ids,
										 NULL,
										 NULL,
										 &rc);
		if (rc != CL_SUCCESS)
			elog(ERROR, "failed on clCreateContext (%s)",
				 opencl_strerror(rc));

		/* also, memory object of shared memory on host */
		clcxt->host_shmem = clCreateBuffer(clcxt->context,
										   CL_MEM_READ_WRITE |
										   CL_MEM_USE_HOST_PTR,
										   shmem_end - shmem_start,
										   (void *)shmem_start,
										   &rc);
		if (rc != CL_SUCCESS)
			elog(ERROR, "failed on clCreateBuffer (%s)",
				 opencl_strerror(rc));

		/* then, create command-queue for each device */
		dlist_foreach_modify(iter, &clcxt->dev_list)
		{
			cl_command_queue_properties qprop;

			cldev = dlist_container(openclDevice, chain, iter.cur);

			qprop = CL_QUEUE_OUT_OF_ORDER_EXEC_MODE_ENABLE;
			cldev->cmdq = clCreateCommandQueue(clcxt->context,
											   cldev->device_id,
											   qprop,
											   &rc);
			if (rc != CL_SUCCESS)
				elog(ERROR, "failed on clCreateCommandQueue (%s)",
					 opencl_strerror(rc));
		}
	}
}

static void
init_opencl_devices(void)
{
	cl_platform_id	platform_ids[MAX_OPENCL_PLATFORMS];
	cl_device_id	device_ids[MAX_OPENCL_DEVICES];
	cl_uint			n_platforms;
	cl_uint			n_devices;
	cl_int			i, j, rc;
	dlist_head		dev_list;
	openclDevice   *cldev;

	rc = clGetPlatformIDs(lengthof(platform_ids),
						  platform_ids, &n_platforms);
	if (rc != CL_SUCCESS)
		elog(ERROR, "failed on clGetPlatformIDs (%s)",
			 opencl_strerror(rc));

	for (i=0; i < n_platforms; i++)
	{
		dlist_init(&dev_list);

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
			cldev = construct_opencl_device(platform_ids[i], device_ids[j]);
			if (cldev)
			{
				const char *dev_type;

				switch (cldev->prop.dev_type)
				{
					case CL_DEVICE_TYPE_CPU:
						dev_type = "CPU";
						break;
					case CL_DEVICE_TYPE_GPU:
						dev_type = "GPU";
						break;
					case CL_DEVICE_TYPE_ACCELERATOR:
						dev_type = "Accelerator";
						break;
					case CL_DEVICE_TYPE_CUSTOM:
						dev_type = "Custom";
						break;
					default:
						dev_type = "Unknown";
						break;
				}
				elog(LOG,
					 "OpenCL %s device[%u] %s (%u units, %uMHz, %luMB) on %s",
					 dev_type,
					 cldev_nums,
					 cldev->prop.dev_name,
					 cldev->prop.dev_max_compute_units,
					 cldev->prop.dev_max_clock_frequency,
					 cldev->prop.dev_global_mem_size >> 20,
					 cldev->prop.pf_name);

				cldev_slot[cldev_nums] = cldev;
				cldev_nums++;

				dlist_push_tail(&dev_list, &cldev->chain);
			}
		}
		construct_opencl_context(platform_ids[i], &dev_list);
	}

	if (cldev_nums == 0)
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
	pthread_attr_t	thread_attr;
	pthread_t	   *thread_ids;
	uintptr_t		i;

	/* We're now ready to receive signals */
	BackgroundWorkerUnblockSignals();

	/* initialize opencl devices */
	init_opencl_devices();

	/* launch worker threads */
	thread_ids = malloc(sizeof(pthread_t) * clserv_num_workers);
	if (!thread_ids)
		elog(ERROR, "out of memory");
	if (pthread_attr_init(&thread_attr) != 0 ||
		pthread_attr_setguardsize(&thread_attr, PTHREAD_STACK_MIN) != 0)
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("failed to set up pthread attributes")));

	for (i=0; i < clserv_num_workers; i++)
	{
		if (pthread_create(&thread_ids[i], &thread_attr,
						   clserv_worker_main, (void *)i) != 0)
			ereport(ERROR,
					(errcode(ERRCODE_INTERNAL_ERROR),
					 errmsg("failed to launch opencl worker thread")));
	}

	/* master thread goes to relaxing */
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

	/* synchronize the worker thread exit */
	pgstrom_queue_wakeup(clserv_queue, true);
	for (i=0; i < clserv_num_workers; i++)
	{
		if (pthread_join(thread_ids[i], NULL) != 0)
			elog(LOG, "failed to join opencl worker thread %lu", i);
	}

	/* TODO: wait for completion of running jobs */

	proc_exit(0);
}

/*
 * pgstrom_opencl_server_startup
 *
 * startup routine to be called just after initialization of shared
 * memory segment.
 */
void
pgstrom_opencl_server_startup(uintptr_t start, uintptr_t end)
{
	int		i, rc;

	/* save the range of shared memory segment */
	shmem_start = start;
	shmem_end = end;

	/* open the request queue */
	clserv_queue = pgstrom_queue_alloc(true);

	/* init cldev_slot */
	memset(cldev_slot, 0, sizeof(cldev_slot));
	cldev_nums = 0;

	/* init clprog_slot */
	for (i=0; i < CLPROGRAM_SLOT_SIZE; i++)
	{
		dlist_init(&clprog_slot[i]);
		if ((rc = pthread_mutex_init(&clprog_lock[i], NULL)) != 0)
			elog(ERROR, "failed on pthread_mutex_init (%s)",
				 strerror(rc));
	}
}

void
pgstrom_opencl_server_init(void)
{
	BackgroundWorker    worker;

	DefineCustomIntVariable("pg_strom.opencl_num_workers",
							"number of opencl server worker threads",
							NULL,
							&clserv_num_workers,
							4,
							1,
							INT_MAX,
							PGC_SIGHUP,
							GUC_NOT_IN_SAMPLE,
							NULL, NULL, NULL);
	DefineCustomStringVariable("pg_strom.opencl_devices",
							   "list of opencl devices to be used",
							   NULL,
							   &clserv_opencl_devices,
							   "gpu",
							   PGC_SIGHUP,
							   GUC_NOT_IN_SAMPLE,
							   NULL, NULL, NULL);

	/* set up background worker process */
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

/*
 * clserv_enqueue_chunk
 *
 * It enqueues the supplied chunk into strom-queue of the opencl-server.
 * Note that this function should be invoked on the backend context.
 */
void
clserv_enqueue_chunk(ChunkBuffer *chunk)
{
	Assert(clserv_queue != NULL);
	if (!pgstrom_queue_enqueue(clserv_queue, &chunk->chain))
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("opencl server does not accept chunks any more")));
}
