/*
 * opencl_entry.c
 *
 * Entrypoint of OpenCL interfaces that should be resolved and linked
 * at run-time.
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
#include "pg_strom.h"
#include <dlfcn.h>
#include <CL/cl.h>
#include <CL/cl_ext.h>

#ifndef CL_VERSION_1_1
#error OpenCL 1.1 or later header files are needed
#endif

/*
 * Query Platform Info
 */
static cl_int (*p_clGetPlatformIDs)(
	cl_uint num_entries,
	cl_platform_id *platforms,
	cl_uint *num_platforms) = NULL;
static cl_int (*p_clGetPlatformInfo)(
	cl_platform_id platform,
	cl_platform_info param_name,
	size_t param_value_size,
	void *param_value,
	size_t *param_value_size_ret) = NULL;

cl_int
clGetPlatformIDs(cl_uint num_entries,
				 cl_platform_id *platforms,
				 cl_uint *num_platforms)
{
	Assert(p_clGetPlatformIDs != NULL);
	return (*p_clGetPlatformIDs)(num_entries,
								 platforms,
								 num_platforms);
}

cl_int
clGetPlatformInfo(cl_platform_id platform,
				  cl_platform_info param_name,
				  size_t param_value_size,
				  void *param_value,
				  size_t *param_value_size_ret)
{
	Assert(p_clGetPlatformInfo != NULL);
	return (*p_clGetPlatformInfo)(platform,
								  param_name,
								  param_value_size,
								  param_value,
								  param_value_size_ret);
}

/*
 * Query Devices
 */
static cl_int (*p_clGetDeviceIDs)(
	cl_platform_id platform,
	cl_device_type device_type,
	cl_uint num_entries,
	cl_device_id *devices,
	cl_uint *num_devices) = NULL;
static cl_int (*p_clGetDeviceInfo)(
	cl_device_id device,
	cl_device_info param_name,
	size_t param_value_size,
	void *param_value,
	size_t *param_value_size_ret) = NULL;

cl_int
clGetDeviceIDs(cl_platform_id platform,
			   cl_device_type device_type,
			   cl_uint num_entries,
			   cl_device_id *devices,
			   cl_uint *num_devices)
{
	Assert(p_clGetDeviceIDs != NULL);
	return (*p_clGetDeviceIDs)(platform,
							   device_type,
							   num_entries,
							   devices,
							   num_devices);
}

cl_int
clGetDeviceInfo(cl_device_id device,
				cl_device_info param_name,
				size_t param_value_size,
				void *param_value,
				size_t *param_value_size_ret)
{
	Assert(p_clGetDeviceInfo != NULL);
	return (*p_clGetDeviceInfo)(device,
								param_name,
								param_value_size,
								param_value,
								param_value_size_ret);
}

/*
 * Contexts
 */
static cl_context (*p_clCreateContext)(
	const cl_context_properties *properties,
	cl_uint num_devices,
	const cl_device_id *devices,
	void (CL_CALLBACK  *pfn_notify)(
		const char *errinfo, 
		const void *private_info, size_t cb, 
		void *user_data),
	void *user_data,
	cl_int *errcode_ret) = NULL;
static cl_context (*p_clCreateContextFromType)(
	const cl_context_properties   *properties,
	cl_device_type  device_type,
	void (CL_CALLBACK *pfn_notify)(
		const char *errinfo,
		const void  *private_info,
		size_t  cb,
		void  *user_data),
	void  *user_data,
	cl_int  *errcode_ret) = NULL;
static cl_int (*p_clRetainContext)(cl_context context) = NULL;
static cl_int (*p_clReleaseContext)(cl_context context) = NULL;
static cl_int (*p_clGetContextInfo)(
	cl_context context,
	cl_context_info param_name,
	size_t param_value_size,
	void *param_value,
	size_t * param_value_size_ret) = NULL;

cl_context
clCreateContext(const cl_context_properties *properties,
				cl_uint num_devices,
				const cl_device_id *devices,
				void (CL_CALLBACK  *pfn_notify)(
					const char *errinfo, 
					const void *private_info,
					size_t cb, 
					void *user_data),
				void *user_data,
				cl_int *errcode_ret)
{
	Assert(p_clCreateContext != NULL);
	return (*p_clCreateContext)(properties,
								num_devices,
								devices,
								pfn_notify,
								user_data,
								errcode_ret);
}

cl_context
clCreateContextFromType(const cl_context_properties *properties,
						cl_device_type  device_type,
						void (CL_CALLBACK *pfn_notify) (
							const char *errinfo,
							const void  *private_info,
							size_t  cb,
							void  *user_data),
						void  *user_data,
						cl_int  *errcode_ret)
{
	Assert(p_clCreateContextFromType != NULL);
	return (*p_clCreateContextFromType)(properties,
										device_type,
										pfn_notify,
										user_data,
										errcode_ret);
}

cl_int
clRetainContext(cl_context context)
{
	Assert(p_clRetainContext != NULL);
	return (*p_clRetainContext)(context);
}

cl_int
clReleaseContext(cl_context context)
{
	Assert(p_clReleaseContext != NULL);
	return (*p_clReleaseContext)(context);
}

cl_int
clGetContextInfo(cl_context context,
				 cl_context_info param_name,
				 size_t param_value_size,
				 void *param_value,
				 size_t * param_value_size_ret)
{
	Assert(p_clGetContextInfo != NULL);
	return (*p_clGetContextInfo)(context,
								 param_name,
								 param_value_size,
								 param_value,
								 param_value_size_ret);
}

/*
 * Command Queues
 */
static cl_command_queue (*p_clCreateCommandQueue)(
	cl_context context,
	cl_device_id device,
	cl_command_queue_properties properties,
	cl_int *errcode_ret) = NULL;
static cl_int (*p_clRetainCommandQueue)(
	cl_command_queue command_queue) = NULL;
static cl_int (*p_clReleaseCommandQueue)(
	cl_command_queue command_queue) = NULL;

cl_command_queue
clCreateCommandQueue(cl_context context,
					 cl_device_id device,
					 cl_command_queue_properties properties,
					 cl_int *errcode_ret)
{
	Assert(p_clCreateCommandQueue != NULL);
	return (*p_clCreateCommandQueue)(context,
									 device,
									 properties,
									 errcode_ret);
}

cl_int clRetainCommandQueue(cl_command_queue command_queue)
{
	Assert(p_clRetainCommandQueue != NULL);
	return (*p_clRetainCommandQueue)(command_queue);
}

cl_int
clReleaseCommandQueue(cl_command_queue command_queue)
{
	Assert(p_clReleaseCommandQueue != NULL);
	return (*p_clReleaseCommandQueue)(command_queue);
}

/*
 * Memory Objects
 */
static cl_mem (*p_clCreateBuffer)(
	cl_context context,
	cl_mem_flags flags,
	size_t size,
	void *host_ptr,
	cl_int *errcode_ret) = NULL;
static cl_mem (*p_clCreateSubBuffer)(
	cl_mem buffer,
	cl_mem_flags flags,
	cl_buffer_create_type buffer_create_type,
	const void *buffer_create_info,
	cl_int *errcode_ret) = NULL;
static cl_int (*p_clEnqueueReadBuffer)(
	cl_command_queue command_queue,
	cl_mem buffer,
	cl_bool blocking_read,
	size_t offset,
	size_t cb,
	void *ptr,
	cl_uint num_events_in_wait_list,
	const cl_event *event_wait_list,
	cl_event *event) = NULL;
static cl_int (*p_clEnqueueWriteBuffer)(
	cl_command_queue command_queue,
	cl_mem buffer,
	cl_bool blocking_write,
	size_t offset,
	size_t cb,
	const void *ptr,
	cl_uint num_events_in_wait_list,
	const cl_event *event_wait_list,
	cl_event *event) = NULL;
static cl_int (*p_clRetainMemObject)(cl_mem memobj) = NULL;
static cl_int (*p_clReleaseMemObject)(cl_mem memobj) = NULL;
static cl_int (*p_clSetMemObjectDestructorCallback)(
	cl_mem memobj,
	void (CL_CALLBACK  *pfn_notify) (cl_mem memobj,
									 void *user_data),
	void *user_data) = NULL;
static cl_int (*p_clGetMemObjectInfo)(
	cl_mem memobj,
	cl_mem_info param_name,
	size_t param_value_size,
	void *param_value,
	size_t *param_value_size_ret) = NULL;

cl_mem
clCreateBuffer(cl_context context,
			   cl_mem_flags flags,
			   size_t size,
			   void *host_ptr,
			   cl_int *errcode_ret)
{
	Assert(p_clCreateBuffer != NULL);
	return (*p_clCreateBuffer)(context,
							   flags,
							   size,
							   host_ptr,
							   errcode_ret);
}

cl_mem
clCreateSubBuffer(cl_mem buffer,
				  cl_mem_flags flags,
				  cl_buffer_create_type buffer_create_type,
				  const void *buffer_create_info,
				  cl_int *errcode_ret)
{
	Assert(p_clCreateSubBuffer != NULL);
	return (*p_clCreateSubBuffer)(buffer,
								  flags,
								  buffer_create_type,
								  buffer_create_info,
								  errcode_ret);
}

cl_int
clEnqueueReadBuffer(cl_command_queue command_queue,
					cl_mem buffer,
					cl_bool blocking_read,
					size_t offset,
					size_t cb,
					void *ptr,
					cl_uint num_events_in_wait_list,
					const cl_event *event_wait_list,
					cl_event *event)
{
	Assert(p_clEnqueueReadBuffer != NULL);
	return (*p_clEnqueueReadBuffer)(command_queue,
									buffer,
									blocking_read,
									offset,
									cb,
									ptr,
									num_events_in_wait_list,
									event_wait_list,
									event);
}

cl_int
clEnqueueWriteBuffer(cl_command_queue command_queue,
					 cl_mem buffer,
					 cl_bool blocking_write,
					 size_t offset,
					 size_t cb,
					 const void *ptr,
					 cl_uint num_events_in_wait_list,
					 const cl_event *event_wait_list,
					 cl_event *event)
{
	Assert(p_clEnqueueWriteBuffer != NULL);
	return (*p_clEnqueueWriteBuffer)(command_queue,
									 buffer,
									 blocking_write,
									 offset,
									 cb,
									 ptr,
									 num_events_in_wait_list,
									 event_wait_list,
									 event);
}

cl_int
clRetainMemObject(cl_mem memobj)
{
	Assert(p_clRetainMemObject != NULL);
	return (*p_clRetainMemObject)(memobj);
}

cl_int
clReleaseMemObject(cl_mem memobj)
{
	Assert(p_clReleaseMemObject != NULL);
	return (*p_clReleaseMemObject)(memobj);
}

cl_int
clSetMemObjectDestructorCallback(cl_mem memobj,
								 void (CL_CALLBACK  *pfn_notify) (
									 cl_mem memobj,
									 void *user_data),
								 void *user_data)
{
	Assert(p_clSetMemObjectDestructorCallback != NULL);
	return (*p_clSetMemObjectDestructorCallback)(memobj,
												 pfn_notify,
												 user_data);
}

cl_int
clGetMemObjectInfo(cl_mem memobj,
				   cl_mem_info param_name,
				   size_t param_value_size,
				   void *param_value,
				   size_t *param_value_size_ret)
{
	Assert(p_clGetMemObjectInfo != NULL);
	return (*p_clGetMemObjectInfo)(memobj,
								   param_name,
								   param_value_size,
								   param_value,
								   param_value_size_ret);
}

/*
 * Program Objects
 */
static cl_program (*p_clCreateProgramWithSource)(
	cl_context context,
	cl_uint count,
	const char **strings,
	const size_t *lengths,
	cl_int *errcode_ret) = NULL;
static cl_program (*p_clCreateProgramWithBinary)(
	cl_context context,
	cl_uint num_devices,
	const cl_device_id *device_list,
	const size_t *lengths,
	const unsigned char **binaries,
	cl_int *binary_status,
	cl_int *errcode_ret) = NULL;

static cl_int (*p_clRetainProgram)(cl_program program) = NULL;
static cl_int (*p_clReleaseProgram)(cl_program program) = NULL;
static cl_int (*p_clUnloadCompiler)(void) = NULL;
static cl_int (*p_clBuildProgram)(
	cl_program program,
	cl_uint num_devices,
	const cl_device_id *device_list,
	const char *options,
	void (CL_CALLBACK *pfn_notify)(
		cl_program program,
		void *user_data),
	void *user_data) = NULL;
static cl_int (*p_clGetProgramInfo)(
	cl_program program,
	cl_program_info param_name,
	size_t param_value_size,
	void *param_value,
	size_t *param_value_size_ret) = NULL;
static cl_int (*p_clGetProgramBuildInfo)(
	cl_program  program,
	cl_device_id  device,
	cl_program_build_info  param_name,
	size_t  param_value_size,
	void  *param_value,
	size_t  *param_value_size_ret) = NULL;

cl_program
clCreateProgramWithSource(cl_context context,
						  cl_uint count,
						  const char **strings,
						  const size_t *lengths,
						  cl_int *errcode_ret)
{
	Assert(p_clCreateProgramWithSource != NULL);
	return (*p_clCreateProgramWithSource)(context,
										  count,
										  strings,
										  lengths,
										  errcode_ret);
}

cl_program
clCreateProgramWithBinary(cl_context context,
						  cl_uint num_devices,
						  const cl_device_id *device_list,
						  const size_t *lengths,
						  const unsigned char **binaries,
						  cl_int *binary_status,
						  cl_int *errcode_ret)
{
	Assert(p_clCreateProgramWithBinary != NULL);
	return (*p_clCreateProgramWithBinary)(context,
										  num_devices,
										  device_list,
										  lengths,
										  binaries,
										  binary_status,
										  errcode_ret);
}

cl_int
clRetainProgram(cl_program program)
{
	Assert(p_clRetainProgram != NULL);
	return (*p_clRetainProgram)(program);
}

cl_int
clReleaseProgram(cl_program program)
{
	Assert(p_clReleaseProgram != NULL);
	return (*p_clReleaseProgram)(program);
}

cl_int
clUnloadCompiler(void)
{
	Assert(p_clUnloadCompiler != NULL);
	return (*p_clUnloadCompiler)();
}

cl_int
clBuildProgram(cl_program program,
			   cl_uint num_devices,
			   const cl_device_id *device_list,
			   const char *options,
			   void (CL_CALLBACK *pfn_notify)(
				   cl_program program,
				   void *user_data),
			   void *user_data)
{
	Assert(p_clBuildProgram != NULL);
	return (*p_clBuildProgram)(program,
							   num_devices,
							   device_list,
							   options,
							   pfn_notify,
							   user_data);
}

cl_int
clGetProgramInfo(cl_program program,
				 cl_program_info param_name,
				 size_t param_value_size,
				 void *param_value,
				 size_t *param_value_size_ret)
{
	Assert(p_clGetProgramInfo != NULL);
	return (*p_clGetProgramInfo)(program,
								 param_name,
								 param_value_size,
								 param_value,
								 param_value_size_ret);
}

cl_int
clGetProgramBuildInfo(cl_program program,
					  cl_device_id device,
					  cl_program_build_info param_name,
					  size_t param_value_size,
					  void *param_value,
					  size_t *param_value_size_ret)
{
	Assert(p_clGetProgramBuildInfo != NULL);
	return (*p_clGetProgramBuildInfo)(program,
									  device,
									  param_name,
									  param_value_size,
									  param_value,
									  param_value_size_ret);
}

/*
 * Kernel Objects
 */
static cl_kernel (*p_clCreateKernel)(
	cl_program  program,
	const char *kernel_name,
	cl_int *errcode_ret) = NULL;
static cl_int (*p_clCreateKernelsInProgram)(
	cl_program  program,
	cl_uint num_kernels,
	cl_kernel *kernels,
	cl_uint *num_kernels_ret) = NULL;
static cl_int (*p_clRetainKernel)(cl_kernel kernel) = NULL;
static cl_int (*p_clReleaseKernel)(cl_kernel kernel) = NULL;
static cl_int (*p_clSetKernelArg)(
	cl_kernel kernel,
	cl_uint arg_index,
	size_t arg_size,
	const void *arg_value) = NULL;
static cl_int (*p_clGetKernelInfo)(
	cl_kernel kernel,
	cl_kernel_info param_name,
	size_t param_value_size,
	void *param_value,
	size_t *param_value_size_ret) = NULL;
static cl_int (*p_clGetKernelWorkGroupInfo)(
	cl_kernel kernel,
	cl_device_id device,
	cl_kernel_work_group_info param_name,
	size_t param_value_size,
	void *param_value,
	size_t *param_value_size_ret) = NULL;

cl_kernel
clCreateKernel(cl_program  program,
			   const char *kernel_name,
			   cl_int *errcode_ret)
{
	Assert(p_clCreateKernel != NULL);
	return (*p_clCreateKernel)(program,
							   kernel_name,
							   errcode_ret);
}

cl_int
clCreateKernelsInProgram(cl_program  program,
						 cl_uint num_kernels,
						 cl_kernel *kernels,
						 cl_uint *num_kernels_ret)
{
	Assert(p_clCreateKernelsInProgram != NULL);
	return (*p_clCreateKernelsInProgram)(program,
										 num_kernels,
										 kernels,
										 num_kernels_ret);
}

cl_int
clRetainKernel(cl_kernel kernel)
{
	Assert(p_clRetainKernel != NULL);
	return (*p_clRetainKernel)(kernel);
}

cl_int
clReleaseKernel(cl_kernel kernel)
{
	Assert(p_clReleaseKernel != NULL);
	return (*p_clReleaseKernel)(kernel);
}

cl_int
clSetKernelArg(cl_kernel kernel,
			   cl_uint arg_index,
			   size_t arg_size,
			   const void *arg_value)
{
	Assert(p_clSetKernelArg != NULL);
	return (*p_clSetKernelArg)(kernel,
							   arg_index,
							   arg_size,
							   arg_value);
}

cl_int
clGetKernelInfo(cl_kernel kernel,
				cl_kernel_info param_name,
				size_t param_value_size,
				void *param_value,
				size_t *param_value_size_ret)
{
	Assert(p_clGetKernelInfo != NULL);
	return (*p_clGetKernelInfo)(kernel,
								param_name,
								param_value_size,
								param_value,
								param_value_size_ret);
}

cl_int
clGetKernelWorkGroupInfo(cl_kernel kernel,
						 cl_device_id device,
						 cl_kernel_work_group_info param_name,
						 size_t param_value_size,
						 void *param_value,
						 size_t *param_value_size_ret)
{
	Assert(p_clGetKernelWorkGroupInfo != NULL);
	return (*p_clGetKernelWorkGroupInfo)(kernel,
										 device,
										 param_name,
										 param_value_size,
										 param_value,
										 param_value_size_ret);
}

/*
 * Executing Kernels
 */
static cl_int (*p_clEnqueueNDRangeKernel)(
	cl_command_queue command_queue,
	cl_kernel kernel,
	cl_uint work_dim,
	const size_t *global_work_offset,
	const size_t *global_work_size,
	const size_t *local_work_size,
	cl_uint num_events_in_wait_list,
	const cl_event *event_wait_list,
	cl_event *event) = NULL;
static cl_int (*p_clEnqueueTask)(
	cl_command_queue command_queue,
	cl_kernel kernel,
	cl_uint num_events_in_wait_list,
	const cl_event *event_wait_list,
	cl_event *event) = NULL;
static cl_int (*p_clEnqueueNativeKernel)(
	cl_command_queue command_queue,
	void (*user_func)(void *),
	void *args,
	size_t cb_args,
	cl_uint num_mem_objects,
	const cl_mem *mem_list,
	const void **args_mem_loc,
	cl_uint num_events_in_wait_list,
	const cl_event *event_wait_list,
	cl_event *event) = NULL;
#ifdef CL_VERSION_1_2
static cl_int (*p_clEnqueueMarkerWithWaitList)(
	cl_command_queue  command_queue,
	cl_uint  num_events_in_wait_list,
	const cl_event  *event_wait_list,
	cl_event *event) = NULL;
static cl_int (*p_clEnqueueBarrierWithWaitList)(
	cl_command_queue  command_queue,
	cl_uint  num_events_in_wait_list,
	const cl_event  *event_wait_list ,
	cl_event  *event) = NULL;
#else
static cl_int (*p_clEnqueueMarker)(
	cl_command_queue command_queue,
	cl_event *event) = NULL;
static cl_int (*p_clEnqueueBarrier)(
	cl_command_queue command_queue) = NULL;
static cl_int (*p_clEnqueueWaitForEvents)(
	cl_command_queue command_queue,
	cl_uint num_events,
	const cl_event *event_list) = NULL;
#endif

cl_int
clEnqueueNDRangeKernel(cl_command_queue command_queue,
					   cl_kernel kernel,
					   cl_uint work_dim,
					   const size_t *global_work_offset,
					   const size_t *global_work_size,
					   const size_t *local_work_size,
					   cl_uint num_events_in_wait_list,
					   const cl_event *event_wait_list,
					   cl_event *event)
{
	Assert(p_clEnqueueNDRangeKernel != NULL);
	return (*p_clEnqueueNDRangeKernel)(command_queue,
									   kernel,
									   work_dim,
									   global_work_offset,
									   global_work_size,
									   local_work_size,
									   num_events_in_wait_list,
									   event_wait_list,
									   event);
}

cl_int
clEnqueueTask(cl_command_queue command_queue,
			  cl_kernel kernel,
			  cl_uint num_events_in_wait_list,
			  const cl_event *event_wait_list,
			  cl_event *event)
{
	Assert(p_clEnqueueTask != NULL);
	return (*p_clEnqueueTask)(command_queue,
							  kernel,
							  num_events_in_wait_list,
							  event_wait_list,
							  event);
}

cl_int
clEnqueueNativeKernel(cl_command_queue command_queue,
					  void (*user_func)(void *),
					  void *args,
					  size_t cb_args,
					  cl_uint num_mem_objects,
					  const cl_mem *mem_list,
					  const void **args_mem_loc,
					  cl_uint num_events_in_wait_list,
					  const cl_event *event_wait_list,
					  cl_event *event)
{
	Assert(p_clEnqueueNativeKernel != NULL);
	return (*p_clEnqueueNativeKernel)(command_queue,
									  user_func,
									  args,
									  cb_args,
									  num_mem_objects,
									  mem_list,
									  args_mem_loc,
									  num_events_in_wait_list,
									  event_wait_list,
									  event);
}

#ifdef CL_VERSION_1_2
cl_int
clEnqueueMarkerWithWaitList(cl_command_queue command_queue,
							cl_uint num_events_in_wait_list,
							const cl_event *event_wait_list,
							cl_event *event)
{
	Assert(p_clEnqueueMarkerWithWaitList != NULL);
	return (*p_clEnqueueMarkerWithWaitList)(command_queue,
											num_events_in_wait_list,
											event_wait_list,
											event);
}

cl_int
clEnqueueBarrierWithWaitList(cl_command_queue command_queue,
							 cl_uint num_events_in_wait_list,
							 const cl_event *event_wait_list,
							 cl_event *event)
{
	Assert(p_clEnqueueBarrierWithWaitList != NULL);
	return (*p_clEnqueueBarrierWithWaitList)(command_queue,
											 num_events_in_wait_list,
											 event_wait_list,
											 event);
}
#else
cl_int
clEnqueueMarker(cl_command_queue command_queue,
				cl_event *event)
{
	Assert(p_clEnqueueMarker != NULL);
	return (*p_clEnqueueMarker)(command_queue, event);
}

cl_int
clEnqueueBarrier(cl_command_queue command_queue)
{
	Assert(p_clEnqueueBarrier != NULL);
	return (*p_clEnqueueBarrier)(command_queue);
}

cl_int
clEnqueueWaitForEvents(cl_command_queue command_queue,
					   cl_uint num_events,
					   const cl_event *event_list)
{
	Assert(p_clEnqueueWaitForEvents != NULL);
	return (*p_clEnqueueWaitForEvents)(command_queue,
									   num_events,
									   event_list);
}
#endif

/*
 * Event Objects
 */
static cl_event (*p_clCreateUserEvent)(
	cl_context context,
	cl_int *errcode_ret) = NULL;
static cl_int (*p_clSetUserEventStatus)(
	cl_event event,
	cl_int execution_status) = NULL;
static cl_int (*p_clWaitForEvents)(
	cl_uint num_events,
	const cl_event *event_list) = NULL;
static cl_int (*p_clGetEventInfo)(
	cl_event event,
	cl_event_info param_name,
	size_t param_value_size,
	void *param_value,
	size_t *param_value_size_ret) = NULL;
static cl_int (*p_clSetEventCallback)(
	cl_event event,
	cl_int  command_exec_callback_type ,
	void (CL_CALLBACK  *pfn_event_notify)(
		cl_event event,
		cl_int event_command_exec_status,
		void *user_data),
	void *user_data) = NULL;
static cl_int (*p_clRetainEvent)(cl_event event) = NULL;
static cl_int (*p_clReleaseEvent)(cl_event event) = NULL;

cl_event
clCreateUserEvent(cl_context context,
				  cl_int *errcode_ret)
{
	Assert(p_clCreateUserEvent != NULL);
	return (*p_clCreateUserEvent)(context, errcode_ret);
}

cl_int
clSetUserEventStatus(cl_event event,
					 cl_int execution_status)
{
	Assert(p_clSetUserEventStatus != NULL);
	return (*p_clSetUserEventStatus)(event, execution_status);
}

cl_int
clWaitForEvents(cl_uint num_events,
				const cl_event *event_list)
{
	Assert(p_clWaitForEvents != NULL);
	return (*p_clWaitForEvents)(num_events, event_list);
}

cl_int
clGetEventInfo(cl_event event,
			   cl_event_info param_name,
			   size_t param_value_size,
			   void *param_value,
			   size_t *param_value_size_ret)
{
	Assert(p_clGetEventInfo != NULL);
	return (*p_clGetEventInfo)(event,
							   param_name,
							   param_value_size,
							   param_value,
							   param_value_size_ret);
}

cl_int
clSetEventCallback(cl_event event,
				   cl_int command_exec_callback_type ,
				   void (CL_CALLBACK  *pfn_event_notify)(
					   cl_event event,
					   cl_int event_command_exec_status,
					   void *user_data),
				   void *user_data)
{
	Assert(p_clSetEventCallback != NULL);
	return (*p_clSetEventCallback)(event,
								   command_exec_callback_type,
								   pfn_event_notify,
								   user_data);
}

cl_int
clRetainEvent(cl_event event)
{
	Assert(p_clRetainEvent != NULL);
	return (*p_clRetainEvent)(event);
}

cl_int
clReleaseEvent(cl_event event)
{
	Assert(p_clReleaseEvent != NULL);
	return (*p_clReleaseEvent)(event);
}

/*
 * Profiling
 */
static cl_int (*p_clGetEventProfilingInfo)(
	cl_event event,
	cl_profiling_info param_name,
	size_t param_value_size,
	void *param_value,
	size_t *param_value_size_ret) = NULL;

cl_int
clGetEventProfilingInfo(cl_event event,
						cl_profiling_info param_name,
						size_t param_value_size,
						void *param_value,
						size_t *param_value_size_ret)
{
	Assert(p_clGetEventProfilingInfo != NULL);
	return (*p_clGetEventProfilingInfo)(event,
										param_name,
										param_value_size,
										param_value,
										param_value_size_ret);
}

/*
 * Flush and Finish
 */
static cl_int (*p_clFlush)(cl_command_queue command_queue) = NULL;
static cl_int (*p_clFinish)(cl_command_queue command_queue) = NULL;

cl_int
clFlush(cl_command_queue command_queue)
{
	Assert(p_clFlush != NULL);
	return (*p_clFlush)(command_queue);
}

cl_int
clFinish(cl_command_queue command_queue)
{
	Assert(p_clFinish != NULL);
	return (*p_clFinish)(command_queue);
}

/*
 * Init OpenCL entrypoint
 */
static void *
lookup_opencl_function(void *handle, const char *func_name)
{
	void   *func_addr = dlsym(handle, func_name);

	if (!func_addr)
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("could not find symbol \"%s\" - %s",
						func_name, dlerror())));
	return func_addr;
}

#define LOOKUP_OPENCL_FUNCTION(func_name)			\
	p_##func_name = lookup_opencl_function(handle, #func_name)

void
pgstrom_opencl_entry_init(void)
{
	void   *handle;

	handle = dlopen("libOpenCL.so", RTLD_NOW | RTLD_LOCAL);
	if (!handle)
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not open OpenCL library: %s", dlerror())));
	PG_TRY();
	{
		/* Query Platform Info */
		LOOKUP_OPENCL_FUNCTION(clGetPlatformIDs);
		LOOKUP_OPENCL_FUNCTION(clGetPlatformInfo);
		/* Query Devices */
		LOOKUP_OPENCL_FUNCTION(clGetDeviceIDs);
		LOOKUP_OPENCL_FUNCTION(clGetDeviceInfo);
		/* Contexts */
		LOOKUP_OPENCL_FUNCTION(clCreateContext);
		LOOKUP_OPENCL_FUNCTION(clCreateContextFromType);
		LOOKUP_OPENCL_FUNCTION(clRetainContext);
		LOOKUP_OPENCL_FUNCTION(clReleaseContext);
		LOOKUP_OPENCL_FUNCTION(clGetContextInfo);
		/* Command Queues */
		LOOKUP_OPENCL_FUNCTION(clCreateCommandQueue);
		LOOKUP_OPENCL_FUNCTION(clRetainCommandQueue);
		LOOKUP_OPENCL_FUNCTION(clReleaseCommandQueue);
		/* Memory Objects (partial) */
		LOOKUP_OPENCL_FUNCTION(clCreateBuffer);
		LOOKUP_OPENCL_FUNCTION(clCreateSubBuffer);
		LOOKUP_OPENCL_FUNCTION(clEnqueueReadBuffer);
		LOOKUP_OPENCL_FUNCTION(clEnqueueWriteBuffer);
		LOOKUP_OPENCL_FUNCTION(clRetainMemObject);
		LOOKUP_OPENCL_FUNCTION(clReleaseMemObject);
		LOOKUP_OPENCL_FUNCTION(clSetMemObjectDestructorCallback);
		LOOKUP_OPENCL_FUNCTION(clGetMemObjectInfo);
		/* Program Objects */
		LOOKUP_OPENCL_FUNCTION(clCreateProgramWithSource);
		LOOKUP_OPENCL_FUNCTION(clCreateProgramWithBinary);
		LOOKUP_OPENCL_FUNCTION(clRetainProgram);
		LOOKUP_OPENCL_FUNCTION(clReleaseProgram);
		LOOKUP_OPENCL_FUNCTION(clUnloadCompiler);
		LOOKUP_OPENCL_FUNCTION(clBuildProgram);
		LOOKUP_OPENCL_FUNCTION(clGetProgramInfo);
		LOOKUP_OPENCL_FUNCTION(clGetProgramBuildInfo);
		/* Kernel Objects */
		LOOKUP_OPENCL_FUNCTION(clCreateKernel);
		LOOKUP_OPENCL_FUNCTION(clCreateKernelsInProgram);
		LOOKUP_OPENCL_FUNCTION(clRetainKernel);
		LOOKUP_OPENCL_FUNCTION(clReleaseKernel);
		LOOKUP_OPENCL_FUNCTION(clSetKernelArg);
		LOOKUP_OPENCL_FUNCTION(clGetKernelInfo);
		LOOKUP_OPENCL_FUNCTION(clGetKernelWorkGroupInfo);
		/* Executing Kernels */
		LOOKUP_OPENCL_FUNCTION(clEnqueueNDRangeKernel);
		LOOKUP_OPENCL_FUNCTION(clEnqueueTask);
		LOOKUP_OPENCL_FUNCTION(clEnqueueNativeKernel);
#ifdef CL_VERSION_1_2
		LOOKUP_OPENCL_FUNCTION(clEnqueueMarkerWithWaitList);
		LOOKUP_OPENCL_FUNCTION(clEnqueueBarrierWithWaitList);
#else
		LOOKUP_OPENCL_FUNCTION(clEnqueueMarker);
		LOOKUP_OPENCL_FUNCTION(clEnqueueBarrier);
		LOOKUP_OPENCL_FUNCTION(clEnqueueWaitForEvents);
#endif
		/* Event Objects */
		LOOKUP_OPENCL_FUNCTION(clCreateUserEvent);
		LOOKUP_OPENCL_FUNCTION(clSetUserEventStatus);
		LOOKUP_OPENCL_FUNCTION(clWaitForEvents);
		LOOKUP_OPENCL_FUNCTION(clGetEventInfo);
		LOOKUP_OPENCL_FUNCTION(clSetEventCallback);
		LOOKUP_OPENCL_FUNCTION(clRetainEvent);
		LOOKUP_OPENCL_FUNCTION(clReleaseEvent);
		/* Profiling */
		LOOKUP_OPENCL_FUNCTION(clGetEventProfilingInfo);
		/* Flush and Finish */
		LOOKUP_OPENCL_FUNCTION(clFlush);
		LOOKUP_OPENCL_FUNCTION(clFinish);
	}
	PG_CATCH();
	{
		dlclose(handle);
		PG_RE_THROW();
	}
	PG_END_TRY();
}
