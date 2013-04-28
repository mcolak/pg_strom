/*
 * shmem.c
 *
 * Routines to manage shared memory segment & queues
 *
 * --
 * Copyright 2013 (c) PG-Strom Development Team
 * Copyright 2012-2013 (c) KaiGai Kohei <kaigai@kaigai.gr.jp>
 *
 * This software is an extension of PostgreSQL; You can use, copy,
 * modify or distribute it under the terms of 'LICENSE' included
 * within this package.
 */
#include "postgres.h"
#include "catalog/pg_type.h"
#include "funcapi.h"
#include "storage/ipc.h"
#include "utils/builtins.h"
#include "utils/guc.h"
#include "utils/memutils.h"
#include "pg_strom.h"
#include <limits.h>
#include <unistd.h>

#define SHMEM_BLOCK_FREE			0xF9EEA9EA
#define SHMEM_BLOCK_USED			0xA110CED0
#define SHMEM_BLOCK_USED_MASK		0xfffffff0
#define SHMEM_BLOCK_OVERRUN_MARK	0xDEADBEAF
#define SHMEM_BLOCK_STROM_QUEUE		(SHMEM_BLOCK_USED | 0x01)
#define SHMEM_BLOCK_KERNEL_PARAMS	(SHMEM_BLOCK_USED | 0x02)
#define SHMEM_BLOCK_CHUNK_BUFFER	(SHMEM_BLOCK_USED | 0x03)
#define SHMEM_BLOCK_VARLENA_BUFFER	(SHMEM_BLOCK_USED | 0x04)
#define SHMEM_BLOCK_DEVICE_PROPERTY	(SHMEM_BLOCK_USED | 0x05)

#define SHMEM_BLOCK_OVERRUN_MARKER(block)	\
	(*((uint32 *)(((char *)(block)) + (block)->size - sizeof(uint32))))

typedef struct {
	uint32			magic;		/* one of SHMEM_BLOCK_* */
	Size			size;		/* size of this block includes metadata */
	dlist_node		addr_list;	/* list in order of address */
	dlist_node		free_list;	/* list of free blocks, if free block.
								 * Also note that this field is used to
								 * chain this block on the private hash
								 * slot to track blocks being allocated
								 * on a particular processes.
								 */
	pid_t			pid;		/* pid of process that uses this block */
	ResourceOwner	owner;		/* transaction owner of this block */
	Datum			data[0];
} ShmemBlock;

typedef struct {
	Size			total_size;	/* size of total shmem segment */
	Size			free_size;	/* size of total free area */
	dlist_head		addr_head;	/* list head of all nodes in address oder */
	dlist_head		free_head;	/* list head of free blocks  */
	pthread_mutex_t	lock;

	/* for device properties */
	dlist_head			dev_head;	/* head of device properties */
	pthread_rwlock_t	dev_lock;	/* lock of device properties */

	ShmemBlock		first_block[0];
} ShmemHead;

static int						pgstrom_shmem_size;
static pthread_mutexattr_t		shmem_mutex_attr;
static pthread_rwlockattr_t		shmem_rwlock_attr;
static pthread_condattr_t		shmem_cond_attr;
static dlist_head				shmem_private_track;
static shmem_startup_hook_type	shmem_startup_hook_next = NULL;
static ShmemHead			   *pgstrom_shmem_head;

/*
 * Utility routines of synchronization objects
 */
bool
pgstrom_mutex_init(pthread_mutex_t *mutex)
{
	int		rc;

	if ((rc = pthread_mutex_init(mutex, &shmem_mutex_attr)) != 0)
	{
		elog(NOTICE, "failed to initialize mutex at %p (%s)",
			 mutex, strerror(rc));
		return false;
	}
	return true;
}

bool
pgstrom_rwlock_init(pthread_rwlock_t *rwlock)
{
	int		rc;

	if ((rc = pthread_rwlock_init(rwlock, &shmem_rwlock_attr)) != 0)
	{
		elog(NOTICE, "failed to initialize rwlock at %p (%s)",
			 rwlock, strerror(rc));
		return false;
	}
	return true;
}

bool
pgstrom_cond_init(pthread_cond_t *cond, pthread_mutex_t *mutex)
{
	int		rc;

	if ((rc = pthread_mutex_init(mutex, &shmem_mutex_attr)) != 0)
    {
        elog(NOTICE, "failed to initialize mutex at %p (%s)",
             mutex, strerror(rc));
        return false;
    }

	if ((rc = pthread_cond_init(cond, &shmem_cond_attr)) != 0)
	{
		elog(NOTICE, "failed to initialize conditional variable at %p (%s)",
			 cond, strerror(rc));
		pthread_mutex_destroy(mutex);
		return false;
	}
	return true;
}

/*
 * pgstrom_cond_wait - wait for wake-up of conditional variable
 *
 * XXX - Note that this function may wake-up by signal. Even if it backs
 * control the caller, don't forget to check whether the condition is
 * really satisfied, or not. So, typical coding style shall be as follows.
 *
 * pthread_mutex_lock(&lock);
 * do {
 *     if (!pgstrom_cond_wait(&cond, &lock, 1000))
 *         break;     // timeout
 *     if (!queue_has_item)
 *         continue;  // signal interruption
 *     // do the works to be synchronized
 *     break;
 * } while(true);
 * pthread_mutex_unlock(&lock)
 */
bool
pgstrom_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex,
				  unsigned int timeout)
{
	int		rc;

	if (timeout > 0)
	{
		struct timespec	abstime;
		struct timeval tv;

		gettimeofday(&tv, NULL);
		abstime.tv_sec = tv.tv_sec + timeout / 1000;
		abstime.tv_nsec = (tv.tv_usec + (timeout % 1000) * 1000) * 1000;

		rc = pthread_cond_timedwait(cond, mutex, &abstime);
	}
	else
		rc = pthread_cond_wait(cond, mutex);

	Assert(rc == 0 || rc == ETIMEDOUT);

	return (rc == 0 ? true : false);
}

/*
 * Routines to allocate / free shared memory region
 */
static void
pgstrom_shmem_free(ShmemBlock *block)
{
	ShmemBlock	   *prev;
	ShmemBlock	   *next;
	dlist_node	   *temp;

	Assert((block->magic & SHMEM_BLOCK_USED_MASK) == SHMEM_BLOCK_USED);
	Assert(SHMEM_BLOCK_OVERRUN_MARKER(block) == SHMEM_BLOCK_OVERRUN_MARK);

	pthread_mutex_lock(&pgstrom_shmem_head->lock);
	pgstrom_shmem_head->free_size += block->size;

	/* merge, if previous block is also free */
	if (dlist_has_prev(&pgstrom_shmem_head->addr_head, &block->addr_list))
	{
		temp = dlist_prev_node(&pgstrom_shmem_head->addr_head,
							   &block->addr_list);
		prev = dlist_container(ShmemBlock, addr_list, temp);

		if (prev->magic == SHMEM_BLOCK_FREE)
		{
			dlist_delete(&block->addr_list);
			dlist_delete(&prev->free_list);
			prev->size += block->size;
			block = prev;
		}
	}

	/* merge, if next block is also free */
	if (dlist_has_next(&pgstrom_shmem_head->addr_head, &block->addr_list))
	{
		temp = dlist_next_node(&pgstrom_shmem_head->addr_head,
							   &block->addr_list);
		next = dlist_container(ShmemBlock, addr_list, temp);

		if (next->magic == SHMEM_BLOCK_FREE)
		{
			dlist_delete(&next->addr_list);
			dlist_delete(&next->free_list);
			block->size += next->size;
		}
	}
	block->magic = SHMEM_BLOCK_FREE;
	dlist_push_head(&pgstrom_shmem_head->free_head, &block->free_list);

	pthread_mutex_unlock(&pgstrom_shmem_head->lock);
}

static ShmemBlock *
pgstrom_shmem_alloc(uint32 magic, Size size)
{
	ShmemBlock *block = NULL;
	dlist_iter	iter;
	Size		required;

	required = MAXALIGN(offsetof(ShmemBlock, data) +
						MAXALIGN(size) + sizeof(uint32));

	pthread_mutex_lock(&pgstrom_shmem_head->lock);
	dlist_foreach(iter, &pgstrom_shmem_head->free_head)
	{
		block = dlist_container(ShmemBlock, free_list, iter.cur);

		Assert(block->magic == SHMEM_BLOCK_FREE);

		/*
		 * Size of the current free block is not enough to assign shared
		 * memory block with required size, so we try next free block.
		 */
		if (block->size < required)
			continue;

		/*
		 * In case when size of the current free block is similar to the 
		 * required size, we replace whole the block for the requirement
		 * to avoid management overhead on such a small fraction.
		 */
		if (block->size < required + 4096)
		{
			dlist_delete(&block->free_list);
			block->magic = magic;
			pgstrom_shmem_head->free_size -= block->size;
		}
		else
		{
			ShmemBlock *block_new;

			dlist_delete(&block->free_list);

			block_new = (ShmemBlock *) (((char *) block) + required);
			block_new->magic = SHMEM_BLOCK_FREE;
			dlist_insert_after(&block->addr_list, &block_new->addr_list);
			dlist_push_head(&pgstrom_shmem_head->free_head,
							&block_new->free_list);
			block_new->size = block->size - required;

			Assert((magic & SHMEM_BLOCK_USED_MASK) == SHMEM_BLOCK_USED);
			block->magic = magic;
			block->size = required;
			pgstrom_shmem_head->free_size -= block->size;
		}
		break;
	}
	pthread_mutex_unlock(&pgstrom_shmem_head->lock);

	if (block)
	{
		block->pid = getpid();
		block->owner = CurrentResourceOwner;
		SHMEM_BLOCK_OVERRUN_MARKER(block) = SHMEM_BLOCK_OVERRUN_MARK;
	}
	return block;
}

/*
 * pgstrom_shmem_cleanup
 *
 * callback routine to cleanup shared memory block being acquired 
 */
static void
pgstrom_shmem_cleanup(ResourceReleasePhase phase,
					  bool is_commit,
					  bool is_toplevel,
					  void *arg)
{
	dlist_mutable_iter	iter;
	ShmemBlock	   *block;

	if (phase != RESOURCE_RELEASE_AFTER_LOCKS)
		return;

	/*
	 * Step.1 - Release chunk-buffers and relevant varlena-buffers,
	 * and wait for completion of its execution if it is running.
	 */
	dlist_foreach_modify(iter, &shmem_private_track)
	{
		block = dlist_container(ShmemBlock, free_list, iter.cur);

		/*
		 * All blocks should be already released on regular code path
		 * when transaction is normally committed.
		 */
		Assert(!is_commit);

		/* No free blocks should appeared */
		Assert((block->magic & SHMEM_BLOCK_USED_MASK) == SHMEM_BLOCK_USED);

		/*
		 * Only blocks relevant to CurrentResourceOwner shall be released.
		 */
		if (block->owner != CurrentResourceOwner)
			continue;

		if (block->magic == SHMEM_BLOCK_CHUNK_BUFFER)
		{
			ChunkBuffer *chunk = (ChunkBuffer *)block->data;

			/*
			 * Wait for completion of kernel-execution on this chunk
			 */
		retry:
			pgstrom_cond_wait(&chunk->cond, &chunk->lock, 30*1000);
			if (chunk->is_running)
			{
				pthread_mutex_unlock(&chunk->lock);
				elog(LOG, "waiting for completion of kernel execution...");
				goto retry;
			}
			pthread_mutex_unlock(&chunk->lock);

			/*
			 * Note: relevant varlena-buffers are also released
			 * at pgstrom_chunk_buffer_free()
			 */
			pgstrom_chunk_buffer_free(chunk);
		}
	}

	/*
	 * Step.2 - Release Kernel-Params buffers
	 */
	dlist_foreach_modify(iter, &shmem_private_track)
	{
		block = dlist_container(ShmemBlock, free_list, iter.cur);

		/* See above */
		if (block->owner != CurrentResourceOwner)
			continue;

		if (block->magic == SHMEM_BLOCK_KERNEL_PARAMS)
			pgstrom_kernel_params_free((KernelParams *)block->data);
	}

	/*
	 * Step.3 - Release queues that should not have any valid items yet
	 */
	dlist_foreach_modify(iter, &shmem_private_track)
	{
		block = dlist_container(ShmemBlock, free_list, iter.cur);

		/* See above */
		if (block->owner != CurrentResourceOwner)
			continue;

		Assert(block->magic == SHMEM_BLOCK_STROM_QUEUE);
		pgstrom_queue_free((StromQueue *)block->data);
	}
}

/*
 * Routines for PG-Strom Queue
 */
StromQueue *
pgstrom_queue_alloc(bool abort_on_error)
{
	StromQueue *queue;
	ShmemBlock *block;

	block = pgstrom_shmem_alloc(SHMEM_BLOCK_STROM_QUEUE, sizeof(StromQueue));
	if (!block)
	{
		if (abort_on_error)
			ereport(ERROR,
					(errcode(ERRCODE_FDW_OUT_OF_MEMORY),
					 errmsg("out of shared memory segment"),
					 errhint("enlarge pg_strom.shmem_size")));
		return NULL;
	}
	queue = (StromQueue *)block->data;
	dlist_init(&queue->head);
	if (!pgstrom_cond_init(&queue->cond, &queue->lock))
	{
		pgstrom_shmem_free(block);
		if (abort_on_error)
			ereport(ERROR,
					(errcode(ERRCODE_INTERNAL_ERROR),
					 errmsg("failed to init mutex object")));
		return NULL;
	}
	queue->is_shutdown = false;

	/* add this block into private tracker */
	dlist_push_tail(&shmem_private_track, &block->free_list);

	return queue;
}

void
pgstrom_queue_free(StromQueue *queue)
{
	ShmemBlock *block = container_of(ShmemBlock, data, queue);

	/* untrack this block in private tracker */
	dlist_delete(&block->free_list);
	Assert(block->magic == SHMEM_BLOCK_STROM_QUEUE);

	/* release it */
	pthread_mutex_destroy(&queue->lock);
	pthread_cond_destroy(&queue->cond);
	pgstrom_shmem_free(block);
}

bool
pgstrom_queue_enqueue(StromQueue *queue, dlist_node *chain)
{
	bool	result = true;

	pthread_mutex_lock(&queue->lock);
	if (!queue->is_shutdown)
		dlist_push_tail(&queue->head, chain);
	else
		result = false;
	pthread_cond_signal(&queue->cond);
	pthread_mutex_unlock(&queue->lock);

	return result;
}

dlist_node *
pgstrom_queue_dequeue(StromQueue *queue, unsigned int timeout)
{
	dlist_node *result = NULL;

	pthread_mutex_lock(&queue->lock);
	if (!dlist_is_empty(&queue->head))
		result = dlist_pop_head_node(&queue->head);
	else
	{
		/*
		 * XXX - Note that signal can interrupt pthread_cond_wait, thus
		 * queue->head may be still empty even if pgstrom_cond_wait
		 * returns true.
		 */
		if (pgstrom_cond_wait(&queue->cond, &queue->lock, timeout) &&
			!dlist_is_empty(&queue->head))
			result = dlist_pop_head_node(&queue->head);
	}
	pthread_mutex_unlock(&queue->lock);

	return result;
}

dlist_node *
pgstrom_queue_try_dequeue(StromQueue *queue)
{
	dlist_node *result = NULL;

	pthread_mutex_lock(&queue->lock);
	if (!dlist_is_empty(&queue->head))
		result = dlist_pop_head_node(&queue->head);
	pthread_mutex_unlock(&queue->lock);

	return result;
}

/*
 * pgstrom_queue_wakeup
 *
 * It wakes up threads waiting for the supplied queue. Signal handler
 * should NOT call this interface with is_broadcase = false due to
 * the restriction of pthread_cond_signal(); that may cause a deadlock.
 */
void
pgstrom_queue_wakeup(StromQueue *queue, bool is_broadcast)
{
	if (is_broadcast)
	{
		if (pthread_cond_broadcast(&queue->cond) != 0)
			elog(FATAL, "failed on pthread_cond_broadcast");
	}
	else
	{
		if (pthread_cond_signal(&queue->cond) != 0)
			elog(FATAL, "failed on pthread_cond_signal");
	}
}

bool
pgstrom_queue_is_empty(StromQueue *queue)
{
	bool	result;

	pthread_mutex_lock(&queue->lock);
	result = dlist_is_empty(&queue->head);
	pthread_mutex_unlock(&queue->lock);

	return result;
}

void
pgstrom_queue_shutdown(StromQueue *queue)
{
	pthread_mutex_lock(&queue->lock);
	queue->is_shutdown = true;
	pthread_mutex_unlock(&queue->lock);
}

/*
 * Interface for KernelParams
 */
KernelParams *
pgstrom_kernel_params_alloc(Size total_length, bool abort_on_error)
{
	ShmemBlock *block;

	block = pgstrom_shmem_alloc(SHMEM_BLOCK_KERNEL_PARAMS, total_length);
	if (!block)
	{
		if (abort_on_error)
			ereport(ERROR,
					(errcode(ERRCODE_FDW_OUT_OF_MEMORY),
					 errmsg("out of shared memory segment"),
					 errhint("enlarge pg_strom.shmem_size")));
		return NULL;
	}
	/* add this block into private tracker */
	dlist_push_tail(&shmem_private_track, &block->free_list);

	return (KernelParams *)block->data;
}

void
pgstrom_kernel_params_free(KernelParams *kernel_params)
{
	ShmemBlock *block = container_of(ShmemBlock, data, kernel_params);

	Assert(block->magic == SHMEM_BLOCK_KERNEL_PARAMS);
	/* untrack this block in private tracker */
	dlist_delete(&block->free_list);

	pgstrom_shmem_free(block);
}

/*
 * Interface for VarlenaBuffer
 */
VarlenaBuffer *
pgstrom_varlena_buffer_alloc(Size total_length, bool abort_on_error)
{
	ShmemBlock	   *block;
	VarlenaBuffer  *vlbuf;

	block = pgstrom_shmem_alloc(SHMEM_BLOCK_VARLENA_BUFFER, total_length);
	if (!block)
	{
		if (abort_on_error)
			ereport(ERROR,
					(errcode(ERRCODE_FDW_OUT_OF_MEMORY),
					 errmsg("out of shared memory segment"),
					 errhint("enlarge pg_strom.shmem_size")));
		return NULL;
	}

	/*
	 * Note: varlena buffer shall be always associated with a particular
	 * chunk-buffer, then released same timing with its master. So, we
	 * don't track individual varlena-buffers on private-tracker.
	 * Its design reason is, varlena-buffers can be allocated by parallel-
	 * loader that is a different process from the process that acquires
	 * the chunk-buffer to be associated with.
	 */
	vlbuf = (VarlenaBuffer *)block->data;
	memset(vlbuf, 0, offsetof(VarlenaBuffer, data));
	vlbuf->length = total_length - offsetof(VarlenaBuffer, data);
	vlbuf->usage = 0;

	return vlbuf;
}

void
pgstrom_varlena_buffer_free(VarlenaBuffer *vlbuf)
{
	ShmemBlock *block = container_of(ShmemBlock, data, vlbuf);

	Assert(block->magic == SHMEM_BLOCK_VARLENA_BUFFER);
	/* Note: Also, no need to untrack varlena buffers */

	pgstrom_shmem_free(block);
}

/*
 * Routines for ChunkBuffer
 */
ChunkBuffer *
pgstrom_chunk_buffer_alloc(Size total_length, bool abort_on_error)
{
	ChunkBuffer	   *chunk;
	ShmemBlock	   *block;

	/* ensure total_length is larger than ChunkBuffer */
	if (total_length < sizeof(ChunkBuffer))
		total_length = sizeof(ChunkBuffer);

	block = pgstrom_shmem_alloc(SHMEM_BLOCK_CHUNK_BUFFER, total_length);
	if (!block)
	{
		if (abort_on_error)
			ereport(ERROR,
					(errcode(ERRCODE_FDW_OUT_OF_MEMORY),
					 errmsg("out of shared memory segment"),
					 errhint("enlarge pg_strom.shmem_size")));
		return NULL;
	}

	chunk = (ChunkBuffer *)block->data;
	if (!pgstrom_cond_init(&chunk->cond, &chunk->lock))
	{
		pgstrom_shmem_free(block);
		if (abort_on_error)
			ereport(ERROR,
					(errcode(ERRCODE_INTERNAL_ERROR),
					 errmsg("failed to init mutex object")));
		return NULL;
	}
	/* add this block into private tracker */
	dlist_push_tail(&shmem_private_track, &block->free_list);

	/*
	 * Some fundamental members has to be initialized correctly because
	 * resource cleanup routine tries to synchronize completion of the
	 * execution of this chunk, and also tries to release varalena-
	 * buffers relevant to this chunk-buffer.
	 */
	chunk->recvq = NULL;
	chunk->kernel_params = NULL;
	dlist_init(&chunk->vlbuf_list);
	chunk->is_loaded = false;
	chunk->is_running = false;

	return chunk;
}

void
pgstrom_chunk_buffer_free(ChunkBuffer *chunk)
{
	dlist_mutable_iter	iter;
	ShmemBlock *block = container_of(ShmemBlock, data, chunk);

	Assert(block->magic == SHMEM_BLOCK_CHUNK_BUFFER);
	Assert(block->pid == getpid());

	/*
	 * NOTE: it does not care about local memory on rs_memcxt and rs_cache;
	 * these shall be released by caller, or error cleanup callback.
	 * Usually, these are acquired on per-query memory context, thus, these
	 * objects are released automatically.
	 * Also note that these objects shall be released prior to invocation
	 * of this routine in case of error cleanup, so don't touch these
	 * pointers
	 */
	dlist_foreach_modify(iter, &chunk->vlbuf_list)
	{
		VarlenaBuffer  *vlbuf
			= dlist_container(VarlenaBuffer, chain, iter.cur);

		pgstrom_varlena_buffer_free(vlbuf);
	}

	/* untrack this block in private tracker */
	dlist_delete(&block->free_list);

	/* release it */
	pthread_mutex_destroy(&chunk->lock);
	pthread_cond_destroy(&chunk->cond);
	pgstrom_shmem_free(block);
}

/*
 * pgstrom_device_property_alloc
 *
 * It allocate a DeviceProperty object on shared memory segment according
 * to the supplied template.
 */
DeviceProperty *
pgstrom_device_property_alloc(DeviceProperty *templ, bool abort_on_error)
{
	ShmemBlock	   *block;
	DeviceProperty *devprop;
	Size			length = sizeof(DeviceProperty);
	Size			offset = 0;
	int				i, rc;
	static long		string_fields[] = {
		offsetof(DeviceProperty, pf_profile),
		offsetof(DeviceProperty, pf_vendor),
		offsetof(DeviceProperty, pf_name),
		offsetof(DeviceProperty, pf_version),
		offsetof(DeviceProperty, pf_extensions),
		offsetof(DeviceProperty, dev_profile),
		offsetof(DeviceProperty, dev_vendor),
		offsetof(DeviceProperty, dev_name),
		offsetof(DeviceProperty, dev_version),
		offsetof(DeviceProperty, dev_driver),
		offsetof(DeviceProperty, dev_opencl_c_version),
		offsetof(DeviceProperty, dev_extensions),
	};

	for (i=0; i < lengthof(string_fields); i++)
	{
		char  **field = (char **)((char *)templ + string_fields[i]);

		if (*field)
			length += strlen(*field) + 1;
	}

	block = pgstrom_shmem_alloc(SHMEM_BLOCK_DEVICE_PROPERTY, length);
	if (!block)
	{
		if (abort_on_error)
			ereport(ERROR,
					(errcode(ERRCODE_FDW_OUT_OF_MEMORY),
					 errmsg("out of shared memory segment"),
					 errhint("enlarge pg_strom.shmem_size")));
		return NULL;
	}

	devprop = (DeviceProperty *)block->data;

	/* Copy the given template to shared memory */
	memcpy(devprop, templ, sizeof(DeviceProperty));
	for (i=0; i < lengthof(string_fields); i++)
	{
		char  **src = (char **)((char *)templ + string_fields[i]);
		char  **dst = (char **)((char *)devprop + string_fields[i]);

		if (!*src)
			*dst = NULL;
		else
		{
			*dst = devprop->data + offset;
			strcpy(*dst, *src);
			offset += strlen(*src) + 1;
		}
	}
	Assert(offsetof(DeviceProperty, data) + offset <= length);

	/* Chain it on the global list */
	rc = pthread_rwlock_wrlock(&pgstrom_shmem_head->dev_lock);
	if (rc != 0)
	{
		pgstrom_shmem_free(block);
		if (abort_on_error)
			ereport(ERROR,
					(errcode(ERRCODE_INTERNAL_ERROR),
					 errmsg("could not acquire device property lock: %s",
							strerror(rc))));
		return NULL;
	}
	dlist_push_tail(&pgstrom_shmem_head->dev_head, &devprop->chain);
	pthread_rwlock_unlock(&pgstrom_shmem_head->dev_lock);

	return devprop;
}

/*
 * pgstrom_device_property_free
 *
 * It release the supplied DeviceProperty
 */
void
pgstrom_device_property_free(DeviceProperty *devprop)
{
	ShmemBlock *block = container_of(ShmemBlock, data, devprop);
	int			rc;

	rc = pthread_rwlock_wrlock(&pgstrom_shmem_head->dev_lock);
	if (rc != 0)
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("could not acquire device property lock: %s",
						strerror(rc))));
	dlist_delete(&devprop->chain);
	pthread_rwlock_unlock(&pgstrom_shmem_head->dev_lock);

	pgstrom_shmem_free(block);
}

/*
 * pgstrom_device_property_(un)lock and pgstrom_device_property_next
 *
 * Iterator of DeviceProperty on the shared memory segment.
 * Caller of these routine has to follow the manner below.
 * 
 * pgstrom_device_property_lock(false)
 *   PG_TRY();
 *   {
 *       DeviceProperty  *devprop;
 *
 *       for (devprop = pgstrom_device_property_next(NULL);
 *            devprop != NULL;
 *            devprop = pgstrom_device_property_next(devprop))
 *       {
 *          ... do something to reference device properties ...
 *       }
 *   }
 *   PG_CATCH();
 *   {
 *       pgstrom_device_property_unlock();
 *       PG_RE_THROW();
 *   }
 *   PG_END_TRY();
 *   pgstrom_device_property_unlock();
 *
 * Be careful that device-property-lock has to be unlocked on exceptions,
 * and no to hold the lock too long.
 */
void
pgstrom_device_property_lock(bool write_lock)
{
	int		rc;

	if (write_lock)
		rc = pthread_rwlock_wrlock(&pgstrom_shmem_head->dev_lock);
	else
		rc = pthread_rwlock_rdlock(&pgstrom_shmem_head->dev_lock);

	if (rc != 0)
		ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("could not acquire device property lock: %s",
						strerror(rc))));
}

void
pgstrom_device_property_unlock(void)
{
	pthread_rwlock_unlock(&pgstrom_shmem_head->dev_lock);
}

DeviceProperty *
pgstrom_device_property_next(DeviceProperty *devprop)
{
	dlist_node	   *dnode;

	if (!devprop)
	{
		if (dlist_is_empty(&pgstrom_shmem_head->dev_head))
			return NULL;
		dnode = dlist_head_node(&pgstrom_shmem_head->dev_head);
	}
	else
	{
		if (!dlist_has_next(&pgstrom_shmem_head->dev_head,
							&devprop->chain))
			return NULL;
		dnode = dlist_next_node(&pgstrom_shmem_head->dev_head,
								&devprop->chain);
	}
	return dlist_container(DeviceProperty, chain, dnode);
}

/*
 * pgstrom_opencl_devices
 *
 * It dumps properties of all the installed OpenCL devices.
 * Please note that this function performs in the process context of
 * the backend process, so it is not available to rely on all the private
 * data structure in open_serv.c. It just dumps data on shared memory segment
 */
static Datum
fp_config_string(cl_device_fp_config fpconf)
{
	char	msgbuf[256];
	size_t	offset = 0;

	msgbuf[0] = '\0';
	if (fpconf & CL_FP_DENORM)
		offset += snprintf(msgbuf + offset, sizeof(msgbuf) - offset,
						   "%sDenorm", offset > 0 ? ", " : "");
	if (fpconf & CL_FP_INF_NAN)
		offset += snprintf(msgbuf + offset, sizeof(msgbuf) - offset,
						   "%sINF/NaN", offset > 0 ? ", " : "");
	if (fpconf & CL_FP_ROUND_TO_NEAREST)
		offset += snprintf(msgbuf + offset, sizeof(msgbuf) - offset,
						   "%sR/nearest", offset > 0 ? ", " : "");
	if (fpconf & CL_FP_ROUND_TO_ZERO)
		offset += snprintf(msgbuf + offset, sizeof(msgbuf) - offset,
						   "%sR/zero", offset > 0 ? ", " : "");
	if (fpconf & CL_FP_ROUND_TO_INF)
		offset += snprintf(msgbuf + offset, sizeof(msgbuf) - offset,
						   "%sR/INF", offset > 0 ? ", " : "");
	if (fpconf & CL_FP_FMA)
		offset += snprintf(msgbuf + offset, sizeof(msgbuf) - offset,
						   "%sFMA", offset > 0 ? ", " : "");

	return CStringGetTextDatum(msgbuf);
}

Datum
pgstrom_opencl_devices(PG_FUNCTION_ARGS)
{
	FuncCallContext	   *fncxt;
	dlist_head		   *device_list;
	DeviceProperty	   *devprop;
	int					index;
	int					field;
	HeapTuple			tuple;
	Datum				values[3];
	bool				isnull[3];
	const char		   *attname;
	char				msgbuf[512];
	int					msgoff;

	if (SRF_IS_FIRSTCALL())
	{
		TupleDesc		tupdesc;
		MemoryContext	oldcxt;
		struct timespec	abstime;
        struct timeval	tv;
        int				rc;

		fncxt = SRF_FIRSTCALL_INIT();

		oldcxt = MemoryContextSwitchTo(fncxt->multi_call_memory_ctx);

		tupdesc = CreateTemplateTupleDesc(3, false);
		TupleDescInitEntry(tupdesc, (AttrNumber) 1, "index",
						   INT4OID, -1, 0);
		TupleDescInitEntry(tupdesc, (AttrNumber) 2, "attribute",
						   TEXTOID, -1, 0);
		TupleDescInitEntry(tupdesc, (AttrNumber) 3, "value",
						   TEXTOID, -1, 0);
		fncxt->tuple_desc = BlessTupleDesc(tupdesc);

		device_list = palloc(sizeof(dlist_head));
		dlist_init(device_list);

		gettimeofday(&tv, NULL);
		abstime.tv_sec = tv.tv_sec + 10;
		abstime.tv_nsec = tv.tv_usec * 1000;

		rc = pthread_rwlock_timedrdlock(&pgstrom_shmem_head->dev_lock,
										&abstime);
		if (rc != 0)
		{
			Assert(rc == ETIMEDOUT);
			ereport(ERROR,
					(errcode(ERRCODE_INTERNAL_ERROR),
					 errmsg("Bug? could not acquire lock on opencl devices")));
		}
		PG_TRY();
		{
			dlist_iter		iter;

			dlist_foreach(iter, &pgstrom_shmem_head->dev_head)
			{
				DeviceProperty *orig = dlist_container(DeviceProperty,
													   chain,
													   iter.cur);

				devprop = palloc0(sizeof(DeviceProperty));
				memcpy(devprop, orig, sizeof(DeviceProperty));
				if (orig->pf_profile)
					devprop->pf_profile = pstrdup(orig->pf_profile);
				if (orig->pf_vendor)
					devprop->pf_vendor = pstrdup(orig->pf_vendor);
				if (orig->pf_name)
					devprop->pf_name = pstrdup(orig->pf_name);
				if (orig->pf_version)
					devprop->pf_version = pstrdup(orig->pf_version);
				if (orig->pf_extensions)
					devprop->pf_extensions = pstrdup(orig->pf_extensions);
				if (orig->dev_profile)
					devprop->dev_profile = pstrdup(orig->dev_profile);
				if (orig->dev_vendor)
					devprop->dev_vendor = pstrdup(orig->dev_vendor);
				if (orig->dev_name)
					devprop->dev_name = pstrdup(orig->dev_name);
				if (orig->dev_version)
					devprop->dev_version = pstrdup(orig->dev_version);
				if (orig->dev_driver)
					devprop->dev_driver = pstrdup(orig->dev_driver);
				if (orig->dev_opencl_c_version)
					devprop->dev_opencl_c_version
						= pstrdup(orig->dev_opencl_c_version);
				if (orig->dev_extensions)
					devprop->dev_extensions = pstrdup(orig->dev_extensions);

				dlist_push_tail(device_list, &devprop->chain);
			}
		}
		PG_CATCH();
		{
			pthread_rwlock_unlock(&pgstrom_shmem_head->dev_lock);
			PG_RE_THROW();
		}
		PG_END_TRY();
		pthread_rwlock_unlock(&pgstrom_shmem_head->dev_lock);
		MemoryContextSwitchTo(oldcxt);

		fncxt->user_fctx = device_list;
	}
	fncxt = SRF_PERCALL_SETUP();

	device_list = (dlist_head *) fncxt->user_fctx;
	if (dlist_is_empty(device_list))
		SRF_RETURN_DONE(fncxt);

	devprop = dlist_container(DeviceProperty, chain,
							  dlist_head_node(device_list));

	index = fncxt->call_cntr / 50;
	field = fncxt->call_cntr % 50;

	memset(values, 0, sizeof(values));
	memset(isnull, 0, sizeof(isnull));
	values[0] = Int32GetDatum(index);
	switch (field)
	{
		case 0:
			attname = "local device";
			values[2] = CStringGetTextDatum(devprop->is_local ? "yes" : "no");
			break;
		case 1:
			attname = "platform profile";
			values[2] = CStringGetTextDatum(devprop->pf_profile);
			break;
		case 2:
			attname = "platform vendor";
			values[2] = CStringGetTextDatum(devprop->pf_vendor);
			break;
		case 3:
			attname = "platform name";
			values[2] = CStringGetTextDatum(devprop->pf_name);
			break;
		case 4:
			attname = "platform version";
			values[2] = CStringGetTextDatum(devprop->pf_version);
			break;
		case 5:
			attname = "platform extensions";
			values[2] = CStringGetTextDatum(devprop->pf_extensions);
			break;
		case 6:
			attname = "device type";
			if (devprop->dev_type == CL_DEVICE_TYPE_CPU)
				values[2] = CStringGetTextDatum("CPU");
			else if (devprop->dev_type == CL_DEVICE_TYPE_GPU)
				values[2] = CStringGetTextDatum("GPU");
			else if (devprop->dev_type == CL_DEVICE_TYPE_ACCELERATOR)
				values[2] = CStringGetTextDatum("Accelerator");
			else if (devprop->dev_type == CL_DEVICE_TYPE_CUSTOM)
				values[2] = CStringGetTextDatum("Custom");
			else
				isnull[2] = true;
			break;
		case 7:
			attname = "device profile";
			values[2] = CStringGetTextDatum(devprop->dev_profile);
			break;
		case 8:
			attname = "device vendor";
			values[2] = CStringGetTextDatum(devprop->dev_vendor);
			break;
		case 9:
			attname = "device vendor id";
			snprintf(msgbuf, sizeof(msgbuf),
					 "0x%08x", devprop->dev_vendor_id);
			values[2] = CStringGetTextDatum(msgbuf);
			break;
		case 10:
			attname = "device name";
			values[2] = CStringGetTextDatum(devprop->dev_name);
			break;
		case 11:
			attname = "device version";
			values[2] = CStringGetTextDatum(devprop->dev_version);
			break;
		case 12:
			attname = "device driver";
			values[2] = CStringGetTextDatum(devprop->dev_driver);
			break;
		case 13:
			attname = "device OpenCL C version";
			values[2] = CStringGetTextDatum(devprop->dev_opencl_c_version);
			break;
		case 14:
			attname = "device extensions";
			values[2] = CStringGetTextDatum(devprop->dev_extensions);
			break;
		case 15:
			attname = "device address bits";
			snprintf(msgbuf, sizeof(msgbuf), "%u",
					 devprop->dev_address_bits);
			values[2] = CStringGetTextDatum(msgbuf);
			break;
		case 16:
			attname = "device available";
			if (devprop->dev_available)
				values[2] = CStringGetTextDatum("yes");
            else
                values[2] = CStringGetTextDatum("no");
			break;
		case 17:
			attname = "device compiler available";
			if (devprop->dev_compiler_available)
				values[2] = CStringGetTextDatum("yes");
			else
				values[2] = CStringGetTextDatum("no");
			break;
		case 18:
			attname = "device double FP config";
			values[2] = fp_config_string(devprop->dev_double_fp_config);
			break;
		case 19:
			attname = "device endian";
			if (devprop->dev_endian_little)
				values[2] = CStringGetTextDatum("little");
			else
				values[2] = CStringGetTextDatum("big");
			break;
		case 20:
			attname = "device global memory cache size";
			snprintf(msgbuf, sizeof(msgbuf), "%lu",
					 devprop->dev_global_mem_cache_size);
			values[2] = CStringGetTextDatum(msgbuf);
			break;
		case 21:
			attname = "device global memory cache type";
			if (devprop->dev_global_mem_cache_type == CL_NONE)
				values[2] = CStringGetTextDatum("none");
			else if (devprop->dev_global_mem_cache_type == CL_READ_ONLY_CACHE)
				values[2] = CStringGetTextDatum("read-only");
			else if (devprop->dev_global_mem_cache_type == CL_READ_WRITE_CACHE)
				values[2] = CStringGetTextDatum("read-write");
			else
				isnull[2] = true;
			break;
		case 22:
			attname = "device global memory cacheline size";
			snprintf(msgbuf, sizeof(msgbuf), "%u",
					 devprop->dev_global_mem_cacheline_size);
			values[2] = CStringGetTextDatum(msgbuf);
			break;
		case 23:
			attname = "device global memory size";
			snprintf(msgbuf, sizeof(msgbuf), "%lu",
					 devprop->dev_global_mem_size);
			values[2] = CStringGetTextDatum(msgbuf);
			break;
		case 24:
			attname = "device host unified memory";
			if (devprop->dev_host_unified_memory)
				values[2] = CStringGetTextDatum("yes");
			else
				values[2] = CStringGetTextDatum("no");
			break;
		case 25:
			attname = "device local memory size";
			snprintf(msgbuf, sizeof(msgbuf), "%lu",
					 devprop->dev_local_mem_size);
			values[2] = CStringGetTextDatum(msgbuf);
			break;
		case 26:
			attname = "device local memory type";
			if (devprop->dev_local_mem_type == CL_LOCAL)
				values[2] = CStringGetTextDatum("SRAM");
			else if (devprop->dev_local_mem_type == CL_GLOBAL)
				values[2] = CStringGetTextDatum("DRAM");
			else if (devprop->dev_local_mem_type == CL_NONE)
				values[2] = CStringGetTextDatum("none");
			else
				isnull[2] = true;
			break;
		case 27:
			attname = "device max clock frequency";
			snprintf(msgbuf, sizeof(msgbuf), "%u",
					 devprop->dev_max_clock_frequency);
			values[2] = CStringGetTextDatum(msgbuf);
			break;
		case 28:
			attname = "device max compute units";
			snprintf(msgbuf, sizeof(msgbuf), "%u",
					 devprop->dev_max_compute_units);
			values[2] = CStringGetTextDatum(msgbuf);
			break;
		case 29:
			attname = "device max constant arguments";
			snprintf(msgbuf, sizeof(msgbuf), "%u",
					 devprop->dev_max_constant_args);
			values[2] = CStringGetTextDatum(msgbuf);
			break;
		case 30:
			attname = "device max constant buffer size";
			snprintf(msgbuf, sizeof(msgbuf), "%lu",
					 devprop->dev_max_constant_buffer_size);
			values[2] = CStringGetTextDatum(msgbuf);
			break;
		case 31:
			attname = "device max memory allocation size";
			snprintf(msgbuf, sizeof(msgbuf), "%lu",
					 devprop->dev_max_mem_alloc_size);
			values[2] = CStringGetTextDatum(msgbuf);
			break;
		case 32:
			attname = "device max parameter size";
			snprintf(msgbuf, sizeof(msgbuf), "%lu",
					 devprop->dev_max_parameter_size);
			values[2] = CStringGetTextDatum(msgbuf);
			break;
		case 33:
			attname = "device max work group size";
			snprintf(msgbuf, sizeof(msgbuf), "%lu",
					 devprop->dev_max_work_group_size);
			values[2] = CStringGetTextDatum(msgbuf);
			break;
		case 34:
			attname = "device max work item size";
			snprintf(msgbuf, sizeof(msgbuf), "{%lu, %lu, %lu}",
					 devprop->dev_max_work_item_sizes[0],
					 devprop->dev_max_work_item_sizes[1],
					 devprop->dev_max_work_item_sizes[2]);
			values[2] = CStringGetTextDatum(msgbuf);
			break;
		case 35:
			attname = "device memory base address alignment";
			snprintf(msgbuf, sizeof(msgbuf), "%u",
					 devprop->dev_mem_base_addr_align);
			values[2] = CStringGetTextDatum(msgbuf);
			break;
		case 36:
			attname = "device native vector width (char)";
			snprintf(msgbuf, sizeof(msgbuf), "%u",
					 devprop->dev_native_vector_width_char);
			values[2] = CStringGetTextDatum(msgbuf);
			break;
		case 37:
			attname = "device native vector width (short)";
			snprintf(msgbuf, sizeof(msgbuf), "%u",
					 devprop->dev_native_vector_width_short);
			values[2] = CStringGetTextDatum(msgbuf);
			break;
		case 38:
			attname = "device native vector width (int)";
			snprintf(msgbuf, sizeof(msgbuf), "%u",
					 devprop->dev_native_vector_width_int);
			values[2] = CStringGetTextDatum(msgbuf);
			break;
		case 39:
			attname = "device native vector width (long)";
			snprintf(msgbuf, sizeof(msgbuf), "%u",
					 devprop->dev_native_vector_width_long);
			values[2] = CStringGetTextDatum(msgbuf);
			break;
		case 40:
			attname = "device native vector width (float)";
			snprintf(msgbuf, sizeof(msgbuf), "%u",
					 devprop->dev_native_vector_width_float);
			values[2] = CStringGetTextDatum(msgbuf);
			break;
		case 41:
			attname = "device native vector width (double)";
			snprintf(msgbuf, sizeof(msgbuf), "%u",
					 devprop->dev_native_vector_width_double);
			values[2] = CStringGetTextDatum(msgbuf);
			break;
		case 42:
			attname = "device preferred vector width (char)";
			snprintf(msgbuf, sizeof(msgbuf), "%u",
					 devprop->dev_preferred_vector_width_char);
			values[2] = CStringGetTextDatum(msgbuf);
			break;
		case 43:
			attname = "device preferred vector width (short)";
			snprintf(msgbuf, sizeof(msgbuf), "%u",
					 devprop->dev_preferred_vector_width_short);
			values[2] = CStringGetTextDatum(msgbuf);
			break;
		case 44:
			attname = "device preferred vector width (int)";
			snprintf(msgbuf, sizeof(msgbuf), "%u",
					 devprop->dev_preferred_vector_width_int);
			values[2] = CStringGetTextDatum(msgbuf);
			break;
		case 45:
			attname = "device preferred vector width (long)";
			snprintf(msgbuf, sizeof(msgbuf), "%u",
					 devprop->dev_preferred_vector_width_long);
			values[2] = CStringGetTextDatum(msgbuf);
			break;
		case 46:
			attname = "device preferred vector width (float)";
			snprintf(msgbuf, sizeof(msgbuf), "%u",
					 devprop->dev_preferred_vector_width_float);
			values[2] = CStringGetTextDatum(msgbuf);
			break;
		case 47:
			attname = "device preferred vector width (double)";
			snprintf(msgbuf, sizeof(msgbuf), "%u",
					 devprop->dev_preferred_vector_width_double);
			values[2] = CStringGetTextDatum(msgbuf);
			break;
		case 48:
			attname = "device queue properties";
			msgoff = 0;
			if (devprop->dev_queue_properties &
				CL_QUEUE_OUT_OF_ORDER_EXEC_MODE_ENABLE)
				msgoff += snprintf(msgbuf + msgoff, sizeof(msgbuf) - msgoff,
								   "%sout of order execution",
								   msgoff > 0 ? ", " : "");
			if (devprop->dev_queue_properties & CL_QUEUE_PROFILING_ENABLE)
				msgoff += snprintf(msgbuf + msgoff, sizeof(msgbuf) - msgoff,
								   "%sprofiling",
								   msgoff > 0 ? ", " : "");
			values[2] = CStringGetTextDatum(msgbuf);
			break;
		case 49:
			attname = "device single FP config";
			values[2] = fp_config_string(devprop->dev_single_fp_config);

			/* because this attribute is last, remove current device */
			dlist_delete(&devprop->chain);
			break;
		default:
			elog(ERROR, "Bug? DeviceProperty has no %dth field", field);
			attname = NULL;		/* be compiler quiet */
			break;
	}
	values[1] = CStringGetTextDatum(attname);

	tuple = heap_form_tuple(fncxt->tuple_desc, values, isnull);

	SRF_RETURN_NEXT(fncxt, HeapTupleGetDatum(tuple));
}
PG_FUNCTION_INFO_V1(pgstrom_opencl_devices);

/*
 * pgstrom_shmem_startup
 *
 * A callback routine during initialization of shared memory segment.
 * It acquires shared memory segment from the core, and initializes
 * this region for future allocation for chunk-buffers and so on.
 */
static void
pgstrom_shmem_startup(void)
{
	ShmemBlock *block;
	Size		segment_sz = (pgstrom_shmem_size << 20);
	bool		found;

	/* call the startup hook */
	if (shmem_startup_hook_next)
		(*shmem_startup_hook_next)();

	/* acquire shared memory segment */
	pgstrom_shmem_head = ShmemInitStruct("shared memory segment of PG-Strom",
										 segment_sz, &found);
	Assert(!found);

	/* init ShmemHead field */
	pgstrom_shmem_head->total_size
		= segment_sz - offsetof(ShmemHead, first_block);
	pgstrom_shmem_head->free_size = pgstrom_shmem_head->total_size;
	dlist_init(&pgstrom_shmem_head->free_head);
	dlist_init(&pgstrom_shmem_head->addr_head);
	if (!pgstrom_mutex_init(&pgstrom_shmem_head->lock))
		elog(ERROR, "failed to init mutex lock");

	if (!pgstrom_rwlock_init(&pgstrom_shmem_head->dev_lock))
		elog(ERROR, "failed to init read-write lock");
	dlist_init(&pgstrom_shmem_head->dev_head);

	/* init ShmemBlock as an empty big block */
	block = pgstrom_shmem_head->first_block;
	block->magic = SHMEM_BLOCK_FREE;
	dlist_push_head(&pgstrom_shmem_head->addr_head, &block->addr_list);
	dlist_push_head(&pgstrom_shmem_head->free_head, &block->free_list);
	block->size = pgstrom_shmem_head->total_size;

	/* startup routines of other modules */
	pgstrom_opencl_server_startup((uintptr_t) pgstrom_shmem_head,
								  (uintptr_t) pgstrom_shmem_head +
								  offsetof(ShmemHead, first_block) +
								  pgstrom_shmem_head->total_size);
}

void
pgstrom_shmem_init(void)
{
	/* prepare mutex-attribute on shared memory segment */
	if (pthread_mutexattr_init(&shmem_mutex_attr) != 0 ||
		pthread_mutexattr_setpshared(&shmem_mutex_attr,
									 PTHREAD_PROCESS_SHARED) != 0)
		elog(ERROR, "failed to init mutex attribute");

	/* prepare rwlock-attribute on shared memory segment */
	if (pthread_rwlockattr_init(&shmem_rwlock_attr) != 0 ||
		pthread_rwlockattr_setpshared(&shmem_rwlock_attr,
									  PTHREAD_PROCESS_SHARED) != 0)
		elog(ERROR, "failed to init rwlock attribute");

	/* prepare cond-attribute on shared memory segment */
	if (pthread_condattr_init(&shmem_cond_attr) != 0 ||
		pthread_condattr_setpshared(&shmem_cond_attr,
									PTHREAD_PROCESS_SHARED) != 0)
		elog(ERROR, "failed to init condition attribute");

	/* GUC */
	DefineCustomIntVariable("pg_strom.shmem_size",
							"size of shared memory segment in MB",
							NULL,
							&pgstrom_shmem_size,
							256,	/* 256MB */
							64,		/* 64MB */
							INT_MAX,
							PGC_SIGHUP,
							0,
							NULL, NULL, NULL);

	/* acquire shared memory segment */
	RequestAddinShmemSpace(pgstrom_shmem_size << 20);
	shmem_startup_hook_next = shmem_startup_hook;
	shmem_startup_hook = pgstrom_shmem_startup;

	/* init private list to track acquired memory blocks */
	dlist_init(&shmem_private_track);

	/* registration of shared-memory cleanup handler  */
	RegisterResourceReleaseCallback(pgstrom_shmem_cleanup, NULL);
}

/*
 * pgstrom_shmem_dump
 *
 * it dumps current usage of shared memory segment for debugging.
 */
typedef struct {
	dlist_node	chain;
	uint32		magic;
	Size		size;
	Datum		start;
	Datum		end;
	pid_t		pid;
	bool		overrun;
} shmem_dump_item;

Datum
pgstrom_shmem_dump(PG_FUNCTION_ARGS)
{
	FuncCallContext	   *fncxt;
	dlist_head		   *dump_list;
	dlist_node		   *dnode;
	shmem_dump_item	   *ditem;
	HeapTuple			tuple;
	Datum				values[6];
	bool				isnull[6];
	char				msgbuf[512];

	if (SRF_IS_FIRSTCALL())
	{
		TupleDesc		tupdesc;
		MemoryContext	oldcxt;
		struct timespec	abstime;
        struct timeval	tv;
		int				rc;

		fncxt = SRF_FIRSTCALL_INIT();
		oldcxt = MemoryContextSwitchTo(fncxt->multi_call_memory_ctx);

		tupdesc = CreateTemplateTupleDesc(6, false);
		TupleDescInitEntry(tupdesc, (AttrNumber) 1, "block_type",
						   TEXTOID, -1, 0);
		TupleDescInitEntry(tupdesc, (AttrNumber) 2, "block_size",
						   INT8OID, -1, 0);
		TupleDescInitEntry(tupdesc, (AttrNumber) 3, "start_addr",
						   TEXTOID, -1, 0);
		TupleDescInitEntry(tupdesc, (AttrNumber) 4, "end_addr",
						   TEXTOID, -1, 0);
		TupleDescInitEntry(tupdesc, (AttrNumber) 5, "owned_by",
						   INT4OID, -1, 0);
		TupleDescInitEntry(tupdesc, (AttrNumber) 6, "overrun",
						   BOOLOID, -1, 0);
		fncxt->tuple_desc = BlessTupleDesc(tupdesc);

		dump_list = palloc(sizeof(dlist_head));
		dlist_init(dump_list);

		gettimeofday(&tv, NULL);
		abstime.tv_sec = tv.tv_sec + 10;
		abstime.tv_nsec = tv.tv_usec * 1000;

		rc = pthread_mutex_timedlock(&pgstrom_shmem_head->lock, &abstime);
		if (rc != 0)
		{
			Assert(rc == ETIMEDOUT);
			ereport(ERROR,
					(errcode(ERRCODE_INTERNAL_ERROR),
					 errmsg("Bug? could not acquire lock on shared memory")));
		}
		PG_TRY();
		{
			dlist_iter			iter;
			uint32				marker;

			/* overview of shared memory segment */
			ditem = palloc0(sizeof(shmem_dump_item));
			ditem->magic = 1;	/* for total */
			ditem->size = pgstrom_shmem_head->total_size;
			ditem->start = PointerGetDatum((char *)pgstrom_shmem_head +
										   offsetof(ShmemHead, first_block));
			ditem->end = PointerGetDatum((char *)pgstrom_shmem_head +
										 offsetof(ShmemHead, first_block) +
										 pgstrom_shmem_head->total_size);
			dlist_push_tail(dump_list, &ditem->chain);

			/* total free size */
			ditem = palloc0(sizeof(shmem_dump_item));
			ditem->magic = 2;	/* for total free */
			ditem->size = pgstrom_shmem_head->free_size;
			dlist_push_tail(dump_list, &ditem->chain);

			/* total used size */
			ditem = palloc0(sizeof(shmem_dump_item));
			ditem->magic = 3;	/* for total used */
			ditem->size = (pgstrom_shmem_head->total_size -
						   pgstrom_shmem_head->free_size);
			dlist_push_tail(dump_list, &ditem->chain);

			/* for each regular blocks */
			dlist_foreach(iter, &pgstrom_shmem_head->addr_head)
			{
				ShmemBlock *block = dlist_container(ShmemBlock,
													addr_list,
													iter.cur);
				ditem = palloc0(sizeof(shmem_dump_item));
				ditem->magic = block->magic;
				ditem->size = block->size;
				ditem->start = PointerGetDatum(block);
				ditem->end = PointerGetDatum((char *)block + block->size);
				ditem->pid = block->pid;
				marker = SHMEM_BLOCK_OVERRUN_MARKER(block);
				ditem->overrun = (marker != SHMEM_BLOCK_OVERRUN_MARK);

				dlist_push_tail(dump_list, &ditem->chain);
			}
		}
		PG_CATCH();
		{
			pthread_mutex_unlock(&pgstrom_shmem_head->lock);
			PG_RE_THROW();
		}
		PG_END_TRY();
		pthread_mutex_unlock(&pgstrom_shmem_head->lock);
		MemoryContextSwitchTo(oldcxt);

		fncxt->user_fctx = dump_list;
	}
	fncxt = SRF_PERCALL_SETUP();

	dump_list = (dlist_head *)fncxt->user_fctx;

	if (dlist_is_empty(dump_list))
		SRF_RETURN_DONE(fncxt);

	dnode = dlist_pop_head_node(dump_list);
	ditem = dlist_container(shmem_dump_item, chain, dnode);

	memset(values, 0, sizeof(values));
	memset(isnull, 0, sizeof(isnull));

	switch (ditem->magic)
	{
		case 1:
			values[0] = CStringGetTextDatum("total");
			isnull[4] = isnull[5] = true;
			break;
		case 2:
			values[0] = CStringGetTextDatum("total free");
			isnull[2] = isnull[3] = isnull[4] = isnull[5] = true;
			break;
		case 3:
			values[0] = CStringGetTextDatum("total used");
			isnull[2] = isnull[3] = isnull[4] = isnull[5] = true;
			break;
		case SHMEM_BLOCK_FREE:
			values[0] = CStringGetTextDatum("free block");
			isnull[4] = isnull[5] = true;
			break;
		case SHMEM_BLOCK_STROM_QUEUE:
			values[0] = CStringGetTextDatum("strom queue");
			break;
		case SHMEM_BLOCK_KERNEL_PARAMS:
			values[0] = CStringGetTextDatum("kernel params");
			break;
		case SHMEM_BLOCK_CHUNK_BUFFER:
			values[0] = CStringGetTextDatum("chunk buffer");
			break;
		case SHMEM_BLOCK_VARLENA_BUFFER:
			values[0] = CStringGetTextDatum("varlena buffer");
			break;
		case SHMEM_BLOCK_DEVICE_PROPERTY:
			values[0] = CStringGetTextDatum("device property");
			break;
		default:
			snprintf(msgbuf, sizeof(msgbuf),
					 "unknown (magic = %08u)", ditem->magic);
			values[0] = CStringGetTextDatum(msgbuf);
			break;
	}

	values[1] = Int64GetDatum(ditem->size);
	snprintf(msgbuf, sizeof(msgbuf), "%p", DatumGetPointer(ditem->start));
	values[2] = CStringGetTextDatum(msgbuf);
	snprintf(msgbuf, sizeof(msgbuf), "%p", DatumGetPointer(ditem->end));
	values[3] = CStringGetTextDatum(msgbuf);
	values[4] = Int32GetDatum(ditem->pid);
	values[5] = BoolGetDatum(ditem->overrun);

	tuple = heap_form_tuple(fncxt->tuple_desc, values, isnull);

	SRF_RETURN_NEXT(fncxt, HeapTupleGetDatum(tuple));
}
PG_FUNCTION_INFO_V1(pgstrom_shmem_dump);
