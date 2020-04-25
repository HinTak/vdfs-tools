/**
 * VDFS4 -- Vertically Deliberate improved performance File System
 *
 * Copyright 2012 by Samsung Electronics, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#ifndef KERNEL_REDEF_H_
#define KERNEL_REDEF_H_

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <pthread.h>
#include <limits.h>
#include <endian.h>
#include <linux/fs.h>
#include "list.h"

#define BNODE_SIZE	156

#define kmalloc(a, b) malloc((a))
#define GFP_NOFS 0

/**
 * @brief       Attribute of unused parameters in function.
 *		Use: void foo(int a UNUSED);
 */
#define UNUSED __attribute__ ((unused))
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))

#define ALIGN(x, a)	(((x) + (typeof(x))(a) - 1) & ~((typeof(x))(a) - 1))
#define IS_ALIGNED(x, a)	(((x) & ((typeof(x))(a) - 1)) == 0)

struct vdfs4_sb_info;
static inline void *__kzalloc(unsigned int a)
{
	void *ptr = malloc((a));
	memset(ptr, 0, a);
	return ptr;
}


struct kmem_cache {
	int cache_item_size;
	int items_num;
	pthread_spinlock_t kmemcache_lock;
};

static inline void *kmem_cache_alloc(struct kmem_cache *cachep,
		int flags UNUSED)
{
	pthread_spin_lock(&cachep->kmemcache_lock);
	void *ret = malloc(cachep->cache_item_size);
	if (ret)
		cachep->items_num++;
	pthread_spin_unlock(&cachep->kmemcache_lock);
	return ret;
}

static inline void kmem_cache_free(struct kmem_cache *cachep, void *objp)
{
	pthread_spin_lock(&cachep->kmemcache_lock);
	assert(cachep->items_num > 0);
	cachep->items_num--;
	free(objp);
	pthread_spin_unlock(&cachep->kmemcache_lock);
}

static inline struct kmem_cache *init_usr_kmem_cache(int cache_item_size)
{
	struct kmem_cache *cache = malloc(sizeof(*cache));

	if (0 == cache)
		return 0;
	pthread_spin_init(&cache->kmemcache_lock, 0);
	cache->cache_item_size = cache_item_size;
	cache->items_num = 0;

	return cache;
}

static inline void kmem_cache_destroy(struct kmem_cache *cachep)
{
	pthread_spin_destroy(&cachep->kmemcache_lock);
	free(cachep);
}

#define KMEM_CACHE(__struct, __flags) init_usr_kmem_cache(\
		sizeof(struct __struct))

#define KERN_ERR ""
#define KERN_INFO ""
#define printk printf

#define is_sbi_flag_set(a, b) 1

#define kzalloc(a, b) __kzalloc(a)
#define VDFS4_ADD_CHUNK(a, b, c) (0)
#define vdfs4_add_chunk(a, b, c) do {} while (0)
#define WARN_ON(a) {}
#define vdfs4_prealloc_bnode_reserve(a, b) (1)
#define VDFS4_I(a) (a)

#define kfree(a) free(a)
#define offsetof(TYPE, MEMBER) __builtin_offsetof (TYPE, MEMBER)
#define container_of(ptr, type, member) ({			\
	const typeof(((type *)0)->member) * __mptr = (ptr);	\
	(type *)((char *)__mptr - offsetof(type, member)); })
#define mutex_w_unlock(a) do {} while (0)
#define mutex_w_lock(a) do {} while (0)
#define mutex_r_unlock(a) do {} while (0)
#define mutex_r_lock(a) do {} while (0)
#define mutex_w_lock_nested(a, class) do {} while (0)
#define unlikely(a) (a)
extern int free_block;
int get_free_block();

#ifdef CONFIG_LBDAF
typedef u64 sector_t;
typedef u64 blkcnt_t;
#else
typedef unsigned long sector_t;
#endif

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef unsigned long pgoff_t;
typedef	u_int64_t	atomic64_t;
typedef int atomic_t;

static inline int atomic_inc_and_test(atomic_t *v)
{
	return ++(*v);
}

static inline int atomic_dec_and_test(atomic_t *v)
{
	return --(*v);
}

static inline void atomic_set(atomic_t *v, int i)
{
	*v = i;
}

static inline int atomic_read(const atomic_t *v)
{
	return *v;
}

#define __packed __attribute__((packed))

#define kmap(a) malloc(BNODE_SIZE)
#define new_node_get(a) {}
#define new_node_put(a) {}

#define BUILD_BUG_ON(a)	((void)sizeof(char[1 - 2*!!(a)]))
#define BUG_ON(a) assert(!(a))
#define BUG() assert(0)

extern const int VDFS4_BTREE_INDEX_NODE_MAGIC;	/* 0x00000001 */
extern const int VDFS4_BTREE_LEAF_NODE_MAGIC;	/* 0x00000002 */

# if __BYTE_ORDER == __LITTLE_ENDIAN
#  define htobe16(x) __bswap_16 (x)
#  define htole16(x) (x)
#  define be16toh(x) __bswap_16 (x)
#  define le16toh(x) (x)
#  define htobe32(x) __bswap_32 (x)
#  define htole32(x) (x)
#  define be32toh(x) __bswap_32 (x)
#  define htobe64(x) __bswap_64 (x)
#  define htole64(x) (x)
#  define be64toh(x) __bswap_64 (x)
#  define le64toh(x) (x)
# else
#  define htobe16(x) (x)
#  define htole16(x) __bswap_16 (x)
#  define be16toh(x) (x)
#  define le16toh(x) __bswap_16 (x)
#  define htobe32(x) (x)
#  define htole32(x) __bswap_32 (x)
#  define be32toh(x) (x)
#  define le32toh(x) __bswap_32 (x)
#  define htobe64(x) (x)
#  define htole64(x) __bswap_64 (x)
#  define be64toh(x) (x)
#  define le64toh(x) __bswap_64 (x)
# endif

#define cpu_to_le64(a) htole64(a)
#define le64_to_cpu(a) le64toh(a)
#define cpu_to_le32(a) htole32(a)
#define le32_to_cpu(a) le32toh(a)
#define cpu_to_le16(a) htole16(a)
#define le16_to_cpu(a) le16toh(a)
#define VDFS4_GET_TABLE(table, x) (struct vdfs4_base_table_record *)(\
		(char *)table + \
		le32_to_cpu(table->translation_table_offsets[VDFS4_SF_INDEX(x)]))
#define VDFS4_GET_LAST_IBLOCK(table, x) (le32_to_cpu( \
		table->last_page_index[VDFS4_SF_INDEX(x)]))
struct fork_struct {
	int total_block_count;
};

struct inode {
	void *data;
	struct fork_struct fork;
	unsigned long i_ino;
};

#define MAX_ERRNO	4095
#define IS_ERR_VALUE(x) ((x) >= (unsigned long)-MAX_ERRNO)
static inline void *ERR_PTR(long error)
{
	return (void *) error;
}

static inline long PTR_ERR(const void *ptr)
{
	return (long) ptr;
}

static inline long IS_ERR(const void *ptr)
{
	return IS_ERR_VALUE((unsigned long)ptr);
}

static inline long IS_ERR_OR_NULL(const void *ptr)
{
	return !ptr || IS_ERR_VALUE((unsigned long)ptr);
}

static inline void *ERR_CAST(const void *ptr)
{
	return ERR_PTR(PTR_ERR(ptr));
}

typedef pthread_rwlock_t rw_mutex_t;

/* Stubs for spinlocks */
#define spinlock_t pthread_mutex_t
#define spin_lock_init(_lock)				\
do {							\
	if (vdfs_tools_mode & VDFS4_TOOLS_MULTITHREAD)	\
		assert(pthread_mutex_init(_lock, NULL) == 0);	\
} while (0)

#define spin_lock(lock)					\
do {							\
	if (vdfs_tools_mode && VDFS4_TOOLS_MULTITHREAD)	\
		pthread_mutex_lock(lock);		\
} while (0)

#define spin_unlock(lock)				\
do {							\
	if (vdfs_tools_mode && VDFS4_TOOLS_MULTITHREAD)	\
		pthread_mutex_unlock(lock);		\
} while (0)

#define mutex_init(lock) do { } while (0)
#define mutex_lock(lock) do { } while (0)
#define mutex_unlock(lock) do { } while (0)

struct mutex {
	/* 1: unlocked, 0: locked, negative: locked, possible waiters */
	atomic_t		count;
	spinlock_t		wait_lock;
	struct list_head	wait_list;

};

/* typedef pthread_mutex_t rw_mutex_t; */

#endif /* KERNEL_REDEF_H_ */
