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

#ifndef _VDFS4_VDFS4_H_
#define _VDFS4_VDFS4_H_

#ifndef USER_SPACE
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/rbtree.h>
#include <linux/fs.h>
#include <linux/aio.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/pagemap.h>
#include <linux/completion.h>
#include <linux/version.h>
#include <linux/list.h>
#include <linux/crypto.h>
#include <linux/xattr.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/kfifo.h>

#include "vdfs4_layout.h"
#include "btree.h"
#include "cattree.h"
#include "debug.h"
#ifdef CONFIG_VDFS4_DATA_AUTHENTICATION
#include <crypto/internal/hash.h>
#include <crypto/md5.h>
#include <linux/mpi.h>
#include <crypto/crypto_wrapper.h>
#endif
#endif /* USER_SPACE */

#define UUL_MAX_LEN 20

/*
 * Dump out the contents of some memory nicely...
 */
#if defined(CONFIG_SEPARATE_PRINTK_FROM_USER) && !defined(MODULE)
void _sep_printk_start(void);
void _sep_printk_end(void);
#else
#define _sep_printk_start() {}
#define _sep_printk_end() {}
#endif

struct vdfs4_packtree_meta_common {
	__u64 packoffset; /* packtree first bnode offset in file */
	__u64 nfs_offset; /* inode finder info for nfs callbacks */
	__u64 xattr_off;  /* xattr area offset in file (in pages) */
	__u64 chtab_off;  /* chunk index table offset */
	__u32 chunk_cnt;  /* chunk count in image */
	__u16 squash_bss; /* squashfs image block size shift */
	__u16 compr_type; /* squashfs image compression type */
	__u32 inodes_cnt; /* number of inodes in the squashfs image */
};

struct vdfs4_ioc_file_info {
	int open_count;
	int compressed_status;
	int compressed_type;
	int authenticated_status;
	int encryption_status;
	int extents_num;
	unsigned long long size;
	unsigned long long compressed_size;	/* If compressed type */
	int chunk_cnt;				/* If compressed type */
	int compressed_chunk_cnt;		/* If compressed type */
	int uncompressed_chunk_cnt;		/* If compressed type */
};

#define VDFS4_Z_NEED_DICT_ERR	-7
#define HW_DECOMPRESSOR_PAGES_NUM	32
#define SQUASHFS_COMPR_NR 6

/* INTERNAL CONSTANTS, do not export them via ioctl or disk format */
enum compr_type {
	VDFS4_COMPR_UNDEF = 0,	/* Undefined or uninitialized */
	VDFS4_COMPR_NONE,	/* No compression */
	VDFS4_COMPR_ZLIB,
	VDFS4_COMPR_LZO,
	VDFS4_COMPR_XZ,
	VDFS4_COMPR_LZMA,
	VDFS4_COMPR_GZIP,
	VDFS4_COMPR_NR,
};

enum hash_type {
	VDFS4_HASH_UNDEF = 0,
	VDFS4_HASH_SHA1,
	VDFS4_HASH_SHA256,
	VDFS4_HASH_MD5,
	VDFS4_HASH_NR,
};

enum vdfs4_read_type {
	VDFS4_META_READ = 0,
	VDFS4_PACKTREE_READ,
	VDFS4_FBASED_READ_M,
	VDFS4_FBASED_READ_C, /* file based compressed contenes read */
	VDFS4_FBASED_READ_UNC, /* file based un-compresed contents read */
	VDFS4_READ_NR,
};

/* Enabels additional print at mount - how long mount is */
/* #define CONFIG_VDFS4_PRINT_MOUNT_TIME */

#define VDFS4_BUG() do { BUG(); } while (0)

#define VDFS4_BUG_ON(cond) do { \
	BUG_ON((cond)); \
} while (0)

#ifdef CONFIG_VDFS4_DEBUG
#define VDFS4_DEBUG_BUG_ON(cond) do { \
	BUG_ON((cond)); \
} while (0)
#else
#define VDFS4_DEBUG_BUG_ON(cond) do { \
	if (cond) \
		VDFS4_ERR(#cond); \
} while (0)
#endif

#define VDFS4_IS_READONLY(sb) (sb->s_flags & MS_RDONLY)
#define VDFS4_IS_VOL_ENCRYPTED(sbi) (is_sbi_flag_set(sbi, VOLUME_ENCRYPTED))

extern unsigned int file_prealloc;
extern unsigned int cattree_prealloc;

#define EMMMCFS_VOLUME_START	4


#define VDFS4_LINK_MAX 32

#define VDFS4_INVALID_BLOCK (~((sector_t) 0xffff))
/* the block size if fixed in vdfs4 file system = 4K */
#define VDFS4_BLOCK_SIZE (1 << 12)

/** Maximal supported file size. Equal maximal file size supported by VFS */
#define VDFS4_MAX_FILE_SIZE_IN_BYTES MAX_LFS_FILESIZE

/* The eMMCFS runtime flags */
#define EXSB_DIRTY		0
#define IS_MOUNT_FINISHED	2
#define VDFS4_META_CRC		3
#define DO_NOT_CHECK_SIGN	4
#define VOLUME_AUTH		5
#define VOLUME_ENCRYPTED	6
#define AES_KEY_IN_SB		7

/** The VDFS4 inode flags */
#define HAS_BLOCKS_IN_EXTTREE	1
#define VDFS4_IMMUTABLE		2
#define HARD_LINK		10
#define ORPHAN_INODE		12
#define VDFS4_COMPRESSED_FILE	13
/* UNUSED:			 			14 */
#define VDFS4_AUTH_FILE		15
#define VDFS4_READ_ONLY_AUTH	16
#define VDFS4_ENCRYPTED_FILE	17
#define VDFS4_PROFILED_FILE	18

/* below flags are only used at mkfs runtime
 * and aren't written on partition layout */
#define VDFS4_HLINK_TUNE_TRIED	30
#define VDFS4_NOCOMPRESS_FILE	31

/* Macros for calculating catalog tree expand step size.
 * x - total blocks count on volume
 * right shift 7 - empirical value. For example, on 1G volume catalog tree will
 * expands by 8M one step*/
#define TREE_EXPAND_STEP(x)	(x >> 7)

/* Preallocation blocks amount */
#define FSM_PREALLOC_DELTA	0

#define VDFS4_META_REREAD	2
#define VDFS4_META_REREAD_BNODE 2

/**
 * @brief		Compare two 64 bit values
 * @param [in]	b	first value
 * @param [in]	a	second value
 * @return		Returns 0 if a == b, 1 if a > b, -1 if a < b
 */
static inline int cmp_2_le64(__le64 a, __le64 b)
{
	if (le64_to_cpu(a) == le64_to_cpu(b))
		return 0;
	else
		return (le64_to_cpu(a) > le64_to_cpu(b)) ? 1 : -1;
}

/* Flags that should be inherited by new inodes from their parent. */
#define VDFS4_FL_INHERITED	0
/* force read-only ioctl command */
#define VDFS4_IOC_FORCE_RO		_IOR('A', 1, long)
/* ioctl command code for open_count fetch */
#define	VDFS4_IOC_GET_OPEN_COUNT		_IOR('C', 1, long)
#define	VDFS4_IOC32_GET_OPEN_COUNT	_IOR('C', 1, int)
/* File based compression commands */
#define VDFS4_IOC_SET_DECODE_STATUS	_IOW('I', 1, int)
#define VDFS4_IOC_GET_DECODE_STATUS	_IOR('I', 1, int)
#define VDFS4_IOC_GET_COMPR_TYPE		_IOR('J', 1, int)
#define VDFS4_IOC_IS_AUTHENTICATED	_IOR('K', 1, int)
#define VDFS4_IOC_IS_ENCRYPTED		_IOR('L', 1, int)
#define VDFS4_IOC_GET_FILE_INFORMATION	_IOR('M', 1, struct vdfs4_ioc_file_info *)


#ifndef USER_SPACE

#define vdfs4_vmalloc(...) ({				\
	unsigned noio_flags = memalloc_noio_save();	\
	void *ret = vmalloc(__VA_ARGS__);		\
	memalloc_noio_restore(noio_flags);		\
	ret;						\
})

#define vdfs4_vzalloc(...) ({				\
	unsigned noio_flags = memalloc_noio_save();	\
	void *ret = vzalloc(__VA_ARGS__);		\
	memalloc_noio_restore(noio_flags);		\
	ret;						\
})

#define vdfs4_vmap(...) ({				\
	unsigned noio_flags = memalloc_noio_save();	\
	void *ret = vmap(__VA_ARGS__);			\
	memalloc_noio_restore(noio_flags);		\
	ret;						\
})

#define vdfs4_vm_map_ram(...) ({				\
	unsigned noio_flags = memalloc_noio_save();	\
	void *ret = vm_map_ram(__VA_ARGS__);		\
	memalloc_noio_restore(noio_flags);		\
	ret;						\
})

struct packtrees_list {
	/* pack tree multi-access protection */
	struct mutex lock_pactree_list;

	struct list_head list;
};

/** @brief	Maintains private super block information.
 */
struct vdfs4_sb_info {
	/** The VFS super block */
	struct super_block	*sb;
	/** The page that contains superblocks */
	struct page *superblocks;
	/** The page that contains superblocks copy */
	struct page *superblocks_copy;
	/** The eMMCFS mapped raw superblock data */
	void *raw_superblock;
	/** The eMMCFS mapped raw superblock copy data */
	void *raw_superblock_copy;
	/** The page that contains debug area */
	struct page **debug_pages;
	/** Mapped debug area */
	void *debug_area;
	/** The eMMCFS flags */
	unsigned long flags;
	/** Allocated block size in bytes */
	unsigned int		block_size;
	/** Allocated block size shift  */
	unsigned int		block_size_shift;
	/** Allocated block size mask for offset  */
	unsigned int		offset_msk_inblock;
	/** Size of LEB in blocks */
	unsigned int		log_blocks_in_leb;
	/* log blocks in page  */
	unsigned int		log_blocks_in_page;
	/** Log sector per block */
	unsigned int		log_sectors_per_block;
	/** The eMMCFS mount options */
	unsigned int		mount_options;
	/** Volume size in blocks */
	unsigned long long	volume_blocks_count;
	/** The current value of free block count on the whole eMMCFS volume */
	unsigned long long	free_blocks_count;
	/* Reserved for delayed allocations, not in free_blocks_count */
	unsigned long long	reserved_blocks_count;
	/** The files count on the whole eMMCFS volume */
	unsigned long long	files_count;
	/** The folders count on the whole eMMCFS volume */
	unsigned long long	folders_count;
	/** 64-bit uuid for volume */
	u64			volume_uuid;
	/** How many blocks in the bnode */
	unsigned long		btree_node_size_blks;
	/** Catalog tree in memory */
	struct vdfs4_btree	*catalog_tree;
	/** Maximum value of catalog tree height */
	int			max_cattree_height;
	/** Extents overflow tree */
	struct vdfs4_btree	*extents_tree;
	/** Xattr tree */
	struct vdfs4_btree	*xattr_tree;
	/*Sysfs kobject structure*/
	struct kobject	s_kobj;
	struct completion s_kobj_unregister;

	u32 erase_block_size;
	u32 erase_block_size_in_blocks;

	u8 log_erase_block_size_in_blocks;
	u8 log_erase_block_size;
	u8 log_block_size;
	char umount_time;

	u32 *erase_blocks_counters;
	u32 nr_erase_blocks_counters;
	/** Free space bitmap information */
	struct {
		struct inode *inode;
		atomic64_t last_used;
	} free_inode_bitmap;

	/** Free space management */
	struct vdfs4_fsm_info *fsm_info;

	/** Snapshot manager */
	struct vdfs4_snapshot_info *snapshot_info;

	/** pending transaction commit */
	struct delayed_work delayed_commit;

	/* fallback completion for metadata writeback */
	wait_queue_head_t meta_bio_wait;
	atomic_t meta_bio_count;

	/* check the debug area in background */
	struct delayed_work delayed_check_debug_area;

	/** log flash superpage size */
	unsigned int log_super_page_size;
#ifdef CONFIG_VDFS4_STATISTIC
	/** Number of written pages */
	__le64	umount_written_bytes;
#endif
	int bugon_count;
	/* opened packtree list */
	struct packtrees_list packtree_images;

	/* decompression type : hardware or software */
	int use_hw_decompressor;

	struct vdfs4_proc_dir_info *proc_info;

	/* new files mode mask, filled if fmask mount option is specifided */
	umode_t fmask;

	/* new directory mode mask, filled if dmask mount option
	 * is specifided */
	umode_t dmask;

	int orig_ro;
	/* under catalog_tree->rw_tree_lock */
	struct list_head orphan_inodes;

#ifdef CONFIG_VDFS4_DEBUG
	struct mutex dump_meta;
#endif
	__u64 dump_meta_file_offset;
#ifdef CONFIG_VDFS4_DATA_AUTHENTICATION
	rsakey_t *rsa_key;
	rsakey_t *rsa_key_legacy;
#endif
	enum sign_type sign_type;

#ifdef CONFIG_VDFS4_SQUEEZE_PROFILING
	struct file *prof_file;
	struct kfifo prof_fifo;
	spinlock_t prof_lock;
	struct delayed_work prof_task;
#endif
};

#ifdef CONFIG_VDFS4_SQUEEZE_PROFILING
struct vdfs4_prof_data {
	struct vdfs4_timespec stamp;
	__u32 ino;
	__u32 block;
	__u32 count;
};
#endif

#endif /* USER_SPACE */

/** @brief	Current extent information.
 */
struct vdfs4_extent_info {
	/** physical start block of the extent */
	u64 first_block;
	/** logical start block of the extent  */
	sector_t iblock;
	/** block count in the extent*/
	u32 block_count;
};

struct vdfs4_runtime_extent_info {
	/** logical start block of the extent  */
	sector_t iblock;
	sector_t alloc_hint;
	/** block count in the extent*/
	u32 block_count;
	struct list_head list;
};

/** @brief	Current fork information.
 */
struct vdfs4_fork_info {
	/**
	 * The total number of allocation blocks which are
	 * allocated for file system object described by this fork */
	u32 total_block_count;
	/**
	 * Number of blocks,which are preallocated by free space manager for
	 * file system object described by this fork */
	__u32 prealloc_block_count;
	/* Preallocated space first block physical number */
	sector_t prealloc_start_block;
	/**
	 * The set of extents which describe file system object's blocks
	 * placement */
	struct vdfs4_extent_info extents[VDFS4_EXTENTS_COUNT_IN_FORK];
	/** Used extents */
	unsigned int used_extents;
};

int vdfs4_exttree_get_extent(struct vdfs4_sb_info *sbi, struct inode *inode,
		sector_t iblock, struct vdfs4_extent_info *result);

#ifndef USER_SPACE
/*
 * Free space extents are hashed by log2(length) in
 * VDFS4_FSM_MAX_ORDER + 1 buckets: 1..2^FSM_MAX_ORDER blocks
 */
#define VDFS4_FSM_MAX_ORDER	16

/*
 * Upper limit of tracked free area extents
 */
# define VDFS4_FSM_MAX_FREE_NODES	20480

/*
 * Upper limit of tracked next-free area extents
 */
# define VDFS4_FSM_MAX_NEXT_NODES	10240

/** @brief	Maintains free space management info.
 */
struct vdfs4_fsm_info {
	/* Superblock info structure pointer */
	struct vdfs4_sb_info *sbi;
	/** Free space start (in blocks)*/
	__u32		free_space_start;
	/** LEB state bitmap pages */
	struct page	**pages;
	/** TODO */
	__u32		page_count;
	/** Mapped pages (ptr to LEB bitmap)*/
	void		*data;
	/** Lock for LEBs bitmap  */
	struct mutex	lock;
	/** Free space bitmap inode (VFS inode) */
	struct inode	*bitmap_inode;

	/* free extents sorted by start block */
	struct rb_root free_area;

	/* free extents hashed by log2(length) */
	struct list_head free_list[VDFS4_FSM_MAX_ORDER + 1];

	/* extents will be freed after commit, sorted by start block */
	struct rb_root	next_free_area;

	/* list of will-be-freed extents */
	struct list_head next_free_list;

	/* count of extents in free_area tree */
	unsigned int	free_area_nodes;

	/* count of extents in next_free_area tree */
	unsigned int	next_free_nodes;

	/* will be freed after metadata commit */
	long long	next_free_blocks;

	/* free space not present in free_area for some reason */
	long long	untracked_blocks;

	/* next free space not present in next_free_area */
	long long	untracked_next_free;
};

struct vdfs4_comp_extent_info {
	pgoff_t start_block;
	int offset;
	int len_bytes;
	int blocks_n;
	__u16 flags;
#ifdef CONFIG_VDFS4_SQUEEZE
	__u16 profiled_prio;
#endif
};

enum {
	FORCE_NONE = 0,
	FORCE_SW,
	FORCE_HW2,
};

/** @brief	Maintains file-based decompression info
 */
struct vdfs4_file_based_info {
	/* offset to chunks table */
	loff_t comp_table_start_offset;
	/* file compressed size */
	loff_t comp_size;
	/* log chunk size 12 ~ 17 */
	size_t log_chunk_size;
	/* compressed extents count */
	__u32 comp_extents_n;
	/* force readpage path (SW/HW) for this file */
	int force_path;
	/* compression type */
	enum compr_type compr_type;
	/* hash type */
	enum hash_type hash_type;
	/* signature type */
	enum sign_type sign_type;
	/* hash length */
	size_t hash_len;
	/* decompression function */
	int (*decomp_fn)(void *src, void *dst, size_t offset, size_t len_bytes,
			size_t chunk_size);
	/* authentication function */
	int (*hash_fn)(unsigned char *buffer, size_t length, char *hash);
	/* hardware decompression / authentication function */
	int (*hw_fn)(struct inode *inode, struct page *page);
	/* debug auth */
	int informed_about_fail_read;
#ifdef CONFIG_VDFS4_DECRYPTION_SUPPORT
	/* random part of AES ivec */
	__u8 aes_nonce[VDFS4_AES_NONCE_SIZE];
#endif
};

#ifdef CONFIG_VDFS4_SQUEEZE
struct vdfs4_squeeze_chunk_info {
	__u16 order;
	struct list_head list;
};
#endif


/** @brief	Maintains private inode info.
 */
struct vdfs4_inode_info {
	/** VFS inode */
	struct inode	vfs_inode;
	/* record type */
	__u8 record_type;
	/** The inode fork information */
		struct vdfs4_fork_info fork;
	/* file-based decompression info */
	struct vdfs4_file_based_info *fbc;
	/* runtime fork */
	struct list_head runtime_extents;
	/** Truncate_mutex is for serializing vdfs4_truncate_blocks() against
	 *  vdfs4_getblock()
	 */
	struct mutex truncate_mutex;
	/** Name information */
	char *name;
	/** Parent ID */
	__u64 parent_id;
	/** Inode flags */
	long unsigned int flags;

	/* for vdfs4_sb_info->orphan_inodes */
	struct list_head orphan_list;
	__u64 next_orphan_id;

	/** difference between file_open() and file_release() calls */
	atomic_t open_count;
#ifdef CONFIG_VDFS4_DEBUG_AUTHENTICAION
	int informed_about_fail_read;
#endif
#ifdef CONFIG_VDFS4_SQUEEZE
	struct list_head to_read_list;
	spinlock_t to_read_lock;
	struct vdfs4_squeeze_chunk_info* sci;
#endif
};

struct vdfs4_snapshot_info {
	/** Lock metadata update */
	struct mutex insert_lock;
	/** Transaction lock */
	struct rw_semaphore transaction_lock;
	struct rw_semaphore writeback_lock;
	/* snapshot tables protections */
	struct rw_semaphore tables_lock;
	/* current snapshot state : describe current and next snapshot */
	unsigned long *snapshot_bitmap;
	/* next snapshot state */
	unsigned long *next_snapshot_bitmap;
	/* moved iblocks bitmap */
	unsigned long *moved_iblock;

	/* sizeof snapshot_bitmap & next_snapshot_bitmap in bits */
	unsigned long bitmap_size_in_bits;
	/* last allocation place for btree */
	unsigned long int hint_btree;
	/* last allocation place for bitmaps */
	unsigned long int hint_bitmaps;
	/* --------------------- */
	/* base table */
	struct vdfs4_base_table *base_t;
	/* extended table page */
	struct vdfs4_extended_table *extended_table;
	/* first free block in tables area */
	sector_t iblock;
	__u32 sync_count;
	/* dirty pages ammount */
	unsigned int dirty_pages_count;
	/* flag - use base table or expand table */
	__u8 use_base_table;
	__u8 exteneded_table_count;
};

enum snapshot_table_type {
	SNAPSHOT_BASE_TABLE,
	SNAPSHOT_EXT_TABLE
};

/**  @brief	struct for writeback function
 *
 */
struct vdfs4_mpage_data {
	sector_t last_block_in_bio;
	struct bio *bio;
};


struct vdfs4_attr {
	struct attribute attr;
	ssize_t (*show)(struct vdfs4_sb_info *, char *);
	ssize_t (*store)(struct vdfs4_sb_info *, const char *, size_t);
};

/**
 * @brief		Get eMMCFS inode info structure from
 *			encapsulated inode.
 * @param [in]	inode	VFS inode
 * @return		Returns pointer to eMMCFS inode info data structure
 */
static inline struct vdfs4_inode_info *VDFS4_I(struct inode *inode)
{
	return container_of(inode, struct vdfs4_inode_info, vfs_inode);
}

/**
 * @brief		Get eMMCFS superblock from VFS superblock.
 * @param [in]	sb	The VFS superblock
 * @return		Returns eMMCFS run-time superblock
 */
static inline struct vdfs4_sb_info *VDFS4_SB(struct super_block *sb)
{
	return sb->s_fs_info;
}


static inline int vdfs4_produce_err(struct vdfs4_sb_info *sbi)
{
	if (sbi->bugon_count <= 0) {
		BUG_ON(sbi->bugon_count < 0);
		sbi->bugon_count--;
		return -ERANGE;
	}
	sbi->bugon_count--;

	return 0;
}

/**
 * @brief	save function name and error code to oops area (first 1K of
 * a volume).
 */
int vdfs4_log_error(struct vdfs4_sb_info *sbi, unsigned int ,
		const char *name, int err);

/**
 * @brief		wrapper : write function name and error code on disk in
 *			debug area
 * @param [in]	sbi	Printf format string.
 * @return	void
 */
#define VDFS4_LOG_ERROR(sbi, err) vdfs4_log_error(sbi, __LINE__, __func__, err)

void __printf(2, 3)
vdfs4_fatal_error(struct vdfs4_sb_info *sbi, const char *fmt, ...);
void destroy_layout(struct vdfs4_sb_info *sbi);

/**
 * @brief		Validate fork.
 * @param [in] fork	Pointer to the fork for validation
 * @return		Returns 1 if fork is valid, 0 in case of wrong fork
 * */
static inline int is_fork_valid(const struct vdfs4_fork *fork,
		struct vdfs4_sb_info *sbi)
{
	int ext;
	if (!fork)
		goto ERR;

	if (fork->total_blocks_count > sbi->volume_blocks_count)
		goto ERR;
	for (ext = 0; ext < VDFS4_EXTENTS_COUNT_IN_FORK; ext++) {
		if ((fork->extents[ext].extent.begin +
				fork->extents[ext].extent.length) >
				sbi->volume_blocks_count)
			goto ERR;
	}
	return 1;
ERR:
	VDFS4_ERR("fork is invalid\n");
	return 0;
}

/**
 * @brief		Set flag in superblock.
 * @param [in]	sbi	Superblock information
 * @param [in]	flag	Value to be set
 * @return	void
 */
static inline void set_sbi_flag(struct vdfs4_sb_info *sbi, int flag)
{
	set_bit(flag, &sbi->flags);
}

/**
 * @brief		Check flag in superblock.
 * @param [in]	sbi	Superblock information
 * @param [in]	flag	Flag to be checked
 * @return		Returns flag value
 */
static inline int is_sbi_flag_set(struct vdfs4_sb_info *sbi, int flag)
{
	return test_bit(flag, &sbi->flags);
}

/**
 * @brief		Clear flag in superblock.
 * @param [in]	sbi	Superblock information
 * @param [in]	flag	Value to be clear
 * @return	void
 */
static inline void clear_sbi_flag(struct vdfs4_sb_info *sbi, int flag)
{
	clear_bit(flag, &sbi->flags);
}

/**
 * @brief		Set flag in vdfs4 inode info
 * @param [in]	sbi	VFS inode
 * @param [in]	flag	flag to set
 * @return		Return previous flag value
 */
static inline int set_vdfs4_inode_flag(struct inode *inode, int flag)
{
	struct vdfs4_inode_info *inode_info = VDFS4_I(inode);

	return test_and_set_bit(flag, &inode_info->flags);
}

static inline struct inode *INODE(struct kiocb *iocb)
{
	return iocb->ki_filp->f_path.dentry->d_inode;
}

/**
 * @brief		Set flag in vdfs4 inode info
 * @param [in]	sbi	VFS inode
 * @param [in]	flag	Flag to be checked
 * @return		Returns flag value
 */
static inline int is_vdfs4_inode_flag_set(struct inode *inode, int flag)
{
	struct vdfs4_inode_info *inode_info = VDFS4_I(inode);
	return test_bit(flag, &inode_info->flags);
}

/**
 * @brief		Clear flag in vdfs4 inode info
 * @param [in]	sbi	VFS inode
 * @param [in]	flag	Flag to be cleared
 * @return		Returns flag value
 */
static inline int clear_vdfs4_inode_flag(struct inode *inode, int flag)
{
	struct vdfs4_inode_info *inode_info = VDFS4_I(inode);

	return test_and_clear_bit(flag, &inode_info->flags);
}


/**
 * @brief		Copy layout fork into run time fork.
 * @param [out]	rfork	Run time fork
 * @param [in]	lfork	Layout fork
 * @return	void
 */
static inline void vdfs4_lfork_to_rfork(struct vdfs4_fork *lfork,
		struct vdfs4_fork_info *rfork)
{
	unsigned i;
	/* Caller must check fork, call is_fork_valid(struct vdfs4_fork *) */
	/* First blanked extent means - no any more valid extents */

	rfork->used_extents = 0;
	for (i = 0; i < VDFS4_EXTENTS_COUNT_IN_FORK; ++i) {
		struct vdfs4_iextent *lextent;

		lextent = &lfork->extents[i];

		rfork->extents[i].first_block =
				le64_to_cpu(lextent->extent.begin);
		rfork->extents[i].block_count =
				le32_to_cpu(lextent->extent.length);
		rfork->extents[i].iblock = le64_to_cpu(lextent->iblock);
		if (rfork->extents[i].first_block)
			rfork->used_extents++;
	}
}

/**
 * @brief		Get current time for inode.
 * @param [in]	inode	The inode for which current time will be returned
 * @return		Time value for current inode
 */
static inline struct timespec vdfs4_current_time(struct inode *inode)
{
	return (inode->i_sb->s_time_gran < NSEC_PER_SEC) ?
		current_fs_time(inode->i_sb) : CURRENT_TIME_SEC;
}

static inline int get_sign_length(enum sign_type type)
{
	switch (type) {
		case VDFS4_SIGN_RSA1024:
			return VDFS4_RSA1024_SIGN_LEN;
		case VDFS4_SIGN_RSA2048:
			return VDFS4_RSA2048_SIGN_LEN;
		case VDFS4_SIGN_NONE:
			return 0;
		default:
			return -1;
	}
}

static inline rsakey_t* get_rsa_key_by_type(struct vdfs4_sb_info *sbi, enum sign_type type)
{
	switch (type) {
#ifdef 	CONFIG_VDFS4_ALLOW_LEGACY_SIGN
		case VDFS4_SIGN_RSA1024:
			return sbi->rsa_key_legacy;
#endif
		case VDFS4_SIGN_RSA2048:
			return sbi->rsa_key;
		default:
			return NULL;
	}
}

/* super.c */

int vdfs4_sync_fs(struct super_block *sb, int wait);
int vdfs4_sync_first_super(struct vdfs4_sb_info *sbi);
int vdfs4_sync_second_super(struct vdfs4_sb_info *sbi);
void vdfs4_dirty_super(struct vdfs4_sb_info *sbi);
void vdfs4_init_inode(struct vdfs4_inode_info *inode);

/** todo move to btree.c ?
 * @brief	The eMMCFS B-tree common constructor.
 */
int vdfs4_fill_btree(struct vdfs4_sb_info *sbi,
		struct vdfs4_btree *btree, struct inode *inode);

/**
 * @brief	Function removes superblock from writeback thread queue.
 */
void vdfs4_remove_sb_from_wbt(struct super_block *sb);

/* inode.c */
struct inode *vdfs4_get_image_inode(struct vdfs4_sb_info *sbi,
		__u64 parent_id, __u8 *name, size_t name_len);
int vdfs4_prepare_compressed_file_inode(struct vdfs4_inode_info *inode_i);
int vdfs4_init_file_decompression(struct vdfs4_inode_info *inode_i, int debug);
int vdfs4_disable_file_decompression(struct vdfs4_inode_info *inode_i);

/**
 * @brief	Checks and copy layout fork into run time fork.
 */
int vdfs4_parse_fork(struct inode *inode, struct vdfs4_fork *lfork);

/**
 * @brief	Form layout fork from run time fork.
 */
void vdfs4_form_fork(struct vdfs4_fork *lfork, struct inode *inode);

/**
 * @brief	Translation logical numbers to physical.
 */
int vdfs4_get_block(struct inode *inode, sector_t iblock,
			struct buffer_head *bh_result, int create);
int vdfs4_get_block_da(struct inode *inode, sector_t iblock,
	struct buffer_head *bh_result, int create);
int vdfs4_get_int_block(struct inode *inode, sector_t iblock,
	struct buffer_head *bh_result, int create, int fsm_flags);

/**
 * @brief	Get free inode index[es].
 */
int vdfs4_get_free_inode(struct vdfs4_sb_info *sbi, ino_t *i_ino,
		unsigned int count);

/**
 * @brief	Free several inodes.
 */
int vdfs4_free_inode_n(struct vdfs4_sb_info *sbi, ino_t inode_n, int count);
/**
 * @brief	Write inode to bnode.
 */
int vdfs4_write_inode(struct inode *inode, struct writeback_control *wbc);

/**
 * @brief	Propagate flags from inode i_flags to VDFS4_I(inode)->flags.
 */
void vdfs4_get_vfs_inode_flags(struct inode *inode);

/**
 * @brief	Set vfs inode i_flags according to VDFS4_I(inode)->flags.
 */
void vdfs4_set_vfs_inode_flags(struct inode *inode);

/**
 * @brief		Method to look up an entry in a directory.
 */
struct dentry *vdfs4_lookup(struct inode *dir, struct dentry *dentry,
						unsigned int flags);
struct inode *vdfs4_iget(struct vdfs4_sb_info *sbi, ino_t ino);

/**
 * @brief			Method to read inode.
 */
struct inode *vdfs4_get_inode_from_record(struct vdfs4_cattree_record *record,
		struct inode *parent);
struct inode *vdfs4_special_iget(struct super_block *sb, unsigned long ino);
struct inode *vdfs4_get_root_inode(struct vdfs4_btree *tree);
int vdfs4_get_iblock_extent(struct inode *inode, sector_t iblock,
		struct vdfs4_extent_info *result, sector_t *hint_block);
void vdfs4_free_reserved_space(struct inode *inode, sector_t iblocks_count);
/* options.c */

/**
 * @brief	Parse eMMCFS options.
 */
int vdfs4_parse_options(struct super_block *sb, char *input);
int vdfs4_show_options(struct seq_file *seq, struct dentry *root);

/* btree.c */
int vdfs4_check_bnode_reserve(struct vdfs4_btree *btree, int force_insert);
u16 vdfs4_btree_get_height(struct vdfs4_btree *btree);
/**
 * @brief	Get next B-tree record transparently to user.
 */
void *__vdfs4_get_next_btree_record(struct vdfs4_bnode **__bnode, int *index);

/**
 * @brief	B-tree verifying
 */
int vdfs4_verify_btree(struct vdfs4_btree *btree);

#ifdef CONFIG_VDFS4_SQUEEZE_PROFILING
void vdfs4_save_profiling_log(struct vdfs4_sb_info *sbi,
		ino_t ino, sector_t iblock, u32 blk_cnt);
#endif

/* bnode.c */
long vdfs4_fallocate(struct file *file, int mode, loff_t offset, loff_t len);
/**
 * @brief	Build free bnode bitmap runtime structure
 */
struct vdfs4_bnode_bitmap *vdfs4_build_free_bnode_bitmap(void *data,
		__u32 start_bnode_id, __u64 size_in_bytes,
		struct vdfs4_bnode *host_bnode);

#if defined(CONFIG_VDFS4_META_SANITY_CHECK)
void vdfs4_bnode_sanity_check(struct vdfs4_bnode *bnode);
void vdfs4_meta_sanity_check_bnode(void *bnode_data, struct vdfs4_btree *btree,
		pgoff_t index);
#endif
/**
 * @brief	Clear memory allocated for bnode bitmap.
 */
void vdfs4_destroy_free_bnode_bitmap(struct vdfs4_bnode_bitmap *bitmap);

/* cattree.c */

/**
 * @brief	Catalog tree key compare function for case-sensitive usecase.
 */
int vdfs4_cattree_cmpfn(struct vdfs4_generic_key *__key1,
		struct vdfs4_generic_key *__key2);

/**
 * @brief	Catalog tree key compare function for case-insensitive usecase.
 */
int vdfs4_cattree_cmpfn_ci(struct vdfs4_generic_key *__key1,
		struct vdfs4_generic_key *__key2);

/**
 * @brief	Allocate key for catalog tree record.
 */
struct vdfs4_cattree_key *vdfs4_alloc_cattree_key(int name_len,
		u8 record_type);

/**
 * @brief	Fill already allocated key with data.
 */
void vdfs4_fill_cattree_key(struct vdfs4_cattree_key *fill_key, u64 object_id,
		u64 parent_id, const char *name, unsigned int len);

/**
 * @brief	Fill already allocated value area (file or folder) with data
 *		from VFS inode.
 */
void vdfs4_fill_cattree_value(struct inode *inode, void *value_area);

/* extents.c */

int vdfs4_extree_insert_extent(struct vdfs4_sb_info *sbi,
		unsigned long object_id, struct vdfs4_extent_info *extent,
		int force_insert);
int vdfs4_exttree_cache_init(void);
void vdfs4_exttree_cache_destroy(void);
struct vdfs4_exttree_key *vdfs4_get_exttree_key(void);
void vdfs4_put_exttree_key(struct vdfs4_exttree_key *key);
int vdfs4_runtime_extent_add(sector_t iblock, sector_t alloc_hint,
		struct list_head *list);
int vdfs4_runtime_extent_del(sector_t iblock,
		struct list_head *list) ;
u32 vdfs4_runtime_extent_count(struct list_head *list);
sector_t vdfs4_truncate_runtime_blocks(sector_t new_size_iblocks,
		struct list_head *list);
u32 vdfs4_runtime_extent_exists(sector_t iblock, struct list_head *list);
/**
 * @brief	Add newly allocated blocks chunk to extents overflow area.
 */
int vdfs4_exttree_add(struct vdfs4_sb_info *sbi, unsigned long object_id,
		struct vdfs4_extent_info *extent, int force_insert);

/**
 * @brief	Extents tree key compare function.
 */
int vdfs4_exttree_cmpfn(struct vdfs4_generic_key *__key1,
		struct vdfs4_generic_key *__key2);

/* fsm.c */

#define VDFS4_FSM_ALLOC_DELAYED		0x01	/* for dalayed-allocation */
#define VDFS4_FSM_ALLOC_ALIGNED		0x02	/* align to superpage */
#define VDFS4_FSM_ALLOC_METADATA		0x04	/* transaction table locked */
#define VDFS4_FSM_FREE_UNUSED		0x10	/* never linked to inode */
#define VDFS4_FSM_FREE_RESERVE		0x20	/* put back to reserve */

/**
 * @brief	Build free space management.
 */
int vdfs4_fsm_build_management(struct super_block *);

/**
 * @brief	Destroy free space management.
 */
void vdfs4_fsm_destroy_management(struct super_block *);

/**
 * @brief	Get free space block chunk from tree and update free
 *		space manager bitmap.
 */
__u64 vdfs4_fsm_get_free_block(struct vdfs4_sb_info *sbi, __u64 block_offset,
		__u32 *length_in_blocks, unsigned int min_blk_count, int fsm_flags);
/**
 * @brief	Function is the fsm_free_block_chunk wrapper. Pust free space
 *		chunk to tree and updates free space manager bitmap.
 *		This function is called during truncate or unlink inode
 *		processes.
 */
int vdfs4_fsm_put_free_block(struct vdfs4_inode_info *inode_info,
		__u64 offset, __u32 length_in_blocks, int fsm_flags);
/**
 * @brief	Puts preallocated blocks back to the tree.
 */
void vdfs4_fsm_discard_preallocation(struct vdfs4_inode_info *inode_info);

void vdfs4_commit_free_space(struct vdfs4_sb_info *sbi);

/**
 * @brief	Initialize the eMMCFS FSM B-tree cache.
 */
int  vdfs4_fsm_cache_init(void);

/**
 * @brief	Destroy the eMMCFS FSM B-tree cache.
 */
void vdfs4_fsm_cache_destroy(void);

/* file.c */

/**
 * @brief	This function is called when a file is opened with O_TRUNC or
 *		truncated with truncate()/ftruncate() system calls.
 *		1) It truncates exttree extents according to new file size.
 *		2) If fork internal extents contains more extents than new file
 *		size in blocks, internal fork is also truncated.
 */
int vdfs4_truncate_blocks(struct inode *inode, loff_t new_size);

/* snapshot.c */

#ifdef CONFIG_VDFS4_DEBUG
void vdfs4_check_moved_iblocks(struct vdfs4_sb_info *sbi, struct page **pages,
		unsigned int page_count);
#endif
__le64 vdfs4_get_page_version(struct vdfs4_sb_info *sbi, struct inode *inode,
		pgoff_t page_index);
int vdfs4_build_snapshot_manager(struct vdfs4_sb_info *sbi);
void vdfs4_destroy_snapshot_manager(struct vdfs4_sb_info *sbi);
void vdfs4_start_transaction(struct vdfs4_sb_info *sbi);
void vdfs4_stop_transaction(struct vdfs4_sb_info *sbi);
void vdfs4_start_writeback(struct vdfs4_sb_info *sbi);
void vdfs4_stop_writeback(struct vdfs4_sb_info *sbi);
void vdfs4_add_chunk_bitmap(struct vdfs4_sb_info *sbi, struct page *page,
		int lock);
void vdfs4_add_chunk_bnode(struct vdfs4_sb_info *sbi, struct page **pages);
void vdfs4_add_chunk_no_lock(struct vdfs4_sb_info *sbi, ino_t object_id,
		pgoff_t page_index);
int vdfs4_update_translation_tables(struct vdfs4_sb_info *sbi);
int vdfs4_build_snapshot_manager(struct vdfs4_sb_info *sbi);
int vdfs4_get_meta_iblock(struct vdfs4_sb_info *sbi, ino_t ino_n,
		pgoff_t page_index, sector_t *meta_iblock);
loff_t vdfs4_special_file_size(struct vdfs4_sb_info *sbi, ino_t ino_n);
void vdfs4_update_bitmaps(struct vdfs4_sb_info *sbi);
int vdfs4_check_page_offset(struct vdfs4_sb_info *sbi, struct inode *inode,
		pgoff_t page_index, char *is_new, int force_insert);
int vdfs4_is_enospc(struct vdfs4_sb_info *sbi, int threshold);
int vdfs4_check_meta_space(struct vdfs4_sb_info *sbi);
__u64 validate_base_table(struct vdfs4_base_table *table);


/* data.c */
int vdfs4__read(struct inode *inode, int type, struct page **pages,
		unsigned int page_count, sector_t start_block);
int vdfs4_dump_chunk_to_disk(void *mapped_chunk, size_t chunk_length,
		const char *name, unsigned int length);
int vdfs4_read_page(struct block_device *, struct page *, sector_t ,
			unsigned int , unsigned int);
int vdfs4_write_page(struct vdfs4_sb_info *, struct page *, sector_t ,
			unsigned int , unsigned int, int);
struct page *vdfs4_read_create_page(struct inode *inode, pgoff_t page_index);

struct bio *allocate_new_bio(struct block_device *bdev,
		sector_t first_sector, unsigned int nr_vecs);
int vdfs4_read_pages(struct block_device *bdev, struct page **page,
			sector_t sector_addr, unsigned int page_count);
int vdfs4_write_snapshot_pages(struct vdfs4_sb_info *sbi, struct page **pages,
		sector_t start_sector, unsigned int page_count, int mode);

int vdfs4_mpage_writepages(struct address_space *mapping,
		struct writeback_control *wbc, long int *written_pages_num);
int vdfs4_get_block_file_based(struct inode *inode, pgoff_t page_index,
		sector_t *res_block);
int vdfs4_read_or_create_pages(struct inode *inode, pgoff_t start,
			      unsigned int nr_pages, struct page **pages,
			      enum vdfs4_read_type type, int start_block,
			      int force_insert);
int vdfs4_read_comp_pages(struct inode *inode, pgoff_t index,
			      int page_count, struct page **pages,
			      enum vdfs4_read_type type);
int vdfs4_sign_pages(struct page *page, int magic_len,
		__u64 version);
void vdfs4_update_block_crc(char *buff, unsigned int block_size,
		unsigned int magic_len);

int vdfs4_set_bits(char *buff, int buff_size, unsigned int offset,
		unsigned int count, unsigned int magic_len,
		unsigned int block_size);

int vdfs4_clear_bits(char *buff, int buff_size, unsigned int offset,
		unsigned int count, unsigned int magic_len,
		unsigned int block_size);

int vdfs4_sync_metadata(struct vdfs4_sb_info *sbi);

int vdfs4_table_IO(struct vdfs4_sb_info *sbi, void *buffer,
		__u64 buffer_size, int rw, sector_t *iblock);

struct page *vdfs4_read_or_create_page(struct inode *inode, pgoff_t index,
		enum vdfs4_read_type type);
struct bio *vdfs4_mpage_bio_submit(int rw, struct bio *bio);

int vdfs4_mpage_writepage(struct page *page,
		struct writeback_control *wbc, void *data);

int vdfs4_get_table_sector(struct vdfs4_sb_info *sbi, sector_t iblock,
		sector_t *result);
struct vdfs4_base_table_record *vdfs4_get_table(struct vdfs4_sb_info *sbi,
		ino_t ino);
int vdfs4_read_chunk(struct page *page, struct page **chunk_pages,
	struct vdfs4_comp_extent_info *cext);
int vdfs4_auth_decompress(struct inode *inode, struct page **chunk_pages,
		pgoff_t index, struct vdfs4_comp_extent_info *cext,
		struct page *page);
int vdfs4_auth_decompress_hw2(struct inode *inode, struct page *page);
void *vdfs_get_hwdec_fn(struct vdfs4_inode_info *inode_i);

/* orphan.c */
int vdfs4_add_to_orphan(struct vdfs4_sb_info *sbi, struct inode *inode);
void vdfs4_del_from_orphan(struct vdfs4_sb_info *sbi, struct inode *inode);
int vdfs4_process_orphan_inodes(struct vdfs4_sb_info *sbi);
int __vdfs4_write_inode(struct vdfs4_sb_info *sbi, struct inode *inode);

/* ioctl.c */

/**
 * @brief	ioctl (an abbreviation of input/output control) is a system
 *		call for device-specific input/output operations and other
 *		 operations which cannot be expressed by regular system calls
 */

long vdfs4_ioctl(struct file *filp, unsigned int cmd, unsigned long arg);
long vdfs4_compat_ioctl(struct file *filp, unsigned int cmd, unsigned long arg);
long vdfs4_dir_ioctl(struct file *filp, unsigned int cmd, unsigned long arg);

/* xattr.c */
int vdfs4_setxattr(struct dentry *dentry, const char *name, const void *value,
		size_t size, int flags);

ssize_t vdfs4_getxattr(struct dentry *dentry, const char *name, void *buffer,
		size_t size);
int vdfs4_removexattr(struct dentry *dentry, const char *name);

int vdfs4_xattrtree_cmpfn(struct vdfs4_generic_key *__key1,
		struct vdfs4_generic_key *__key2);
ssize_t vdfs4_listxattr(struct dentry *dentry, char *buffer, size_t size);
int vdfs4_xattrtree_remove_all(struct vdfs4_btree *tree, u64 object_id);

struct posix_acl *vdfs4_get_acl(struct inode *inode, int type);
int vdfs4_init_acl(struct inode *inode, struct inode *dir);
int vdfs4_chmod_acl(struct inode *inode);
int vdfs4_init_security_xattrs(struct inode *inode,
		const struct xattr *xattr_array, void *fs_data);

/* decompress.c */
int vdfs4_unpack_chunk_zlib(void *src, void *dst, size_t offset,
		size_t len_bytes, size_t chunk_length);
int vdfs4_unpack_chunk_gzip(void *src, void *dst, size_t offset,
		size_t len_bytes, size_t chunk_length);
int vdfs4_unpack_chunk_lzo(void *src, void *dst, size_t offset,
		size_t len_bytes, size_t chunk_length);
void vdfs4_dump_fbc_error(struct vdfs4_inode_info *inode_i, void *packed,
		struct vdfs4_comp_extent_info *cext);

static inline unsigned is_tree(ino_t object_type)
{
	if (object_type == VDFS4_CAT_TREE_INO ||
			object_type == VDFS4_EXTENTS_TREE_INO ||
			object_type == VDFS4_XATTR_TREE_INO)
		return 1;
	else
		return 0;
}

/* authenticaion.c */
int vdfs4_verify_file_signature(struct vdfs4_inode_info *inode_i,
		enum sign_type sign_type, void *data);
int vdfs4_check_hash_meta(struct vdfs4_inode_info *inode_i,
		struct vdfs4_comp_file_descr *descr);
int vdfs4_check_hash_chunk(struct vdfs4_inode_info *inode_i,
		void *buffer, size_t length, size_t extent_idx);
int vdfs4_check_hash_meta(struct vdfs4_inode_info *inode_i,
		struct vdfs4_comp_file_descr *descr);

int vdfs4_verify_rsa_md5_signature(unsigned char *buf, size_t buf_len,
		unsigned char *signature);
#ifdef CONFIG_VDFS4_DATA_AUTHENTICATION
int vdfs4_verify_superblock_rsa_signature(enum hash_type hash_type,
		enum sign_type sign_type,
		void *buf, size_t buf_len,
		void *signature, rsakey_t *pkey);
#endif
int vdfs4_check_hash_chunk_no_calc(struct vdfs4_inode_info *inode_i,
		size_t extent_idx, void *hash_calc);

/* macros */
# define IFTODT(mode)	(((mode) & 0170000) >> 12)
# define DTTOIF(dirtype)	((dirtype) << 12)

#define VDFS4_GET_CATTREE_RECORD_TYPE(record) (record->key->record_type)

#define VDFS4_IS_FOLDER(record_type)\
	((record_type) == VDFS4_CATALOG_FOLDER_RECORD)

#define VDFS4_IS_FILE(record_type)\
	((record_type) & VDFS4_CATALOG_FILE_RECORD)

#define VDFS4_IS_REGFILE(record_type)\
	((record_type) == VDFS4_CATALOG_FILE_RECORD)

#define VDFS4_LEB_FROM_BLK(sbi, blk) (blk >> sbi->log_blocks_in_leb)
#define VDFS4_LEB_START_BLK(sbi, leb_n) (leb_n << sbi->log_blocks_in_leb)
#define VDFS4_BLK_INDEX_IN_LEB(sbi, blk) \
		(blk & ((1 << sbi->log_blocks_in_leb) - 1))

#define VDFS4_ESB_OFFSET		(2 * SB_SIZE)

#define VDFS4_RAW_SB(sbi)	((struct vdfs4_super_block *) \
				((char *)sbi->raw_superblock + 1 * SB_SIZE))

#define VDFS4_RAW_EXSB_COPY(sbi) ((struct vdfs4_extended_super_block *) \
				(sbi->raw_superblock_copy + 3 * SB_SIZE))

#define VDFS4_LAST_EXTENDED_SB(sbi) ((struct vdfs4_extended_super_block *) \
			(sbi->raw_superblock + 3 * SB_SIZE))
#define VDFS4_DEBUG_AREA_START(sbi) le64_to_cpu(VDFS4_LAST_EXTENDED_SB(sbi)-> \
		debug_area.begin)

#define VDFS4_DEBUG_AREA_LENGTH_BLOCK(sbi) le32_to_cpu( \
			(VDFS4_RAW_EXSB(sbi))->debug_area.length)

#define VDFS4_DEBUG_AREA(sbi) (sbi->debug_area)
#define VDFS4_DEBUG_PAGES(sbi) (sbi->debug_pages)

#define VDFS4_DEBUG_AREA_LENGTH_BYTES(sbi) (VDFS4_DEBUG_AREA_LENGTH_BLOCK(sbi) \
		<< sbi->block_size_shift)

#define VDFS4_DEBUG_AREA_PAGE_COUNT(sbi) (VDFS4_DEBUG_AREA_LENGTH_BYTES(sbi) \
		>> PAGE_CACHE_SHIFT)

#define DEBUG_AREA_CRC_OFFSET(sbi) (VDFS4_DEBUG_AREA_LENGTH_BYTES(sbi) \
			- sizeof(unsigned int))

#define VDFS4_LOG_DEBUG_AREA(sbi, err) \
	vdfs4_log_error(sbi, __LINE__, __func__, err);

#define VDFS4_SNAPSHOT_VERSION(x) (((__u64)le32_to_cpu(x->descriptor.\
		mount_count) << 32) | (le32_to_cpu(x->descriptor.sync_count)))

#define VDFS4_IS_COW_TABLE(table) (!strncmp(table->descriptor.signature, \
	VDFS4_SNAPSHOT_BASE_TABLE,\
	sizeof(VDFS4_SNAPSHOT_BASE_TABLE) - 1))

#define VDFS4_EXSB_VERSION(exsb) (((__u64)le32_to_cpu(exsb->mount_counter)\
		<< 32) | (le32_to_cpu(exsb->sync_counter)))

#define VDFS4_GET_TABLE_OFFSET(sbi, x) (le32_to_cpu( \
	((struct vdfs4_base_table *)sbi->snapshot_info->base_t)-> \
		translation_table_offsets[VDFS4_SF_INDEX(x)]))

#define VDFS4_LAST_TABLE_INDEX(sbi, x) (le64_to_cpu( \
	((struct vdfs4_base_table *)sbi->snapshot_info->base_t)-> \
	last_page_index[VDFS4_SF_INDEX(x)]))

#define GET_TABLE_INDEX(sbi, ino_no, page_offset) \
		(is_tree(ino_no) ? page_offset \
		>> (sbi->log_blocks_in_leb + sbi->block_size_shift - \
		PAGE_SHIFT) : page_offset)

#define PAGE_TO_SECTORS(x) (x * ((1 << (PAGE_CACHE_SHIFT - SECTOR_SIZE_SHIFT))))

#define INODEI_NAME(inode_i) ((inode_i == NULL) ? "<null inodei>" :\
								((inode_i->name == NULL) ? "<noname>" : inode_i->name))

/* VDFS4 mount options */
enum vdfs4_mount_options {
	VDFS4_MOUNT_TINY,
	VDFS4_MOUNT_TINYSMALL,
	VDFS4_MOUNT_CASE_INSENSITIVE,
	VDFS4_MOUNT_FORCE_RO,
	VDFS4_MOUNT_FMASK,
	VDFS4_MOUNT_DMASK,
	VDFS4_MOUNT_DO_NOT_CHECK_SIGN,
	VDFS4_MOUNT_DESTROY_LAYOUT,
};

#define clear_option(sbi, option)	(sbi->mount_options &= \
						~(1 << VDFS4_MOUNT_##option))
#define set_option(sbi, option)		(sbi->mount_options |= \
						(1 << VDFS4_MOUNT_##option))
#define test_option(sbi, option)	(sbi->mount_options & \
						(1 << VDFS4_MOUNT_##option))

#ifdef CONFIG_VDFS4_DEBUG

/* check for active transaction or writeback */
static inline void vdfs4_assert_transaction(struct vdfs4_sb_info *sbi)
{
	/*
	 * Both vdfs4_start_transaction and vdfs4_start_writeback
	 * uses current->journal_info as recursion-preventing counter.
	 */
	if (sbi->sb->s_flags & MS_ACTIVE)
		WARN_ON(!current->journal_info);
}

/* btree must be locked for read or write */
static inline void vdfs4_assert_btree_lock(struct vdfs4_btree *btree)
{
	if (btree->sbi->sb->s_flags & MS_ACTIVE)
		lockdep_assert_held(&btree->rw_tree_lock);
}

/* use it if btree must be locked for write */
static inline void vdfs4_assert_btree_write(struct vdfs4_btree *btree)
{
	if (btree->sbi->sb->s_flags & MS_ACTIVE) {
		lockdep_assert_held(&btree->rw_tree_lock);
		if (WARN_ON(down_read_trylock(&btree->rw_tree_lock))) {
			up_read(&btree->rw_tree_lock);
			BUG();
		}
	}
}

static inline void vdfs4_assert_i_mutex(struct inode *inode)
{
	lockdep_assert_held(&inode->i_mutex);
}


#else /* CONFIG_VDFS4_DEBUG */

static inline void vdfs4_assert_transaction(struct vdfs4_sb_info *sbi) { }
static inline void vdfs4_assert_btree_lock(struct vdfs4_btree *btree) { }
static inline void vdfs4_assert_btree_write(struct vdfs4_btree *btree) { }
static inline void vdfs4_assert_i_mutex(struct inode *inode) { }
#endif /* CONFIG_VDFS4_DEBUG */

#endif /* USER_SPACE */

#endif /* _VDFS4_VDFS4_H_ */
