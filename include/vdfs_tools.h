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

#ifndef __VDFS4_TOOLS_H__
#define __VDFS4_TOOLS_H__

#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <stdbool.h>
#include "kernel_redef.h"
#include "vdfs4_layout.h"
#include "debug.h"
#include "vdfs4.h"
#include "btree.h"
#include "cattree.h"
#include "exttree.h"
#include "xattrtree.h"
#include "errors.h"
#include "logger.h"
#include "encrypt.h"
#include <openssl/rsa.h>

#define VDFS_TOOLS_VERSION TOOLS_VERSION	//version is defined in makefile

/* constant used to separate seconds from full time in nanoseconds */
#define NANOSEC_DIVIDER 1000000000
#define VDFS4_FULL_PATH_LEN	1023
#define XATTR_VAL_SIZE		1023
/**
 * @brief       Set bit flag in variable.
 * @param [in]  var     Variable with flags
 * @param [in]  flag    Flag to set
 * @return		New value of variable
 */
#define SET_FLAG(var, flag) (var |= (1 << flag))

/**
 * @brief       Clear bit flag in variable.
 * @param [in]  var		Variable with flags
 * @param [in]  flag    Flag to clear
 * @return		New value of variable
 */
#define CLEAR_FLAG(var, flag) (var &= (~(1 << flag)))

/**
 * @brief       Chech if flag is set
 * @param [in]  var		Variable with flags
 * @param [in]  flag    Flag to check
 * @return		Returns 0 if flag is clear, 1 if flag is set.
 */
#define IS_FLAG_SET(var, flag) (var & (1 << flag))


typedef unsigned char * (vdfs4_hash_algorithm_func)(const unsigned char *d, size_t n,
		unsigned char *md);
enum tools_flags {
	/* MKFS flag bits positions */
	/*00*/ IMAGE = 0,
	/*01*/ SIMULATE,
	/*02*/ VERBOSE,
	/*03*/ MORE_VERBOSE,
	/*04*/ NO_STRIP_IMAGE,
	/*05*/ READ_ONLY_IMAGE,
	/*06*/ CASE_INSENSITIVE,
	/*07*/ ALL_ROOT,
	/* FSCK flag bits positions */
	/*08*/ SQUASH_CONF_RESTORE,
	/*09*/ COLOR,
	/*10*/ CATTREE_BNODE_DUMP,
	/*11*/ EXTTREE_BNODE_DUMP,
	/*12*/ PARSE_DEBUG_AREA,
	/*13*/ FIND_BY_NAME,
	/*14*/ DUMP_META_BLOCK,
	/*15*/ PERFORM_INJECTION,
	/*16*/ RESTORE,
	/*17*/ UPDATE_CRC,
	/*Conversion utility flags*/
	/*18*/ CHECK,
	/*19*/ TRANSFORM,
	/* MKFS extra flags */
	/*20*/ NO_DECODE,
	/*21*/ SIGN_ALL,
	/*22*/ SHA_256,
	/*23*/ MD_5,
	/*24*/ SHA_1,
	/*25*/ ENCRYPT_EXEC,
	/*26*/ ENCRYPT_ALL,
	/*27*/ LIMITED_SIZE,
};

/* space manager constants */
#define ADDR_ANY	0


/* VDFS4 metadata maximum value (used for journal expanding) */
#define VDFS4_METADATA_PERCENT_DEFAULT 5
#define VERSION ((u64)(1))
/** VDFS4 default values */
#define MIN_VOLUME_SIZE    3145728
#define BLOCK_SIZE_DEFAULT 4096
#define ERASE_BLOCK_SIZE_DEFAULT 2097152
#define SUPER_PAGE_SIZE_DEFAULT 16384
#define VOLUME_SIZE_DEFAULT 1073741824
#define VOLUME_NAME_DEFAULT "VDFS4_VOLUME"
#define DEBUG_AREA_DEFAULT_START 2
#define DEBUG_AREA_DEFAULT_SIZE 4
#define SMALL_AREA_CELL_DEFAULT 1024
#define DEFAULT_SMALL_AREA_SIZE SUPER_PAGE_SIZE_DEFAULT
#define DEFAULT_MIN_SPACE_SAVING_RATIO (25)

#define VDFS4_VERSION_DEFAULT 0x10

#define RSA_KEY_SIZE	256

#define HEAD_BNODE_ID 0
#define ROOT_BNODE_ID 1

#define min(a, b) ((a < b) ? a : b)
#define max(a, b) ((a > b) ? a : b)

#define MIN_SUPER_PAGE_SIZE 8192

/* Modes of working of particular tool */
/* This variable should be unique for each utility */
extern const unsigned int vdfs_tools_mode;
#define VDFS4_TOOLS_MULTITHREAD         (1 << 0)
/* Two bits for checking type of get_bnode */
#define VDFS4_TOOLS_GET_BNODE_TYPE_MASK (7 << 1)
#define VDFS4_TOOLS_GET_BNODE_FROM_VOL  (0 << 1)
#define VDFS4_TOOLS_GET_BNODE_FROM_MEM  (1 << 1)
#define VDFS4_TOOLS_GET_BNODE_DEBUG     (2 << 1)
#define VDFS4_TOOLS_GET_BNODE_FROM_VOLUME_PUT		(4 << 1)

/* This is for vdfs image update verification */
#define VDFS_IMG_VERIFY_MAGIC (0x0DEFACED)
#define VDFS_IMG_VERIFY_OFFSET (0x1000)	//Last page of area.
#define VDFS_DBG_AREA_OFFSET (0x2000)	//It is fixed
#define VDFS_DBG_AREA_MAGIC "Vdbg"
#define VDFS_DBG_AREA_VER (1)
#define VDFS_DBG_VERIFY_START (0x3aa33aa3)
#define VDFS_DBG_VERIFY_OK (0x5a5a5a5a)
#define VDFS_DBG_VERIFY_FAIL (0xdead4ead)
#define VDFS_DBG_VERIFY_MKFS (0x0a0a0a0a)
#define VDFS_DBG_ERR_MAX_CNT (10)
struct vdfs_err_info
{
	uint16_t idx;
	uint16_t vdfs_err_type_k;
	uint32_t proof[2];
	uint32_t reserved;
	uint8_t note[32];
} __attribute__((packed));

struct vdfs_dbg_info
{
	uint32_t verify_result;
	uint32_t err_count;
}__attribute__((packed));

struct vdfs_dbg_area_map
{
	uint8_t magic[4];
	uint32_t dbgmap_ver;
	uint32_t reserved[6];
	union {
		struct vdfs_dbg_info dbg_info;
		uint32_t for_fixed_size[120];
	} dbg;
	union {
		struct vdfs_err_info err_list[VDFS_DBG_ERR_MAX_CNT];
		uint32_t for_fixed_size[128];
	} err;
} __attribute__((packed));

/** VDFS4 default values end*/

/*****************************************************************************/
/* STRUCTURES                                                                */
/*****************************************************************************/

struct vdfs4_version {
	/** Major version number */
	__u8 major:4;
	/** Minor version number */
	__u8 minor:4;
} __packed;

/** The struct keeps an vdfs4 image data. This is a handle to call disk
 * operation.
*/
struct vdfs4_image {
	/** file ip of opened device of file image */
	int file_id;
};

/** @brief	Maintains private information for each vdfs4 sysbsystem
 *
 */
struct vdfs4_subsystem_data {
	/* subsystem number */
	__u8 sub_system_id;
	char *subsystem_name;
	/* buffer for subsystem metadata */
	char *buffer;
	/** buffer size in bytes */
	u_int32_t buffer_size;
	/** blocks on volume */
	struct vdfs4_fork_info fork;
};

struct space_manager_item {
	struct space_manager_item *next;
	u_int64_t offset;
	u_int32_t length;
};

struct space_manager_info {
	u_int64_t bits_count;
	u_int64_t bitmap_start_block;
	u_int32_t bitmap_block_count;
	u_int64_t first_free_address;
	struct space_manager_item *space_manager_list;
	struct vdfs4_subsystem_data subsystem;
};


struct vdfs_tools_btree_info {
	struct vdfs4_btree vdfs4_btree;

	/* used bnodes count */
	u_int64_t bnodes_count;
	/* how mach already allocated bnodes in memory */
	u_int64_t allocated_bnodes_count;

	struct vdfs4_subsystem_data tree;
	struct vdfs4_bnode **bnode_array;
};

/** @brief	A structure used as a base for list of hlinks paths
 */
struct hlink_list_item {
	/** object id of catalog */
	__le64 ino_n;
	__le64 new_ino_n;
	__le32 links;
	/** directory name with full path */
	char name[VDFS4_FULL_PATH_LEN];
	/** a pointer to the next list item */
	struct hlink_list_item *next;

};

struct data_range {
	struct list_head list;
	__u64 start;
	__u64 length;
	__u32 crc;
	int has_crc;
};

void add_data_range(struct vdfs4_sb_info *sbi, struct list_head *data_ranges,
		__u64 start, __u64 size);
__u64 find_data_duplicate(struct list_head *data_ranges, int fd1,
		int fd2, __u64 start, __u64 size);
__u64 find_file_duplicate(struct vdfs4_sb_info *sbi, char *path);

struct snapshot_info {

	/* snapshot subsystem */
	struct vdfs4_subsystem_data snapshot_subsystem;

	/*  */
	__u32 snapshot_tables_size;

	/*  */
	__u32 metadata_size;
	int meta_tbc;
	int table_tbc;
	/* metadata extents */
	struct vdfs4_extent_info metadata_extent[VDFS4_META_BTREE_EXTENTS];

	/* translation tables extent */
	struct vdfs4_extent_info tables_extent;
	__u32 tables_extent_used;
	struct vdfs4_base_table *base_table;

	__u32 preallocation_len;
	__u32 checksum;
};

struct meta_hashtable_info {
	/* hashtable subsystem */
	struct vdfs4_subsystem_data subsystem;
	/* hashtable checksum */
	__u32 checksum;
};

struct vector {
	u64 mem_size;
	u64 size;
	int data_size;
	char *data;
};

enum unpack_error_types {
	UNPACK_CREATE_FILE_ERR,
	UNPACK_CREATE_SYMLINK_ERR,
	__NR_UNPACK_ERROR_TYPES,
};

struct error_tracer {
	uint enabled;
	uint errors[__NR_UNPACK_ERROR_TYPES];
	u_int32_t err_count;
};

/** @brief	Maintains private super block information.
 */
struct vdfs4_sb_info {
/*---------------------------- Part shared with driver sbi -------------------*/
	/** The VDFS4 on-disk superblock */
	struct vdfs4_super_block sb;
	/** The vdfs4 flags */
	unsigned long flags;
	/** Allocated block size in bytes */
	unsigned int block_size;
	/** Allocated erase block size in bytes */
	unsigned int erase_block_size;
	/** 64-bit uuid for volume */
	__u8 volume_uuid[16];
	/** File system files count */
	u_int64_t files_count;
	/** File system older count */
	u_int64_t folders_count;

	u_int32_t log_erase_block_size;
	u_int32_t log_sectors_per_block;
	u_int32_t log_blocks_in_leb;
	u_int32_t free_blocks_count;
	u_int32_t log_super_page_size;
	u_int32_t log_block_size;

	void *data;
	struct vdfs4_btree       *catalog_tree;
	struct vdfs4_btree       *extents_tree;
	struct vdfs4_btree       *xattr_tree;

	__u8 sign_type;

/*---------------------------- vdfs4-tools unique part ------------------------*/
	/** The VDFS4 on-disk extended superblock */
	struct vdfs4_extended_super_block esb;
	/* The VDFS4 disk operation struct */
	struct vdfs4_image disk_op_image;
	/** Flags used for tool's service needs */
	unsigned int service_flags;
	/** Super-page size of flash in bytes */
	unsigned int super_page_size;
	/** */

	char	volume_name[16];
	char *tmpfs_dir;

	/** Dump file descriptor */
	FILE *dump_file;
	/** File with list of squashfs images to install */
	FILE *squash_list_file;
	/** Filesystem timestamp */
	struct vdfs4_timespec timestamp;
	/** Filesystem Volume size in bytes (min) */
	u_int64_t min_volume_size;
	/** Filesystem Volume size in bytes (max) */
	u_int64_t max_volume_size;
	/** Generated Image file size */
	u_int64_t image_file_size;
	/** Size of metadata of new filesystem in bytes */
	unsigned long long metadata_size;
	/** Device or image file name */
	char *file_name;

	RSA *rsa_key;
	char *rsa_private_file;
	char *rsa_public_file;
	char *rsa_p_file;
	char *rsa_q_file;
	vdfs4_hash_algorithm_func *hash_alg;
	int hash_len;

	/** Encryption stuff */
	AES_KEY *aes_key;
	unsigned char raw_encryption_key[16];

	/** Path to the directory that contains files to be placed in image */
	char *root_path;
	/* snapshot info */
	struct snapshot_info snapshot;

	struct meta_hashtable_info meta_hashtable;

	struct vdfs4_subsystem_data inode_bitmap;
	__u64 last_allocated_inode_number;

	/* catalog tree contains information about files and folders */
	struct vdfs_tools_btree_info cattree;

	/* extents overflow tree contains extents of the fragmented files*/
	struct vdfs_tools_btree_info exttree;

	/* extended attributes tree for stroing additional file attributes*/
	struct vdfs_tools_btree_info xattrtree;

	/** Free space management */
	struct space_manager_info space_manager_info;

	struct vdfs4_extent_info debug_area;


	struct hlink_list_item hlinks_list;
	__u64 bnodes_count;
	__u32 vdfs4_start_block;
	struct list_head data_ranges;
	/* log chunk size */
	int log_chunk_size;
	__u8 is_superblock_reformatted;
	struct vdfs4_super_block sb_format_history;
	struct error_tracer err_tracer;
	int min_compressed_size;
	char *compr_type;
	int min_space_saving_ratio;
	int jobs;

	/* Profiling data (vdfs-squeeze) */
	char *profiling_data_path;
	struct list_head prof_data;
};

struct profiled_file {
	struct list_head list;
	char path[VDFS4_FULL_PATH_LEN];
	__u32 chunk_count;
	__u16* chunk_order;
};

static inline u_int64_t byte_to_block(u_int64_t val_in_byte,
	u_int32_t block_size)
{
	u_int64_t in_blocks;

	in_blocks = val_in_byte / block_size;
	if (val_in_byte % block_size != 0)
		in_blocks++;

	return in_blocks;
}

static inline u_int64_t byte_to_block_no_round(u_int64_t val_in_byte,
	u_int32_t block_size)
{
	return val_in_byte / block_size;
}

static inline u_int64_t block_to_byte(u_int64_t val_in_block,
	u_int32_t block_size)
{
	return val_in_block * block_size;
}

static inline void init_extent(struct  vdfs4_extent *extent,
		u_int64_t begin, u_int32_t length)
{
	memset(extent, 0, sizeof(struct vdfs4_extent));
	extent->begin = cpu_to_le64(begin);
	extent->length = cpu_to_le32(length);
}

static inline void init_iextent(struct  vdfs4_iextent *iextent,
		u_int64_t begin, u_int32_t length, u_int64_t iblock)
{
	memset(iextent, 0, sizeof(struct vdfs4_iextent));
	init_extent(&iextent->extent, begin, length);
	iextent->iblock = cpu_to_le64(iblock);
}

static inline void set_magic(void *magic_to_set, const char *magic_val)
{
	memcpy(magic_to_set, magic_val, strlen(magic_val));
}

static inline __le64 get_volume_body_start(struct vdfs4_sb_info *sbi)
{
	__le64 volume_body_offset = VDFS4_RESERVED_AREA_LENGTH +
			SB_SIZE + VDFS4_EXSB_LEN +
			block_to_byte(sbi->debug_area.block_count,
					sbi->block_size);

	return byte_to_block(volume_body_offset, sbi->block_size);
}

static inline __le64 get_volume_body_length(struct vdfs4_sb_info *sbi)
{
	__le64 volume_body_lenght = 0;

	volume_body_lenght = byte_to_block_no_round(sbi->max_volume_size,
			sbi->block_size);
	volume_body_lenght -= get_volume_body_start(sbi);
	volume_body_lenght -= 1;

	return volume_body_lenght;
}

/**
 * @brief       Simple function to calculate log base 2 value of 32-bit
 *			integer input value.
 * @param [in]  val		Value to calculate log base 2
 * @return	Log base 2 of input value.
 */
static inline u_int32_t log2_32(u_int32_t x)
{
	u_int32_t result = 0;
	u_int32_t x2_16 = (u_int32_t)1 << 16;
	u_int32_t x2_8  = (u_int32_t)1 << 8;
	u_int32_t x2_4  = (u_int32_t)1 << 4;
	u_int32_t x2_2  = (u_int32_t)1 << 2;
	u_int32_t x2_1  = (u_int32_t)2;

	if (x == 0)
		goto out;

	if (x >= x2_16)	{
		x >>= 16;
		result |= 1 << 4;
	}

	if (x >= x2_8) {
		x >>= 8;
		result |= 1 << 3;
	}

	if (x >= x2_4) {
		x >>= 4;
		result |= 1 << 2;
	}

	if (x >= x2_2) {
		x >>= 2;
		result |= 1 << 1;
	}

	if (x >= x2_1)
		result |= 1; /* 1 << 0 */

out:
	return result;
}

static inline u_int32_t log2_64(u_int64_t x)
{
	u_int32_t result = 0;
	u_int64_t x2_32 = (u_int64_t)1 << 32;
	u_int32_t x_32;

	if (x == 0)
		goto out;

	if (x >= x2_32) {
		x >>= 32;
		result |= 1 << 5;
	}

	x_32 = (u_int32_t)x;
	result |= log2_32(x_32);

out:
	return result;
}

static inline void print_version(void)
{
	log_note("vdfs tool version : %s", TOOLS_VERSION);
}

void set_magic(void *magic_to_set, const char *magic_val);
void set_permissions_from_st_mode(struct vdfs4_posix_permissions *permissions,
	mode_t st_mode, uid_t st_uid, gid_t st_gid);
void set_permissions_for_root_dir(struct vdfs4_posix_permissions
		*permissions);

int place_on_volume_subsystem(struct vdfs4_sb_info *sbi,
		struct vdfs4_subsystem_data *subsystem);
u64 metablock_to_iblock(struct vdfs4_sb_info *sbi, u64 metablock);
int iblock_to_metablock(struct vdfs4_sb_info *sbi, u64 iblock);
/* Hard link tree functions */
struct hlink_list_item *hl_list_item_find(struct hlink_list_item *head,
		__u64 object_id);
void hl_list_insert(struct hlink_list_item *head, struct hlink_list_item *new);
void hl_list_item_init(struct hlink_list_item *item, __le64 ino_n, char *name,
		__le64 new_ino_n);

/** snapshot functions */
int calculate_snapshot_size(struct vdfs4_sb_info *sbi);
int clear_snapshot(struct vdfs4_sb_info *sbi);
int calculate_and_place_on_volume_snapshot(struct vdfs4_sb_info *sbi);
int flush_snapshot(struct vdfs4_sb_info *sbi);
int place_on_volume_preallocation(struct vdfs4_sb_info *sbi);
int init_snapshot(struct vdfs4_sb_info *sbi);
int calculate_translation_tables_size(struct vdfs4_sb_info *sbi, int allocate);
void destroy_snapshot(struct vdfs4_sb_info *sbi);

/** meta hashtable functions */
int init_hashtable(struct vdfs4_sb_info *sbi);
int flush_hashtable(struct vdfs4_sb_info *sbi);
void destroy_hashtable(struct vdfs4_sb_info *sbi);

/* Hard link area functions */
int init_hl_area(struct vdfs4_sb_info *sbi);
int place_on_volume_hl_id_alloc(struct vdfs4_sb_info *sbi,
		u_int64_t block_offset);
int flush_hl_id_alloc(struct vdfs4_sb_info *sbi);
void destroy_hl_id_alloc(struct vdfs4_sb_info *sbi);
/* disk op functions */
/** This function opens a block device and returns a handle if device is valid.
*/
int open_disk(struct vdfs4_sb_info *sb_info);
/** This function creates image file. If file exists, this function
 * returns error. */
int vdfs4_create_image(const char *name,
			struct vdfs4_sb_info *sb_info);
/** Close disk handle. */
void close_disk(struct vdfs4_sb_info *sb_info);
/** Write block(s) to image. This function will write few blocks if src_size
 * exceeds the size of one block. */
int vdfs4_write_blocks(struct vdfs4_sb_info *sb_info,
			u_int64_t start,
			const void *src,
			u_int64_t src_size);

int vdfs4_write_bytes(struct vdfs4_sb_info *sb_info,
			u_int64_t start,
			const void *src,
			u_int64_t src_size);

/** This function read dest_size bytes from the image. Start position of
 * reading is defined by offset.
*/
int vdfs4_read_blocks(struct vdfs4_sb_info  *sb_info,
			u_int64_t start,
			void *dest,
			u_int64_t dest_size);


/** Write buffer content at the end of file
*/

int vdfs4_append(int fd, char *buffer, int size);
void get_next_dir(/*struct vdfs4_sb_info *sb_info*/);
void get_next_file(/*struct vdfs4_sb_info *sb_info*/);
void vdfs4_close_image(struct vdfs4_sb_info *sb_info);
int copy_file_to_image(struct vdfs4_sb_info *sb_info, const char *src_filename,
		u64 *file_offset_abs);
void copy_file_from_image(/*struct vdfs4_sb_info *sb_info,
			const char *src_filename,
			const char *dst_filename*/);
int get_image_size(struct vdfs4_sb_info *sbi, u_int64_t *size);
int create_hard_link(/*struct vdfs4_sb_info *sb_info,
			const char *dst_filename,
			const char *src_filename*/);
int copy_small_file_to_image(struct vdfs4_sb_info *sb_info,
		const char *src_filename,
		struct vdfs4_catalog_file_record *rec);
void remove_image_file(struct vdfs4_sb_info *sbi);
/* end of disk op functions */

/* space manager functions */
int init_space_manager(struct vdfs4_sb_info *sbi);
void sign_sm_buffer(struct vdfs4_sb_info *sbi);
int allocate_space(struct vdfs4_sb_info *sbi, u_int64_t block_offset,
		u_int32_t block_count, u_int64_t *first_block);
int flush_space_manager(struct vdfs4_sb_info *sbi);
void destroy_space_manager(struct vdfs4_sb_info *sbi);
int place_on_volume_space_manager(struct vdfs4_sb_info *sbi,
			u_int64_t block_offset);
/*end space manager functions */
int get_iblock_size(struct vdfs4_sb_info *sbi, __u8 type);
int is_tree(__u8 object_type);

u_int32_t vdfs4_crc32(const void *buff, u_int32_t len);
unsigned int calculate_file_crc(int fd, int calc_last_block, int *error);

unsigned int crc32_body(unsigned int crc, __u8 const *buf, u_int32_t len);
u_int32_t vdfs4_file_check_crc32(int fd);
u_int32_t vdfs4_file_append_crc32(int fd);

/** free inode bitmap preparing functions */
int init_inode_id_alloc(struct vdfs4_sb_info *sbi);
int place_on_volume_inode_id_alloc(struct vdfs4_sb_info *sbi,
	u_int64_t block_offset);
int flush_inode_id_alloc(struct vdfs4_sb_info *sbi);
void destroy_inode_id_alloc(struct vdfs4_sb_info *sbi);
u_int64_t get_free_inode_n(struct vdfs4_sb_info *sbi, int count);
int test_and_clear_inode_n(struct vdfs4_sb_info *sbi, __u64 ino_n);
void inode_bitmap_count_crc(struct vdfs4_sb_info *sbi);
int fill_inode_bitmap(struct vdfs4_sb_info *sbi);
RSA *create_rsa_from_private_str(char *private_str);
RSA *create_rsa(char *private_key, char *pub_key, char *q_file, char *p_file);
int sign_rsa(unsigned char *buf, unsigned long buf_len,
		unsigned char *rsa_hash, RSA *rsa_key,
		vdfs4_hash_algorithm_func *hash_alg, int hash_len);
int get_sign_type(RSA *key);
int get_sign_length(RSA* key);

/** catalog tree functions */
int init_cattree(struct vdfs4_sb_info *sbi);
int place_on_volume_cattree(struct vdfs4_sb_info *sbi);
int flush_cattree(struct vdfs4_sb_info *sbi);
int vdfs4_cattree_cmpfn(struct vdfs4_generic_key *__key1,
		struct vdfs4_generic_key *__key2);

/** ext tree functions */
int init_exttree(struct vdfs4_sb_info *sbi);
int place_on_volume_exttree(struct vdfs4_sb_info *sbi);
int flush_exttree(struct vdfs4_sb_info *sbi);

/** xattr tree functions */
int init_xattrtree(struct vdfs4_sb_info *sbi);
int get_set_xattrs(struct vdfs4_sb_info *sbi, char *path, u64 object_id);

int vdfs4_xattrtree_cmpfn(struct vdfs4_generic_key *__key1,
		struct vdfs4_generic_key *__key2);
int unpack_xattr(struct vdfs4_btree *xattr_tree, char *path, u64 object_id);

/** hardlink tree functions */
int vdfs4_hard_link_insert(struct vdfs4_sb_info *sbi,
		struct vdfs4_catalog_file_record *file_value);
void hl_list_free(struct hlink_list_item *hl_list);
/** bnode.c function */
void init_head_bnode(struct vdfs4_bnode *head_bnode);
u_int32_t find_first_free_node_id(struct vdfs_tools_btree_info *tree);
u_int32_t get_bnode_size(struct vdfs4_sb_info *sbi);
__u64 get_bnodes_count(struct vdfs_tools_btree_info *tree);

/** btree.c funtion */
struct vdfs4_bnode *vdfs4_alloc_new_bnode(struct vdfs4_btree *btree);

int temp_stub_insert_into_node(struct vdfs4_bnode *bnode,
		void *new_record, int insert_pos);
void temp_stub_init_new_node_descr(struct vdfs4_bnode *bnode,
		enum vdfs4_node_type type);
int test_and_set_bnode_bitmap_bit(struct vdfs_tools_btree_info *tree,
		struct vdfs4_bnode *bnode);
int test_and_clear_bnode_bitmap_bit(struct vdfs4_bnode *bnode);
int btree_init(struct vdfs4_sb_info *sbi,
		struct vdfs_tools_btree_info *tree,
		int btree_type, short max_record_len);
void btree_destroy_tree(struct vdfs_tools_btree_info *tree);
int expand_tree(struct vdfs_tools_btree_info *tree);
void put_bnode(struct vdfs4_bnode *bnode);
int check_bnode_reserve(struct vdfs4_btree *btree, int reserve_threshold_type);
/** permission.c*/
void get_permissions_for_root_dir(struct vdfs4_posix_permissions *permissions);
/** bitops.c*/
int get_permissions_for_root_dir_from_path(struct vdfs4_sb_info *sbi,
		struct vdfs4_posix_permissions *permissions);
int find_first_zero_bit(const unsigned char *addr, int size);

/** vector.c*/
void init_vector(struct vector *v, int size_of_data);
void destroy_vector(struct vector *v);
void push_elem(struct vector *v, void *data);
void *get_elem(struct vector *v, u64 pos);
void delete_elem(struct vector *v, u64 pos);

/** utils.c functions */
void util_add_btree_size(struct vdfs4_sb_info *sbi, struct vdfs_tools_btree_info *tree);
int util_sign_set_bits(char *buff, int buff_size, u_int64_t addr,
		u_int32_t count, int block_size, int magic_len, int crc_size);
int util_sign_clear_bits(char *buff, int buff_size, u_int64_t addr,
		u_int32_t count, int block_size, int magic_len, int crc_size);
void util_set_bits(char *buffer, u_int64_t addr, u_int32_t count);
int util_test_bit(char *buffer, u_int64_t addr);
int util_sign_test_bit(char *buff, int buff_size, u_int64_t addr,
		int block_size, int magic_len, int crc_size);
void util_clear_bits(char *buffer, u_int64_t addr, u_int32_t count);
int util_test_bit(char *buffer, u_int64_t addr);

int util_validate_crc(char *buff, int buff_size, int skip);
int util_update_crc(char *buff, int buff_size, const char *magic,
		int magic_len);
unsigned int slog(int block);
unsigned int get_elapsed_time(void);

/** small.c*/
int init_small(struct vdfs4_sb_info *sbi);
void destroy_small(struct vdfs4_sb_info *sbi);
u_int32_t test_and_set_small_area_bitmap_bit(struct vdfs4_sb_info *sbi);
void sign_small_area_bitmap(struct vdfs4_sb_info *sbi);
/** lib/check_file_type.c */
int is_need_sign(int src_fd, const char *src_filename);
int is_exec_file_path(const char* path);
int is_exec_file_fd(int fd);

int allocate_space_for_each_subsystem_block(struct vdfs4_sb_info *vdfs4_sbi,
		int blocks_count, struct vdfs4_base_table_record *table,
		u64 iblock_size, int subsystem_idx,
		struct vdfs4_base_table *base_table,
		struct vdfs4_extent_info *extent,
		__u32 *used_extents);
int metablock_to_iblock_for_conversion(struct vdfs4_sb_info *sbi, u64 mblock);



int flush_debug_area(struct vdfs4_sb_info *sbi);
int flush_subsystem(struct vdfs4_sb_info *sbi,
		struct vdfs4_subsystem_data *subsystem);
int flush_subsystem_tree(struct vdfs4_sb_info *sbi,
		struct vdfs_tools_btree_info *tree);
int init_sb_info(struct vdfs4_sb_info *sbi);
int allocate_fixed_areas(struct vdfs4_sb_info *sbi);
void vdfs4_fill_cattree_record_value(struct vdfs4_cattree_record *record,
		u_int64_t total_items_count, u_int64_t links_count,
		struct vdfs4_posix_permissions	*permissions,
		const struct vdfs4_timespec time_creation,
		const struct vdfs4_timespec time_modification,
		const struct vdfs4_timespec time_access,
		u_int64_t begin,
		u_int64_t length,
		unsigned int block_size);
int clean_superblocks_area(struct vdfs4_sb_info *sbi);
int discard_volume(struct vdfs4_sb_info *sbi);
int flush_superblocks(struct vdfs4_sb_info *sbi, int argc, char *argv[]);
void generate_uuid(u_int8_t *uuid_array, u_int32_t uuid_length);
int prepare_superblocks(struct vdfs4_sb_info *sbi);
int get_file_size(int fd, off_t *file_size);
/*tune.vdsf*/
void zerr(int ret);

#endif

