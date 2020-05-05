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

#ifndef BTREE_H_
#define BTREE_H_

#include "vdfs4_layout.h"
#include "vdfs_list.h"

/* #define CONFIG_VDFS4_DEBUG_GET_BNODE */

#ifdef CONFIG_VDFS4_DEBUG_GET_BNODE
#include <linux/stacktrace.h>
#endif

#define VDFS4_BNODE_DSCR(bnode) ((struct vdfs4_gen_node_descr *) \
		(bnode)->data)

#define VDFS4_BNODE_RECS_NR(bnode) \
	le16_to_cpu(VDFS4_BNODE_DSCR(bnode)->recs_count)

#define VDFS4_KEY_LEN(key) (le32_to_cpu(key->key_len))
#define VDFS4_RECORD_LEN(key) (le32_to_cpu(key->record_len))
#define VDFS4_NEXT_BNODE_ID(bnode) \
	(le32_to_cpu(VDFS4_BNODE_DSCR(bnode)->next_node_id))
#define VDFS4_PREV_BNODE_ID(bnode) \
	(le32_to_cpu(VDFS4_BNODE_DSCR(bnode)->prev_node_id))

#define VDFS4_MAX_BTREE_KEY_LEN VDFS4_CAT_KEY_MAX_LEN
#define VDFS4_MAX_BTREE_REC_LEN (VDFS4_CAT_KEY_MAX_LEN + \
		sizeof(struct vdfs4_catalog_file_record))

/** How many free space node should have on removing records, to merge
 * with neighborhood */
#define VDFS4_BNODE_MERGE_LIMIT	(0.7)

#define VDFS4_GET_BNODE_STACK_ITEMS 20

#define VDFS4_WAIT_BNODE_UNLOCK 1
#define VDFS4_NOWAIT_BNODE_UNLOCK 0

#ifndef USER_SPACE
#include "mutex_on_sem.h"
#include <linux/rbtree.h>
#endif

/**
 * @brief		Get pointer to value in key-value pair.
 * @param [in]	key_ptr	Pointer to key-value pair
 * @return		Returns pointer to value in key-value pair
 */
static inline void *get_value_pointer(void *key_ptr)
{
	struct vdfs4_cattree_key *key = key_ptr;
	if (key->gen_key.key_len > VDFS4_MAX_BTREE_KEY_LEN)
		return ERR_PTR(-EINVAL);
	else
		return (void *)((char *)key_ptr + key->gen_key.key_len);
};

/** TODO */
enum vdfs4_get_bnode_mode {
	/** The bnode is operated in read-write mode */
	VDFS4_BNODE_MODE_RW = 0,
	/** The bnode is operated in read-only mode */
	VDFS4_BNODE_MODE_RO
};

/** TODO */
enum vdfs4_node_type {
	VDFS4_FIRST_NODE_TYPE = 1,
	/** bnode type is index */
	VDFS4_NODE_INDEX = VDFS4_FIRST_NODE_TYPE,
	/** bnode type is leaf */
	VDFS4_NODE_LEAF,
	VDFS4_NODE_NR,
};

/** TODO */
enum vdfs4_btree_type {
	VDFS4_BTREE_FIRST_TYPE = 0,
	/** btree is catalog tree */
	VDFS4_BTREE_CATALOG = VDFS4_BTREE_FIRST_TYPE,
	/** btree is extents overflow tree */
	VDFS4_BTREE_EXTENTS,
	/** btree is xattr tree */
	VDFS4_BTREE_XATTRS,
	/* installed catalog tree */
	VDFS4_BTREE_INST_CATALOG,
	/* installed extended atribute tree */
	VDFS4_BTREE_INST_XATTR,
	/* installed extents overflow tree */
	VDFS4_BTREE_INST_EXT,
	VDFS4_BTREE_TYPES_NR
};

typedef int (vdfs4_btree_key_cmp)(struct vdfs4_generic_key *,
		struct vdfs4_generic_key *);

#ifdef CONFIG_VDFS4_DEBUG_GET_BNODE
struct vdfs4_get_bnode_trace {
	unsigned long stack_entries[VDFS4_GET_BNODE_STACK_ITEMS];
	int mode;
	struct stack_trace trace;
	struct list_head list;
};
#endif

/**
 * @brief	Structure contains information about bnode in runtime.
 */
struct vdfs4_bnode {
	/** Pointer to memory area where contents of bnode is mapped to */
	void *data;

	/** The bnode's id */
	__u32 node_id;

	/** Pointer to tree containing this bnode */
	struct vdfs4_btree *host;

	/** Mode in which bnode is got */
	enum vdfs4_get_bnode_mode mode;

	struct hlist_node hash_node;

	/* under btree->hash_lock */
	int ref_count;

#ifdef CONFIG_VDFS4_DEBUG_GET_BNODE
	/* under btree->hash_lock */
	struct list_head get_traces_list;
#endif

	/**
	 * Array of pointers to struct page representing pages in
	 * memory containing data of this bnode
	 */
	struct page *pages[0];
};

#define	VDFS4_BNODE_HASH_SIZE_SHIFT 10
#define	VDFS4_BNODE_HASH_SIZE (1 << VDFS4_BNODE_HASH_SIZE_SHIFT)
#define	VDFS4_BNODE_HASH_MASK (VDFS4_BNODE_HASH_SIZE - 1)

/**
 * @brief	An eMMCFS B-tree held in memory.
 */
struct vdfs4_btree {
	/** Pointer superblock, possessing  this tree */
	struct vdfs4_sb_info *sbi;

	/** The inode of special file containing  this tree */
	struct inode *inode;
	/** Number of pages enough to contain whole bnode in memory */
	unsigned int pages_per_node;
	/** Number of pages enough to contain whole bnode in memory
	 * (power of 2)*/
	unsigned int log_pages_per_node;
	/** Size of bnode in bytes */
	unsigned int node_size_bytes;
	/** Maximal available record length for this tree */
	unsigned short max_record_len;

	/** Type of the tree */
	enum vdfs4_btree_type btree_type;
	/** Comparison function for this tree */
	vdfs4_btree_key_cmp *comp_fn;

	/** Pointer to head (containing essential info)  bnode */
	struct vdfs4_bnode *head_bnode;
	/** Info about free bnode list */
	struct vdfs4_bnode_bitmap *bitmap;

	struct mutex	hash_lock;

	struct hlist_head hash_table[VDFS4_BNODE_HASH_SIZE];

	/** Lock to protect tree operations */
	rw_mutex_t rw_tree_lock;
	/** Offset in blocks of tree metadata area start in inode.
	 * (!=0 for packtree metadata appended to the end of squasfs image) */
	sector_t tree_metadata_offset;
	ino_t start_ino;

	void *split_buff;
	struct mutex split_buff_lock;

	/* ======== TOOLS ONLY ========= */
	struct vdfs4_list bnode_list;
};

/**
 * @brief	Macro gets essential information about tree contained in head
 *		tree node.
 */
#define VDFS4_BTREE_HEAD(btree) ((struct vdfs4_raw_btree_head *) \
	(btree->head_bnode->data))

struct vdfs4_btree_record_pos {
	struct vdfs4_bnode *bnode;
	int pos;
};

/**
 * @brief	Runtime structure representing free bnode id bitmap.
 */
struct vdfs4_bnode_bitmap {
	/** Memory area containing bitmap itself */
	void *data;
	/** Size of bitmap */
	__u64 size;
	/** Starting bnode id */
	__u32 start_id;
	/** Maximal bnode id */
	__u32 end_id;
	/** First free id for quick free bnode id search */
	__u32 first_free_id;
	/** Amount of free bnode ids */
	__u32 free_num;
	/** Amount of bits in bitmap */
	__u32 bits_num;
	/** Pointer to bnode containing this bitmap */
	struct vdfs4_bnode *host;
};

struct vdfs4_btree_gen_record {
	void *key;
	void *val;
};

struct vdfs4_btree_record_info {
	struct vdfs4_btree_gen_record gen_record;
	struct vdfs4_btree_record_pos rec_pos;
};


static inline struct vdfs4_btree_record_info *VDFS4_BTREE_REC_I(
		struct vdfs4_btree_gen_record *record)
{
	return container_of(record, struct vdfs4_btree_record_info, gen_record);
}


/* Set this to sizeof(crc_type) to handle CRC */
#define VDFS4_BNODE_FIRST_OFFSET 4
#define VDFS4_INVALID_NODE_ID 0

typedef __u32 vdfs4_bt_off_t;
#define VDFS4_BT_INVALID_OFFSET ((__u32) (((__u64) 1 << 32) - 1))

struct vdfs4_btree_gen_record *vdfs4_btree_find(struct vdfs4_btree *btree,
		struct vdfs4_generic_key *key,
		enum vdfs4_get_bnode_mode mode);
void *vdfs4_get_btree_record(struct vdfs4_bnode *bnode, int index);
int vdfs4_btree_insert(struct vdfs4_btree *btree, void *new_data,
		int force_insert);
struct vdfs4_btree_gen_record *vdfs4_btree_place_data(struct vdfs4_btree *btree,
		struct vdfs4_generic_key *gen_key);
int vdfs4_get_next_btree_record(struct vdfs4_btree_gen_record *record);
void *__vdfs4_get_next_btree_record(struct vdfs4_bnode **__bnode, int *index);
int vdfs4_btree_remove(struct vdfs4_btree *tree,
			struct vdfs4_generic_key *key);
void vdfs4_put_bnode(struct vdfs4_bnode *bnode);
struct vdfs4_bnode *vdfs4_get_bnode(struct vdfs4_btree *btree,
	__u32 node_id, enum vdfs4_get_bnode_mode mode, int wait);
/* Temporal stubs */
#define __vdfs4_get_bnode(btree, node_id, mode) vdfs4_get_bnode(btree, node_id, \
		mode, VDFS4_WAIT_BNODE_UNLOCK)
#define vdfs4_put_bnode(bnode) vdfs4_put_bnode(bnode)

int vdfs4_destroy_bnode(struct vdfs4_bnode *bnode);
struct vdfs4_bnode *vdfs4_alloc_new_bnode(struct vdfs4_btree *btree);
struct vdfs4_bnode *vdfs4_get_next_bnode(struct vdfs4_bnode *bnode);
void vdfs4_mark_bnode_dirty(struct vdfs4_bnode *node);
u32 vdfs4_btree_get_root_id(struct vdfs4_btree *btree);

void vdfs4_put_btree(struct vdfs4_btree *btree, int iput);
void vdfs4_release_dirty_record(struct vdfs4_btree_gen_record *record);
void vdfs4_release_record(struct vdfs4_btree_gen_record *record);
void vdfs4_mark_record_dirty(struct vdfs4_btree_gen_record *record);

int vdfs4_insert_into_node(struct vdfs4_bnode *bnode,
		void *new_record, int insert_pos);
#ifdef USER_TEST
void test_init_new_node_descr(struct vdfs4_bnode *bnode,
		enum vdfs4_node_type type);
#endif

int vdfs4_init_btree_caches(void);
void vdfs4_destroy_btree_caches(void);

int vdfs4_check_btree_links(struct vdfs4_btree *btree, int *dang_num);
int vdfs4_check_btree_records_order(struct vdfs4_btree *btree);


void vdfs4_init_new_node_descr(struct vdfs4_bnode *bnode,
		enum vdfs4_node_type type);

/* ======== TOOLS ONLY ========= */
static inline void vdfs4_dump_panic_remount(UNUSED struct vdfs4_bnode *bnode,
		UNUSED const char *fmt, ...) {};
void vdfs4_release_bnode_list(struct vdfs4_list *bnode_list);
u_int32_t btree_get_bitmap_size(struct vdfs4_sb_info *sbi);

#endif /* BTREE_H_ */
