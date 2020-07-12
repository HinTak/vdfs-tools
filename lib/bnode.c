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

#include "vdfs_tools.h"
#include "debug.h"

void vdfs4_release_bnode_list(struct vdfs4_list *bnode_list)
{
	struct list_node *ptr = bnode_list->head_node.next;
	for (;;)
	{
		if (!ptr)
			break;

		free(((struct vdfs4_bnode *)ptr->data)->data);
		((struct vdfs4_bnode *)ptr->data)->data = NULL;
		free(ptr->data);
		ptr->data = NULL;
		ptr->data_size = 0;
		ptr = ptr->next;
	}

	vdfs4_list_free(bnode_list);
}

/**
 * @brief Allocating bnode from memory and read it from volume into memory
 * @param [in] btree - host tree
 * @param [in] node_id - index of node in Btree
 * @param [in] mode - get bnode mode
 * @return Address of bnode
 */
struct vdfs4_bnode *vdfs4_get_bnode_from_vol(struct vdfs4_btree *btree,
		__u32 node_id, enum vdfs4_get_bnode_mode mode UNUSED)
{
	int ret = 0;
	int magic_len = 3;
	u_int64_t bnode_begining_pos;
	u64 nd_iblock;
	int tree_ino = 0;

	struct vdfs4_bnode *bnode;
	__u8 *bnode_pos;

	struct list_node *ptr = btree->bnode_list.head_node.next;
	for (;;)
	{
		if (!ptr)
			break;

		if (((struct vdfs4_bnode *)ptr->data)->node_id == node_id)
		{
			bnode = (struct vdfs4_bnode *)ptr->data;
			return bnode;
		}
		ptr = ptr->next;
	}

	bnode = malloc(sizeof(struct vdfs4_bnode));
	if (!bnode)
		goto exit_alloc;
	bnode_pos = malloc(btree->node_size_bytes);
	if (!bnode_pos) {
		free(bnode);
		goto exit_alloc;
	}

	const char *btree_type;
	if (btree->btree_type == VDFS4_BTREE_EXTENTS) {
		tree_ino = VDFS4_EXTENTS_TREE_INO;
		btree_type = "extents tree";
	} else if (btree->btree_type == VDFS4_BTREE_CATALOG) {
		tree_ino = VDFS4_CAT_TREE_INO;
		btree_type = "catalog tree";
	} else if (btree->btree_type == VDFS4_BTREE_XATTRS) {
		tree_ino = VDFS4_XATTR_TREE_INO;
		btree_type = "xattr tree";
	} else {
		log_error("Unknown tree type");
		ret = -ERDFAIL;
		goto err_exit;
	}
	struct vdfs4_base_table *base_table = btree->sbi->snapshot.base_table;
	struct vdfs4_base_table_record *table = VDFS4_GET_TABLE(base_table,
			tree_ino);
	nd_iblock = metablock_to_iblock(btree->sbi, table[node_id].meta_iblock);
	bnode_begining_pos = nd_iblock;

	ret = vdfs4_read_blocks(btree->sbi, bnode_begining_pos, bnode_pos,
			btree->node_size_bytes /
			btree->sbi->block_size);
	if (ret) {
		log_error("Failed to read bnode from disk\n");
		ret = -ERDFAIL;
		goto err_exit;
	}
	bnode->data = bnode_pos;
	bnode->node_id = node_id;
	bnode->host = btree;

 	if (!memcmp(VDFS4_BNODE_DSCR(bnode)->magic, "eH", magic_len - 1) ||
		!memcmp(VDFS4_BNODE_DSCR(bnode)->magic, "Nd", magic_len - 1)) {
		if ((table[node_id].sync_count != VDFS4_BNODE_DSCR(bnode)->version[0]) ||
			(table[node_id].mount_count != VDFS4_BNODE_DSCR(bnode)->version[1]) ||
			((node_id != 0) && (node_id != VDFS4_BNODE_DSCR(bnode)->node_id))) {
			log_error("Corrupted bnode with node id %d in "
				"%s,\n\t Base/ext table says node_id %d v%d.%d\n"
				"\t In reality it is node_id %d v%d.%d\n",
				node_id, btree_type, node_id,
				table[node_id].mount_count,
				table[node_id].sync_count,
				VDFS4_BNODE_DSCR(bnode)->node_id,
				VDFS4_BNODE_DSCR(bnode)->version[1],
				VDFS4_BNODE_DSCR(bnode)->version[0]);
			log_data(bnode->data, btree->node_size_bytes);
			free(bnode_pos);
			free(bnode);
			return ERR_PTR(-ERDFAIL);
		}
		vdfs4_add_to_list(&btree->bnode_list, bnode, 1);
		return bnode;
 	} else {
		char *incorrect_magic = malloc(magic_len);
		memcpy(incorrect_magic, VDFS4_BNODE_DSCR(bnode)->magic,
				magic_len);
		incorrect_magic[magic_len - 1] = '\0';

		log_error("Getting corrupted bnode with node id %d in "
				"%s,\n incorrect bnode magic: %s\n", node_id,
				btree_type, incorrect_magic);
		log_data(bnode->data, btree->node_size_bytes);
		free(incorrect_magic);

		free(bnode_pos);
		free(bnode);
		return ERR_PTR(-ERDFAIL);
	}

err_exit:
	free(bnode_pos);
	free(bnode);
	return ERR_PTR(ret);
exit_alloc:
	log_error("Out of memory\n");
	return ERR_PTR(-ENOMEM);
}

int get_bnode_fault_skip = -1;
int get_bnode_seq_faults = -1;

struct vdfs4_bnode *vdfs4_get_bnode_from_mem(struct vdfs4_btree *btree,
		__u32 node_id, enum vdfs4_get_bnode_mode mode UNUSED)
{
	struct vdfs_tools_btree_info *tree =
			container_of(btree, struct vdfs_tools_btree_info,
					vdfs4_btree);
	return tree->bnode_array[node_id];
}

struct vdfs4_bnode *vdfs4_get_bnode_debug(struct vdfs4_btree *btree,
		__u32 node_id, enum vdfs4_get_bnode_mode mode, int wait)
{
	struct vdfs4_bnode *bnode = vdfs4_get_bnode_from_mem(btree, node_id,
			mode);

	if (!IS_ERR(bnode))
		VDFS4_BUG_ON(2 < atomic_inc_and_test(&bnode->ref_count));

	if (get_bnode_fault_skip >= 0 && wait == VDFS4_NOWAIT_BNODE_UNLOCK) {
		if (get_bnode_fault_skip == 0) {
			if (get_bnode_seq_faults > 1)
				get_bnode_seq_faults--;
			else {
				get_bnode_fault_skip = -1;
				get_bnode_seq_faults = -1;
			}
			vdfs4_put_bnode(bnode);
			return ERR_PTR(-EAGAIN);
		} else
			get_bnode_fault_skip--;
	}

	/*printf("GET_bnode %u at %s:%d\n", node_id, file_name, line);*/

	return bnode;
}

struct vdfs4_bnode *vdfs4_get_bnode(struct vdfs4_btree *btree,
	__u32 node_id, enum vdfs4_get_bnode_mode mode, int wait)
{
	int get_bnode_type = vdfs_tools_mode & VDFS4_TOOLS_GET_BNODE_TYPE_MASK;

	switch (get_bnode_type) {
	case VDFS4_TOOLS_GET_BNODE_FROM_VOL:
	case VDFS4_TOOLS_GET_BNODE_FROM_VOLUME_PUT:
		return vdfs4_get_bnode_from_vol(btree, node_id, mode);
	case VDFS4_TOOLS_GET_BNODE_FROM_MEM:
		return vdfs4_get_bnode_from_mem(btree, node_id, mode);
	case VDFS4_TOOLS_GET_BNODE_DEBUG:
		return vdfs4_get_bnode_debug(btree, node_id, mode, wait);
	default:
		assert(0);
	}

	return ERR_PTR(-EINVAL);
}

void vdfs4_put_bnode_debug(struct vdfs4_bnode *bnode,
		char *file_name UNUSED, int line UNUSED)
{
	VDFS4_BUG_ON(0 > atomic_dec_and_test(&bnode->ref_count));
	/*printf("put_bnode %u at %s:%d\n", bnode->node_id, file_name, line);*/
}

void vdfs4_put_bnode(struct vdfs4_bnode *bnode)
{
	if ((vdfs_tools_mode & VDFS4_TOOLS_GET_BNODE_TYPE_MASK) ==
			VDFS4_TOOLS_GET_BNODE_DEBUG)
		vdfs4_put_bnode_debug(bnode, __FILE__, __LINE__);
	else if ((vdfs_tools_mode & VDFS4_TOOLS_GET_BNODE_TYPE_MASK)
			== VDFS4_TOOLS_GET_BNODE_FROM_VOLUME_PUT) {
		free(bnode->data);
		free(bnode);
	}
}

struct vdfs4_bnode *vdfs4_alloc_new_bnode(struct vdfs4_btree *btree)
{
	u_int32_t node_id;
	struct vdfs4_bnode *bnode = NULL;
	struct vdfs_tools_btree_info *tree =
			container_of(btree, struct vdfs_tools_btree_info,
					vdfs4_btree);

	node_id = find_first_free_node_id(tree);
	if ((node_id + 1) > tree->allocated_bnodes_count)
		if (expand_tree(tree))
			return ERR_PTR(-ENOMEM);
	if (!tree->bnode_array[node_id]) {
		bnode = calloc(1UL, (size_t)sizeof(struct vdfs4_bnode));
		if (!bnode)
			return ERR_PTR(-ENOMEM);
		memset(bnode, 0, (size_t)sizeof(struct vdfs4_bnode));
		bnode->node_id = node_id;
		bnode->host = &tree->vdfs4_btree;
		bnode->data = calloc(1, get_bnode_size(btree->sbi));
		if (!bnode->data) {
			free(bnode);
			return ERR_PTR(-ENOMEM);
		}
		tree->bnode_array[node_id] = bnode;
	} else
		bnode = tree->bnode_array[node_id];
	memset(bnode->data, 0, get_bnode_size(btree->sbi));
	if (node_id == HEAD_BNODE_ID)
		tree->bnodes_count++;
	else if (!test_and_set_bnode_bitmap_bit(tree, bnode)) {
		tree->bnodes_count++;
		vdfs4_mark_bnode_dirty(btree->head_bnode);
	}

	atomic_set(&bnode->ref_count, 1);
	return bnode;
}

int vdfs4_destroy_bnode(struct vdfs4_bnode *bnode)
{
	int ret = 0;
	struct vdfs4_btree *btree = bnode->host;
	if (test_and_clear_bnode_bitmap_bit(bnode)) {
		container_of(bnode->host,
			struct vdfs_tools_btree_info, vdfs4_btree)->
			bnodes_count--;
	} else {
#ifndef USER_TEST
		log_info("Bnode %ul didn't set in bitmap", bnode->node_id);
#endif
		ret = -EINVAL;
	}

	atomic_set(&bnode->ref_count, 0);
	vdfs4_mark_bnode_dirty(btree->head_bnode);
	return ret;
}

void vdfs4_mark_bnode_dirty(struct vdfs4_bnode *bnode)
{
	assert(bnode->mode == VDFS4_BNODE_MODE_RW);
}

u_int32_t get_bnode_size(struct vdfs4_sb_info *sbi)
{
	return (u_int32_t)sbi->super_page_size;
}

__u64 get_bnodes_count(struct vdfs_tools_btree_info *tree)
{
	__u64 i;
	struct vdfs4_raw_btree_head *head_bnode_desc =
			tree->bnode_array[0]->data;
	__u8 *bitmap = head_bnode_desc->bitmap;
	for (i = tree->allocated_bnodes_count - 1; i > 0; i--)
		if (bitmap[i >> 3] & (1 << (i % 8)))
			return i+1;
	return 0;
}
