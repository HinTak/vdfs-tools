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

#ifndef __EXTTREE_C__
#define __EXTTREE_C__

#include "exttree.h"

void dummy_exttree_record_init(struct vdfs4_exttree_lrecord *ext_overfl_record)
{
	set_magic(ext_overfl_record->key.gen_key.magic, VDFS4_EXT_OVERFL_LEAF);
	ext_overfl_record->key.gen_key.key_len =
			sizeof(struct vdfs4_exttree_key);
	ext_overfl_record->key.gen_key.record_len =
			sizeof(struct vdfs4_exttree_lrecord);
	ext_overfl_record->key.object_id = 0;
	ext_overfl_record->key.iblock = 0;

	init_extent(&ext_overfl_record->lextent, 0, 0);
}

static void exttree_init_root_bnode(struct vdfs4_bnode *root_bnode)
{
	struct vdfs4_exttree_lrecord exttree_record;

	vdfs4_init_new_node_descr(root_bnode, VDFS4_NODE_LEAF);
	dummy_exttree_record_init(&exttree_record);
	vdfs4_insert_into_node(root_bnode, &exttree_record, 0);
}

int init_exttree(struct vdfs4_sb_info *sbi)
{
	int ret = 0;
	struct vdfs_tools_btree_info *exttree_btree = &sbi->exttree;
	struct vdfs4_bnode *root_bnode = 0;

	log_activity("Create extents overflow tree");

	ret = btree_init(sbi, exttree_btree, VDFS4_BTREE_EXTENTS,
			sizeof(struct vdfs4_exttree_key) +
			sizeof(struct vdfs4_exttree_lrecord));
	if (ret)

		goto error_exit;
	exttree_btree->vdfs4_btree.comp_fn = vdfs4_exttree_cmpfn;
	sbi->extents_tree = &exttree_btree->vdfs4_btree;
	/* Init root bnode */
	root_bnode = vdfs4_alloc_new_bnode(&exttree_btree->vdfs4_btree);
	if (IS_ERR(root_bnode)) {
		ret = (PTR_ERR(root_bnode));
		root_bnode = 0;
		goto error_exit;
	}
	exttree_init_root_bnode(root_bnode);
	exttree_btree->tree.sub_system_id = VDFS4_EXTENTS_TREE_INO;
	exttree_btree->tree.subsystem_name = "EXTENTS OVERFLOW TREE";
	util_update_crc(exttree_btree->vdfs4_btree.head_bnode->data,
				get_bnode_size(sbi), NULL, 0);
	util_update_crc(root_bnode->data, get_bnode_size(sbi), NULL, 0);
	return 0;
error_exit:

	log_error("Can't init extents overflow tree");
	return ret;
}
#endif
