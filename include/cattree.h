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

#ifndef CATTREE_H_
#define CATTREE_H_

struct vdfs4_cattree_record {
	struct vdfs4_cattree_key *key;
	/* Value type can be different */
	void *val;
};

#define VDFS4_CATTREE_FOLDVAL(record) \
	((struct vdfs4_catalog_folder_record *) (record->val))
#define VDFS4_CATTREE_FILEVAL(record) \
	((struct vdfs4_catalog_file_record *) (record->val))

struct vdfs4_cattree_record *vdfs4_cattree_find(struct vdfs4_btree *tree,
		__u64 parent_id, const char *name, size_t len,
		enum vdfs4_get_bnode_mode mode);

struct vdfs4_cattree_record *vdfs4_cattree_find_inode(struct vdfs4_btree *tree,
		__u64 object_id, __u64 parent_id, const char *name, size_t len,
		enum vdfs4_get_bnode_mode mode);

struct vdfs4_cattree_record *vdfs4_cattree_find_hlink(struct vdfs4_btree *tree,
		__u64 object_id, enum vdfs4_get_bnode_mode mode);

int vdfs4_cattree_remove(struct vdfs4_btree *tree, __u64 object_id,
		__u64 parent_id, const char *name, size_t len, u8 record_type);

struct vdfs4_cattree_record *vdfs4_cattree_get_first_child(
		struct vdfs4_btree *tree, __u64 catalog_id);

int vdfs4_cattree_get_next_record(struct vdfs4_cattree_record *record);

void vdfs4_release_cattree_dirty(struct vdfs4_cattree_record *record);

struct vdfs4_cattree_record *vdfs4_cattree_place_record(
		struct vdfs4_btree *tree, u64 object_id, u64 parent_id,
		const char *name, size_t len, u8 record_type);

struct vdfs4_cattree_record *vdfs4_cattree_build_record(struct vdfs4_btree * tree,
		__u32 bnode_id, __u32 pos);

#include "vdfs4_layout.h"

/**
 * @brief	Catalog tree key compare function for case-sensitive usecase.
 */
bool vdfs4_cattree_is_orphan(struct vdfs4_cattree_record *record);

/**
 * @brief	Fill already allocated value area (hardlink).
 */
void vdfs4_fill_hlink_value(struct inode *inode,
		struct vdfs4_catalog_hlink_record *hl_record);

int vdfs4_cattree_insert_ilink(struct vdfs4_btree *tree, __u64 object_id,
		__u64 parent_id, const char *name, size_t name_len);
int vdfs4_cattree_remove_ilink(struct vdfs4_btree *tree, __u64 object_id,
		__u64 parent_id, const char *name, size_t name_len);

/* ======== TOOLS ONLY ========= */
struct vdfs4_cattree_record *find_record(struct vdfs4_sb_info *sbi,
		char *path);
#endif
