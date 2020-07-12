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

#ifndef EXTTREE_H_
#define EXTTREE_H_

#include "vdfs_tools.h"
#include "vdfs4_layout.h"
#include "btree.h"

/* vdfs4_exttree_key.iblock special values */
#define IBLOCK_DOES_NOT_MATTER	0xFFFFFFFF /* any extent for specific inode */
#define IBLOCK_MAX_NUMBER	0xFFFFFFFE /* find last extent ... */

struct vdfs4_exttree_record {
	/** Key */
	struct vdfs4_exttree_key *key;
	/** Extent for key */
	struct vdfs4_extent *lextent;
};

struct vdfs4_exttree_record *vdfs4_extent_find(struct vdfs4_sb_info *sbi,
		__u64 object_id, sector_t iblock, enum vdfs4_get_bnode_mode
		mode);

int vdfs4_exttree_get_next_record(struct vdfs4_exttree_record *record);

struct vdfs4_exttree_record *vdfs4_exttree_find_first_record(
		struct vdfs4_sb_info *sbi, __u64 object_id,
		enum vdfs4_get_bnode_mode mode);

struct  vdfs4_exttree_record *vdfs4_find_last_extent(struct vdfs4_sb_info *sbi,
		__u64 object_id, enum vdfs4_get_bnode_mode mode);

int vdfs4_exttree_remove(struct vdfs4_btree *btree, __u64 object_id,
		sector_t iblock);
/**
 * @brief	Extents tree key compare function.
 */
int vdfs4_exttree_cmpfn(struct vdfs4_generic_key *__key1,
		struct vdfs4_generic_key *__key2);
int vdfs4_exttree_add(struct vdfs4_sb_info *sbi, unsigned long object_id,
		struct vdfs4_extent_info *extent, int force_insert);
#endif
