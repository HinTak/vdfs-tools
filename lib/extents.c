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
#include <ctype.h>
#include "vdfs4.h"
#include <linux/version.h>
#include "debug.h"
#include "exttree.h"


/**
 * @brief		Extents tree key compare function.
 * @param [in]	__key1	first key to compare.
 * @param [in]	__key2	second key to compare.
 * @return		-1 if key1 less than key2, 0 if equal, 1 in all other
 *			situations.
 */
int vdfs4_exttree_cmpfn(struct vdfs4_generic_key *__key1,
		struct vdfs4_generic_key *__key2)
{
	struct vdfs4_exttree_key *key1, *key2;

	key1 = container_of(__key1, struct vdfs4_exttree_key, gen_key);
	key2 = container_of(__key2, struct vdfs4_exttree_key, gen_key);

	if (key1->object_id != key2->object_id)
		return cmp_2_le64(key1->object_id, key2->object_id);

	return cmp_2_le64 (key1->iblock, key2->iblock);
}

/* ======== TOOLS ONLY BEGIN ========== */
struct vdfs4_exttree_key *vdfs4_get_exttree_key(void)
{
	struct vdfs4_exttree_key *key =
			malloc(sizeof(struct vdfs4_exttree_key));
	return key ? key : ERR_PTR(-ENOMEM);
}

void vdfs4_put_exttree_key(struct vdfs4_exttree_key *key)
{
	free(key);
}
/* ======== TOOLS ONLY END ========= */

int vdfs4_exttree_get_next_record(struct vdfs4_exttree_record *record)
{
	struct vdfs4_btree_record_info *rec_info =
		VDFS4_BTREE_REC_I((void *) record);

	struct vdfs4_bnode *bnode = rec_info->rec_pos.bnode;
	int pos = rec_info->rec_pos.pos;
	struct vdfs4_exttree_lrecord *raw_record =
		__vdfs4_get_next_btree_record(&bnode, &pos);

	BUG_ON(!raw_record);
	if (IS_ERR(raw_record))
		return PTR_ERR(raw_record);

	/* Ret value have to be pointer, or error, not null */
	rec_info->rec_pos.bnode = bnode;
	rec_info->rec_pos.pos = pos;
	record->key = &raw_record->key;
	record->lextent = &raw_record->lextent;

	return 0;
}

/**
 * @brief		New interface for finding extents in exttree, which
 *			available in userspace and kernelspace, old driver
 *			function now uses new interface.
 *
 *			Nonstrict means that this function ALWAYS returns
 *			record,	even if there is no exact key in the btree.
 *
 *			For example, let's imaging:
 *			key[i] < search_key < key[i+1],
 *			where key[i] and key[i+1] are existing neighborhood keys
 *			in the exttree. And there is no exact key "search_key"
 *			in the exttree. In this case function will return
 *			record with key KEY[i]
 * @param [in] sbi		vdfs4 superblock info, used to get exttree.
 * @param [in] object_id	object id to perform search
 * @param [in] iblock		Logical block number to find.
 * @param [out] mode		getting bnode mode.
 * @return		resulting record.
 */
static struct vdfs4_exttree_record *vdfs4_exttree_find_record_nonstrict(
		struct vdfs4_sb_info *sbi, __u64 object_id, sector_t iblock,
		enum vdfs4_get_bnode_mode mode)
{
	struct vdfs4_exttree_key *key = NULL;
	void *err_ret = NULL;
	struct vdfs4_exttree_record *record;
	struct vdfs4_btree *btree = sbi->extents_tree;

	key = vdfs4_get_exttree_key();
	if (IS_ERR(key)) {
		err_ret = key;
		return err_ret;
	}

	key->object_id = cpu_to_le64(object_id);
	key->iblock = cpu_to_le64(iblock);

	record = (struct vdfs4_exttree_record *)
		vdfs4_btree_find(btree, &key->gen_key, mode);
	if (IS_ERR(record)) {
		err_ret = (void *) record;
		goto err_exit;
	}


	vdfs4_put_exttree_key(key);
	return record;

err_exit:
	vdfs4_put_exttree_key(key);
	return err_ret;
}

/**
 * @brief		Behaves like vdfs4_exttree_find_record_nonstrict, but
 *			preforms check for object_id. Function return record
 *			ONLY if found key belongs to given object id. However
 *			another part of the key - iblock is still non-strict
 *
 * @param [in] sbi		vdfs4 superblock info, used to get exttree.
 * @param [in] object_id	object id to perform search
 * @param [in] iblock		Logical block number to find.
 * @param [out] mode		getting bnode mode.
 * @return		resulting record.
 */
static struct vdfs4_exttree_record *vdfs4_exttree_find_record_strict_obj(
		struct vdfs4_sb_info *sbi, __u64 object_id, sector_t iblock,
		enum vdfs4_get_bnode_mode mode)
{
	struct vdfs4_exttree_record *record;

	record = vdfs4_exttree_find_record_nonstrict(sbi, object_id, iblock,
			mode);

	if (IS_ERR(record))
		return record;


	if (le64_to_cpu(record->key->object_id) != object_id) {
		vdfs4_release_record((struct vdfs4_btree_gen_record *) record);
		record = ERR_PTR(-ENOENT);
	}

	return record;
}

struct vdfs4_exttree_record *vdfs4_exttree_find_first_record(
		struct vdfs4_sb_info *sbi, __u64 object_id,
		enum vdfs4_get_bnode_mode mode)
{
	int ret = 0;
	struct vdfs4_exttree_record *record =
		vdfs4_exttree_find_record_nonstrict(sbi, object_id, 0, mode);

	if (IS_ERR(record))
		return record;

	if (unlikely(le64_to_cpu(record->key->object_id) == object_id))
		/* If we are lucky and first record really have zero iblock -
		 * we found exact key */
		return record;

	/* In most cases found record belongs to smaller object_id then given.
	 * It happens because vdfs4_exttree_find_record_nonstrict returns
	 * smaller position, if it can not find exact key. However we are
	 * searching iblock=0, and there can not be iblocks less then 0 */
	ret = vdfs4_exttree_get_next_record(record);
	if (ret)
		goto err_exit;


	/* Now if neighborhood record has desired object_id - this is smallest
	 * key of given object_id */
	if (le64_to_cpu(record->key->object_id) != object_id) {
		ret = -ENOENT;
		goto err_exit;
	}

	return record;

err_exit:
	vdfs4_release_record((struct vdfs4_btree_gen_record *) record);
	return ERR_PTR(ret);
}

struct vdfs4_exttree_record *vdfs4_find_last_extent(
		struct vdfs4_sb_info *sbi, __u64 object_id,
		enum vdfs4_get_bnode_mode mode)
{
	struct vdfs4_exttree_record *record =
		vdfs4_exttree_find_record_strict_obj(sbi, object_id,
				IBLOCK_MAX_NUMBER, mode);

	if (IS_ERR(record))
		return record;

	return record;
}

int vdfs4_exttree_remove(struct vdfs4_btree *btree, __u64 object_id,
		sector_t iblock)
{
	struct vdfs4_exttree_key *key = vdfs4_get_exttree_key();
	int ret = 0;

	if (IS_ERR(key))
		return PTR_ERR(key);

	key->object_id = cpu_to_le64(object_id);
	key->iblock = cpu_to_le64(iblock);
	ret = vdfs4_btree_remove(btree, (struct vdfs4_generic_key *)key);

	vdfs4_put_exttree_key(key);
	return ret;
}

/**
 * @brief	Add newly allocated blocks chunk to extents overflow area.
 * @param [in] inode_info	inode information structure.
 * @param [in] iblock		starting logical block number of block chunk.
 * @param [in] cnt		block count.
 * @return	0 if success, or error number.
 */
int vdfs4_exttree_add(struct vdfs4_sb_info *sbi, unsigned long object_id,
		struct vdfs4_extent_info *extent, int force_insert)
{
	struct vdfs4_exttree_lrecord *record;
	int ret = 0;

	BUILD_BUG_ON(!IS_ALIGNED(sizeof(struct vdfs4_exttree_key), 8));
	BUILD_BUG_ON(!IS_ALIGNED(sizeof(struct vdfs4_exttree_lrecord), 8));

	record = kzalloc(sizeof(struct vdfs4_exttree_lrecord), GFP_NOFS);
	if (!record)
		return -ENOMEM;

	/* Fill the key */
	memcpy(record->key.gen_key.magic, VDFS4_EXTTREE_KEY_MAGIC,
			sizeof(VDFS4_EXTTREE_KEY_MAGIC) - 1);
	record->key.gen_key.key_len = cpu_to_le32(sizeof(record->key));
	record->key.gen_key.record_len = cpu_to_le32(sizeof(*record));
	record->key.object_id = cpu_to_le64(object_id);
	record->key.iblock = cpu_to_le64(extent->iblock);

	/* Fill the extent */
	record->lextent.begin = cpu_to_le64(extent->first_block);
	record->lextent.length = cpu_to_le32(extent->block_count);

	ret = vdfs4_btree_insert(sbi->extents_tree, record, force_insert);

	VDFS4_DEBUG_INO("exit with __FUNCTION__ %d", ret);
	kfree(record);
	return ret;
}

#ifndef USER_SPACE
/** eMMCFS extents tree key cache.
 */
static struct kmem_cache *extents_tree_key_cachep;

/**
 * @brief		Checks and copy layout fork into run time fork.
 * @param [out]	inode	The inode for appropriate run time fork
 * @param [in]	lfork	Layout fork
 * @return		Returns 0 on success, errno on failure
 */
int vdfs4_parse_fork(struct inode *inode, struct vdfs4_fork *lfork)
{
	struct vdfs4_fork_info *ifork = &VDFS4_I(inode)->fork;
	struct vdfs4_sb_info *sbi = inode->i_sb->s_fs_info;
	if (!is_fork_valid(lfork, sbi))
		return -EINVAL;
	inode->i_size = le64_to_cpu(lfork->size_in_bytes);
	if (S_ISCHR(inode->i_mode) || S_ISBLK(inode->i_mode)) {
		inode->i_rdev = (dev_t)inode->i_size;
		inode->i_size = 0;
	}

	ifork->total_block_count = (u32)le64_to_cpu(lfork->total_blocks_count);
	ifork->prealloc_block_count = 0;
	ifork->prealloc_start_block = 0;

	/* VFS expects i_blocks value in sectors*/
	inode->i_blocks = ((blkcnt_t)ifork->total_block_count) <<
			(sbi->block_size_shift - 9);

	vdfs4_lfork_to_rfork(lfork, ifork);
	return 0;
}

/**
 * @brief		Form layout fork from run time fork.
 * @param [out]	inode	The inode for appropriate run time fork
 * @param [in]	lfork	Layout fork
 * @return	void
 */
void vdfs4_form_fork(struct vdfs4_fork *lfork, struct inode *inode)
{
	struct vdfs4_fork_info *ifork = &(VDFS4_I(inode)->fork);
	unsigned i;

	memset(lfork, 0, sizeof(struct vdfs4_fork));

	if (S_ISCHR(inode->i_mode) || S_ISBLK(inode->i_mode))
		lfork->size_in_bytes = cpu_to_le64(inode->i_rdev);
	else {
		if (is_vdfs4_inode_flag_set(inode, VDFS4_COMPRESSED_FILE))
			lfork->size_in_bytes = cpu_to_le64(
					VDFS4_I(inode)->fbc->comp_size);
		else
			lfork->size_in_bytes = cpu_to_le64(inode->i_size);

		lfork->total_blocks_count =
				cpu_to_le32(ifork->total_block_count);

		for (i = 0; i < ifork->used_extents; ++i) {
			struct vdfs4_iextent *lextent;

			lextent = &lfork->extents[i];
			lextent->extent.begin = cpu_to_le64(
				ifork->extents[i].first_block);
			lextent->extent.length = cpu_to_le32(
				ifork->extents[i].block_count);
			lextent->iblock = cpu_to_le64(ifork->extents[i].iblock);
		}
	}
}

/**
 * @brief		exttree key structure initializer.
 * @param [in,out] key	exttree key for initialization.
 * @return		void
 */
static void exttree_key_ctor(void *key)
{
	memset(key, 0, sizeof(struct vdfs4_exttree_key));
}

int vdfs4_exttree_cache_init(void)
{
	extents_tree_key_cachep = kmem_cache_create("vdfs4_exttree_key",
		sizeof(struct vdfs4_exttree_key), 0,
		SLAB_HWCACHE_ALIGN, exttree_key_ctor);
	if (!extents_tree_key_cachep) {
		VDFS4_ERR("failed to initialize extents tree key cache\n");
		return -ENOMEM;
	}
	return 0;
}

void vdfs4_exttree_cache_destroy(void)
{
	kmem_cache_destroy(extents_tree_key_cachep);
}

struct vdfs4_exttree_key *vdfs4_get_exttree_key(void)
{
	struct vdfs4_exttree_key *key =
		kmem_cache_alloc(extents_tree_key_cachep, __GFP_WAIT);
	return key ? key : ERR_PTR(-ENOMEM);
}

void vdfs4_put_exttree_key(struct vdfs4_exttree_key *key)
{
	kmem_cache_free(extents_tree_key_cachep, key);
}
#endif /* USER_SPACE */

/**
 * @brief	Look up for extent nearest to given iblock no
 *		for given object_id (inode->i_ino)
 * @param [in] inode_info	inode information structure.
 * @param [in] iblock		Logical block number to find.
 * @param [out] result		result extent. If it is impossible to find exact
 *				extent for given object_id, *result contains
 *				nearest to the left to the desired extent and
 *				return is -ENOENT.
 * @return		resulting bnode, or error code.
 */
int vdfs4_exttree_get_extent(struct vdfs4_sb_info *sbi, struct inode *inode,
		sector_t iblock, struct vdfs4_extent_info *result)
{
	struct vdfs4_exttree_record *record;
	int ret = 0;
	__u64 first_iblock, object_id = inode->i_ino;
	__u64 last_iblock;

	mutex_r_lock(sbi->extents_tree->rw_tree_lock);

	record = vdfs4_exttree_find_record_strict_obj(sbi, object_id, iblock,
			VDFS4_BNODE_MODE_RO);
	if (IS_ERR(record)) {
		/* There can not be any hint in case of error finding */
		memset(result, 0, sizeof(*result));
		ret = PTR_ERR(record);
		goto exit;
	}

	/* Any way have to fill the hint */
	result->block_count = le32_to_cpu(record->lextent->length);
	result->first_block = le64_to_cpu(record->lextent->begin);
	result->iblock = le64_to_cpu(record->key->iblock);

	/* However we have to inform that it is not exact extent (just hint) */
	first_iblock = le64_to_cpu(record->key->iblock);
	last_iblock = first_iblock + le32_to_cpu(record->lextent->length);
	vdfs4_release_record((struct vdfs4_btree_gen_record *) record);
	if (!(first_iblock <= iblock && iblock <= last_iblock))
		ret = -ENOENT;

exit:
	mutex_r_unlock(sbi->extents_tree->rw_tree_lock);

	return ret;
}

#ifndef USER_SPACE
int vdfs4_extree_insert_extent(struct vdfs4_sb_info *sbi,
		unsigned long object_id, struct vdfs4_extent_info *extent,
		int force_insert)
{
	int ret;

	mutex_w_lock(sbi->extents_tree->rw_tree_lock);
	ret = vdfs4_exttree_add(sbi, object_id, extent, force_insert);
	mutex_w_unlock(sbi->extents_tree->rw_tree_lock);

	return ret;
}


int vdfs4_runtime_extent_add(sector_t iblock, sector_t alloc_hint,
		struct list_head *list) {
	struct list_head *ptr, *next;
	struct vdfs4_runtime_extent_info *entry, *next_entry;
	struct vdfs4_runtime_extent_info *ext = NULL;
	list_for_each_safe(ptr, next, list) {
		entry = list_entry(ptr, struct vdfs4_runtime_extent_info, list);
		/* new block is aligned to the existent block at the end */
		if ((entry->iblock + entry->block_count) == iblock) {
			entry->block_count++;
			/* join with next extent if needed */
			if (next != list) {
				next_entry = list_entry(next,
					struct vdfs4_runtime_extent_info, list);
				if ((entry->iblock + entry->block_count) ==
					next_entry->iblock) {
					next_entry->iblock = entry->iblock;
					next_entry->block_count += entry->
							block_count;
					list_del(&entry->list);
					kfree(entry);
				}
			}
			return 0;
		/* new block is aligned to the existent block at the begining*/
		} else if (entry->iblock == (iblock + 1)) {
			entry->iblock--;
			entry->block_count++;
			return 0;
		/* new block  already exists. */
		} else if (((entry->iblock) <= iblock) &&
			((entry->iblock + entry->block_count) > iblock)) {
			return -EEXIST;
		/* insert new extent */
		} else if (entry->iblock > iblock) {
			ext = kzalloc(sizeof(struct vdfs4_runtime_extent_info),
				GFP_NOFS);
			/* if we have no memory just ignore this situation */
			if (ext == NULL)
				return -ENOMEM;
			ext->alloc_hint = alloc_hint;
			ext->iblock = iblock;
			ext->block_count = 1;
			list_add_tail(&ext->list, ptr);
			return 0;
		}
	}
	ext = kzalloc(sizeof(struct vdfs4_runtime_extent_info), GFP_NOFS);
	/* if we have no memory just ignore this situation, runtime fork is
	 * needed to improve performace of space allocation, but will work
	 * without it */
	if (ext == NULL)
		return -ENOMEM;
	ext->alloc_hint = alloc_hint;
	ext->iblock = iblock;
	ext->block_count = 1;
	list_add_tail(&ext->list, list);
	return 0;
}

int vdfs4_runtime_extent_del(sector_t iblock, struct list_head *list)
{
	struct list_head *ptr, *next;
	struct vdfs4_runtime_extent_info *entry;

	list_for_each_safe(ptr, next, list) {
		entry = list_entry(ptr, struct vdfs4_runtime_extent_info, list);
		/* begining of chunk */
		if (entry->iblock == iblock) {
			entry->iblock++;
			entry->block_count--;
			/* delete entire extent */
			if (entry->block_count == 0) {
				list_del(&entry->list);
				kfree(entry);
			}
			return 0;
		/* delete from end */
		} else if (((entry->iblock + entry->block_count) ==
				(iblock + 1))) {
			entry->block_count--;
			return 0;
		/* middle of chunk */
		} else if (entry->iblock <= iblock &&
			((entry->iblock + entry->block_count) > iblock)) {
			struct vdfs4_runtime_extent_info *new = kzalloc(
				sizeof(struct vdfs4_runtime_extent_info),
				GFP_NOFS);
			if (new == NULL)
				return -ENOMEM;
			new->iblock = iblock + 1;
			new->alloc_hint = 0;
			new->block_count = (u32)(entry->iblock - new->iblock)
				+ entry->block_count;
			list_add_tail(&new->list, ptr);
			entry->block_count -= new->block_count + 1;
			return 0;
		}
	}
	/* try to remove a nonexistent extent */
	BUG();
	return 0;
}
/** returns total of freed blocks
 *
 * */
sector_t vdfs4_truncate_runtime_blocks(sector_t new_size_iblocks,
		struct list_head *list)
{
	struct list_head *ptr, *next;
	struct vdfs4_runtime_extent_info *entry;
	sector_t total = 0;
	u32 trunc_size = 0;
	list_for_each_safe(ptr, next, list) {
		entry = list_entry(ptr, struct vdfs4_runtime_extent_info,
			list);
		/* entire chunck should be truncated */
		if (entry->iblock >= new_size_iblocks) {
			total += entry->block_count;
			list_del(&entry->list);
			kfree(entry);
		/* if new size inside the chunk */
		} else if ((entry->iblock + entry->block_count) >=
			new_size_iblocks) {
			trunc_size = (u32)(new_size_iblocks - entry->iblock);
			total += entry->block_count - trunc_size;
			entry->block_count = trunc_size;
		}
	}
	return total;
}
u32 vdfs4_runtime_extent_exists(sector_t iblock, struct list_head *list)
{
	struct list_head *ptr;
	struct vdfs4_runtime_extent_info *entry;
	list_for_each(ptr, list) {
		entry = list_entry(ptr, struct vdfs4_runtime_extent_info, list);
		if ((iblock >= entry->iblock) && (iblock < entry->iblock +
				entry->block_count))
			return 1;
	}
	return 0;
}

u32 vdfs4_runtime_extent_count(struct list_head *list)
{
	struct list_head *ptr;
	struct vdfs4_runtime_extent_info *entry;
	u32 count = 0;
	list_for_each(ptr, list) {
		entry = list_entry(ptr, struct vdfs4_runtime_extent_info, list);
		count += entry->block_count;
	}
	return count;
}

long vdfs4_fallocate(struct file *file, int mode, loff_t offset, loff_t len)
{
	struct inode *inode = file->f_path.dentry->d_inode;
	if (!S_ISREG(inode->i_mode))
		return -ENODEV;
	return -EOPNOTSUPP; /*todo implementation*/
}
#endif /* USER_SPACE */
