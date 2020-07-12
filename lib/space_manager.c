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

#include "../include/vdfs_tools.h"
#include <string.h>
#include <assert.h>

/**
 * @brief		Put new chunk to free space chunks list.
 * @param [in]	root		Space manager info structure pointer.
 * @param [in]	block_offset	Offset in blocks of chunk.
 * @param [in]	block_count	Block count of chunk.
 * @return	void
 */
void put_space_manager_list_sorted(struct space_manager_info *root,
		u_int64_t offset, u_int32_t length)
{
	struct space_manager_item *list = root->space_manager_list;
	struct space_manager_item *item =
			malloc(sizeof(struct space_manager_item));
	assert(item);
	item->offset = offset;
	item->length = length;
	item->next = 0;

	if (!list || (list->offset > item->offset)) {
		item->next = list;
		root->space_manager_list = item;
		return;
	}
	while (list) {
		if (list == item)
			break;
		if (!list->next)
			list->next = item;
		else if (list->next->offset > item->offset) {
			item->next = list->next;
			list->next = item;
		} else
			list = list->next;
	}
}

/**
 * @brief		Removal item from list.
 * @param [in]	root		Space manager info structure pointer.
 * @param [in]	list_item	List item pointer.
 * @return	void
 */
void remove_from_list(struct space_manager_info *root,
		struct space_manager_item *list_item)
{
	struct space_manager_item *list_ptr = root->space_manager_list;
	assert(list_item);

	if (list_item == root->space_manager_list) {
		root->space_manager_list = root->space_manager_list->next;
		return;
	}

	while (list_ptr->next) {
		if (list_ptr->next == list_item) {
			list_ptr->next = list_ptr->next->next;
			return;
		}
		list_ptr = list_ptr->next;
	}
}

/**
 * @brief		Reduce length of list item and remove this element
 *			if it's length becomes zero.
 * @param [in]	root		Space manager info structure pointer.
 * @param [in]	list_ptr	List item pointer.
 * @param [in]	length		Decrease size.
 * @return	void
 */
static void shrink_list_item(struct space_manager_info *root,
		struct space_manager_item *list_ptr, u_int32_t length)
{
	list_ptr->length -= length;
	if (!list_ptr->length) {
		remove_from_list(root, list_ptr);
		free(list_ptr);
	}
}
/**
 * @brief		Sign space manager buffer. Update it with sign and
 *			crc numbers.
 * @param [in]	sbi	Superblock info structure pointer.
 * @return	void.
 */
void sign_sm_buffer(struct vdfs4_sb_info *sbi)
{
	int64_t cur_blck = 0;
	int64_t end_blck = 0;
	char *buffer;
	u64 version = VERSION;
	char magic[FSM_BMP_MAGIC_LEN];
	memcpy(magic, FSM_BMP_MAGIC,
			sizeof(FSM_BMP_MAGIC) - 1);
	memcpy((magic + sizeof(FSM_BMP_MAGIC)
			- 1), &version, sizeof(u64));
	/* divide the bitmap to blocks and update & sign each block*/
	end_blck = (sbi->space_manager_info.subsystem.buffer_size) /\
			sbi->block_size;

	for (cur_blck = 0; cur_blck < end_blck; cur_blck++) {
		/* calc address of current block */
		buffer = sbi->space_manager_info.subsystem.buffer +\
				(cur_blck * sbi->block_size);
		/* update sign and crc */
		util_update_crc(buffer,\
			sbi->block_size,\
				magic, FSM_BMP_MAGIC_LEN);
	}
}

/**
 * @brief		Init space manager buffer. Update it with sign and
 *			crc numbers.
 * @param [in]	sbi	Superblock info structure pointer.
 * @return	void.
 */
static void init_sm_buffer(struct vdfs4_sb_info *sbi)
{
	memset(sbi->space_manager_info.subsystem.buffer, 0,
			sbi->space_manager_info.subsystem.buffer_size);
	sign_sm_buffer(sbi);
}

/**
 * @brief		Set requested bits range in space_manager bitmap.
 * @param [in]	addr	Offset in bits of first bit to be set.
 * @param [in]	count	Count of bits to be set.
 * @return 0 on success, negative on fail.
 */
static int fsm_set_bits(struct vdfs4_sb_info *sbi, u_int64_t addr, u_int32_t num)
{
	return util_sign_set_bits(sbi->space_manager_info.subsystem.buffer,
			sbi->space_manager_info.subsystem.buffer_size, addr,
		num, sbi->block_size, FSM_BMP_MAGIC_LEN, CRC32_SIZE);
}

/**
 * @brief		Get chunk with requested offset and length from free
 *			space chunks list and update space_manager bitmap.
 * @param [in]	sbi		Superblock info structure pointer.
 * @param [in]	block_offset	Offset in blocks of requested chunk. If equal
 *				to ADDR_ANY, we will find first free chunk of
 *				requested length.
 * @param [in]	block_count	Block count of chunk.
 * @return	Offset of free space chunk or -ENOSPC due to an error.
 */
static int64_t get_free_space(struct vdfs4_sb_info *sbi,
		u_int64_t offset, u_int32_t length)
{
	struct space_manager_info *root = &sbi->space_manager_info;
	struct space_manager_item *list_ptr = root->space_manager_list;
	int64_t addr = -ENOSPC;

	if (IS_FLAG_SET(sbi->service_flags, READ_ONLY_IMAGE)) {
		u_int64_t first_free_address = root->first_free_address;
		__u64 used_size;

		/* image used size check */
		used_size = block_to_byte(first_free_address + length,
				     sbi->block_size);
		if (IS_FLAG_SET(sbi->service_flags, LIMITED_SIZE)
		    && sbi->min_volume_size < used_size) {
			return -ENOSPC;
		}

		if (offset != ADDR_ANY) {
			if (offset != root->first_free_address)
				return -1;
		}
		root->first_free_address += length;
		return first_free_address;
	}

	while (list_ptr) {
		if (offset == ADDR_ANY) {
			if (length <= list_ptr->length) {
				addr = list_ptr->offset;
				list_ptr->offset += length;
				shrink_list_item(root, list_ptr, length);
				break;
			}
		} else if ((offset >= list_ptr->offset) && (offset + length) <=
				(list_ptr->offset + list_ptr->length)) {
			addr = offset;
			if (offset == list_ptr->offset) {
				list_ptr->offset += length;
				shrink_list_item(root, list_ptr, length);
				break;
			}
			if ((offset + length) ==
					(list_ptr->offset + list_ptr->length)) {
				shrink_list_item(root, list_ptr, length);
				break;
			}
			remove_from_list(root, list_ptr);
			put_space_manager_list_sorted(root, list_ptr->offset,
				offset - list_ptr->offset);
			put_space_manager_list_sorted(root, offset + length,
				list_ptr->length - length -
					(offset - list_ptr->offset));
			free(list_ptr);
			break;
		}
		list_ptr = list_ptr->next;
	}
	if (addr != -ENOSPC) {
		fsm_set_bits(sbi, addr, length);
		sbi->free_blocks_count -= length;
	}
	return addr;
}

/**
 * @brief		Space manager initialization function.
 * @param [in]	sbi	Superblock information structure pointer.
 * @return		0	Success,
 *			-ENOSPC	Error while allocate space for superblocks or
 *				leb bitmap.
 *			-ENOMEM	Memory allocation error
 */
int init_space_manager(struct vdfs4_sb_info *sbi)
{
	int ret = 0;
	int sign_crc_len = 0;
	/* data block size in bits */
	struct space_manager_info *space_manager_info =
		&sbi->space_manager_info;
	unsigned long buffer_size;


	log_activity("Initialize space manager");
	assert(sbi->block_size);

	if (IS_FLAG_SET(sbi->service_flags, READ_ONLY_IMAGE))
		return 0;

	assert(sbi->log_blocks_in_leb);
	sign_crc_len = CRC32_SIZE + FSM_BMP_MAGIC_LEN;

	space_manager_info->bits_count = (sbi->max_volume_size
			- sbi->vdfs4_start_block) / sbi->block_size;

	/* Align on_disk_size to the block size boundary */
	/* 1. to byte */
	buffer_size = ((space_manager_info->bits_count + 7) >> 3);
	/* 2. add signature and crc */
	buffer_size += sign_crc_len * (buffer_size / sbi->block_size + 1);
	/* 3. allign to block size */
	buffer_size = (buffer_size + sbi->block_size - 1) &
			(~(sbi->block_size - 1));
	space_manager_info->subsystem.buffer_size = buffer_size;

	put_space_manager_list_sorted(space_manager_info, 0,
			space_manager_info->bits_count);

	space_manager_info->subsystem.sub_system_id = VDFS4_SPACE_BITMAP_INO;
	space_manager_info->subsystem.subsystem_name = "SPACE MANAGER BITMAP";
	space_manager_info->subsystem.buffer = malloc(buffer_size);

	if (!space_manager_info->subsystem.buffer) {
		ret = -ENOMEM;
		goto exit;
	}

	/* init space manager buffer */
	init_sm_buffer(sbi);

	sbi->free_blocks_count = space_manager_info->bits_count;

	sbi->snapshot.metadata_size +=
		byte_to_block(buffer_size, sbi->block_size);
exit:
	if (ret)
		log_error("Can't initialize space manager");
	return ret;
}

/**
 * @brief			Space allocator.
 * @param [in]	sbi		Superblock information structure pointer.
 * @param [in]	block_offset	Offset in blocks of requested chunk.
 *				If block_offset parameter equal to ADDR_ANY,
 *				allocation will been made from beginning
 *				of free space.
 * @param [in]	block_count	Block count of requested chunk.
 * @param [out] address of the first allocated block
 * @return		0 on success, error code otherwise
 */
int allocate_space(struct vdfs4_sb_info *sbi, u_int64_t block_offset,
		u_int32_t block_count, u_int64_t *first_block)
{
	int ret = 0;
	int64_t addr;

	addr = get_free_space(sbi, block_offset, block_count);
	if (addr < 0)
		ret = -ENOSPC;
	else if (first_block != NULL)
		*first_block = addr;

	return ret;
}

void destroy_space_manager(struct vdfs4_sb_info *sbi)
{
	struct space_manager_info *space_manager_info =
			&sbi->space_manager_info;


	while (space_manager_info->space_manager_list) {
		struct space_manager_item *space_manager_list_tmp =
				space_manager_info->space_manager_list->next;
		free(space_manager_info->space_manager_list);
		space_manager_info->space_manager_list = space_manager_list_tmp;
	}

	free(sbi->space_manager_info.subsystem.buffer);
}

int is_tree(__u8 object_type)
{
	if (object_type == VDFS4_CAT_TREE_INO
		|| object_type == VDFS4_EXTENTS_TREE_INO
		|| object_type == VDFS4_XATTR_TREE_INO)
		return 1;

	if (object_type == VDFS4_SPACE_BITMAP_INO
		|| object_type == VDFS4_FREE_INODE_BITMAP_INO)
		return 0;
	if (object_type == 0)
		return 0;
	/* unknown object type */
	assert(0);
}

int get_iblock_size(struct vdfs4_sb_info *sbi, __u8 type)
{
	return is_tree(type) ? sbi->super_page_size / sbi->block_size : 1;
}

/**
 * @brief Function allocates space for VDFS4 subsystem
 * @param [in] sbi Superblock runtime structure
 * @param [in] subsystem
 * @param [in] block_offset
 * @return 0 on success, error code otherwise
 */

#define VDFS4_GET_MBLOCK(iblock, meta_begin)	(iblock - meta_begin)
int place_on_volume_subsystem(struct vdfs4_sb_info *sbi,
		struct vdfs4_subsystem_data *subsystem)
{
	int ret = 0;
	int idx = VDFS4_SF_INDEX(subsystem->sub_system_id);
	u_int32_t size_in_blocks;
	u64 new_size, new_size2;
	__u64 offset = 0;
	int subsystem_is_tree = 0;
	struct vdfs4_extent_info *extent = sbi->snapshot.metadata_extent;
	unsigned int table_size, iblock_count, iblock_size;
	unsigned int count;
	__u64 start_block;
	struct vdfs4_base_table_record *table;

	struct vdfs4_base_table *base_table = (struct vdfs4_base_table *)
				(sbi->snapshot.snapshot_subsystem.buffer);

	struct vdfs4_meta_hashtable *hashtable = (struct vdfs4_meta_hashtable *)
				(sbi->meta_hashtable.subsystem.buffer);

	u_int32_t buffer_size  = sbi->snapshot.snapshot_subsystem.buffer_size;
	u_int32_t buffer_size2 = sbi->meta_hashtable.subsystem.buffer_size;

	if (is_tree(subsystem->sub_system_id)) {
		struct vdfs_tools_btree_info *tree;
		switch (subsystem->sub_system_id) {
		case VDFS4_CAT_TREE_INO:
			tree = &sbi->cattree;
			break;
		case VDFS4_EXTENTS_TREE_INO:
			tree = &sbi->exttree;
			break;
		case VDFS4_XATTR_TREE_INO:
			tree = &sbi->xattrtree;
			break;
		default:
			return -EINVAL;
		}
		subsystem_is_tree = 1;
		size_in_blocks = get_bnodes_count(tree) * (sbi->super_page_size
				/ sbi->block_size);
	} else
		size_in_blocks = byte_to_block(subsystem->buffer_size,
						sbi->block_size);

	/* update basetable info */
	iblock_size = get_iblock_size(sbi, subsystem->sub_system_id);
	iblock_count = size_in_blocks / iblock_size;
	if (subsystem->sub_system_id == VDFS4_SNAPSHOT_INO) {
		extent = &sbi->snapshot.tables_extent;
		goto alloc;
	} else if (subsystem->sub_system_id > VDFS4_LSFILE) {
		extent = &subsystem->fork.extents[0];
		goto alloc;
	}
	table_size = sizeof(struct vdfs4_base_table_record) * iblock_count;
	new_size = sbi->snapshot.snapshot_subsystem.buffer_size +
			table_size;

	base_table = realloc(base_table, new_size);
	if (!base_table)
		return -ENOMEM;

	sbi->snapshot.snapshot_subsystem.buffer = (char *)base_table;
	memset((char *)(sbi->snapshot.snapshot_subsystem.buffer +
			sbi->snapshot.snapshot_subsystem.buffer_size), 0,
			table_size);
	table = (struct vdfs4_base_table_record *)((char *)base_table
			+ buffer_size);
	base_table->translation_table_offsets[idx] = cpu_to_le32(buffer_size);
	sbi->snapshot.snapshot_subsystem.buffer_size = new_size;

	/* update meta hashtable info */
	if (subsystem->sub_system_id == VDFS4_SPACE_BITMAP_INO) {
		/* just empty space for non bnode crc */
		new_size2 = sbi->meta_hashtable.subsystem.buffer_size +
			iblock_count;
	} else if (subsystem->sub_system_id == VDFS4_FREE_INODE_BITMAP_INO) {
		/* just empty space for non bnode crc */
		new_size2 = sbi->meta_hashtable.subsystem.buffer_size +
			iblock_count;
		new_size2 = DIV_ROUND_UP(new_size2, CRC32_SIZE) * CRC32_SIZE;
	} else {
		new_size2 = sbi->meta_hashtable.subsystem.buffer_size +
			iblock_count * CRC32_SIZE;
	}

	hashtable = realloc(hashtable, new_size2);
	if (!hashtable)
		return -ENOMEM;

	sbi->meta_hashtable.subsystem.buffer = (void *)hashtable;
	memset((char *)(sbi->meta_hashtable.subsystem.buffer +
			sbi->meta_hashtable.subsystem.buffer_size), 0,
			new_size2 - sbi->meta_hashtable.subsystem.buffer_size);

	hashtable->hashtable_offsets[idx] = cpu_to_le32(buffer_size2);
	sbi->meta_hashtable.subsystem.buffer_size = new_size2;
	hashtable->size = new_size2;

alloc:
	/* allocate space for subsystem */
	if (subsystem_is_tree) {
		/*align to super page size*/
		offset = ((extent->block_count + (sbi->super_page_size /
				sbi->block_size) - 1)
				& (~((sbi->super_page_size /
				sbi->block_size) - 1))) - extent->block_count;
	} else
		offset = 0;

	ret = allocate_space(sbi, extent->first_block + extent->block_count ,
			size_in_blocks + offset,
			(u_int64_t *)&start_block);
	if (ret) {
		log_error("%s: failed to allocate space for subsystem(%d)",
			  subsystem->subsystem_name, ret);
		return ret;
	}

	log_activity("%s: space allocated from %llu to %llu block, size %lu",
			subsystem->subsystem_name,
			start_block,
			start_block + size_in_blocks - 1,
			size_in_blocks);
	if (extent->first_block == 0)
		extent->first_block = start_block;
	else
		assert(extent->first_block + extent->block_count ==
			start_block);
	if (subsystem->sub_system_id <= VDFS4_LSFILE) {
		start_block = VDFS4_GET_MBLOCK(start_block,
			sbi->snapshot.metadata_extent[0].first_block);
		for (count = 0; count < iblock_count; count++) {
			table->meta_iblock = cpu_to_le64(start_block + offset
					+ count * iblock_size);
			table->mount_count = 0;
			table->sync_count = cpu_to_le32(1);
			table++;
		}
		base_table->last_page_index[idx] =
				cpu_to_le32(iblock_count - 1);
		sbi->snapshot.meta_tbc += size_in_blocks + offset;
	}
	extent->block_count += size_in_blocks + offset;

	return ret;
}

/**
 * @brief Function convert iblock to metablock for runtime structure of snapshot
 * @param [in] sbi		Superblock runtime structure
 * @param [in] iblock		Iblock num to convert
 * @return Metablock num
 */

static u64 iblock_to_mblock_for_conversion(struct vdfs4_sb_info *sbi, u64 iblock)
{
	u_int32_t length, i;
	u64 meta_area = 0, offset, metablock = 0, total_meta_blocks = 0;
	for (i = 0; i < sbi->snapshot.snapshot_subsystem.fork.used_extents + 1;
			i++) {
		length = sbi->snapshot.metadata_extent[i].block_count;
		if (!length)
			return 0;
		offset = sbi->snapshot.metadata_extent[i].first_block;
		total_meta_blocks += length;
		meta_area += length - 1 + offset;
		if ((meta_area >= iblock) && (iblock >= offset)) {
			metablock = total_meta_blocks -
					(offset + length - iblock);
			goto exit;
		}
	}
exit:
	return metablock;
}

/**
 * @brief Function convert metablock to iblock for runtime structure of snapshot
 * @param [in]	sbi		Superblock runtime structure
 * @param [in]	mblock		Metablock num to convert
 * @return iblock num
 */
int metablock_to_iblock_for_conversion(struct vdfs4_sb_info *sbi, u64 mblock)
{
	u_int32_t length, i;
	u64 total_area_size = 0, offset, iblock = 0;
	for (i = 0; i < sbi->snapshot.snapshot_subsystem.fork.used_extents + 1;
			i++) {
		length = sbi->snapshot.metadata_extent[i].block_count;
		offset = sbi->snapshot.metadata_extent[i].first_block;
		total_area_size += length;
		if (total_area_size > mblock) {
			iblock = (offset + length) -
					(total_area_size - mblock);
		goto exit;
		}
	}
exit:
	return iblock;
}

/**
 * @brief		allocate_space_for_each_subsystem_block
 * @param [in]	vdfs4_sbi	Superblock runtime structure
 * @param [in]	blocks_count	Count of blocks which need to place on volume
 * @param [in]	table		Point to table of metadata subsystem (if
 *				subsystem is not meta - table can be NULL)
 * @param [in]	iblock_size	Count of physical blocks in logic subsystem
 *				blocks
 * @param [in]	subsystem_idx	subsystem ino index
 * @param [in]	base_table	Point to base_table of meta area (if
 *				subsystem is not meta - base_table can be NULL)
 * @param [in]	extent		Point to extent of current subsystem
 * @param [in]	used_extents
 * @return	0 if space was successfully allocated, error code otherwise.
 */

int allocate_space_for_each_subsystem_block(struct vdfs4_sb_info *vdfs4_sbi,
		int blocks_count, struct vdfs4_base_table_record *table,
		u64 iblock_size,
		int subsystem_idx,
		struct vdfs4_base_table *base_table,
		struct vdfs4_extent_info *extent,
		__u32 *used_extents)
{
	int i, ret = 0;
	__u64 offset = 0;
	__u64 prev_block_num = 0;
	u_int64_t block_num, start_block = 0;
	int ext_num = *used_extents;
	prev_block_num = extent[ext_num].first_block +
			extent[ext_num].block_count - 1;

	/*align to super page size*/
	if (subsystem_idx <= VDFS4_LSFILE && subsystem_idx >= VDFS4_FSFILE) {
		offset = ((vdfs4_sbi->snapshot.meta_tbc + iblock_size - 1)
				& (~(iblock_size - 1)));
		blocks_count += offset - vdfs4_sbi->snapshot.meta_tbc;
	}
	ret = allocate_space(vdfs4_sbi,
			ADDR_ANY,
			blocks_count, &block_num);
	if (!ret) {
		if (block_num - prev_block_num == 1) {
			extent[ext_num].block_count += blocks_count;

		} else if (!extent[ext_num].block_count) {
			extent[ext_num].first_block = block_num;
			extent[ext_num].block_count = blocks_count;
		} else	{
			ext_num++;
			extent[ext_num].first_block = block_num;
			extent[ext_num].block_count = blocks_count;
			(*used_extents)++;
			assert(ext_num < VDFS4_META_BTREE_EXTENTS);
		}
		start_block = block_num;
		goto fill_table;
	}

	for (i = 0; i < blocks_count; i += iblock_size) {
		ret = allocate_space(vdfs4_sbi,
			ADDR_ANY,
			iblock_size, &block_num);
		if (ret) {
			log_error("Can't allocate space");
			return ret;
		}
		if (i == 0)
			start_block = block_num;

		if (block_num - prev_block_num == 1) {
			extent[ext_num].block_count += iblock_size;
		} else {
			ext_num++;
			extent[ext_num].first_block = block_num;
			extent[ext_num].block_count = iblock_size;
			(*used_extents)++;
			assert(ext_num < VDFS4_META_BTREE_EXTENTS);
		}
		prev_block_num = extent[ext_num].first_block +
				extent[ext_num].block_count - 1;
	}



fill_table:

	if (subsystem_idx <= VDFS4_LSFILE && subsystem_idx >= VDFS4_FSFILE) {
		if (!base_table) {
			vdfs4_sbi->snapshot.meta_tbc += blocks_count;
			return ret;
		}
		__u32 count;
		start_block = iblock_to_mblock_for_conversion
				(vdfs4_sbi, start_block);
		start_block = ((start_block + iblock_size - 1)
				& (~(iblock_size - 1)));
		for (count = 0; count < blocks_count / iblock_size; count++) {
			table->meta_iblock = cpu_to_le64(
					start_block + count * iblock_size);
			table++;
		}
		vdfs4_sbi->snapshot.meta_tbc += blocks_count;
		base_table->last_page_index[subsystem_idx - 2] =
				cpu_to_le32(blocks_count / iblock_size - 1);
	}
	return ret;


}

/**
 * @brief Function convert metablock to iblock read from volume
 * @param [in] sbi		Superblock runtime structure
 * @param [in] mblock		Metablock num to convert
 * @return iblock num
 */


u64 metablock_to_iblock(struct vdfs4_sb_info *sbi, u64 metablock)
{
	u_int32_t length;
	int i;
	u64 total_area_size = 0, offset, iblock = 0;
	for (i = 0; i < VDFS4_META_BTREE_EXTENTS; i++) {
		length = sbi->esb.meta[i].length;
		offset = sbi->esb.meta[i].begin;
		total_area_size += length;
		if (total_area_size > metablock) {
			iblock = (offset + length) -
					(total_area_size - metablock);
			goto exit;
		}
	}
exit:
	return iblock;
}

/**
 * @brief Function convert iblock to metablock read from volume
 * @param [in] sbi		Superblock runtime structure
 * @param [in] iblock		Iblock num to convert
 * @return Metablock num
 */

int iblock_to_metablock(struct vdfs4_sb_info *sbi, u64 iblock)
{
	u_int32_t length;
	int i;
	u64 meta_area = 0, offset, metablock = -1, total_meta_blocks = 0;
	for (i = 0; i < VDFS4_META_BTREE_EXTENTS; i++) {
		length = sbi->esb.meta[i].length;
		offset = sbi->esb.meta[i].begin;
		total_meta_blocks += length;
		meta_area += length - 1 + offset;
		if ((meta_area >= iblock) && (iblock >= offset) && (iblock
				< (length + offset))) {
			metablock = total_meta_blocks -
					(offset + length - iblock);
			goto exit;
		}
	}
exit:
	return metablock;
}
