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

#include <string.h>
#include <assert.h>
#include "../include/vdfs_tools.h"

/**
 * @brief		Flush allocated buffer for snapshot on volume
 * @param [in]	sbi	Superblock runtime structure
 * @return		0 on success, error code otherwise
 */
int flush_snapshot(struct vdfs4_sb_info *sbi)
{
	int ret = 0;
	struct vdfs4_base_table *base_table;
	char *buffer = sbi->snapshot.snapshot_subsystem.buffer;
	__u32 checksum;
	unsigned int size =
		sbi->snapshot.snapshot_subsystem.buffer_size;
	unsigned int full_table_size = sbi->snapshot.tables_extent.block_count
			* sbi->block_size;

	log_activity("Flush SNAPSHOT start");

	if (size + CRC32_SIZE > full_table_size) {
		log_error("Error: size for on-disk layout(%u) is smaller then "
				"snapshot calculated size(%u)",
				full_table_size,
				size + CRC32_SIZE);
		return -EINVAL;
	}

	buffer = realloc(buffer, full_table_size);
	if (!buffer) {
		log_error("Error: realloc failed (0x%x/0x%x)",
				buffer, full_table_size);
		return -ENOMEM;
	}

	/* first - calculate snapshot tables CRC */
	base_table = (struct vdfs4_base_table *)buffer;
	base_table->descriptor.checksum_offset = cpu_to_le32(size);
	base_table->descriptor.sync_count = 1;
	checksum = vdfs4_crc32(buffer, size);
	*((__le32 *)(buffer + size)) = cpu_to_le32(checksum);

	sbi->snapshot.checksum = cpu_to_le32(checksum);

	/* second - write full snapshot table to disk */
	if (full_table_size > size + CRC32_SIZE)
		memset(buffer + size + CRC32_SIZE, 0,
			full_table_size - size - CRC32_SIZE);

	log_activity("Flush SNAPSHOT - snapshot table data ready");
	ret = vdfs4_write_blocks(sbi, sbi->snapshot.tables_extent.first_block +
			sbi->vdfs4_start_block, buffer,
			sbi->snapshot.tables_extent.block_count);

	sbi->snapshot.snapshot_subsystem.buffer = buffer;
	sbi->snapshot.snapshot_subsystem.buffer_size = full_table_size;
	if (ret)
		log_error("Failed to flush SNAPSHOT");
	else
		log_activity("Succeed to flush SNAPSHOT");

	return ret;
}

int flush_hashtable(struct vdfs4_sb_info *sbi)
{
	int ret = 0;
	__u32 checksum;
	u_int64_t block_offset, first_block;
	char *buffer = sbi->meta_hashtable.subsystem.buffer;
	unsigned int size = sbi->meta_hashtable.subsystem.buffer_size;
	unsigned int full_table_blkcnt = DIV_ROUND_UP(size + CRC32_SIZE,
						      sbi->block_size);
	unsigned int full_table_size = block_to_byte(full_table_blkcnt,
						     sbi->block_size);

	log_activity("Flush HASHTABLE start");

	buffer = realloc(buffer, full_table_size);
	if (!buffer) {
		log_error("Error: realloc failed (0x%x/0x%x)",
				buffer, full_table_size);
		return -ENOMEM;
	}

	checksum = vdfs4_crc32(buffer, size);
	*((__le32 *)(buffer + size)) = cpu_to_le32(checksum);
	sbi->meta_hashtable.checksum = cpu_to_le32(checksum);

	if (full_table_size > size + CRC32_SIZE)
		memset(buffer + size + CRC32_SIZE, 0,
			full_table_size - size - CRC32_SIZE);

	log_activity("Flush HASHTABLE - hash table data ready");
	/* try to allocate space for HASHTABLE */
	ret = allocate_space(sbi, ADDR_ANY, full_table_blkcnt, &block_offset);
	if (ret) {
		log_error("Failed to allocate space for HASHTABLE");
		return ret;
	}

	/* write meta hashtable to disk */
	first_block = sbi->vdfs4_start_block + block_offset;
	ret = vdfs4_write_blocks(sbi, first_block, buffer, full_table_blkcnt);

	sbi->meta_hashtable.subsystem.buffer = buffer;
	sbi->meta_hashtable.subsystem.buffer_size = full_table_size;
	sbi->meta_hashtable.subsystem.fork.total_block_count =
		full_table_blkcnt;
	sbi->meta_hashtable.subsystem.fork.extents[0].first_block = first_block;
	sbi->meta_hashtable.subsystem.fork.extents[0].block_count =
		full_table_blkcnt;
	if (ret)
		log_error("Failed to flush HASHTABLE");
	else
		log_activity("Succeed to flush HASHTABLE(0x%x, %d blocks)",
			     block_to_byte(first_block, sbi->block_size),
			     full_table_blkcnt);
	return ret;
}

/**
 * @brief		The fuction calculates metadata size and saves the
 *			result into snapshot_info metadata extent.
 * @param [in]	sbi	Superblock information structure pointer
 */
int calculate_metadata_size(struct vdfs4_sb_info *sbi)
{
	unsigned long volume_size_in_blocks =
		byte_to_block(sbi->max_volume_size, sbi->block_size)
		- sbi->vdfs4_start_block;
	__u32 metadata_size, metadata_addition;
	int ret = 0;

	/* meta_extent contains already allocated space, we must expand it
	 * reserve +256 blocks for preventing early meta expansion.
	 */
	metadata_size = sbi->snapshot.metadata_size;
	metadata_addition = metadata_size * 2 <
		(volume_size_in_blocks / 100) * 2 ?
		(volume_size_in_blocks / 100) * 2 - metadata_size + 256 :
		metadata_size + 256;

	/* align metadata size to super page size */
	metadata_size = ALIGN(metadata_size,
			sbi->super_page_size / sbi->block_size);

	/* align metadata preallocation size to super page size */
	metadata_addition = ALIGN(metadata_addition,
			sbi->super_page_size / sbi->block_size);

	sbi->snapshot.metadata_size = metadata_size + metadata_addition;
	sbi->snapshot.preallocation_len = metadata_addition;
	return ret;
}

/**
 * @brief		CoW translation size calculation.
 * @param [in]	sbi	Superblock information structure pointer
 * @return		0 Success, -ENOMEM Memory allocation error
 * @details
 */
int calculate_translation_tables_size(struct vdfs4_sb_info *sbi, int allocate)
{
	unsigned int table_size;
	unsigned int tables_size_in_blocks;
	struct vdfs4_extent_info *tables_extent = &sbi->snapshot.tables_extent;
	unsigned long bnode_size = get_bnode_size(sbi);
	unsigned long minimal_record_size, records_count;
	unsigned long max_bnodes_count, max_objects_count;
	unsigned long objects_per_page = VDFS4_BIT_BLKSIZE(sbi->block_size,
			INODE_BITMAP_MAGIC_LEN);
	unsigned long inode_bitmap_pages;
	int ret = 0;
	__u64 tables_start;
	if (IS_FLAG_SET(sbi->service_flags, READ_ONLY_IMAGE)) {
		max_bnodes_count = get_bnodes_count(&sbi->cattree) +
				get_bnodes_count(&sbi->exttree) +
				get_bnodes_count(&sbi->xattrtree);
		table_size = sizeof(struct vdfs4_snapshot_descriptor) +
			sizeof(struct vdfs4_base_table_record)
			* max_bnodes_count + CRC32_SIZE +
					sizeof(struct vdfs4_base_table);
		tables_size_in_blocks =
				DIV_ROUND_UP(table_size, sbi->block_size);
		goto allocate;
	}
	/* minimal record size is directory */
	minimal_record_size = sizeof(struct vdfs4_cattree_key) -
			VDFS4_FILE_NAME_LEN;
	minimal_record_size += sizeof(struct vdfs4_catalog_folder_record);
	minimal_record_size = (minimal_record_size + 8 - 1) & (~(8 - 1));
	/* each record has an offset in bnode offsets area */
	minimal_record_size += 4;

	/* records count in bnode */
	/* node size - descriptor - CRC size*/
	records_count = (bnode_size - sizeof(struct vdfs4_gen_node_descr) - 4) /
			minimal_record_size;
	max_bnodes_count = sbi->max_volume_size / bnode_size;
	max_objects_count = max_bnodes_count * records_count;
	inode_bitmap_pages = DIV_ROUND_UP(max_objects_count, objects_per_page);
	max_bnodes_count = (sbi->max_volume_size -
		(inode_bitmap_pages << sbi->log_block_size)) / bnode_size;

	/* one table must be able to describe all metadata */
	table_size = sizeof(struct vdfs4_snapshot_descriptor) +
			sizeof(struct vdfs4_base_table_record)
			* (inode_bitmap_pages + max_bnodes_count)
		+ CRC32_SIZE;

	tables_size_in_blocks = DIV_ROUND_UP(table_size, sbi->block_size);
	tables_size_in_blocks += VDFS4_SNAPSHOT_EXT_TABLES;

	/* we have two base tables and two set of the extended tables */
	tables_size_in_blocks <<= 1;
allocate:
	if (allocate) {
		ret = allocate_space(sbi, ADDR_ANY,
			tables_size_in_blocks,
			(u_int64_t *)&tables_start);
		tables_extent->first_block = tables_start;
		if (ret) {
			log_error("Can't allocate space for"
				  " translation tables");
			return ret;
		}
	}
	tables_extent->block_count = tables_size_in_blocks;
	sbi->snapshot.table_tbc = tables_size_in_blocks;
	return 0;
}

/**
 * @brief		Snapshot size calculation.
 * @param [in]	sbi	Superblock information structure pointer
 * @return		0	Success,
 *			-ENOMEM	Memory allocation error
 */
int calculate_and_place_on_volume_snapshot(struct vdfs4_sb_info *sbi)
{
	int ret = 0;

	log_activity("Create empty snapshot");
	if (!IS_FLAG_SET(sbi->service_flags, READ_ONLY_IMAGE)) {
		ret = calculate_metadata_size(sbi);
		if (ret)
			goto exit;
	}
	ret = calculate_translation_tables_size(sbi, 1);
exit:
	return ret;
}

int place_on_volume_preallocation(struct vdfs4_sb_info *sbi)
{
	int ret = 0;
	struct vdfs4_extent_info *meta_extent = sbi->snapshot.metadata_extent;
	__u64 metadata_addr;
	/* allocate space for metadata preallocation */
	ret = allocate_space(sbi, (meta_extent->first_block +
				meta_extent->block_count),
				sbi->snapshot.preallocation_len,
				(u_int64_t *)&metadata_addr);
	if (ret) {
		log_error("Can't allocate space for snpashot preallocation");
		return ret;
	}
	assert(metadata_addr == meta_extent->first_block +
			meta_extent->block_count);
	meta_extent->block_count += sbi->snapshot.preallocation_len;
	return ret;
}

int init_snapshot(struct vdfs4_sb_info *sbi)
{
	struct vdfs4_base_table *base_table;

	base_table = calloc(1, sizeof(*base_table));
	if (!base_table)
		return -ENOMEM;

	/* copy signature */
	memcpy((void *)&base_table->descriptor.signature,
			VDFS4_SNAPSHOT_BASE_TABLE,
			sizeof(VDFS4_SNAPSHOT_BASE_TABLE) - 1);
	sbi->snapshot.snapshot_subsystem.subsystem_name = "SNAPSHOT";
	sbi->snapshot.snapshot_subsystem.buffer = (char *)base_table;
	sbi->snapshot.snapshot_subsystem.buffer_size = sizeof(*base_table);
	return 0;
}

void destroy_snapshot(struct vdfs4_sb_info *sbi)
{

	free(sbi->snapshot.snapshot_subsystem.buffer);
}

int init_hashtable(struct vdfs4_sb_info *sbi)
{
	struct vdfs4_meta_hashtable *meta_hashtable;

	meta_hashtable = calloc(1, sizeof(*meta_hashtable));
	if (!meta_hashtable)
		return -ENOMEM;

	/* copy signature */
	memcpy((void *)&meta_hashtable->signature,
	       VDFS4_META_HASHTABLE,
	       sizeof(VDFS4_META_HASHTABLE) - 1);
	sbi->meta_hashtable.subsystem.subsystem_name = "HASHTABLE";
	sbi->meta_hashtable.subsystem.buffer = (char *)meta_hashtable;
	sbi->meta_hashtable.subsystem.buffer_size = sizeof(*meta_hashtable);
	return 0;
}

void destroy_hashtable(struct vdfs4_sb_info *sbi)
{
	free(sbi->meta_hashtable.subsystem.buffer);
}
