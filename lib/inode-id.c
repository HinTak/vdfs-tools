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
#include "../include/logger.h"

/* real data size of block. it's block size without signature and crc number */
#define GET_SIGNED_BLOCK_SIZE(x)	((x->block_size) -\
		(INODE_BITMAP_MAGIC_LEN + CRC32_SIZE))



/**
 * @brief Function sets bit by number in the bitmap
 * @param [out] bitmap Pointer to the bitmap
 * @param [in] inode_num Number of inode to set in bitmap
 * @return void
 */
void set_inode_bit(char *bitmap, u_int64_t inode_num)
{
	unsigned int byte;
	char bit;

	byte = inode_num / 8;	/* get byte number in array */
	bit = inode_num % 8;
	bitmap[byte] |= 1 << bit;
}

/**
 * @brief Function counts size and allocates memory for inodes bitmap
 * @param [in] sbi Superblock runtime structure
 * @return 0 on success, error code otherwise
 */
int init_inode_id_alloc(struct vdfs4_sb_info *sbi)
{
	int ret = 0;
	log_activity("Create inodes bitmap");
	sbi->inode_bitmap.sub_system_id = VDFS4_FREE_INODE_BITMAP_INO;
	sbi->inode_bitmap.subsystem_name = "INODE BITMAP";
	sbi->last_allocated_inode_number = VDFS4_1ST_FILE_INO - 1;
	return ret;
}

/**
 * @brief Function get new id - find free bit in inode_bitmap  for VDFS4 subsystem
 * @param [in] sbi			Superblock runtime structure
 * @param [in] count			count inodes to allocate
  * @return 0 on unsuccess, or number of allocated inode
 */
u_int64_t get_free_inode_n(struct vdfs4_sb_info *sbi, int count)
{
	u_int64_t result = sbi->last_allocated_inode_number + 1;
	sbi->last_allocated_inode_number += count;
	return result;
}

int test_and_clear_inode_n(struct vdfs4_sb_info *sbi, __u64 ino_n)
{
	int ret = 0;
	ret = util_sign_test_bit(sbi->inode_bitmap.buffer,
			sbi->inode_bitmap.buffer_size, ino_n,
			sbi->block_size, INODE_BITMAP_MAGIC_LEN, CRC32_SIZE);
	util_sign_clear_bits(sbi->inode_bitmap.buffer,
			sbi->inode_bitmap.buffer_size, ino_n, 1,
			sbi->block_size, INODE_BITMAP_MAGIC_LEN, CRC32_SIZE);
	sbi->last_allocated_inode_number = ino_n - 1;
	return ret ;
}


/**
 * @brief Free space allocated for free inodes bitmap
 * @param [in] sbi Superblock runtime structure
 * @return void
 */
void destroy_inode_id_alloc(struct vdfs4_sb_info *sbi)
{
	free(sbi->inode_bitmap.buffer);
}

void inode_bitmap_count_crc(struct vdfs4_sb_info *sbi)
{
	char *block_ptr = NULL;
	int block_count = 0, i;
	u64 version = VERSION;
	char magic[INODE_BITMAP_MAGIC_LEN];
	memcpy(magic, INODE_BITMAP_MAGIC, sizeof(INODE_BITMAP_MAGIC)
			- 1);
	memcpy((magic + sizeof(INODE_BITMAP_MAGIC)
			- 1), &version, sizeof(u64));
	/* fill signature and crc for each block */
	block_count = sbi->inode_bitmap.buffer_size / sbi->block_size;
	for (i = 0; i < block_count; i++) {
		block_ptr = sbi->inode_bitmap.buffer
				+ i * sbi->block_size;

		util_update_crc(block_ptr, sbi->block_size,
			magic, INODE_BITMAP_MAGIC_LEN);
	}
}

static u_int64_t get_inode_bitmap_size(struct vdfs4_sb_info *sbi)
{
	u_int64_t bitmap_bytes_per_block = sbi->block_size - INODE_BITMAP_MAGIC_LEN - CRC32_SIZE;
	u_int64_t bitmap_bytes_needed = ALIGN(sbi->last_allocated_inode_number + 1, 8) >> 3;
	u_int64_t blocks_needed = bitmap_bytes_needed / bitmap_bytes_per_block;
	if(bitmap_bytes_needed % bitmap_bytes_per_block)
		blocks_needed++;

	return block_to_byte(blocks_needed, (u_int32_t)sbi->block_size);
}


int fill_inode_bitmap(struct vdfs4_sb_info *sbi)
{
	int ret = 0;
	u_int64_t inode_bitmap_size =
			get_inode_bitmap_size(sbi);
	if (IS_FLAG_SET(sbi->service_flags, READ_ONLY_IMAGE))
		return ret;
	sbi->inode_bitmap.buffer = malloc(inode_bitmap_size);
	if (!sbi->inode_bitmap.buffer)
		return -ENOMEM;
	sbi->inode_bitmap.buffer_size = inode_bitmap_size;
	memset(sbi->inode_bitmap.buffer, 0, inode_bitmap_size);
	sbi->snapshot.metadata_size += byte_to_block(
			inode_bitmap_size, sbi->block_size);
	ret = util_sign_set_bits(sbi->inode_bitmap.buffer, inode_bitmap_size,
			0, sbi->last_allocated_inode_number + 1,
			sbi->block_size, INODE_BITMAP_MAGIC_LEN,
			CRC32_SIZE);
	if (ret)
		return ret;
	inode_bitmap_count_crc(sbi);
	return ret;
}
