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

#include <assert.h>
#include <string.h>
#include "../include/vdfs_tools.h"

/** return values for validate crc function */
#define UTIL_INVALID_MAGIC		1
#define UTIL_INVALID_CRC		2

void util_add_btree_size(struct vdfs4_sb_info *sbi,
		struct vdfs_tools_btree_info *tree)
{
	int block_count = get_bnodes_count(tree) *
		(sbi->super_page_size / sbi->block_size);

	block_count += ((block_count + (sbi->super_page_size /
		sbi->block_size) - 1) & (~((sbi->super_page_size /
		sbi->block_size) - 1))) - block_count;

	sbi->snapshot.metadata_size += block_count;
}

/**
 * @brief				Update the buffer with magic and crc
 *					numbers. the magic will be placed in
 *					first bytes, the crc will be placed
 *					in last 4 bytes.
 * @param [in]	buff			Buffer to update.
 * @param [in]	buff_size		Size of the buffer
 * @param [in]	magic			Magic word for update. If it's null
 *					the function will update crc only.
 * @param [in]	magic_len		Length of the magic word in bytes
  */
int util_update_crc(char *buff, int buff_size, const char *magic,
		int magic_len)
{
	int crc = 0;
	assert(magic_len < buff_size);
	/* copy magic to begin of the buffer */
	if (magic)
		memcpy(buff, magic, magic_len);
	/* set crc to the end of the buffer */
	crc = vdfs4_crc32((unsigned char *)buff + magic_len,
			buff_size - (CRC32_SIZE + magic_len));
	memcpy(buff + (buff_size-CRC32_SIZE), &crc, CRC32_SIZE);
	return crc;
}

/**
 * @brief			Validate the buffer crc
 *				the crc should be in last 4 bytes
 * @param [in]	buff		Buffer to validate.
 * @param [in]	buff_size	Size of the buffer
 * @param [in]	skip		Do not take into account first N bites.
 *				Sometimes there a magic in the begining of
 *				the buffer.
 *				And for some unknown reason, this magic is not
 *				accounted during crc calcluation.
 *
 * @return			0 - if crc and magic are valid
 *				1 - if crc is invalid
 */
int util_validate_crc(char *buff, int buff_size, int skip)
{
	int ret_val = 0;
	int crc = 0;
	int len;
	unsigned char *crc_protected;
	void *crc_ptr;

	crc_protected = (unsigned char *)buff + skip;
	len = buff_size - (CRC32_SIZE + skip);

	/*hexDump("Data for crc", (unsigned char *)buff, 32);*/

	crc = vdfs4_crc32(crc_protected, len);

	crc_ptr = buff + (buff_size - CRC32_SIZE);
	if (memcmp(crc_ptr, &crc, CRC32_SIZE) != 0)
		ret_val |= UTIL_INVALID_CRC;

	return ret_val;
}

/**
 * @brief		Test requested bit.
 * @param [in]	buffer	Bitmap buffer.
 * @param [in]	addr	Bit to test.
 * @return	return bit value.
 */
int util_test_bit(char *buffer, u_int64_t addr)
{
	return buffer[(addr >> 3)] & (1 << addr % CHAR_BIT);
}

/**
 * @brief		Set requested bits range in buffer.
 * @param [in]	addr	Offset in bits of first bit to be set.
 * @param [in]	count	Count of bits to be set.
 * @return	void.
 */
void util_set_bits(char *buffer, u_int64_t addr, u_int32_t count)
{
	for (; count; count--) {
		buffer[(addr >> 3)] |=
			1 << (addr % 8);
		addr++;
	}
}

/**
 * @brief		Clear requested bits range in buffer.
 * @param [in]	addr	Offset in bits of first bit to be set.
 * @param [in]	count	Count of bits to be set.
 * @return	void.
 */
void util_clear_bits(char *buffer, u_int64_t addr, u_int32_t count)
{
	for (; count; count--) {
		buffer[(addr >> 3)] &=
			~(1 << (addr % 8));
		addr++;
	}
}

/**
 * @brief		Test requested bit in signed bitmap.
 * @param [in]	buff	buffer which contains bit map
 * @param [in]	buff_size	size of the buffer
 * @param [in]	addr	Offset in bits of first bit to be set.
 * @return	return bit value in success, negative if fails.
 */
int util_sign_test_bit(char *buff, int buff_size, u_int64_t addr,
		int block_size, int magic_len, int crc_size)
{
	int64_t int_addr = -ENOSPC; /* address inside block */
	int64_t start_blck = 0;
	char *buffer = NULL;
	int64_t buffer_range = buff_size - crc_size;
	int64_t requested_block = 0;

	/* data block size in bits */
	const int datablock_size = (block_size - (magic_len + crc_size)) << 3;

	/* divide the bitmap to blocks and update & sign each block*/
	start_blck = (addr >> 3) / (block_size - (magic_len + crc_size));

	int_addr = addr  % (datablock_size);

	/* calc address of current block */
	requested_block = (start_blck * block_size);
	if ((requested_block + magic_len + ((int_addr) >> 3)) > buffer_range)
		return -EINVAL;
	/* set bits */
	buffer = buff + requested_block;
	return util_test_bit(buffer + magic_len, int_addr);
}

/**
 * @brief		Set requested bits range in signed bitmap.
 * @param [in]	buff	buffer which contains bit map
 * @param [in]	buff_size	size of the buffer
 * @param [in]	addr	Offset in bits of first bit to be set.
 * @param [in]	count	Count of bits to be set.
 * @return	return 0 on success, negative on fail.
 */
int util_sign_set_bits(char *buff, int buff_size, u_int64_t addr,
		u_int32_t count, int block_size, int magic_len, int crc_size)
{
	int64_t int_addr = -ENOSPC; /* address inside block */
	int64_t start_blck = 0;
	int64_t cur_blck = 0;
	int64_t end_blck = 0;
	u_int32_t length = 0;
	char *buffer = NULL;
	int64_t buffer_range = buff_size - crc_size;
	int64_t requested_block = 0;
	/* data block size in bits */
	const int datablock_size = (block_size - (magic_len\
			+ crc_size))<<3;

	if (!count)
		return 0;

	/* divide the bitmap to blocks and update & sign each block*/
	start_blck = (addr >> 3) / (block_size -\
			(magic_len + crc_size));
	end_blck = ((addr + count - 1) >> 3) / (block_size -\
			(magic_len + crc_size));

	for (cur_blck = start_blck; cur_blck <= end_blck; cur_blck++) {
		/* if it first block */
		if (cur_blck == start_blck)
			int_addr = addr  % (datablock_size);
		else
			int_addr = 0;
			length = (datablock_size - int_addr);
		if (count < length)
			length = count;
		else
			count -= length;
		/* calc address of current block */
		requested_block = (cur_blck * block_size);
		if ((requested_block + magic_len +
			((int_addr + length) >> 3)) > buffer_range)
			return -EINVAL;

		buffer = buff + (cur_blck * block_size);
		/* set bits */
		util_set_bits(buffer + magic_len,
				int_addr, length);
	}
	return 0;
}

/**
 * @brief		Clear requested bits range in signed bitmap.
 * @param [in]	buff	buffer which contains bit map
 * @param [in]	buff_size	size of the buffer
 * @param [in]	addr	Offset in bits of first bit to be set.
 * @param [in]	count	Count of bits to be set.
 * @return	return 0 on success, negative on fail.
 */
int util_sign_clear_bits(char *buff, int buff_size, u_int64_t addr,
		u_int32_t count, int block_size, int magic_len, int crc_size)
{
	int64_t int_addr = -ENOSPC; /* address inside block */
	int64_t start_blck = 0;
	int64_t cur_blck = 0;
	int64_t end_blck = 0;
	u_int32_t length = 0;
	char *buffer = NULL;
	int64_t buffer_range = buff_size - crc_size;
	int64_t requested_block = 0;
	/* data block size in bits */
	const int datablock_size = (block_size - (magic_len\
			+ crc_size))<<3;

	if (!count)
		return 0;

	/* divide the bitmap to blocks and update & sign each block*/
	start_blck = (addr >> 3) / (block_size -\
			(magic_len + crc_size));
	end_blck = ((addr + count - 1) >> 3) / (block_size -\
			(magic_len + crc_size));

	for (cur_blck = start_blck; cur_blck <= end_blck; cur_blck++) {
		/* if it first block */
		if (cur_blck == start_blck)
			int_addr = addr  % (datablock_size);
		else
			int_addr = 0;
			length = (datablock_size - int_addr);
		if (count < length)
			length = count;
		else
			count -= length;
		/* calc address of current block */
		requested_block = (cur_blck * block_size);
		if ((requested_block + magic_len +
			((int_addr + length) >> 3)) > buffer_range)
			return -EINVAL;
		/* clear bits */
		buffer = buff + (cur_blck * block_size);
		util_clear_bits(buffer + magic_len,
				int_addr, length);
	}
	return 0;
}


unsigned int slog(int block)
{
	int i;
	if (block < (1 << VDFS4_MIN_LOG_CHUNK_SIZE)) {
		log_warning("Too small chunk size - %d."
				" Minimum chunk size was set"
				" - %d", block, (1 << VDFS4_MIN_LOG_CHUNK_SIZE));
		return VDFS4_MIN_LOG_CHUNK_SIZE;
	} else if (block > (1 << VDFS4_MAX_LOG_CHUNK_SIZE)) {
		log_warning("Too big chunk size - %d."
				" Maximum chunk size was set"
				" - %d", block, (1 << VDFS4_MAX_LOG_CHUNK_SIZE));
		return VDFS4_MAX_LOG_CHUNK_SIZE;
	}
	for (i = VDFS4_MAX_LOG_CHUNK_SIZE; i >= VDFS4_MIN_LOG_CHUNK_SIZE; i--)
		if (block & (1 << i))
			return i;
	return 0;
}
