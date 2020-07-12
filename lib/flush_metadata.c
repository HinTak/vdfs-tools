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

#include <vdfs_tools.h>
#include <vdfs4_layout.h>
#include <vdfs4.h>
#include <time.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
/**
 * @brief Function flushes subsystem on volume
 * @param [in] sbi Superblock runtime structure
 * @return 0 on success, error code otherwise
 */


int flush_debug_area(struct vdfs4_sb_info *sbi)
{
	int ret = 0;
	char *buf = malloc(sbi->block_size * sbi->debug_area.block_count);
	if (!buf)
		return -ENOMEM;
	memset(buf, 0, sbi->block_size * sbi->debug_area.block_count);
	ret = vdfs4_write_blocks(sbi, sbi->debug_area.first_block,
				buf, sbi->debug_area.block_count);
	free(buf);
	if (ret)
		log_error("Can't put debug area on disk");
	return ret;
}
#define VDFS4_GET_IBLOCK(mblock, first_mblock)	(mblock + first_mblock)
int flush_subsystem(struct vdfs4_sb_info *sbi,
		struct vdfs4_subsystem_data *subsystem)
{
	int ret = 0;
	__u64 start_block;
	struct vdfs4_base_table_record *table;
	__le64 last_iblock;
	__u32 blocks_count;
	struct vdfs4_base_table *base_table;

	log_activity("Flush : %s", subsystem->subsystem_name);
	if (subsystem->sub_system_id == 0) {
		start_block = sbi->snapshot.tables_extent.first_block;
		blocks_count = sbi->snapshot.tables_extent.block_count;
		goto write;
	} else if (subsystem->sub_system_id > VDFS4_LSFILE) {
		start_block = subsystem->fork.extents[0].first_block;
		blocks_count = subsystem->fork.extents[0].block_count;
		goto write;
	}
	base_table = (struct vdfs4_base_table *)
			sbi->snapshot.snapshot_subsystem.buffer;
	table = (struct vdfs4_base_table_record *)(VDFS4_GET_TABLE(base_table,
			subsystem->sub_system_id));
	last_iblock = le64_to_cpu(VDFS4_GET_LAST_IBLOCK(base_table,
			subsystem->sub_system_id));

	blocks_count = (last_iblock + 1) * get_iblock_size(sbi,
			subsystem->sub_system_id);
	start_block = le64_to_cpu(VDFS4_GET_IBLOCK(table->meta_iblock,
			sbi->snapshot.metadata_extent[0].first_block));
	assert(start_block != 0);
write:

	ret = vdfs4_write_blocks(sbi, (u_int64_t)start_block,
			subsystem->buffer, blocks_count);
	if (ret)
		log_error("Can't copy %s to disk(ret:%d)",
			  subsystem->subsystem_name, ret);
	else
		log_activity("Successed to flush %s",
			     subsystem->subsystem_name);
	return ret;
}
/**
 * @brief Function flushes subsystem tree on volume
 * @param [in] sbi Superblock runtime structure
 * @return 0 on success, error code otherwise
 */
int flush_subsystem_tree(struct vdfs4_sb_info *sbi,
		struct vdfs_tools_btree_info *tree)
{
	int ret = 0, crc;
	u64 i;
	__u64 version = VERSION;
	__u64 bnodes_count = get_bnodes_count(tree);
	struct vdfs4_base_table *base_table = (struct vdfs4_base_table *)
			sbi->snapshot.snapshot_subsystem.buffer;
	/** FIXME check subsystem fragmentation */
	struct vdfs4_base_table_record *table = (VDFS4_GET_TABLE(
			base_table, tree->tree.sub_system_id));
	struct vdfs4_meta_hashtable *hashtable = (struct vdfs4_meta_hashtable *)
		sbi->meta_hashtable.subsystem.buffer;
	__le32 *hashtable_crc = (__le32 *)
		((char*)hashtable + sizeof(struct vdfs4_meta_hashtable));
	u64 start = 0;

	log_activity("Flush tree : %s", tree->tree.subsystem_name);
	for (i = 0; i < bnodes_count; i++) {
		start = VDFS4_GET_IBLOCK(table[i].meta_iblock,
				sbi->snapshot.metadata_extent[0].first_block)
				+ sbi->vdfs4_start_block;
		memcpy(((char *)tree->bnode_array[i]->data) + 4,
		       &version, VERSION_SIZE);
		crc = util_update_crc(tree->bnode_array[i]->data,
				get_bnode_size(sbi), NULL, 0);
		/* fill hash table crc */
		*(__le32 *)((char *)hashtable_crc + table[i].meta_iblock) = crc;
		log_info("[%d:%x]", table[i].meta_iblock, crc);
		ret = vdfs4_write_blocks(sbi, start, tree->bnode_array[i]->data,
					byte_to_block(get_bnode_size(sbi),
							sbi->block_size));
		if (ret) {
			log_error("Can't copy %s to disk(ret:%d)",
				  tree->tree.subsystem_name, ret);
			break;
		}
	}
	if (!ret)
		log_activity("Successed to flush %s",
			     tree->tree.subsystem_name);
	return ret;
}
/******************************************************************************/
static int fill_superblock(struct vdfs4_sb_info *sbi)
{
	int real_sb_size;
	int ret = 0;
	assert(sizeof(struct vdfs4_super_block) == 512);

	memset(&sbi->sb, 0, sizeof(struct vdfs4_super_block));
	set_magic(sbi->sb.signature, VDFS4_SB_SIGNATURE);
	memcpy(sbi->sb.layout_version, VDFS4_LAYOUT_VERSION,
		strlen(VDFS4_LAYOUT_VERSION));

	sbi->sb.log_block_size = log2_32(sbi->block_size);
	sbi->sb.log_super_page_size = log2_32(sbi->super_page_size);
	sbi->sb.log_erase_block_size = log2_32(sbi->erase_block_size);

	if (IS_FLAG_SET(sbi->service_flags, READ_ONLY_IMAGE))
		sbi->sb.read_only = 1;

	if (IS_FLAG_SET(sbi->service_flags, READ_ONLY_IMAGE)) {
		sbi->sb.maximum_blocks_count =
			cpu_to_le64(sbi->image_file_size / sbi->block_size);
	} else {
		sbi->sb.maximum_blocks_count =
			cpu_to_le64(sbi->max_volume_size / sbi->block_size);
	}

	memcpy(&sbi->sb.creation_timestamp, &sbi->timestamp,
				sizeof(sbi->sb.creation_timestamp));

	memcpy(sbi->sb.volume_uuid, sbi->volume_uuid,
			sizeof(sbi->sb.volume_uuid));

	memcpy(sbi->sb.volume_name, sbi->volume_name,
			sizeof(sbi->volume_name));

	set_magic(sbi->sb.mkfs_version, VDFS_TOOLS_VERSION);

	sbi->sb.case_insensitive =
			IS_FLAG_SET(sbi->service_flags, CASE_INSENSITIVE);

	/* +2 = +1 - root, +1 - last_allocated */
	sbi->sb.image_inode_count =
			cpu_to_le64(sbi->last_allocated_inode_number + 2);

	/* fill exsb crc in super block */
	sbi->sb.exsb_checksum = sbi->esb.checksum;
	/* fill basetable crc in super block */
	sbi->sb.basetable_checksum = sbi->snapshot.checksum;
	/* fill hashtable crc in super block */
	sbi->sb.meta_hashtable_checksum = sbi->meta_hashtable.checksum;

	/* encryption flags */
	if (IS_FLAG_SET(sbi->service_flags, ENCRYPT_EXEC) ||
		IS_FLAG_SET(sbi->service_flags, ENCRYPT_ALL)) {
		SET_FLAG(sbi->sb.encryption_flags, VDFS4_VOLUME_ENCRYPTED);
	}
	sbi->sb.sign_type = sbi->sign_type;

	/*SB signing*/
	if (sbi->rsa_key) {
		log_activity("Superblock signing");
		if (sbi->hash_alg == SHA256)
			sbi->sb.hash_type = VDFS4_HASH_SHA256;
		else if (sbi->hash_alg == SHA1)
			sbi->sb.hash_type = VDFS4_HASH_SHA1;
		else if (sbi->hash_alg == MD5)
			sbi->sb.hash_type = VDFS4_HASH_MD5;
		real_sb_size = sizeof(sbi->sb) - get_sign_length(sbi->rsa_key) -
			sizeof(sbi->sb.checksum);
		ret = sign_rsa((unsigned char *)&sbi->sb, real_sb_size,
			sbi->sb.sb_hash + VDFS4_MAX_CRYPTED_HASH_LEN -
			get_sign_length(sbi->rsa_key), sbi->rsa_key,
			sbi->hash_alg, sbi->hash_len);
		if (ret)
			log_error("RSA signing error");
	}
	sbi->sb.checksum = cpu_to_le32(vdfs4_crc32(&(sbi->sb), sizeof(sbi->sb)
			- sizeof(sbi->sb.checksum)));

	return ret;

}

/******************************************************************************/
void fill_layout_fork(struct vdfs4_fork *fork, struct vdfs4_fork_info *fork_info,
		u_int32_t block_size)
{
	unsigned int count;

	memset((void *)fork, 0, sizeof(*fork));

	fork->total_blocks_count = cpu_to_le32(fork_info->total_block_count);
	fork->size_in_bytes = cpu_to_le64
			(block_to_byte(fork_info->total_block_count,
					block_size));

	for (count = 0; count < fork_info->used_extents; count++)
		init_iextent(&fork->extents[count],
				fork_info->extents[count].first_block,
				fork_info->extents[count].block_count,
				fork_info->extents[count].iblock);
}

static void fill_ext_superblock(struct vdfs4_sb_info *sbi)
{
	struct snapshot_info *snapshot = &sbi->snapshot;
	__u32 i;
	assert(sizeof(sbi->esb) <= VDFS4_EXSB_LEN);
	assert(sizeof(struct vdfs4_extended_super_block) == 512 * 5);


	memset(&sbi->esb, 0, sizeof(struct vdfs4_extended_super_block));
	/* Copy-on-Write metadata updating algorithm */
	/* fill extended superblock */

	for (i = 0; i < sbi->snapshot.snapshot_subsystem.fork.used_extents + 1;
			i++) {
		sbi->esb.meta[i].begin =
			cpu_to_le64(snapshot->metadata_extent[i].first_block);
		sbi->esb.meta[i].length =
			cpu_to_le32(snapshot->metadata_extent[i].block_count);
		sbi->esb.meta_tbc +=
			cpu_to_le32(snapshot->metadata_extent[i].block_count);
	}

	sbi->esb.tables.begin =
		cpu_to_le64(snapshot->tables_extent.first_block);
	sbi->esb.tables.length =
		cpu_to_le32(snapshot->tables_extent.block_count);

	/*sbi->esb.tables[0].begin =
		cpu_to_le64(snapshot->tables_extent.first_block);
	sbi->esb.tables[0].length =
		cpu_to_le32(snapshot->tables_extent.block_count);
	sbi->esb.tables_tbc =
		cpu_to_le32(snapshot->tables_extent.block_count);*/
	sbi->esb.volume_body.length = cpu_to_le32(get_volume_body_length(sbi));

	/* set volume size */
	if (IS_FLAG_SET(sbi->service_flags, READ_ONLY_IMAGE)) {
		sbi->esb.volume_blocks_count =
			cpu_to_le64(sbi->image_file_size / sbi->block_size);
	} else {
		sbi->esb.volume_blocks_count =
			cpu_to_le64(sbi->min_volume_size / sbi->block_size);
	}

	sbi->esb.files_count = cpu_to_le64(sbi->files_count);
	sbi->esb.folders_count = cpu_to_le64(sbi->folders_count);
	sbi->esb.crc = CRC_ENABLED;

	/* fill debug area extent: fixed place 1,2,3,4 blocks */
	sbi->esb.debug_area.begin = cpu_to_le64(sbi->debug_area.first_block);
	sbi->esb.debug_area.length = cpu_to_le32(sbi->debug_area.block_count);

	/* initial sync counter */
	sbi->esb.sync_counter = cpu_to_le32(1);

	/* fill HASHTABLE extent */
	sbi->esb.meta_hashtable_area.begin =
		sbi->meta_hashtable.subsystem.fork.extents[0].first_block;
	sbi->esb.meta_hashtable_area.length =
		sbi->meta_hashtable.subsystem.fork.extents[0].block_count;

	/* calculate extended superblock checksum */
	sbi->esb.checksum = cpu_to_le32(vdfs4_crc32(&sbi->esb, sizeof(sbi->esb) -
			sizeof(sbi->esb.checksum)));
}

int prepare_superblocks(struct vdfs4_sb_info *sbi)
{
	int ret;

	ret = get_image_size(sbi, &sbi->image_file_size);
	if (ret) {
		log_error("get image file size failed");
		return ret;
	}

	fill_ext_superblock(sbi);
	return fill_superblock(sbi);
}

int clean_superblocks_area(struct vdfs4_sb_info *sbi)
{
	int write_size = (VDFS4_RESERVED_AREA_LENGTH + SB_SIZE +
			VDFS4_EXSB_LEN) * 2;
	__u8 write_buffer[write_size];
	__u8 superblock[write_size];
	int ret = 0;

	memset(write_buffer, 0, write_size);
	if (!IS_FLAG_SET(sbi->service_flags, IMAGE)) {
		ret = vdfs4_read_blocks(sbi, 0, superblock, 1);
		if (ret)
			return ret;
		if (!memcmp(((struct vdfs4_layout_sb *)superblock)->_sb2.signature,
				VDFS4_SB_SIGNATURE_REFORMATTED,
			strlen(VDFS4_SB_SIGNATURE_REFORMATTED))) {
			sbi->is_superblock_reformatted = 1;
			memcpy((&((struct vdfs4_layout_sb *)write_buffer)->_sb2),
				&(((struct vdfs4_layout_sb *)superblock)->_sb2),
				sizeof(struct vdfs4_super_block));
			memcpy(&sbi->sb_format_history,
				&((struct vdfs4_layout_sb *)superblock)->_sb2,
				sizeof(struct vdfs4_super_block));
			log_info("Volume was reformatted. Mkfs will save"
					" reformat history");
		}
	}

	ret = vdfs4_write_blocks(sbi, 0 + sbi->vdfs4_start_block, &write_buffer,
		byte_to_block(write_size, sbi->block_size));

	sync();

	return ret;
}


static void copy_cmd_line(int argc, char *argv[], char *buffer)
{
	size_t length;
	struct vdfs4_volume_begins *cmd_block =
			(struct vdfs4_volume_begins *)buffer;
	time_t t;
	struct tm lt;
	char image_info_buf[32]={0,};
	if (argc > 2)
		length = (size_t)((argv[argc - 2] - argv[0]) +
			strnlen(argv[argc - 2], IMAGE_CMD_LENGTH - 1));
	else
		length = (size_t)((argv[argc - 1] - argv[0]) +
				strnlen(argv[argc - 1], IMAGE_CMD_LENGTH - 1));

	//Store cmd line
	if (length > IMAGE_CMD_LENGTH)
		length = IMAGE_CMD_LENGTH;
	memcpy(cmd_block->command_line, *argv, length);

	//Store magic value
	set_magic(cmd_block->signature, VDFS4_SB_SIGNATURE);
	memcpy(cmd_block->layout_version, VDFS4_LAYOUT_VERSION,
		strlen(VDFS4_LAYOUT_VERSION));

	//Store time
	t = time(NULL);
	if (localtime_r(&t, &lt)) {
		snprintf( image_info_buf, sizeof(image_info_buf),
		  		"%04d.%02d.%02d-%02d:%02d", 
		  		lt.tm_year+1900, lt.tm_mon+1, lt.tm_mday,
				lt.tm_hour, lt.tm_min);
	} else {
		snprintf(image_info_buf, sizeof(image_info_buf),
			"Invalid time" );
	}
	memcpy( cmd_block->creation_time, image_info_buf, sizeof(cmd_block->creation_time));

	//Store user name
	if (getlogin_r( (char*)cmd_block->user_name, sizeof(cmd_block->user_name)))
		strncpy( (char*)cmd_block->user_name, "Anonymous", sizeof(cmd_block->user_name));

	cmd_block->checksum = cpu_to_le32(vdfs4_crc32(cmd_block,
			sizeof(*cmd_block) - 4));
}

/**
 * @brief send discard cmd in blk device open case.
 * @param [in] sbi Superblock runtime structure
 * @return 0 on success, error code otherwise
 */
int discard_volume(struct vdfs4_sb_info *sbi)
{
	int ret = 0;
	unsigned long long range[2];
	struct stat stat_buf;

	ret = fstat(sbi->disk_op_image.file_id, &stat_buf);
	if (ret < 0) {
		log_error("failed to get file stat");
		return -1;
	}
	if (S_ISBLK(stat_buf.st_mode)) {
		/* send discard cmd */
		range[0] = 0;
		range[1] = sbi->max_volume_size;
		ret = ioctl(sbi->disk_op_image.file_id,
			    BLKDISCARD, &range);
		if (ret < 0 && errno == EOPNOTSUPP) {
			log_warning("this target doesn't support discard.\n");
			ret = 0;	//set to normal.
		} else if (ret < 0) {
			log_error("mkfs.vdfs failed discard(err:%d, ret:%d)", errno);
		}
	} else {
		/* do nothing */
	}
	return ret;
}

int flush_superblocks(struct vdfs4_sb_info *sbi, int argc, char *argv[])
{
	int write_size = VDFS4_RESERVED_AREA_LENGTH + SB_SIZE +
			VDFS4_EXSB_LEN;
	u8 write_buffer[write_size];
	int ret = 0;
	int i;

	memset(write_buffer, 0, write_size);

	/* the first 512 bytes of the vdfs4 volume contains 
	 * mkfs cmd line, creation time and user name */
	copy_cmd_line(argc, argv, (char *)write_buffer);

	/* filling vdfs4 reserved area of first sb with one copy of
	 * superblock, then writing superblock on it's normal place
	 * (1024 bytes shift) */
	for (i = 1; i < 3; i++)
		if (sbi->is_superblock_reformatted && i == 1)
			memcpy(write_buffer + sizeof(sbi->sb) * i,
					&sbi->sb_format_history,
					sizeof(struct vdfs4_super_block));
		else
			memcpy(write_buffer + sizeof(sbi->sb) * i, &sbi->sb,
				sizeof(sbi->sb));

	memcpy(write_buffer + 3 * SB_SIZE, &sbi->esb, sizeof(sbi->esb));

	log_activity("Copy superblocks");
	ret = vdfs4_write_blocks(sbi, 0 + sbi->vdfs4_start_block, write_buffer,
		byte_to_block(write_size, sbi->block_size));
	if (ret)
		return ret;
	ret = vdfs4_write_blocks(sbi, 1 + sbi->vdfs4_start_block, write_buffer,
		byte_to_block(write_size, sbi->block_size));

	return ret;
}



int allocate_fixed_areas(struct vdfs4_sb_info *sbi)
{
	int ret = 0;

	/* begin of a volume :						*/
	/* 0    1    2    3      8    9    10   11    16             32 */
	/* | SB | SB | SB | EXSB | SB | SB | SB | EXSB |  DEBUG AREA |  */

	/*
	 * first 4k - superblocks (superblock and extended superblock)
	 * second 4k - superblocks copy
	 * 8-16K Debug area
	 * */

	/* Mark unaligned areas at the begin and end of partition
	 * as used and change space manager data accordingly. */
	ret = allocate_space(sbi, 0, 1, NULL);
	if (ret) {/* First superblock */
		log_error("Can not get free space for first superblock");
		return ret;
	} else
		log_activity("First superblock allocated at block %lu",
			NULL);
	ret = allocate_space(sbi, 1, 1, NULL);
	if (ret) {
		log_error("Can not get free space for second"
				" superblock");
		return ret;	/* ... second */
	} else
		log_activity("Second superblock allocated at block %lu", 1);
	/*allocate space for debug area*/
	ret = allocate_space(sbi, sbi->debug_area.first_block,
			sbi->debug_area.block_count, NULL);
	if (ret)
		log_error("Can not get free space for debug area");

	return ret;
}

void generate_uuid(u_int8_t *uuid_array, u_int32_t uuid_length)
{
	u_int32_t i;
	unsigned int rand_32;
	u_int8_t rand_char;
	unsigned int seed;
	seed = time(NULL);

	for (i = 0; i < uuid_length; i++) {
		do {
			rand_32 = rand_r(&seed);
			/* small digits of rand() is not truly random,     */
			/* so get big one                                    */
			rand_char = (u_int8_t)(rand_32 >> 24);
		} while (!isalpha(rand_char));

		uuid_array[i] = rand_char;
	}
}
