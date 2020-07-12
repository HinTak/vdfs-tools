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

#include "mkfs.h"
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
#include <zlib.h>
#include <signal.h>
#include <crypto_lock.h>
#include <execinfo.h>

unsigned int vdfs4_debug_mask = 0
		/*+ VDFS4_DBG_INO*/
		/*+ VDFS4_DBG_FSM*/
		/*+ VDFS4_DBG_SNAPSHOT*/
		/*+ VDFS4_DBG_TRANSACTION*/
		+ VDFS4_DBG_BTREE
		+ VDFS4_DBG_TMP
		;

const unsigned int vdfs_tools_mode = 0
		/*+ VDFS4_TOOLS_MULTITHREAD*/
		+ VDFS4_TOOLS_GET_BNODE_FROM_MEM
		;

void clear_data_range_list(struct list_head *data_range_list)
{
	struct list_head *pos, *q;
	list_for_each_safe(pos, q, data_range_list) {
		struct data_range *dr =
			list_entry(pos, struct data_range, list);
		list_del(pos);
		free(dr);
	}
}

__u64 find_file_duplicate(struct vdfs4_sb_info *sbi, char *path)
{
	int fd;
	__u64 ret;
	struct stat st;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		log_error("cannot open %s", path);
		return 0;
	}
	if (fstat(fd, &st)) {
		log_error("cannot stat %s", path);
		close(fd);
		return 0;
	}
	ret = find_data_duplicate(&sbi->data_ranges,
			fd, sbi->disk_op_image.file_id, 0, st.st_size);
	close(fd);
	return ret;
}

/*
int copy_tiny_file(struct vdfs4_sb_info *sb_info UNUSED,
		const char *src_filename,
		struct vdfs4_catalog_file_record *rec)
{
	char *buf;
	int file, read_real, ret = 0;
	struct stat stat_info;
	memset(&stat_info, 0, sizeof(stat_info));
	ret = lstat(src_filename, &stat_info);
	if (ret < 0) {
		ret = errno;
		log_error("%s %s", "Can't get stat info of ", src_filename);
		return ret;
	}
	assert(stat_info.st_size <= (__off_t)(TINY_DATA_SIZE));
	buf = malloc(TINY_DATA_SIZE);
	if (!buf) {
		log_info("Mkfs can't allocate enough memory");
		return errno;
	}

	memset(buf, 0, TINY_DATA_SIZE);
	file = open(src_filename, O_RDONLY);
	if (file < 0)
		goto exit;
	read_real = read(file, buf, stat_info.st_size);
	close(file);
	if (read_real == -1) {
		log_warning("%s %s", "Can't read file", src_filename);
		ret = errno;
		goto exit;
	}
	memcpy(rec->tiny.data, buf, TINY_DATA_SIZE);
exit:
	free(buf);
	return ret;
}
*/
int insert_hlinks_data(struct vdfs4_sb_info *sbi, u64 *file_offset_abs)
{
	struct hlink_list_item *list;
	int ret = 0;
	u64 begin = 0, length = 0;
	struct vdfs4_cattree_record *record = NULL;
	struct vdfs4_catalog_file_record *file_rec;
	u64 file_offset_abs_new = *file_offset_abs;
	list = sbi->hlinks_list.next;
	if (list != 0)
		log_info("Copy hardlinks");
	while (list != NULL) {
		record = vdfs4_cattree_find(&sbi->cattree.vdfs4_btree,
				list->new_ino_n, NULL, 0, VDFS4_BNODE_MODE_RW);
		if (IS_ERR(record))
			return -ENOMEM;

		file_rec = record->val;
		file_rec->common.flags &= ~(1 << VDFS4_HLINK_TUNE_TRIED);

		if (IS_FLAG_SET(file_rec->common.flags,
				VDFS4_COMPRESSED_FILE))
			goto next;

		if (S_ISREG(le16_to_cpu(file_rec->common.file_mode)) &&
		    file_rec->data_fork.size_in_bytes &&
		    IS_FLAG_SET(sbi->service_flags, READ_ONLY_IMAGE)) {
			length = le64_to_cpu(file_rec->data_fork.size_in_bytes);
			begin = find_file_duplicate(sbi, list->name);
			if (begin) {
				fork_init(&file_rec->data_fork, begin,
						length, sbi->block_size);
				goto next;
			}
		}

/*		if (file_rec->common.flags & (1 << TINY_FILE)) {
			ret = copy_tiny_file(sbi, list->name, file_rec);
			if (ret)
				goto errors;
			goto next;
		}
*/

		if (file_offset_abs_new % sbi->block_size)
			file_offset_abs_new = block_to_byte
			(byte_to_block(file_offset_abs_new,
				sbi->block_size), sbi->block_size);
		*file_offset_abs = file_offset_abs_new;
		begin = file_offset_abs_new;

		ret = copy_file_to_image(sbi, list->name, &file_offset_abs_new);
		if (ret)
			goto errors;
		length = file_offset_abs_new - *file_offset_abs;

		fork_init(&file_rec->data_fork, begin, length, sbi->block_size);
		add_data_range(sbi, &sbi->data_ranges, begin, length);
		*file_offset_abs = file_offset_abs_new;
next:
		list = list->next;
		vdfs4_release_record((struct vdfs4_btree_gen_record *) record);
	}
	hl_list_free(sbi->hlinks_list.next);
	sbi->hlinks_list.next = NULL;
	return ret;
errors:
	vdfs4_release_record((struct vdfs4_btree_gen_record *) record);
	return ret;
}

int insert_hlinks_metadata(struct vdfs4_sb_info *sbi)
{
	int ret = 0;

	struct hlink_list_item *list;
	struct stat stat_info;
	__u64 obj_count = 0;


	list = sbi->hlinks_list.next;
	if (list != 0)
		log_info("Copy hardlinks");
	while (list != NULL) {
		ret = lstat(list->name, &stat_info);
		if (ret < 0) {
			log_error("%s %s", "Can't take stat info of",
					list->name);
			ret = errno;
			return ret;
		}

		stat_info.st_nlink = list->links;
		ret = insert_record(sbi, list->name, NULL, &stat_info,
				list->new_ino_n, list->new_ino_n,
				&obj_count);
		if (ret)
			break;

		list = list->next;
	}

	return ret;
}


/**
 * @brief Function fill image metadata for VDFS4 subsystem
 * @param [in] sbi Superblock runtime structure
 * @return 0 on success, error code otherwise
 */
int fill_image_metadata(struct vdfs4_sb_info *sbi)
{
	int ret = 0;
	char *root_rec_name = "root";
	int root_parent_id = 0;
	struct vdfs4_cattree_record *record;
	__u64 object_count = 0;

	if (sbi->root_path != NULL) {
		log_activity("Fill catalog tree from %s", sbi->root_path);
		ret = insert_metadata(sbi, sbi->root_path, VDFS4_ROOT_INO,
				&object_count);
		if (ret)
			return ret;

		record = vdfs4_cattree_find(&sbi->cattree.vdfs4_btree,
				root_parent_id,
				root_rec_name, strlen(root_rec_name),
				VDFS4_BNODE_MODE_RW);
		if (IS_ERR(record))
			return -ENOMEM;
		VDFS4_CATTREE_FOLDVAL(record)->total_items_count =
				cpu_to_le64(object_count);
		vdfs4_release_record((struct vdfs4_btree_gen_record *) record);
		ret = insert_hlinks_metadata(sbi);
		if (ret)
			return ret;
	}
	return ret;
};
/**
* @brief Function fill image data  for VDFS4 subsystem copy files from
* root_path to image file
* @param [in] sbi Superblock runtime structure
* @return 0 on success, error code otherwise
*/
int fill_image_data(struct vdfs4_sb_info *sbi)
{
	u64 file_offset = 0;
	int ret = 0;

	file_offset = get_metadata_size(sbi);
	if (sbi->metadata_size) {
		if (sbi->snapshot.metadata_size
				> sbi->metadata_size) {
			log_error("Metadata size is more than %lu",
				sbi->metadata_size);
			ret = -ENOSPC;
			return ret;
		} else {
			sbi->snapshot.preallocation_len +=
					sbi->metadata_size -
					sbi->snapshot.metadata_size;
			sbi->snapshot.metadata_size =
					sbi->metadata_size;
		}
	}

	if (sbi->root_path != NULL) {
		log_activity("Copy files data from %s", sbi->root_path);
		ret = insert_data(sbi, sbi->root_path, VDFS4_ROOT_INO,
				&file_offset);
		if (ret) {
			log_error("Error when insert data(ret:%d)", ret);
			return ret;
		}
		ret = insert_hlinks_data(sbi, &file_offset);
		if (ret) {
			log_error("Error when insert hlinks data(ret:%d)", ret);
			return ret;
		}
	}

	return ret;
}
/**
 * @brief Function insert_data  for VDFS4 subsystem copy files from
 * root_path to image file
 * @param [in] sbi Superblock runtime structure
 * @param [in] dir_path Path to root_directory to insert from
 * @param [in] parent_id ID of directory to insert data from it
 * @param [in] file_offset_abs	offset of data
 * @return 0 on success, error code otherwise
 */
int insert_data(struct vdfs4_sb_info *sbi, char *dir_path,
		__u64 parent_id, u64 *file_offset_abs)
{
	DIR *dir;
	u64 parent_id_new, file_offset_abs_new;
	u_int64_t begin, length;
	u8 record_type;
	int ret = 0;
	char *path = NULL;
	struct dirent *data;
	struct dirent entry;
	struct vdfs4_cattree_record *record = NULL;
	struct vdfs4_catalog_file_record *file_rec;
	if (!sbi->root_path) {
		ret = 0;
		return ret;
	}
	dir = opendir(dir_path);

	if (dir == NULL) {
		log_info("%s %s", "Can't open dir", dir_path);
		return errno;
	}
	file_offset_abs_new = *file_offset_abs;

	/*while ((data = readdir(dir)) != NULL) {*/
	ret = readdir_r(dir, &entry, &data);
	while (!ret && data) {
		if ((strcmp(data->d_name, ".") == 0) ||
				(strcmp(data->d_name, "..") == 0))
			/*continue;*/
			goto next;

		path = calloc(1, strlen(dir_path) + strlen(data->d_name) + 2);
		if (!path) {
			ret = -ENOMEM;
			goto exit;
		}

		strncat(path, dir_path, strlen(dir_path));
		strncat(path, "/", 1);
		strncat(path, data->d_name, strlen(data->d_name));

		record = vdfs4_cattree_find(&sbi->cattree.vdfs4_btree,
				parent_id, data->d_name, strlen(data->d_name),
				VDFS4_BNODE_MODE_RW);

		if (IS_ERR(record)) {
			log_error("Can't find record about object %s in"
					"catalog tree", path);
			ret = PTR_ERR(record);
			goto exit;
		}
		record_type = record->key->record_type;

		if (record_type == VDFS4_CATALOG_FOLDER_RECORD) {
			/* Device/Socket/Fifo */
			if (!S_ISDIR(le16_to_cpu(VDFS4_CATTREE_FOLDVAL(record)
							->file_mode)))
				goto loop_end;
			/*Folder*/
			parent_id_new = record->key->object_id;
			ret = insert_data(sbi, path, parent_id_new,
					&file_offset_abs_new);
			if (ret)
				goto errors;
			*file_offset_abs = file_offset_abs_new;
		} else if (record_type == VDFS4_CATALOG_FILE_RECORD) {
			/*File */

			file_rec = (struct vdfs4_catalog_file_record *)
					record->val;
			if (IS_FLAG_SET(file_rec->common.flags,
					VDFS4_COMPRESSED_FILE))
				/*Nothing to do if file is
				 *  compressed
				 * (file data was already copied)*/
				goto loop_end;

			if (S_ISREG(le16_to_cpu(file_rec->common.file_mode)) &&
			    file_rec->data_fork.size_in_bytes &&
			    IS_FLAG_SET(sbi->service_flags, READ_ONLY_IMAGE)) {
				length = le64_to_cpu(file_rec->data_fork.size_in_bytes);
				begin = find_file_duplicate(sbi, path);
				if (begin) {
					fork_init(&file_rec->data_fork, begin,
						  length, sbi->block_size);
					goto loop_end;
				}
			}

/*			if (file_rec->common.flags & (1 << TINY_FILE)) {
				ret = copy_tiny_file(sbi, path,
					file_rec);
				if (ret)
					goto errors;
				goto loop_end;
			}
*/


			if (file_offset_abs_new % sbi->block_size)
				file_offset_abs_new = block_to_byte
					(byte_to_block(file_offset_abs_new,
					sbi->block_size), sbi->block_size);
			*file_offset_abs = file_offset_abs_new;
			begin = file_offset_abs_new;
			ret = copy_file_to_image(sbi, path,
					&file_offset_abs_new);
			if (ret)
				goto errors;
			length = file_offset_abs_new - *file_offset_abs;

			fork_init(&file_rec->data_fork, begin, length,
					sbi->block_size);
			add_data_range(sbi, &sbi->data_ranges, begin, length);
			*file_offset_abs = file_offset_abs_new;
		} else if (record_type != VDFS4_CATALOG_HLINK_RECORD){
			ret = -EINVAL;
			goto errors;
		}
loop_end:
		vdfs4_release_record((struct vdfs4_btree_gen_record *) record);
		record = NULL;
		free(path);
		path = NULL;
next:
		ret = readdir_r(dir, &entry, &data);
	}

	goto exit;
errors:
	vdfs4_release_record((struct vdfs4_btree_gen_record *) record);
exit:
	free(path);
	closedir(dir);
	return ret;
}

/*****************************************************************************/
/**
 * @brief Function insert_record to cattree for VDFS4 subsystem
 * @param [in] sbi		Superblock runtime structure
 * @param [in] path		Full path to file or folder
 * @param [in] name		name of file
 * @param [in] record_type	Type of object to add in tree
 * @param [in] uuid		Id of current object
 * @param [in] parent_id	Id of parent directory
 * @return 0 on success, error code otherwise
 */
int insert_record(struct vdfs4_sb_info *sbi, char *path, char *name,
		struct stat *stat_info, int obj_id, int parent_id,
		__u64 *obj_count)
{

	int ret = 0;
	__u64 start = 0, length = 0;
	__u64 items = 0, links = 0;
	struct vdfs4_posix_permissions	permissions;
	struct vdfs4_timespec creation_time;
	struct vdfs4_timespec modification_time;
	struct vdfs4_timespec access_time;
	struct vdfs4_cattree_record *new_record;
	unsigned int record_type = VDFS4_CATALOG_FILE_RECORD;

	permissions.file_mode = cpu_to_le16(stat_info->st_mode);
	if (IS_FLAG_SET(sbi->service_flags, ALL_ROOT)) {
		permissions.gid = 0;
		permissions.uid = 0;
	} else {
		permissions.gid = cpu_to_le32(stat_info->st_gid);
		permissions.uid = cpu_to_le32(stat_info->st_uid);
	}
	creation_time = vdfs4_encode_time(stat_info->st_ctim);
	modification_time = vdfs4_encode_time(stat_info->st_mtim);
	access_time = vdfs4_encode_time(stat_info->st_atim);
	if (S_ISDIR(stat_info->st_mode)) {
		start = 0;
		length = 0;
		items = *obj_count;
		links = 1;
		record_type = VDFS4_CATALOG_FOLDER_RECORD;
	} else {
		start = 0;
		length = stat_info->st_size;
		links = stat_info->st_nlink;

		if (S_ISCHR(stat_info->st_mode) || S_ISBLK(stat_info->st_mode))
			items = (major(stat_info->st_rdev) << 20)
				| minor(stat_info->st_rdev);

		if (name && links > 1) {
			struct hlink_list_item *list_item;
			record_type = VDFS4_CATALOG_HLINK_RECORD;
			list_item = hl_list_item_find(&sbi->hlinks_list,
					stat_info->st_ino);
			if (list_item) {
				list_item->links++;
				test_and_clear_inode_n(sbi, obj_id);
				obj_id = list_item->new_ino_n;
			} else {
				list_item = malloc(sizeof
						(struct hlink_list_item));
				memset(list_item, 0, sizeof
						(struct hlink_list_item));
				hl_list_item_init(list_item,
					stat_info->st_ino, path, obj_id);
				hl_list_insert(&sbi->hlinks_list, list_item);
			}
		}
	}

	if (!S_ISLNK(stat_info->st_mode) &&
			record_type != VDFS4_CATALOG_HLINK_RECORD) {

		ret = get_set_xattrs(sbi, path, obj_id);
		if (ret)
			return ret;
	}
	new_record = vdfs4_cattree_place_record(&sbi->cattree.vdfs4_btree,
			obj_id, parent_id, name,
			name ? strlen(name) : 0, record_type);

	if (IS_ERR(new_record)) {
		ret = PTR_ERR(new_record);
		return ret;
	}
	vdfs4_fill_cattree_record_value(new_record, items, links,
		&permissions, creation_time, modification_time,
		access_time, start, length, sbi->block_size);

	if ((record_type == VDFS4_CATALOG_FILE_RECORD) &&
			(S_ISREG(stat_info->st_mode))) {
		/* if (length <= TINY_DATA_SIZE) {
			VDFS4_CATTREE_FOLDVAL(new_record)->flags |=
					(1 << TINY_FILE);
			sbi->tiny_files_count++;
		}*/
	}

	/* handle encryption if requested from command line */
	if(S_ISREG(stat_info->st_mode) && stat_info->st_size != 0) {
		if(IS_FLAG_SET(sbi->service_flags, ENCRYPT_ALL) ||
		   (IS_FLAG_SET(sbi->service_flags, ENCRYPT_EXEC) && is_exec_file_path(path))) {
			VDFS4_CATTREE_FOLDVAL(new_record)->flags |= (1 << VDFS4_ENCRYPTED_FILE);
		}
	}

	vdfs4_release_record((struct vdfs4_btree_gen_record *) new_record);
	return ret;
}


/**
 * @brief Function insert_metadata
 * (read directory and add metadata about its objects to cattree)
 * for VDFS4 subsystem
 * @param [in] sbi		Superblock runtime structure
 * @param [in] dir_path		path to direcroty to read
 * @param [in] parent_id	ID of directory to insert metadata from it
  * @return 0 on success, or error code
 */
/******************************************************************************/
int insert_metadata(struct vdfs4_sb_info *sbi, char *dir_path, int parent_id,
		__u64 *object_count)
{
	DIR *dir;
	int ret;
	char *path = NULL;
	struct dirent *data;
	struct dirent entry;
	struct stat info;
	int obj_id;
	__u64 obj_count = 0;
	ret = 0;

	dir = opendir(dir_path);

	if (dir == NULL) {
		log_error("Can't open dir %s(err:%d)", dir_path, errno);
		return errno;
	}

	/*while ((data = readdir(dir)) != NULL) {*/
	ret = readdir_r(dir, &entry, &data);
	while (!ret && data) {
		if ((strcmp(data->d_name, ".") == 0) ||
				(strcmp(data->d_name, "..") == 0))
			goto next;

		path = calloc(1, strlen(dir_path) + strlen(data->d_name) + 2);
		if (!path) {
			ret = -ENOMEM;
			goto exit;
		}
		strncat(path, dir_path, strlen(dir_path));
		strncat(path, "/", 1);
		strncat(path, data->d_name, strlen(data->d_name));
		ret = lstat(path, &info);
		if (ret) {
			log_error("Can't get stat information for %s(err:%d)",
				  path, errno);
			goto exit;
		}

		obj_id = get_free_inode_n(sbi, 1);

		if (S_ISDIR(info.st_mode)) {
			/*Found folder*/
			obj_count = 0;
			char *xattr_buf = malloc(XATTR_VAL_SIZE);
			memset(xattr_buf, 0, XATTR_VAL_SIZE);
			free(xattr_buf);
			ret = insert_metadata(sbi, path, obj_id, &obj_count);

			if (ret)
				goto exit;
			ret = insert_record(sbi, path, data->d_name, &info,
					obj_id, parent_id, &obj_count);
		} else {
			sbi->files_count++;


			ret = insert_record(sbi, path, data->d_name, &info,
				obj_id, parent_id, &obj_count);

			if (ret)
				goto exit;
		}
		(*object_count)++;
		free(path);
		path = NULL;
next:
		ret = readdir_r(dir, &entry, &data);
	}


exit:
	free(path);
	closedir(dir);
	return ret;
}
/******************************************************************************/




int init_sb_info(struct vdfs4_sb_info *sbi)
{
	struct timespec cur_time;

	/*sbi->xattrtree.tree.name = subsystem_names[6];
	sbi->small_area_bitmap.name = subsystem_names[7];
	sbi->small_area.name = subsystem_names[8];*/
	if (sbi->max_volume_size && sbi->max_volume_size < MIN_VOLUME_SIZE) {
		log_error("Can't make file less then %d",
				MIN_VOLUME_SIZE);
		return -EINVAL;
	}
	if (!sbi->tmpfs_dir)
		sbi->tmpfs_dir = "/tmp";


	/* in case of image creation without size set in arguments */
	if (sbi->max_volume_size == 0) {
		log_info("Image size is not specified.");
		sbi->max_volume_size = -1;
		sbi->min_volume_size = -1;
	} else {
		log_info("Image size is %llu", sbi->max_volume_size);
	}

	if (IS_FLAG_SET(sbi->service_flags, SIMULATE))
		log_info("Disk operations are in SIMULATE mode");

	sbi->block_size = BLOCK_SIZE_DEFAULT;

	if (sbi->super_page_size == 0)
		sbi->super_page_size = SUPER_PAGE_SIZE_DEFAULT;

	if (sbi->erase_block_size == 0)
		sbi->erase_block_size = ERASE_BLOCK_SIZE_DEFAULT;
	log_info("Block size = %lu, erase block = %lu, super page = %lu",
		sbi->block_size, sbi->erase_block_size,
		sbi->super_page_size);
	log_info("Disk size in blocks %llu", byte_to_block(sbi->max_volume_size,
		sbi->block_size));

	clock_gettime(CLOCK_REALTIME, &cur_time);
	sbi->timestamp = vdfs4_encode_time(cur_time);

	generate_uuid(sbi->volume_uuid, sizeof(sbi->volume_uuid));

	memcpy(sbi->volume_name, VOLUME_NAME_DEFAULT,
			sizeof(VOLUME_NAME_DEFAULT));

	sbi->log_blocks_in_leb = log2_32(sbi->super_page_size);
	sbi->log_sectors_per_block = log2_32(sbi->block_size / SECTOR_SIZE);
	sbi->log_erase_block_size = log2_32(sbi->erase_block_size);
	sbi->log_super_page_size = log2_32(sbi->super_page_size);
	sbi->log_block_size = log2_32(sbi->block_size);

	sbi->files_count = 0;
	sbi->folders_count = 1; /* root directory */

	sbi->debug_area.first_block = DEBUG_AREA_DEFAULT_START;
	sbi->debug_area.block_count = DEBUG_AREA_DEFAULT_SIZE;

	sbi->sign_type = get_sign_type(sbi->rsa_key);

	INIT_LIST_HEAD(&sbi->data_ranges);

	return 0;
}

static int calc_and_add_crc(int file_id)
{
	unsigned char buf[BLOCK_SIZE_DEFAULT]={0,};
	unsigned int crc=0;
	struct stat stat;
	s64 calc_size, read_size;

	lseek(file_id, 0, SEEK_SET);
	if (fstat(file_id, &stat)) {
		return errno;
	}
	calc_size = stat.st_size;
	crc = crc32(0L, Z_NULL, 0);
	while (calc_size > 0 && (read_size=read(file_id, buf, BLOCK_SIZE_DEFAULT))) {
		if (-1 == read_size) {
			return errno;
		}
		crc = crc32(crc, (const unsigned char*)buf, read_size);
		calc_size -= read_size;
	}

	memset(buf, 0x00, sizeof(char) * BLOCK_SIZE_DEFAULT);
	*((unsigned int*)buf) = VDFS_IMG_VERIFY_MAGIC;	//magic
	*(((unsigned int*)buf)+1) = crc;	//crc
	if (write(file_id, buf, BLOCK_SIZE_DEFAULT) != BLOCK_SIZE_DEFAULT)
		return errno;
	return 0;
}

/**
 * @brief Function fill mkfs verification magic for update verification.
 * @param [in] sbi		Superblock runtime structure
 * @param [in] magic     special defined value for verification
 * @return 0 on success, or error code
 */
static int fill_verification_magic(struct vdfs4_sb_info *sbi, unsigned int magic)
{
	int fd = sbi->disk_op_image.file_id;
	off_t current_pos;
	struct vdfs_dbg_area_map dbg_area;
	current_pos = lseek(fd, 0, SEEK_CUR);
	memset(&dbg_area, 0x00, sizeof(dbg_area));
	memcpy(dbg_area.magic, VDFS_DBG_AREA_MAGIC, sizeof(dbg_area.magic));
	dbg_area.dbgmap_ver = VDFS_DBG_AREA_VER;
	dbg_area.dbg.dbg_info.verify_result = magic;
	if (VDFS_DBG_AREA_OFFSET != lseek(fd, VDFS_DBG_AREA_OFFSET, SEEK_SET)) {
		log_error("failed to seek for fill start magic(errno:%d)", errno);
		return -errno;
	}
	if (sizeof(dbg_area)!=write(fd, &dbg_area, sizeof(dbg_area))) {
		log_error("failed to write for debug area(errno:%d)\n", errno);
		return -errno;
	}
	if (current_pos != lseek(fd, current_pos, SEEK_SET)) {
		log_error("failed to recover fpos(errno:%d)\n", errno);
		return -errno;
	}
	return 0;
}

void init_threads(struct vdfs4_sb_info *sbi)
{
	int tnum;
	int ret = 0;
	int path_len = 0;
	if (sbi->jobs)
		processors = sbi->jobs;
	else
		processors = sysconf(_SC_NPROCESSORS_ONLN);

	log_activity("Create number of thread : %d ", processors);

	thread = malloc(processors * sizeof(struct thread_info));
	thread_file = malloc(processors * sizeof(struct thread_file_info));
	pthread_mutex_init(&file_finished_mutex, NULL);
	pthread_mutex_init(&write_file_mutex, NULL);
	pthread_mutex_init(&files_count_mutex, NULL);
	pthread_mutex_init(&find_record_mutex, NULL);
	pthread_mutex_init(&thread_free_mutex, NULL);
	pthread_mutex_init(&thread_file_free_mutex, NULL);
	pthread_cond_init(&thread_free_cond, NULL);
	pthread_cond_init(&thread_file_free_cond, NULL);
	pthread_cond_init(&file_finished, NULL);
	for (tnum = 0; tnum < processors; tnum++) {
		memset(&thread[tnum], 0, sizeof(struct thread_info));
		thread[tnum].thread_num = tnum + 1;
		thread[tnum].is_free = 1;
		thread[tnum].in = malloc(1 << sbi->log_chunk_size);
		thread[tnum].out_size = (1 << sbi->log_chunk_size) +
				((1 << sbi->log_chunk_size) / 16 + 64 + 3);
		thread[tnum].out = malloc(thread[tnum].out_size);
		pthread_mutex_init(&thread[tnum].compress_mutex, NULL);
		pthread_mutex_init(&thread_file[tnum].write_uncompr_mutex,
				NULL);
		pthread_mutex_init(&thread_file[tnum].write_compr_mutex, NULL);
		pthread_mutex_init(&thread_file[tnum].compress_mutex, NULL);
		pthread_mutex_init(&thread_file[tnum].write_mutex, NULL);
		pthread_mutex_init(&thread_file[tnum].compr_file_mutex, NULL);
		pthread_cond_init(&thread_file[tnum].compr_file_cond, NULL);
		pthread_cond_init(&thread_file[tnum].finished, NULL);
		pthread_cond_init(&thread[tnum].compress_cond, NULL);

		ret = pthread_create(&thread[tnum].thread_id, NULL,
				(void *)&compress_chunk_thread,
				(void *)&thread[tnum]);
		if (ret != 0)
			exit(EXIT_FAILURE);
		memset(&thread_file[tnum], 0, sizeof(struct thread_file_info));
		thread_file[tnum].thread_num = tnum + 1;
		thread_file[tnum].is_free = 1;
		thread_file[tnum].ptr = malloc(sizeof(struct install_task));
		if (sbi->rsa_key) {
			thread_file[tnum].rsa_copy  = malloc(sizeof(RSA));
			memcpy(thread_file[tnum].rsa_copy, sbi->rsa_key,
					sizeof(RSA));
			thread[tnum].hash_alg = sbi->hash_alg;
			thread[tnum].hash_len = sbi->hash_len;
		}
		ret = pthread_create(&thread_file[tnum].thread_id, NULL,
				(void *)&compress_file_thread,
				(void *)&thread_file[tnum]);
		if (ret != 0)
			exit(EXIT_FAILURE);



		path_len = strlen(sbi->tmpfs_dir)
				+ 1 + strlen("comp_") + 32;
		thread_file[tnum].compr_temp = malloc(path_len);
		memset(thread_file[tnum].compr_temp, 0, path_len);
		snprintf(thread_file[tnum].compr_temp, path_len,
				"%s/comp_%lu", sbi->tmpfs_dir,
				(long unsigned)thread_file[tnum].thread_id);
		path_len = strlen(sbi->tmpfs_dir) + 1 + strlen("uncom_") + 32;
		thread_file[tnum].uncompr_temp = malloc(path_len);
		memset(thread_file[tnum].uncompr_temp, 0, path_len);
		snprintf(thread_file[tnum].uncompr_temp, path_len,
				"%s/uncom_%lu", sbi->tmpfs_dir,
				(long unsigned)thread_file[tnum].thread_id);


	}

}

void destroy_threads(void)
{
	int i;
	for (i = 0; i < processors; i++) {
		if (thread[i].thread_id) {
			pthread_mutex_lock(&thread[i].compress_mutex);
			thread[i].exit = 1;
			pthread_cond_signal(&thread[i].compress_cond);
			pthread_mutex_unlock(&thread[i].compress_mutex);
			pthread_join(thread[i].thread_id, NULL);
			free(thread[i].in);
			free(thread[i].out);
			pthread_cond_destroy(&thread[i].compress_cond);
			pthread_mutex_destroy(&thread[i].compress_mutex);

		}
	}
	free(thread);
	for (i = 0; i < processors; i++) {
		if (thread_file[i].thread_id) {
			pthread_mutex_lock(&thread_file[i].compr_file_mutex);
			thread_file[i].exit = 1;
			pthread_cond_signal(&thread_file[i].compr_file_cond);
			pthread_mutex_unlock(&thread_file[i].compr_file_mutex);
			pthread_join(thread_file[i].thread_id, NULL);
			free(thread_file[i].ptr);
			free(thread_file[i].rsa_copy);
			free(thread_file[i].compr_temp);
			free(thread_file[i].uncompr_temp);
			pthread_cond_destroy(&thread_file[i].compr_file_cond);
			pthread_mutex_destroy(&thread_file[i].compr_file_mutex);
			pthread_mutex_destroy(
					&thread_file[i].write_compr_mutex);
			pthread_mutex_destroy(
					&thread_file[i].write_uncompr_mutex);
			pthread_mutex_destroy(&thread_file[i].write_mutex);
			pthread_mutex_destroy(&thread_file[i].compress_mutex);
			pthread_cond_destroy(&thread_file[i].finished);
		}
	}
	pthread_mutex_destroy(&thread_free_mutex);
	pthread_mutex_destroy(&thread_file_free_mutex);
	pthread_cond_destroy(&thread_file_free_cond);
	pthread_cond_destroy(&thread_free_cond);
	pthread_mutex_destroy(&files_count_mutex);
	pthread_mutex_destroy(&find_record_mutex);
	pthread_mutex_destroy(&file_finished_mutex);
	pthread_mutex_destroy(&write_file_mutex);
	pthread_cond_destroy(&file_finished);
	free(thread_file);

}

/**
 * @brief Function print used space(unit:KB)
 *  (referencing print_superblock() in fsck_print.c)
 * @param [in] sbi		Superblock runtime structure
 * @return 0 on success, or error code
 */
static int handle_used_space(struct vdfs4_sb_info *sbi)
{
	struct vdfs4_extended_super_block esb = sbi->esb;
	struct vdfs4_subsystem_data *mehs_subs =
		&(sbi->meta_hashtable.subsystem);
	long long unsigned int used_block;
	uint64_t used_size;
	int ret = 0;

	if (!(IS_FLAG_SET(sbi->service_flags, IMAGE)))
		return ret;

	/* Because only one struct vdfs4_extent is made during initial image creation,
	    it's enough to refer first entry in this time */
	used_block = le64_to_cpu(esb.meta[0].length)
		+ le64_to_cpu(esb.meta[0].begin);
	if (IS_FLAG_SET(sbi->service_flags, READ_ONLY_IMAGE)
	    && sbi->rsa_key) {
		used_block += mehs_subs->fork.extents[0].block_count;
	}

	/* crc at the end of image file */
	used_block += 1;

	used_size = block_to_byte(used_block, sbi->block_size);
	log_activity("Used size : %llu KB", used_size / 1024);

	if (IS_FLAG_SET(sbi->service_flags, LIMITED_SIZE) &&
	    used_size > sbi->min_volume_size) {
		log_error("the image size(-z) is not enough");
		return -ENOSPC;
	}

	if (IS_FLAG_SET(sbi->service_flags, SIMULATE))
		return ret;

	/* make suitable image size */
	if (IS_FLAG_SET(sbi->service_flags, NO_STRIP_IMAGE))
		ret = ftruncate(sbi->disk_op_image.file_id,
				sbi->max_volume_size);
	else
		ret = ftruncate(sbi->disk_op_image.file_id, used_size);

	return ret;
}

/**
 * @brief set default option values in sb_info (for vdfs4-tools unique part)
 * @param [in] sbi Superblock runtime structure
 */
static void set_default_opt_values(struct vdfs4_sb_info *sbi)
{
	/* minimum compression ratio */
	sbi->min_space_saving_ratio = 25;
}

static void sig_handler(int signo)
{
	void *array[10];
	size_t size;

	log_error("[%3us] mkfs.vdfs receive %d signal!!!",
		  get_elapsed_time(), signo);

	size = backtrace(array, 10);
	log_error("+------ backtrace(%2d,%2d) ------+", signo, size);
	backtrace_symbols_fd(array, size, STDERR_FILENO);
	log_error("+------------------------------+");
	fflush(stdout);
	fflush(stderr);

	signal(signo, SIG_DFL);
	raise(signo);
}

int main(int argc, char *argv[])
{
	int ret = 0, i;
	struct vdfs4_sb_info sbi;
	struct list_head install_task_list;

	/* for setting process start time. */
	get_elapsed_time();

	print_version();
	INIT_LIST_HEAD(&install_task_list);
	INIT_LIST_HEAD(&sbi.data_ranges);
	memset(&sbi, 0, sizeof(sbi));
	INIT_LIST_HEAD(&sbi.prof_data);

	/* regist signal handler for alarm */
	for (i = SIGHUP; i < SIGRTMAX ; i++)
		signal(i, sig_handler);

	ret = init_crypto_lock();
	if (ret)
		goto err_init_crypto_lock;

	set_default_opt_values(&sbi);
	ret = parse_cmd(argc, argv, &sbi);
	if (ret)
		goto err_before_open;

	log_activity("mkfs.vdfs begin");
	if (!IS_FLAG_SET(sbi.service_flags, IMAGE))
		ret = open_disk(&sbi);
	else
		ret = vdfs4_create_image(sbi.file_name, &sbi);
	if (ret) {
		log_error("mkfs.vdfs tool open failed.(errno:%d)(%d)\n",
				errno, IS_FLAG_SET(sbi.service_flags, IMAGE));
		goto err_before_open;
	}

	ret = init_sb_info(&sbi);
	if (ret) {
		log_error("mkfs.vdfs failed to sb init.\n");
		goto err_exit;
	}

	if (!IS_FLAG_SET(sbi.service_flags, IMAGE)) {
		ret = discard_volume(&sbi);
		if (ret)
			goto err_exit;
	}

	ret = flush_debug_area(&sbi);
	if (ret) {
		goto err_exit;
	}

	// write special magic at first for guaranteeing mkfs finish
	if (!IS_FLAG_SET(sbi.service_flags,IMAGE) &&
		!IS_FLAG_SET(sbi.service_flags, SIMULATE)) {
		ret = fill_verification_magic(&sbi, VDFS_DBG_VERIFY_START);
		if (ret)
			goto err_exit;
	}

	ret = vdfs4_init_btree_caches();
	if (ret) {
		log_error("error btree caches init - ENOMEM");
		goto err_exit;
	}

	ret = init_snapshot(&sbi);
	if (ret)
		goto err_space_manager;

	ret = init_hashtable(&sbi);
	if (ret)
		goto err_space_manager;

	ret = init_space_manager(&sbi);
	if (ret)
		goto err_space_manager;

	ret = clean_superblocks_area(&sbi);
	if (ret)
		goto err_space_manager;

	ret = init_inode_id_alloc(&sbi);
	if (ret)
		goto err_inode_id_alloc;

	ret = init_cattree(&sbi);
	if (ret)
		goto err_cat_tree;
	ret = init_exttree(&sbi);
	if (ret)
		goto err_ext_tree;
	ret = init_xattrtree(&sbi);
	if (ret)
		goto err_xattr_tree;

	if (sbi.squash_list_file) {
		//"-q config_file" param case
		ret = preprocess_sq_tasklist(&sbi, &install_task_list,
				sbi.squash_list_file);
		if (ret)
			goto err_squashfs;
	} else if (sbi.compr_type) {
		//"-c compr_type" param case.
		ret = preprocess_sq_tasklist(&sbi, &install_task_list, NULL);
		if (ret)
			goto err_squashfs;
	}

	init_threads(&sbi);
	ret = fill_image_metadata(&sbi);
	if (ret)
		goto err_destroy_all;

	util_add_btree_size(&sbi, &sbi.cattree);
	util_add_btree_size(&sbi, &sbi.xattrtree);
	util_add_btree_size(&sbi, &sbi.exttree);

	ret = allocate_fixed_areas(&sbi);
	if (ret)
		goto err_destroy_all;

	ret = fill_inode_bitmap(&sbi);
	if (ret)
		goto err_destroy_all;
	ret = calculate_and_place_on_volume_snapshot(&sbi);
	if (ret)
		goto err_destroy_all;
	if (!list_empty(&install_task_list)) {
		ret = tune_files(&sbi, &install_task_list);
		if (ret)
			goto  err_destroy_all;
	}
	ret = fill_image_data(&sbi);
	if (ret)
		goto err_destroy_all;

	if (!IS_FLAG_SET(sbi.service_flags, READ_ONLY_IMAGE)) {
		ret = place_on_volume_subsystem(&sbi,
				&sbi.space_manager_info.subsystem);
		if (ret)
			goto err_destroy_all;
		ret = place_on_volume_subsystem(&sbi, &sbi.inode_bitmap);
		if (ret)
			goto err_destroy_all;
	}

	ret = place_on_volume_subsystem(&sbi, &sbi.cattree.tree);
	if (ret)
		goto err_destroy_all;
	ret = place_on_volume_subsystem(&sbi, &sbi.exttree.tree);
	if (ret)
		goto err_destroy_all;
	ret = place_on_volume_subsystem(&sbi, &sbi.xattrtree.tree);
	if (ret)
		goto err_destroy_all;
	ret = place_on_volume_preallocation(&sbi);
	if (ret)
		goto err_destroy_all;

	sign_sm_buffer(&sbi);
	if (!IS_FLAG_SET(sbi.service_flags, READ_ONLY_IMAGE)) {
		ret = flush_subsystem(&sbi, &sbi.inode_bitmap);
		if (ret)
			goto err_destroy_all;
	}
	ret = flush_subsystem_tree(&sbi, &sbi.cattree);
	if (ret)
		goto err_destroy_all;
	ret = flush_subsystem_tree(&sbi, &sbi.exttree);
	if (ret)
		goto err_destroy_all;
	ret = flush_subsystem_tree(&sbi, &sbi.xattrtree);
	if (ret)
		goto err_destroy_all;
	ret = flush_snapshot(&sbi);
	if (ret)
		goto err_destroy_all;

	if (!IS_FLAG_SET(sbi.service_flags, READ_ONLY_IMAGE)) {
		ret = flush_subsystem(&sbi, &sbi.space_manager_info.subsystem);
		if (ret)
			goto err_destroy_all;
	} else if (sbi.rsa_key) {
		ret = flush_hashtable(&sbi);
		if (ret)
			goto err_destroy_all;
	}

	ret = prepare_superblocks(&sbi);
	if (ret)
		goto err_destroy_all;
	ret = flush_superblocks(&sbi, argc, argv);
	if (ret)
		goto err_destroy_all;

	ret = handle_used_space(&sbi);
	if (ret)
		goto err_destroy_all;

	if (!IS_FLAG_SET(sbi.service_flags, SIMULATE)) {
		//Do sync
		if (fsync(sbi.disk_op_image.file_id)) {
			log_error("failed to fsync (err:%d)\n", errno);
			goto err_destroy_all;
		}

		if (IS_FLAG_SET(sbi.service_flags, IMAGE)) {
			//write CRC of [0 ~ 'file size-4K']
			ret = calc_and_add_crc(sbi.disk_op_image.file_id);
			if (ret)
				goto err_destroy_all;
		} else {
			//write finish special magic
			ret = fill_verification_magic(&sbi, VDFS_DBG_VERIFY_MKFS);
			if (ret)
				goto err_destroy_all;
		}
	}

err_destroy_all:
	if (ret)
		hl_list_free(sbi.hlinks_list.next);
	destroy_threads();
	if (!list_empty(&sbi.data_ranges))
		clear_data_range_list(&sbi.data_ranges);
err_squashfs:
	if (!list_empty(&install_task_list))
		clear_install_task_list(&install_task_list);
err_xattr_tree:
	btree_destroy_tree(&sbi.xattrtree);
err_ext_tree:
	btree_destroy_tree(&sbi.exttree);
err_cat_tree:
	btree_destroy_tree(&sbi.cattree);
err_inode_id_alloc:
	destroy_inode_id_alloc(&sbi);
err_space_manager:
	destroy_snapshot(&sbi);
	destroy_hashtable(&sbi);
	destroy_space_manager(&sbi);
	if (sbi.dump_file)
		fclose(sbi.dump_file);
	close_disk(&sbi);
	vdfs4_destroy_btree_caches();
err_exit:
	if (ret == 0) {
		log_activity("mkfs.vdfs end");
		log_info("Finished successfully");
	}
	else {
		remove_image_file(&sbi);
		if (ret == -ENOSPC)
			log_error("Mkfs can't allocate enough disk space");
		log_error("mkfs.vdfs was failed...!!");
	}
err_before_open:
	if (sbi.squash_list_file)
		fclose(sbi.squash_list_file);
	if (sbi.rsa_key) {
		RSA_free(sbi.rsa_key);
		CRYPTO_cleanup_all_ex_data();
	}
	free(sbi.aes_key);
	destroy_crypto_lock();
err_init_crypto_lock:
	return ret;
}
