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

/* This option permits use ordinary lseek, read and write operations with    */
/* 64 bit offsets                                                            */
#define _FILE_OFFSET_BITS 64

#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include <mntent.h>
#include <sys/stat.h>
#include <linux/fs.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <assert.h>
#include <sys/stat.h>
#include <vdfs_tools.h>

#define PATH_PROC_MOUNTS "/proc/mounts"
#define BUFFER_SIZE_MOUNTS 1024
/** @brief This function write buffer to the file at current position
 *  @param [in] file_id file descriptor
 *  @param [in] buffer pointer to buffer to write
 *  @param [in] size   size of buffer
 *  @return 0 on success, error code otherwise
*/
static int diskop_write(const int file_id, const char *buffer, u_int64_t size)
{
	ssize_t written;
	size_t written_total;
	size_t to_be_written;
	int ret = 0;
	const char *buffer_ptr;
	written_total = 0;
	/* write buffer to the image */
	while (written_total < size) {
		buffer_ptr = buffer + written_total;
		to_be_written = size - written_total;
		written = write(file_id,
				buffer_ptr,
				to_be_written);
		if (written == -1) {
			ret = -EWRFAIL;
			goto FUNC_END;
		}
		if (written <= (ssize_t)to_be_written)
			written_total += (size_t)written;
	}
FUNC_END:
	return ret;
}
/** @brief  This function gets disk size of specified block device.
 *  @param [in]  file_id file descriptor of device to check
 *  @param [out] disk_size size of device
 *  @return 0 on success, error code otherwise
 */
int diskop_get_disk_size(const int file_id,
				u_int64_t *disk_size)
{
	int ret = 0;
	/*sector size and sectors count*/
	unsigned long long sector_size = 0;
	unsigned long long sectors_count = 0;

	assert(file_id >= 0);

	if (ioctl(file_id, BLKSSZGET, &sector_size) < 0) {
		log_error("Can't get sector size for device by ioctl() %u",
		BLKSSZGET);
		ret = -ENOSECTSIZE;
		goto FUNC_END;
	}

	if (ioctl(file_id, BLKGETSIZE, &sectors_count) < 0) {
		log_error("Can't get sectors count for device by ioctl() %u",
		BLKGETSIZE);
		ret = -ENOSECTNUM;
		goto FUNC_END;
	}

	*disk_size = sectors_count * sector_size;
FUNC_END:
	return ret;
}

/**
 * @brief Verify that specified device is mounted according to /etc/mtab.
 * @param [in] device name of device
 * @return 0 if device isn't mounted,
 *     -error_code otherwise
 */
int diskop_is_disk_mounted_mtab(const char *device)
{
	FILE *mnt_id = NULL;
	struct mntent *mnt_ent = NULL;
	int ret_val = 0;

	/* open descriptor of file system description file */
	mnt_id  = setmntent(_PATH_MOUNTED, "r");

	/* check errors */
	if (NULL == mnt_id) {
		log_error("Can't open %s", _PATH_MOUNTED);
		ret_val = -ENOENT;
		return ret_val;
	}

	/* scan file system description file and verify mounted devices */
	while (NULL != (mnt_ent = getmntent(mnt_id))) {
		if (0 == strcmp(mnt_ent->mnt_fsname, device)) {
			ret_val = -EISMNTD;
			break;
		}
	}

	endmntent(mnt_id);

	return ret_val;
}

/**
 * @brief Verify that specified device is mounted according to /proc/mounts
 * @param [in] device name of device
 * @return 0 if device isn't mounted,
 *     -error_code otherwise
 */
int diskop_is_disk_mounted_proc(const char *device)
{
	FILE *file_id = NULL;
	char buffer[BUFFER_SIZE_MOUNTS];
	char *space_position;
	int ret_val = 0;

	file_id = fopen(PATH_PROC_MOUNTS, "r");
	if (NULL == file_id) {
		log_error("Can't open %s", PATH_PROC_MOUNTS);
		ret_val = -ENOENT;
		return ret_val;
	}

	while (!feof(file_id)) {
		memset(buffer, 0, sizeof(buffer));
		/* force buffer to be null terminated C string, so we read    */
		/* less than buffer size symbols, last symbol will be 0       */
		fgets(buffer, sizeof(buffer) - 1, file_id);
		/* get first token from entry */
		space_position = strchr(buffer, ' ');
		if (space_position == NULL)
			/* this is last line entry */
			continue;
		*space_position = 0;
		if (0 == strcmp(buffer, device)) {
			ret_val = -EISMNTD;
			break;
		}
	}
	fclose(file_id);

	return ret_val;
}
/**
 * @brief This function verifies in two ways that specified device is mounted.
 * @param [in] device name of device
 * @return 1 if device is mounted, 0 if is not mounted,
 *     -error_code otherwise
 */
int diskop_is_disk_mounted(const char *device)
{
	int ret = 0;

	ret = diskop_is_disk_mounted_mtab(device);
	if (ret)
		return ret;

	ret = diskop_is_disk_mounted_proc(device);

	return ret;
}

/**
 * @brief This function opens a block device and returns a handle if device is valid.
 * @param [in] sb_info super block structure
 * @return 0 on success, error code otherwise
 */
int open_disk(struct vdfs4_sb_info *sb_info)
{
	int ret = 0;
	struct stat stat_buf;
	char *filename = sb_info->file_name;
	if (NULL == filename) {
		log_error("Device is not initialized (null)");
		ret = -ENODEV;
		goto FUNC_END;
	}

	/* open device */
	sb_info->disk_op_image.file_id = open(filename, O_RDWR|O_SYNC);
	/* opening fails */
	/* log error and report it to caller */
	if (sb_info->disk_op_image.file_id == -1) {
		log_error("Can't open %s", filename);
		ret = -ENOENT;
		goto FUNC_END;
	}
	/* disk is opened */
	if (fstat(sb_info->disk_op_image.file_id, &stat_buf) < 0) {
		log_error("Failed to get the device stat");
		return -1;
		}

	if (S_ISREG(stat_buf.st_mode)) {
		sb_info->image_size = stat_buf.st_size;
	} else if (S_ISBLK(stat_buf.st_mode)) {
		if (0 != getuid()) {
			log_error("You must be root to perform "
					"real disk operations");
			ret = -EPERM;
			goto FUNC_END;
		}
	/* check if disk is mounted */
		ret = diskop_is_disk_mounted(filename);
		if (ret) {
			if (ret == -EISMNTD)
				log_error("Device %s is mounted",
					filename);
			goto FUNC_END;
		}
		ret = diskop_get_disk_size(sb_info->disk_op_image.file_id,
				&sb_info->image_size);
	} else {
		log_error("Volume type is not supported");
		return -1;
	}
	sb_info->min_image_size = sb_info->image_size;
FUNC_END:
	return ret;
}

/**
 * @brief This function closes block device after all disk operations are done
 * @param [in] sb_info super block structure
 */
void close_disk(struct vdfs4_sb_info *const sb_info)
{
	if (sb_info->disk_op_image.file_id != -1) {
		fsync(sb_info->disk_op_image.file_id);
		close(sb_info->disk_op_image.file_id);
	}
}

/**
 * @brief This function creates image file. If file exists, this function returns error.
 * @param [in] name filename of the image
 * @param [in] sb_info super block structure
 * @return  0 on success, error code otherwise
 */
int vdfs4_create_image(const char *name,
		struct vdfs4_sb_info * const sb_info)
{
	char err_msg[ERR_BUF_LEN];
	int ret = 0;
	if (NULL == name) {
		log_error("Image is not initialized (null)");
		ret = -ENOENT;
		goto FUNC_END;
	}

	/* no disk write in simulate mode */
	if (IS_FLAG_SET(sb_info->service_flags, SIMULATE)) {
		ret = 0;
		goto FUNC_END;
	}

	/* create image file */
	errno = 0;
	sb_info->disk_op_image.file_id = open(name,
		O_CREAT | O_EXCL | O_RDWR | O_TRUNC,
		S_IRUSR | S_IWUSR);
	if (sb_info->disk_op_image.file_id == -1) {
		/* file exists */
		if (errno == EEXIST)
			ret = -EEXIST;
		else
			ret = -ENOENT;
		log_error("Can't open image file \"%s\" (%s)",
			name,
			strerror_r(errno, err_msg, ERR_BUF_LEN));
		goto FUNC_END;
	/* disk is opened */
	} else {
		ret = 0;
		goto FUNC_END;
	}
FUNC_END:
	return ret;
}

/**
 * @brief This function close file image handle
 * @param [in] sb_info super block structure
 */
void vdfs4_close_image(struct vdfs4_sb_info *sb_info)
{
	assert(NULL != sb_info);
	if (sb_info->disk_op_image.file_id != -1)
		close(sb_info->disk_op_image.file_id);
}

/**
 * @brief Write buffer content on "disk" (real or file image)
 * @param [in] sb_info super block structure
 * @param [in] start offset on disk for data to be written. It should point to
 *  number of blocks from start of the image
 * @param [in] src source buffer to copy
 * @param [in] src_size size of source buffer in blocks
 * @return 0 on success, error code otherwise
 */
int vdfs4_write_blocks(struct vdfs4_sb_info *sb_info,
			u_int64_t start,
			const void *src,
			u_int64_t src_size)
{
	return vdfs4_write_bytes(sb_info,
			block_to_byte(start, sb_info->block_size), src,
			block_to_byte(src_size, sb_info->block_size));
}

int vdfs4_write_bytes(struct vdfs4_sb_info *sb_info,
			u_int64_t start,
			const void *src,
			u_int64_t src_size)
{
	int ret = 0;
	assert(sb_info != NULL);

	/* no disk write in simulate mode */
	if (IS_FLAG_SET(sb_info->service_flags, SIMULATE)) {
		ret = 0;
		goto FUNC_END;
	}

	/* seek to right position in the image */
	if (lseek(sb_info->disk_op_image.file_id, start, SEEK_SET) < 0) {
		log_error("Can't perform seek operation to %llu", start);
		ret = -ESPIPE;
		goto FUNC_END;
	}
	/* write buffer to the image */
	ret = diskop_write(sb_info->disk_op_image.file_id, (const char *)src,
			src_size);
	if (ret < 0) {
		log_error("Write operation fails on start block %llu",	start);
		goto FUNC_END;
	}
FUNC_END:
	/* calculate number of written blocks */
	return ret;
}

/**
 * @brief This function read data from image (file or block device).
 * @param [in] h pointer to image handle
 * @param [in] offset start position of the read operation. It should be
 *			specified in blocks.
 * @param [in] dest destination buffer where the read content will be stored
 * @param [in] dest_size The number of blocks to read.
 * @param [out] err error code of operation
 * @return Returns the number of blocks that were read
 */
int vdfs4_read_blocks(struct vdfs4_sb_info *sb_info,
			u_int64_t offset,
			void *dest,
			u_int64_t dest_size)
{
	u_int64_t actual_offset  = 0;
	size_t nbytes = 0;
	size_t size_in_bytes = dest_size * sb_info->block_size;
	int ret = 0;
	if (dest_size == 0)
		goto FUNC_END;
	assert(sb_info != 0);
	actual_offset = offset * sb_info->block_size;
	/* check we are inside disk */
	assert(actual_offset < sb_info->image_size);
	/* check that record does not fall out of disk */
	if (actual_offset + size_in_bytes >= sb_info->image_size) {
		assert((size_in_bytes + actual_offset- sb_info->image_size) <=
				sb_info->block_size);
		size_in_bytes = sb_info->image_size - actual_offset;
	}
	/* if nothing to do, go to end of function */


	if (lseek(sb_info->disk_op_image.file_id,
			actual_offset,
			SEEK_SET) < 0) {
		log_error("Can't perform seek operation to %llu", offset);
		ret = -ESPIPE;
		goto FUNC_END;
	}

	/* read the data  */
	nbytes = read(sb_info->disk_op_image.file_id, dest, size_in_bytes);
	if (nbytes < size_in_bytes) {
		log_error("Read operation fails");
		ret = -ERDFAIL;
	} else {
		ret = 0;
	}

FUNC_END:
	return ret;
}
/**
 * @brief Write buffer content at the end of file
 * @param [in] buffer - buffer to copy
 * @param [in] size size of the buffer in bytes
 * @return 0 on success, error code otherwise
 */
int vdfs4_append(int fd, char *buffer, int size)
{
	int ret_val = 0;
	/* seek to the end of file */
	if (0 > lseek(fd, 0, SEEK_END)) {
		log_error("Can't perform SEEK_END operation err=", errno);
		return -ESPIPE;
	}
	/* write the data to file */
	ret_val = diskop_write(fd, buffer, size);
	if (0 > ret_val) {
		log_error("Can't append buffer to the end of file( err = %d)",
		ret_val);
	}
	return ret_val;
}
/**
 * @brief This function
 * @param [in] device
 * @return
 */
void get_next_dir(/*struct vdfs4_sb_info *sb_info*/)
{
}

/**
 * @brief This function
 * @param [in] device
 * @return
 */
void get_next_file(/*struct vdfs4_sb_info *sb_info*/)
{
}

/**
 * @brief This function
 * @param [in] device name of device
 * @return
 */

/**
 * @brief Function copy_symlink_file_to_image
 * @param [in]		sbi		Superblock runtime structure
 * @param [in]		src_filename	Name of symbolic link file
 * @param [in/out]	file_offset_abs	Offset of data in image
 * @return 0 on success, error code otherwise
 */
int copy_symlink_file_to_image(struct vdfs4_sb_info *sbi,
		const char *src_filename, u64 *file_offset_abs, int size)
{
	char *buf = malloc(sbi->block_size);
	if (!buf) {
		log_error("Mkfs can't allocate enough memory");
		return -ENOMEM;
	}
	memset(buf, 0, sbi->block_size);
	int r = readlink(src_filename, buf, size);
	if (r < 0) {
		log_error("Can't read link %s", src_filename);
		free(buf);
		return errno;
	}
	allocate_space(sbi, (byte_to_block(*file_offset_abs,
			sbi->block_size)), (byte_to_block(r,
			sbi->block_size)), file_offset_abs);
	*file_offset_abs = block_to_byte(*file_offset_abs, sbi->block_size);
	vdfs4_write_blocks(sbi, byte_to_block
				(*file_offset_abs, sbi->block_size), buf,
				byte_to_block(size,
					sbi->block_size));
	*file_offset_abs += size;
	free(buf);
	return 0;
}

/**
 * @brief Function copy_file_to_image
 * @param [in]		sbi		Superblock runtime structure
 * @param [in]		src_filename	Name of file to copy
 * @param [in/out]	file_offset_abs	Offset of data in image
 * @return 0 on success, error code otherwise
 */

int copy_file_to_image(struct vdfs4_sb_info *sb_info,
		const char *src_filename, u64 *file_offset_abs)
{
	int file;
	char *buf;
	unsigned int buf_size;
	unsigned int file_size ;
	struct stat stat_info;
	int ret = 0, read_real;
	unsigned int need_to_read, file_cont, file_offset, start;

	file_offset = 0;
	memset(&stat_info, 0, sizeof(stat_info));

	/*Take file stat_information*/
	ret = lstat(src_filename, &stat_info);
	if (ret < 0) {
		ret = errno;
		log_error("%s %s", "Can't get stat info of ", src_filename);
		return ret;
	}
	if (stat_info.st_size == 0)
		return ret;
	/*Object is symlink*/
	if (S_ISLNK(stat_info.st_mode)) {
		ret = copy_symlink_file_to_image(sb_info, src_filename,
					file_offset_abs, stat_info.st_size);
		return ret;
	}
	file_size = stat_info.st_size;
	ret = allocate_space(sb_info, (byte_to_block(*file_offset_abs,
			sb_info->block_size)), (byte_to_block(file_size,
			sb_info->block_size)), (u_int64_t *)file_offset_abs);
	if (ret) {
		log_error("Mkfs can't allocate enough disk space");
		return ret;
	}
	*file_offset_abs = block_to_byte(*file_offset_abs, sb_info->block_size);
	file = open(src_filename, O_RDONLY);
	if (file < 0) {
		ret = errno;
		log_error("%s %s", "Can't open file", src_filename);
		return ret;
	}
	buf_size = sb_info->block_size;
	buf = malloc(buf_size);
	if (!buf) {
		log_info("Mkfs can't allocate enough memory");
		close(file);
		return errno;
	}



	while (1) {
		file_cont = file_size - file_offset;
		if (file_cont == 0)
			break;
		need_to_read = (file_cont > buf_size) ? buf_size : file_cont;
		memset(buf, 0, sb_info->block_size);
		read_real = read(file, buf, need_to_read);


		if (read_real == -1) {
			log_warning("%s %s", "Can't read file", src_filename);
			ret = errno;
			goto exit;
		}
		start =  *file_offset_abs + file_offset;
		ret = vdfs4_write_blocks(sb_info,
				byte_to_block(start, sb_info->block_size),
				buf, byte_to_block(need_to_read,
				sb_info->block_size));
		if (ret) {
			log_warning("%s %s", "Can't copy file", src_filename);
			goto exit;
		}
		file_offset += read_real;
	}
	*file_offset_abs += file_offset;
exit:
	free(buf);
	close(file);
	return ret;

}

/**
 * @brief Function fget_metadata_size count size of metadata
 * @param [in] sbi Superblock runtime structure
 * @return metadata_size
 */
__u64 get_metadata_size(struct vdfs4_sb_info *sbi)
{
	__u64 size = 0;
	if (IS_FLAG_SET(sbi->service_flags, READ_ONLY_IMAGE))
		size = block_to_byte(sbi->space_manager_info.first_free_address,
				sbi->block_size);
	else
		size = block_to_byte(sbi->space_manager_info.
			space_manager_list->offset, sbi->block_size);
	return size;
}
/**
 * @brief This function
 * @param [in] device
 * @return
 */
void copy_file_from_image(/*struct vdfs4_sb_info *sb_info,
			const char *src_filename,
			const char *dst_filename*/)
{
}

off_t get_image_size(struct vdfs4_sb_info *sbi)
{
	struct stat file_stat;

	if (fstat(sbi->disk_op_image.file_id, &file_stat) < 0)
		return -1;

	return file_stat.st_size;
}

void remove_image_file(struct vdfs4_sb_info *sbi)
{
	if (IS_FLAG_SET(sbi->service_flags, IMAGE))
		unlink(sbi->file_name);
}

/**
 * @brief This function create hadr link.
 * @param [in] device
 * @return
 */
int create_hard_link(/*struct vdfs4_sb_info *sb_info, const char *dst_filename,
			const char *src_filename*/)
{
	return 0;
}

int get_file_size(int fd, off_t *file_size)
{
	char err_msg[ERR_BUF_LEN];
	struct stat info;
	int ret = fstat(fd, &info);
	if (ret == -1) {
		ret = errno;
		log_error("Can't get stat info because of %s",
				strerror_r(errno, err_msg, ERR_BUF_LEN));
		*file_size = 0;
		return ret;
	}
	*file_size = info.st_size;
	return 0;
}


void add_data_range(struct vdfs4_sb_info *sbi, struct list_head *data_ranges,
		__u64 start, __u64 length)
{
	struct data_range *dr;

	if (!IS_FLAG_SET(sbi->service_flags, READ_ONLY_IMAGE))
		return;

	dr = malloc(sizeof(*dr));
	dr->start = start;
	dr->length = length;
	dr->crc = 0;
	dr->has_crc = 0;
	list_add(&dr->list, data_ranges);
}

__u64 find_data_duplicate(struct list_head *data_ranges, int fd1, int fd2,
				__u64 start, __u64 length)
{
	int ret, len, has_crc = 0, has_diff;
	unsigned char buf1[4096], buf2[4096];
	struct data_range *dr;
	__u32 crc = 0;
	__u64 offset;

	list_for_each_entry(dr, data_ranges, list) {
		if (dr->length != length ||
		    (has_crc && dr->has_crc && dr->crc != crc))
			continue;

		has_diff = 0;
		for (offset = 0; offset < length; offset += len) {
			len = min(sizeof(buf1), length - offset);

			if (!has_diff || !dr->has_crc) {
				ret = pread(fd1, buf1, len, dr->start + offset);
				if (ret != len)
					goto out;
			}

			if (!has_diff || !has_crc) {
				ret = pread(fd2, buf2, len, start + offset);
				if (ret != len)
					goto out;
			}

			if (!dr->has_crc)
				dr->crc = crc32_body(dr->crc, buf1, len);

			if (!has_crc)
				crc = crc32_body(crc, buf2, len);

			if (!has_diff && memcmp(buf1, buf2, len))
				has_diff = 1;

			if (has_diff && has_crc && dr->has_crc)
				break;
		}
		has_crc = 1;
		dr->has_crc = 1;
		if (!has_diff)
			return dr->start;
	}
out:
	return 0;
}
