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

#ifndef	__VDFS4_SQUASHFS_IMAGE_INSTALL_H__
#define	__VDFS4_SQUASHFS_IMAGE_INSTALL_H__

#include "encrypt.h"
#include "../include/vdfs_tools.h"
#include "vdfs4.h"
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#define PAGE_SIZE	4096
#define PAGE_SHIFT	12
/*
 * Command line commands.
 */
#define CMD_COMPRESS	0x40
#define CMD_DECOMPRESS	0x80
#define CMD_ENCRYPT		0x100
#define CMD_OUTPUT	0x400
#define CMD_ON_OFF_DECODE	0x800
#define CMD_SHOW_FILE_INFO	0x2000
#define CMD_AUTH	0x4000

#define CHECK_PM_FAIL	-2

#define BLOCK_SIZE_SHIFT 12
#define MIN_COMPRESSED_FILE_SIZE	8192

/* zlib setting for different compression types */
#define GZIP_WINDOW_SIZE	12+16
#define ZLIB_WINDOW_SIZE	12

enum cmd_on_off_decompress {
	CMD_DISABLE = 0,
	CMD_ENABLE,
	CMD_GET_STATUS,
	UNKNOWN

};

enum {
	TYPE_VDFS4,
};

enum {
	ALIGN_START,
	ALIGN_LENGTH,
	ALIGN_NR,
};

struct install_task {
	struct list_head list;
	/* squashfs image filename (without path) */
	char *src_fname;
	char *dst_fname;
	unsigned cmd;
	int compress_type;
	/* paths below are from root of image*/
	char src_full_path[VDFS4_FULL_PATH_LEN + 1];
	char dst_parent_dir[VDFS4_FULL_PATH_LEN + 1];
	int fs_type;
};

extern int processors;
struct thread_info {		/* Used as argument to thread_start() */
	pthread_t thread_id;	/* ID returned by pthread_create() */
	int thread_num;	/* Application-defined thread # */
	unsigned int count;
	unsigned int chunk_size;
	int max_chunk_size;
	struct vdfs4_comp_extent *ext_table;
	unsigned char *hash_table;
	int tmp_uncompr_fd;
	int tmp_compr_fd;
	int src_file_size;
	size_t *packed_offset;
	size_t *unpacked_offset;
	off_t *new_file_size;
	unsigned char *in;
	int in_size;
	unsigned char *out;
	int out_size;
	int compress_type;
	int min_space_saving_ratio;
	int *chunks;
	int parent_thread;
	int has_data;
	int src_fd;
	int is_free;
	int finish;
	int *error;
	vdfs4_hash_algorithm_func *hash_alg;
	int hash_len;
	struct vdfs4_aes_info aes_info;
	pthread_cond_t compress_cond;
	pthread_mutex_t compress_mutex;
	char exit;
};

struct thread_file_info {
	pthread_t thread_id;	/* ID returned by pthread_create() */
	int thread_num;	/* Application-defined thread # */
	struct vdfs4_sb_info *sbi;
	struct install_task *ptr;
	__u64 parent_id;
	int is_free;
	int has_data;
	int *count;
	int chunks_count;
	int finish;
	int *error;
	RSA *rsa_copy;
	pthread_cond_t compr_file_cond;
	pthread_mutex_t compr_file_mutex;
	pthread_mutex_t	write_uncompr_mutex;
	pthread_mutex_t	write_compr_mutex;
	pthread_mutex_t compress_mutex;
	pthread_mutex_t write_mutex;
	pthread_cond_t finished;
	char *compr_temp;
	char *uncompr_temp;
	char exit;
	int min_compressed_size;
};
struct thread_info *thread;
struct thread_file_info *thread_file;
pthread_cond_t file_finished;
pthread_mutex_t file_finished_mutex;
pthread_mutex_t files_count_mutex;
pthread_mutex_t find_record_mutex;
pthread_mutex_t	write_file_mutex;
pthread_mutex_t	thread_free_mutex;
pthread_cond_t thread_free_cond;
pthread_mutex_t	thread_file_free_mutex;
pthread_cond_t thread_file_free_cond;
void compress_file_thread(void *arg);
void init_threads(struct vdfs4_sb_info *sbi);
void compress_chunk_thread(void *arg);

__u64 get_metadata_size(struct vdfs4_sb_info *sbi);
int decompress(unsigned char *ibuff, int ilen, unsigned char *obuff, int *olen);

char *compressor_names[VDFS4_COMPR_NR];
int (*decompressor[VDFS4_COMPR_NR])(unsigned char *ibuff, int ilen,
		unsigned char *obuff, int *olen);
int vdfs4_cattree_cmpfn(struct vdfs4_generic_key *__key1,
		struct vdfs4_generic_key *__key2);
enum compr_type get_compression_type(char *type_string);

int (*compressor[VDFS4_COMPR_NR])(unsigned char *ibuff, int ilen,
		unsigned char *obuff, int olen, int *comp_size);
int encode_file(struct vdfs4_sb_info *sbi, char *src_filename, int dst_fd,
		int need_compress, int compress_type, off_t *rsl_filesize,
		RSA *rsa_key, int log_chunk_size,
		const char *tmp_dir, u_int64_t *block, int thread_num,
		vdfs4_hash_algorithm_func *hash_alg, int hash_len,
		int do_encrypt, const struct profiled_file* pfile);
int decode_file(const char *src_name, int dst_fd,
		int need_decompress,
		int *flags, AES_KEY *encryption_key);
int tune_files(struct vdfs4_sb_info *sbi,
		struct list_head *install_task_list);
int read_descriptor_info(int fd, struct vdfs4_comp_file_descr *descr,
		off_t *data_area_size, struct vdfs4_comp_extent **ext,
		int *compress_type, off_t file_size_offset,
		int *log_chunk_size);
int check_file_before_compress(const char *filename, int need_compress,
		mode_t *src_mode, int min_comp_size);
int analyse_existing_file(int rd_fd, int *compress_type,
		int *chunks_num, off_t *src_file_size, off_t *data_area_size,
		struct vdfs4_comp_extent **extents, int *is_authenticated,
		int *log_chunk_size,
		struct vdfs4_comp_file_descr* descr_ret);
int add_compression_info(int dst_fd, int chunks_num, int file_size,
		const struct vdfs4_comp_extent *ext,
		int compress_type, unsigned char **hash,
		RSA *rsa_key, off_t *c_size, int log_chunk_size, 
		vdfs4_hash_algorithm_func *hash_alg, int hash_len);

void clear_install_task_list(struct list_head *install_task_list);
int get_trees_offset(int image_fd, __u64 *catalog_offset,
		__u64 *xattr_offset, __u64 *extents_offset, int check_crc);
void init_threads(struct vdfs4_sb_info *sbi);
void fork_init(struct vdfs4_fork *_fork, u_int64_t begin, u_int64_t length,
		unsigned int block_size);
int disable_compression(struct install_task *task, struct vdfs4_sb_info* sbi);

#endif	/*__VDFS4_SQUASHFS_IMAGE_INSTALL_H__*/
