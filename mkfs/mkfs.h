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

#ifndef __MKFS_H__
#define __MKFS_H__

#include <vdfs_tools.h>
#include <compress.h>
#include <vdfs4.h>
#define DEBUG 1


/**
 * @brief       Parse parameters from mkfs.vdfs4 run command line.
 * @param [in]  argc    Number of command line parameters.
 * @param [in]  argv[]  An array with command line parameters strings.
 * @param [in]  sbi     A pointer to the structure containing runtime
 *		parameters of vdfs4 superblock.
 * @return		0 if parced successfully, or error
 */
int parse_cmd(int argc, char *argv[], struct vdfs4_sb_info *sbi);
u_int64_t read_value_with_multiplier(const char *value);
int insert_metadata(struct vdfs4_sb_info *sbi, char * dir_path, int parent_id,
		__u64 *object_count);
int insert_record(struct vdfs4_sb_info *sbi, char * path, char * name,
		struct stat *stat_info, int uuid, int parent_id,
		__u64 *obj_count);
int insert_data(struct vdfs4_sb_info *sbi, char * dir_path, __u64 parent_id,
		u64 *file_offset_abs);
int fill_image_metadata(struct vdfs4_sb_info *sbi);

__u64 get_metadata_size(struct vdfs4_sb_info *sbi);
int preprocess_sq_tasklist(struct vdfs4_sb_info *sbi, struct list_head *list,
		FILE *list_file);
void wait_finish(int *count);
int get_free_file_thread(void);
int disable_compression(struct install_task *task, struct vdfs4_sb_info* sbi);
#endif /* __MKFS_H__ */
