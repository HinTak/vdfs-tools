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

/*----------------------------------------------------------------------------*/
void set_permissions_from_st_mode(struct vdfs4_posix_permissions *permissions,
	mode_t st_mode, uid_t st_uid, gid_t st_gid)
{
	permissions->file_mode = st_mode;
	permissions->uid = st_uid;
	permissions->gid = st_gid;
}
/*----------------------------------------------------------------------------*/
void get_permissions_for_root_dir(struct vdfs4_posix_permissions *permissions)
{
	set_permissions_from_st_mode(permissions,
		S_IFDIR |
		S_IRUSR | S_IWUSR | S_IXUSR |
		S_IRGRP | S_IXGRP |
		S_IROTH | S_IXOTH,
		0, 0);
}

int get_permissions_for_root_dir_from_path(struct vdfs4_sb_info *sbi,
		struct vdfs4_posix_permissions *permissions)
{
	char err_msg[ERR_BUF_LEN];
	struct stat stat_info;
	int ret = lstat(sbi->root_path, &stat_info);
	if (ret) {
		log_error("Can't get stat information of root dir %s - %s",
					sbi->root_path,
					strerror_r(errno, err_msg, ERR_BUF_LEN));
		return ret;
	}
	permissions->file_mode = cpu_to_le16(stat_info.st_mode);
	if (IS_FLAG_SET(sbi->service_flags, ALL_ROOT)) {
		permissions->gid = 0;
		permissions->uid = 0;
	} else {
		permissions->gid = cpu_to_le32(stat_info.st_gid);
		permissions->uid = cpu_to_le32(stat_info.st_uid);
	}
	return 0;
}


