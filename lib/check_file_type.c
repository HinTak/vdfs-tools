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
 * */
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#include "vdfs_tools.h"

#include <elf.h>
#include <endian.h>
#ifndef ElfW
# if ELFCLASSM == ELFCLASS32
#  define ElfW(x)  Elf32_ ## x
#  define ELFW(x)  ELF32_ ## x
# else
#  define ElfW(x)  Elf64_ ## x
#  define ELFW(x)  ELF64_ ## x
# endif
#endif

#define CHECK_BYTES_COUNT (sizeof(ElfW(Ehdr)))

UNUSED static int is_pfm_file(char *buffer, int length)
{
	if (length < 4)
		return 0;

	if (((*((__u32 *)buffer) & 0xff00ffff) == 0x12000100) ||
			((*(__u32 *)buffer & 0xff00ffff) == 0x02000100))
		return 1;

	return 0;
}

 UNUSED static int is_pdp_11_file(char *buffer, int length)
{
	if (length < 3)
		return 0;

	if (((*((__u16 *)buffer) & 0xffff) == 0x109))
		return 1;

	return 0;
}

static int is_elf_file(char *buffer, int length)
{
	if (length < 4)
		return 0;

	if (buffer[0] == 0x7f && buffer[1] == 'E' && buffer[2] == 'L' &&
			buffer[3] == 'F')
		return 1;

	return 0;
}

int is_elf_file_fd(int fd)
{
	#define ELF_HDR_LEN 4
	unsigned char elf_hdr[ELF_HDR_LEN] = {0x7F, 0x45, 0x4C, 0x46}; //0x7F,'E','L','F'
	unsigned char fil_hdr[ELF_HDR_LEN];
	char err_msg[ERR_BUF_LEN];
	int ret;
	off_t orig_offset;
	struct stat info;
	if(fd <= 0)
		return -EINVAL;


	if((orig_offset = lseek(fd, 0, SEEK_CUR)) < 0)
		return -errno;
	if(lseek(fd, 0, SEEK_SET))
		return -errno;

	ret = fstat(fd, &info);
	if(ret) {
		ret = -errno;
		log_error("Failed to get stats for checking ELF err=%s",
				strerror_r(errno, err_msg, ERR_BUF_LEN));
		goto end;
	} else if(info.st_size < ELF_HDR_LEN) {
		// files less than 4 bytes are not ELF's
		ret = 0;
		goto end;
	}

	if(read(fd, fil_hdr, ELF_HDR_LEN) != ELF_HDR_LEN) {
		log_error("Failed to read data for checking ELF");
		ret = -EIO;
		goto end;
	}

	ret = !memcmp(elf_hdr, fil_hdr, ELF_HDR_LEN) ? 1 : 0;

end:
	lseek(fd, orig_offset, SEEK_SET);
	return ret;
}

int is_elf_file_path(const char* path)
{
	int fd;
	int ret = 0;
	if(!path)
		return -1;
	char err_msg[ERR_BUF_LEN];

	fd = open(path, O_RDONLY);

	if(fd < 0) {
		ret = -errno;
		log_error("Failed to open file for checking ELF err=%s path=%s",
				strerror_r(errno, err_msg, ERR_BUF_LEN), path);
		return ret;
	}

	ret = is_elf_file_fd(fd);
	if(ret < 0)
		log_error("Failed to check path for ELF file err=%s", ret);

	close(fd);
	return ret;
}


UNUSED static int is_ascii_file(char *buffer, int length)
{
	int count;
	int c;

	if (length == 0)
		return 0;
	for (count = 0; count < length; count++) {
		c = (int)buffer[count];
		if (!isascii(c))
			return 0;
	}

	return 1;
}

static int is_kernel_module(const char *filename)
{
	if (!strncmp(filename + strlen(filename)
				- strlen (".ko"), ".ko", strlen(".ko")))
		return 1;
	return 0;
}

int is_need_sign(int src_fd, const char *src_filename)
{
	char buffer[CHECK_BYTES_COUNT];
	int ret, check_bytes_count;

	if (is_kernel_module(src_filename))
		return 0;

	memset(buffer, 0, CHECK_BYTES_COUNT);
	ret = read(src_fd, buffer, CHECK_BYTES_COUNT);
	if (ret == -1) {
		ret = errno;
		perror("cannot read data from a file");
		return ret;
	}
	check_bytes_count = ret;
	ret = lseek(src_fd, 0, SEEK_SET);
	if (ret == -1) {
		ret = errno;
		perror("cannot set file position");
		return ret;
	}

	if (is_elf_file(buffer, check_bytes_count))
		return 1;

	return 0;
}
