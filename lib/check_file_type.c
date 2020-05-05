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

#define ARRAY_SIZE(x) (sizeof((x))/sizeof((x)[0]))
typedef struct exec_file_format {
	unsigned char *hdrname;
	unsigned int hdrlen;
} exec_file_format;

#define MAX_HDRLEN	4	/* longest header len in exec file lists */
exec_file_format format_list[] = {
	{ (unsigned char *)"\x7f\x45\x4c\x46", 4 },
	{ (unsigned char *)"\x4d\x5a", 2 }
};

int is_exec_file_path(const char *path)
{
	int fd;
	int ret = 0;
	char err_msg[ERR_BUF_LEN];

	if (!path) {
		log_error("path is NULL\n");
		exit(EXIT_FAILURE);
	}

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		log_error("Failed to open file for checking exec err=%s path=%s",
				strerror_r(errno, err_msg, ERR_BUF_LEN), path);
		exit(EXIT_FAILURE);
	}

	ret = is_exec_file_fd(fd);
	if (ret < 0) {
		log_error("Failed to check path for exec file err=%s", ret);
		exit(EXIT_FAILURE);
	}

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

int is_exec_file_fd(int fd)
{
	unsigned char file_hdr[MAX_HDRLEN];
	char err_msg[ERR_BUF_LEN];
	int ret = 0;
	int matched = 0;
	unsigned int i;
	off_t orig_offset;
	unsigned int readlen;
	struct stat info;

	if (fd <= 0) {
		log_error("invalid fd(%d)\n", fd);
		exit(EXIT_FAILURE);
	}

	orig_offset = lseek(fd, 0, SEEK_CUR);
	if (orig_offset < 0) {
		log_error("orig_offset is smaller than 0\n");
		exit(EXIT_FAILURE);
	}
	if (lseek(fd, 0, SEEK_SET)) {
		log_error("offset zero setting failure\n");
		exit(EXIT_FAILURE);
	}

	/* getting file size */
	ret = fstat(fd, &info);
	if (ret) {
		log_error("Failed to get stats for checking exec err=%s",
				strerror_r(errno, err_msg, ERR_BUF_LEN));
		exit(EXIT_FAILURE);
	}

	/* decide readlen */
	if (info.st_size > MAX_HDRLEN)
		readlen = MAX_HDRLEN;
	else
		readlen = info.st_size;

	/* read header */
	ret = read(fd, file_hdr, readlen);
	if (ret != readlen) {
		log_error("Failed to read data for checking exec");
		exit(EXIT_FAILURE);
	}

	/* ALL exec file type check */
	for (i = 0; i < ARRAY_SIZE(format_list); i++) {
		/* small file checking is skipped */
		if (readlen < format_list[i].hdrlen)
			continue;

		/* matched found */
		if (!memcmp(file_hdr, format_list[i].hdrname,
					format_list[i].hdrlen)) {
			matched = 1;
			break;
		}
	}

	lseek(fd, orig_offset, SEEK_SET);
	return matched;
}

static int is_kernel_module(const char *filename)
{
	if (!strncmp(filename + strlen(filename)
				- strlen(".ko"), ".ko", strlen(".ko")))
		return 1;
	return 0;
}

int is_need_sign(int src_fd, const char *src_filename)
{
	if (is_kernel_module(src_filename))
		return 0;

	return is_exec_file_fd(src_fd);
}
