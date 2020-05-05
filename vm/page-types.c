/*
* page-types: Tool for querying page flags
*
* This program is free software; you can redistribute it and/or modify it
* under the terms of the GNU General Public License as published by the Free
* Software Foundation; version 2.
*
* This program is distributed in the hope that it will be useful, but WITHOUT
* ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
* FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
* more details.
*
* You should find a copy of v2 of the GNU General Public License somewhere on
* your Linux system; if not, write to the Free Software Foundation, Inc., 59
* Temple Place, Suite 330, Boston, MA 02111-1307 USA.
*
* Copyright (C) 2009 Intel corporation
*
* Authors: Wu Fengguang <fengguang.wu@intel.com>
*/

#define _FILE_OFFSET_BITS 64
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <getopt.h>
#include <limits.h>
#include <assert.h>
#include <ftw.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/fcntl.h>
#include <sys/mount.h>
#include <sys/statfs.h>
#include <sys/mman.h>
#include "kernel-page-flags.h"

#ifndef MAX_PATH
# define MAX_PATH 256
#endif

#ifndef STR
# define _STR(x) #x
# define STR(x) _STR(x)
#endif

/*
* pagemap kernel ABI bits
*/

#define PM_ENTRY_BYTES sizeof(uint64_t)
#define PM_STATUS_BITS 3
#define PM_STATUS_OFFSET (64 - PM_STATUS_BITS)
#define PM_STATUS_MASK (((1LL << PM_STATUS_BITS) - 1) << PM_STATUS_OFFSET)
#define PM_STATUS(nr) (((nr) << PM_STATUS_OFFSET) & PM_STATUS_MASK)
#define PM_PSHIFT_BITS 6
#define PM_PSHIFT_OFFSET (PM_STATUS_OFFSET - PM_PSHIFT_BITS)
#define PM_PSHIFT_MASK (((1LL << PM_PSHIFT_BITS) - 1) << PM_PSHIFT_OFFSET)
#define __PM_PSHIFT(x) (((uint64_t) (x) << PM_PSHIFT_OFFSET) & PM_PSHIFT_MASK)
#define PM_PFRAME_MASK ((1LL << PM_PSHIFT_OFFSET) - 1)
#define PM_PFRAME(x) ((x) & PM_PFRAME_MASK)

#define __PM_SOFT_DIRTY (1LL)
#define PM_PRESENT PM_STATUS(4LL)
#define PM_SWAP PM_STATUS(2LL)
#define PM_SOFT_DIRTY __PM_PSHIFT(__PM_SOFT_DIRTY)


/*
* kernel page flags
*/

#define KPF_BYTES 8
#define PROC_KPAGEFLAGS "/proc/kpageflags"

/* [32-] kernel hacking assistances */
#define KPF_RESERVED 32
#define KPF_MLOCKED 33
#define KPF_MAPPEDTODISK 34
#define KPF_PRIVATE 35
#define KPF_PRIVATE_2 36
#define KPF_OWNER_PRIVATE 37
#define KPF_ARCH 38
#define KPF_UNCACHED 39
#define KPF_SOFTDIRTY 40

/* [48-] take some arbitrary free slots for expanding overloaded flags
* not part of kernel API
*/
#define KPF_READAHEAD 48
#define KPF_SLOB_FREE 49
#define KPF_SLUB_FROZEN 50
#define KPF_SLUB_DEBUG 51

#define KPF_ALL_BITS ((uint64_t)~0ULL)
#define KPF_HACKERS_BITS (0xffffULL << 32)
#define KPF_OVERLOADED_BITS (0xffffULL << 48)
#define BIT(name) (1ULL << KPF_##name)
#define BITS_COMPOUND (BIT(COMPOUND_HEAD) | BIT(COMPOUND_TAIL))

static const char * const page_flag_names[] = {
[KPF_LOCKED]	= "L:locked",
[KPF_ERROR]	= "E:error",
[KPF_REFERENCED]	= "R:referenced",
[KPF_UPTODATE]	= "U:uptodate",
[KPF_DIRTY]	= "D:dirty",
[KPF_LRU]	= "l:lru",
[KPF_ACTIVE]	= "A:active",
[KPF_SLAB]	= "S:slab",
[KPF_WRITEBACK]	= "W:writeback",
[KPF_RECLAIM]	= "I:reclaim",
[KPF_BUDDY]	= "B:buddy",

[KPF_MMAP]	= "M:mmap",
[KPF_ANON]	= "a:anonymous",
[KPF_SWAPCACHE]	= "s:swapcache",
[KPF_SWAPBACKED]	= "b:swapbacked",
[KPF_COMPOUND_HEAD]	= "H:compound_head",
[KPF_COMPOUND_TAIL]	= "T:compound_tail",
[KPF_HUGE]	= "G:huge",
[KPF_UNEVICTABLE]	= "u:unevictable",
[KPF_HWPOISON]	= "X:hwpoison",
[KPF_NOPAGE]	= "n:nopage",
[KPF_KSM]	= "x:ksm",
[KPF_THP]	= "t:thp",

[KPF_RESERVED]	= "r:reserved",
[KPF_MLOCKED]	= "m:mlocked",
[KPF_MAPPEDTODISK]	= "d:mappedtodisk",
[KPF_PRIVATE]	= "P:private",
[KPF_PRIVATE_2]	= "p:private_2",
[KPF_OWNER_PRIVATE]	= "O:owner_private",
[KPF_ARCH]	= "h:arch",
[KPF_UNCACHED]	= "c:uncached",
[KPF_SOFTDIRTY]	= "f:softdirty",

[KPF_READAHEAD]	= "I:readahead",
[KPF_SLOB_FREE]	= "P:slob_free",
[KPF_SLUB_FROZEN]	= "A:slub_frozen",
[KPF_SLUB_DEBUG]	= "E:slub_debug",
};


static const char *const debugfs_known_mountpoints[] = {
"/sys/kernel/debug",
"/debug",
0,
};

/*
* data structures
*/

static int	opt_list;	/* list pages (in ranges) */
const char *opt_file;

#define MAX_ADDR_RANGES 1024
#define MAX_VMAS 10240


#define MAX_BIT_FILTERS 64
static uint64_t	opt_mask;


static int	page_size;

static int	pagemap_fd;
static int	kpageflags_fd;

#define HASH_SHIFT 13
#define HASH_SIZE (1 << HASH_SHIFT)
#define HASH_MASK (HASH_SIZE - 1)
#define HASH_KEY(flags) (flags & HASH_MASK)


/*
* helper functions
*/

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define min_t(type, x, y) ({ \
type __min1 = (x); \
type __min2 = (y); \
__min1 < __min2 ? __min1 : __min2; })

#define max_t(type, x, y) ({ \
type __max1 = (x); \
type __max2 = (y); \
__max1 > __max2 ? __max1 : __max2; })

static void fatal(const char *x, ...)
{
	va_list ap;

	va_start(ap, x);
	vfprintf(stderr, x, ap);
	va_end(ap);
	exit(EXIT_FAILURE);
}

static int checked_open(const char *pathname, int flags)
{
	int fd = open(pathname, flags);

	if (fd < 0) {
		perror(pathname);
		exit(EXIT_FAILURE);
	}

	return fd;
}

/*
* pagemap/kpageflags routines
*/

static unsigned long do_u64_read(int fd, char *name,
uint64_t *buf,
unsigned long index,
unsigned long count)
{
	long bytes;

	if (index > ULONG_MAX / 8)
		fatal("index overflow: %lu\n", index);

	bytes = pread(fd, buf, count * 8, (off_t)index * 8);
	if (bytes < 0) {
		perror(name);
	exit(EXIT_FAILURE);
	}
	if (bytes % 8)
		fatal("partial read: %lu bytes\n", bytes);

	return bytes / 8;
}

static unsigned long kpageflags_read(uint64_t *buf,
unsigned long index,
unsigned long pages)
{
	return do_u64_read(kpageflags_fd, PROC_KPAGEFLAGS, buf, index, pages);
}

static unsigned long pagemap_read(uint64_t *buf,
unsigned long index,
unsigned long pages)
{
	return do_u64_read(pagemap_fd, "/proc/pid/pagemap", buf, index, pages);
}

static unsigned long pagemap_pfn(uint64_t val)
{
	unsigned long pfn;

	if (val & PM_PRESENT)
		pfn = PM_PFRAME(val);
	else
	pfn = 0;

	return pfn;
}


/*
* page flag filters
*/

static int bit_mask_ok(uint64_t flags)
{
	if ((flags & opt_mask) == 0)
		return 0;
	return 1;
}


#define KPAGEFLAGS_BATCH (64 << 10) /* 64k pages */
#define PAGEMAP_BATCH (64 << 10)



static void usage(void)
{
	printf("page-types dir_path\n");
}

static void walk_file(const char *name, const struct stat *st)
{
	uint8_t vec[PAGEMAP_BATCH];
	uint64_t buf[PAGEMAP_BATCH], flags;
	unsigned long pages, pfn, i;
	int fd;
	off_t off;
	ssize_t len;
	void *ptr;
	int first = 1;

	fd = checked_open(name, O_RDONLY|O_NOATIME|O_NOFOLLOW);

	for (off = 0; off < st->st_size; off += len) {
		len = PAGEMAP_BATCH * page_size;
		if (len > st->st_size - off)
			len = (st->st_size - off + page_size - 1)
				& ~(page_size-1);
		pages = len / page_size;

		ptr = mmap(NULL, len, PROT_READ, MAP_SHARED, fd, off);
		if (ptr == MAP_FAILED)
			fatal("mmap failed: %s", name);

		/* turn off readahead */
		if (madvise(ptr, len, MADV_RANDOM))
			fatal("madvice failed: %s", name);

		/* determine cached pages */
		if (mincore(ptr, len, vec))
			fatal("mincore failed: %s", name);

		/* populate ptes */
		for (i = 0; i < pages ; i++) {
			if (!(vec[i] & 1))
				continue;
			(void)*(volatile int *)(ptr + i * page_size);
		}

		if (pagemap_read(buf, (unsigned long)ptr / page_size,
		pages) != pages)
			fatal("cannot read pagemap");

		/* turn off harvesting reference bits */
		if (madvise(ptr, len, MADV_SEQUENTIAL))
			fatal("madvice failed: %s", name);
		munmap(ptr, len);

		for (i = 0; i < pages; i++) {
			pfn = pagemap_pfn(buf[i]);
			if (!pfn)
				continue;
			if (!kpageflags_read(&flags, pfn, 1))
				continue;
			if (first && bit_mask_ok(flags)) {
				printf("%s\n", name);
				first = 0;
				break;
			}
		}
	}
	close(fd);
}

int walk_tree(const char *name, const struct stat *st, int type, struct FTW *f)
{
	(void)f;
	switch (type) {
	case FTW_F:
		if (S_ISREG(st->st_mode))
			walk_file(name, st);
		break;
	case FTW_DNR:
		fprintf(stderr, "cannot read dir: %s\n", name);
		break;
	}
	return 0;
}

static void walk_page_cache(void)
{
	struct stat st;

	kpageflags_fd = checked_open(PROC_KPAGEFLAGS, O_RDONLY);
	pagemap_fd = checked_open("/proc/self/pagemap", O_RDONLY);

	if (stat(opt_file, &st))
		fatal("stat failed: %s\n", opt_file);

	if (S_ISREG(st.st_mode)) {
		walk_file(opt_file, &st);
	} else if (S_ISDIR(st.st_mode)) {
		/* do not follow symlinks and mountpoints */
		if (nftw(opt_file, walk_tree, 64, FTW_MOUNT | FTW_PHYS) < 0)
			fatal("nftw failed: %s\n", opt_file);
		} else
			fatal("unhandled file type: %s\n", opt_file);

	close(kpageflags_fd);
	close(pagemap_fd);
}

static const struct option opts[] = {
{ "help" , 0, NULL, 'h' },
{ NULL , 0, NULL, 0 }
};

int main(int argc, char *argv[])
{
	int c;
	while ((c = getopt_long(argc, argv, "h", opts, NULL)) != -1)
		if (c == 'h') {
			usage();
			exit(0);
		} else if (c > 0 || !argv[optind]) {
			usage();
			exit(1);
		}
	if (!argv[optind]) {
		usage();
		exit(1);
	}
	page_size = getpagesize();
	opt_file = argv[optind];
	opt_list = 1;
	opt_mask = (1 << KPF_WRITEBACK) | (1 << KPF_DIRTY);
	walk_page_cache();
	return 0;
}
