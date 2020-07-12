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

#include "compress.h"
#include <encrypt.h>
#include "vdfs_tools.h"
#include "zlib.h"
#include <lzo/lzoconf.h>
#include <lzo/lzo1x.h>
#include <openssl/aes.h>

int decompress_zlib(unsigned char *ibuff, int ilen,
		unsigned char *obuff, int *olen)
{
	static z_stream strm;
	int ret;

	strm.zalloc = Z_NULL;
	strm.zfree = Z_NULL;
	strm.opaque = Z_NULL;

	strm.avail_in = ilen;
	strm.next_in = (unsigned char *)ibuff;
	strm.avail_out = *olen;
	strm.next_out = (unsigned char *)obuff;

	ret = inflateInit(&strm);
	if (ret != Z_OK) {
		log_error("zlib_inflateInit error %d", ret);
		return -1;
	}

	ret = inflate(&strm, Z_SYNC_FLUSH);

	if ((ret == Z_OK) || (ret == Z_STREAM_END)) {
		inflateEnd(&strm);
		*olen = strm.total_out;
		return 0;
	}
	log_error("zlib_inflate error %d", ret);
	return -2;
}

int decompress_gzip(unsigned char *ibuff, int ilen,
		unsigned char *obuff, int *olen)
{
	static z_stream strm;
	int ret;
	unsigned long bytes = PAGE_SIZE;
	strm.zalloc = Z_NULL;
	strm.zfree = Z_NULL;
	strm.opaque = Z_NULL;
	strm.total_in = 0;
	strm.avail_in = ilen;
	strm.next_in = (unsigned char *)ibuff;
	strm.avail_out = *olen;
	strm.next_out = (unsigned char *)obuff;
	strm.total_out = 0;
	ret = inflateInit2(&strm, (15+16)/*-MAX_WBITS*/);
	/*res = deflateInit2(strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED,\
				 (12+16), 8, Z_DEFAULT_STRATEGY);
	ret = inflateInit(&strm);
	log_info("ret =%d, before avail_in = %d, avail_out = %d,"
			" total_out = %d", ret, strm.avail_in,
			strm.avail_out, strm.total_out);*/
	if (ret != Z_OK) {
		log_error("zlib_inflateInit error %d", ret);
		return -1;
	}

	ret = inflate(&strm, Z_FINISH);

	if ((ret == Z_OK) || (ret == Z_STREAM_END)) {
		inflateEnd(&strm);
		*olen = strm.total_out;
		return 0;
	}

	ret = uncompress(obuff, &bytes, ibuff, ilen);
	if ((ret == Z_OK) || (ret == Z_STREAM_END)) {
		inflateEnd(&strm);
		*olen = strm.total_out;
		return 0;
	}
	log_error("zlib_inflate error %d", ret);
	return -2;
};

static int get_sign_length_from_type(int type)
{
	switch (type) {
		case VDFS4_SIGN_RSA1024:
			return 128;
		case VDFS4_SIGN_RSA2048:
			return 256;
		default:
			return 0;
	}
}

int read_descriptor_info(int fd, struct vdfs4_comp_file_descr *descr,
		off_t *data_area_size, struct vdfs4_comp_extent **ext,
		int *compress_type, off_t file_size_offset, int *log_chunk_size)
{
	int ret = 0;
	loff_t first_ext_pos;
	int ext_n = 0;
	int table_size, descr_size;
	int hash_len = 0, sign_len;
	if (pread(fd, descr, sizeof(struct vdfs4_comp_file_descr),
			file_size_offset - sizeof(*descr)) == -1) {
		ret = -errno;
		log_error("cannot read from file(err:%d)", errno);
		return ret;
	}
	*log_chunk_size = le32_to_cpu(descr->log_chunk_size);
	if (!memcmp(descr->magic + 1, VDFS4_COMPR_ZIP_FILE_DESCR_MAGIC,
			sizeof(descr->magic) - 1))
		*compress_type = VDFS4_COMPR_ZLIB;
	else if (!memcmp(descr->magic + 1, VDFS4_COMPR_GZIP_FILE_DESCR_MAGIC,
			sizeof(descr->magic) - 1))
		*compress_type = VDFS4_COMPR_GZIP;
	else if (!memcmp(descr->magic + 1, VDFS4_COMPR_LZO_FILE_DESCR_MAGIC,
			sizeof(descr->magic) - 1))
		*compress_type = VDFS4_COMPR_LZO;
	else
		return -EINVAL;

	descr_size = sizeof(struct vdfs4_comp_file_descr);

	if (le16_to_cpu(descr->layout_version) == VDFS4_COMPR_LAYOUT_VER_05) {
		descr->sign_type = VDFS4_SIGN_RSA1024;
		memset(descr->reserved, 0, sizeof(descr->reserved));
		descr_size = VDFS4_COMPR_FILE_DESC_LEN_05;
	}

	ext_n = le16_to_cpu(descr->extents_num);
	sign_len = get_sign_length_from_type(descr->sign_type);
	if ((unsigned) ext_n > file_size_offset / sizeof(struct vdfs4_comp_extent)
			|| ext_n < 0)
		return -EINVAL;
	first_ext_pos = (loff_t)descr_size +
			(((loff_t)ext_n) * ((loff_t)sizeof(struct vdfs4_comp_extent)));
	if (descr->magic[0] == VDFS4_MD5_AUTH ) {
		hash_len = VDFS4_MD5_HASH_LEN;
		first_ext_pos += hash_len * (ext_n + 1) + sign_len;
	} else if (descr->magic[0] == VDFS4_SHA1_AUTH) {
		hash_len = VDFS4_SHA1_HASH_LEN;
		first_ext_pos += hash_len * (ext_n + 1) + sign_len;
	} else if (descr->magic[0] == VDFS4_SHA256_AUTH) {
		hash_len = VDFS4_SHA256_HASH_LEN;
		first_ext_pos += hash_len * (ext_n + 1) + sign_len;
	}
	first_ext_pos = file_size_offset - first_ext_pos;
	*data_area_size = first_ext_pos;
	if (ext_n != 0) {
		*ext = realloc(*ext, ext_n * sizeof(struct vdfs4_comp_extent));
		if (!*ext)
			return -ENOMEM;
		table_size = ext_n * sizeof(struct vdfs4_comp_extent);
		if (pread(fd, *ext, table_size, first_ext_pos) == -1) {
			ret = errno;
			log_error("cannot read from file(err:%d)", errno);
			return ret;
		}
	}

	if (lseek(fd, 0L, SEEK_SET) == -1)
		return errno;
	return 0;
}

int decompress_lzo(unsigned char *ibuff, int ilen,
		unsigned char *obuff, int *olen)
{
	int ret = 0;
	int new_len = *olen;
	ret = lzo_init();
	if (ret != LZO_E_OK) {
		log_error("internal error - lzo_init() failed !!!\n");
		goto exit;
	}
	ret = lzo1x_decompress_safe(ibuff, ilen, obuff, (lzo_uintp)&new_len,
			NULL);
	if ((ret != LZO_E_OK && new_len != *olen)) {
		log_error("%d: compressed data violation\n", ret);
		return ret;
	}
	*olen = new_len;
exit:
	return ret;
}

int not_supported_decompressor(unsigned char *ibuff, int ilen,
		unsigned char *obuff, int *olen)
{
	/* Silence gcc warnings */
	(void) ibuff;
	(void) ilen;
	(void) obuff;
	(void) olen;

	log_error("Decompressor is not supported");
	return -ENOTSUP;
}

int decompress_file(int src_fd, int dst_fd, unsigned int extents_num,
		int compress_type, struct vdfs4_comp_extent *extents,
		int log_chunk_size,
		struct vdfs4_comp_file_descr *descr, AES_KEY *encryption_key)
{
	int ret = 0;
	unsigned have = 0;
	unsigned char *in;
	unsigned char *out;

	/* allocate inflate state */
	struct vdfs4_comp_extent *cur_ext = NULL;
	u_int32_t ext_n = 0;
	ssize_t avail_in;
	int out_len;
	u64 aes_counter;
	off_t init_offset = lseek(src_fd, 0, SEEK_CUR);
	assert(compress_type >= VDFS4_COMPR_ZLIB &&
	       compress_type < VDFS4_COMPR_NR);
	int chunk_size = 1 << log_chunk_size;

	/* why chunk_size*2? look on comments in
	 * compress_file() and force_compress
	 */
	in = malloc(chunk_size*2);
	out = malloc(chunk_size*2);

	if (!in || !out)
		goto exit;

	while (ext_n < extents_num) {
		/* decompress until deflate stream ends or end of file */
		cur_ext = extents + ext_n;
		lseek(src_fd, cur_ext->start + init_offset, SEEK_SET);
		avail_in = read(src_fd, in, cur_ext->len_bytes);
		if (avail_in == 0) {
			ret = 0;
			break;
		} else if (avail_in == -1 || avail_in != (int)cur_ext->len_bytes) {
			ret = -errno;
			goto exit;
		}

		if (cur_ext->flags & VDFS4_CHUNK_FLAG_ENCRYPTED) {
			if (encryption_key != NULL) {
				aes_counter = (ext_n << log_chunk_size) / AES_BLOCK_SIZE;
				encrypt_chunk(in, out, descr->aes_nonce,
						encryption_key, avail_in,
						aes_counter);
				memcpy(in, out, avail_in);
			} else {
				log_error("We have encrypted files,"
						" but no key to decode them. Abort!\n");
				ret = -ENOENT;
				goto exit;
			}
		}

		if (cur_ext->flags & VDFS4_CHUNK_FLAG_UNCOMPR) {
			have = avail_in;
			memcpy(out, in, have);
			goto write;
		}
		out_len = chunk_size;
		ret = decompressor[compress_type](in, avail_in, out, &out_len);
		if (ret)
			goto exit;
		have = out_len;
write:
		ret = write(dst_fd, out, have);
		if (ret != (ssize_t)have) {
			if (ret < 0)
				ret = -errno;
			else
				ret = -ENOSPC;
			goto exit;
		}
		ret = 0;
		ext_n++;
	}
exit:

	free(in);
	free(out);
	return ret;
}

int add_footer_info(int src_fd, int dst_fd, off_t table_size)
{
	int sz, ret = 0;
	char *buf = malloc(table_size);
	if (!buf)
		return -ENOMEM;

	sz = read(src_fd, buf, table_size);
	if (sz != table_size) {
		ret = -errno;
		goto free_buf;
	}

	sz = write(dst_fd, buf, table_size);
	if (sz != table_size)
		ret = -errno;

free_buf:
	free(buf);
	return ret;
}

int decode_file(const char *src_name, int dst_fd, int need_decompress,
		int *flags, AES_KEY *encryption_key)
{
	int ret = 0;
	struct vdfs4_comp_extent *exts = NULL;
	int compress_type, chunks_num;
	off_t src_file_size, data_area_size;
	int src_fd = open(src_name, O_RDONLY);
	int is_authenticated = 0;
	int log_chunk_size;
	struct vdfs4_comp_file_descr descriptor;
	memset(&descriptor, 0, sizeof(struct vdfs4_comp_file_descr));
	if (src_fd == -1)
		return errno;

	ret = analyse_existing_file(src_fd, &compress_type,
			&chunks_num, &src_file_size, &data_area_size, &exts,
			&is_authenticated, &log_chunk_size, &descriptor);
	if (ret)
		goto free_exts;
	*flags = (is_authenticated << VDFS4_AUTH_FILE);
	lseek(src_fd, 0, SEEK_SET);


	if (need_decompress && compress_type == VDFS4_COMPR_NONE) {
		log_error("Request to decompress non-compressed file");
		ret = -EINVAL;
		goto free_exts;
	}

	if (need_decompress) {
		ret = decompress_file(src_fd, dst_fd, chunks_num,
				compress_type, exts, log_chunk_size,
				&descriptor, encryption_key);
		if (ret)
			log_error("Fail while decompression - (ret:%d)", ret);
	}

free_exts:
	free(exts);
	if (src_fd != -1)
		close(src_fd);
	return ret;
}


/* Should correspond to enum compr_type*/
int (*decompressor[VDFS4_COMPR_NR])(unsigned char *ibuff, int ilen,
		unsigned char *obuff, int *olen) = {
	[VDFS4_COMPR_ZLIB]	= decompress_zlib,
	[VDFS4_COMPR_LZO]	= decompress_lzo,
	[VDFS4_COMPR_XZ]		= not_supported_decompressor,
	[VDFS4_COMPR_LZMA]	= not_supported_decompressor,
	[VDFS4_COMPR_GZIP]	= decompress_gzip,
};
