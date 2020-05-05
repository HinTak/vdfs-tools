/* zpipe.c: example of proper use of zlib's inflate() and deflate()
   Not copyrighted -- provided to the public domain
   Version 1.4	11 December 2005  Mark Adler */

/* Version history:
   1.0	30 Oct 2004  First version
   1.1	 8 Nov 2004  Add void casting for unused return values
					 Use switch statement for inflate() return values
   1.2	 9 Nov 2004  Add assertions to document zlib guarantees
   1.3	 6 Apr 2005  Remove incorrect assertion in inf()
   1.4	11 Dec 2005  Add hack to avoid MSDOS end-of-line conversions
					 Avoid some compiler warnings for input and output buffers
 */

/* Origina source and explanation is here:
 * http://www.zlib.net/zlib_how.html */

#define _GNU_SOURCE

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <zlib.h>
#include <lzo/lzoconf.h>
#include <lzo/lzo1x.h>
#include <vdfs_tools.h>
#include <compress.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <ctype.h>

int processors = 1;
char *compressor_names[VDFS4_COMPR_NR] = {
	[VDFS4_COMPR_UNDEF] = NULL,
	[VDFS4_COMPR_ZLIB] = "zlib",
	[VDFS4_COMPR_LZO] = "lzo",
	[VDFS4_COMPR_XZ] = "xz",
	[VDFS4_COMPR_LZMA] = "lzma",
	[VDFS4_COMPR_GZIP] = "gzip",
	[VDFS4_COMPR_NONE] = NULL,
};

/* value of 0 means 1 byte alignment */
size_t compr_align[VDFS4_COMPR_NR][ALIGN_NR] = {
		[VDFS4_COMPR_UNDEF]	= {[ALIGN_START] = 0,	[ALIGN_LENGTH] = 0},
		[VDFS4_COMPR_ZLIB]	= {[ALIGN_START] = 8,	[ALIGN_LENGTH] = 64},
		[VDFS4_COMPR_LZO]	= {[ALIGN_START] = 0,	[ALIGN_LENGTH] = 0},
		[VDFS4_COMPR_XZ]	= {[ALIGN_START] = 0,	[ALIGN_LENGTH] = 0},
		[VDFS4_COMPR_LZMA]	= {[ALIGN_START] = 0,	[ALIGN_LENGTH] = 0},
		[VDFS4_COMPR_GZIP]	= {[ALIGN_START] = 8,	[ALIGN_LENGTH] = 64},
		[VDFS4_COMPR_NONE]	= {[ALIGN_START] = 0,	[ALIGN_LENGTH] = 0},
};

static const uint16_t supported_compressed_layouts[] = {
	/* current layout */
	VDFS4_COMPR_LAYOUT_VER_06,
	/* with RSA1024 hardcoded */
	VDFS4_COMPR_LAYOUT_VER_05,
};

#define VDFS4_NUM_OF_SUPPORTED_COMPR_LAYOUTS \
	(sizeof(supported_compressed_layouts)/sizeof(supported_compressed_layouts[0]))


/* Compress from file source to file dest until EOF on source.
   def() returns Z_OK on success, Z_MEM_ERROR if memory could not be
   allocated for processing, Z_STREAM_ERROR if an invalid compression
   level is supplied, Z_VERSION_ERROR if the version of zlib.h and the
   version of the library linked do not match, or Z_ERRNO if there is
   an error reading or writing the files. */
enum compr_type get_compression_type(char *type_string)
{
	int comp_type;
	for (comp_type = 0; comp_type < VDFS4_COMPR_NR; comp_type++)
		if (!strcmp(type_string, "default"))
			return VDFS4_COMPR_ZLIB;
		else if (compressor_names[comp_type] &&
		    !strcmp(type_string, compressor_names[comp_type]))
			return comp_type;
	return -1;
}

static void clear_tuned_flags(__le32 *flags)
{
	*flags &= ~((1<<VDFS4_COMPRESSED_FILE) |
			(1<<VDFS4_AUTH_FILE) |
			(1<<VDFS4_READ_ONLY_AUTH) |
			(1<<VDFS4_ENCRYPTED_FILE) |
			(1<<VDFS4_NOCOMPRESS_FILE));
}

int add_compression_info(int dst_fd, int chunks_num, int file_size,
		const struct vdfs4_comp_extent *ext,
		int compress_type, unsigned char **hash,
		RSA *rsa_key, off_t *c_size, int log_chunk_size,
		vdfs4_hash_algorithm_func *hash_alg, int hash_len)
{
	int ret = 0;
	struct vdfs4_comp_file_descr _descr, *descr = &_descr;
	char *magic = NULL;
	ssize_t written, aligned_size;
	u_int32_t crc;
	size_t h_size;
	struct stat f_stat;
	char buffer[VDFS4_BLOCK_SIZE];
	memset(descr, 0x0, sizeof(*descr));
	memset(buffer, 0x0, VDFS4_BLOCK_SIZE);

	if (chunks_num == 0)
		return 0;
	/* align the dst_fd to block size */
	ret = fstat(dst_fd, &f_stat);
	if (ret == -1)
		return ret;

	aligned_size = ALIGN(*c_size, sizeof(struct vdfs4_comp_extent))
			- *c_size;
	/*ret = ftruncate(dst_fd, aligned_size);
	if (ret == -1)
		return ret;*/

	lseek(dst_fd, f_stat.st_size + aligned_size, SEEK_SET);
	*c_size += aligned_size;
	switch (compress_type) {
	case VDFS4_COMPR_ZLIB:
		magic = VDFS4_COMPR_ZIP_FILE_DESCR_MAGIC;
		break;
	case VDFS4_COMPR_GZIP:
		magic = VDFS4_COMPR_GZIP_FILE_DESCR_MAGIC;
		break;
	case VDFS4_COMPR_LZO:
		magic = VDFS4_COMPR_LZO_FILE_DESCR_MAGIC;
		break;
	default:
		log_error("Incorrect compress type %d", compress_type);
		ret = -EINVAL;
		goto exit;
	}

	if (*hash) {
		if (hash_alg == MD5)
			descr->magic[0] = VDFS4_MD5_AUTH;
		else if (hash_alg == SHA256)
			descr->magic[0] = VDFS4_SHA256_AUTH;
		else if (hash_alg == SHA1)
			descr->magic[0] = VDFS4_SHA1_AUTH;
	} else
		descr->magic[0] = VDFS4_COMPR_DESCR_START;

	memcpy(descr->magic + 1, magic, sizeof(descr->magic) - 1);
	descr->extents_num = chunks_num;
	descr->unpacked_size = (__le64)file_size;
	descr->layout_version = VDFS4_COMPR_LAYOUT_VER;
	descr->log_chunk_size = log_chunk_size;
	descr->sign_type = get_sign_type(rsa_key);

	h_size = (size_t)(chunks_num + 1) * (size_t)hash_len +
			(size_t)get_sign_length(rsa_key);

	if (rsa_key) {
		unsigned char *extended_hash_table = NULL;

		extended_hash_table = realloc(*hash, h_size);
		if (extended_hash_table)
			*hash = extended_hash_table;
		else {
			errno = ENOMEM;
			return -1;
		}
		/*Sign tuned file*/
		assert(hash);

		hash_alg((const unsigned char *)descr,
			VDFS4_COMPR_FILE_DESC_LEN,
			*hash + hash_len * chunks_num);

		ret = sign_rsa(*hash, hash_len *
				(chunks_num + 1), *hash + hash_len *
				(chunks_num + 1), rsa_key, hash_alg, hash_len);
		if (ret) {
			log_error("Error when signing hash");
			return ret;
		}
	}
	crc = crc32_body(0, (const __u8 *)ext, chunks_num * sizeof(*ext));
	if (*hash)
		crc = crc32_body(crc, *hash, h_size);
	descr->crc = crc32_body(crc, (const __u8 *)descr, sizeof(*descr));

	/* write chunk table */
	written = write(dst_fd, ext, chunks_num * sizeof(*ext));
	if (written != (ssize_t)(sizeof(*ext) * chunks_num)) {
		errno = (written == -1) ? errno : ENOSPC;
		goto exit;
	} else
		*c_size += written;

	/* write hash table */
	if (*hash) {
		written = write(dst_fd, *hash, h_size);
		if (written != (ssize_t)h_size) {
			errno = (written == -1) ? errno : ENOSPC;
			goto exit;
		} else
			*c_size += written;
	}


	/* write descriptor */
	written = write(dst_fd, descr, sizeof(*descr));
	if (written != sizeof(*descr)) {
		errno = (written == -1) ? errno : ENOSPC;
		goto exit;
	} else {
		*c_size += written;
	}
exit:
	return ret;
}
#define LZO_OUT_LEN	()

static int compress_chunk(unsigned char *in, int ilen,
		unsigned char *out, int olen, int compress_type,
		struct vdfs4_comp_extent *c_ext, int *c_size,
		int volume_chunk_size, int min_space_saving_ratio)
{
	int ret = 0;
	int space_saving_ratio = 0;
	int compressed_size = -1;
	size_t align;

	ret = compressor[compress_type](in, ilen, out, olen, &compressed_size);
	if(ret)
		return ret;
	space_saving_ratio = 100 - ((compressed_size * 100) / ilen);

	if(space_saving_ratio <= min_space_saving_ratio)
		goto chunk_uncomp;
	else
		goto chunk_comp;

chunk_uncomp:
	memcpy(out, in, ilen);
	c_ext->len_bytes = ilen;
	c_ext->flags |= VDFS4_CHUNK_FLAG_UNCOMPR;
	*c_size = 0;
	return 0;
chunk_comp:
	align = compr_align[compress_type][ALIGN_LENGTH];
	if(c_ext->flags & VDFS4_CHUNK_FLAG_ENCRYPTED)
		encrypted_chunk_align(&align, ALIGN_LENGTH);

	c_ext->len_bytes = compressed_size;
	if(align)
		c_ext->len_bytes = ALIGN(c_ext->len_bytes, align);

	if(c_ext->len_bytes > (unsigned)volume_chunk_size)
		goto chunk_uncomp;

	*c_size = c_ext->len_bytes;
	return 0;
}



void compress_chunk_thread(void *arg)
{
	struct thread_info *tinfo = (struct thread_info *)arg;
	struct vdfs4_comp_extent *cur_ext = NULL;
	int compressed_size;
	int ret = 0, written = 0;
	u64 aes_counter;
	unsigned int enc_data_size;
	unsigned char *encryption_buffer = NULL;
	unsigned char *data;
	int chunk_uncompressed;
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
	while (!tinfo->exit) {

		pthread_mutex_lock(&tinfo->compress_mutex);

		while (!(tinfo->has_data)) {
			pthread_cond_wait(&tinfo->compress_cond,
					&tinfo->compress_mutex);
			if (tinfo->exit) {
				pthread_mutex_unlock(&tinfo->compress_mutex);
				return;
			}
		}
		tinfo->has_data = 0;
		ret = 0;
		if (*tinfo->error) {
			ret = *tinfo->error;
			pthread_mutex_unlock(&tinfo->compress_mutex);
			goto err_exit;
		}
		pthread_mutex_unlock(&tinfo->compress_mutex);

		cur_ext = &tinfo->ext_table[tinfo->count - 1];
		memset(cur_ext, 0x0, sizeof(struct vdfs4_comp_extent));
		memset(tinfo->out, 0, tinfo->chunk_size);
		memcpy(cur_ext->magic, VDFS4_COMPR_EXT_MAGIC,
				sizeof(cur_ext->magic));

		if(tinfo->aes_info.do_encrypt) {
			/* prepare encryption variables */
			aes_counter = (tinfo->count - 1) * tinfo->chunk_size / AES_BLOCK_SIZE;
			cur_ext->flags |= VDFS4_CHUNK_FLAG_ENCRYPTED;
			encryption_buffer = malloc(tinfo->out_size);
			if(!encryption_buffer) {
				printf("No memory for encryption in compress_chunk_thread.\n");
				ret = -ENOMEM;
				goto err_exit;
			}
		}

		ret = compress_chunk(tinfo->in, tinfo->in_size,
				tinfo->out, tinfo->out_size,
				tinfo->compress_type,
				cur_ext, &compressed_size,
				tinfo->max_chunk_size,
				tinfo->min_space_saving_ratio);
		if (ret) {
			ret = -errno;
			goto err_exit;
		}

		chunk_uncompressed = (int)(cur_ext->flags & VDFS4_CHUNK_FLAG_UNCOMPR);
		data = chunk_uncompressed ? tinfo->in : tinfo->out;

		if(tinfo->aes_info.do_encrypt) {
			/* ENCRYPT CHUNK */
			enc_data_size = chunk_uncompressed ?
					tinfo->in_size : compressed_size;
			encrypt_chunk(data, encryption_buffer,
					tinfo->aes_info.aes_nonce,
					&(tinfo->aes_info.aes_key),
					enc_data_size, aes_counter);
			data = encryption_buffer;
		}

		if (chunk_uncompressed) {
			/*UNCOMPRESSED CHUNK*/
			size_t align = compr_align[tinfo->compress_type][ALIGN_START];
			if(tinfo->aes_info.do_encrypt)
				encrypted_chunk_align(&align, ALIGN_START);

			if(align && (tinfo->in_size % align)) {
				memset(tinfo->in + tinfo->in_size, 0,
						align - tinfo->in_size % align);
				tinfo->in_size = ALIGN(tinfo->in_size, align);
			}
			pthread_mutex_lock(&thread_file[tinfo->parent_thread].
					write_uncompr_mutex);
			written = write(tinfo->tmp_uncompr_fd, data,
					tinfo->in_size);
			cur_ext->start = *tinfo->unpacked_offset;
			*tinfo->unpacked_offset += written;
			pthread_mutex_unlock(&thread_file[tinfo->parent_thread].
					write_uncompr_mutex);
			if (written != tinfo->in_size) {
				ret = (written == -1) ? -errno : -ENOSPC;
				goto err_exit;
			}

		} else {
			/*COMPRESSED CHUNK*/
			pthread_mutex_lock(&thread_file[tinfo->parent_thread].
					write_compr_mutex);
			written = write(tinfo->tmp_compr_fd, data,
					compressed_size);
			cur_ext->start = *tinfo->packed_offset;
			*tinfo->packed_offset += written;
			pthread_mutex_unlock(&thread_file[tinfo->parent_thread].
					write_compr_mutex);
			if (written != compressed_size) {
				ret = (written == -1) ? -errno : -ENOSPC;
				goto err_exit;
			}
		}

		if (tinfo->hash_table) {
			/*CALCULATE HASH FOR CHUNK*/
			tinfo->hash_alg((const unsigned char *)data, cur_ext->len_bytes,
					tinfo->hash_table
					+ tinfo->hash_len * (tinfo->count - 1));
		}
err_exit:
		if(encryption_buffer) {
			free(encryption_buffer);
			encryption_buffer = NULL;
		}
		pthread_mutex_lock(
				&thread_file[tinfo->parent_thread].write_mutex);
		if (ret)
			*tinfo->error = ret;
		*tinfo->new_file_size += written;
		if (!--*tinfo->chunks) {
			pthread_mutex_unlock(&thread_file[tinfo->parent_thread].
					write_mutex);

			pthread_cond_signal(&thread_file[tinfo->parent_thread].
					finished);
		} else
			pthread_mutex_unlock(&thread_file[tinfo->parent_thread].
					write_mutex);
		pthread_mutex_lock(&tinfo->compress_mutex);
		tinfo->is_free = 1;
		pthread_mutex_unlock(&tinfo->compress_mutex);
		pthread_cond_broadcast(&thread_free_cond);

	}
}



int get_free_thread()
{
	int i;
	struct timespec timewait;
	timewait.tv_sec = 0;
	timewait.tv_nsec = 1000000;
	while (1) {
		for (i = 0; i < processors; i++) {
			pthread_mutex_lock(&thread[i].compress_mutex);
				if (thread[i].is_free) {
					thread[i].is_free = 0;
					pthread_mutex_unlock(&thread[i].
							compress_mutex);
					return i;
				}
				pthread_mutex_unlock(&thread[i].compress_mutex);
		}
		pthread_mutex_lock(&thread_free_mutex);
		pthread_cond_timedwait(&thread_free_cond, &thread_free_mutex,
				&timewait);
		pthread_mutex_unlock(&thread_free_mutex);
	}

}
static int prepare_file_descr(struct vdfs4_comp_file_descr *descr,
		int compress_type, int chunks, int src_file_size,
		int log_chunk_size, int hash,
		vdfs4_hash_algorithm_func *hash_alg,
		unsigned char* aes_nonce, enum sign_type sign_type)
{
	char *magic;
	int ret = 0;
	memset(descr, 0x0, sizeof(*descr));
	switch (compress_type) {
	case VDFS4_COMPR_ZLIB:
		magic = VDFS4_COMPR_ZIP_FILE_DESCR_MAGIC;
		break;
	case VDFS4_COMPR_GZIP:
		magic = VDFS4_COMPR_GZIP_FILE_DESCR_MAGIC;
		break;
	case VDFS4_COMPR_LZO:
		magic = VDFS4_COMPR_LZO_FILE_DESCR_MAGIC;
		break;
	default:
		log_error("Incorrect compress type %d", compress_type);
		ret = -EINVAL;
		goto err_exit;
	}
	if (hash) {
		if (hash_alg == MD5)
			descr->magic[0] = VDFS4_MD5_AUTH;
		else if (hash_alg == SHA256)
			descr->magic[0] = VDFS4_SHA256_AUTH;
		else if (hash_alg == SHA1)
			descr->magic[0] = VDFS4_SHA1_AUTH;
	} else
		descr->magic[0] = VDFS4_COMPR_DESCR_START;

	memcpy(descr->magic + 1, magic, sizeof(descr->magic) - 1);
	descr->extents_num = chunks;
	descr->unpacked_size = (__le64)src_file_size;
	descr->layout_version = VDFS4_COMPR_LAYOUT_VER;
	descr->log_chunk_size = log_chunk_size;
	descr->sign_type = sign_type;

	if(aes_nonce)
		memcpy(descr->aes_nonce, aes_nonce, VDFS4_AES_NONCE_SIZE);
err_exit:
	return ret;
}

/* the compress_file returns chunks count */
/* TODO: add encryption support */
static int compress_file_tune(int src_fd, int dst_fd,
		int tmp_fd, int compress_type, struct vdfs4_comp_extent **ext,
		unsigned char **hash, off_t *new_file_size, int log_chunk_size,
		off_t src_file_size, vdfs4_hash_algorithm_func *hash_alg,
		int hash_len)
{
	int ret = 0;
	size_t packed_offset = 0, unpacked_offset = 0;
	ssize_t written = 0, avail_in = 0;
	int count = 0;
	struct vdfs4_comp_extent *ext_table = NULL, *extended_ext_table = NULL;
	unsigned char *hash_table = NULL, *extended_hash_table = NULL;
	int chunk_size = 1 << log_chunk_size;
	unsigned char *in = malloc(chunk_size);
	int olen = chunk_size + chunk_size / 16 + 64 + 3;
	unsigned char *out = malloc(olen);

	if (!in || !out) {
		ret = ENOMEM;
		goto err_exit;
	}

	if (compress_type < 0 || compress_type >= VDFS4_COMPR_NR) {
		ret = -1;
		errno = EINVAL;
		goto err_exit;
	}
	memset(in, 0x0, chunk_size);

	avail_in = read(src_fd, in, chunk_size);
	for (count = 1; avail_in; count++, avail_in = read(src_fd, in,
				chunk_size)) {
		struct vdfs4_comp_extent *cur_ext = NULL;
		int compressed_size;


		if (avail_in == -1) {
			ret = -1;
			goto err_exit;
		}
		extended_ext_table = realloc(ext_table,
				count * sizeof(*ext_table));
		if (extended_ext_table == NULL) {
			errno = ENOMEM;
			ret = -1;
			goto err_exit;
		}
		ext_table = extended_ext_table;
		cur_ext = &ext_table[count - 1];
		memset(cur_ext, 0x0, sizeof(*ext_table));
		memset(out, 0, chunk_size);
		memcpy(cur_ext->magic, VDFS4_COMPR_EXT_MAGIC,
				sizeof(cur_ext->magic));

		if (src_file_size < (VDFS4_BLOCK_SIZE << 1)) {
			cur_ext->len_bytes = avail_in;
			/* Fill vdfs4 extent */
			cur_ext->flags |= VDFS4_CHUNK_FLAG_UNCOMPR;
		} else {
			ret = compress_chunk(in, avail_in, out, olen,
					compress_type, cur_ext,
					&compressed_size, chunk_size,
					DEFAULT_MIN_SPACE_SAVING_RATIO);
			if (ret) {
				errno = ret;
				ret = -1;
				goto err_exit;
			}
		}
		if (cur_ext->flags & VDFS4_CHUNK_FLAG_UNCOMPR) {
			/* chunk is uncompressed */
			size_t align = compr_align[compress_type][ALIGN_LENGTH];
			if(align && (avail_in % align)) {
				memset(in + avail_in, 0, align - (avail_in % align));
				avail_in = ALIGN(avail_in, align);
			}
			written = write(dst_fd, in, avail_in);
			if (written != avail_in) {
				errno = (written == -1) ? errno : ENOSPC;
				ret = -1;
				goto err_exit;
			}
			cur_ext->start = unpacked_offset;
			unpacked_offset += written;
		} else {
			/* chunk is compressed */
			written = write(tmp_fd, out, compressed_size);
			if (written != compressed_size) {
				errno = (written == -1) ? errno : ENOSPC;
				ret = -1;
				goto err_exit;
			}
			cur_ext->start = packed_offset;
			packed_offset += written;
		}

		if (hash) {
			unsigned char *data = (cur_ext->flags &
					VDFS4_CHUNK_FLAG_UNCOMPR) ? in : out;
			ssize_t data_size = cur_ext->len_bytes;

			extended_hash_table = realloc(hash_table, count *
					hash_len);
			if (extended_hash_table == NULL) {
				errno = ENOMEM;
				ret = -1;
				goto err_exit;
			}
			hash_table = extended_hash_table;
			hash_alg((const unsigned char *)data, data_size, hash_table
					+ hash_len * (count - 1));
		}

		*new_file_size += written;
	}
	count--;

	/* copy  chunks */
	ret = lseek(tmp_fd, 0, SEEK_SET);
	if (ret == -1)
		goto err_exit;

	while ((avail_in = read(tmp_fd, in, chunk_size)) > 0)
		write(dst_fd, in, avail_in);

	if (avail_in == -1)
		goto err_exit;

	if (hash)
		*hash = hash_table;
	*ext = ext_table;

	/* update compressed chunks offsets */
	for (ret = 0; ret < count; ret++) {
		if (!(ext_table[ret].flags & VDFS4_CHUNK_FLAG_UNCOMPR))
			ext_table[ret].start += unpacked_offset;
	}

	free(in);
	free(out);

	return count;

err_exit:
	*ext = ext_table;
	if (hash)
		*hash = hash_table;
	free(in);
	free(out);
	return ret;
}


void wait_file_finish(int *count, int parent_thread)
{

	int a = 0;
	struct timespec timewait;
	timewait.tv_sec = 1;
	timewait.tv_nsec = 0;
	while (1) {
		pthread_mutex_lock(&thread_file[parent_thread].
							write_mutex);

		a = *count;


		if (a) {
			pthread_mutex_unlock(&thread_file[parent_thread].write_mutex);
			pthread_mutex_lock(&thread_file[parent_thread].compress_mutex);
			pthread_cond_timedwait(&thread_file[parent_thread].finished,
					&thread_file[parent_thread].compress_mutex,
					&timewait);
			pthread_mutex_unlock(&thread_file[parent_thread].compress_mutex);
		} else {
			pthread_mutex_unlock(&thread_file[parent_thread].write_mutex);
			return;
		}
	}
}

static int get_comp_extent_starting_at(struct vdfs4_comp_extent *table,
		int count, size_t start_at)
{
	int ret = -1;
	int i = 0;
	if(!count)
		return ret;
	for(i=0;i<count; ++i) {
		if(!(table[i].flags & VDFS4_CHUNK_FLAG_UNCOMPR) &&
				table[i].start == start_at) {
			return (int)(&table[i] - table);
		}
	}

	return ret;
}

static int copy_from_fd_to_fd(int fd_src, off_t in_offset, int fd_dst, int len)
{
	unsigned char *buf = malloc(len);
	int avail_in;
	int ret = 0;
	if(!buf)
		return -ENOMEM;

	avail_in = lseek(fd_src, in_offset, SEEK_SET);
	if(avail_in == -1) {
		ret = -errno;
		goto exit;
	}
	avail_in = read(fd_src, buf, len);
	if(avail_in != len) {
		ret = -EINVAL;
		goto exit;
	}
	avail_in = write(fd_dst, buf, len);
	if(avail_in != len) {
		ret = -EINVAL;
		goto exit;
	}
exit:
	free(buf);
	return ret;
}

static int write_zero_area(int fd, int len)
{
	unsigned char *buf = malloc(len);
	if(!buf)
		return -ENOMEM;
	memset(buf, 0, len);
	if(write(fd, buf, len) != len) {
		free(buf);
		return -EINVAL;
	}
	free(buf);
	return 0;
}

static int is_all_chunks_uncompressed(struct vdfs4_comp_extent *table,
		int count)
{
	int i;
	for (i = 0; i < count; i++) {
		if (!(table[i].flags & VDFS4_CHUNK_FLAG_UNCOMPR))
			break;
		if(i == count - 1)
			return 1;
	}
	return 0;
}

static int is_all_chunks_compressed(struct vdfs4_comp_extent *table,
		int count)
{
	int i;
	for (i = 0; i < count; i++) {
		if (table[i].flags & VDFS4_CHUNK_FLAG_UNCOMPR)
			break;
		if(i == count - 1)
			return 1;
	}
	return 0;
}

/* the compress_file returns chunks count */
static int compress_file(struct vdfs4_sb_info *sbi, int src_fd,
		int tmp_uncompr_fd, int dst_fd, int tmp_fd, int compress_type,
		struct vdfs4_comp_extent **ext,
		unsigned char **hash, off_t *new_file_size, int log_chunk_size,
		off_t src_file_size, RSA *rsa_key, u_int64_t *block,
		int parent_thread, 	struct vdfs4_aes_info *aes_info,
		const struct profiled_file* pfile)
{
	int ret = 0;
	char err_msg[ERR_BUF_LEN];
	size_t packed_offset = 0, unpacked_offset = 0;
	ssize_t  avail_in = 0;
	int count = 0, ret_thread = 0;
	struct vdfs4_comp_file_descr __descr, *descr = &__descr;
	struct vdfs4_comp_extent *ext_table = NULL;
	struct vdfs4_comp_extent *ext_table_copy = NULL;
	struct vdfs4_comp_extent *extended_ext_table = NULL;
	unsigned char *hash_table = NULL;
	unsigned char *extended_hash_table = NULL;
	int chunk_size = 1 << log_chunk_size;
	unsigned char *in = malloc(chunk_size);
	int hash_len = sbi->hash_len;
	int chunks;
	size_t cur_offset, cur_packed_offset = 0;
	ssize_t align;
	size_t volume_chunk_size = (size_t)1 << log_chunk_size;
	int no_written_chunks = 0;

	if (compress_type < 0 || compress_type >= VDFS4_COMPR_NR) {
		ret = -1;
		errno = EINVAL;
		goto err_exit;
	}

compress_retry:
	packed_offset = 0;
	unpacked_offset = 0;
	*new_file_size = 0;
	if((ret = lseek(tmp_fd, 0, SEEK_SET)) != 0)
		goto err_exit;
	if((ret = lseek(tmp_uncompr_fd, 0, SEEK_SET)) != 0)
		goto err_exit;
	if((ret = lseek(src_fd, 0, SEEK_SET)) != 0)
		goto err_exit;

	chunks = ALIGN(src_file_size, chunk_size) / chunk_size;
	thread_file[parent_thread].chunks_count = chunks;
	extended_ext_table = realloc(ext_table,
			chunks * sizeof(struct vdfs4_comp_extent));
	if (extended_ext_table == NULL) {
		errno = ENOMEM;
		ret = -1;
		goto err_exit;
	}
	ext_table = extended_ext_table;
	memset(ext_table, 0, chunks * sizeof(struct vdfs4_comp_extent));
	if (hash) {
		extended_hash_table = realloc(hash_table, chunks *
				hash_len);
		if (extended_hash_table == NULL) {
			errno = ENOMEM;
			ret = -1;
			goto err_exit;
		}
		hash_table = extended_hash_table;
		memset(hash_table, 0, chunks * hash_len);
	}
	for (count = 1; count <= chunks; count++) {
		avail_in = read(src_fd, in, chunk_size);
		if (avail_in == -1) {
			ret = -1;
			goto err_exit;
		}
		int thread_num = get_free_thread();

		thread[thread_num].chunks =
				&thread_file[parent_thread].chunks_count;
		thread[thread_num].src_fd = src_fd;
		thread[thread_num].chunk_size = chunk_size;
		thread[thread_num].max_chunk_size =
				HW_DECOMPRESSOR_PAGES_NUM << PAGE_SHIFT;
		thread[thread_num].compress_type = compress_type;
		thread[thread_num].min_space_saving_ratio =
				sbi->min_space_saving_ratio;
		thread[thread_num].count = count;
		thread[thread_num].tmp_uncompr_fd = tmp_uncompr_fd;
		memcpy(thread[thread_num].in, in, chunk_size);
		thread[thread_num].in_size = avail_in;
		thread[thread_num].tmp_compr_fd = tmp_fd;
		thread[thread_num].ext_table = ext_table;
		thread[thread_num].hash_table = hash_table;
		pthread_mutex_lock(&thread[thread_num].compress_mutex);
		thread[thread_num].has_data = 1;
		thread[thread_num].error = &ret_thread;
		thread[thread_num].new_file_size = new_file_size;
		thread[thread_num].unpacked_offset = &unpacked_offset;
		thread[thread_num].packed_offset = &packed_offset;
		thread[thread_num].src_file_size = src_file_size;
		thread[thread_num].parent_thread = parent_thread;
		thread[thread_num].aes_info = *aes_info;

		ret = pthread_cond_signal(&thread[thread_num].compress_cond);
		pthread_mutex_unlock(&thread[thread_num].compress_mutex);
		if (ret != 0)
			goto err_exit;

	}

	wait_file_finish(&thread_file[parent_thread].chunks_count, parent_thread);

	*ext = ext_table;
	if (hash)
		*hash = hash_table;

	if (ret_thread) {
		ret = ret_thread;
		goto err_exit;
	}
	count--;

	/* if none of chunks has been compressed
	 * then file won't be tuned except:
	 * - it is EXEC file  as those must retain auth feature
	 * - encryption requested */
	if(is_all_chunks_uncompressed(ext_table, count) &&
			!is_exec_file_fd(src_fd) &&
			!aes_info->do_encrypt) {
		ret = -ENOTCOMPR;
		goto err_exit;
	}

	ret = prepare_file_descr(descr, compress_type, chunks, src_file_size,
			log_chunk_size, hash_table ? 1 : 0, sbi->hash_alg,
			aes_info->aes_nonce, get_sign_type(rsa_key));
	if (ret)
		goto err_exit;

	if (rsa_key) {
		unsigned char *extended_hash_table = NULL;

		extended_hash_table = realloc(hash_table, (chunks + 1) *
				hash_len + get_sign_length(rsa_key));
		if (extended_hash_table)
			hash_table = extended_hash_table;
		else {
			ret = -ENOMEM;
			goto err_exit;
		}
		if (hash)
			*hash = hash_table;
		/*Sign tuned file*/
		assert(hash_table);
		sbi->hash_alg((const unsigned char *)descr,
			VDFS4_COMPR_FILE_DESC_LEN,
			hash_table + hash_len * chunks);

		ret = sign_rsa(hash_table, hash_len *
				(chunks + 1), hash_table + hash_len *
				(chunks + 1),
				rsa_key, sbi->hash_alg, sbi->hash_len);
		if (ret) {
			log_error("Error when signing hash");
			goto err_exit;
		}
	}

	pthread_mutex_lock(&write_file_mutex);

	if (!IS_FLAG_SET(sbi->service_flags, READ_ONLY_IMAGE) &&
			!sbi->space_manager_info.space_manager_list) {
		ret = -ENOSPC;
		goto err_write_exit;
	}

	/* write uncompressed chunks */
	no_written_chunks = 0;
	int dst_offset = get_metadata_size(sbi);
	lseek(dst_fd, dst_offset, SEEK_SET);
	unpacked_offset = 0;
	for (ret = 0; ret < count; ret++) {
		if ((ext_table[ret].flags & VDFS4_CHUNK_FLAG_UNCOMPR)) {
			size_t aligned_len = ext_table[ret].len_bytes;
			size_t align = compr_align[compress_type][ALIGN_START];
			if(ext_table[ret].flags & VDFS4_CHUNK_FLAG_ENCRYPTED)
				encrypted_chunk_align(&align, ALIGN_START);
			if(align)
				aligned_len = ALIGN(ext_table[ret].len_bytes, align);

			lseek(tmp_uncompr_fd, ext_table[ret].start, SEEK_SET);
			avail_in = read(tmp_uncompr_fd, in, aligned_len);
			if (avail_in != (ssize_t)aligned_len) {
				ret = -1;
				goto err_write_exit;
			}
			ext_table[ret].start = unpacked_offset;

			unpacked_offset += aligned_len;
			write(dst_fd, in, avail_in);
			no_written_chunks++;

			if (pfile)
				ext_table[ret].profiled_prio = pfile->chunk_order[ret];
		}

	}

	/* write compressed chunks */
	cur_packed_offset = 0;
	struct vdfs4_comp_extent *temp_ptr = realloc(ext_table_copy, chunks * sizeof(struct vdfs4_comp_extent));
	if (!temp_ptr)
	{
		log_error("not enough memory");
		ret = -ENOMEM;
		goto err_exit;
	}
	ext_table_copy = temp_ptr;

	memcpy(ext_table_copy, ext_table,
			chunks * sizeof(struct vdfs4_comp_extent));
	cur_offset = unpacked_offset;
	while(no_written_chunks < chunks) {
		int index = get_comp_extent_starting_at(ext_table_copy, chunks,
				cur_packed_offset);
		assert(index >= 0);
		struct vdfs4_comp_extent* ext = &ext_table[index];

		align = (ext->len_bytes + (cur_offset % sbi->block_size)) - volume_chunk_size;
		if(align > 0) {
			align = sbi->block_size - align;
			ret = write_zero_area(dst_fd, align);
			if(ret)
				 goto err_write_exit;
			cur_offset += align;
			*new_file_size += align;
		}

		ret = copy_from_fd_to_fd(tmp_fd, cur_packed_offset, dst_fd, ext->len_bytes);
		if(ret)
			goto err_write_exit;

		ext->start = cur_offset;
		cur_offset += ext->len_bytes;
		cur_packed_offset += ext->len_bytes;
		no_written_chunks++;

		if (pfile)
			ext->profiled_prio = pfile->chunk_order[index];
	}
	assert(no_written_chunks == chunks);

	__u32 crc = crc32_body(0, (const __u8 *)ext_table,
			chunks * sizeof(*ext_table));
	if (hash_table)
		crc = crc32_body(crc, hash_table, (chunks + 1) * hash_len +
				get_sign_length(rsa_key));
	descr->crc = crc32_body(crc, (const __u8 *)descr, sizeof(*descr));

	/* align whole file size */
	int aligned_size = ALIGN(*new_file_size,
			sizeof(struct vdfs4_comp_extent)) - *new_file_size;
	size_t h_size = (size_t)(chunks + 1) * (size_t)hash_len +
			(size_t)get_sign_length(rsa_key);

	/* write chunk table */
	struct stat f_stat;
	ret = fstat(dst_fd, &f_stat);
	if (ret == -1)
		goto err_write_exit;

	lseek(dst_fd, f_stat.st_size + aligned_size, SEEK_SET);
	*new_file_size += aligned_size;
	int written = write(dst_fd, ext_table, chunks * sizeof(*ext_table));
	if (written != (ssize_t)(sizeof(*ext_table) * chunks)) {
		ret = (written == -1) ? -errno : -ENOSPC;
		goto err_write_exit;
	} else
		*new_file_size += written;

	/* write hash table */
	if (hash_table) {
		written = write(dst_fd, hash_table, h_size);
		if (written != (ssize_t)h_size) {
			ret = (written == -1) ? -errno : -ENOSPC;
			goto err_write_exit;
		} else
			*new_file_size += written;
	}


	/* write descriptor */
	written = write(dst_fd, descr, sizeof(*descr));
	if (written != sizeof(*descr)) {
		ret = (written == -1) ? -errno : -ENOSPC;
		goto err_write_exit;
	} else {
		*new_file_size += written;
	}
	if (IS_FLAG_SET(sbi->service_flags, READ_ONLY_IMAGE)) {
		__u64 begin = find_data_duplicate(&sbi->data_ranges,
				sbi->disk_op_image.file_id,
				sbi->disk_op_image.file_id,
				dst_offset, *new_file_size);
		if (begin) {
			*block = ALIGN(begin, sbi->block_size) / sbi->block_size;;
			ftruncate(sbi->disk_op_image.file_id, dst_offset);
			goto exit;
		}
	}
	u_int64_t begin = ALIGN(dst_offset, sbi->block_size) / sbi->block_size;
	uint32_t count_blocks = (u_int32_t)(ALIGN(*new_file_size,
			sbi->block_size) / sbi->block_size);
	ret = allocate_space(sbi,  begin, count_blocks, block);
	if (ret) {
		log_error("Can't allocate space - %s",
					strerror_r(-ret, err_msg, ERR_BUF_LEN));
		goto err_write_exit;
	}

	if (IS_FLAG_SET(thread_file[parent_thread].sbi->service_flags,
			READ_ONLY_IMAGE))
		add_data_range(sbi, &sbi->data_ranges, (*block << PAGE_SHIFT),
				*new_file_size);
exit:
	pthread_mutex_unlock(&write_file_mutex);
	free(in);
	if(ext_table_copy)
		free(ext_table_copy);
	return count;
err_write_exit:
	pthread_mutex_unlock(&write_file_mutex);
err_exit:
	if (ext)
		*ext = ext_table;
	if (hash)
		*hash = hash_table;
	free(in);
	if(ext_table_copy)
		free(ext_table_copy);
	return ret;
}


#if 0
static inline int is_magic_set(struct vdfs4_comp_file_descr *descr,
		const char *magic)
{
	return !memncmp(descr->magic + 1, magic, strlen(magic));
}
#else
#define is_magic_set(descr, magic_str) !memcmp((descr)->magic + 1, (magic_str),\
		sizeof((magic_str)) - 1)
#endif

int analyse_existing_file(int rd_fd,
		int *compress_type, int *chunks_num, off_t *src_file_size,
		off_t *data_area_size, struct vdfs4_comp_extent **extents,
		int *is_authenticated, int *log_chunk_size,
		struct vdfs4_comp_file_descr* descr_ret)
{
	struct vdfs4_comp_file_descr descr;
	int ret = 0, supported = 0;
	unsigned i;
	off_t file_size;

	ret = get_file_size(rd_fd, &file_size);
	if (ret)
		return ret;

	if (file_size < (off_t)sizeof(struct vdfs4_comp_file_descr)) {
		*compress_type = VDFS4_COMPR_NONE;
		*chunks_num = 0;
		*extents = NULL;
		return 0;
	}

	ret = read_descriptor_info(rd_fd, &descr, data_area_size, extents,
			compress_type, file_size, log_chunk_size);
	if (ret == -EINVAL) {
		*compress_type = VDFS4_COMPR_NONE;
	} else if (ret == 0) {
		*chunks_num = le16_to_cpu(descr.extents_num);
		*src_file_size = le64_to_cpu(descr.unpacked_size);

		if (descr.magic[0] == VDFS4_MD5_AUTH ||
			descr.magic[0] == VDFS4_SHA1_AUTH ||
			descr.magic[0] == VDFS4_SHA256_AUTH) {
			*is_authenticated = 1;
		} else if (descr.magic[0] != VDFS4_COMPR_DESCR_START) {
			*compress_type = VDFS4_COMPR_NONE;
			*chunks_num = 0;
			*extents = NULL;
		}
		if(descr_ret)
			memcpy(descr_ret, &descr, sizeof(*descr_ret));

		for (i = 0; i < VDFS4_NUM_OF_SUPPORTED_COMPR_LAYOUTS; i++) {
			if (le16_to_cpu(descr.layout_version) ==
						supported_compressed_layouts[i]) {
				supported = 1;
				break;
			}
		}
		if (!supported) {
			log_error("Wrong VDFS4 COMPRESSED FILE LAYOUT VERSION -"
					" %d, current version - %d",
					descr.layout_version,
					VDFS4_COMPR_LAYOUT_VER);
			return -EINVAL;
		}
	}
	return 0;
}

int check_file_before_compress(const char *filename, int need_compress,
		mode_t *src_mode, int min_comp_size)
{
	char err_msg[ERR_BUF_LEN];
	int ret = 0;
	struct stat stat_info;
	int min_size = min_comp_size == -1 ?
			MIN_COMPRESSED_FILE_SIZE : min_comp_size;
	memset(&stat_info, 0, sizeof(struct stat));
	ret = lstat(filename, &stat_info);
	if (ret < 0) {
		int err = errno;
		log_error("Can't get stat info of %s because of %s",
				filename, strerror_r(errno, err_msg, ERR_BUF_LEN));
		return err;
	}
	*src_mode = stat_info.st_mode;
	if (!S_ISREG(*src_mode)) {
		log_info("Source file %s is not regular file"
				" and cannot be compressed", filename);
		return -ENOTCOMPR;
	}
	if (need_compress && stat_info.st_size < min_size &&
			!is_exec_file_path(filename))
		return -ENOTCOMPR;
	return ret;
}

struct profiled_file* find_prof_data_path(struct list_head *prof_data, char* path)
{
	struct profiled_file* pfile;
	list_for_each_entry(pfile, prof_data, list) {
		if (strcmp(path, pfile->path))
			continue;
		return pfile;
	}
	return NULL;
}

#define COMPRTEMP "comprXXXXXX"

int encode_file(struct vdfs4_sb_info *sbi, char *src_filename, int dst_fd,
		int need_compress, int compress_type, off_t *rsl_filesize,
		RSA *rsa_key, int log_chunk_size,
		const char *tmp_dir, u_int64_t *block, int thread_num,
		vdfs4_hash_algorithm_func *hash_alg, int hash_len,
		int do_encrypt, const struct profiled_file* pfile)
{
	int src_fd;
	int tmp_dst_fd = -1, tmp_uncompr_fd = -1;

	char *compr_name = NULL;
	char *uncompr_name = NULL;

	off_t src_file_size;
	char err_msg[ERR_BUF_LEN];
	int ret;
	RSA *__rsa_key = rsa_key;
	int is_authenticated = 0;
	/* If the file was really compressed. Not already! Actual only if
	 * compression requested. Unused if compression is not requested, even
	 * if the source file is already compressed by tune utility.
	 * There's no guarantee that file can be actually compressed, because
	 * uncompressed contents. So even if compression requested we need to
	 * treat this file as common, though return -ENOTCOMPR.
	 */
	struct vdfs4_comp_extent *extents = NULL;
	unsigned char *hash_table = NULL;
	int chunks_num = 0, infile_compression;
	off_t data_area_size;
	int _log_chunk_size = 0;
	struct vdfs4_aes_info aes_info;

	*rsl_filesize = 0;

	src_fd = open(src_filename, O_RDONLY);
	if (src_fd == -1) {
		ret = errno;
		log_error("error %s while opening file %s for read",
				strerror_r(errno, err_msg, ERR_BUF_LEN),
				src_filename);
		goto rel_src_fd;
	}
	ret = get_file_size(src_fd, &src_file_size);
	if (ret)
		goto rel_src_fd;

	/* check: is file encoded? */
	ret = analyse_existing_file(src_fd, &infile_compression,
			&chunks_num, &src_file_size, &data_area_size, &extents,
			&is_authenticated, &_log_chunk_size, NULL);
	if (ret) {
		log_error("cannot analyse the input file");
		goto rel_src_fd;
	}

	if (infile_compression != VDFS4_COMPR_NONE) {
		log_error("Input file is compressed");

		ret = -EINVAL;
		goto rel_extents;
	}

	/* check if file must be signed (auth feature) */
	__rsa_key = (is_need_sign(src_fd, src_filename) > 0) ?
				rsa_key : NULL;
	if (sbi && IS_FLAG_SET(sbi->service_flags, SIGN_ALL))
			__rsa_key = rsa_key;

	if (thread_num >= 0) {
		compr_name =thread_file[thread_num].compr_temp;
		uncompr_name = thread_file[thread_num].uncompr_temp;
		tmp_dst_fd = open(compr_name, O_RDWR | O_CREAT | O_TRUNC,
				  S_IRUSR | S_IWUSR);
	} else {
		size_t len = strlen(tmp_dir) + strlen(COMPRTEMP) + 2;
		compr_name = (char *)malloc(len);
		if (!compr_name)
		{
			log_error("not enough memory");
			goto rel_extents;
		}
		memset(compr_name, 0x00, len);
		if (strlen(tmp_dir) > 0)
		{
			strncpy(compr_name, tmp_dir, strlen(tmp_dir));
			if (compr_name[strlen(compr_name) - 1] != '/')
			{
				strncat(compr_name, "/", 1);
			}
		}
		strncat(compr_name, COMPRTEMP, strlen(COMPRTEMP));
		tmp_dst_fd = mkostemp(compr_name, O_RDWR | O_CREAT | O_TRUNC);
	}

	if (tmp_dst_fd == -1) {
		ret = errno;
		log_error("%s temporary file %s",
				strerror_r(errno, err_msg, ERR_BUF_LEN),
				compr_name);
		goto rel_src_fd;
	}
	unlink(compr_name);
	if (thread_num >= 0) {
		tmp_uncompr_fd = open(uncompr_name, O_RDWR | O_CREAT | O_TRUNC,
				      S_IRUSR | S_IWUSR);
		if (tmp_uncompr_fd == -1) {
			ret = errno;
			log_error("%s temporary file %s",
					strerror_r(errno, err_msg, ERR_BUF_LEN),
					uncompr_name);
			close(tmp_dst_fd);
			goto rel_src_fd;
		}
		unlink(uncompr_name);
	}

	memset(&aes_info, 0, sizeof(struct vdfs4_aes_info));
	if(do_encrypt) {
		memcpy(&aes_info.aes_key, sbi->aes_key, sizeof(aes_info.aes_key));
		if(!RAND_status())
			log_error("Warning: PRNG is not seeded correctly!");
		RAND_bytes(aes_info.aes_nonce, VDFS4_AES_NONCE_SIZE);
		aes_info.do_encrypt = 1;
		need_compress = 1;
	}

	if (need_compress) {
		infile_compression = compress_type;
		if (thread_num >= 0)
			chunks_num = compress_file(sbi, src_fd, tmp_uncompr_fd,
					dst_fd, tmp_dst_fd, compress_type,
					&extents, (__rsa_key) ?
					&hash_table : NULL,  rsl_filesize,
					log_chunk_size, src_file_size,
					__rsa_key, block, thread_num,
					&aes_info, pfile);
		else
			chunks_num = compress_file_tune(src_fd, dst_fd,
					tmp_dst_fd, compress_type, &extents,
					(__rsa_key) ? &hash_table : NULL,
					rsl_filesize, log_chunk_size,
					src_file_size, hash_alg, hash_len);
		if (chunks_num < 0) {
			ret = chunks_num;
			if (ret == -ENOTCOMPR)
				/* For Gzip compression */
				*rsl_filesize =  src_file_size;
			else
				goto rel_extents;
		}
	}

rel_extents:
	if (tmp_dst_fd >= 0)
		close(tmp_dst_fd);
	if (tmp_uncompr_fd >= 0)
		close(tmp_uncompr_fd);
	if ((thread_num < 0) && !ret)
		ret = add_compression_info(dst_fd, chunks_num,
				src_file_size, extents, infile_compression,
				&hash_table, __rsa_key, rsl_filesize,
				log_chunk_size, hash_alg, hash_len);
	free(extents);
	free(hash_table);

rel_src_fd:
	if (thread_num < 0)
		free(compr_name);
	if (src_fd != -1)
		close(src_fd);

	return ret;
}

static int __compress_zlib_gzip_chunk(unsigned char *ibuff, int ilen,
		unsigned char *obuff, int olen, int *comp_size, int window_bits)
{
	int ret = 0;

	z_stream strm;
	strm.zalloc = Z_NULL;
	strm.zfree = Z_NULL;
	strm.opaque = Z_NULL;
	ret = deflateInit2(&strm, Z_BEST_COMPRESSION, Z_DEFLATED, window_bits,
			8, Z_DEFAULT_STRATEGY);
	if (ret != Z_OK)
		return ret;
	strm.avail_in = ilen;
	strm.next_in = ibuff;
	strm.avail_out = olen;
	strm.next_out = obuff;
	ret = deflate(&strm, Z_FINISH);
	if (ret == Z_OK || !strm.avail_out) {
		/* Incompressible chunk */
		*comp_size = 0;
	} else {
		assert(ret == Z_STREAM_END);
		*comp_size = strm.total_out;
	}

	(void)deflateEnd(&strm);
	if (ret != Z_STREAM_END)
		return ret;
	return 0;
}

int compress_zlib_chunk(unsigned char *ibuff, int ilen,
		unsigned char *obuff, int olen, int *comp_size)
{
	return __compress_zlib_gzip_chunk(ibuff, ilen, obuff, olen, comp_size,
			ZLIB_WINDOW_SIZE);
}

int compress_gzip_chunk(unsigned char *ibuff, int ilen,
		unsigned char *obuff, int olen, int *comp_size)
{
	return __compress_zlib_gzip_chunk(ibuff, ilen, obuff, olen, comp_size,
			GZIP_WINDOW_SIZE);
}

int compress_lzo_chunk(unsigned char *ibuff, int ilen,
		unsigned char *obuff, int olen, int *comp_size)
{
	int ret = 0;
	int new_olen = olen;
	lzo_voidp wrkmem[LZO1X_999_MEM_COMPRESS];
	ret = lzo_init();
	if (ret != LZO_E_OK) {
		log_error("internal error - lzo_init() failed !!!\n");
		goto exit;
	}
	ret = lzo1x_999_compress(ibuff, ilen, obuff, (lzo_uintp)&new_olen,
			wrkmem);
	if (ret != LZO_E_OK) {
		log_error("%d: lzo compress error\n", ret);
		goto exit;
	}
	if (new_olen >= olen) {
		*comp_size = 0;
	} else
		*comp_size = new_olen;
exit:
	return ret;
}

int not_supported_compressor(unsigned char *ibuff, int ilen,
		unsigned char *obuff, int olen, int *comp_size)
{
	/* Silent gcc warnings */
	(void) ibuff;
	(void) ilen;
	(void) obuff;
	(void) olen;
	(void) comp_size;

	log_error("Compressor is not supported");
	return -ENOTSUP;
}

/* report a zlib or i/o error */
void zerr(int ret)
{
	fputs("zlib: ", stderr);
	switch (ret) {
	case Z_ERRNO:
		if (ferror(stdin))
			fputs("error reading stdin\n", stderr);
		if (ferror(stdout))
			fputs("error writing stdout\n", stderr);
		break;
	case Z_STREAM_ERROR:
		fputs("invalid compression level\n", stderr);
		break;
	case Z_DATA_ERROR:
		fputs("invalid or incomplete deflate data\n", stderr);
		break;
	case Z_MEM_ERROR:
		fputs("out of memory\n", stderr);
		break;
	case Z_VERSION_ERROR:
		fputs("zlib version mismatch!\n", stderr);
	}
}

/* Should correspond to enum compr_type*/
int (*compressor[VDFS4_COMPR_NR])(unsigned char *ibuff, int ilen,
		unsigned char *obuff, int olen, int *comp_size) = {
	[VDFS4_COMPR_ZLIB]	= compress_zlib_chunk,
	[VDFS4_COMPR_LZO]	= compress_lzo_chunk,
	[VDFS4_COMPR_XZ]		= not_supported_compressor,
	[VDFS4_COMPR_LZMA]	= not_supported_compressor,
	[VDFS4_COMPR_GZIP]	= compress_gzip_chunk,
};

int parse_list_cmd(struct install_task *sqt, char *cmd_str)
{
	char *cmd = cmd_str;
	char *next_cmd = NULL;
	char *type = NULL;
	int ret = 0;
	while (cmd) {
		next_cmd = strpbrk(cmd, ",");
		if (next_cmd)
			memcpy(next_cmd, "\0", 1);
		if (!strncmp(cmd, "COMPRESS", strlen("COMPRESS"))) {
			sqt->cmd |= CMD_COMPRESS;
			type = cmd;
			if (type[strlen("COMPRESS")] == '=')
				strsep(&type, "=");
			if (type)
				sqt->compress_type =
					get_compression_type(type);
			if (sqt->compress_type < 0 || !type) {
				ret = -EINVAL;
				goto exit;
			}
		} else if(!strncmp(cmd, "NOCOMPRESS", strlen("NOCOMPRESS"))) {
			sqt->cmd |= CMD_DECOMPRESS;
		} else {
			ret = -ENOTCMD;
			return ret;
		}
		if (next_cmd)
			cmd = ++next_cmd;
		else
			break;

	}

exit:
	if (ret)
		log_error("Incorrect format of config file");
	return ret;
}

int get_wsp_separated_payload(char **src, char *whitespace, char *payload)
{
	const char *orig_start = *src, *payl_start;
	int whsp_len, payl_len;
	while (**src && isspace(**src))
		++(*src);
	if (whitespace != NULL) {
		whsp_len = *src - orig_start;
		strncpy(whitespace, orig_start, whsp_len);
		whitespace[whsp_len] = 0;
	}

	payl_start = *src;
	while (**src && !isspace(**src))
		++(*src);
	payl_len = *src - payl_start;
	strncpy(payload, payl_start, payl_len);
	payload[payl_len] = 0;
	return payl_len;
}

/**
 * @brief	todo
 * @param [in]	sbi Superblock runtime structure
 * @return 0 on success, error code otherwise
 */
int preprocess_sq_tasklist(struct vdfs4_sb_info *sbi,
		struct list_head *list, FILE *list_file)
{
	struct install_task *sqt = NULL;
	int ret = 0;
	char cmd[VDFS4_FULL_PATH_LEN];
	memset(cmd, 0, VDFS4_FULL_PATH_LEN);

	if (strlen(sbi->root_path) > VDFS4_FULL_PATH_LEN) {
		log_error("Can't work with files list because of length of root"
				" path is more than %d", VDFS4_FULL_PATH_LEN);
		return -EINVAL;
	}
	if (list_file) { // In "-q config_file"  param case
		for (;;) {
			char wsp[VDFS4_FULL_PATH_LEN],payl[VDFS4_FULL_PATH_LEN];
			char *cur = cmd;
			char *dst;
			int i;

			if (!fgets(cmd, VDFS4_FULL_PATH_LEN - 1,
					list_file))
				break;
			/* skip comments lines */
			if(cmd[0] == '#')
				continue;

			get_wsp_separated_payload(&cur, NULL, payl);
			if (strlen(payl) == 0)
				continue;

			sqt = malloc(sizeof(struct install_task));
			if (!sqt) {
				log_error("not enough memory");
				return -ENOMEM;
			}

			memset(sqt, 0, sizeof(*sqt));
			strncpy(sqt->src_full_path, sbi->root_path,
					VDFS4_FULL_PATH_LEN);
			sqt->compress_type = VDFS4_COMPR_NONE;

			ret = parse_list_cmd(sqt, payl);
			if (ret)
				goto err;

			get_wsp_separated_payload(&cur, NULL, payl);
			if (strlen(sqt->src_full_path) + strlen(payl) + 2 >
						VDFS4_FULL_PATH_LEN) {
				log_error("Full path to file is too long - %s/%s."
						"Should be not more than %d",
						sqt->src_full_path, payl,
						VDFS4_FULL_PATH_LEN);
				ret = -ENAMETOOLONG;
				goto err;
			}
			strncat(sqt->src_full_path, payl, VDFS4_FULL_PATH_LEN);

			dst = sqt->src_full_path;
			while (get_wsp_separated_payload(&cur, wsp, payl)) {
				if (payl[0] == '/')
					dst = sqt->dst_parent_dir;
				else
					strncat(dst, wsp, VDFS4_FULL_PATH_LEN);

				strncat(dst, payl, VDFS4_FULL_PATH_LEN);
			}

			if (sqt->src_full_path[strlen(sbi->root_path)] != '/') {
				log_error("Incorrect source path - %s. Must be"
					" - /%s",
					&sqt->src_full_path[strlen(sbi->root_path)],
					&sqt->src_full_path[strlen(sbi->root_path)]);
				ret = -EINVAL;
				goto err;
			}

			for (i = strlen(sqt->src_full_path) - 1; i >= 0; i--) {
				if (sqt->src_full_path[i] == '/') {
					sqt->src_fname = &sqt->src_full_path[++i];
						break;
				}
			}
			list_add(&sqt->list, list);
		}
	} else if (sbi->compr_type) { // In "-c comp r_type" param case. It affect all of file.
		sqt = malloc(sizeof(struct install_task));
		if (!sqt) {
			log_error("not enough memory");
			return -ENOMEM;
		}
		memset(sqt, 0, sizeof(*sqt));
		snprintf(sqt->src_full_path, VDFS4_FULL_PATH_LEN,
			"%s/", sbi->root_path);
		sqt->compress_type =
			get_compression_type(sbi->compr_type);
		sqt->cmd |=CMD_COMPRESS;
		list_add(&sqt->list, list);
	}
	return 0;
err:
	log_error("check config file format. please refer usage message.\n");
	free(sqt);
	return ret;
}

int get_free_file_thread(void)
{
	int i;
	struct timespec timewait;
	timewait.tv_sec = 0;
	timewait.tv_nsec = 1000000;
	while (1) {
		for (i = 0; i < processors; i++) {
			pthread_mutex_lock(&thread_file[i].compr_file_mutex);
			if (thread_file[i].is_free) {
				thread_file[i].is_free = 0;
				pthread_mutex_unlock(&thread_file[i].
						compr_file_mutex);
				return i;
			}
			pthread_mutex_unlock(&thread_file[i].compr_file_mutex);
		}
		pthread_mutex_lock(&thread_file_free_mutex);
		pthread_cond_timedwait(&thread_file_free_cond,
				&thread_file_free_mutex, &timewait);
		pthread_mutex_unlock(&thread_file_free_mutex);
	}


}


void compress_file_thread(void *arg)
{
	struct thread_file_info *tinfo = (struct thread_file_info *)arg;
	int ret = 0;
	off_t new_file_size = 0;
	u_int64_t  begin, block = 0;
	struct vdfs4_catalog_file_record *f_rec = NULL;
	struct vdfs4_cattree_record *record = NULL;
	__mode_t src_mode;
	struct profiled_file* pfile = NULL;
	char* src_base_path;
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
	/*Do not repeat copy data for hlinks*/
	while (!tinfo->exit) {
		pthread_mutex_lock(&tinfo->compr_file_mutex);
		while (!(tinfo->has_data)) {
			pthread_cond_wait(&tinfo->compr_file_cond,
					&tinfo->compr_file_mutex);
			if (tinfo->exit) {
				pthread_mutex_unlock(&tinfo->compr_file_mutex);
				return;
			}
		}
		tinfo->has_data = 0;
		record = NULL;
		ret = 0;
		pthread_mutex_unlock(&tinfo->compr_file_mutex);
		pthread_mutex_lock(&files_count_mutex);
		if (*tinfo->error) {
			ret = *tinfo->error;
			pthread_mutex_unlock(&files_count_mutex);
			goto exit;
		}
		pthread_mutex_unlock(&files_count_mutex);
		assert(tinfo->parent_id == 0);

		record = find_record(tinfo->sbi,
				&tinfo->ptr->src_full_path[strlen(
					tinfo->sbi->root_path)]);
		if (IS_ERR(record)) {
			ret = PTR_ERR(record);
			goto err_exit;
		}

		if (record->key->record_type == VDFS4_CATALOG_HLINK_RECORD) {
			pthread_mutex_lock(&find_record_mutex);
			__u64 obj_id = record->key->object_id;
			vdfs4_release_record((struct vdfs4_btree_gen_record *)
					record);
			record = vdfs4_cattree_find(
					&tinfo->sbi->cattree.vdfs4_btree,
					obj_id, NULL, 0, VDFS4_BNODE_MODE_RW);
			f_rec = (struct vdfs4_catalog_file_record *)
					(record->val);
			if (IS_FLAG_SET(f_rec->common.flags,
					VDFS4_COMPRESSED_FILE)) {
				log_info("File %s has been copied already",
						tinfo->ptr->src_full_path);
				pthread_mutex_unlock(&find_record_mutex);
				goto exit;
			} else if (tinfo->ptr->cmd & CMD_COMPRESS) {
				f_rec->common.flags |=
					(1 << VDFS4_COMPRESSED_FILE);
			}
			pthread_mutex_unlock(&find_record_mutex);
		} else {
			f_rec = (struct vdfs4_catalog_file_record *)
					(record->val);
			if (IS_FLAG_SET(f_rec->common.flags,
					VDFS4_COMPRESSED_FILE)) {
				log_info("File %s has been copied already",
						tinfo->ptr->src_full_path);
				goto exit;
			}
		}
		if (IS_FLAG_SET(f_rec->common.flags, VDFS4_IMMUTABLE)) {
			log_info("File %s has been installed. Mkfs"
					" will not compress installed file",
					tinfo->ptr->src_full_path);
			goto exit;
		}

		if (IS_FLAG_SET(f_rec->common.flags, VDFS4_NOCOMPRESS_FILE)) {
			f_rec->common.flags &= ~(1 << VDFS4_NOCOMPRESS_FILE);
			/* EXEC files must stay compressed to retain auth feature */
			if(!is_exec_file_path(tinfo->ptr->src_full_path)) {
				ret = 0;
				clear_tuned_flags(&(f_rec->common.flags));
				goto exit;
			}
		}

		/* encryption can be enabled via:
		 * - VDFS4_ENCRYPTED_FILE record flag set in insert_record() */
		if(IS_FLAG_SET(f_rec->common.flags, VDFS4_ENCRYPTED_FILE) ||
			(tinfo->ptr->cmd & CMD_ENCRYPT)) {
			assert(record->key->record_type == VDFS4_CATALOG_FILE_RECORD);
			tinfo->ptr->cmd |= CMD_ENCRYPT;
			/* force compression */
			goto do_compress;
		}

		ret = check_file_before_compress(tinfo->ptr->src_full_path,
				tinfo->ptr->cmd & CMD_COMPRESS, &src_mode,
				tinfo->min_compressed_size);
		if (ret) {
			if (ret == -ENOTCOMPR) {
				log_info("File %s was not compressed because "
						"of too small size",
						tinfo->ptr->src_full_path);
				clear_tuned_flags(&(f_rec->common.flags));
				ret = 0;
			}
			goto err_exit;
		}

do_compress:
		if ((tinfo->ptr->cmd & CMD_ENCRYPT) &&
				(tinfo->ptr->cmd & CMD_COMPRESS))
			log_info("Compress and encrypt file %s", tinfo->ptr->src_full_path);
		else if (tinfo->ptr->cmd & CMD_COMPRESS)
			log_info("Compress file %s", tinfo->ptr->src_full_path);
		else if(tinfo->ptr->cmd & CMD_ENCRYPT)
			log_info("Encrypt file %s", tinfo->ptr->src_full_path);

		src_base_path = strchr(tinfo->ptr->src_full_path, '/');
		/* remove multiple / at the beginning - need just one */
		while (src_base_path[0] == '/' && src_base_path[1] == '/')
			src_base_path += 1;
		pfile = find_prof_data_path(&tinfo->sbi->prof_data, src_base_path);
		if (pfile)
			SET_FLAG(f_rec->common.flags, VDFS4_PROFILED_FILE);

		ret = encode_file(tinfo->sbi, tinfo->ptr->src_full_path,
				tinfo->sbi->disk_op_image.file_id,
				tinfo->ptr->cmd & CMD_COMPRESS,
				tinfo->ptr->compress_type, &new_file_size,
				tinfo->rsa_copy,
				tinfo->sbi->log_chunk_size,
				tinfo->sbi->tmpfs_dir, &block,
				(tinfo->thread_num - 1), tinfo->sbi->hash_alg,
				tinfo->sbi->hash_len,
				tinfo->ptr->cmd & CMD_ENCRYPT,
				pfile);

		if (!new_file_size)
			goto exit;

		if (ret) {
			if (ret == -ENOTCOMPR) {
				ret = 0;
			} else {
				log_error("Compression error - %d,"
						" file - %s", ret,
						tinfo->ptr->src_full_path);
				goto err_exit;
			}
		} else {
			pthread_mutex_lock(&find_record_mutex);
			if (tinfo->ptr->cmd & CMD_COMPRESS)
				f_rec->common.flags |= (1 << VDFS4_COMPRESSED_FILE);
			if (tinfo->ptr->cmd & CMD_ENCRYPT)
				f_rec->common.flags |=
						(1 << VDFS4_ENCRYPTED_FILE);
			pthread_mutex_unlock(&find_record_mutex);
		}

		begin = block_to_byte(block, tinfo->sbi->block_size);
		fork_init(&f_rec->data_fork, begin, new_file_size,
				tinfo->sbi->block_size);


err_exit:
exit:
		pthread_mutex_lock(&files_count_mutex);
		if (ret)
			*tinfo->error = ret;
		if (!IS_ERR(record) && record)
			vdfs4_release_record((struct vdfs4_btree_gen_record *)
					record);
		if (!--*tinfo->count) {
			pthread_mutex_unlock(&files_count_mutex);
			pthread_cond_broadcast(&file_finished);
		} else
			pthread_mutex_unlock(&files_count_mutex);
		pthread_mutex_lock(&tinfo->compr_file_mutex);
		tinfo->is_free = 1;
		pthread_mutex_unlock(&tinfo->compr_file_mutex);
		pthread_cond_broadcast(&thread_file_free_cond);

	}

}


void wait_finish(int *count)
{
	int a = 0;
	struct timespec timewait;
	timewait.tv_sec = 1;
	timewait.tv_nsec = 0;
	while (1) {

		pthread_mutex_lock(&files_count_mutex);

		a = *count;


		if (a) {
			pthread_mutex_unlock(&files_count_mutex);
			pthread_mutex_lock(&file_finished_mutex);
			pthread_cond_timedwait(&file_finished,
					&file_finished_mutex,
					&timewait);
			pthread_mutex_unlock(&file_finished_mutex);

		} else {
			pthread_mutex_unlock(&files_count_mutex);
			return;
		}
	}
}

static int compress_dir(struct vdfs4_sb_info *sbi,
		struct install_task *ptr)
{
	int ret = 0, ret_thread = 0;
	DIR *dir;
	char *path = NULL;
	struct dirent *data;
	struct dirent entry;
	struct stat info;
	struct install_task obj_ptr;
	int count = 0;
	char *dirpath = ptr->src_full_path;
	memset(&obj_ptr, 0, sizeof(struct install_task));

	if (ptr->cmd & CMD_COMPRESS)
		log_info("Recursive compress directory %s",
				dirpath);
	dir = opendir(dirpath);

	if (dir == NULL) {
		log_info("%s %s", "Can't open dir", dirpath);
		return errno;
	}
	obj_ptr.cmd = ptr->cmd;
	obj_ptr.compress_type = ptr->compress_type;
	/*while ((data = readdir(dir)) != NULL) {*/
	ret = readdir_r(dir, &entry, &data);
	while (!ret && data) {
		if ((strcmp(data->d_name, ".") == 0) ||
				(strcmp(data->d_name, "..") == 0))
			/*continue;*/
			goto next;
		if (strlen(dirpath) + strlen(data->d_name) + 2 >
					VDFS4_FULL_PATH_LEN) {
			log_error("Full path to file is too long - %s/%s."
					"Should be not more than %d",
					dirpath, data->d_name,
					VDFS4_FULL_PATH_LEN);
			ret = -ENAMETOOLONG;
			goto exit;
		}
		path = calloc(1, strlen(dirpath) + strlen(data->d_name) + 2);
		if (!path) {
			ret = -ENOMEM;
			goto exit;
		}
		strncat(path, dirpath, strlen(dirpath));
		if (path[strlen(dirpath) - 1] != '/')
			strncat(path, "/", 1);
		strncat(path, data->d_name, strlen(data->d_name));
		memset(obj_ptr.src_full_path, 0, sizeof(obj_ptr.src_full_path));
		memcpy(obj_ptr.src_full_path, path, strlen(path));
		obj_ptr.src_fname = data->d_name;
		ret = lstat(path, &info);
		if (ret)
			goto exit;
		if (S_ISDIR(info.st_mode)) {
			memcpy(obj_ptr.src_full_path + strlen(path), "/", 1);
			ret = compress_dir(sbi, &obj_ptr);
			if (ret)
				goto exit;
		} else if (((S_ISREG(info.st_mode)) ||
			(IS_FLAG_SET(sbi->service_flags, READ_ONLY_IMAGE)
			&& S_ISLNK(info.st_mode))) && (info.st_size)) {

			int tnum = get_free_file_thread();
			pthread_mutex_lock(&thread_file[tnum].compr_file_mutex);
			memcpy(thread_file[tnum].ptr, &obj_ptr,
					sizeof(struct install_task));
			thread_file[tnum].parent_id = 0;
			thread_file[tnum].sbi = sbi;
			thread_file[tnum].has_data = 1;
			thread_file[tnum].is_free = 0;
			thread_file[tnum].error = &ret_thread;
			thread_file[tnum].min_compressed_size = sbi->min_compressed_size;
			pthread_mutex_lock(&files_count_mutex);
			count++;

			thread_file[tnum].count = &count;
			pthread_mutex_unlock(&files_count_mutex);
			pthread_cond_signal(&thread_file[tnum].compr_file_cond);
			pthread_mutex_unlock(
					&thread_file[tnum].compr_file_mutex);
		}

		free(path);
		path = NULL;
next:
		ret = readdir_r(dir, &entry, &data);
	}

	ret = ret_thread;
exit:
	wait_finish(&count);
	free(path);
	closedir(dir);
	return ret;
}

void clear_install_task_list(struct list_head *install_task_list)
{
	struct list_head *pos, *q;

	list_for_each_safe(pos, q, install_task_list) {
		struct install_task *ptr =
			list_entry(pos, struct install_task, list);
		list_del(pos);
		free(ptr);
	}
}


int tune_files(struct vdfs4_sb_info *sbi,
		struct list_head *install_task_list) {
	int ret = 0, ret_thread = 0;
	struct list_head *pos;
	struct stat stat_info;
	int count = 0;
	/* first we need process files that musn't be compressed */
	for (pos = install_task_list->next; pos != install_task_list;
					pos = pos->next) {
		struct install_task *ptr =
					list_entry(pos, struct install_task, list);
		if(ptr->cmd == CMD_DECOMPRESS) {
			ret = disable_compression(ptr, sbi);
			if(ret) {
				log_error("Disable compression error=%d", ret);
				return ret;
			}
		}
	}
	for (pos = install_task_list->next; pos != install_task_list;
				pos = pos->next) {
		struct install_task *ptr =
			list_entry(pos, struct install_task, list);
		if ((ptr->cmd & CMD_COMPRESS)) {
			ret = lstat(ptr->src_full_path, &stat_info);
			if (ret) {
				log_error("Can't get stat info of %s",
						ptr->src_full_path);
				ret = errno;
				goto exit;
			}
			if (S_ISREG(stat_info.st_mode)) {
				/*ret = compress_file(sbi, ptr, 0);
				if (ret) {
					log_error("Can't process file %s",
							ptr->src_full_path);
					goto exit;
				}*/
				if (!stat_info.st_size)
					continue;
				int tnum = get_free_file_thread();
				pthread_mutex_lock(&thread_file[tnum].
						compr_file_mutex);
				memcpy(thread_file[tnum].ptr, ptr,
						sizeof(struct install_task));
				thread_file[tnum].parent_id = 0;
				thread_file[tnum].sbi = sbi;
				thread_file[tnum].has_data = 1;
				pthread_mutex_lock(&files_count_mutex);
				count++;
				thread_file[tnum].count = &count;
				thread_file[tnum].error = &ret_thread;
				thread_file[tnum].min_compressed_size = sbi->min_compressed_size;
				pthread_mutex_unlock(&files_count_mutex);
				pthread_cond_signal(&thread_file[tnum].
						compr_file_cond);
				pthread_mutex_unlock(&thread_file[tnum].
						compr_file_mutex);
			} else if (S_ISDIR(stat_info.st_mode)) {
				ret = compress_dir(sbi, ptr);
				if (ret)
					goto exit;
			} else {
				log_error("Incorrect type of %s. "
					"Can be regular file or directory only",
					ptr->src_full_path);
				ret = -EINVAL;
				goto exit;
			}
		}
	}


	ret = ret_thread;
exit:
	wait_finish(&count);
	return ret;
}

static int disable_file_compression(char* path, struct vdfs4_sb_info* sbi)
{
	struct vdfs4_cattree_record *record;
	struct vdfs4_catalog_file_record *file_rec;
	char *rec_path;
	if(!path || !sbi)
		return -EINVAL;

	rec_path = malloc(VDFS4_FULL_PATH_LEN + 1);
	if(!rec_path)
		return -ENOMEM;

	log_info("Disabling compression on file=%s", path);
	strncpy(rec_path, path + strlen(sbi->root_path), VDFS4_FULL_PATH_LEN);
	record = find_record(sbi, rec_path);
	free(rec_path);
	if (IS_ERR(record)) {
		log_error("Record for file not found!");
		return PTR_ERR(record);
	}

	file_rec = (struct vdfs4_catalog_file_record *)
						record->val;
	file_rec->common.flags |= (1 << VDFS4_NOCOMPRESS_FILE);
	vdfs4_release_record((struct vdfs4_btree_gen_record *)
						record);
	return 0;
}

static int disable_dir_compression(char* dir_path, struct vdfs4_sb_info* sbi)
{
	DIR *dir;
	char err_msg[ERR_BUF_LEN];
	int ret;
	struct dirent *data;
	struct dirent entry;
	char *cur_path;
	if(!dir_path || !sbi)
		return -EINVAL;
	cur_path = malloc(VDFS4_FULL_PATH_LEN + 1);
	if(!cur_path)
		return -ENOMEM;
	dir = opendir(dir_path);
	if (!dir) {
		log_error("disable_dir_compression Can't open dir %s - %s",
				dir_path, strerror_r(errno, err_msg, ERR_BUF_LEN));
		ret = -errno;
		goto err_dir;
	}
	ret = readdir_r(dir, &entry, &data);
	while (!ret && data) {
		struct stat st;
		if ((strcmp(data->d_name, ".") == 0) ||
			(strcmp(data->d_name, "..") == 0))
			goto next;
		cur_path[0] = '\0';
		strncat(cur_path, dir_path, strlen(dir_path));
		if(cur_path[strlen(cur_path) - 1] != '/')
			strncat(cur_path, "/", 1);
		strncat(cur_path, data->d_name, strlen(data->d_name));

		ret = lstat(cur_path, &st);
		if(ret) {
			log_error("disable_dir_compression failed to stat err=%d path: %s",
					-errno, cur_path);
			ret = -errno;
			goto err;
		}

		if(S_ISREG(st.st_mode)) {
			ret = disable_file_compression(cur_path, sbi);
			if(ret)
				goto err;
		} else if(S_ISDIR(st.st_mode)) {
			log_info("Resurively disabling compression in directory %s", cur_path);
			ret = disable_dir_compression(cur_path, sbi);
			if(ret)
				goto err;
		}
next:
		ret = readdir_r(dir, &entry, &data);
		continue;
	}
	if(ret) {
		log_error("disable_dir_compression readdir err=%d path=%s",
				ret, dir_path);
		goto err;
	}
err:
	closedir(dir);
err_dir:
	free(cur_path);
	return ret;
}

int disable_compression(struct install_task *task, struct vdfs4_sb_info* sbi)
{
	struct stat st;
	int ret;

	if(!task || !sbi)
		return -EFAULT;
	if(!strlen(task->src_full_path))
		return -EINVAL;

	ret = lstat(task->src_full_path, &st);
	if(ret) {
		log_error("disable_compression failed to stat err=%d path: %s",
				-errno, task->src_full_path);
		return -errno;
	}

	if(S_ISREG(st.st_mode)) {
		ret = disable_file_compression(task->src_full_path, sbi);
		if(ret)
			return ret;
	} else if(S_ISDIR(st.st_mode)) {
		ret = disable_dir_compression(task->src_full_path, sbi);
		if(ret)
			return ret;
	}

	return 0;
}
