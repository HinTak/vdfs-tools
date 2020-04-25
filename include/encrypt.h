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

#ifndef	__VDFS4_ENCRYPT_H__
#define	__VDFS4_ENCRYPT_H__

#include <openssl/aes.h>
#include <openssl/rand.h>
#include <vdfs_tools.h>

/* when changing contents of this structure make sure
 * it can be safely copied between different threads */
struct vdfs4_aes_info {
	int do_encrypt;
	unsigned char aes_nonce[VDFS4_AES_NONCE_SIZE];
	AES_KEY aes_key;
};

int get_key_from_file(unsigned char *mkey, const char *filename, int m_keysize);
int read_encryption_key(struct vdfs4_sb_info *sbi, char *filename);
int read_encryption_key_sb(struct vdfs4_sb_info *sbi,
		struct vdfs4_super_block *sb);

void encrypt_chunk(unsigned char *in, unsigned char *out,
		unsigned char *nonce, AES_KEY *encryption_key, int size, u64 AES_offset);
void encrypted_chunk_align(size_t *cur_align, int align_type);

#endif /* __VDFS4_ENCRYPT_H__ */
