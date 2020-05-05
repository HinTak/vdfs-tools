/**
 * VDFS4 -- Vertically Deliberate improved performance File System
 *
 * Copyright 2014 by Samsung Electronics, Inc.
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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>

#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>

#include "vdfs_tools.h"
#include "compress.h"

int hextoint(char c)
{
	switch (c) {
	case 'a':
		c = 'A';
		break;
	case 'b':
		c = 'B';
		break;
	case 'c':
		c = 'C';
		break;
	case 'd':
		c = 'D';
		break;
	case 'e':
		c = 'E';
		break;
	case 'f':
		c = 'F';
		break;
	default:
		break;
	}
return c > '9' ? c - 'A' + 10 : c - '0';
}

int get_key_from_file(unsigned char *mkey, const char *filename, int m_keysize)
{
	int i, ret, realsize;
	FILE *file;
	unsigned char key[m_keysize];
	unsigned char tmp[m_keysize*2];

	realsize = m_keysize*2;

	file = fopen(filename, "r");
	if (file == NULL) {
		printf("[ERROR] %s does not exist.!!!!\n", filename);
		return -1;
	}
	ret = fread((void *)tmp, sizeof(unsigned char), realsize, file);
	if( ret != realsize ) {
		printf("[ERROR] real size and read size"
				" are different (real size:%d,"
				" read size : %d!!!!\n", realsize, ret);
		fclose(file);
		return -1;
	}
	for (i = 0; i < realsize; i = i+2) {
		ret = (hextoint((char)tmp[i]) << 4) + hextoint((char)tmp[i+1]);
		key[i/2] = ret;
	}
	memcpy(mkey, key, m_keysize);

	fclose(file);
	return 0;
}

RSA *create_rsa_from_private_str(char *private_str)
{
	RSA *rsa = NULL;
	BIO *mem;
	mem = BIO_new_mem_buf(private_str, strlen(private_str));
	if (!mem) {
		return ERR_PTR(-ENOMEM);
	}
	rsa = PEM_read_bio_RSAPrivateKey(mem, NULL, NULL, NULL);
	BIO_free(mem);
	return rsa;
}

RSA *create_rsa(char *private_file, char *pub_file, char *q_file, char *p_file)
{
	int ret = 0;
	RSA *rs = NULL;
	BN_CTX *ctx = NULL;
	ctx = BN_CTX_new();
	if (ctx == NULL)
		return ERR_PTR(-ENOMEM);
	BN_CTX_start(ctx);

	if (pub_file) {
		int expon = 0x10001;
		unsigned char *modulus = NULL, *private = NULL;
		modulus = malloc(RSA_KEY_SIZE);
		if (!modulus)
			goto err_exit;
		private = malloc(RSA_KEY_SIZE);
		if (!private)
			goto err_exit;
		ret = get_key_from_file(modulus, pub_file, RSA_KEY_SIZE);
		if (ret)
			goto err_exit;
		ret = get_key_from_file(private, private_file, RSA_KEY_SIZE);
		if (ret)
			goto err_exit;
		rs = RSA_new();
		if (!rs)
			goto err_exit;
		rs->ex_data.dummy = 0;
		rs->meth->init(rs);
		rs->n = BN_new();
		rs->d = BN_new();
		rs->e = BN_new();

		BN_bin2bn(modulus, RSA_KEY_SIZE, rs->n);
		BN_bin2bn(private, RSA_KEY_SIZE, rs->d);
		BN_bin2bn((const unsigned char *)&expon, 3, rs->e);
		/*Calculate*/
		if (q_file && p_file) {
			BIGNUM *r1 = NULL, *r2 = NULL;

			unsigned char *p = NULL, *q = NULL;


			r1 = BN_CTX_get(ctx);
			r2 = BN_CTX_get(ctx);
			if (r2 == NULL || r1 == NULL)
				goto err1_exit;
			rs->p = BN_new();
			rs->q = BN_new();
			rs->dmp1 = BN_new();
			rs->dmq1 = BN_new();
			rs->iqmp = BN_new();
			p = malloc(RSA_KEY_SIZE);
			q = malloc(RSA_KEY_SIZE);
			if (!p || !q)
				goto err1_exit;
			memset(p, 0, RSA_KEY_SIZE);
			memset(q, 0, RSA_KEY_SIZE);
			ret = get_key_from_file(p, p_file, RSA_KEY_SIZE);
			if (ret)
				goto err1_exit;
			ret = get_key_from_file(q, q_file, RSA_KEY_SIZE);
			if (ret)
				goto err1_exit;


			BN_bin2bn(q, RSA_KEY_SIZE, rs->q);
			BN_bin2bn(p, RSA_KEY_SIZE, rs->p);

			if (!BN_sub(r1, rs->p, BN_value_one()))
				goto err1_exit;	/* p-1 */
			if (!BN_sub(r2, rs->q, BN_value_one()))
				goto err1_exit;	/* q-1 */

			/* calculate d mod (p-1) */
			if (!BN_mod(rs->dmp1, rs->d, r1, ctx))
				goto err1_exit;

			/* calculate d mod (q-1) */
			if (!BN_mod(rs->dmq1, rs->d, r2, ctx))
				goto err1_exit;

			/* calculate inverse of q mod p */
			if (!BN_mod_inverse(rs->iqmp, rs->q, rs->p, ctx))
				goto err1_exit;

err1_exit:

			free(p);
			free(q);

		}
err_exit:
		free(modulus);
		free(private);
	} else {
		FILE *fp = fopen(private_file, "r");
		if (fp == NULL)
			return NULL;
		rs = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
		fclose(fp);
	}
	if (rs && !(rs->flags & RSA_FLAG_NO_BLINDING))
		rs->blinding = RSA_setup_blinding(rs, ctx);
	if (ctx != NULL) {
		BN_CTX_end(ctx);
		BN_CTX_free(ctx);
	}
	return rs;

}

int get_sign_type(RSA *key)
{
	int len;

	if (key == NULL)
		return VDFS4_SIGN_NONE;
	len = RSA_size(key);
	switch (len) {
		case 128:
			return VDFS4_SIGN_RSA1024;
		case 256:
			return VDFS4_SIGN_RSA2048;
		default:
			return VDFS4_SIGN_NONE;
	}
}

int get_sign_length(RSA* key)
{
	if (key == NULL)
		return 0;
	return RSA_size(key);
}

int sign_rsa(unsigned char *buf, unsigned long buf_len,
		unsigned char *rsa_hash, RSA *rsa_key,
		vdfs4_hash_algorithm_func *hash_alg, int hash_len)
{
	int ret = 0;
	unsigned char* hash = malloc(hash_len);
	if (!hash)
		return -ENOMEM;

	hash_alg(buf, buf_len, hash);
	ret = RSA_private_encrypt(hash_len,
			(const unsigned char *)hash,
			rsa_hash, rsa_key, RSA_PKCS1_PADDING);
	free(hash);
	if (ret != RSA_size(rsa_key))
		return -EINVAL;

	return 0;
}

/* function gets cur_align align and finds least common multiple
 * of it and predefined encrypted chunk align.
 * Found value is returned back trough cur_align.
 */
void encrypted_chunk_align(size_t *cur_align, int align_type)
{
	size_t t, lcm, a, b, x, y;
	size_t encrypt_align = (size_t)((align_type == ALIGN_START) ?
			VDFS4_AES_CHUNK_ALIGN_START :
			VDFS4_AES_CHUNK_ALIGN_LEN);

	a = *cur_align;
	b = encrypt_align;
	if(a == 0)
		a = 1;
	if(b == 0)
		b = 1;
	x = a;
	y = b;

	while (b != 0) {
		t = b;
		b = a % b;
		a = t;
	}

	lcm = (x*y)/a;
	if(lcm == 1)
		lcm = 0;

	assert((lcm % encrypt_align) == 0);
	assert((lcm % x) == 0);

	*cur_align = lcm;
}

void encrypt_chunk(unsigned char *in, unsigned char *out,
		unsigned char *nonce, AES_KEY *encryption_key, int size, u64 AES_offset)
{
	unsigned char ivec[AES_BLOCK_SIZE];
	unsigned char ecount[AES_BLOCK_SIZE];
	unsigned int num;

	if( encryption_key == NULL || in == NULL || out == NULL || nonce == NULL )
	{
		printf("decrypt_chunk() - invalid parameters.\n");
		return;
	}

	memset(ecount, 0, AES_BLOCK_SIZE);
	memcpy(ivec, nonce, VDFS4_AES_NONCE_SIZE);
	memcpy(ivec + VDFS4_AES_NONCE_SIZE, &AES_offset, AES_BLOCK_SIZE - VDFS4_AES_NONCE_SIZE);

	while (size >= AES_BLOCK_SIZE) {
		num = 0;
		AES_ctr128_encrypt(in, out, AES_BLOCK_SIZE, encryption_key, ivec, ecount, &num);
		in +=  AES_BLOCK_SIZE;
		out += AES_BLOCK_SIZE;
		size -= AES_BLOCK_SIZE;
	}
	if (size > 0) {
		num = 0;
		AES_ctr128_encrypt(in, out, size, encryption_key,   ivec, ecount, &num);
	}
}

int read_encryption_key(struct vdfs4_sb_info *sbi, char *filename)
{
	FILE *file;
	unsigned int bytes;
	if( filename == NULL )
	{
		printf("Invalid args. Filename is null\n");
		return -ENOENT;
	}

	file = fopen(filename, "r");
	if( file == NULL )
	{
		printf("Error while opening file: %s\n", filename);
		return -ENOENT;
	}
	bytes = fread((void *)sbi->raw_encryption_key,
			sizeof(unsigned char), AES_BLOCK_SIZE, file);

	if( bytes != AES_BLOCK_SIZE )
	{
		printf("Password length is insufficient\n");
		fclose(file);
		return -EINVAL;
	}
	sbi->aes_key = malloc(sizeof(*sbi->aes_key));
	if(!sbi->aes_key) {
		log_error("Failed to allocate memory fo sbi's AES key");
		fclose(file);
		return -ENOMEM;
	}

	AES_set_encrypt_key(sbi->raw_encryption_key, 128, sbi->aes_key);
	fclose(file);

	return 0;
}
