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
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <pthread.h>
#include <openssl/crypto.h>

static pthread_mutex_t *crypto_lock = NULL;
static void crypto_lock_callback(int mode, int type,
				 const char *file, int line)
{
	if (mode & CRYPTO_LOCK)
		pthread_mutex_lock(&(crypto_lock[type]));
	else
		pthread_mutex_unlock(&(crypto_lock[type]));
}

int init_crypto_lock(void)
{
	int i;
	crypto_lock = malloc(sizeof(pthread_mutex_t) * CRYPTO_num_locks());
	if (!crypto_lock)
		return -ENOMEM;
	for (i = 0 ; i < CRYPTO_num_locks(); i++)
		pthread_mutex_init(&(crypto_lock[i]), NULL);
	CRYPTO_set_locking_callback(crypto_lock_callback);
	return 0;
}

void destroy_crypto_lock(void)
{
	int i;
	if (!crypto_lock)
		return;
	CRYPTO_set_locking_callback(NULL);
	for (i = 0; i < CRYPTO_num_locks() ; i++)
		pthread_mutex_destroy(&(crypto_lock[i]));
	free(crypto_lock);
	crypto_lock = NULL;
}
