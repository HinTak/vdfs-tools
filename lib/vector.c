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

#ifndef VDFS4_VECTOR
#define VDFS4_VECTOR
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "vdfs_tools.h"


void init_vector(struct vector *v, int size_of_data)
{
	v->mem_size = 100;
	v->size = 0;
	v->data_size = size_of_data;
	v->data = calloc(size_of_data, v->mem_size);
}

void destroy_vector(struct vector *v)
{
	free(v->data);
}

void push_elem(struct vector *v, void *data)
{
	if (v->size == v->mem_size) {
		v->mem_size *= 2;
		v->data = realloc(v->data, v->mem_size * v->data_size);
	}
	memcpy((v->data + v->data_size * v->size), data,
			v->data_size);
	v->size++;
}

void *get_elem(struct vector *v, u64 pos)
{
	/*assert(pos >= 0);*/
	assert(pos < v->size);
	return v->data + v->data_size * pos;
}
/*

void set_elem(struct vector *v, int pos, void *data)
{
	if (pos >= v->mem_size) {
		while (pos >= v->mem_size)
			v->mem_size *= 2;
		v->data = realloc(v->data, v->mem_size * v->data_size);
	}
	memcpy((v->data + v->data_size * pos), data, v->data_size);
}
*/
void delete_elem(struct vector *v, u64 pos)
{
	assert(v->size);
	assert(pos < v->size);
	__u64 copy_len = (v->size - pos) * v->data_size;
	void *temp = malloc(copy_len);
	memcpy(temp, v->data + (pos + 1) * v->data_size, copy_len);
	memcpy(v->data + pos * v->data_size, temp, copy_len);
	free(temp);
	v->size--;
}
#endif
