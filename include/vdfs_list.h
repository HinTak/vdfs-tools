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

#ifndef _VDFS_LIST_H
#define _VDFS_LIST_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <stdbool.h>
#include <errno.h>
#include <assert.h>

/*
 * @struct Node of the list
 */

struct list_node {
	void *data;
	u_int32_t data_size;
	struct list_node *next;
	struct list_node *prev;
};
/*
 * @struct The main structure for list
 */
struct vdfs4_list {
	struct list_node *current_node;
	struct list_node head_node;
	u_int32_t count;
};

void vdfs4_list_init(struct vdfs4_list *list);

void vdfs4_list_free(struct vdfs4_list *list);

void vdfs4_add_to_list(struct vdfs4_list *list, void *data, u_int32_t data_size);

int vdfs4_list_switch_to_next(struct vdfs4_list *list);

void vdfs4_put_list_to_buffer(struct vdfs4_list *list, void *buffer, int offset, int element_size);

#endif
