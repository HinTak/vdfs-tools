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

#include "../include/vdfs_list.h"

void vdfs4_list_init(struct vdfs4_list *list)
{
	list->current_node = NULL;
	list->head_node.prev = NULL;
	list->head_node.next = NULL;
	list->count = 0;
}

void vdfs4_list_free(struct vdfs4_list *list)
{
	struct list_node *curr_node = list->head_node.next;
	struct list_node *next_node;

	for (;;)
	{
		if (!curr_node)
			return;

		next_node = curr_node->next;
		free(curr_node);
		curr_node = next_node;
	}
}

void vdfs4_add_to_list(struct vdfs4_list *list, void *data, u_int32_t data_size)
{
	struct list_node *node_new;
	struct list_node *node_old;
	/* generating new node */
	node_new = (struct list_node *)malloc(sizeof(struct list_node));
	assert(node_new != NULL);
	node_new->data = data;
	node_new->data_size = data_size;

	/* adding node to list */
	node_old = list->head_node.prev;
	node_new->prev = node_old;
	node_new->next = NULL;
	if (!node_old)
		list->head_node.next = node_new;
	else
		node_old->next = node_new;

	list->current_node = node_new;
	list->head_node.prev = node_new;
	list->count++;
}

static inline void *vdfs4_get_cur_elem_data_from_list(struct vdfs4_list *list)
{
	if (list->current_node == NULL)
		return NULL;

	return list->current_node->data;
}

inline void vdfs4_list_reset_to_first(struct vdfs4_list *list)
{
	list->current_node = list->head_node.next;
}

int vdfs4_list_switch_to_next(struct vdfs4_list *list)
{
	if (list->current_node != NULL)
		list->current_node = list->current_node->next;
	if (NULL == list->current_node)
		return -EINVAL;

	return 0;
}

void vdfs4_put_list_to_buffer(struct vdfs4_list *list, void *buffer, int offset,
		int element_size)
{
	int i;
	char *char_buffer = buffer;
	void *list_data = vdfs4_get_cur_elem_data_from_list(list);
	if (!list_data)
		return;
	for (i = 0; !(vdfs4_list_switch_to_next(list)); i++) {
		memcpy(&char_buffer[offset + i * element_size],
			list_data, element_size);
	}
}
