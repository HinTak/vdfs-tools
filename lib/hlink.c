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

#include <vdfs_tools.h>
#include "logger.h"

/**
 * @brief	Init new item of list with data
 * @param[out]	item	Pointer to a structure to init
 * @param[in]	object_id Value to set to object_id field
 * @param[in]	name	String with full path to the object to set
 */
void hl_list_item_init(struct hlink_list_item *item, __le64 ino_n, char *name,
		__le64 new_ino_n)
{
	memset(item, 0, sizeof(struct hlink_list_item));
	item->ino_n = ino_n;
	item->new_ino_n = new_ino_n;
	if (strlen(name) <= VDFS4_FULL_PATH_LEN)
		strncpy(item->name, name, strlen(name));
	item->links = 1;
}

void hl_list_insert(struct hlink_list_item *head, struct hlink_list_item *new)
{
	struct hlink_list_item *list = head;

	while (list != NULL) {
		if (list->next == NULL) {
			list->next = new;
			break;
		}
		if (list->next->new_ino_n > new->new_ino_n) {
			new->next = list->next;
			list->next = new;
			break;
		}
		list = list->next;
	}
}


struct hlink_list_item *hl_list_item_find(struct hlink_list_item *head,
		__u64 object_id)
{
	struct hlink_list_item *list = head;

	while (list != NULL) {
		if (list->ino_n == object_id)
			return list;
		list = list->next;
	}
	return 0;
}

void hl_list_free(struct hlink_list_item *list)
{
	while (list != NULL) {
		struct hlink_list_item *temp = list;
		list = list->next;
		free(temp);
	}
}
