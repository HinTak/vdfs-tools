/**
 * VDFS4 -- Vertically Deliberate improved performance File System
 *
 * Copyright 2013 by Samsung Electronics, Inc.
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

#ifndef XATRTREE_H_
#define XATRTREE_H_

#include "vdfs4_layout.h"

#define XATTRTREE_LEAF "XAle"
#define VDFS4_XATTRTREE_ROOT_REC_NAME "xattr_root"


struct vdfs4_xattrtree_record {
	struct vdfs4_xattrtree_key *key;
	char *val;
};


#endif

