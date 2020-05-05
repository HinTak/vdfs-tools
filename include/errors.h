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

#ifndef _VDFS4_ERRORS_H_
#define _VDFS4_ERRORS_H_

#include <asm-generic/errno.h>

#define EWRONGOPTS	134  /* Wrong program options */
#define ENOSECTSIZE	135  /* Diskop can't get sectors size */
#define ENOSECTNUM	136  /* Diskop can't get sectors count */
#define EISMNTD		137  /* Diskop device is mounted */
#define EWRFAIL		138  /* Diskop write operation fail */
#define ERDFAIL		139  /* Diskop read operation fail */
#define ENOTCOMPR	140  /*	Compression operation fail*/
#define ENOTCMD		141  /*	Can't find cmd word*/
#endif
