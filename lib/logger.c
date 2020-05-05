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

#include <stdarg.h>
#include <stdio.h>
#include <ctype.h>
#include "../include/vdfs_tools.h"

/**
 * @brief logger verbosity
 */
enum logger_level log_level = LOG_ERRORS_WARNINGS;

/**
 * @brief Function that actualy write to log.
 * @param [in] msg NULL terminated string with message.
 * @return void
 */
void show_log_message(const char *type, const char *format, va_list argptr)
{
	if (NULL == format)
		return;

	printf("[%s]: ", type);
	vprintf(format, argptr);
	printf("\n");
}

void set_logger_verbosity(const enum logger_level value)
{
	log_level = value;
}

void log_note(const char *format, ...)
{
	va_list argptr;

	va_start(argptr, format);
	show_log_message("VDFS-NOTE", format, argptr);
	va_end(argptr);
}

void log_error(const char *format, ...)
{
	va_list argptr;

	va_start(argptr, format);
	show_log_message("VDFS-ERROR", format, argptr);
	va_end(argptr);
}

void log_warning(const char *format, ...)
{
	va_list argptr;

	if (log_level >= LOG_ERRORS_WARNINGS) {
		va_start(argptr, format);
		show_log_message("VDFS-WARNING", format, argptr);
		va_end(argptr);
	}
}

void log_info(const char *format, ...)
{
	va_list argptr;

	if (log_level >= LOG_INFO) {
		va_start(argptr, format);
		show_log_message("VDFS-INFO", format, argptr);
		va_end(argptr);
	}
}

void log_activity(const char *format, ...)
{
	va_list argptr;

	if (log_level >= LOG_ACTIVITY) {
		va_start(argptr, format);
		show_log_message("VDFS-JOB", format, argptr);
		va_end(argptr);
	}
}

void log_data(void *data, int size)
{
	unsigned char *p;
	int offset;
	int i;

	if (log_level < LOG_DATA)
		return;

	for (offset = 0, p = data; offset < size; offset += 16, p += 16) {
		printf("%#8x :", offset);
		for (i = 0; i < 16 && i < size - offset ; i++)
			printf(" %02x", p[i]);
		for (; i < 16; i++)
			printf("   ");
		printf(" |");
		for (i = 0; i < 16 && i < size - offset ; i++)
			if (isprint(p[i]))
				printf("%c", p[i]);
			else
				printf(".");
		printf("|\n");
	}
}
