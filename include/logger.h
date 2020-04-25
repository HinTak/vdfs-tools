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

#ifndef __LOGGER_H__
#define __LOGGER_H__

/**
 * @brief Enumeration of possible log levels.
 */
enum logger_level {
	LOG_ERRORS,               /* log only errors                         */
	LOG_ERRORS_WARNINGS,      /* log only errors and warnings            */
	LOG_ACTIVITY,             /* log all above and activity messages     */
	LOG_INFO,                 /* log all above and verbose debug info    */
	LOG_DATA,		  /* log huge hex dumps of data blobs	     */
	LOG_ALL                   /* log all messages                        */
};

/**
 * @brief Set verbosity level of logger.
 * @param [in] value of debug level to be set.
 * @return void
 */
void set_logger_verbosity(const enum logger_level value);

/**
 * @brief Log message with error verbosity.
 * @param [in] format NULL terminated string with message.
 * @return void
 */
void log_error(const char *format, ...);

/**
 * @brief Log message with warning verbosity.
 * @param [in] format NULL terminated string with message.
 * @return void
 */
void log_warning(const char *format, ...);

/**
 * @brief Log message with info verbosity.
 * @param [in] format NULL terminated string with message.
 * @return void
 */
void log_info(const char *format, ...);

/**
 * @brief Log activity message with, for actions, that can take a time.
 * @param [in] format NULL terminated string with message.
 * @return void
 */
void log_activity(const char *format, ...);

/**
 * Dump hex dump of data blob
 */
void log_data(void *data, int size);

#endif /* __LOGGER_H__ */
