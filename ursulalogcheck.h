/* -----------------------------------------------------------------------------
 * The Cyberiada Ursula game engine log analyzer
 *
 * The C library header
 *
 * Copyright (C) 2025 Alexey Fedoseev <aleksey@fedoseev.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see https://www.gnu.org/licenses/
 *
 * ----------------------------------------------------------------------------- */

#ifndef __URSULA_LOG_CHECK_H
#define __URSULA_LOG_CHECK_H

#ifdef __cplusplus
extern "C" {
#endif

/* -----------------------------------------------------------------------------
 * The internal structure
 * ----------------------------------------------------------------------------- */
	
struct _UrsulaLogCheckerData;
typedef struct _UrsulaLogCheckerData UrsulaLogCheckerData;

/* -----------------------------------------------------------------------------
 * The library checker result codes
 * ----------------------------------------------------------------------------- */
	
typedef char UrsulaLogCheckerResult;

#define URSULA_CHECK_RESULT_ERROR       0
#define URSULA_CHECK_RESULT_VALID_FLAGS 0x7f

/* -----------------------------------------------------------------------------
 * The library error codes
 * ----------------------------------------------------------------------------- */
	
#define URSULA_CHECK_NO_ERROR       0
#define URSULA_CHECK_BAD_PARAMETERS 1
#define URSULA_CHECK_FORMAT_ERROR   2

/* -----------------------------------------------------------------------------
 * The checker library functions
 * ----------------------------------------------------------------------------- */

	/* Initialize the checker internal structure using the config file located
	   at the path from config_file */
	int cyberiada_ursula_log_checker_init(UrsulaLogCheckerData** checker, const char* config_file);
	
	/* Free the checker internal structure */
	int cyberiada_ursula_log_checker_free(UrsulaLogCheckerData* checker);

	/* Check the CyberiadaML program from the buffer in the context of the task.
       Returns the actual result and the encoded result string */
	int cyberiada_ursula_log_checker_check_log(UrsulaLogCheckerData* checker,
											   const char* task_id,
											   int salt,
											   const char* program_file,
											   UrsulaLogCheckerResult* result,
											   char** result_code);

#ifdef __cplusplus
}
#endif
    
#endif
