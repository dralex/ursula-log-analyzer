/* -----------------------------------------------------------------------------
 * The Cyberiada Ursula game engine log analyzer
 *
 * The command line checker program
 *
 * Copyright (C) 2025 Alexey Fedoseev <aleksey@fedoseev.net>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see https://www.gnu.org/licenses/
 * ----------------------------------------------------------------------------- */

#include <stdio.h>
#include <stdlib.h>

#include "ursulalogcheck.h"

static void print_usage(const char* name)
{
	fprintf(stderr, "Usage: %s <config-file> <task-id> <salt> <log-file>\n", name);
	fprintf(stderr, "\n");
}

int main(int argc, char** argv)
{
	const char *config_file = NULL, *task_id = NULL, *log_file = NULL;
	int salt = 0;
	UrsulaLogCheckerData* checker = NULL;
	UrsulaLogCheckerResult result = 0;
	char* result_code = NULL;
	int res = 0;
	
	if (argc != 5) {
		print_usage(argv[0]);
		return 99;
	}

	config_file = argv[1];
	task_id = argv[2];
	salt = atoi(argv[3]);
	log_file = argv[4];

	res = cyberiada_ursula_log_checker_init(&checker, config_file);
	if (res != URSULA_CHECK_NO_ERROR) {
		fprintf(stderr, "Cannot initialize Ursula log checker library: %d\n", res);
		return res;
	}

	res = cyberiada_ursula_log_checker_check_log(checker,
												 task_id,
												 salt,
												 log_file,
												 &result,
												 &result_code);
	if (res != URSULA_CHECK_NO_ERROR) {
		fprintf(stderr, "Program checking error: %d\n", res);
		printf("Result code: %d\n", result);
	} else {
		printf("Checking completed!\n");
		printf("Result code: %d\n", result);
		printf("Code string: %s\n", result_code);
	}

	if (result_code) free(result_code);
	cyberiada_ursula_log_checker_free(checker);
	
	return res;
}
