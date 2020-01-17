/*
 * Copyright (C) 2019-2020 Rick V. All rights reserved.
 *
 * This software is provided 'as-is', without any express or implied
 * warranty.  In no event will the authors be held liable for any damages
 * arising from the use of this software.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely, subject to the following restrictions:
 *
 * 1. The origin of this software must not be misrepresented; you must not
 *    claim that you wrote the original software. If you use this software
 *    in a product, an acknowledgment in the product documentation would be
 *    appreciated but is not required.
 * 2. Altered source versions must be plainly marked as such, and must not be
 *    misrepresented as being the original software.
 * 3. This notice may not be removed or altered from any source distribution.
 */

/*
 * File:   main.c
 * Description: cage-keygen entry point
 * Author: despair
 *
 * Created on December 30, 2019, 3:39 PM
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef _MSC_VER
#include "getopt_win32.h"
#else
#include <getopt.h>
#endif

/* age HRPs and date formatting */
static const char* age_secret_hrp = "AGE-SECRET-KEY-";
static const char* age_hrp = "age";
static const char* date_fmt = "%Y-%m-%dT%H:%M:%SZ";

static void generate();

main(argc, argv)
char** argv;
{
	int option_index, c;
	char* filename;
	FILE* output;

	option_index = c = 0;
	filename = NULL;
	output = stdout;
	while (1)
	{
		static struct option long_options[] =
		{
			{"help", no_argument, 0, 'h'},
			{0,0,0,0}
		};

		c = getopt_long(argc, argv, "o:h", long_options, &option_index);
		if (c == -1 && argc > 1)
		{
bad:
			fprintf(stderr, "cage-keygen takes no arguments\n");
			return -1;
		}

		switch (c)
		{
		case 'o':
			filename = strdup(optarg);
			break;
		case 'h':
			printf("usage: %s -o filename (default: stdout)\n", argv[0]);
			return 1;
		case '?':
			goto bad;
		default:
			break;
		}
		break;
	}

	if (filename)
	{
		output = fopen(filename, "w");
		if (!output)
		{
			fprintf(stderr, "Failed to open %s for writing!\n", filename);
			free(filename);
			return -1;
		}
	}

	generate(output);

	if (filename)
	{
		free(filename);
		fclose(output);
	}
	return (EXIT_SUCCESS);
}

static void generate(out)
FILE* out;
{
#ifdef _WIN32
	__time64_t now;
#else
	time_t now;
#endif
	struct tm* tinfo;
	char tstring[128];

#ifdef _WIN32
	time64(&now);
	tinfo = gmtime64(&now);
#else
	time(&now);
	tinfo = gmtime(&now);
#endif
	strftime(tstring, 128, date_fmt, tinfo);
	fprintf(out, "# created: %s\n", tstring);
}
