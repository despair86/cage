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
#ifdef _MSC_VER
#include "getopt_win32.h"
#else
#include <getopt.h>
#endif

main(argc, argv)
char** argv;
{
	int option_index, c;
	char* filename;

	option_index = c = 0;
	filename = NULL;
	while (1)
	{
		static struct option long_options[] =
		{
			{"help", no_argument, 0, 'h'},
			{0,0,0,0}
		};

		c = getopt_long(argc, argv, "?ho:",
						long_options, &option_index);
		if (c == -1)
			break;

		switch (c)
		{
		case 'o':
			filename = strdup(optarg);
			break;
		case 'h':
		/* fall through */
		case '?':
			printf("usage: %s -o filename (default: stdout)\n", argv[0]);
			return 1;
		default:
			break;
		}
	}

	if (filename)
		free(filename);
	return (EXIT_SUCCESS);
}
