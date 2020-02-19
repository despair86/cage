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
 * Description: cage entry point
 * Author: despair
 *
 * Created on January 21, 2020, 8:27 PM
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <time.h>
#include <ctype.h>

#ifdef _MSC_VER
#include "getopt_win32.h"
#include <malloc.h>
#include <io.h>
#if _MSC_VER < 1600
#include "stdint_msvc.h"
#else
#include <stdint.h>
#endif
#else
#include <stdint.h>
#include <getopt.h>
#include <unistd.h>
#endif

#if defined(__sun)
#include <alloca.h>
#endif

#include <mbedtls/config.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <nacl.h>
#include <bech32.h>
#include <mbedtls/platform_util.h>

/* age HRPs and date formatting */
/* the private key HRP is emitted as lowercase since the bech32
 * function operates entirely on the lowercase string. We convert it
 * back to uppercase at the end.
 */
static const char* age_secret_hrp = "age-secret-key-";
static const char* age_hrp = "age";
static const char* date_fmt = "%Y-%m-%dT%H:%M:%SZ";

/* X25519 base point */
static const unsigned char basepoint[32] = {9};

/* RNG */
static mbedtls_ctr_drbg_context drbg_ctx;
static mbedtls_entropy_context rnd_ctx;

/* is the RNG ready? */
static int rand_active = 0;

/* A so-called "device specific id" to seed the internal RNG */
static const unsigned char* APP_SEED_RNG = "cage-v1-default-seed";

/* our EC key pair. MUST be scrubbed before exit */
typedef struct ec_key_pair
{
	uint8_t secret[32];
	uint8_t public[32];
} ec_key_pair;

/* internal functions */
static void generate();
static ec_key_pair *generate_identity();

void init_rand()
{
	int r;
	mbedtls_ctr_drbg_init(&drbg_ctx);
	mbedtls_entropy_init(&rnd_ctx);
	r = mbedtls_ctr_drbg_seed(&drbg_ctx, mbedtls_entropy_func, &rnd_ctx, APP_SEED_RNG, strlen((char*)APP_SEED_RNG));
	if (r)
	{
		fprintf(stderr, "failed to seed RNG!\n");
		abort();
	}
	rand_active = 1;
}

main(argc, argv)
char** argv;
{
	int option_index, c;
	char* filename;
	FILE* output;

	option_index = c = 0;
	filename = NULL;
	output = stdout;
	init_rand();
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
	mbedtls_ctr_drbg_free(&drbg_ctx);
	mbedtls_entropy_free(&rnd_ctx);
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
	char tstring[128], c, *bech32_secret, *bech32_public;
	ec_key_pair* kp;
	int r;

#ifdef _WIN32
	_time64(&now);
	tinfo = _gmtime64(&now);
#else
	time(&now);
	tinfo = gmtime(&now);
#endif
	strftime(tstring, 128, date_fmt, tinfo);
	kp = generate_identity();

	bech32_secret = alloca(strlen(age_secret_hrp) + 60);
	bech32_public = alloca(strlen(age_hrp) + 60);
	age_key_encode(bech32_secret, age_secret_hrp, kp->secret, 32);
	age_key_encode(bech32_public, age_hrp, kp->public, 32);

	r=0;
	while(bech32_secret[r])
	{
		c = bech32_secret[r];
		if (!isdigit(c))
			bech32_secret[r] = toupper(c);
		r++;
	}

	fprintf(out, "# created: %s\n", tstring);
	fprintf(out, "# public key: %s\n", bech32_public);
	fprintf(out, "%s\n", bech32_secret);
	if ((out != stdout) || !isatty(fileno(stdout)))
		fprintf(stderr, "Public key: %s\n", bech32_public);

	/* scrub everything */
	mbedtls_platform_zeroize(bech32_public, strlen(age_hrp)+60);
	mbedtls_platform_zeroize(bech32_secret, strlen(age_secret_hrp)+60);
	mbedtls_platform_zeroize(kp->secret, 32);
	mbedtls_platform_zeroize(kp->public, 32);

	free(kp);
}

static ec_key_pair *generate_identity()
{
	ec_key_pair* out;
	int r;

	r = 0;
	out = NULL;
	out = malloc(sizeof(ec_key_pair));
	if (!out)
	{
		fprintf(stderr, "out of memory!\n");
		abort();
	}
	r = mbedtls_ctr_drbg_random(&drbg_ctx, out->secret, 32);
#if 0
	out->secret[0] &= 248;
	out->secret[31] &= 127;
	out->secret[31] |= 64;
#endif
	crypto_scalarmult_curve25519(out->public, out->secret, basepoint);

	return out;
}

/* we need this for any kind of libsodium implementation */
void randombytes(uint8_t* data, uint64_t l)
{
	mbedtls_ctr_drbg_random(&drbg_ctx, data, l);
}

