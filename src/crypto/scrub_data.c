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
 * This implementation should never be optimized out by the compiler
 *
 * This implementation for mbedtls_platform_zeroize() was inspired from Colin
 * Percival's blog article at:
 *
 * http://www.daemonology.net/blog/2014-09-04-how-to-zero-a-buffer.html
 *
 * It uses a volatile function pointer to the standard memset(). Because the
 * pointer is volatile the compiler expects it to change at
 * any time and will not optimize out the call that could potentially perform
 * other operations on the input buffer instead of just setting it to 0.
 * Nevertheless, as pointed out by davidtgoldblatt on Hacker News
 * (refer to http://www.daemonology.net/blog/2014-09-05-erratum.html for
 * details), optimizations of the following form are still possible:
 *
 * if( memset_func != memset )
 *     memset_func( buf, 0, len );
 *
 * Note that it is extremely difficult to guarantee that
 * mbedtls_platform_zeroize() will not be optimized out by aggressive compilers
 * in a portable way. For this reason, Mbed TLS also provides the configuration
 * option MBEDTLS_PLATFORM_ZEROIZE_ALT, which allows users to configure
 * mbedtls_platform_zeroize() to use a suitable implementation for their
 * platform and needs.
 */

/* This implementation is lifted from the Signal Protocol code, and testing
 * with several different compilers has otherwise shown it to remain even 
 * under high optinisation levels and/or LTO
 * 
 * So far, Sun Studio, GCC, and Clang all appear to keep this code intact.
 * 
 * Unfortunately, this behaviour is still NOT sanctioned, and may break at
 * any time. It appears to work properly on the grounds that 
 * mbedtls_platform_zeroize() is declared external, see:
 * https://dwheeler.com/secure-programs/Secure-Programs-HOWTO/protect-secrets.html
 * 
 * TODO: perhaps a self-XOR is more resistant to optimisation?
 * -RVX
 */

#include <stddef.h>

#ifdef _WIN32
#include <windows.h>
#include <winbase.h>
#else
#include <sys/param.h>
#include <string.h>
#include <strings.h>
#endif

void mbedtls_platform_zeroize(void *v, size_t n)
{
#ifdef _WIN32
	SecureZeroMemory(v, n);
#elif defined(BSD) || defined(__sun) || defined(__linux__)
	explicit_bzero(v, n);
#else
	volatile unsigned char  *p  =  v;
	while(n--) *p++ = 0;
#endif
}
