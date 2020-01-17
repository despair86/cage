/*
 * Copyright (C) 2019 Rick V. All rights reserved.
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
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

void mbedtls_platform_zeroize(void *v, size_t n)
{
    volatile unsigned char  *p  =  v;
    while(n--) *p++ = 0;
}
