/*-
 * Copyright 2012 Matthew Endsley
 * All rights reserved
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted providing that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "http.h"

#include <ctype.h>
#include <string.h>

#include "header.h"
#include "chunk.h"

static void append_body(struct http_roundtripper* rt, const char* data, int ndata)
{
    rt->funcs.body(rt->opaque, data, ndata);
}

static void grow_scratch(struct http_roundtripper* rt, int size)
{
    int nsize;
    if (rt->nscratch >= size)
        return;

    if (size < 64)
        size = 64;
    nsize = (rt->nscratch * 3) / 2;
    if (nsize < size)
        nsize = size;

    rt->scratch = (char*) rt->funcs.realloc_scratch(rt->opaque, rt->scratch, nsize);
    rt->nscratch = nsize;
}

static int min(int a, int b)
{
    return a > b ? b : a;
}

enum http_roundtripper_state
{
    http_roundtripper_header,
    http_roundtripper_chunk_header,
    http_roundtripper_chunk_data,
    http_roundtripper_raw_data,
    http_roundtripper_unknown_data,
    http_roundtripper_close,
    http_roundtripper_error,
};

void http_init(struct http_roundtripper* rt, struct http_funcs funcs, void* opaque)
{
    rt->funcs = funcs;
    rt->scratch = 0;
    rt->opaque = opaque;
    rt->code = 0;
    rt->parsestate = 0;
    rt->contentlength = -1;
    rt->state = http_roundtripper_header;
    rt->nscratch = 0;
    rt->nkey = 0;
    rt->nvalue = 0;
    rt->chunked = 0;
}

void http_free(struct http_roundtripper* rt)
{
    if (rt->scratch)
    {
        rt->funcs.realloc_scratch(rt->opaque, rt->scratch, 0);
        rt->scratch = 0;
    }
}

int http_data(struct http_roundtripper* rt, const char* data, int size, int* read)
{
    const int initial_size = size;
    while (size)
    {
        switch (rt->state)
        {
        case http_roundtripper_header:
            switch (http_parse_header_char(&rt->parsestate, *data))
            {
            case http_header_status_done:
                rt->funcs.code(rt->opaque, rt->code);
                if (rt->parsestate != 0)
                    rt->state = http_roundtripper_error;
                else if (rt->chunked)
                {
                    rt->contentlength = 0;
                    rt->state = http_roundtripper_chunk_header;
                }
                else if (rt->contentlength == 0)
                    rt->state = http_roundtripper_close;
                else if (rt->contentlength > 0)
                    rt->state = http_roundtripper_raw_data;
                else if (rt->contentlength == -1)
                    rt->state = http_roundtripper_unknown_data;
                else
                    rt->state = http_roundtripper_error;
                break;

            case http_header_status_code_character:
                rt->code = rt->code * 10 + *data - '0';
                break;

            case http_header_status_key_character:
                grow_scratch(rt, rt->nkey + 1);
                rt->scratch[rt->nkey] = tolower(*data);
                ++rt->nkey;
                break;

            case http_header_status_value_character:
                grow_scratch(rt, rt->nkey + rt->nvalue + 1);
                rt->scratch[rt->nkey + rt->nvalue] = *data;
                ++rt->nvalue;
                break;

            case http_header_status_store_keyvalue:
                if (rt->nkey == 17 && 0 == strncmp(rt->scratch, "transfer-encoding", rt->nkey))
                    rt->chunked = (rt->nvalue == 7 && 0 == strncmp(rt->scratch + rt->nkey, "chunked", rt->nvalue));
                else if (rt->nkey == 14 && 0 == strncmp(rt->scratch, "content-length", rt->nkey))
                {
                    int ii, end;
                    rt->contentlength = 0;
                    for (ii = rt->nkey, end = rt->nkey + rt->nvalue; ii != end; ++ii)
                        rt->contentlength = rt->contentlength * 10 + rt->scratch[ii] - '0';
                }

                rt->funcs.header(rt->opaque, rt->scratch, rt->nkey, rt->scratch + rt->nkey, rt->nvalue);

                rt->nkey = 0;
                rt->nvalue = 0;
                break;
            }

            --size;
            ++data;
            break;

        case http_roundtripper_chunk_header:
            if (!http_parse_chunked(&rt->parsestate, &rt->contentlength, *data))
            {
                if (rt->contentlength == -1)
                    rt->state = http_roundtripper_error;
                else if (rt->contentlength == 0)
                    rt->state = http_roundtripper_close;
                else
                    rt->state = http_roundtripper_chunk_data;
            }

            --size;
            ++data;
            break;

        case http_roundtripper_chunk_data:
        {
            const int chunksize = min(size, rt->contentlength);
            append_body(rt, data, chunksize);
            rt->contentlength -= chunksize;
            size -= chunksize;
            data += chunksize;

            if (rt->contentlength == 0)
            {
                rt->contentlength = 1;
                rt->state = http_roundtripper_chunk_header;
            }
        }
            break;

        case http_roundtripper_raw_data:
        {
            const int chunksize = min(size, rt->contentlength);
            append_body(rt, data, chunksize);
            rt->contentlength -= chunksize;
            size -= chunksize;
            data += chunksize;

            if (rt->contentlength == 0)
                rt->state = http_roundtripper_close;
        }
            break;

        case http_roundtripper_unknown_data:
        {
            if (size == 0)
                rt->state = http_roundtripper_close;
            else
            {
                append_body(rt, data, size);
                size -= size;
                data += size;
            }
        }
            break;

        case http_roundtripper_close:
        case http_roundtripper_error:
            break;
        }

        if (rt->state == http_roundtripper_error || rt->state == http_roundtripper_close)
        {
            if (rt->scratch)
            {
                rt->funcs.realloc_scratch(rt->opaque, rt->scratch, 0);
                rt->scratch = 0;
            }
            *read = initial_size - size;
            return 0;
        }
    }

    *read = initial_size - size;
    return 1;
}

int http_iserror(struct http_roundtripper* rt)
{
    return rt->state == http_roundtripper_error;
}

#ifdef _MSC_VER
/*-
 * Copyright (c) 1998 Softweyr LLC.  All rights reserved.
 *
 * strtok_r, from Berkeley strtok
 * Oct 13, 1998 by Wes Peters <wes@softweyr.com>
 *
 * Copyright (c) 1988, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notices, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notices, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY SOFTWEYR LLC, THE REGENTS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL SOFTWEYR LLC, THE
 * REGENTS, OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#define _POSIX_SOURCE 1
#include <string.h>

/*
 * strtok_r documentation:
 * http://pubs.opengroup.org/onlinepubs/009695399/functions/strtok.html
 *
 * Implementation:
 * http://svnweb.freebsd.org/base/head/lib/libc/string/strtok.c?view=co
 *
 * strtok_r cannot completely be implemented by strtok because of the internal state.
 * It breaks when used on 2 strings where they are scanned A, B then A, B.
 * Thread-safety is not the issue.
 *
 * Sample strtok implemenatation, note the internal state:
 * char *strtok(char *s, const char *d) { static char *t; return strtok_r(s,d,t); }
 *
 */

char *
strtok_r(char * __restrict s, const char * __restrict delim, char * * __restrict last)
{
    char *spanp, *tok;
    int c, sc;

    if (s == NULL && (s = *last) == NULL)
        return (NULL);

    /*
     * Skip (span) leading delimiters (s += strspn(s, delim), sort of).
     */
cont:
    c = *s++;
    for (spanp = (char *) delim; (sc = *spanp++) != 0;)
    {
        if (c == sc)
            goto cont;
    }

    if (c == 0)
    { /* no non-delimiter characters */
        *last = NULL;
        return (NULL);
    }
    tok = s - 1;

    /*
     * Scan token (scan for delimiters: s += strcspn(s, delim), sort of).
     * Note that delim must have one NUL; we stop if we see that, too.
     */
    for (;;)
    {
        c = *s++;
        spanp = (char *) delim;
        do
        {
            if ((sc = *spanp++) == c)
            {
                if (c == 0)
                    s = NULL;
                else
                    s[-1] = '\0';
                *last = s;
                return (tok);
            }
        }
        while (sc != 0);
    }
    /* NOTREACHED */
}
#endif
