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
 * generic http client
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <stdint.h>
#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#ifdef _MSC_VER
#include <malloc.h>
char*
strtok_r(char* __restrict s, const char* __restrict delim, char** __restrict last);
#endif
#else
#include <sys/utsname.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#endif
#include "http.h"
#ifdef __sun
#include <alloca.h>
#endif

 /* PolarSSL */
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/error.h>
#include <mbedtls/certs.h>
#include <mbedtls/base64.h>
#include <mbedtls/version.h>

/* PolarSSL internal state */
mbedtls_net_context server_fd;
mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_ssl_context ssl;
mbedtls_ssl_config conf;
mbedtls_x509_crt cacert;
unsigned char* ca_certs = NULL;

/* While strong cryptography is used throughout the library and
 * app, marking the build is done for compliance with US export
 * restrictions on strong crypto. A build marked U cannot be
 * re-exported to hostile/enemy nations. A build marked I has no
 * such restriction, but the packager must take steps to ensure
 * the code is indeed built outside the US.
 */
#ifdef _EXPORT_BUILD
static char userAgent[] = "Loki_Pager/0.1 PolarSSL/" MBEDTLS_VERSION_STRING "; I; ";
#else
static char userAgent[] = "Loki_Pager/0.1 PolarSSL/" MBEDTLS_VERSION_STRING "; U; ";
#endif

typedef struct url_parser_url
{
	char* protocol;
	char* host;
	int port;
	char* path;
	char* query_string;
} url_parser_url_t;

static const char* seed = "Loki Pager HTTPS client";

/* If this fails, do NOT use the HTTP client */

/* Must call http_client_cleanup() before attempting to recover
 * from a failed web client boot */
bool http_client_init()
{
#ifdef _WIN32
	DWORD version, major, minor, build;
	char* arch;
#endif
	int r;
	char str[512];
	char* ua;
	size_t s;
	FILE* certs;

	mbedtls_net_init(&server_fd);
	mbedtls_ssl_init(&ssl);
	mbedtls_ssl_config_init(&conf);
	/* Everything below this comment is persistent throughout the app's
	 * lifetime. */
	mbedtls_x509_crt_init(&cacert);
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);

	certs = fopen("rootcerts.pem", "rb");
	if (!certs)
	{
		fprintf(stderr, "root certs not found, aborting\n");
		return false;
	}
	ca_certs = malloc(524288);
	if (!ca_certs)
		return false;

	memset(ca_certs, 0, 524288);
	s = fread(ca_certs, 1, 524288, certs);
	ca_certs[s] = 0;
	r = mbedtls_x509_crt_parse(&cacert, ca_certs, s + 1);
	if (r < 0)
	{
		mbedtls_strerror(r, str, 512);
		printf("parse ca cert store failed\n  !  mbedtls_x509_crt_parse returned: %s\n\n", str);
		return false;
	}
	if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (unsigned char*)seed, strlen(seed)) != 0)
		return false;
	/* fill in user-agent string */
#ifdef _WIN32
	version = GetVersion();
	major = (DWORD)(LOBYTE(LOWORD(version)));
	minor = (DWORD)(HIBYTE(LOWORD(version)));
	if (version < 0x80000000)
		build = (DWORD)(HIWORD(version));
	ua = malloc(512);
	arch = getenv("PROCESSOR_ARCHITECTURE");
	snprintf(ua, 512, "%sWindows NT %lu.%lu.%lu; %s", userAgent, major, minor, build, arch);
	client_ua = ua;
#else
	ua = malloc(512);
	assert(ua);
	struct utsname sys_name;
	uname(&sys_name);
#if (__x86_64__ || __amd64__) && defined(__sun)
	snprintf(sys_name.machine, _SYS_NMLN, "x86_64");
#endif
	snprintf(ua, 512, "%s%s %s; %s", userAgent, sys_name.sysname, sys_name.release, sys_name.machine);
	client_ua = ua;
#endif
	fclose(certs);
	return true;
}

static void initTLS()
{
	/* Clear only previous connection state */
	mbedtls_net_init(&server_fd);
	mbedtls_ssl_init(&ssl);
	mbedtls_ssl_config_init(&conf);
}

static void free_parsed_url(url_parsed)
url_parser_url_t* url_parsed;
{
	if (url_parsed->protocol)
		free(url_parsed->protocol);
	if (url_parsed->host)
		free(url_parsed->host);
	if (url_parsed->path)
		free(url_parsed->path);
	if (url_parsed->query_string)
		free(url_parsed->query_string);

	free(url_parsed);
}

static void parse_url(url, parsed_url)
char* url;
url_parser_url_t* parsed_url;
{
	char* local_url;
	char* token;
	char* token_host;
	char* host_port;
	char* token_ptr;
	char* host_token_ptr;
	char* path = NULL;

	/* Copy our string */
	local_url = strdup(url);

	token = strtok_r(local_url, ":", &token_ptr);
	parsed_url->protocol = strdup(token);

	/* Host:Port */
	token = strtok_r(NULL, "/", &token_ptr);
	if (token)
		host_port = strdup(token);
	else
		host_port = (char*)calloc(1, sizeof(char));

	token_host = strtok_r(host_port, ":", &host_token_ptr);
	if (token_host)
	{
		parsed_url->host = strdup(token_host);
	}
	else
	{
		parsed_url->host = NULL;
	}

	/* Port */
	token_host = strtok_r(NULL, ":", &host_token_ptr);
	if (token_host)
		parsed_url->port = atoi(token_host);
	else
		parsed_url->port = 0;

	token_host = strtok_r(NULL, ":", &host_token_ptr);
	assert(token_host == NULL);

	token = strtok_r(NULL, "?", &token_ptr);
	parsed_url->path = NULL;
	if (token)
	{
		path = (char*)realloc(path, sizeof(char) * (strlen(token) + 2));
		memset(path, 0, sizeof(char) * (strlen(token) + 2));
		strcpy(path, "/");
		strcat(path, token);

		parsed_url->path = strdup(path);

		free(path);
	}
	else
	{
		parsed_url->path = (char*)malloc(sizeof(char) * 2);
		strcpy(parsed_url->path, "/");
	}

	token = strtok_r(NULL, "?", &token_ptr);
	if (token)
	{
		parsed_url->query_string = (char*)malloc(sizeof(char) * (strlen(token) + 1));
		strncpy(parsed_url->query_string, token, strlen(token));
	}
	else
	{
		parsed_url->query_string = NULL;
	}

	token = strtok_r(NULL, "?", &token_ptr);
	assert(token == NULL);

	free(local_url);
	free(host_port);
}

/* Insecure mode */
static bool open_http_sock(host, port)
char* host, * port;
{
	int r;

	r = mbedtls_net_connect(&server_fd, host, port, MBEDTLS_NET_PROTO_TCP);
	if (r)
	{
		printf("error - failed to connect to server: %d\n", r);
		return false;
	}
	return true;
}

static bool open_tls_sock(host, port)
char* host, * port;
{
	int r;
	unsigned int flags;

	r = mbedtls_net_connect(&server_fd, host, port, MBEDTLS_NET_PROTO_TCP);
	if (r)
	{
		printf("error - failed to connect to server: %d\n", r);
		return false;
	}

	r = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
	if (r)
	{
		printf("error - failed to set TLS options: %d\n", r);
		return false;
	}

	mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
	mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
	mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

	r = mbedtls_ssl_setup(&ssl, &conf);
	if (r)
	{
		printf("error - failed to setup TLS session: %d\n", r);
		return false;
	}

	r = mbedtls_ssl_set_hostname(&ssl, host);

	if (r)
	{
		printf("error - failed to perform SNI: %d\n", r);
		return false;
	}

	mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

	while ((r = mbedtls_ssl_handshake(&ssl)) != 0)
	{
		if (r != MBEDTLS_ERR_SSL_WANT_READ && r != MBEDTLS_ERR_SSL_WANT_WRITE)
		{
			printf(" failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n", -r);
			return false;
		}
	}
	if ((flags = mbedtls_ssl_get_verify_result(&ssl)) != 0)
	{
		char vrfy_buf[512];
		printf(" failed\n");
		mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);
		printf("%s\n", vrfy_buf);
		return false;
	}
	return true;
}

static void* response_realloc(opaque, ptr, size)
void* opaque, * ptr;
{
	return realloc(ptr, size);
}

static void response_body(opaque, data, size)
void* opaque;
const char* data;
{
	struct HttpResponse* response = (struct HttpResponse*) opaque;

	/* If we got nothing in the response array, allocate a buffer
	 * large enough to fit the first chunk of data
	 */
	if (!response->body)
	{
		response->body = malloc(size + 1);
		assert(response->body);
		memset(response->body, 0, size + 1);
	}
	/* This covers the case where we pre-allocate a large response buffer:
	 * we can just move on if we did. Otherwise, we need to enlarge the
	 * existing buffer before we start writing to it.
	 * If we just allocated a buffer above we can also skip this.
	 */
	if (((response->size + size) > response->size) && response->size)
	{
		response->body = realloc(response->body, (response->size + size + 1));
		assert(response->body);
	}
	/* If we already have pre-existing data, move up and scrub the newly allocated
	 * core memory cells.  Then we can append to the existing response text.
	 */
	if (response->body && response->size)
	{
		memset(response->body + response->size, '\0', size);
		memmove(response->body + response->size, data, size);
	}
	else
	{
		memmove(response->body, data, size);
	}
	/* we only update the current size if we were able to write it correctly.
	 * (How do we cover failure cases? Do we need to cover any set of them?)
	 */
	response->size += size;
}

static void response_header(opaque, ckey, nkey, cvalue, nvalue)
void* opaque;
const char* ckey, * cvalue;
{
	/* The internal function that collects the
	 * response headers does NOT terminate the pieces,
	 * only the whole buffer resulting in: "keyvalue\0"
	 * which is why the function also passes the size of each
	 * field
	 */
	char* key, * value;
	struct HTTPHeader* first, * current, * tmp;
	struct HttpResponse* rsp;

	rsp = (struct HttpResponse*) opaque;
	first = &rsp->headers;
	current = first;

	while (current != NULL)
	{
		tmp = current;
		current = current->next;
	}

	if (!rsp->header_size)
		current = first;
	else if (rsp->header_size == 1)
	{
		first->next = malloc(sizeof(struct HTTPHeader));
		assert(first->next);
		current = first->next;
	}
	else
	{
		tmp->next = malloc(sizeof(struct HTTPHeader));
		assert(tmp->next);
		current = tmp->next;
	}

	/* print the key */
	key = malloc(nkey + 1);
	assert(key);
	memset(key, 0, nkey + 1);
	memmove(key, ckey, nkey);
	current->key = key;

	/* print value */
	value = malloc(nvalue + 1);
	assert(value);
	memset(value, 0, nvalue + 1);
	memmove(value, cvalue, nvalue);
	current->value = value;
	rsp->header_size++;
	current->next = NULL;
}

static void response_code(opaque, code)
void* opaque;
{
	struct HttpResponse* response = (struct HttpResponse*) opaque;
	response->code = code;
}

static const struct http_funcs callbacks = {
	response_realloc,
	response_body,
	response_header,
	response_code,
};

/* A oneshot HTTP client. Probably even reentrant, in case of redirection. */
/* IN: http request object, debug bit for unit testing */
/* OUT: http response object */

/* RETURN: HTTP status code in [ER]AX (Or whatever the machine ABI designates return values in.) */
http_request(req, rsp, reserved)
struct HttpRequest* req;
struct HttpResponse* rsp;
bool reserved;
{
	int r, s, len;
	bool useTLS;
	char buf[1024], port[8], * rq;
	char* rq_type = 0, * rq_headers = 0;
	url_parser_url_t* parsed_uri;
	struct http_roundtripper rt;

	if (!req || !rsp)
		return -1;

	rq = alloca(req->size + 8192);
	memset(rq, 0, req->size + 8192);
	http_init(&rt, callbacks, rsp);
	rsp->size = 0;
	rsp->body = NULL;
	rsp->code = 0;
	rsp->header_size = 0;
	rsp->headers.key = NULL;
	rsp->headers.value = NULL;
	rsp->headers.next = NULL;

	if (!req->headers)
		req->headers = "";

	parsed_uri = malloc(sizeof(url_parser_url_t));
	assert(parsed_uri);
	memset(parsed_uri, 0, sizeof(url_parser_url_t));
	parse_url(req->uri, parsed_uri);

	initTLS();

	/* get URI protocol scheme, set port if blank */
	if (!parsed_uri->protocol)
	{
		printf("Invalid URI\n");
		return -1;
	}

	if (!strcmp("https", parsed_uri->protocol))
		useTLS = true;
	else
		useTLS = false;

	if (!parsed_uri->port && useTLS)
		parsed_uri->port = 443;
	else if (!parsed_uri->port && !useTLS)
		parsed_uri->port = 80;

	snprintf(port, 8, "%d", parsed_uri->port);

	if (useTLS)
	{
		if (!open_tls_sock(parsed_uri->host, port))
		{
			fprintf(stderr, "Failed to connect to %s\n", parsed_uri->host);
			goto exit;
		}
	}
	else
	{
		if (!open_http_sock(parsed_uri->host, port))
		{
			fprintf(stderr, "Failed to connect to %s\n", parsed_uri->host);
			goto exit;
		}
	}

	switch (req->verb)
	{
	case GET:
		rq_type = "GET";
		break;
	case POST:
		rq_type = "POST";
		break;
	default:
		break;
	}

	switch (req->c_type)
	{
	case HTTP_ENCODED:
#ifdef _MSC_VER
		snprintf(buf, 1024, "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: %d", req->size);
#else
		snprintf(buf, 1024, "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: %zu", req->size);
#endif
		rq_headers = strdup(buf);
		break;
	case HTTP_FORM_DATA:
		rq_headers = "Content-Type: multipart/form-data;boundary=\"LOKI_POST_DATA\"\r\n";
		break;
	case HTTP_JSON_DATA:
#ifdef _MSC_VER
		snprintf(buf, 1024, "Content-Type: application/json\r\nContent-Length: %d", req->size);
#else
		snprintf(buf, 1024, "Content-Type: application/json\r\nContent-Length: %zu", req->size);
#endif
		rq_headers = strdup(buf);
	default:
		rq_headers = "";
		break;
	}

	snprintf(rq, 8192, "%s %s HTTP/1.0\r\nHost: %s\r\nUser-Agent: %s\r\n%s%s\r\n\r\n", rq_type, parsed_uri->path, parsed_uri->host, client_ua, req->headers, rq_headers);
	if (reserved)
		printf("Request headers:\n--->%s<---\n", rq);

	s = strlen(rq);
	if (req->rq_data && req->size)
	{
		memcpy(rq + s, req->rq_data, req->size);
		s += req->size;
	}

	if (useTLS)
	{
		while ((r = mbedtls_ssl_write(&ssl, (unsigned char*)rq, s)) <= 0)
		{
			if (r != MBEDTLS_ERR_SSL_WANT_READ && r != MBEDTLS_ERR_SSL_WANT_WRITE)
			{
				printf("failed! error %d\n\n", r);
				goto exit;
			}
		}

		len = 0;
		s = 0;
		do
		{
			r = mbedtls_ssl_read(&ssl, (unsigned char*)buf, 1024);
			if (r <= 0)
				break;
			else
			{
				s = http_data(&rt, buf, r, &len);
			}
		} while (r && s);
		mbedtls_ssl_close_notify(&ssl);
	}
	else
	{
		while ((r = mbedtls_net_send(&server_fd, (unsigned char*)rq, s)) <= 0)
		{
			if (r != MBEDTLS_ERR_SSL_WANT_READ && r != MBEDTLS_ERR_SSL_WANT_WRITE)
			{
				printf("failed! error %d\n\n", r);
				goto exit;
			}
		}
		len = 0;
		s = 0;
		do
		{
			r = mbedtls_net_recv(&server_fd, (unsigned char*)buf, 1024);
			if (r <= 0)
				break;
			else
			{
				s = http_data(&rt, buf, r, &len);
			}
		} while (r && s);
	}
	/* Oracle libumem likes placing objects contiguously in core, so if we
	 * fail to terminate the buffer, on my machine, it lands straight into
	 * a slab where one of the pieces of the Netscape root certificate
	 * trust store was loaded into core by same.
	 */
	rsp->body[rsp->size] = 0;

exit:
	free_parsed_url(parsed_uri);
	r = rsp->code;
	http_free(&rt);
	if (req->c_type == HTTP_ENCODED || req->c_type == HTTP_JSON_DATA)
		free(rq_headers);

	/* Don't leave connections open */
	mbedtls_net_free(&server_fd);
	return r;
}

void http_client_cleanup()
{
	mbedtls_x509_crt_free(&cacert);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
	mbedtls_ssl_free(&ssl);
	mbedtls_net_free(&server_fd);
	mbedtls_ssl_config_free(&conf);
	if (ca_certs) free(ca_certs);
	if (client_ua) free(client_ua);
	ca_certs = NULL;
	client_ua = NULL;
}

void freeHeaders(head)
struct HTTPHeader* head;
{
	struct HTTPHeader* tmp;

	/* Free the head first, it is the only fixed member */
	free(head->key);
	free(head->value);

	if (head->next)
		head = head->next;

	while (head != NULL)
	{
		tmp = head;
		head = head->next;
		free(tmp->key);
		free(tmp->value);
		free(tmp);
	}

}

void printHeaders(head)
struct HTTPHeader* head;
{
	struct HTTPHeader* current;
	current = NULL;

	printf("Response headers:\n");
	for (current = head; current != NULL; current = current->next)
	{
		printf("%s: %s\n", current->key, current->value);
	}
}
