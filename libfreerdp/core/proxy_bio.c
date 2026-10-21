/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * HTTP and SOCKS5 proxy BIO
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <freerdp/config.h>

#include <winpr/assert.h>
#include <winpr/cast.h>
#include <winpr/crt.h>
#include <winpr/stream.h>
#include <winpr/string.h>
#include <winpr/winsock.h>

#include <freerdp/log.h>
#include <freerdp/settings_types.h>
#include <freerdp/crypto/crypto.h>

#include <openssl/bio.h>
#include <openssl/err.h>

#include "tcp.h"
#include "proxy.h"

#define TAG FREERDP_TAG("core.proxy")

#define CRLF "\r\n"

/* The longest reply: the HTTP status line and headers, a SOCKS5 reply is 262 bytes at most */
#define PROXY_REPLY_MAX 4096

/* SOCKS Proxy auth methods by rfc1928 */
enum
{
	AUTH_M_NO_AUTH = 0,
	AUTH_M_GSSAPI = 1,
	AUTH_M_USR_PASS = 2,
	AUTH_M_NONE_ACCEPTABLE = 0xFF
};

enum
{
	SOCKS_CMD_CONNECT = 1,
	SOCKS_CMD_BIND = 2,
	SOCKS_CMD_UDP_ASSOCIATE = 3
};

enum
{
	SOCKS_ADDR_IPV4 = 1,
	SOCKS_ADDR_FQDN = 3,
	SOCKS_ADDR_IPV6 = 4,
};

/* CONN REQ replies in enum. order */
static const char* rplstat[] = { "succeeded",
	                             "general SOCKS server failure",
	                             "connection not allowed by ruleset",
	                             "Network unreachable",
	                             "Host unreachable",
	                             "Connection refused",
	                             "TTL expired",
	                             "Command not supported",
	                             "Address type not supported" };

/* What the handshake waits for */
typedef enum
{
	PROXY_STEP_HTTP_CONNECT,
	PROXY_STEP_SOCKS_METHOD,
	PROXY_STEP_SOCKS_AUTH,
	PROXY_STEP_SOCKS_REQUEST,
	PROXY_STEP_OPEN,
	PROXY_STEP_FAILED
} proxy_step;

typedef struct
{
	UINT32 type;
	char* username;
	char* password;
	char* hostname;
	UINT16 port;

	proxy_step step;
	/* the request being sent, sent from its position on */
	wStream* out;
	/* the reply being read. Once open, what came after it is read first. */
	BYTE in[PROXY_REPLY_MAX];
	size_t inLength;
	size_t inOffset;
} proxy_bio;

WINPR_ATTR_NODISCARD
static BOOL proxy_has_credentials(const proxy_bio* ptr)
{
	WINPR_ASSERT(ptr);
	return ptr->username && ptr->password && (ptr->username[0] != '\0') &&
	       (ptr->password[0] != '\0');
}

static BOOL proxy_fail(proxy_bio* ptr, const char* what)
{
	WINPR_ASSERT(ptr);
	WLog_ERR(TAG, "%s proxy: %s", (ptr->type == PROXY_TYPE_HTTP) ? "HTTP" : "SOCKS", what);
	ptr->step = PROXY_STEP_FAILED;
	return FALSE;
}

/* Starts sending the request of the next step, the stream holds it from its start to its
 * position. */
static void proxy_send(proxy_bio* ptr, proxy_step step)
{
	WINPR_ASSERT(ptr);
	Stream_SealLength(ptr->out);
	Stream_ResetPosition(ptr->out);
	ptr->step = step;
}

WINPR_ATTR_NODISCARD
static BOOL proxy_write_string(wStream* s, const char* str, size_t length)
{
	if (!Stream_EnsureRemainingCapacity(s, length))
		return FALSE;
	Stream_Write(s, str, length);
	return TRUE;
}

/* host:port, an IPv6 address in brackets */
WINPR_ATTR_NODISCARD
static BOOL http_write_authority(wStream* s, const char* hostname, UINT16 port)
{
	const BOOL ipv6 = strchr(hostname, ':') != nullptr;
	char portStr[8] = WINPR_C_ARRAY_INIT;
	(void)_snprintf(portStr, sizeof(portStr), "%" PRIu16, port);

	return (!ipv6 || proxy_write_string(s, "[", 1)) &&
	       proxy_write_string(s, hostname, strlen(hostname)) &&
	       (!ipv6 || proxy_write_string(s, "]", 1)) && proxy_write_string(s, ":", 1) &&
	       proxy_write_string(s, portStr, strlen(portStr));
}

WINPR_ATTR_NODISCARD
static BOOL http_write_credentials(wStream* s, const char* username, const char* password)
{
	char* creds = nullptr;
	size_t size = 0;
	(void)winpr_asprintf(&creds, &size, "%s:%s", username, password);
	if (!creds || (size < 1))
	{
		free(creds);
		return FALSE;
	}

	size_t b64len = 0;
	char* base64 = crypto_base64_encode_len(creds, size, &b64len);
	memset(creds, 0, size);
	free(creds);
	if (!base64)
		return FALSE;

	static const char basic[] = "Proxy-Authorization: Basic ";
	const BOOL rc = proxy_write_string(s, basic, strlen(basic)) &&
	                proxy_write_string(s, base64, strlen(base64)) && proxy_write_string(s, CRLF, 2);
	memset(base64, 0, b64len);
	free(base64);
	return rc;
}

WINPR_ATTR_NODISCARD
static BOOL http_send_connect(proxy_bio* ptr)
{
	WINPR_ASSERT(ptr);
	wStream* s = ptr->out;
	Stream_ResetPosition(s);

	static const char connect[] = "CONNECT ";
	static const char version[] = " HTTP/1.1" CRLF;
	static const char host[] = "Host: ";
	if (!proxy_write_string(s, connect, strlen(connect)) ||
	    !http_write_authority(s, ptr->hostname, ptr->port) ||
	    !proxy_write_string(s, version, strlen(version)) ||
	    !proxy_write_string(s, host, strlen(host)) ||
	    !http_write_authority(s, ptr->hostname, ptr->port) || !proxy_write_string(s, CRLF, 2))
		return FALSE;

	if (proxy_has_credentials(ptr) && !http_write_credentials(s, ptr->username, ptr->password))
		return FALSE;

	if (!proxy_write_string(s, CRLF, 2))
		return FALSE;

	proxy_send(ptr, PROXY_STEP_HTTP_CONNECT);
	return TRUE;
}

WINPR_ATTR_NODISCARD
static BOOL socks_send_method(proxy_bio* ptr)
{
	WINPR_ASSERT(ptr);
	wStream* s = ptr->out;
	Stream_ResetPosition(s);

	const BOOL userpass = (ptr->username || ptr->password);
	if (!Stream_EnsureRemainingCapacity(s, 4))
		return FALSE;
	Stream_Write_UINT8(s, 5);                /* SOCKS version */
	Stream_Write_UINT8(s, userpass ? 2 : 1); /* #of methods offered */
	Stream_Write_UINT8(s, AUTH_M_NO_AUTH);
	if (userpass)
		Stream_Write_UINT8(s, AUTH_M_USR_PASS);

	proxy_send(ptr, PROXY_STEP_SOCKS_METHOD);
	return TRUE;
}

WINPR_ATTR_NODISCARD
static BOOL socks_send_auth(proxy_bio* ptr)
{
	WINPR_ASSERT(ptr);

	if (!ptr->username || !ptr->password)
		return proxy_fail(ptr, "the username and the password are both needed");

	const size_t usernameLen = strnlen(ptr->username, 256);
	const size_t passwordLen = strnlen(ptr->password, 256);
	if ((usernameLen > 255) || (passwordLen > 255))
		return proxy_fail(ptr, "the username or the password is longer than 255 bytes");

	/* user/password v1 method */
	wStream* s = ptr->out;
	Stream_ResetPosition(s);
	if (!Stream_EnsureRemainingCapacity(s, 3 + usernameLen + passwordLen))
		return FALSE;
	Stream_Write_UINT8(s, 1);
	Stream_Write_UINT8(s, WINPR_ASSERTING_INT_CAST(UINT8, usernameLen));
	Stream_Write(s, ptr->username, usernameLen);
	Stream_Write_UINT8(s, WINPR_ASSERTING_INT_CAST(UINT8, passwordLen));
	Stream_Write(s, ptr->password, passwordLen);

	proxy_send(ptr, PROXY_STEP_SOCKS_AUTH);
	return TRUE;
}

WINPR_ATTR_NODISCARD
static BOOL socks_send_request(proxy_bio* ptr)
{
	WINPR_ASSERT(ptr);
	wStream* s = ptr->out;
	Stream_ResetPosition(s);

	const size_t hostnameLen = strnlen(ptr->hostname, 256);
	if (!Stream_EnsureRemainingCapacity(s, 4 + 1 + 255 + 2))
		return FALSE;
	Stream_Write_UINT8(s, 5);                 /* SOCKS version */
	Stream_Write_UINT8(s, SOCKS_CMD_CONNECT); /* command */
	Stream_Write_UINT8(s, 0);                 /* 3rd octet is reserved x00 */

	BYTE address[16] = WINPR_C_ARRAY_INIT;
	if (inet_pton(AF_INET6, ptr->hostname, address) == 1)
	{
		Stream_Write_UINT8(s, SOCKS_ADDR_IPV6);
		Stream_Write(s, address, 16);
	}
	else if (inet_pton(AF_INET, ptr->hostname, address) == 1)
	{
		Stream_Write_UINT8(s, SOCKS_ADDR_IPV4);
		Stream_Write(s, address, 4);
	}
	else
	{
		if (hostnameLen > 255)
			return proxy_fail(ptr, "the hostname is longer than 255 bytes");
		Stream_Write_UINT8(s, SOCKS_ADDR_FQDN);
		Stream_Write_UINT8(s, WINPR_ASSERTING_INT_CAST(UINT8, hostnameLen));
		Stream_Write(s, ptr->hostname, hostnameLen);
	}
	Stream_Write_UINT16_BE(s, ptr->port); /* DST.PORT */

	proxy_send(ptr, PROXY_STEP_SOCKS_REQUEST);
	return TRUE;
}

/* @return the length of the reply once \b in holds it all, 0 while it does not */
WINPR_ATTR_NODISCARD
static size_t proxy_reply_length(const proxy_bio* ptr)
{
	WINPR_ASSERT(ptr);
	const BYTE* in = ptr->in;
	const size_t length = ptr->inLength;

	switch (ptr->step)
	{
		case PROXY_STEP_HTTP_CONNECT:
			for (size_t x = 0; x + 4 <= length; x++)
			{
				if (memcmp(&in[x], CRLF CRLF, 4) == 0)
					return x + 4;
			}
			return 0;

		case PROXY_STEP_SOCKS_METHOD:
		case PROXY_STEP_SOCKS_AUTH:
			return (length >= 2) ? 2 : 0;

		case PROXY_STEP_SOCKS_REQUEST:
		{
			/* VER, REP, RSV, ATYP, BND.ADDR, BND.PORT */
			if (length < 5)
				return 0;
			size_t addressLength = 0;
			switch (in[3])
			{
				case SOCKS_ADDR_IPV4:
					addressLength = 4;
					break;
				case SOCKS_ADDR_IPV6:
					addressLength = 16;
					break;
				case SOCKS_ADDR_FQDN:
					addressLength = 1ull + in[4];
					break;
				default:
					/* the reply of a failure can come without an address */
					return (in[1] != 0) ? length : 0;
			}
			const size_t needed = 4 + addressLength + 2;
			return (length >= needed) ? needed : 0;
		}

		default:
			return 0;
	}
}

WINPR_ATTR_NODISCARD
static BOOL http_handle_reply(proxy_bio* ptr, size_t length)
{
	WINPR_ASSERT(ptr);

	/* the status line */
	char line[256] = WINPR_C_ARRAY_INIT;
	size_t lineLength = 0;
	while ((lineLength < length) && (lineLength < sizeof(line) - 1) &&
	       (ptr->in[lineLength] != '\r') && (ptr->in[lineLength] != '\n'))
	{
		line[lineLength] = (char)ptr->in[lineLength];
		lineLength++;
	}
	WLog_INFO(TAG, "HTTP Proxy: %s", line);

	/* HTTP/1.0 or HTTP/1.1, then the status code */
	if ((lineLength < 12) || (strncmp(line, "HTTP/1.", 7) != 0) ||
	    (strncmp(&line[8], " 200", 4) != 0))
		return proxy_fail(ptr, "the CONNECT request was refused");

	ptr->step = PROXY_STEP_OPEN;
	return TRUE;
}

WINPR_ATTR_NODISCARD
static BOOL socks_handle_reply(proxy_bio* ptr, size_t length)
{
	WINPR_ASSERT(ptr);
	const BYTE* in = ptr->in;
	WINPR_ASSERT(length >= 2);

	switch (ptr->step)
	{
		case PROXY_STEP_SOCKS_METHOD:
			if (in[0] != 5)
				return proxy_fail(ptr, "the proxy is not a SOCKS5 proxy");
			switch (in[1])
			{
				case AUTH_M_NO_AUTH:
					WLog_DBG(TAG, "SOCKS Proxy: (NO AUTH) method was selected");
					return socks_send_request(ptr);
				case AUTH_M_USR_PASS:
					if (!ptr->username && !ptr->password)
						return proxy_fail(ptr, "USER/PASS method was not proposed to server");
					return socks_send_auth(ptr);
				default:
					WLog_ERR(TAG, "SOCKS Proxy: unknown method 0x%02" PRIx8 " was selected", in[1]);
					return proxy_fail(ptr, "no acceptable authentication method");
			}

		case PROXY_STEP_SOCKS_AUTH:
			if (in[0] != 1)
				return proxy_fail(ptr, "invalid user/password reply");
			if (in[1] != 0)
				return proxy_fail(ptr, "invalid user/password");
			return socks_send_request(ptr);

		case PROXY_STEP_SOCKS_REQUEST:
			if (in[0] != 5)
				return proxy_fail(ptr, "the proxy is not a SOCKS5 proxy");
			if (in[1] != 0)
			{
				if (in[1] < ARRAYSIZE(rplstat))
					WLog_INFO(TAG, "SOCKS Proxy replied: %s", rplstat[in[1]]);
				else
					WLog_INFO(TAG, "SOCKS Proxy replied: %" PRIu8 " status not listed in rfc1928",
					          in[1]);
				return proxy_fail(ptr, "the CONNECT request was refused");
			}
			WLog_INFO(TAG, "Successfully connected to %s:%" PRIu16, ptr->hostname, ptr->port);
			ptr->step = PROXY_STEP_OPEN;
			return TRUE;

		default:
			return FALSE;
	}
}

/* A complete reply: on to the next step. The reply is consumed, the bytes after it are kept. */
WINPR_ATTR_NODISCARD
static BOOL proxy_handle_reply(proxy_bio* ptr, size_t length)
{
	WINPR_ASSERT(ptr);
	WINPR_ASSERT(length <= ptr->inLength);

	const BOOL rc = (ptr->type == PROXY_TYPE_HTTP) ? http_handle_reply(ptr, length)
	                                               : socks_handle_reply(ptr, length);
	if (!rc)
	{
		if (ptr->step != PROXY_STEP_FAILED)
			return proxy_fail(ptr, "failed to build the request");
		return FALSE;
	}

	if (ptr->step == PROXY_STEP_OPEN)
		ptr->inOffset = length;
	else
	{
		/* nothing comes before the request is sent, keep it anyway */
		memmove(ptr->in, &ptr->in[length], ptr->inLength - length);
		ptr->inLength -= length;
	}
	return TRUE;
}

/* Runs the handshake as far as it goes without blocking.
 * @return 1 once open, -1 with the retry flags of \b bio set while it waits, -1 without them on
 * failure */
static int proxy_run(BIO* bio)
{
	proxy_bio* ptr = BIO_get_data(bio);
	WINPR_ASSERT(ptr);
	BIO* next = BIO_next(bio);

	BIO_clear_retry_flags(bio);
	while (TRUE)
	{
		if (ptr->step == PROXY_STEP_OPEN)
			return 1;
		if (ptr->step == PROXY_STEP_FAILED)
			return -1;
		if (!next)
			return -1;

		/* the request */
		if (Stream_GetRemainingLength(ptr->out) > 0)
		{
			const size_t remaining = Stream_GetRemainingLength(ptr->out);
			ERR_clear_error();
			const int rc = BIO_write(next, Stream_ConstPointer(ptr->out),
			                         WINPR_ASSERTING_INT_CAST(int, MIN(remaining, INT32_MAX)));
			if (rc > 0)
			{
				Stream_Seek(ptr->out, WINPR_ASSERTING_INT_CAST(size_t, rc));
				continue;
			}
			if (!BIO_should_retry(next))
			{
				(void)proxy_fail(ptr, "failed to send the request");
				return -1;
			}
			BIO_set_retry_write(bio);
			return -1;
		}

		/* a buffered BIO below takes all of it, and sends it when it can */
		if (BIO_flush(next) < 0)
		{
			(void)proxy_fail(ptr, "failed to send the request");
			return -1;
		}
		if (BIO_write_blocked(next) > 0)
		{
			BIO_set_retry_write(bio);
			return -1;
		}

		/* the reply */
		const size_t length = proxy_reply_length(ptr);
		if (length > 0)
		{
			if (!proxy_handle_reply(ptr, length))
				return -1;
			continue;
		}

		if (ptr->inLength >= sizeof(ptr->in))
		{
			(void)proxy_fail(ptr, "the reply is too long");
			return -1;
		}

		ERR_clear_error();
		const int rc = BIO_read(next, &ptr->in[ptr->inLength],
		                        WINPR_ASSERTING_INT_CAST(int, sizeof(ptr->in) - ptr->inLength));
		if (rc > 0)
		{
			ptr->inLength += WINPR_ASSERTING_INT_CAST(size_t, rc);
			continue;
		}
		if (BIO_should_retry(next))
		{
			BIO_set_retry_read(bio);
			return -1;
		}
		(void)proxy_fail(ptr, (rc == 0) ? "the proxy closed the connection"
		                                : "failed to read the reply");
		return -1;
	}
}

static int proxy_bio_write(BIO* bio, const char* buf, int size)
{
	proxy_bio* ptr = BIO_get_data(bio);
	WINPR_ASSERT(ptr);

	if (ptr->step != PROXY_STEP_OPEN)
		return proxy_run(bio) == 1 ? proxy_bio_write(bio, buf, size) : -1;

	BIO* next = BIO_next(bio);
	BIO_clear_retry_flags(bio);
	const int rc = BIO_write(next, buf, size);
	BIO_copy_next_retry(bio);
	return rc;
}

static int proxy_bio_read(BIO* bio, char* buf, int size)
{
	proxy_bio* ptr = BIO_get_data(bio);
	WINPR_ASSERT(ptr);

	if (ptr->step != PROXY_STEP_OPEN)
		return proxy_run(bio) == 1 ? proxy_bio_read(bio, buf, size) : -1;

	BIO_clear_retry_flags(bio);
	if (!buf || (size <= 0))
		return 0;

	/* what the proxy sent along with its reply */
	if (ptr->inOffset < ptr->inLength)
	{
		const size_t length =
		    MIN(ptr->inLength - ptr->inOffset, WINPR_ASSERTING_INT_CAST(size_t, size));
		memcpy(buf, &ptr->in[ptr->inOffset], length);
		ptr->inOffset += length;
		return WINPR_ASSERTING_INT_CAST(int, length);
	}

	BIO* next = BIO_next(bio);
	const int rc = BIO_read(next, buf, size);
	BIO_copy_next_retry(bio);
	return rc;
}

static int proxy_bio_puts(WINPR_ATTR_UNUSED BIO* bio, WINPR_ATTR_UNUSED const char* str)
{
	return -2;
}

static int proxy_bio_gets(WINPR_ATTR_UNUSED BIO* bio, WINPR_ATTR_UNUSED char* str,
                          WINPR_ATTR_UNUSED int size)
{
	return -2;
}

static long proxy_bio_ctrl(BIO* bio, int cmd, long arg1, void* arg2)
{
	proxy_bio* ptr = BIO_get_data(bio);
	WINPR_ASSERT(ptr);
	BIO* next = BIO_next(bio);

	switch (cmd)
	{
		case BIO_C_DO_STATE_MACHINE: /* BIO_do_connect() */
			return proxy_run(bio);

		case BIO_CTRL_PENDING:
		{
			const size_t pending =
			    (ptr->step == PROXY_STEP_OPEN) ? ptr->inLength - ptr->inOffset : 0;
			const long below = next ? BIO_ctrl(next, cmd, arg1, arg2) : 0;
			return WINPR_ASSERTING_INT_CAST(long, pending) + MAX(below, 0);
		}

		case BIO_CTRL_DUP:
			return 0;

		default:
			return next ? BIO_ctrl(next, cmd, arg1, arg2) : 0;
	}
}

static int proxy_bio_new_cb(BIO* bio)
{
	proxy_bio* ptr = calloc(1, sizeof(proxy_bio));
	if (!ptr)
		return 0;
	ptr->out = Stream_New(nullptr, 512);
	if (!ptr->out)
	{
		free(ptr);
		return 0;
	}
	ptr->step = PROXY_STEP_FAILED;
	BIO_set_data(bio, ptr);
	return 1;
}

static void proxy_free_secret(char* secret)
{
	if (secret)
		memset(secret, 0, strlen(secret));
	free(secret);
}

static int proxy_bio_free_cb(BIO* bio)
{
	if (!bio)
		return 0;

	proxy_bio* ptr = BIO_get_data(bio);
	if (ptr)
	{
		proxy_free_secret(ptr->username);
		proxy_free_secret(ptr->password);
		free(ptr->hostname);
		if (ptr->out)
		{
			memset(Stream_Buffer(ptr->out), 0, Stream_Capacity(ptr->out));
			Stream_Free(ptr->out, TRUE);
		}
		free(ptr);
	}
	BIO_set_data(bio, nullptr);
	BIO_set_init(bio, 0);
	return 1;
}

static BIO_METHOD* BIO_f_proxy(void)
{
	static BIO_METHOD* bio_methods = nullptr;

	if (bio_methods == nullptr)
	{
		if (!(bio_methods = BIO_meth_new(BIO_TYPE_PROXY, "Proxy")))
			return nullptr;

		BIO_meth_set_write(bio_methods, proxy_bio_write);
		BIO_meth_set_read(bio_methods, proxy_bio_read);
		BIO_meth_set_puts(bio_methods, proxy_bio_puts);
		BIO_meth_set_gets(bio_methods, proxy_bio_gets);
		BIO_meth_set_ctrl(bio_methods, proxy_bio_ctrl);
		BIO_meth_set_create(bio_methods, proxy_bio_new_cb);
		BIO_meth_set_destroy(bio_methods, proxy_bio_free_cb);
	}

	return bio_methods;
}

WINPR_ATTR_NODISCARD
static BOOL proxy_strdup(char** dst, const char* src)
{
	WINPR_ASSERT(dst);
	if (!src)
		return TRUE;
	*dst = _strdup(src);
	return *dst != nullptr;
}

BIO* proxy_bio_new(UINT32 proxyType, const char* proxyUsername, const char* proxyPassword,
                   const char* hostname, UINT16 port)
{
	WINPR_ASSERT(hostname);

	if ((proxyType != PROXY_TYPE_HTTP) && (proxyType != PROXY_TYPE_SOCKS))
	{
		WLog_ERR(TAG, "Invalid internal proxy configuration");
		return nullptr;
	}

	BIO_METHOD* methods = BIO_f_proxy();
	BIO* bio = methods ? BIO_new(methods) : nullptr;
	if (!bio)
		return nullptr;

	proxy_bio* ptr = BIO_get_data(bio);
	WINPR_ASSERT(ptr);
	ptr->type = proxyType;
	ptr->port = port;
	if (!proxy_strdup(&ptr->username, proxyUsername) ||
	    !proxy_strdup(&ptr->password, proxyPassword) || !proxy_strdup(&ptr->hostname, hostname))
		goto fail;

	if (!((proxyType == PROXY_TYPE_HTTP) ? http_send_connect(ptr) : socks_send_method(ptr)))
		goto fail;

	BIO_set_init(bio, 1);
	return bio;

fail:
	BIO_free(bio);
	return nullptr;
}
