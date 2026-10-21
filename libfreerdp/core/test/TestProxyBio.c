/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Proxy BIO unit test
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

/* The proxy BIO over one end of a BIO pair, the test plays the proxy on the other end: the
 * handshake runs without blocking, one step per call. */

#include <stdio.h>
#include <string.h>

#include <winpr/wtypes.h>
#include <winpr/crt.h>
#include <winpr/sysinfo.h>
#include <winpr/winsock.h>

#include <freerdp/client.h>
#include <freerdp/settings.h>

#include <openssl/bio.h>

#include "../tcp.h"
#include "../proxy.h"

typedef struct
{
	const char* name;
	BOOL (*fn)(void);
} TestCase;

typedef struct
{
	BIO* client; /* the proxy BIO on its end of the pair */
	BIO* proxy;  /* the other end */
} PairCtx;

static void pair_free(PairCtx* ctx)
{
	BIO_free_all(ctx->client);
	BIO_free(ctx->proxy);
}

static BOOL pair_start(PairCtx* ctx, UINT32 type, const char* username, const char* password,
                       const char* hostname, UINT16 port)
{
	BIO* end = nullptr;
	if (BIO_new_bio_pair(&end, 0, &ctx->proxy, 0) != 1)
		return FALSE;
	BIO* bio = proxy_bio_new(type, username, password, hostname, port);
	if (!bio)
	{
		BIO_free(end);
		return FALSE;
	}
	ctx->client = BIO_push(bio, end);
	return TRUE;
}

/* The handshake is waiting for the proxy */
static BOOL connect_waits(PairCtx* ctx)
{
	return (BIO_do_connect(ctx->client) <= 0) && BIO_should_retry(ctx->client) &&
	       BIO_should_read(ctx->client);
}

static BOOL connect_fails(PairCtx* ctx)
{
	return (BIO_do_connect(ctx->client) <= 0) && !BIO_should_retry(ctx->client);
}

/* What the client sent is exactly \b expected */
static BOOL proxy_expect(PairCtx* ctx, const void* expected, size_t length)
{
	BYTE buffer[1024] = { 0 };
	const int rc = BIO_read(ctx->proxy, buffer, sizeof(buffer));
	if ((rc < 0) || ((size_t)rc != length) || (memcmp(buffer, expected, length) != 0))
	{
		(void)printf("  sent %d bytes: %.*s\n", rc, (rc > 0) ? rc : 0, (const char*)buffer);
		return FALSE;
	}
	return TRUE;
}

static BOOL proxy_send(PairCtx* ctx, const void* data, size_t length)
{
	return BIO_write(ctx->proxy, data, (int)length) == (int)length;
}

/* Once open, the data passes through both ways */
static BOOL passes_through(PairCtx* ctx)
{
	BYTE buffer[16] = { 0 };
	return (BIO_write(ctx->client, "ping", 4) == 4) && proxy_expect(ctx, "ping", 4) &&
	       proxy_send(ctx, "pong", 4) && (BIO_read(ctx->client, buffer, sizeof(buffer)) == 4) &&
	       (memcmp(buffer, "pong", 4) == 0);
}

static const char httpRequest[] = "CONNECT rdp.example.com:3389 HTTP/1.1\r\n"
                                  "Host: rdp.example.com:3389\r\n"
                                  "\r\n";

static BOOL http_connect_opens_the_tunnel(void)
{
	PairCtx ctx = { 0 };
	static const char reply[] = "HTTP/1.1 200 Connection established\r\nVia: test\r\n\r\n";
	const BOOL rc = pair_start(&ctx, PROXY_TYPE_HTTP, nullptr, nullptr, "rdp.example.com", 3389) &&
	                connect_waits(&ctx) && proxy_expect(&ctx, httpRequest, strlen(httpRequest)) &&
	                connect_waits(&ctx) && proxy_send(&ctx, reply, strlen(reply)) &&
	                (BIO_do_connect(ctx.client) == 1) && passes_through(&ctx);
	pair_free(&ctx);
	return rc;
}

static BOOL http_reply_can_come_in_pieces(void)
{
	PairCtx ctx = { 0 };
	static const char reply[] = "HTTP/1.0 200 OK\r\n\r\n";
	BOOL rc = pair_start(&ctx, PROXY_TYPE_HTTP, nullptr, nullptr, "rdp.example.com", 3389) &&
	          connect_waits(&ctx) && proxy_expect(&ctx, httpRequest, strlen(httpRequest));
	for (size_t x = 0; rc && (x + 1 < strlen(reply)); x++)
		rc = proxy_send(&ctx, &reply[x], 1) && connect_waits(&ctx);
	rc = rc && proxy_send(&ctx, &reply[strlen(reply) - 1], 1) && (BIO_do_connect(ctx.client) == 1);
	pair_free(&ctx);
	return rc;
}

static BOOL http_data_after_the_reply_is_kept(void)
{
	PairCtx ctx = { 0 };
	static const char reply[] = "HTTP/1.1 200 OK\r\n\r\nearly";
	BYTE buffer[16] = { 0 };
	const BOOL rc = pair_start(&ctx, PROXY_TYPE_HTTP, nullptr, nullptr, "rdp.example.com", 3389) &&
	                connect_waits(&ctx) && proxy_expect(&ctx, httpRequest, strlen(httpRequest)) &&
	                proxy_send(&ctx, reply, strlen(reply)) && (BIO_do_connect(ctx.client) == 1) &&
	                (BIO_pending(ctx.client) == 5) &&
	                (BIO_read(ctx.client, buffer, sizeof(buffer)) == 5) &&
	                (memcmp(buffer, "early", 5) == 0) && passes_through(&ctx);
	pair_free(&ctx);
	return rc;
}

static BOOL http_sends_the_credentials(void)
{
	PairCtx ctx = { 0 };
	/* base64 of user:secret */
	static const char request[] = "CONNECT [2001:db8::1]:443 HTTP/1.1\r\n"
	                              "Host: [2001:db8::1]:443\r\n"
	                              "Proxy-Authorization: Basic dXNlcjpzZWNyZXQ=\r\n"
	                              "\r\n";
	const BOOL rc = pair_start(&ctx, PROXY_TYPE_HTTP, "user", "secret", "2001:db8::1", 443) &&
	                connect_waits(&ctx) && proxy_expect(&ctx, request, strlen(request));
	pair_free(&ctx);
	return rc;
}

static BOOL http_refusal_fails(void)
{
	PairCtx ctx = { 0 };
	static const char reply[] = "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n";
	BYTE buffer[16] = { 0 };
	const BOOL rc = pair_start(&ctx, PROXY_TYPE_HTTP, nullptr, nullptr, "rdp.example.com", 3389) &&
	                connect_waits(&ctx) && proxy_expect(&ctx, httpRequest, strlen(httpRequest)) &&
	                proxy_send(&ctx, reply, strlen(reply)) && connect_fails(&ctx) &&
	                (BIO_read(ctx.client, buffer, sizeof(buffer)) < 0) &&
	                !BIO_should_retry(ctx.client);
	pair_free(&ctx);
	return rc;
}

static BOOL a_closed_connection_fails(void)
{
	PairCtx ctx = { 0 };
	const BOOL rc = pair_start(&ctx, PROXY_TYPE_HTTP, nullptr, nullptr, "rdp.example.com", 3389) &&
	                connect_waits(&ctx) && proxy_expect(&ctx, httpRequest, strlen(httpRequest)) &&
	                (BIO_shutdown_wr(ctx.proxy) == 1) && connect_fails(&ctx);
	pair_free(&ctx);
	return rc;
}

static BOOL socks_connect_opens_the_tunnel(void)
{
	PairCtx ctx = { 0 };
	static const BYTE request[] = { 5,   1,   0,   3,   15,  'r', 'd', 'p', '.', 'e',  'x',
		                            'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 0x0D, 0x3D };
	static const BYTE reply[] = { 5, 0, 0, 1, 198, 51, 100, 1, 0x1F, 0x90 };
	const BOOL rc = pair_start(&ctx, PROXY_TYPE_SOCKS, nullptr, nullptr, "rdp.example.com", 3389) &&
	                connect_waits(&ctx) && proxy_expect(&ctx, "\x05\x01\x00", 3) &&
	                proxy_send(&ctx, "\x05\x00", 2) && connect_waits(&ctx) &&
	                proxy_expect(&ctx, request, sizeof(request)) && connect_waits(&ctx) &&
	                proxy_send(&ctx, reply, sizeof(reply)) && (BIO_do_connect(ctx.client) == 1) &&
	                passes_through(&ctx);
	pair_free(&ctx);
	return rc;
}

static BOOL socks_authenticates(void)
{
	PairCtx ctx = { 0 };
	static const BYTE auth[] = { 1, 4, 'u', 's', 'e', 'r', 2, 'p', 'w' };
	static const BYTE request[] = { 5, 1, 0, 1, 192, 0, 2, 7, 0x0D, 0x3D };
	static const BYTE reply[] = {
		5, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1
	};
	const BOOL rc = pair_start(&ctx, PROXY_TYPE_SOCKS, "user", "pw", "192.0.2.7", 3389) &&
	                connect_waits(&ctx) && proxy_expect(&ctx, "\x05\x02\x00\x02", 4) &&
	                proxy_send(&ctx, "\x05\x02", 2) && connect_waits(&ctx) &&
	                proxy_expect(&ctx, auth, sizeof(auth)) && proxy_send(&ctx, "\x01\x00", 2) &&
	                connect_waits(&ctx) && proxy_expect(&ctx, request, sizeof(request)) &&
	                proxy_send(&ctx, reply, sizeof(reply)) && (BIO_do_connect(ctx.client) == 1);
	pair_free(&ctx);
	return rc;
}

static BOOL socks_reply_can_come_in_pieces(void)
{
	PairCtx ctx = { 0 };
	static const BYTE request[] = { 5, 1, 0, 1, 192, 0, 2, 7, 0x0D, 0x3D };
	static const BYTE reply[] = { 5, 0, 0, 3, 3, 'a', 'b', 'c', 0x1F, 0x90 };
	BOOL rc = pair_start(&ctx, PROXY_TYPE_SOCKS, nullptr, nullptr, "192.0.2.7", 3389) &&
	          connect_waits(&ctx) && proxy_expect(&ctx, "\x05\x01\x00", 3) &&
	          proxy_send(&ctx, "\x05\x00", 2) && connect_waits(&ctx) &&
	          proxy_expect(&ctx, request, sizeof(request));
	for (size_t x = 0; rc && (x + 1 < sizeof(reply)); x++)
		rc = proxy_send(&ctx, &reply[x], 1) && connect_waits(&ctx);
	rc = rc && proxy_send(&ctx, &reply[sizeof(reply) - 1], 1) &&
	     (BIO_do_connect(ctx.client) == 1) && passes_through(&ctx);
	pair_free(&ctx);
	return rc;
}

static BOOL socks_refusals_fail(void)
{
	PairCtx ctx = { 0 };
	static const BYTE reply[] = { 5, 5, 0, 1, 0, 0, 0, 0, 0, 0 }; /* connection refused */
	BOOL rc = pair_start(&ctx, PROXY_TYPE_SOCKS, nullptr, nullptr, "192.0.2.7", 3389) &&
	          connect_waits(&ctx) && proxy_send(&ctx, "\x05\x00", 2) && connect_waits(&ctx) &&
	          proxy_send(&ctx, reply, sizeof(reply)) && connect_fails(&ctx);
	pair_free(&ctx);

	/* no acceptable method */
	PairCtx ctx2 = { 0 };
	rc = rc && pair_start(&ctx2, PROXY_TYPE_SOCKS, nullptr, nullptr, "192.0.2.7", 3389) &&
	     connect_waits(&ctx2) && proxy_send(&ctx2, "\x05\xFF", 2) && connect_fails(&ctx2);
	pair_free(&ctx2);

	/* the proxy wants credentials the client does not have */
	PairCtx ctx3 = { 0 };
	rc = rc && pair_start(&ctx3, PROXY_TYPE_SOCKS, nullptr, nullptr, "192.0.2.7", 3389) &&
	     connect_waits(&ctx3) && proxy_send(&ctx3, "\x05\x02", 2) && connect_fails(&ctx3);
	pair_free(&ctx3);

	/* wrong credentials */
	PairCtx ctx4 = { 0 };
	rc = rc && pair_start(&ctx4, PROXY_TYPE_SOCKS, "user", "pw", "192.0.2.7", 3389) &&
	     connect_waits(&ctx4) && proxy_send(&ctx4, "\x05\x02", 2) && connect_waits(&ctx4) &&
	     proxy_send(&ctx4, "\x01\x01", 2) && connect_fails(&ctx4);
	pair_free(&ctx4);
	return rc;
}

static BOOL reads_and_writes_wait_for_the_tunnel(void)
{
	PairCtx ctx = { 0 };
	static const char reply[] = "HTTP/1.1 200 OK\r\n\r\n";
	BYTE buffer[16] = { 0 };
	const BOOL rc = pair_start(&ctx, PROXY_TYPE_HTTP, nullptr, nullptr, "rdp.example.com", 3389) &&
	                (BIO_write(ctx.client, "ping", 4) < 0) && BIO_should_retry(ctx.client) &&
	                proxy_expect(&ctx, httpRequest, strlen(httpRequest)) &&
	                (BIO_read(ctx.client, buffer, sizeof(buffer)) < 0) &&
	                BIO_should_retry(ctx.client) && proxy_send(&ctx, reply, strlen(reply)) &&
	                passes_through(&ctx);
	pair_free(&ctx);
	return rc;
}

/* proxy_connect() over a loopback TCP connection, the proxy's reply waits in the socket */
static BOOL proxy_connect_returns_the_new_top(void)
{
	RDP_CLIENT_ENTRY_POINTS entry = { 0 };
	entry.Version = RDP_CLIENT_INTERFACE_VERSION;
	entry.Size = sizeof(RDP_CLIENT_ENTRY_POINTS_V1);
	entry.ContextSize = sizeof(rdpClientContext);
	rdpContext* context = freerdp_client_context_new(&entry);
	BOOL rc = FALSE;
	SOCKET listener = INVALID_SOCKET;
	SOCKET client = INVALID_SOCKET;
	SOCKET server = INVALID_SOCKET;
	BIO* bio = nullptr;
	if (!context)
		goto out;

	listener = _socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	struct sockaddr_in addr = { 0 };
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	socklen_t addrLength = sizeof(addr);
	if ((listener == INVALID_SOCKET) ||
	    (_bind(listener, (const struct sockaddr*)&addr, sizeof(addr)) != 0) ||
	    (_getsockname(listener, (struct sockaddr*)&addr, &addrLength) != 0) ||
	    (_listen(listener, 1) != 0))
		goto out;
	client = _socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if ((client == INVALID_SOCKET) ||
	    (_connect(client, (const struct sockaddr*)&addr, sizeof(addr)) != 0))
		goto out;
	struct sockaddr_in peer = { 0 };
	int peerLength = sizeof(peer);
	server = _accept(listener, (struct sockaddr*)&peer, &peerLength);
	static const char reply[] = "HTTP/1.1 200 OK\r\n\r\n";
	if ((server == INVALID_SOCKET) ||
	    (_send(server, reply, (int)strlen(reply), 0) != (int)strlen(reply)))
		goto out;

	bio = BIO_new(BIO_s_simple_socket());
	if (!bio)
		goto out;
	BIO_set_fd(bio, (int)client, BIO_CLOSE);
	client = INVALID_SOCKET;

	/* without a proxy, nothing changes */
	if (!freerdp_settings_set_uint32(context->settings, FreeRDP_ProxyType, PROXY_TYPE_NONE) ||
	    (proxy_connect(context, bio, nullptr, nullptr, "rdp.example.com", 3389) != bio))
		goto out;

	if (!freerdp_settings_set_uint32(context->settings, FreeRDP_ProxyType, PROXY_TYPE_HTTP))
		goto out;
	BIO* top = proxy_connect(context, bio, nullptr, nullptr, "rdp.example.com", 3389);
	if (!top || (top == bio) || (BIO_next(top) != bio))
		goto out;
	bio = top;

	char request[256] = { 0 };
	const int length = _recv(server, request, sizeof(request) - 1, 0);
	rc = (length == (int)strlen(httpRequest)) && (strcmp(request, httpRequest) == 0);
out:
	BIO_free_all(bio);
	if (server != INVALID_SOCKET)
		closesocket(server);
	if (client != INVALID_SOCKET)
		closesocket(client);
	if (listener != INVALID_SOCKET)
		closesocket(listener);
	freerdp_client_context_free(context);
	return rc;
}

static const TestCase cases[] = {
	{ "http_connect_opens_the_tunnel", http_connect_opens_the_tunnel },
	{ "http_reply_can_come_in_pieces", http_reply_can_come_in_pieces },
	{ "http_data_after_the_reply_is_kept", http_data_after_the_reply_is_kept },
	{ "http_sends_the_credentials", http_sends_the_credentials },
	{ "http_refusal_fails", http_refusal_fails },
	{ "a_closed_connection_fails", a_closed_connection_fails },
	{ "socks_connect_opens_the_tunnel", socks_connect_opens_the_tunnel },
	{ "socks_authenticates", socks_authenticates },
	{ "socks_reply_can_come_in_pieces", socks_reply_can_come_in_pieces },
	{ "socks_refusals_fail", socks_refusals_fail },
	{ "reads_and_writes_wait_for_the_tunnel", reads_and_writes_wait_for_the_tunnel },
	{ "proxy_connect_returns_the_new_top", proxy_connect_returns_the_new_top },
};

int TestProxyBio(int argc, char* argv[])
{
	WINPR_UNUSED(argc);
	WINPR_UNUSED(argv);

	WSADATA wsaData = { 0 };
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
		return -1;

	int rc = 0;
	for (size_t x = 0; x < ARRAYSIZE(cases); x++)
	{
		const BOOL ok = cases[x].fn();
		(void)printf("%s %s\n", ok ? "ok    " : "FAILED", cases[x].name);
		if (!ok)
			rc = -1;
	}

	WSACleanup();
	return rc;
}
