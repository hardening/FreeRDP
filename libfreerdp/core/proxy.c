/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * HTTP Proxy support
 *
 * Copyright 2016 Christian Plattner <ccpp@gmx.at>
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

#include <ctype.h>
#include <errno.h>
#include <limits.h>

#include <openssl/err.h>

#include "settings.h"
#include "proxy.h"
#include <freerdp/settings.h>
#include <freerdp/utils/proxy_utils.h>
#include "tcp.h"

#include <winpr/assert.h>
#include <winpr/sysinfo.h>
#include <winpr/environment.h> /* For GetEnvironmentVariableA */

#include <freerdp/log.h>
#define TAG FREERDP_TAG("core.proxy")

static void proxy_read_environment(rdpSettings* settings, char* envname);

BOOL proxy_prepare(rdpSettings* settings, const char** lpPeerHostname, UINT16* lpPeerPort,
                   const char** lpProxyUsername, const char** lpProxyPassword)
{
	if (freerdp_settings_get_uint32(settings, FreeRDP_ProxyType) == PROXY_TYPE_IGNORE)
		return FALSE;

	/* For TSGateway, find the system HTTPS proxy automatically */
	if (freerdp_settings_get_uint32(settings, FreeRDP_ProxyType) == PROXY_TYPE_NONE)
		proxy_read_environment(settings, "https_proxy");

	if (freerdp_settings_get_uint32(settings, FreeRDP_ProxyType) == PROXY_TYPE_NONE)
		proxy_read_environment(settings, "HTTPS_PROXY");

	if (freerdp_settings_get_uint32(settings, FreeRDP_ProxyType) != PROXY_TYPE_NONE)
		proxy_read_environment(settings, "no_proxy");

	if (freerdp_settings_get_uint32(settings, FreeRDP_ProxyType) != PROXY_TYPE_NONE)
		proxy_read_environment(settings, "NO_PROXY");

	if (freerdp_settings_get_uint32(settings, FreeRDP_ProxyType) != PROXY_TYPE_NONE)
	{
		*lpPeerHostname = freerdp_settings_get_string(settings, FreeRDP_ProxyHostname);
		if (!*lpPeerHostname || !winpr_str_is_valid_hostname(*lpPeerHostname))
			return FALSE;
		*lpPeerPort = freerdp_settings_get_uint16(settings, FreeRDP_ProxyPort);
		*lpProxyUsername = freerdp_settings_get_string(settings, FreeRDP_ProxyUsername);
		*lpProxyPassword = freerdp_settings_get_string(settings, FreeRDP_ProxyPassword);
		return TRUE;
	}

	return FALSE;
}

WINPR_ATTR_NODISCARD
static BOOL value_to_int(const char* value, LONGLONG* result, LONGLONG min, LONGLONG max)
{
	long long rc = 0;

	if (!value || !result)
		return FALSE;

	errno = 0;
	rc = _strtoi64(value, nullptr, 0);

	if (errno != 0)
		return FALSE;

	if ((rc < min) || (rc > max))
		return FALSE;

	*result = rc;
	return TRUE;
}

WINPR_ATTR_NODISCARD
static BOOL cidr4_match(const struct in_addr* addr, const struct in_addr* net, BYTE bits)
{
	if (bits == 0)
		return TRUE;

	const uint32_t mask = htonl(0xFFFFFFFFu << (32 - bits));
	const uint32_t amask = addr->s_addr & mask;
	const uint32_t nmask = net->s_addr & mask;
	return amask == nmask;
}

WINPR_ATTR_NODISCARD
static BOOL cidr6_match(const struct in6_addr* address, const struct in6_addr* network,
                        uint8_t bits)
{
	const uint32_t* a = (const uint32_t*)address;
	const uint32_t* n = (const uint32_t*)network;
	const size_t bits_whole = bits >> 5;
	const size_t bits_incomplete = bits & 0x1F;

	if (bits_whole)
	{
		if (memcmp(a, n, bits_whole << 2) != 0)
			return FALSE;
	}

	if (bits_incomplete)
	{
		uint32_t mask = htonl((0xFFFFFFFFu) << (32 - bits_incomplete));

		if ((a[bits_whole] ^ n[bits_whole]) & mask)
			return FALSE;
	}

	return TRUE;
}

WINPR_ATTR_NODISCARD
static BOOL option_ends_with(const char* str, const char* ext)
{
	WINPR_ASSERT(str);
	WINPR_ASSERT(ext);
	const size_t strLen = strlen(str);
	const size_t extLen = strlen(ext);

	if (strLen < extLen)
		return FALSE;

	return _strnicmp(&str[strLen - extLen], ext, extLen) == 0;
}

/* no_proxy has no proper definition, so use curl as reference:
 * https://about.gitlab.com/blog/2021/01/27/we-need-to-talk-no-proxy/
 */
WINPR_ATTR_NODISCARD
static BOOL no_proxy_match_host(const char* val, const char* hostname)
{
	WINPR_ASSERT(val);
	WINPR_ASSERT(hostname);

	/* match all */
	if (_stricmp("*", val) == 0)
		return TRUE;

	/* Strip leading . */
	if (val[0] == '.')
		val++;

	/* Match suffix */
	return option_ends_with(hostname, val);
}

WINPR_ATTR_NODISCARD
static BOOL starts_with(const char* val, const char* prefix)
{
	const size_t plen = strlen(prefix);
	const size_t vlen = strlen(val);
	if (vlen < plen)
		return FALSE;
	return _strnicmp(val, prefix, plen) == 0;
}

WINPR_ATTR_NODISCARD
static BOOL no_proxy_match_ip(const char* val, const char* hostname)
{
	WINPR_ASSERT(val);
	WINPR_ASSERT(hostname);

	struct sockaddr_in sa4 = WINPR_C_ARRAY_INIT;
	struct sockaddr_in6 sa6 = WINPR_C_ARRAY_INIT;

	if (inet_pton(AF_INET, hostname, &sa4.sin_addr) == 1)
	{
		/* Prefix match */
		if (starts_with(hostname, val))
			return TRUE;

		char* sub = strchr(val, '/');
		if (sub)
			*sub++ = '\0';

		struct sockaddr_in mask = WINPR_C_ARRAY_INIT;
		if (inet_pton(AF_INET, val, &mask.sin_addr) == 0)
			return FALSE;

		/* IP address match */
		if (memcmp(&mask, &sa4, sizeof(mask)) == 0)
			return TRUE;

		if (sub)
		{
			const unsigned long usub = strtoul(sub, nullptr, 0);
			if ((errno == 0) && (usub <= UINT8_MAX))
				return cidr4_match(&sa4.sin_addr, &mask.sin_addr, (UINT8)usub);
		}
	}
	else if (inet_pton(AF_INET6, hostname, &sa6.sin6_addr) == 1)
	{
		if (val[0] == '[')
			val++;

		char str[INET6_ADDRSTRLEN + 1] = WINPR_C_ARRAY_INIT;
		strncpy(str, val, INET6_ADDRSTRLEN);

		const size_t len = strnlen(str, INET6_ADDRSTRLEN);
		if (len > 0)
		{
			if (str[len - 1] == ']')
				str[len - 1] = '\0';
		}

		/* Prefix match */
		if (starts_with(hostname, str))
			return TRUE;

		char* sub = strchr(str, '/');
		if (sub)
			*sub++ = '\0';

		struct sockaddr_in6 mask = WINPR_C_ARRAY_INIT;
		if (inet_pton(AF_INET6, str, &mask.sin6_addr) == 0)
			return FALSE;

		/* Address match */
		if (memcmp(&mask, &sa6, sizeof(mask)) == 0)
			return TRUE;

		if (sub)
		{
			const unsigned long usub = strtoul(sub, nullptr, 0);
			if ((errno == 0) && (usub <= UINT8_MAX))
				return cidr6_match(&sa6.sin6_addr, &mask.sin6_addr, (UINT8)usub);
		}
	}

	return FALSE;
}

WINPR_ATTR_NODISCARD
static BOOL is_ipv6_addr(const char* hostname, size_t len)
{
	struct sockaddr_in6 sa6 = WINPR_C_ARRAY_INIT;
	if (strnlen(hostname, len) > INET6_ADDRSTRLEN)
		return FALSE;
	return inet_pton(AF_INET6, hostname, &sa6.sin6_addr) == 1;
}

WINPR_ATTR_NODISCARD
static BOOL check_no_proxy(rdpSettings* settings, const char* no_proxy)
{
	const char* delimiter = ", ";
	BOOL result = FALSE;
	char* context = nullptr;

	if (!no_proxy || !settings)
		return FALSE;

	char* copy = _strdup(no_proxy);

	if (!copy)
		return FALSE;

	char* current = strtok_s(copy, delimiter, &context);

	while (current && !result)
	{
		const size_t currentlen = strlen(current);

		if (currentlen > 0)
		{
			const char* ServerHostname =
			    freerdp_settings_get_string(settings, FreeRDP_ServerHostname);
			WLog_DBG(TAG, "%s => %s (%" PRIuz ")", ServerHostname, current, currentlen);

			if (no_proxy_match_host(current, ServerHostname))
				result = TRUE;
			else if (no_proxy_match_ip(current, ServerHostname))
				result = TRUE;
		}

		current = strtok_s(nullptr, delimiter, &context);
	}

	free(copy);
	return result;
}

void proxy_read_environment(rdpSettings* settings, char* envname)
{
	const DWORD envlen = GetEnvironmentVariableA(envname, nullptr, 0);

	if (!envlen || (envlen <= 1))
		return;

	char* env = calloc(1, envlen);

	if (!env)
	{
		WLog_ERR(TAG, "Not enough memory");
		return;
	}

	if (GetEnvironmentVariableA(envname, env, envlen) == envlen - 1)
	{
		if (_strnicmp("NO_PROXY", envname, 9) == 0)
		{
			if (check_no_proxy(settings, env))
			{
				WLog_INFO(TAG, "deactivating proxy: %s [%s=%s]",
				          freerdp_settings_get_string(settings, FreeRDP_ServerHostname), envname,
				          env);
				if (!freerdp_settings_set_uint32(settings, FreeRDP_ProxyType, PROXY_TYPE_NONE))
					WLog_WARN(TAG, "failed to set FreeRDP_ProxyType=PROXY_TYPE_NONE");
			}
		}
		else
		{
			if (!proxy_parse_uri(settings, env))
			{
				WLog_WARN(
				    TAG, "Error while parsing proxy URI from environment variable; ignoring proxy");
			}
		}
	}

	free(env);
}

BOOL proxy_parse_uri(rdpSettings* settings, const char* uri_in)
{
	BOOL rc = FALSE;
	const char* protocol = "";
	UINT16 port = 0;

	if (!settings || !uri_in)
		return FALSE;

	char* uri_copy = _strdup(uri_in);
	char* uri = uri_copy;
	if (!uri)
		goto fail;

	{
		char* p = strstr(uri, "://");
		if (p)
		{
			*p = '\0';

			if (_stricmp("no_proxy", uri) == 0)
			{
				if (!freerdp_settings_set_uint32(settings, FreeRDP_ProxyType, PROXY_TYPE_IGNORE))
					goto fail;
			}
			if (_stricmp("http", uri) == 0)
			{
				if (!freerdp_settings_set_uint32(settings, FreeRDP_ProxyType, PROXY_TYPE_HTTP))
					goto fail;
				protocol = "http";
			}
			else if (_stricmp("socks5", uri) == 0)
			{
				if (!freerdp_settings_set_uint32(settings, FreeRDP_ProxyType, PROXY_TYPE_SOCKS))
					goto fail;
				protocol = "socks5";
			}
			else
			{
				WLog_ERR(TAG, "Only HTTP and SOCKS5 proxies supported by now");
				goto fail;
			}

			uri = p + 3;
		}
		else
		{
			/* default proxy protocol is http */
			if (!freerdp_settings_set_uint32(settings, FreeRDP_ProxyType, PROXY_TYPE_HTTP))
				goto fail;
			protocol = "http";
		}
	}

	/* uri is now [user:password@]hostname:port */
	{
		char* atPtr = strrchr(uri, '@');

		if (atPtr)
		{
			/* got a login / password,
			 *				 atPtr
			 *				 v
			 * [user:password@]hostname:port
			 *		^
			 *		colonPtr
			 */
			char* colonPtr = strchr(uri, ':');

			if (!colonPtr || (colonPtr > atPtr))
			{
				WLog_ERR(TAG, "invalid syntax for proxy (contains no password)");
				goto fail;
			}

			*colonPtr = '\0';
			if (!freerdp_settings_set_string(settings, FreeRDP_ProxyUsername, uri))
			{
				WLog_ERR(TAG, "unable to allocate proxy username");
				goto fail;
			}

			*atPtr = '\0';

			if (!freerdp_settings_set_string(settings, FreeRDP_ProxyPassword, colonPtr + 1))
			{
				WLog_ERR(TAG, "unable to allocate proxy password");
				goto fail;
			}

			uri = atPtr + 1;
		}
	}

	{
		char* p = strchr(uri, ':');

		if (p)
		{
			LONGLONG val = 0;

			if (!value_to_int(&p[1], &val, 0, UINT16_MAX))
			{
				WLog_ERR(TAG, "invalid syntax for proxy (invalid port)");
				goto fail;
			}

			if (val == 0)
			{
				WLog_ERR(TAG, "invalid syntax for proxy (port missing)");
				goto fail;
			}

			port = (UINT16)val;
			*p = '\0';
		}
		else
		{
			if (_stricmp("http", protocol) == 0)
			{
				/* The default is 80. Also for Proxies. */
				port = 80;
			}
			else
			{
				port = 1080;
			}

			WLog_DBG(TAG, "setting default proxy port: %" PRIu16, port);
		}

		if (!freerdp_settings_set_uint16(settings, FreeRDP_ProxyPort, port))
			goto fail;
	}
	{
		char* p = strchr(uri, '/');
		if (p)
			*p = '\0';
		if (!freerdp_settings_set_string(settings, FreeRDP_ProxyHostname, uri))
			goto fail;
	}

	if (_stricmp("", uri) == 0)
	{
		WLog_ERR(TAG, "invalid syntax for proxy (hostname missing)");
		goto fail;
	}

	if (freerdp_settings_get_string(settings, FreeRDP_ProxyUsername))
	{
		WLog_INFO(TAG, "Parsed proxy configuration: %s://%s:%s@%s:%" PRIu16, protocol,
		          freerdp_settings_get_string(settings, FreeRDP_ProxyUsername), "******",
		          freerdp_settings_get_string(settings, FreeRDP_ProxyHostname),
		          freerdp_settings_get_uint16(settings, FreeRDP_ProxyPort));
	}
	else
	{
		WLog_INFO(TAG, "Parsed proxy configuration: %s://%s:%" PRIu16, protocol,
		          freerdp_settings_get_string(settings, FreeRDP_ProxyHostname),
		          freerdp_settings_get_uint16(settings, FreeRDP_ProxyPort));
	}
	rc = TRUE;

fail:
	if (!rc)
		WLog_WARN(TAG, "Failed to parse proxy configuration: %s://%s:%" PRIu16, protocol, uri,
		          port);
	free(uri_copy);
	return rc;
}

BIO* proxy_connect(rdpContext* context, BIO* bio, const char* proxyUsername,
                   const char* proxyPassword, const char* hostname, UINT16 port)
{
	WINPR_ASSERT(context);
	WINPR_ASSERT(bio);
	WINPR_ASSERT(hostname);
	rdpSettings* settings = context->settings;

	const UINT32 proxyType = freerdp_settings_get_uint32(settings, FreeRDP_ProxyType);
	if ((proxyType == PROXY_TYPE_NONE) || (proxyType == PROXY_TYPE_IGNORE))
		return bio;

	// Check for IPv6 (max 45) or DNS (max 255) name. Bounded length to 256 so too long hostnames do
	// not silently pass
	const size_t hostnlen = strnlen(hostname, 255 + 1);
	if (!is_ipv6_addr(hostname, hostnlen) && !winpr_str_is_valid_hostnameN(hostname, hostnlen))
		return nullptr;

	BIO* proxy = proxy_bio_new(proxyType, proxyUsername, proxyPassword, hostname, port);
	if (!proxy)
		return nullptr;
	BIO* top = BIO_push(proxy, bio);

	const UINT32 timeout = freerdp_settings_get_uint32(settings, FreeRDP_TcpConnectTimeout);
	const UINT64 start = GetTickCount64();
	while (!freerdp_shall_disconnect_context(context))
	{
		ERR_clear_error();
		if (BIO_do_connect(top) == 1)
			return top;
		if (!BIO_should_retry(top))
			break;

		const UINT64 elapsed = GetTickCount64() - start;
		if (elapsed > timeout)
		{
			WLog_ERR(TAG, "timed out waiting for the proxy");
			break;
		}

		const long waitMs = (long)MIN(100, timeout - elapsed + 1);
		const long rc =
		    BIO_should_read(top) ? BIO_wait_read(bio, waitMs) : BIO_wait_write(bio, waitMs);
		if (rc < 0)
			Sleep(1); /* the BIO cannot wait, poll */
	}

	WLog_ERR(TAG, "Failed to connect to %s:%" PRIu16 " through the proxy", hostname, port);
	(void)BIO_pop(proxy);
	BIO_free(proxy);
	return nullptr;
}
