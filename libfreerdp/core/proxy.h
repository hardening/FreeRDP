/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * HTTP proxy support
 *
 * Copyright 2014 Christian Plattner <ccpp@gmx.at>
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

#ifndef FREERDP_LIB_CORE_HTTP_PROXY_H
#define FREERDP_LIB_CORE_HTTP_PROXY_H

#include "freerdp/settings.h"
#include <openssl/bio.h>

WINPR_ATTR_NODISCARD
FREERDP_LOCAL BOOL proxy_prepare(rdpSettings* settings, const char** lpPeerHostname,
                                 UINT16* lpPeerPort, const char** lpProxyUsername,
                                 const char** lpProxyPassword);

/** A filter BIO that opens a tunnel to \b hostname:\b port through the proxy the connection
 *  below it goes to, an HTTP proxy (CONNECT) or a SOCKS5 proxy.
 *
 *  BIO_do_connect() runs the handshake without blocking: it returns 1 once the tunnel is open,
 *  and fails with BIO_should_retry() set while it waits on the connection below,
 *  BIO_should_read() or BIO_should_write() telling for what. Reads and writes fail the same
 *  way until then, then pass through. The strings are copied.
 *
 *  @param proxyType PROXY_TYPE_HTTP or PROXY_TYPE_SOCKS
 */
WINPR_ATTR_MALLOC(BIO_free_all, 1)
WINPR_ATTR_NODISCARD
FREERDP_LOCAL BIO* proxy_bio_new(UINT32 proxyType, const char* proxyUsername,
                                 const char* proxyPassword, const char* hostname, UINT16 port);

/** Opens the tunnel of the proxy of the settings over \b bio, a connection to the proxy: pushes
 *  a proxy BIO on it and waits for the handshake, FreeRDP_TcpConnectTimeout at most.
 *
 *  @return the new top of the chain, \b bio itself without a proxy, \b nullptr on failure,
 *  \b bio is left as it was then
 */
WINPR_ATTR_NODISCARD
FREERDP_LOCAL BIO* proxy_connect(rdpContext* context, BIO* bio, const char* proxyUsername,
                                 const char* proxyPassword, const char* hostname, UINT16 port);

#endif /* FREERDP_LIB_CORE_HTTP_PROXY_H */
