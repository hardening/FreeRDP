/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 *
 * Copyright 2023 David Fort <contact@hardening-consulting.com>
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

#ifndef FREERDP_CHANNEL_RDPEAR_COMMON_H
#define FREERDP_CHANNEL_RDPEAR_COMMON_H

#include <winpr/stream.h>
#include <winpr/asn1.h>

#include <freerdp/api.h>

typedef enum
{
	RDPEAR_PACKAGE_KERBEROS,
	RDPEAR_PACKAGE_NTLM,
	RDPEAR_PACKAGE_UNKNOWN
} RdpEarPackageType;

/* RDPEAR 2.2.1.1 */
typedef enum
{
	// Start Kerberos remote calls
	RemoteCallKerbMinimum = 0x100,
	RemoteCallKerbNegotiateVersion = 0x100,
	RemoteCallKerbBuildAsReqAuthenticator,
	RemoteCallKerbVerifyServiceTicket,
	RemoteCallKerbCreateApReqAuthenticator,
	RemoteCallKerbDecryptApReply,
	RemoteCallKerbUnpackKdcReplyBody,
	RemoteCallKerbComputeTgsChecksum,
	RemoteCallKerbBuildEncryptedAuthData,
	RemoteCallKerbPackApReply,
	RemoteCallKerbHashS4UPreauth,
	RemoteCallKerbSignS4UPreauthData,
	RemoteCallKerbVerifyChecksum,
	RemoteCallKerbReserved1,
	RemoteCallKerbReserved2,
	RemoteCallKerbReserved3,
	RemoteCallKerbReserved4,
	RemoteCallKerbReserved5,
	RemoteCallKerbReserved6,
	RemoteCallKerbReserved7,
	RemoteCallKerbDecryptPacCredentials,
	RemoteCallKerbCreateECDHKeyAgreement,
	RemoteCallKerbCreateDHKeyAgreement,
	RemoteCallKerbDestroyKeyAgreement,
	RemoteCallKerbKeyAgreementGenerateNonce,
	RemoteCallKerbFinalizeKeyAgreement,
	RemoteCallKerbMaximum = 0x1ff,
	// End Kerberos remote calls

	// Start NTLM remote calls
	RemoteCallNtlmMinimum = 0x200,
	RemoteCallNtlmNegotiateVersion = 0x200,
	RemoteCallNtlmLm20GetNtlm3ChallengeResponse,
	RemoteCallNtlmCalculateNtResponse,
	RemoteCallNtlmCalculateUserSessionKeyNt,
	RemoteCallNtlmCompareCredentials,
	RemoteCallNtlmMaximum = 0x2ff,
	// End NTLM remote calls
} RemoteGuardCallId;


FREERDP_LOCAL RdpEarPackageType rdpear_packageType_from_name(WinPrAsn1_OctetString *package);
FREERDP_LOCAL wStream *rdpear_encodePayload(RdpEarPackageType packageType, wStream *payload);


typedef struct {
	size_t dummy;
} NdrContext;

typedef struct {
	UINT32 reserved1;
	UINT32 reserved2;
	wStream reserved3;
} KERB_RPC_ENCRYPTION_KEY;

typedef struct {
	UINT32 pdu;
	wStream asn1Buffer;
} KERB_ASN1_DATA;

typedef struct {
	UINT32 keyUsage;
	KERB_RPC_ENCRYPTION_KEY key;
	KERB_ASN1_DATA plainAuthData;
} BuildEncryptedAuthData;

FREERDP_LOCAL BOOL ndr_read_uint32(wStream *s, BYTE drep, UINT32 *v);
FREERDP_LOCAL BOOL ndr_write_uint32(wStream *s, BYTE drep, UINT32 v);
FREERDP_LOCAL BOOL ndr_read_uint16(wStream *s, BYTE drep, UINT16 *v);
FREERDP_LOCAL BOOL ndr_write_uint16(wStream *s, BYTE drep, UINT16 v);

FREERDP_LOCAL BOOL rdpear_read_ndr_header(wStream *s, BYTE *version, BYTE *drep);
FREERDP_LOCAL BOOL rdpear_write_ndr_header(wStream *s, BYTE version, BYTE drep);

FREERDP_LOCAL BOOL ndr_read_constructed(wStream *s, BYTE drep, wStream *target);
FREERDP_LOCAL BOOL ndr_write_constructed_header(wStream *s, BYTE drep, UINT32 payloadLen);
FREERDP_LOCAL BOOL ndr_write_constructed(wStream *s, BYTE drep, wStream *payload);

FREERDP_LOCAL BOOL ndr_read_pickle(wStream *s, BYTE drep);
FREERDP_LOCAL BOOL ndr_write_pickle(wStream *s, BYTE drep);

#endif  /* FREERDP_CHANNEL_RDPEAR_COMMON_H */
