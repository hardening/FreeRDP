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
#include <winpr/wlog.h>
#include <winpr/sspi.h>

#include <freerdp/api.h>

#include "ndr.h"

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

FREERDP_LOCAL RdpEarPackageType rdpear_packageType_from_name(WinPrAsn1_OctetString* package);
FREERDP_LOCAL wStream* rdpear_encodePayload(RdpEarPackageType packageType, wStream* payload);

typedef struct
{
	UINT32 length;
	BYTE* value;
} KERB_RPC_OCTET_STRING;

FREERDP_LOCAL BOOL ndr_read_KERB_RPC_OCTET_STRING(NdrContext* context, wStream* s, const void* hints, void* res);
FREERDP_LOCAL void KERB_RPC_OCTET_STRING_dump(wLog* logger, UINT32 lvl, KERB_RPC_OCTET_STRING* obj);

typedef struct
{
	UINT32 Pdu;
	NdrArrayHints Asn1BufferHints;
	BYTE* Asn1Buffer;
} KERB_ASN1_DATA;

FREERDP_LOCAL BOOL ndr_read_KERB_ASN1_DATA(NdrContext* context, wStream* s, void *hints, KERB_ASN1_DATA* res);
FREERDP_LOCAL BOOL ndr_write_KERB_ASN1_DATA(NdrContext* context, wStream* s, const void *hints,
                                            const KERB_ASN1_DATA* res);
FREERDP_LOCAL void KERB_ASN1_DATA_dump(wLog* logger, UINT32 lvl, KERB_ASN1_DATA* obj);
FREERDP_LOCAL void KERB_ASN1_DATA_destroy(NdrContext* context, KERB_ASN1_DATA* obj);
FREERDP_LOCAL NdrMessageType KERB_ASN1_DATA_descr();

typedef struct
{
	/*UINT16 Length;
	UINT16 MaximumLength;*/
	NdrVaryingArrayHints lenHints;
	UINT32 strLength;
	WCHAR* Buffer;
} RPC_UNICODE_STRING;

FREERDP_LOCAL BOOL ndr_read_RPC_UNICODE_STRING(NdrContext* context, wStream* s, void *hints,
                                               RPC_UNICODE_STRING* res);
FREERDP_LOCAL BOOL ndr_write_RPC_UNICODE_STRING(NdrContext* context, wStream* s, const void *hints,
                                                const RPC_UNICODE_STRING* res);
FREERDP_LOCAL void RPC_UNICODE_STRING_dump(wLog* logger, UINT32 lvl, RPC_UNICODE_STRING* obj);
FREERDP_LOCAL void RPC_UNICODE_STRING_destroy(NdrContext* context, RPC_UNICODE_STRING* obj);
FREERDP_LOCAL NdrMessageType RPC_UNICODE_STRING_descr();

typedef struct
{
	UINT16 NameType;
	NdrArrayHints nameHints;
	RPC_UNICODE_STRING* Names;
} KERB_RPC_INTERNAL_NAME;

FREERDP_LOCAL BOOL ndr_read_KERB_RPC_INTERNAL_NAME(NdrContext* context, wStream* s, void *hints,
                                                   KERB_RPC_INTERNAL_NAME* res);
FREERDP_LOCAL BOOL ndr_write_KERB_RPC_INTERNAL_NAME(NdrContext* context, wStream* s,
                                                    const KERB_RPC_INTERNAL_NAME* res);
FREERDP_LOCAL void KERB_RPC_INTERNAL_NAME_dump(wLog* logger, UINT32 lvl,
                                               KERB_RPC_INTERNAL_NAME* obj);
FREERDP_LOCAL void KERB_RPC_INTERNAL_NAME_destroy(NdrContext* context, KERB_RPC_INTERNAL_NAME* obj);

typedef struct
{
	UINT32 reserved1;
	UINT32 reserved2;
	KERB_RPC_OCTET_STRING reserved3;
} KERB_RPC_ENCRYPTION_KEY;

typedef struct
{
	UINT32 KeyUsage;
	KERB_RPC_ENCRYPTION_KEY* Key;
	KERB_ASN1_DATA* PlainAuthData;
} BuildEncryptedAuthDataReq;

FREERDP_LOCAL BOOL ndr_read_BuildEncryptedAuthDataReq(NdrContext* context, wStream* s,
                                                      BuildEncryptedAuthDataReq* req);
FREERDP_LOCAL void BuildEncryptedAuthDataReq_dump(wLog* logger, UINT32 lvl,
                                                  BuildEncryptedAuthDataReq* obj);

typedef struct
{
	KERB_ASN1_DATA* requestBody;
	KERB_RPC_ENCRYPTION_KEY* Key;
	UINT32 ChecksumType;
} ComputeTgsChecksumReq;

FREERDP_LOCAL BOOL ndr_read_ComputeTgsChecksumReq(NdrContext* context, wStream* s,
                                                  ComputeTgsChecksumReq* req);
FREERDP_LOCAL void ComputeTgsChecksumReq_dump(wLog* logger, UINT32 lvl, ComputeTgsChecksumReq* obj);

typedef struct
{
	KERB_RPC_ENCRYPTION_KEY* EncryptionKey;
	ULONG SequenceNumber;
	KERB_RPC_INTERNAL_NAME* ClientName;
	RPC_UNICODE_STRING* ClientRealm;
	PLARGE_INTEGER SkewTime;
	KERB_RPC_ENCRYPTION_KEY* SubKey; // optional
	KERB_ASN1_DATA* AuthData;        // optional
	KERB_ASN1_DATA* GssChecksum;     // optional
	ULONG KeyUsage;
} CreateApReqAuthenticatorReq;

FREERDP_LOCAL BOOL ndr_read_CreateApReqAuthenticatorReq(NdrContext* context, wStream* s,
                                                        CreateApReqAuthenticatorReq* req);
FREERDP_LOCAL void CreateApReqAuthenticatorReq_dump(wLog* logger, UINT32 lvl,
                                                    CreateApReqAuthenticatorReq* obj);
FREERDP_LOCAL void CreateApReqAuthenticatorReq_destroy(NdrContext* context, CreateApReqAuthenticatorReq* obj);

/** @brief */
typedef struct
{
	LARGE_INTEGER AuthenticatorTime;
	KERB_ASN1_DATA Authenticator;
	LONG KerbProtocolError;
} CreateApReqAuthenticatorResp;

FREERDP_LOCAL BOOL CreateApReqAuthenticatorResp_read(NdrContext* context, wStream* s,
                                                        CreateApReqAuthenticatorResp* obj);
FREERDP_LOCAL BOOL CreateApReqAuthenticatorResp_write(NdrContext* context, wStream* s, const CreateApReqAuthenticatorResp* obj);
FREERDP_LOCAL void CreateApReqAuthenticatorResp_dump(wLog* logger, UINT32 lvl,
                                                    CreateApReqAuthenticatorResp* obj);
FREERDP_LOCAL void CreateApReqAuthenticatorResp_destroy(NdrContext* context, CreateApReqAuthenticatorResp* obj);



typedef struct
{
	KERB_ASN1_DATA* EncryptedData;
	KERB_RPC_ENCRYPTION_KEY* Key;
	KERB_RPC_ENCRYPTION_KEY* StrengthenKey;
	ULONG Pdu;
	ULONG KeyUsage;
} UnpackKdcReplyBodyReq;

FREERDP_LOCAL BOOL ndr_read_UnpackKdcReplyBodyReq(NdrContext* context, wStream* s, UnpackKdcReplyBodyReq* req);



typedef struct
{
	LONG KerbProtocolError;
	KERB_ASN1_DATA ReplyBody;
} UnpackKdcReplyBodyResp;

FREERDP_LOCAL BOOL UnpackKdcReplyBodyResp_write(NdrContext* context, wStream* s, const UnpackKdcReplyBodyResp* resp);



FREERDP_LOCAL wStream* rdpear_enc_Checksum(UINT32 cksumtype, SecPkgContext_Asn1Data* payload);
FREERDP_LOCAL wStream* rdpear_enc_EncryptedData(UINT32 encType, SecPkgContext_Asn1Data* payload);

#endif /* FREERDP_CHANNEL_RDPEAR_COMMON_H */
