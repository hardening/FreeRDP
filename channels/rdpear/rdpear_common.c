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

#include "rdpear_common.h"
#include "ndr.h"

#include <stddef.h>
#include <winpr/print.h>
#include <freerdp/channels/log.h>

#define TAG CHANNELS_TAG("rdpear")

const char kerberosPackageName[] = {
	'K', 0, 'e', 0, 'r', 0, 'b', 0, 'e', 0, 'r', 0, 'o', 0, 's', 0
};
const char ntlmPackageName[] = { 'N', 0, 'T', 0, 'L', 0, 'M', 0 };

RdpEarPackageType rdpear_packageType_from_name(WinPrAsn1_OctetString* package)
{
	if (package->len == sizeof(kerberosPackageName) &&
	    memcmp(package->data, kerberosPackageName, package->len))
		return RDPEAR_PACKAGE_KERBEROS;

	if (package->len == sizeof(ntlmPackageName) &&
	    memcmp(package->data, ntlmPackageName, package->len))
		return RDPEAR_PACKAGE_NTLM;

	return RDPEAR_PACKAGE_UNKNOWN;
}

wStream* rdpear_encodePayload(RdpEarPackageType packageType, wStream* payload)
{
	wStream* ret = NULL;
	WinPrAsn1Encoder* enc = WinPrAsn1Encoder_New(WINPR_ASN1_DER);
	if (!enc)
		return NULL;

	/* TSRemoteGuardInnerPacket ::= SEQUENCE { */
	if (!WinPrAsn1EncSeqContainer(enc))
		goto out;

	/* packageName [1] OCTET STRING */
	WinPrAsn1_OctetString packageOctetString;
	switch (packageType)
	{
		case RDPEAR_PACKAGE_KERBEROS:
			packageOctetString.data = (BYTE*)kerberosPackageName;
			packageOctetString.len = sizeof(kerberosPackageName);
			break;
		case RDPEAR_PACKAGE_NTLM:
			packageOctetString.data = (BYTE*)ntlmPackageName;
			packageOctetString.len = sizeof(ntlmPackageName);
			break;
		default:
			goto out;
	}

	if (!WinPrAsn1EncContextualOctetString(enc, 1, &packageOctetString))
		goto out;

	/* buffer [2] OCTET STRING*/
	WinPrAsn1_OctetString payloadOctetString = { Stream_GetPosition(payload),
		                                         Stream_Buffer(payload) };
	if (!WinPrAsn1EncContextualOctetString(enc, 2, &payloadOctetString))
		goto out;

	/* } */
	if (!WinPrAsn1EncEndContainer(enc))
		goto out;

	ret = Stream_New(NULL, 100);
	if (!ret)
		goto out;

	if (!WinPrAsn1EncToStream(enc, ret))
	{
		Stream_Free(ret, TRUE);
		ret = NULL;
		goto out;
	}
out:
	WinPrAsn1Encoder_Free(&enc);
	return ret;
}


NdrFieldStruct KERB_RPC_OCTET_STRING_fields[] = {
	{ "Length", offsetof(KERB_RPC_OCTET_STRING, length), FALSE, -1, &ndr_uint32_descr_s },
	{ "value", offsetof(KERB_RPC_OCTET_STRING, value), TRUE, 0, &ndr_uint8Array_descr_s }
};
NdrStructDescr KERB_RPC_OCTET_STRING_struct = {
	"KERB_RPC_OCTET_STRING", 2,
	KERB_RPC_OCTET_STRING_fields
};


BOOL ndr_read_KERB_RPC_OCTET_STRING(NdrContext* context, wStream* s, const void *hints, void* res)
{
	return ndr_struct_read_fromDescr(context, s, &KERB_RPC_OCTET_STRING_struct, res);
}

void KERB_RPC_OCTET_STRING_dump(wLog* logger, UINT32 lvl, KERB_RPC_OCTET_STRING* obj)
{
	WLog_Print(logger, lvl, "\tLength=0x%x", obj->length);
	winpr_HexLogDump(logger, lvl, obj->value, obj->length);
}

void KERB_RPC_OCTET_STRING_destroy(NdrContext* context, KERB_RPC_OCTET_STRING* obj)
{
	free(obj->value);
	obj->value = NULL;
}

static NdrMessageDescr KERB_RPC_OCTET_STRING_descr_ = {
	NDR_ARITY_SIMPLE,
	sizeof(KERB_RPC_OCTET_STRING),
	ndr_read_KERB_RPC_OCTET_STRING,
	(NDR_WRITER_FN) NULL /*ndr_write_KERB_RPC_OCTET_STRING*/,
	(NDR_DESTROY_FN)KERB_RPC_OCTET_STRING_destroy
};

NdrMessageType KERB_RPC_OCTET_STRING_descr() {
	return &KERB_RPC_OCTET_STRING_descr_;
}


/* ============================= KERB_ASN1_DATA ============================== */

NdrFieldStruct KERB_ASN1_DATA_fields[] = {
	{ "Pdu", offsetof(KERB_ASN1_DATA, Pdu), FALSE, -1, &ndr_uint32_descr_s },
	{ "Count", offsetof(KERB_ASN1_DATA, Asn1BufferHints.count), FALSE, -1, &ndr_uint32_descr_s },
	{ "Asn1Buffer", offsetof(KERB_ASN1_DATA, Asn1Buffer), TRUE, 1, &ndr_uint8Array_descr_s }
};
NdrStructDescr KERB_ASN1_DATA_struct = {
	"KERB_ASN1_DATA", ARRAYSIZE(KERB_ASN1_DATA_fields),
	KERB_ASN1_DATA_fields
};

BOOL ndr_read_KERB_ASN1_DATA(NdrContext* context, wStream* s, void *hints, KERB_ASN1_DATA* res)
{
	return ndr_struct_read_fromDescr(context, s, &KERB_ASN1_DATA_struct, res);
}


BOOL ndr_write_KERB_ASN1_DATA(NdrContext* context, wStream* s, const void *hints, const KERB_ASN1_DATA* res)
{
	return ndr_struct_write_fromDescr(context, s, &KERB_ASN1_DATA_struct, res);
}

void KERB_ASN1_DATA_dump(wLog* logger, UINT32 lvl, KERB_ASN1_DATA* obj)
{
	WLog_Print(logger, lvl, "\tPduType=0x%x Length=0x%x", obj->Pdu, obj->Asn1BufferHints.count);
	winpr_HexLogDump(logger, lvl, obj->Asn1Buffer, obj->Asn1BufferHints.count);
}

void KERB_ASN1_DATA_destroy(NdrContext* context, KERB_ASN1_DATA* obj)
{
	if (!obj)
		return;
	free(obj->Asn1Buffer);
	obj->Asn1Buffer = NULL;
}

static NdrMessageDescr KERB_ASN1_DATA_descr_s = {
	NDR_ARITY_SIMPLE,
	sizeof(KERB_ASN1_DATA),
	(NDR_READER_FN)ndr_read_KERB_ASN1_DATA,
	(NDR_WRITER_FN)ndr_write_KERB_ASN1_DATA,
	(NDR_DESTROY_FN)KERB_ASN1_DATA_destroy
};

NdrMessageType KERB_ASN1_DATA_descr() {
	return &KERB_ASN1_DATA_descr_s;
}

/* ============================ RPC_UNICODE_STRING ========================== */


BOOL ndr_read_RPC_UNICODE_STRING(NdrContext* context, wStream* s, void *hints, RPC_UNICODE_STRING* res)
{
	NdrDeferredEntry bufferDesc = {
		NDR_PTR_NULL,
		"RPC_UNICODE_STRING.Buffer",
		&res->lenHints,
		&res->Buffer,
		ndr_uint16VaryingArray_descr()
	};
	UINT16 Length, MaximumLength;

	if (!ndr_read_uint16(context, s, &Length) ||
	    !ndr_read_uint16(context, s, &MaximumLength) ||
	    !ndr_read_refpointer(context, s, &bufferDesc.ptrId) || Length > MaximumLength)
		return FALSE;

	res->lenHints.length = Length;
	res->lenHints.maxLength = MaximumLength;
	res->strLength = Length / 2;

	return ndr_push_deferreds(context, &bufferDesc, 1);
}

BOOL ndr_write_RPC_UNICODE_STRING(NdrContext* context, wStream* s, const void *hints, const RPC_UNICODE_STRING* res)
{
	return ndr_write_uint32(context, s, res->lenHints.length) &&
	       ndr_write_uint32(context, s, res->lenHints.maxLength) /*&&
	       ndr_write_BYTE_ptr(context, s, (BYTE*)res->Buffer, res->Length)*/
	    ;
}

void RPC_UNICODE_STRING_dump(wLog* logger, UINT32 lvl, RPC_UNICODE_STRING* obj)
{
	WLog_Print(logger, lvl, "\tLength=%d MaximumLength=%d", obj->lenHints.length, obj->lenHints.maxLength);
	winpr_HexLogDump(logger, lvl, obj->Buffer, obj->lenHints.length);
}

void RPC_UNICODE_STRING_destroy(NdrContext* context, RPC_UNICODE_STRING* obj)
{
	if (!obj)
		return;
	free(obj->Buffer);
	obj->Buffer = NULL;
}


static NdrMessageDescr RPC_UNICODE_STRING_descr_ = {
	NDR_ARITY_SIMPLE,
	sizeof(RPC_UNICODE_STRING),
	(NDR_READER_FN)ndr_read_RPC_UNICODE_STRING,
	(NDR_WRITER_FN)ndr_write_RPC_UNICODE_STRING,
	(NDR_DESTROY_FN)RPC_UNICODE_STRING_destroy
};

NdrMessageType RPC_UNICODE_STRING_descr() {
	return &RPC_UNICODE_STRING_descr_;
}

/* ========================= RPC_UNICODE_STRING_Array ======================== */


static BOOL ndr_read_RPC_UNICODE_STRING_Array(NdrContext* context, wStream* s, const void *hints, void* v)
{
	WINPR_ASSERT(context);
	WINPR_ASSERT(s);
	WINPR_ASSERT(hints);
	return ndr_read_uconformant_array(context, s, hints, RPC_UNICODE_STRING_descr(), v);
}

static BOOL ndr_write_RPC_UNICODE_STRING_Array(NdrContext* context, wStream* s, const void *ghints, const void* v)
{
	WINPR_ASSERT(context);
	WINPR_ASSERT(s);
	WINPR_ASSERT(ghints);

	const NdrArrayHints *hints = (const NdrArrayHints *)ghints;

	return ndr_write_uconformant_array(context, s, hints->count, RPC_UNICODE_STRING_descr(), v);
}


static NdrMessageDescr RPC_UNICODE_STRING_Array_descr_ = {
	NDR_ARITY_ARRAYOF,
	sizeof(RPC_UNICODE_STRING),
	ndr_read_RPC_UNICODE_STRING_Array,
	ndr_write_RPC_UNICODE_STRING_Array,
	(NDR_DESTROY_FN)NULL
};

NdrMessageType RPC_UNICODE_STRING_Array_descr()
{
	return &RPC_UNICODE_STRING_Array_descr_;
}

/* ========================== KERB_RPC_INTERNAL_NAME ======================== */

BOOL ndr_read_KERB_RPC_INTERNAL_NAME(NdrContext* context, wStream* s, void *hints, KERB_RPC_INTERNAL_NAME* res)
{
	NdrDeferredEntry names = {
		NDR_PTR_NULL,
		"KERB_RPC_INTERNAL_NAME.Names",
		&res->nameHints,
		&res->Names,
		RPC_UNICODE_STRING_Array_descr()
	};

	UINT16 nameCount;
	if (!ndr_read_uint16(context, s, &res->NameType) ||
	    !ndr_read_uint16(context, s, &nameCount))
		return FALSE;

	res->nameHints.count = nameCount;

	return ndr_read_refpointer(context, s, &names.ptrId) &&
		ndr_push_deferreds(context, &names, 1);
}

BOOL ndr_write_KERB_RPC_INTERNAL_NAME(NdrContext* context, wStream* s,
                                      const KERB_RPC_INTERNAL_NAME* res)
{
	return FALSE;
}

void KERB_RPC_INTERNAL_NAME_dump(wLog* logger, UINT32 lvl, KERB_RPC_INTERNAL_NAME* obj)
{
}

void KERB_RPC_INTERNAL_NAME_destroy(NdrContext* context, KERB_RPC_INTERNAL_NAME* obj)
{
	if (!obj)
		return;

	for (int i = 0; i < obj->nameHints.count; i++)
		RPC_UNICODE_STRING_destroy(context, &obj->Names[i]);

	free(obj->Names);
	obj->Names = NULL;
}


NdrMessageDescr KERB_RPC_INTERNAL_NAME_descr_ = {
	NDR_ARITY_SIMPLE,
	sizeof(KERB_RPC_INTERNAL_NAME),
	(NDR_READER_FN)ndr_read_KERB_RPC_INTERNAL_NAME,
	(NDR_WRITER_FN)NULL,
	(NDR_DESTROY_FN)KERB_RPC_INTERNAL_NAME_destroy
};

NdrMessageType KERB_RPC_INTERNAL_NAME_descr() {
	return &KERB_RPC_INTERNAL_NAME_descr_;
}

/* ========================== KERB_RPC_ENCRYPTION_KEY ======================== */

NdrFieldStruct KERB_RPC_ENCRYPTION_KEY_fields[] = {
	{ "reserved1", offsetof(KERB_RPC_ENCRYPTION_KEY, reserved1), FALSE, -1, &ndr_uint32_descr_s },
	{ "reserved2", offsetof(KERB_RPC_ENCRYPTION_KEY, reserved2), FALSE, -1, &ndr_uint32_descr_s },
	{ "reserved3", offsetof(KERB_RPC_ENCRYPTION_KEY, reserved3), FALSE, -1, &KERB_RPC_OCTET_STRING_descr_ }
};
NdrStructDescr KERB_RPC_ENCRYPTION_KEY_struct = {
	"KERB_ASN1_DATA", ARRAYSIZE(KERB_RPC_ENCRYPTION_KEY_fields),
	KERB_RPC_ENCRYPTION_KEY_fields
};


BOOL ndr_read_KERB_RPC_ENCRYPTION_KEY(NdrContext* context, wStream* s, const void *hints, void* res)
{
	return ndr_struct_read_fromDescr(context, s, &KERB_RPC_ENCRYPTION_KEY_struct, res);
}


void KERB_RPC_ENCRYPTION_KEY_dump(wLog* logger, UINT32 lvl, KERB_RPC_ENCRYPTION_KEY* obj)
{
	WLog_Print(logger, lvl, "\treserved1=0x%x reserved2=0x%x", obj->reserved1, obj->reserved2);
	WLog_Print(logger, lvl, "\treserved3=");
	KERB_RPC_OCTET_STRING_dump(logger, lvl, &obj->reserved3);
}

void KERB_RPC_ENCRYPTION_KEY_destroy(NdrContext* context, KERB_RPC_ENCRYPTION_KEY* obj)
{
	KERB_RPC_OCTET_STRING_destroy(context, &obj->reserved3);
}

NdrMessageDescr KERB_RPC_ENCRYPTION_KEY_descr_s = {
	NDR_ARITY_SIMPLE,
	sizeof(KERB_RPC_ENCRYPTION_KEY),
	ndr_read_KERB_RPC_ENCRYPTION_KEY,
	(NDR_WRITER_FN)NULL,
	(NDR_DESTROY_FN)KERB_RPC_ENCRYPTION_KEY_destroy
};

NdrMessageType KERB_RPC_ENCRYPTION_KEY_descr() {
	return &KERB_RPC_ENCRYPTION_KEY_descr_s;
}


/* ========================== BuildEncryptedAuthDataReq ======================== */

NdrFieldStruct BuildEncryptedAuthDataReq_fields[] = {
	{ "KeyUsage", offsetof(BuildEncryptedAuthDataReq, KeyUsage), FALSE, -1, &ndr_uint32_descr_s },
	{ "key", offsetof(BuildEncryptedAuthDataReq, Key), TRUE, -1, &KERB_RPC_ENCRYPTION_KEY_descr_s },
	{ "plainAuthData", offsetof(BuildEncryptedAuthDataReq, PlainAuthData), TRUE, -1, &KERB_ASN1_DATA_descr_s }
};
NdrStructDescr BuildEncryptedAuthDataReq_struct = {
	"BuildEncryptedAuthDataReq", ARRAYSIZE(BuildEncryptedAuthDataReq_fields),
	BuildEncryptedAuthDataReq_fields
};


BOOL ndr_read_BuildEncryptedAuthDataReq(NdrContext* context, wStream* s,
                                        BuildEncryptedAuthDataReq* req)
{
	return ndr_struct_read_fromDescr(context, s, &BuildEncryptedAuthDataReq_struct, req);
}

void BuildEncryptedAuthDataReq_dump(wLog* logger, UINT32 lvl, BuildEncryptedAuthDataReq* obj)
{
	WLog_Print(logger, lvl, "\tKeyUsage=0x%x", obj->KeyUsage);

	WLog_Print(logger, lvl, "\tKey:");
	if (obj->Key)
		KERB_RPC_ENCRYPTION_KEY_dump(logger, lvl, obj->Key);
	else
		WLog_Print(logger, lvl, "\tKey: null");

	WLog_Print(logger, lvl, "\tPlainAuthData:");
	KERB_ASN1_DATA_dump(logger, lvl, obj->PlainAuthData);
}


/* ========================== ComputeTgsChecksumReq ======================== */

NdrFieldStruct ComputeTgsChecksumReq_fields[] = {
	{ "requestBody", offsetof(ComputeTgsChecksumReq, requestBody), TRUE, -1, &KERB_ASN1_DATA_descr_s },
	{ "key", offsetof(ComputeTgsChecksumReq, Key), TRUE, -1, &KERB_RPC_ENCRYPTION_KEY_descr_s },
	{ "ChecksumType", offsetof(ComputeTgsChecksumReq, ChecksumType), FALSE, -1, &ndr_uint32_descr_s }
};
NdrStructDescr ComputeTgsChecksumReq_struct = {
	"ComputeTgsChecksumReq", ARRAYSIZE(ComputeTgsChecksumReq_fields),
	ComputeTgsChecksumReq_fields
};


BOOL ndr_read_ComputeTgsChecksumReq(NdrContext* context, wStream* s, ComputeTgsChecksumReq* req)
{
	return ndr_struct_read_fromDescr(context, s, &ComputeTgsChecksumReq_struct, req);
}

void ComputeTgsChecksumReq_dump(wLog* logger, UINT32 lvl, ComputeTgsChecksumReq* obj)
{
	WLog_Print(logger, lvl, "\tRequestBody:");
	KERB_ASN1_DATA_dump(logger, lvl, obj->requestBody);

	WLog_Print(logger, lvl, "\tKey:");
	KERB_RPC_ENCRYPTION_KEY_dump(logger, lvl, obj->Key);

	WLog_Print(logger, lvl, "\tChecksumType=0x%x", obj->ChecksumType);
}

/* ========================== CreateApReqAuthenticatorReq ======================== */


NdrFieldStruct CreateApReqAuthenticatorReq_fields[] = {
	{ "EncryptionKey", offsetof(CreateApReqAuthenticatorReq, EncryptionKey), TRUE, -1, &KERB_RPC_ENCRYPTION_KEY_descr_s },
	{ "SequenceNumber", offsetof(CreateApReqAuthenticatorReq, SequenceNumber), FALSE, -1, &ndr_uint32_descr_s },
	{ "ClientName", offsetof(CreateApReqAuthenticatorReq, ClientName), TRUE, -1, &KERB_RPC_INTERNAL_NAME_descr_ },
	{ "ClientRealm", offsetof(CreateApReqAuthenticatorReq, ClientRealm), TRUE, -1, &RPC_UNICODE_STRING_descr_ },
	{ "SkewTime", offsetof(CreateApReqAuthenticatorReq, SkewTime), TRUE, -1, &ndr_uint64_descr_s },
	{ "SubKey", offsetof(CreateApReqAuthenticatorReq, SubKey), TRUE, -1, &KERB_RPC_ENCRYPTION_KEY_descr_s },
	{ "AuthData", offsetof(CreateApReqAuthenticatorReq, AuthData), TRUE, -1, &KERB_ASN1_DATA_descr_s },
	{ "GssChecksum", offsetof(CreateApReqAuthenticatorReq, GssChecksum), TRUE, -1, &KERB_ASN1_DATA_descr_s },
	{ "KeyUsage", offsetof(CreateApReqAuthenticatorReq, KeyUsage), FALSE, -1, &ndr_uint32_descr_s },
};
NdrStructDescr CreateApReqAuthenticatorReq_struct = {
	"CreateApReqAuthenticatorReq", ARRAYSIZE(CreateApReqAuthenticatorReq_fields),
	CreateApReqAuthenticatorReq_fields
};

BOOL ndr_read_CreateApReqAuthenticatorReq(NdrContext* context, wStream* s, CreateApReqAuthenticatorReq* req)
{
	return ndr_struct_read_fromDescr(context, s, &CreateApReqAuthenticatorReq_struct, req);
}

void CreateApReqAuthenticatorReq_dump(wLog* logger, UINT32 lvl, CreateApReqAuthenticatorReq* obj)
{
	WLog_Print(logger, lvl, "Encryption Key:");
	KERB_RPC_ENCRYPTION_KEY_dump(logger, lvl, obj->EncryptionKey);

	WLog_Print(logger, lvl, "Realm:");
	RPC_UNICODE_STRING_dump(logger, lvl, obj->ClientRealm);

	WLog_Print(logger, lvl, "AuthData:");
	RPC_UNICODE_STRING_dump(logger, lvl, obj->ClientRealm);

}

void CreateApReqAuthenticatorReq_destroy(NdrContext* context, CreateApReqAuthenticatorReq* obj)
{
	if (obj->EncryptionKey) {
		KERB_RPC_ENCRYPTION_KEY_destroy(context, obj->EncryptionKey);
		free(obj->EncryptionKey);
		obj->EncryptionKey = NULL;
	}

	if (obj->ClientName) {
		KERB_RPC_INTERNAL_NAME_destroy(context, obj->ClientName);
		free(obj->ClientName);
		obj->ClientName = NULL;
	}

	if (obj->ClientRealm) {
		RPC_UNICODE_STRING_destroy(context, obj->ClientRealm);
		free(obj->ClientRealm);
		obj->ClientRealm = NULL;
	}

	free(obj->SkewTime);
	obj->SkewTime = NULL;

	if (obj->SubKey) {
		KERB_RPC_ENCRYPTION_KEY_destroy(context, obj->SubKey);
		free(obj->SubKey);
		obj->SubKey = NULL;
	}

	if (obj->AuthData) {
		KERB_ASN1_DATA_destroy(context, obj->AuthData);
		free(obj->AuthData);
		obj->AuthData = NULL;
	}

	if (obj->GssChecksum) {
		KERB_ASN1_DATA_destroy(context, obj->GssChecksum);
		free(obj->GssChecksum);
		obj->GssChecksum = NULL;
	}
}


/* ========================== CreateApReqAuthenticatorResp ======================== */

NdrFieldStruct CreateApReqAuthenticatorResp_fields[] = {
	{ "AuthenticatorTime", offsetof(CreateApReqAuthenticatorResp, AuthenticatorTime), FALSE, -1, &ndr_uint64_descr_s },
	{ "Authenticator", offsetof(CreateApReqAuthenticatorResp, Authenticator), FALSE, -1, &KERB_ASN1_DATA_descr_s },
	{ "KerbProtocolError", offsetof(CreateApReqAuthenticatorResp, KerbProtocolError), FALSE, -1, &ndr_uint32_descr_s },
};

NdrStructDescr CreateApReqAuthenticatorResp_struct = {
	"CreateApReqAuthenticatorResp", ARRAYSIZE(CreateApReqAuthenticatorResp_fields),
	CreateApReqAuthenticatorResp_fields
};


BOOL CreateApReqAuthenticatorResp_read(NdrContext* context, wStream* s, CreateApReqAuthenticatorResp* obj)
{
	return ndr_struct_read_fromDescr(context, s, &CreateApReqAuthenticatorResp_struct, obj);
}

BOOL CreateApReqAuthenticatorResp_write(NdrContext* context, wStream* s, const CreateApReqAuthenticatorResp* obj)
{
	return ndr_struct_write_fromDescr(context, s, &CreateApReqAuthenticatorResp_struct, obj);
}

void CreateApReqAuthenticatorResp_dump(wLog* logger, UINT32 lvl, CreateApReqAuthenticatorResp* obj)
{
}

void CreateApReqAuthenticatorResp_destroy(NdrContext* context, CreateApReqAuthenticatorResp* obj)
{
	ndr_struct_destroy(context, &CreateApReqAuthenticatorResp_struct, obj);
}




/* ========================== UnpackKdcReplyBodyReq ======================== */

NdrFieldStruct UnpackKdcReplyBodyReq_fields[] = {
	{ "EncryptedData", offsetof(UnpackKdcReplyBodyReq, EncryptedData), TRUE, -1, &KERB_ASN1_DATA_descr_s },
	{ "Key", offsetof(UnpackKdcReplyBodyReq, Key), TRUE, -1, &KERB_RPC_ENCRYPTION_KEY_descr_s },
	{ "StrenghtenKey", offsetof(UnpackKdcReplyBodyReq, StrengthenKey), TRUE, -1, &KERB_RPC_ENCRYPTION_KEY_descr_s },
	{ "Pdu", offsetof(UnpackKdcReplyBodyReq, Pdu), FALSE, -1, &ndr_uint32_descr_s },
	{ "KeyUsage", offsetof(UnpackKdcReplyBodyReq, KeyUsage), FALSE, -1, &ndr_uint32_descr_s },
};

NdrStructDescr UnpackKdcReplyBodyReq_struct = {
	"UnpackKdcReplyBodyReq", ARRAYSIZE(UnpackKdcReplyBodyReq_fields),
	UnpackKdcReplyBodyReq_fields
};

BOOL ndr_read_UnpackKdcReplyBodyReq(NdrContext* context, wStream* s, UnpackKdcReplyBodyReq* req)
{
	return ndr_struct_read_fromDescr(context, s, &UnpackKdcReplyBodyReq_struct, req);
}


/* ========================== UnpackKdcReplyBodyResp ======================== */

NdrFieldStruct UnpackKdcReplyBodyResp_fields[] = {
	{ "KerbProtocolError", offsetof(UnpackKdcReplyBodyResp, KerbProtocolError), FALSE, -1, &ndr_uint32_descr_s },
	{ "ReplyBody", offsetof(UnpackKdcReplyBodyResp, ReplyBody), FALSE, -1, &KERB_ASN1_DATA_descr_s }
};

NdrStructDescr UnpackKdcReplyBodyResp_struct = {
	"UnpackKdcReplyBodyResp", ARRAYSIZE(UnpackKdcReplyBodyResp_fields),
	UnpackKdcReplyBodyResp_fields
};


BOOL UnpackKdcReplyBodyResp_write(NdrContext* context, wStream* s, const UnpackKdcReplyBodyResp* resp)
{
	return ndr_struct_write_fromDescr(context, s, &UnpackKdcReplyBodyResp_struct, resp);
}

