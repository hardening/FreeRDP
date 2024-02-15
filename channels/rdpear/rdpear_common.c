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


BOOL ndr_read_KERB_RPC_OCTET_STRING(NdrContext* context, wStream* s, void *hints, KERB_RPC_OCTET_STRING* res)
{
	NdrDeferredEntry valueDef = {
		0,
		"KERB_RPC_OCTET_STRING.value",
		&res->length,
		&res->value,
		ndr_uint8Array_descr()
	};

	return ndr_read_uint32(context, s, &res->length) &&
			ndr_read_refpointer(context, s, &valueDef.ptrId) &&
			ndr_push_deferreds(context, &valueDef, 1);
}

void KERB_RPC_OCTET_STRING_dump(wLog* logger, UINT32 lvl, KERB_RPC_OCTET_STRING* obj)
{
	WLog_Print(logger, lvl, "\tLength=0x%x", obj->length);
	winpr_HexLogDump(logger, lvl, obj->value, obj->length);
}

void KERB_RPC_OCTET_STRING_destroy(NdrContext* context, KERB_RPC_OCTET_STRING* obj)
{
	free(obj->value);
}

static NdrMessageDescr KERB_RPC_OCTET_STRING_descr_ = {
	sizeof(KERB_RPC_OCTET_STRING),
	(NDR_READER_FN)ndr_read_KERB_RPC_OCTET_STRING,
	(NDR_WRITER_FN) NULL /*ndr_write_KERB_RPC_OCTET_STRING*/,
	(NDR_DESTROY_FN)KERB_RPC_OCTET_STRING_destroy
};

NdrMessageType KERB_RPC_OCTET_STRING_descr() {
	return &KERB_RPC_OCTET_STRING_descr_;
}


BOOL ndr_read_KERB_ASN1_DATA(NdrContext* context, wStream* s, void *hints, KERB_ASN1_DATA* res)
{
	NdrDeferredEntry asn1BufferDef = {
		0,
		"KERB_ASN1_DATA.Asn1Buffer",
		&res->Asn1BufferHints,
		&res->Asn1Buffer,
		ndr_uint8Array_descr()
	};

	return ndr_read_uint32(context, s, &res->Pdu) &&
		ndr_read_uint32(context, s, &res->Asn1BufferHints.count) &&
	    ndr_read_refpointer(context, s, &asn1BufferDef.ptrId) &&
		ndr_push_deferreds(context, &asn1BufferDef, 1);
}


BOOL ndr_write_KERB_ASN1_DATA(NdrContext* context, wStream* s, const KERB_ASN1_DATA* res)
{
	return ndr_write_uint32(context, s, res->Pdu) &&
			ndr_write_uint32(context, s, res->Asn1BufferHints.count)/* &&
	       ndr_write_byteArrayPtr(context, s, res->Asn1Buffer, res->Length)*/;
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

static NdrMessageDescr KERB_ASN1_DATA_descr_ = {
	sizeof(KERB_ASN1_DATA),
	(NDR_READER_FN)ndr_read_KERB_ASN1_DATA,
	(NDR_WRITER_FN)ndr_write_KERB_ASN1_DATA,
	(NDR_DESTROY_FN)KERB_ASN1_DATA_destroy
};

NdrMessageType KERB_ASN1_DATA_descr() {
	return &KERB_ASN1_DATA_descr_;
}


BOOL ndr_read_RPC_UNICODE_STRING(NdrContext* context, wStream* s, void *hints, RPC_UNICODE_STRING* res)
{
	NdrDeferredEntry bufferDesc = {
		0,
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

BOOL ndr_write_RPC_UNICODE_STRING(NdrContext* context, wStream* s, const RPC_UNICODE_STRING* res)
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
	sizeof(RPC_UNICODE_STRING),
	(NDR_READER_FN)ndr_read_RPC_UNICODE_STRING,
	(NDR_WRITER_FN)ndr_write_RPC_UNICODE_STRING,
	(NDR_DESTROY_FN)RPC_UNICODE_STRING_destroy
};

NdrMessageType RPC_UNICODE_STRING_descr() {
	return &RPC_UNICODE_STRING_descr_;
}

BOOL ndr_read_RPC_UNICODE_STRING_Array(NdrContext* context, wStream* s, void *hints, void* v)
{
	WINPR_ASSERT(context);
	NdrArrayHints *ahints = (NdrArrayHints *)hints;
	return ndr_read_uconformant_array(context, s, ahints->count, RPC_UNICODE_STRING_descr(), (void**)v);
}

static NdrMessageDescr RPC_UNICODE_STRING_Array_descr_ = {
	sizeof(RPC_UNICODE_STRING*),
	(NDR_READER_FN)ndr_read_RPC_UNICODE_STRING_Array,
	(NDR_WRITER_FN)/*ndr_write_##TYPE##Array*/NULL,
	(NDR_DESTROY_FN)NULL
};

NdrMessageType RPC_UNICODE_STRING_Array_descr()
{
	return &RPC_UNICODE_STRING_Array_descr_;
}

BOOL ndr_read_KERB_RPC_INTERNAL_NAME(NdrContext* context, wStream* s, void *hints, KERB_RPC_INTERNAL_NAME* res)
{
	NdrDeferredEntry names = {
		0,
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
	sizeof(KERB_RPC_INTERNAL_NAME),
	(NDR_READER_FN)ndr_read_KERB_RPC_INTERNAL_NAME,
	(NDR_WRITER_FN)NULL,
	(NDR_DESTROY_FN)KERB_RPC_INTERNAL_NAME_destroy
};

NdrMessageType KERB_RPC_INTERNAL_NAME_descr() {
	return &KERB_RPC_INTERNAL_NAME_descr_;
}



BOOL ndr_read_KERB_RPC_ENCRYPTION_KEY(NdrContext* context, wStream* s, void *hints, KERB_RPC_ENCRYPTION_KEY* res)
{
	return ndr_read_uint32(context, s, &res->reserved1) &&
	       ndr_read_uint32(context, s, &res->reserved2) &&
	       ndr_read_KERB_RPC_OCTET_STRING(context, s, NULL, &res->reserved3);
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

NdrMessageDescr KERB_RPC_ENCRYPTION_KEY_descr_ = {
	sizeof(KERB_RPC_ENCRYPTION_KEY),
	(NDR_READER_FN)ndr_read_KERB_RPC_ENCRYPTION_KEY,
	(NDR_WRITER_FN)NULL,
	(NDR_DESTROY_FN)KERB_RPC_ENCRYPTION_KEY_destroy
};

NdrMessageType KERB_RPC_ENCRYPTION_KEY_descr() {
	return &KERB_RPC_ENCRYPTION_KEY_descr_;
}

BOOL ndr_read_BuildEncryptedAuthDataReq(NdrContext* context, wStream* s,
                                        BuildEncryptedAuthDataReq* req)
{
	NdrDeferredEntry pointers[] = {
		{
			0,
			"BuildEncryptedAuthDataReq.key",
			NULL,
			&req->Key,
			KERB_RPC_ENCRYPTION_KEY_descr()
		},
		{
			0,
			"BuildEncryptedAuthDataReq.plainAuth",
			NULL,
			&req->PlainAuthData,
			KERB_ASN1_DATA_descr()
		}
	};

	return ndr_read_uint32(context, s, &req->KeyUsage) &&
		ndr_read_refpointer(context, s, &pointers[0].ptrId) &&
		ndr_read_refpointer(context, s, &pointers[1].ptrId) &&
		ndr_push_deferreds(context, pointers, 2);

}

void BuildEncryptedAuthDataReq_dump(wLog* logger, UINT32 lvl, BuildEncryptedAuthDataReq* obj)
{
	WLog_Print(logger, lvl, "\tKeyUsage=0x%x", obj->KeyUsage);

	WLog_Print(logger, lvl, "\tKey:");
	KERB_RPC_ENCRYPTION_KEY_dump(logger, lvl, obj->Key);

	WLog_Print(logger, lvl, "\tPlainAuthData:");
	KERB_ASN1_DATA_dump(logger, lvl, obj->PlainAuthData);
}

BOOL ndr_read_ComputeTgsChecksumReq(NdrContext* context, wStream* s, ComputeTgsChecksumReq* req)
{
	NdrDeferredEntry pointers[] = {
		{
			0,
			"ComputeTgsChecksumReq.requestBody",
			NULL,
			&req->requestBody,
			KERB_ASN1_DATA_descr()
		},
		{
			0,
			"ComputeTgsChecksumReq.Key",
			NULL,
			&req->requestBody,
			KERB_RPC_ENCRYPTION_KEY_descr()
		}
	};

	return ndr_read_refpointer(context, s, &pointers[0].ptrId) &&
	    ndr_read_refpointer(context, s, &pointers[1].ptrId) &&
	    ndr_read_uint32(context, s, &req->ChecksumType) &&
		ndr_push_deferreds(context, pointers, 2);
}

void ComputeTgsChecksumReq_dump(wLog* logger, UINT32 lvl, ComputeTgsChecksumReq* obj)
{
	WLog_Print(logger, lvl, "\tRequestBody:");
	KERB_ASN1_DATA_dump(logger, lvl, obj->requestBody);

	WLog_Print(logger, lvl, "\tKey:");
	KERB_RPC_ENCRYPTION_KEY_dump(logger, lvl, obj->Key);

	WLog_Print(logger, lvl, "\tChecksumType=0x%x", obj->ChecksumType);
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

BOOL ndr_read_CreateApReqAuthenticatorReq(NdrContext* context, wStream* s, CreateApReqAuthenticatorReq* req)
{
	NdrDeferredEntry pointers[] = {
		{
			0,
			"CreateApReqAuthenticatorReq.EncryptionKey",
			NULL,
			&req->EncryptionKey,
			KERB_RPC_ENCRYPTION_KEY_descr()
		},
		{
			0,
			"CreateApReqAuthenticatorReq.ClientName",
			NULL,
			&req->ClientName,
			KERB_RPC_INTERNAL_NAME_descr()
		},
		{
			0,
			"CreateApReqAuthenticatorReq.ClientRealm",
			NULL,
			&req->ClientRealm,
			RPC_UNICODE_STRING_descr()
		},
		{
			0,
			"CreateApReqAuthenticatorReq.SkewTime",
			NULL,
			&req->SkewTime,
			ndr_uint64_descr()
		},
		{
			0,
			"CreateApReqAuthenticatorReq.SubKey",
			NULL,
			&req->SubKey,
			KERB_RPC_ENCRYPTION_KEY_descr()
		},
		{
			0,
			"CreateApReqAuthenticatorReq.authData",
			NULL,
			&req->AuthData,
			KERB_ASN1_DATA_descr()
		},
		{
			0,
			"CreateApReqAuthenticatorReq.GssChecksum",
			NULL,
			&req->GssChecksum,
			KERB_ASN1_DATA_descr()
		}
	};

	return ndr_read_refpointer(context, s, &pointers[0].ptrId) &&
	    ndr_read_uint32(context, s, &req->SequenceNumber) &&
	    ndr_read_refpointer(context, s, &pointers[1].ptrId) &&
	    ndr_read_refpointer(context, s, &pointers[2].ptrId) &&
	    ndr_read_refpointer(context, s, &pointers[3].ptrId) &&
	    ndr_read_refpointer(context, s, &pointers[4].ptrId) &&
	    ndr_read_refpointer(context, s, &pointers[5].ptrId) &&
	    ndr_read_refpointer(context, s, &pointers[6].ptrId) &&
	    ndr_read_uint32(context, s, &req->KeyUsage) &&
		ndr_push_deferreds(context, pointers, ARRAYSIZE(pointers));
}

void CreateApReqAuthenticatorReq_dump(wLog* logger, UINT32 lvl, CreateApReqAuthenticatorReq* obj)
{
}


