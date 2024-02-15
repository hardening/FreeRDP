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

#include <freerdp/channels/log.h>

#define TAG CHANNELS_TAG("rdpear")

const char kerberosPackageName[] = {
	'K', 0, 'e', 0, 'r', 0, 'b', 0, 'e', 0, 'r', 0, 'o', 0, 's', 0
};
const char ntlmPackageName[] = {
	'N', 0, 'T', 0, 'L', 0, 'M', 0
};


RdpEarPackageType rdpear_packageType_from_name(WinPrAsn1_OctetString *package)
{
	if (package->len == sizeof(kerberosPackageName) && memcmp(package->data, kerberosPackageName, package->len))
		return RDPEAR_PACKAGE_KERBEROS;

	if (package->len == sizeof(ntlmPackageName) && memcmp(package->data, ntlmPackageName, package->len))
		return RDPEAR_PACKAGE_NTLM;

	return RDPEAR_PACKAGE_UNKNOWN;
}

wStream *rdpear_encodePayload(RdpEarPackageType packageType, wStream *payload)
{
	wStream *ret = NULL;
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
	WinPrAsn1_OctetString payloadOctetString = { Stream_GetPosition(payload), Stream_Buffer(payload) };
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

BOOL rdpear_read_ndr_header(wStream *s, BYTE *version, BYTE *drep) {
	if (!Stream_CheckAndLogRequiredLength(TAG, s, 8))
		return FALSE;

	Stream_Read_UINT8(s, *version);
	Stream_Read_UINT8(s, *drep);

	UINT16 headerLen;
	Stream_Read_UINT16(s, headerLen);

	if (headerLen < 4 || !Stream_CheckAndLogRequiredLength(TAG, s, headerLen-4))
		return FALSE;

	/* skip filler */
	Stream_Seek(s, headerLen-4);
	return TRUE;
}

BOOL rdpear_write_ndr_header(wStream *s, BYTE version, BYTE drep) {
	if (!Stream_EnsureRemainingCapacity(s, 8))
		return FALSE;

	Stream_Write_UINT8(s, version);
	Stream_Write_UINT8(s, drep);
	Stream_Write_UINT16(s, 0x8); /* header len */

	BYTE filler[] = { 0xcc, 0xcc, 0xcc, 0xcc };
	Stream_Write(s, filler, 4);
	return TRUE;
}


BOOL ndr_read_uint32(wStream *s, BYTE drep, UINT32 *v)
{
	if (!Stream_CheckAndLogRequiredLength(TAG, s, 4))
		return FALSE;

	if (drep == 0x10)
		Stream_Read_UINT32(s, *v);
	else
		Stream_Read_UINT32_BE(s, *v);
	return TRUE;
}

BOOL ndr_write_uint32(wStream *s, BYTE drep, UINT32 v)
{
	if (!Stream_EnsureRemainingCapacity(s, 4))
		return FALSE;

	if (drep == 0x10)
		Stream_Write_UINT32(s, v);
	else
		Stream_Write_UINT32_BE(s, v);
	return TRUE;
}

BOOL ndr_read_uint16(wStream *s, BYTE drep, UINT16 *v)
{
	if (!Stream_CheckAndLogRequiredLength(TAG, s, 2))
		return FALSE;

	if (drep == 0x10)
		Stream_Read_UINT16(s, *v);
	else
		Stream_Read_UINT16_BE(s, *v);
	return TRUE;
}

BOOL ndr_write_uint16(wStream *s, BYTE drep, UINT16 v)
{
	if (!Stream_EnsureRemainingCapacity(s, 2))
		return FALSE;

	if (drep == 0x10)
		Stream_Write_UINT16(s, v);
	else
		Stream_Write_UINT16_BE(s, v);
	return TRUE;
}

BOOL ndr_read_constructed(wStream *s, BYTE drep, wStream *target)
{
	UINT32 len;

	/* len */
	if (!ndr_read_uint32(s, drep, &len))
		return FALSE;

	/* padding */
	if (!Stream_CheckAndLogRequiredLength(TAG, s, 4))
		return FALSE;
	Stream_Seek(s, 4);

	/* payload */
	if (!Stream_CheckAndLogRequiredLength(TAG, s, len))
		return FALSE;

	Stream_StaticInit(target, Stream_PointerAs(s, BYTE), len);
	Stream_Seek(s, len);
	return TRUE;
}

BOOL ndr_write_constructed_header(wStream *s, BYTE drep, UINT32 payloadLen)
{
	if (!Stream_EnsureCapacity(s, 8))
		return FALSE;

	/* len */
	if (!ndr_write_uint32(s, drep, payloadLen))
		return FALSE;

	/* padding */
	Stream_Zero(s, 4);
	return TRUE;
}

BOOL ndr_write_constructed(wStream *s, BYTE drep, wStream *payload)
{
	UINT32 len = Stream_GetPosition(payload);

	if (!ndr_write_constructed_header(s, drep, len))
		return FALSE;

	/* payload */
	if (!Stream_EnsureRemainingCapacity(s, len))
		return FALSE;

	Stream_Write(s, Stream_Buffer(payload), len);
	return TRUE;
}

BOOL ndr_read_pickle(wStream *s, BYTE drep)
{
	UINT32 v;

	/* NDR format label */
	if (!ndr_read_uint32(s, drep, &v) || v != 0x20000)
		return FALSE;

	/* padding */
	if (!Stream_CheckAndLogRequiredLength(TAG, s, 4))
		return FALSE;
	Stream_Seek(s, 4);
	return TRUE;
}

BOOL ndr_write_pickle(wStream *s, BYTE drep)
{
	/* NDR format label */
	if (!ndr_write_uint32(s, drep, 0x20000))
		return FALSE;

	/* padding */
	if (!Stream_EnsureRemainingCapacity(s, 4))
		return FALSE;
	Stream_Zero(s, 4);
	return TRUE;
}


BOOL ndr_read_conformantArray(wStream *s, BYTE drep, size_t elemSize, wStream *arr)
{
	UINT32 count;

	if (!ndr_read_uint32(s, drep, &count))
		return FALSE;

	if (!Stream_CheckAndLogRequiredLengthEx(TAG, WLOG_ERROR, s, count, elemSize, "ndr_read_conformantArray(elemSize=%d, count=%d)", elemSize, count))
		return FALSE;

	Stream_StaticInit(arr, Stream_PointerAs(s, BYTE), count * elemSize);
	Stream_Seek(s, count * elemSize);
	return TRUE;
}

BOOL ndr_read_refPointerArray(NdrContext *ctx, wStream *s, BYTE drep, UINT32 pointerRef, size_t elemSize, wStream *arr)
{
	// TODO: test pointerRef
	return ndr_read_conformantArray(s, drep, elemSize, arr);
}


BOOL ndr_read_RPC_OCTET_STRING(NdrContext *ctx, wStream *s, BYTE drep, wStream *buffer)
{
	UINT32 len;
	UINT32 pointerRef;

	if (!ndr_read_uint32(s, drep, &len) || !ndr_read_uint32(s, drep, &pointerRef))
		return FALSE;

	return ndr_read_refPointerArray(ctx, s, drep, pointerRef, 1, buffer);
}

BOOL ndr_read_KERB_ASN1_DATA(NdrContext *ctx, wStream *s, BYTE drep, KERB_ASN1_DATA *asn1)
{
	UINT32 len;
	UINT32 pointerRef;

	if (!ndr_read_uint32(s, drep, &asn1->pdu) || !ndr_read_uint32(s, drep, &len) ||
		!ndr_read_uint32(s, drep, &pointerRef))
		return FALSE;

	return ndr_read_refPointerArray(ctx, s, drep, pointerRef, 1, &asn1->asn1Buffer);
}

BOOL ndr_read_KERB_RPC_ENCRYPTION_KEY(NdrContext *ctx, wStream *s, BYTE drep, UINT32 pointerRef, KERB_RPC_ENCRYPTION_KEY *key)
{
	if (!ndr_read_uint32(s, drep, &key->reserved1) || !ndr_read_uint32(s, drep, &key->reserved2))
		return FALSE;

	return ndr_read_RPC_OCTET_STRING(ctx, s, drep, &key->reserved3);
}

BOOL ndr_read_BuildEncryptedAuthData(NdrContext *ctx, wStream *s, BYTE drep, BuildEncryptedAuthData *auth)
{
	UINT32 keyPointerRef, plainPointerRef;

	if (!ndr_read_uint32(s, drep, &auth->keyUsage) || !ndr_read_uint32(s, drep, &keyPointerRef) ||
		!ndr_read_uint32(s, drep, &plainPointerRef))
		return FALSE;

	return ndr_read_KERB_RPC_ENCRYPTION_KEY(ctx, s, drep, keyPointerRef, &auth->key) &&
			ndr_read_KERB_ASN1_DATA(ctx, s, drep, &auth->plainAuthData);
}


