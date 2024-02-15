/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Authentication redirection virtual channel
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

#include <winpr/assert.h>

#include <winpr/crt.h>
#include <winpr/wlog.h>
#include <winpr/print.h>
#include <winpr/asn1.h>
#include <winpr/sspi.h>
#include <winpr/collections.h>

#include "../rdpear_common.h"
#include "../ndr.h"

#include <freerdp/config.h>
#include <freerdp/freerdp.h>
#include <freerdp/addin.h>
#include <freerdp/client/channels.h>
#include <freerdp/channels/log.h>
#include <freerdp/channels/rdpear.h>

#define TAG CHANNELS_TAG("rdpear.client")

typedef struct
{
	GENERIC_DYNVC_PLUGIN base;
	rdpContext* rdp_context;
} RDPEAR_PLUGIN;

const BYTE payloadHeader[16] = { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

static BOOL rdpear_send_payload(RDPEAR_PLUGIN* rdpear, IWTSVirtualChannelCallback* pChannelCallback,
                                RdpEarPackageType packageType, wStream* payload)
{
	GENERIC_CHANNEL_CALLBACK* callback = (GENERIC_CHANNEL_CALLBACK*)pChannelCallback;
	BOOL ret = FALSE;
	wStream* unencodedContent = rdpear_encodePayload(packageType, payload);
	if (!unencodedContent)
		goto out;

	size_t unencodedLen = Stream_GetPosition(unencodedContent);
	SecBuffer inBuffer = { unencodedLen, SECBUFFER_DATA, Stream_Buffer(unencodedContent) };
	SecBuffer cryptedBuffer = { 0 };

	if (!freerdp_nla_encrypt(rdpear->rdp_context, &inBuffer, &cryptedBuffer))
		goto out;

	wStream* finalStream = Stream_New(NULL, 200);
	Stream_Write_UINT32(finalStream, 0x4EACC3C8);             /* ProtocolMagic (4 bytes) */
	Stream_Write_UINT32(finalStream, cryptedBuffer.cbBuffer); /* Length (4 bytes) */
	Stream_Write_UINT32(finalStream, 0x00000000);             /* Version (4 bytes) */
	Stream_Write_UINT32(finalStream, 0x00000000);             /* Reserved (4 bytes) */
	Stream_Write_UINT64(finalStream, 0);                      /* TsPkgContext (8 bytes) */

	/* payload */
	if (!Stream_EnsureRemainingCapacity(finalStream, cryptedBuffer.cbBuffer))
		goto out;

	Stream_Write(finalStream, cryptedBuffer.pvBuffer, cryptedBuffer.cbBuffer);

	ret = callback->channel->Write(callback->channel, Stream_GetPosition(finalStream),
	                                   Stream_Buffer(finalStream), NULL) == CHANNEL_RC_OK;
out:
	Stream_Free(unencodedContent, TRUE);
	return ret;
}

static BOOL rdpear_prepare_response(NdrContext* rcontext, UINT16 callId, UINT32 status,
                                    NdrContext** pwcontext, wStream** pRetStream)
{
	WINPR_ASSERT(rcontext);
	WINPR_ASSERT(pwcontext);
	WINPR_ASSERT(pRetStream);

	NdrContext* wcontext = ndr_context_copy(rcontext);
	if (!wcontext)
		return FALSE;

	wStream* retStream = Stream_New(NULL, 500);
	if (!retStream)
		goto out_stream;

	Stream_Write(retStream, payloadHeader, sizeof(payloadHeader));

	if (!ndr_write_header(wcontext, retStream) || !ndr_start_constructed(wcontext, retStream) ||
	    !ndr_write_pickle(wcontext, retStream) ||         /* pickle header */
	    !ndr_write_uint16(wcontext, retStream, callId) || /* callId */
	    !ndr_write_uint16(wcontext, retStream, 0x0000) || /* align padding */
	    !ndr_write_uint32(wcontext, retStream, status) || /* status */
	    !ndr_write_uint16(wcontext, retStream, callId) || /* callId */
	    !ndr_write_uint16(wcontext, retStream, 0x0000))   /* align padding */
		goto out_write;

	*pwcontext = wcontext;
	*pRetStream = retStream;
	return TRUE;

out_write:
	Stream_Free(retStream, TRUE);
out_stream:
	ndr_context_destroy(&wcontext);
	return FALSE;
}

static BOOL rdpear_kerb_version(RDPEAR_PLUGIN* rdpear, IWTSVirtualChannelCallback* pChannelCallback,
                                NdrContext* rcontext, wStream* s)
{
	UINT32 version;
	BOOL ret = FALSE;
	NdrContext* wcontext = NULL;
	wStream* retStream = NULL;

	WLog_DBG(TAG, "KerbNegotiateVersion=");
	winpr_HexDump(TAG, WLOG_DEBUG, Stream_Buffer(s), Stream_GetRemainingLength(s));

	if (!ndr_read_uint32(rcontext, s, &version))
		return FALSE;

	WLog_DBG(TAG, "KerbNegotiateVersion(v=0x%x)", version);

	if (!rdpear_prepare_response(rcontext, RemoteCallKerbNegotiateVersion, 0x0000, &wcontext,
	                             &retStream) ||
	    !ndr_write_uint32(wcontext, retStream, version) || /* version */
	    !ndr_end_constructed(wcontext, retStream))
		goto out;

	ret = rdpear_send_payload(rdpear, pChannelCallback, RDPEAR_PACKAGE_KERBEROS, retStream);
out:
	ndr_context_destroy(&wcontext);
	Stream_Free(retStream, TRUE);
	return ret;
}

static BOOL rdpear_kerb_ComputeTgsChecksum(RDPEAR_PLUGIN* rdpear,
                                           IWTSVirtualChannelCallback* pChannelCallback,
                                           NdrContext* rcontext, wStream* s)
{
	BOOL ret = FALSE;
	NdrContext* wcontext = NULL;
	wStream* retStream = NULL;
	ComputeTgsChecksumReq req = { 0 };
	BYTE checksumBuffer[64];
	SecPkgContext_ComputeTgsChecksum computeTgsChecksum = { 0 };

	WLog_DBG(TAG, "ComputeTgsChecksum=");
	winpr_HexDump(TAG, WLOG_DEBUG, Stream_Pointer(s), Stream_GetRemainingLength(s));

	if (!ndr_read_ComputeTgsChecksumReq(rcontext, s, &req))
		return FALSE;
	ComputeTgsChecksumReq_dump(WLog_Get(""), WLOG_DEBUG, &req);

	computeTgsChecksum.requestBody.data = req.requestBody->Asn1Buffer;
	computeTgsChecksum.requestBody.len = req.requestBody->Asn1BufferHints.count;
	computeTgsChecksum.key.encType = req.Key->reserved2;
	computeTgsChecksum.key.key = req.Key->reserved3.value;
	computeTgsChecksum.key.keyLen = req.Key->reserved3.length;
	computeTgsChecksum.checksumType = req.ChecksumType;
	computeTgsChecksum.checksum.data = checksumBuffer;
	computeTgsChecksum.checksum.len = sizeof(checksumBuffer);

	SECURITY_STATUS status = freerdp_nla_setKerbAttribute(
	    rdpear->rdp_context, SECPKG_CRED_ATTR_COMPUTE_TGS_CHECKSUM, &computeTgsChecksum);
	if (status != SEC_E_OK)
		goto out;

	wStream* asn1Payload = rdpear_enc_Checksum(7, &computeTgsChecksum.checksum);
	if (!asn1Payload)
		goto out;

	KERB_ASN1_DATA asn1;
	asn1.Pdu = 8;
	asn1.Asn1Buffer = Stream_Buffer(asn1Payload);
	asn1.Asn1BufferHints.count = Stream_GetPosition(asn1Payload);

	WLog_DBG(TAG, "checksum=");
	winpr_HexDump(TAG, WLOG_DEBUG, computeTgsChecksum.checksum.data,
	              computeTgsChecksum.checksum.len);

	if (!rdpear_prepare_response(rcontext, RemoteCallKerbComputeTgsChecksum, 0x0000, &wcontext,
	                             &retStream) ||
	    !ndr_write_KERB_ASN1_DATA(wcontext, retStream, &asn1) || /* Checksum */
	    !ndr_end_constructed(wcontext, retStream))
		goto out;

	ret = rdpear_send_payload(rdpear, pChannelCallback, RDPEAR_PACKAGE_KERBEROS, retStream);
out:
	ndr_context_destroy(&wcontext);
	Stream_Free(retStream, TRUE);
	return ret;
}

static BOOL rdpear_kerb_BuildAsReqAuthenticator(RDPEAR_PLUGIN* rdpear, IWTSVirtualChannelCallback* pChannelCallback,
	   NdrContext* rcontext, wStream* s)
{
	BOOL ret = FALSE;
	NdrContext* wcontext = NULL;
	wStream* retStream = NULL;
	CreateApReqAuthenticatorReq req = { 0 };
	//	SecPkgContext_ComputeTgsChecksum computeTgsChecksum = { 0 };

	WLog_DBG(TAG, "rdpear_kerb_BuildAsReqAuthenticator=");
	winpr_HexDump(TAG, WLOG_DEBUG, Stream_Pointer(s), Stream_GetRemainingLength(s));

	if (!ndr_read_CreateApReqAuthenticatorReq(rcontext, s, &req))
		return FALSE;


//out:
	ndr_context_destroy(&wcontext);
	Stream_Free(retStream, TRUE);
	return ret;
}

static BOOL rdpear_kerb_BuildEncryptedAuthData(RDPEAR_PLUGIN* rdpear,
                                               IWTSVirtualChannelCallback* pChannelCallback,
                                               NdrContext* rcontext, wStream* s)
{
	BOOL ret = FALSE;
	NdrContext* wcontext = NULL;
	wStream* retStream = NULL;
	BuildEncryptedAuthDataReq req = { 0 };
	SecPkgContext_KerbEncryptedLen encryptedLen;
	SecPkgContext_KerbBuildEncryptedAuthData kerbArgs = { 0 };

	if (!ndr_read_BuildEncryptedAuthDataReq(rcontext, s, &req))
		return FALSE;

	BuildEncryptedAuthDataReq_dump(WLog_Get(""), WLOG_DEBUG, &req);

	/* determine the output length */
	encryptedLen.encType = req.Key->reserved2;
	encryptedLen.plainLen = req.PlainAuthData->Asn1BufferHints.count;

	SECURITY_STATUS status = freerdp_nla_setKerbAttribute(
	    rdpear->rdp_context, SECPKG_CRED_ATTR_ENCRYPTED_LEN, &encryptedLen);
	if (status != SEC_E_OK)
		goto out;

	kerbArgs.keyUsage = req.KeyUsage;

	kerbArgs.key.encType = req.Key->reserved2;
	kerbArgs.key.key = req.Key->reserved3.value;
	kerbArgs.key.keyLen = req.Key->reserved3.length;

	kerbArgs.plain.data = req.PlainAuthData->Asn1Buffer;
	kerbArgs.plain.len = req.PlainAuthData->Asn1BufferHints.count;

	size_t allocLen = encryptedLen.encodedLen;
	kerbArgs.encrypted.data = (BYTE*)malloc(allocLen);
	if (!kerbArgs.encrypted.data)
		goto out;
	kerbArgs.encrypted.len = allocLen;

	status = freerdp_nla_setKerbAttribute(rdpear->rdp_context,
	                                      SECPKG_CRED_ATTR_BUILD_ENCRYPTED_AUTH_DATA, &kerbArgs);
	if (status != SEC_E_OK)
		goto out;

	/* do the encoding */
	wStream* asn1Payload = rdpear_enc_EncryptedData(kerbArgs.key.encType, &kerbArgs.encrypted);
	if (!asn1Payload)
		goto out;

	KERB_ASN1_DATA asn1;
	asn1.Pdu = 6;
	asn1.Asn1Buffer = Stream_Buffer(asn1Payload);
	asn1.Asn1BufferHints.count = Stream_GetPosition(asn1Payload);

	/*WLog_DBG(TAG, "encrypted=");
	winpr_HexDump(TAG, WLOG_DEBUG, kerbArgs.encrypted, kerbArgs.encryptedLen);*/

	if (!rdpear_prepare_response(rcontext, RemoteCallKerbBuildEncryptedAuthData, 0x0000, &wcontext,
	                             &retStream) ||
	    !ndr_write_KERB_ASN1_DATA(wcontext, retStream, &asn1) || /* EncryptedAuthData */
	    !ndr_end_constructed(wcontext, retStream))
		goto out;

	WLog_DBG(TAG, "response=");
	winpr_HexDump(TAG, WLOG_DEBUG, Stream_Buffer(retStream), Stream_GetPosition(retStream));

	ret = rdpear_send_payload(rdpear, pChannelCallback, RDPEAR_PACKAGE_KERBEROS, retStream);
out:
	// TODO: release req
	free(kerbArgs.encrypted.data);

	ndr_context_destroy(&wcontext);
	Stream_Free(retStream, TRUE);
	return ret;
}

static UINT rdpear_decode_payload(RDPEAR_PLUGIN* rdpear,
                                  IWTSVirtualChannelCallback* pChannelCallback,
                                  RdpEarPackageType packageType, wStream* s)
{
	UINT ret = ERROR_INVALID_DATA;
	NdrContext* context = NULL;

	if (!Stream_CheckAndLogRequiredLength(TAG, s, 16))
		goto out;
	Stream_Seek(s, 16); /* skip first 16 bytes */

	context = ndr_read_header(s);
	if (!context)
		goto out;

	wStream commandStream;
	if (!ndr_read_constructed(context, s, &commandStream))
		goto out;

	if (!ndr_read_pickle(context, &commandStream))
		goto out;

	UINT16 callId, callId2;
	if (!ndr_read_uint16(context, &commandStream, &callId))
		goto out;

	if (!ndr_read_uint16(context, &commandStream, &callId2) || (callId != callId2))
		goto out;

	ret = CHANNEL_RC_NOT_OPEN;
	switch (callId)
	{
		case RemoteCallKerbNegotiateVersion:
			if (rdpear_kerb_version(rdpear, pChannelCallback, context, &commandStream))
				ret = CHANNEL_RC_OK;
			break;
		case RemoteCallKerbBuildAsReqAuthenticator:
			if (rdpear_kerb_BuildAsReqAuthenticator(rdpear, pChannelCallback, context, &commandStream))
				ret = CHANNEL_RC_OK;
			break;

		case RemoteCallKerbComputeTgsChecksum:
			if (rdpear_kerb_ComputeTgsChecksum(rdpear, pChannelCallback, context, &commandStream))
				ret = CHANNEL_RC_OK;
			break;
		case RemoteCallKerbBuildEncryptedAuthData:
			if (rdpear_kerb_BuildEncryptedAuthData(rdpear, pChannelCallback, context,
			                                       &commandStream))
				ret = CHANNEL_RC_OK;
			break;

		case RemoteCallNtlmNegotiateVersion:
			WLog_ERR(TAG, "don't wanna support NTLM");
			break;
		default:
			WLog_DBG(TAG, "Unhandled callId=0x%x", callId);
			winpr_HexDump(TAG, WLOG_DEBUG, Stream_PointerAs(&commandStream, BYTE),
			              Stream_GetRemainingLength(&commandStream));
			break;
	}

out:
	return ret;
}

static UINT rdpear_on_data_received(IWTSVirtualChannelCallback* pChannelCallback, wStream* s)
{
	GENERIC_CHANNEL_CALLBACK* callback = (GENERIC_CHANNEL_CALLBACK*)pChannelCallback;
	WINPR_ASSERT(callback);
	UINT ret = ERROR_INVALID_DATA;

	// winpr_HexDump(TAG, WLOG_DEBUG, Stream_PointerAs(s, BYTE), Stream_GetRemainingLength(s));

	if (!Stream_CheckAndLogRequiredLength(TAG, s, 24))
		return ERROR_INVALID_DATA;

	UINT32 protocolMagic, Length, Version;
	Stream_Read_UINT32(s, protocolMagic);
	if (protocolMagic != 0x4EACC3C8)
		return ERROR_INVALID_DATA;

	Stream_Read_UINT32(s, Length);

	Stream_Read_UINT32(s, Version);
	if (Version != 0x00000000)
		return ERROR_INVALID_DATA;

	Stream_Seek(s, 4); /* Reserved (4 bytes) */
	Stream_Seek(s, 8); /* TsPkgContext (8 bytes) */

	if (!Stream_CheckAndLogRequiredLength(TAG, s, Length))
		return ERROR_INVALID_DATA;

	SecBuffer inBuffer = { Length, SECBUFFER_TOKEN, Stream_PointerAs(s, void*) };
	SecBuffer decrypted;
	decrypted.BufferType = SECBUFFER_DATA;
	if (!sspi_SecBufferAlloc(&decrypted, Length))
		return CHANNEL_RC_NO_MEMORY;

	RDPEAR_PLUGIN* rdpear = (RDPEAR_PLUGIN*)callback->plugin;
	WINPR_ASSERT(rdpear);
	if (!freerdp_nla_decrypt(rdpear->rdp_context, &inBuffer, &decrypted))
		goto out;

	WinPrAsn1Decoder dec, dec2;
	wStream decodedStream;
	Stream_StaticInit(&decodedStream, decrypted.pvBuffer, decrypted.cbBuffer);
	WinPrAsn1Decoder_Init(&dec, WINPR_ASN1_DER, &decodedStream);

	if (!WinPrAsn1DecReadSequence(&dec, &dec2))
		goto out;

	WinPrAsn1_OctetString packageName;
	WinPrAsn1_OctetString payload;
	BOOL error;
	if (!WinPrAsn1DecReadContextualOctetString(&dec2, 1, &error, &packageName, FALSE))
		goto out;

	RdpEarPackageType packageType = rdpear_packageType_from_name(&packageName);

	if (!WinPrAsn1DecReadContextualOctetString(&dec2, 2, &error, &payload, FALSE))
		goto out;

	wStream payloadStream;
	Stream_StaticInit(&payloadStream, payload.data, payload.len);

	ret = rdpear_decode_payload(rdpear, pChannelCallback, packageType, &payloadStream);
out:
	sspi_SecBufferFree(&decrypted);
	return ret;
}

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
static UINT rdpear_on_open(IWTSVirtualChannelCallback* pChannelCallback)
{

	return CHANNEL_RC_OK;
}

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
static UINT rdpear_on_close(IWTSVirtualChannelCallback* pChannelCallback)
{
	UINT error = CHANNEL_RC_OK;
	return error;
}

static void terminate_plugin_cb(GENERIC_DYNVC_PLUGIN* base)
{
}

#if 0
static void OnFirstFrame(void* context, const FirstGraphicFrameEventArgs* e)
{
	WLog_DBG(TAG, "first frame I shall send my packet...");
	GENERIC_CHANNEL_CALLBACK* callback = g_callback;

	WINPR_ASSERT(callback);
	BYTE message[0x12];
	wStream staticStream;
	wStream *s = Stream_StaticInit(&staticStream, message, sizeof(message));

	Stream_Write_UINT8(s, 0x01); /* Id */
	Stream_Write_UINT8(s, 0x12); /* Length */
	Stream_Write_UINT32(s, 0x00000000); /* PromptForCredentialsMillis */
	Stream_Write_UINT32(s, 0x00000000); /* PromptForCredentialsDoneMillis */
	Stream_Write_UINT32(s, 0x00000100); /* GraphicsChannelOpenedMillis */
	Stream_Write_UINT32(s, 0x00000100); /* FirstGraphicsReceivedMillis */

	callback->channel->Write(callback->channel, (UINT32)Stream_GetPosition(s), Stream_Buffer(s), NULL);
}
#endif

static UINT init_plugin_cb(GENERIC_DYNVC_PLUGIN* base, rdpContext* rcontext, rdpSettings* settings)
{
	WINPR_ASSERT(base);

	RDPEAR_PLUGIN* rdpear = (RDPEAR_PLUGIN*)base;
	rdpear->rdp_context = rcontext;
	return CHANNEL_RC_OK;
}

static const IWTSVirtualChannelCallback telemetry_callbacks = { rdpear_on_data_received,
	                                                            rdpear_on_open, rdpear_on_close };

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
FREERDP_ENTRY_POINT(UINT rdpear_DVCPluginEntry(IDRDYNVC_ENTRY_POINTS* pEntryPoints))
{
	return freerdp_generic_DVCPluginEntry(pEntryPoints, TAG, RDPEAR_DVC_CHANNEL_NAME,
	                                      sizeof(RDPEAR_PLUGIN), sizeof(GENERIC_CHANNEL_CALLBACK),
	                                      &telemetry_callbacks, init_plugin_cb,
	                                      terminate_plugin_cb);
}
