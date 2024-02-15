/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Authentication redirection virtual channel
 *
 * Copyright 2024 David Fort <contact@hardening-consulting.com>
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
#include <winpr/collections.h>
#include <freerdp/log.h>

#include "ndr.h"

#define TAG FREERDP_TAG("ndr")

#define NDR_MAX_CONSTRUCTS 16
#define NDR_MAX_DEFERRED 50



/** @brief */
struct NdrContext_s
{
	BYTE version;
	BOOL bigEndianDrep;
	size_t alignBytes;

	int currentLevel;
	size_t indentLevels[16];

	int constructLevel;
	size_t constructs[NDR_MAX_CONSTRUCTS];

	wHashTable* refPointers;
	size_t ndeferred;
	NdrDeferredEntry deferred[NDR_MAX_DEFERRED];
};

NdrContext* ndr_context_new(BOOL bigEndianDrep, BYTE version)
{
	NdrContext* ret = calloc(1, sizeof(*ret));
	if (!ret)
		return NULL;

	ret->version = version;
	ret->bigEndianDrep = bigEndianDrep;
	ret->alignBytes = 4;
	ret->refPointers = HashTable_New(FALSE);
	if (!ret->refPointers)
	{
		free(ret);
		return NULL;
	}

	ndr_context_reset(ret);
	return ret;
}

void ndr_context_reset(NdrContext* context)
{
	WINPR_ASSERT(context);

	context->currentLevel = 0;
	context->constructLevel = -1;

	if (context->refPointers)
		HashTable_Clear(context->refPointers);
	context->ndeferred = 0;
}

NdrContext* ndr_context_copy(const NdrContext* src)
{
	NdrContext* ret = calloc(1, sizeof(*ret));
	if (!ret)
		return NULL;

	*ret = *src;

	ret->refPointers = HashTable_New(FALSE);
	if (!ret->refPointers)
	{
		free(ret);
		return NULL;
	}

	ndr_context_reset(ret);
	return ret;
}

void ndr_context_destroy(NdrContext** pcontext)
{
	WINPR_ASSERT(pcontext);

	NdrContext* context = *pcontext;
	if (context)
	{
		HashTable_Free(context->refPointers);
		free(context);
	}
	*pcontext = NULL;
}

void ndr_context_bytes_read(NdrContext* context, size_t len)
{
	context->indentLevels[context->currentLevel] += len;
}

void ndr_context_bytes_written(NdrContext* context, size_t len)
{
	ndr_context_bytes_read(context, len);
}

NdrContext* ndr_read_header(wStream* s)
{
	if (!Stream_CheckAndLogRequiredLength(TAG, s, 8))
		return NULL;

	BYTE version, drep;
	Stream_Read_UINT8(s, version);
	Stream_Read_UINT8(s, drep);

	UINT16 headerLen;
	Stream_Read_UINT16(s, headerLen);

	if (headerLen < 4 || !Stream_CheckAndLogRequiredLength(TAG, s, headerLen - 4))
		return NULL;

	/* skip filler */
	Stream_Seek(s, headerLen - 4);

	return ndr_context_new((drep != 0x10), version);
}

BOOL ndr_write_header(NdrContext* context, wStream* s)
{
	if (!Stream_EnsureRemainingCapacity(s, 8))
		return FALSE;

	Stream_Write_UINT8(s, context->version);
	Stream_Write_UINT8(s, context->bigEndianDrep ? 0x00 : 0x10);
	Stream_Write_UINT16(s, 0x8); /* header len */

	BYTE filler[] = { 0xcc, 0xcc, 0xcc, 0xcc };
	Stream_Write(s, filler, sizeof(filler));
	return TRUE;
}

BOOL ndr_read_align(NdrContext* context, wStream* s)
{
	size_t rest = context->indentLevels[context->currentLevel] % context->alignBytes;
	if (rest)
	{
		size_t padding = (context->alignBytes - rest);
		if (!Stream_CheckAndLogRequiredLength(TAG, s, padding))
			return FALSE;

		Stream_Seek(s, padding);
		context->indentLevels[context->currentLevel] += padding;
	}

	return TRUE;
}

BOOL ndr_write_align(NdrContext* context, wStream* s)
{
	size_t rest = context->indentLevels[context->currentLevel] % context->alignBytes;
	if (rest)
	{
		size_t padding = (context->alignBytes - rest);

		if (!Stream_EnsureRemainingCapacity(s, padding))
			return FALSE;

		Stream_Zero(s, padding);
		context->indentLevels[context->currentLevel] += padding;
	}

	return TRUE;
}

BOOL ndr_read_pickle(NdrContext* context, wStream* s)
{
	UINT32 v;

	/* NDR format label */
	if (!ndr_read_uint32(context, s, &v) || v != 0x20000)
		return FALSE;

	return ndr_read_uint32(context, s, &v); // padding
}

BOOL ndr_write_pickle(NdrContext* context, wStream* s)
{
	/* NDR format label */
	if (!ndr_write_uint32(context, s, 0x20000))
		return FALSE;

	ndr_write_uint32_(context, s, 0); /* padding */
	return TRUE;
}

BOOL ndr_read_constructed(NdrContext* context, wStream* s, wStream* target)
{
	UINT32 len;

	/* len */
	if (!ndr_read_uint32(context, s, &len))
		return FALSE;

	/* padding */
	if (!ndr_read_align(context, s))
		return FALSE;

	/* payload */
	if (!Stream_CheckAndLogRequiredLength(TAG, s, len))
		return FALSE;

	Stream_StaticInit(target, Stream_PointerAs(s, BYTE), len);
	Stream_Seek(s, len);
	return TRUE;
}

BOOL ndr_start_constructed(NdrContext* context, wStream* s)
{
	if (!Stream_EnsureCapacity(s, 8))
		return FALSE;

	if (context->constructLevel == NDR_MAX_CONSTRUCTS)
		return FALSE;

	context->constructLevel++;
	context->constructs[context->constructLevel] = Stream_GetPosition(s);

	Stream_Zero(s, 8);
	return TRUE;
}

BOOL ndr_end_constructed(NdrContext* context, wStream* target)
{
	WINPR_ASSERT(context->constructLevel >= 0);

	size_t offset = context->constructs[context->constructLevel];

	wStream staticS;
	Stream_StaticInit(&staticS, Stream_Buffer(target) + offset, 4);

	/* len */
	size_t len = Stream_GetPosition(target) - (offset + 8);
	if (!ndr_write_uint32(context, &staticS, len))
		return FALSE;

	return TRUE;
}


void Stream_Write_UINT64_BE(wStream* _s, UINT64 _v)
{
	WINPR_ASSERT(FALSE && "implement Stream_Write_UINT64_BE()");
}


BOOL ndr_read_uint8(NdrContext* context, wStream* s, BYTE * v)
{
	WINPR_ASSERT(context);

	if (!Stream_CheckAndLogRequiredLength(TAG, s, 1))
		return FALSE;

	Stream_Read_UINT8(s, *v);

	ndr_context_bytes_read(context, 1);
	return TRUE;
}

BOOL ndr_read_uint8_(NdrContext* context, wStream* s, void *hints, void* v)
{
	return ndr_read_uint8(context, s, (BYTE*)v);
}

BOOL ndr_write_uint8(NdrContext* context, wStream* s, BYTE v)
{
	if (!Stream_EnsureRemainingCapacity(s, 1))
		return FALSE;

	Stream_Write_UINT8(s, v);
	ndr_context_bytes_written(context, 1);
	return TRUE;
}

BOOL ndr_write_uint8_(NdrContext* context, wStream* s, const BYTE *v)
{
	WINPR_ASSERT(context);
	WINPR_ASSERT(s);
	WINPR_ASSERT(v);

	return ndr_write_uint8(context, s, *v);
}

static NdrMessageDescr uint8_descr = {
	1,
	(NDR_READER_FN)ndr_read_uint8_,
	(NDR_WRITER_FN)ndr_write_uint8_,
	(NDR_DESTROY_FN)NULL
};

NdrMessageType ndr_uint8_descr()
{
	return &uint8_descr;
}


#define SIMPLE_TYPE_IMPL(UPPERTYPE, LOWERTYPE) \
		BOOL ndr_read_##LOWERTYPE(NdrContext* context, wStream* s, UPPERTYPE* v) \
		{ \
			WINPR_ASSERT(context); \
			\
			if (!Stream_CheckAndLogRequiredLength(TAG, s, sizeof(UPPERTYPE))) \
				return FALSE; \
			\
			if (context->bigEndianDrep) \
				Stream_Read_##UPPERTYPE##_BE(s, *v); \
			else \
				Stream_Read_##UPPERTYPE(s, *v); \
			\
			ndr_context_bytes_read(context, sizeof(UPPERTYPE)); \
			return TRUE; \
		} \
		\
		BOOL ndr_read_##LOWERTYPE##_(NdrContext* context, wStream* s, void *hints, void* v) { \
			return ndr_read_##LOWERTYPE(context, s, (UPPERTYPE*)v); \
		} \
		\
		BOOL ndr_write_##LOWERTYPE(NdrContext* context, wStream* s, UPPERTYPE v) \
		{ \
			if (!Stream_EnsureRemainingCapacity(s, sizeof(UPPERTYPE))) \
				return FALSE; \
			\
			if (context->bigEndianDrep) \
				Stream_Write_##UPPERTYPE##_BE(s, v); \
			else \
				Stream_Write_UINT32(s, v); \
			\
			ndr_context_bytes_written(context, sizeof(UPPERTYPE)); \
			return TRUE; \
		} \
		\
		BOOL ndr_write_##LOWERTYPE##_(NdrContext* context, wStream* s, const UPPERTYPE *v) \
		{ \
			WINPR_ASSERT(context); \
			WINPR_ASSERT(s); \
			WINPR_ASSERT(v); \
			\
			return ndr_write_##LOWERTYPE(context, s, *v); \
		} \
		\
		static NdrMessageDescr LOWERTYPE##_descr = { \
			sizeof(UPPERTYPE), \
			(NDR_READER_FN)ndr_read_##LOWERTYPE##_, \
			(NDR_WRITER_FN)ndr_write_##LOWERTYPE##_, \
			(NDR_DESTROY_FN)NULL \
		}; \
		\
		NdrMessageType ndr_##LOWERTYPE##_descr() \
		{ \
			return &LOWERTYPE##_descr; \
		}


SIMPLE_TYPE_IMPL(UINT32, uint32)
SIMPLE_TYPE_IMPL(UINT16, uint16)
SIMPLE_TYPE_IMPL(UINT64, uint64)

#define ARRAY_OF_TYPE_IMPL(TYPE, UPPERTYPE) \
		BOOL ndr_read_##TYPE##Array(NdrContext* context, wStream* s, void *hints, void* v) \
		{ \
			WINPR_ASSERT(context); \
			NdrArrayHints *ahints = (NdrArrayHints *)hints; \
			return ndr_read_uconformant_array(context, s, ahints->count, ndr_##TYPE##_descr(), (void**)v); \
		} \
		\
		static NdrMessageDescr TYPE##Array_descr = { \
			sizeof(UPPERTYPE*), \
			(NDR_READER_FN)ndr_read_##TYPE##Array, \
			(NDR_WRITER_FN)/*ndr_write_##TYPE##Array*/NULL, \
			(NDR_DESTROY_FN)NULL \
		}; \
		\
		NdrMessageType ndr_##TYPE##Array_descr() \
		{ \
			return &TYPE##Array_descr; \
		} \
		BOOL ndr_read_##TYPE##VaryingArray(NdrContext* context, wStream* s, void *hints, void* v) \
		{ \
			WINPR_ASSERT(context); \
			NdrVaryingArrayHints *ahints = (NdrVaryingArrayHints *)hints; \
			return ndr_read_uconformant_varying_array(context, s, ahints->length, ahints->maxLength, ndr_##TYPE##_descr(), (void**)v); \
		} \
		\
		static NdrMessageDescr TYPE##VaryingArray_descr = { \
			sizeof(UPPERTYPE*), \
			(NDR_READER_FN)ndr_read_##TYPE##VaryingArray, \
			(NDR_WRITER_FN)/*ndr_write_##TYPE##VaryingArray*/NULL, \
			(NDR_DESTROY_FN)NULL \
		}; \
		\
		NdrMessageType ndr_##TYPE##VaryingArray_descr() \
		{ \
			return &TYPE##VaryingArray_descr; \
		}


ARRAY_OF_TYPE_IMPL(uint8, BYTE)
ARRAY_OF_TYPE_IMPL(uint16, UINT16)

BOOL ndr_read_wchar(NdrContext* context, wStream* s, WCHAR* ptr)
{
	return ndr_read_uint16(context, s, (UINT16*)ptr);
}

BOOL ndr_read_uconformant_varying_array(NdrContext* context, wStream* s, UINT32 lenHint,
                                        UINT32 maxHint, NdrMessageType itemType,
                                        void** ptarget)
{
	WINPR_ASSERT(context);
	WINPR_ASSERT(s);

	UINT32 maxCount, offset, length;

	if (!ndr_read_uint32(context, s, &maxCount) || !ndr_read_uint32(context, s, &offset) ||
	    !ndr_read_uint32(context, s, &length))
		return FALSE;

	if ((length * itemType->itemSize) < lenHint)
		return FALSE;

	if ((maxCount * itemType->itemSize) < maxHint)
		return FALSE;

	BYTE* data = NULL;

	if (length)
	{
		BYTE* target;
		data = target = calloc(maxCount, itemType->itemSize);
		if (!target)
			return FALSE;

		for (UINT32 i = 0; i < length; i++, target += itemType->itemSize)
		{
			if (!itemType->readFn(context, s, NULL, target))
			{
				free(data);
				*ptarget = NULL;
				return FALSE;
			}
		}
	}

	*ptarget = data;
	return ndr_read_align(context, s);;
}



BOOL ndr_read_uconformant_array(NdrContext* context, wStream* s, UINT32 countHint, NdrMessageType itemType, void** ptarget)
{
	WINPR_ASSERT(context);
	WINPR_ASSERT(s);
	WINPR_ASSERT(itemType);
	WINPR_ASSERT(ptarget);

	UINT32 count;

	if (!ndr_read_uint32(context, s, &count))
		return FALSE;

	if ((count * itemType->itemSize < countHint))
		return FALSE;

	*ptarget = NULL;
	BYTE* data = NULL;
	if (count)
	{
		BYTE* target;
		target = data = (BYTE*)calloc(count, itemType->itemSize);
		if (!data)
			return FALSE;

		for (UINT32 i = 0; i < count; i++, target += itemType->itemSize)
		{
			if (!itemType->readFn(context, s, NULL, data))
				return FALSE;
		}
	}

	*ptarget = data;
	return ndr_read_align(context, s);
}


BOOL ndr_write_uconformant_array(NdrContext* context, wStream* s, const BYTE* ptr, UINT32 len)
{
	if (!ndr_write_uint32(context, s, len) || !Stream_EnsureRemainingCapacity(s, len))
		return FALSE;

	Stream_Write(s, ptr, len);
	return TRUE;
}


ndr_refid ndr_pointer_refid(const void* ptr)
{
	return (ndr_refid)((ULONG_PTR)ptr);
}

BOOL ndr_read_refpointer(NdrContext* context, wStream* s, ndr_refid* refId)
{
	return ndr_read_uint32(context, s, refId);
}


BOOL ndr_read_pointedMessageEx(NdrContext* context, wStream* s, ndr_refid ptrId, NdrMessageType descr, void *hints, void **target)
{
	WINPR_ASSERT(context);
	WINPR_ASSERT(s);
	WINPR_ASSERT(descr);
	WINPR_ASSERT(target);

	*target = NULL;
	if (!ptrId) {
		UINT32 v;
		return ndr_read_uint32(context, s, &v);
	}

	void* ret = HashTable_GetItemValue(context->refPointers, (void*)(UINT_PTR)ptrId);
	if (!ret)
	{
		ret = calloc(1, descr->itemSize);
		if (!ret)
			return FALSE;

		if (!descr->readFn(context, s, hints, ret) ||
			!HashTable_Insert(context->refPointers, (void*)(UINT_PTR)ptrId, ret))
		{
			if (descr->destroyFn)
				descr->destroyFn(context, ret);
			free(ret);
			return FALSE;
		}
	}

	*target = ret;
	return TRUE;
}

BOOL ndr_push_deferreds(NdrContext* context, NdrDeferredEntry *deferreds, size_t ndeferred)
{
	WINPR_ASSERT(context);
	WINPR_ASSERT(deferreds);
	WINPR_ASSERT(ndeferred);

	if (context->ndeferred + ndeferred > NDR_MAX_DEFERRED)
	{
		WLog_ERR(TAG, "too many deferred");
		return FALSE;
	}

	for (size_t i = ndeferred; i > 0; i--, context->ndeferred++)
	{
		context->deferred[context->ndeferred] = deferreds[i-1];
	}
	return TRUE;
}

BOOL ndr_treat_deferred(NdrContext* context, wStream* s)
{
	WINPR_ASSERT(context);
	WINPR_ASSERT(s);

	while (context->ndeferred)
	{
		NdrDeferredEntry current = context->deferred[context->ndeferred - 1];
		context->ndeferred--;

		WLog_VRB(TAG, "treating deferred for %s", current.name);
		if (!ndr_read_pointedMessageEx(context, s, current.ptrId, current.msg, current.hints, current.target))
		{
			WLog_ERR(TAG, "error parsing deferred %s", current.name);
			return FALSE;
		}
	}

	return TRUE;
}
