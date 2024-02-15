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
#include <winpr/wlog.h>

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

	UINT32 refIdCounter;
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
	memset(context->indentLevels, 0, sizeof(context->indentLevels));

	if (context->refPointers)
		HashTable_Clear(context->refPointers);
	context->ndeferred = 0;
	context->refIdCounter = 0x20000;
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
BOOL ndr_skip_bytes(NdrContext* context, wStream* s, size_t nbytes)
{
	if (!Stream_CheckAndLogRequiredLength(TAG, s, nbytes))
		return FALSE;

	context->indentLevels[context->currentLevel] += nbytes;
	Stream_Seek(s, nbytes);
	return TRUE;
}

BOOL ndr_read_align(NdrContext* context, wStream* s, size_t sz)
{
	size_t rest = context->indentLevels[context->currentLevel] % sz;
	if (rest)
	{
		size_t padding = (sz - rest);
		if (!Stream_CheckAndLogRequiredLength(TAG, s, padding))
			return FALSE;

		Stream_Seek(s, padding);
		context->indentLevels[context->currentLevel] += padding;
	}

	return TRUE;
}

BOOL ndr_write_align(NdrContext* context, wStream* s, size_t sz)
{
	size_t rest = context->indentLevels[context->currentLevel] % sz;
	if (rest)
	{
		size_t padding = (sz - rest);

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

	ndr_write_uint32(context, s, 0); /* padding */
	return TRUE;
}

BOOL ndr_read_constructed(NdrContext* context, wStream* s, wStream* target)
{
	UINT32 len;

	/* len */
	if (!ndr_read_uint32(context, s, &len))
		return FALSE;

	/* padding */
	if (!ndr_skip_bytes(context, s, 4))
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


static size_t ndr_hintsCount(NdrMessageType msgType, const void *hints)
{
	WINPR_ASSERT(msgType);

	switch (msgType->arity) {
	case NDR_ARITY_SIMPLE:
		return 1;
	case NDR_ARITY_ARRAYOF:
		return ((const NdrArrayHints*)hints)->count;
	case NDR_ARITY_VARYING_ARRAYOF:
		return ((const NdrVaryingArrayHints*)hints)->maxLength;
	default:
		WINPR_ASSERT(0 && "unknown arity");
		return 0;
	}
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

BOOL ndr_read_uint8_(NdrContext* context, wStream* s, const void *hints, void* v)
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

BOOL ndr_write_uint8_(NdrContext* context, wStream* s, const void *hints, const void *v)
{
	WINPR_ASSERT(context);
	WINPR_ASSERT(s);
	WINPR_ASSERT(v);

	return ndr_write_uint8(context, s, *(const BYTE *)v);
}

const NdrMessageDescr uint8_descr = {
	NDR_ARITY_SIMPLE,
	1,
	ndr_read_uint8_,
	ndr_write_uint8_,
	NULL
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
			if (!ndr_read_align(context, s, sizeof(UPPERTYPE))) \
					return FALSE; \
			\
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
		BOOL ndr_read_##LOWERTYPE##_(NdrContext* context, wStream* s, const void *hints, void* v) { \
			return ndr_read_##LOWERTYPE(context, s, (UPPERTYPE*)v); \
		} \
		\
		BOOL ndr_write_##LOWERTYPE(NdrContext* context, wStream* s, UPPERTYPE v) \
		{ \
			if (!ndr_write_align(context, s, sizeof(UPPERTYPE)) || !Stream_EnsureRemainingCapacity(s, sizeof(UPPERTYPE))) \
				return FALSE; \
			\
			if (context->bigEndianDrep) \
				Stream_Write_##UPPERTYPE##_BE(s, v); \
			else \
				Stream_Write_##UPPERTYPE(s, v); \
			\
			ndr_context_bytes_written(context, sizeof(UPPERTYPE)); \
			return TRUE; \
		} \
		\
		BOOL ndr_write_##LOWERTYPE##_(NdrContext* context, wStream* s, const void *hints, const void *v) \
		{ \
			WINPR_ASSERT(context); \
			WINPR_ASSERT(s); \
			WINPR_ASSERT(v); \
			\
			return ndr_write_##LOWERTYPE(context, s, *(const UPPERTYPE *)v); \
		} \
		\
		const NdrMessageDescr ndr_##LOWERTYPE##_descr_s = { \
			NDR_ARITY_SIMPLE, \
			sizeof(UPPERTYPE), \
			ndr_read_##LOWERTYPE##_, \
			ndr_write_##LOWERTYPE##_, \
			(NDR_DESTROY_FN)NULL \
		}; \
		\
		NdrMessageType ndr_##LOWERTYPE##_descr() \
		{ \
			return &ndr_##LOWERTYPE##_descr_s; \
		}


SIMPLE_TYPE_IMPL(UINT32, uint32)
SIMPLE_TYPE_IMPL(UINT16, uint16)
SIMPLE_TYPE_IMPL(UINT64, uint64)

#define ARRAY_OF_TYPE_IMPL(TYPE, UPPERTYPE) \
		BOOL ndr_read_##TYPE##Array(NdrContext* context, wStream* s, const void *hints, void* v) \
		{ \
			WINPR_ASSERT(context); \
			WINPR_ASSERT(s); \
			WINPR_ASSERT(hints); \
			return ndr_read_uconformant_array(context, s, (NdrArrayHints *)hints, ndr_##TYPE##_descr(), (void*)v); \
		} \
		\
		BOOL ndr_write_##TYPE##Array(NdrContext* context, wStream* s, const void *hints, const void* v) \
		{ \
			WINPR_ASSERT(context); \
			WINPR_ASSERT(s); \
			NdrArrayHints *ahints = (NdrArrayHints *)hints; \
			return ndr_write_uconformant_array(context, s, ahints->count, ndr_##TYPE##_descr(), (const void *)v); \
		} \
		\
		const NdrMessageDescr ndr_##TYPE##Array_descr_s = { \
			NDR_ARITY_ARRAYOF, \
			sizeof(UPPERTYPE), \
			ndr_read_##TYPE##Array, \
			ndr_write_##TYPE##Array, \
			(NDR_DESTROY_FN)NULL \
		}; \
		\
		NdrMessageType ndr_##TYPE##Array_descr() \
		{ \
			return &ndr_##TYPE##Array_descr_s; \
		} \
		\
		BOOL ndr_read_##TYPE##VaryingArray(NdrContext* context, wStream* s, const void *hints, void* v) \
		{ \
			WINPR_ASSERT(context); \
			WINPR_ASSERT(s); \
			WINPR_ASSERT(hints); \
			return ndr_read_uconformant_varying_array(context, s, (NdrVaryingArrayHints *)hints, ndr_##TYPE##_descr(), v); \
		} \
		BOOL ndr_write_##TYPE##VaryingArray(NdrContext* context, wStream* s, const void *hints, const void* v) \
		{ \
			WINPR_ASSERT(context); \
			WINPR_ASSERT(s); \
			WINPR_ASSERT(hints); \
			return ndr_write_uconformant_varying_array(context, s, (NdrVaryingArrayHints *)hints, ndr_##TYPE##_descr(), v); \
		} \
		\
		const NdrMessageDescr ndr_##TYPE##VaryingArray_descr_s = { \
			NDR_ARITY_VARYING_ARRAYOF, \
			sizeof(UPPERTYPE), \
			ndr_read_##TYPE##VaryingArray, \
			ndr_write_##TYPE##VaryingArray, \
			(NDR_DESTROY_FN)NULL \
		}; \
		\
		NdrMessageType ndr_##TYPE##VaryingArray_descr() \
		{ \
			return &ndr_##TYPE##VaryingArray_descr_s; \
		}


ARRAY_OF_TYPE_IMPL(uint8, BYTE)
ARRAY_OF_TYPE_IMPL(uint16, UINT16)

BOOL ndr_read_wchar(NdrContext* context, wStream* s, WCHAR* ptr)
{
	return ndr_read_uint16(context, s, (UINT16*)ptr);
}

BOOL ndr_read_uconformant_varying_array(NdrContext* context, wStream* s, const NdrVaryingArrayHints *hints, NdrMessageType itemType,
                                        void* ptarget)
{
	WINPR_ASSERT(context);
	WINPR_ASSERT(s);
	WINPR_ASSERT(hints);
	WINPR_ASSERT(ptarget);

	UINT32 maxCount, offset, length;

	if (!ndr_read_uint32(context, s, &maxCount) || !ndr_read_uint32(context, s, &offset) ||
	    !ndr_read_uint32(context, s, &length))
		return FALSE;

	if ((length * itemType->itemSize) < hints->length)
		return FALSE;

	if ((maxCount * itemType->itemSize) < hints->maxLength)
		return FALSE;

	BYTE *target = (BYTE *)ptarget;
	for (UINT32 i = 0; i < length; i++, target += itemType->itemSize)
	{
		if (!itemType->readFn(context, s, NULL, target))
			return FALSE;
	}

	return ndr_read_align(context, s, 4);
}

BOOL ndr_write_uconformant_varying_array(NdrContext* context, wStream* s, const NdrVaryingArrayHints *hints, NdrMessageType itemType,
                                        const void* psrc)
{
	WINPR_ASSERT(context);
	WINPR_ASSERT(s);
	WINPR_ASSERT(hints);
	WINPR_ASSERT(psrc);

	if (!ndr_write_uint32(context, s, hints->maxLength) || !ndr_write_uint32(context, s, 0) ||
	    !ndr_write_uint32(context, s, hints->length))
		return FALSE;

	const BYTE *src = (const BYTE *)psrc;
	for (UINT32 i = 0; i < hints->length; i++, src += itemType->itemSize)
	{
		if (!itemType->writeFn(context, s, NULL, src))
			return FALSE;
	}

	return TRUE;
}



BOOL ndr_read_uconformant_array(NdrContext* context, wStream* s, const NdrArrayHints *hints, NdrMessageType itemType, void* vtarget)
{
	WINPR_ASSERT(context);
	WINPR_ASSERT(s);
	WINPR_ASSERT(itemType);
	WINPR_ASSERT(vtarget);

	UINT32 count;

	if (!ndr_read_uint32(context, s, &count))
		return FALSE;

	if ((count * itemType->itemSize < hints->count))
		return FALSE;

	BYTE *target = (BYTE *)vtarget;
	for (UINT32 i = 0; i < count; i++, target += itemType->itemSize)
	{
		if (!itemType->readFn(context, s, NULL, target))
			return FALSE;
	}

	return ndr_read_align(context, s, /*context->alignBytes*/4);
}


BOOL ndr_write_uconformant_array(NdrContext* context, wStream* s, UINT32 len, NdrMessageType itemType, const BYTE* ptr)
{
	if (!ndr_write_uint32(context, s, len) || !Stream_EnsureRemainingCapacity(s, len * itemType->itemSize))
		return FALSE;

	for (UINT32 i = 0; i < len; i++, ptr += itemType->itemSize)
	{
		if (!itemType->writeFn(context, s, NULL, ptr))
			return FALSE;
	}

	return TRUE;
}

#if 0
BOOL ndr_dump_struct_fromDescr(wLog* logger, UINT32 lvl, const NdrStructDescr *descr, const void* obj)
{
	for (size_t i = 0; i < descr->nfields; i++)
	{
		const NdrFieldStruct *field = &descr->fields[i];
		BYTE *ptr = (BYTE *)obj + field->structOffset;


	}
	return TRUE;
}
#endif

BOOL ndr_struct_read_fromDescr(NdrContext* context, wStream* s, const NdrStructDescr *descr, void* target)
{
	WINPR_ASSERT(context);
	WINPR_ASSERT(s);
	WINPR_ASSERT(descr);
	WINPR_ASSERT(target);

#define NDR_MAX_STRUCT_DEFERRED 16
	NdrDeferredEntry deferreds[NDR_MAX_STRUCT_DEFERRED] = { 0 };
	size_t ndeferred = 0;

	for (size_t i = 0; i < descr->nfields; i++)
	{
		const NdrFieldStruct *field = &descr->fields[i];
		BYTE *ptr = target;
		ptr += field->structOffset;
		void *hints = NULL;

		if (field->hintsField >= 0) {
			/* computes the address of the hints field if any */
			WINPR_ASSERT(field->hintsField < descr->nfields);
			const NdrFieldStruct *hintsField = &descr->fields[field->hintsField];

			hints = (BYTE *)target + hintsField->structOffset;
		}

		if (field->isPointer) {
			NdrDeferredEntry *deferred = &deferreds[ndeferred];
			if (ndeferred >= NDR_MAX_STRUCT_DEFERRED) {
				WLog_ERR(TAG, "too many deferred when calling ndr_read_struct_fromDescr for %s", descr->name);
				return FALSE;
			}

			deferred->name = field->name;
			deferred->hints = hints;
			deferred->target = ptr;
			deferred->msg = field->typeDescr;
			if (!ndr_read_refpointer(context, s, &deferred->ptrId)) {
				WLog_ERR(TAG, "error when reading %s.%s", descr->name, field->name);
				return FALSE;
			}
			ndeferred++;
		} else {
			if (!field->typeDescr->readFn(context, s, hints, ptr)) {
				WLog_ERR(TAG, "error when reading %s.%s", descr->name, field->name);
				return FALSE;
			}
		}
	}

	return ndr_push_deferreds(context, deferreds, ndeferred);
}

BOOL ndr_struct_write_fromDescr(NdrContext* context, wStream* s, const NdrStructDescr *descr, const void* src)
{
	WINPR_ASSERT(context);
	WINPR_ASSERT(s);
	WINPR_ASSERT(descr);
	WINPR_ASSERT(src);

	NdrDeferredEntry deferreds[NDR_MAX_STRUCT_DEFERRED] = { 0 };
	size_t ndeferred = 0;

	for (size_t i = 0; i < descr->nfields; i++)
	{
		const NdrFieldStruct *field = &descr->fields[i];
		BYTE *ptr = (BYTE *)src + field->structOffset;

		void *hints = NULL;

		if (field->hintsField > 0) {
			/* computes the address of the hints field if any */
			WINPR_ASSERT(field->hintsField < descr->nfields);
			const NdrFieldStruct *hintsField = &descr->fields[field->hintsField];

			hints = (BYTE *)src + hintsField->structOffset;
		}

		if (field->isPointer) {
			ndr_refid ptrId = NDR_PTR_NULL;
			BOOL isNew;
			ptr = *(void**)ptr;
			if (!ndr_context_allocatePtr(context, ptr, &ptrId, &isNew))
				return FALSE;

			if (isNew)
			{
				NdrDeferredEntry *deferred = &deferreds[ndeferred];
				if (ndeferred >= NDR_MAX_STRUCT_DEFERRED) {
					WLog_ERR(TAG, "too many deferred when calling ndr_read_struct_fromDescr for %s", descr->name);
					return FALSE;
				}

				deferred->name = field->name;
				deferred->hints = hints;
				deferred->target = ptr;
				deferred->msg = field->typeDescr;
				ndeferred++;
			}

			if (!ndr_write_uint32(context, s, ptrId))
				return FALSE;
		} else {
			if (!field->typeDescr->writeFn(context, s, hints, ptr)) {
				WLog_ERR(TAG, "error when writing %s.%s", descr->name, field->name);
				return FALSE;
			}
		}
	}

	return ndr_push_deferreds(context, deferreds, ndeferred);
}

void ndr_struct_destroy(NdrContext* context, const NdrStructDescr *descr, void* pptr)
{
	WINPR_ASSERT(context);
	WINPR_ASSERT(descr);
	WINPR_ASSERT(pptr);

	for (size_t i = 0; i < descr->nfields; i++)
	{
		const NdrFieldStruct *field = &descr->fields[i];
		if (field->typeDescr->destroyFn) {
			void *ptr = (BYTE *)pptr + field->structOffset;
			if (field->isPointer)
				ptr = *(void **)ptr;

			if (ptr)
				field->typeDescr->destroyFn(context, ptr);
			if (field->isPointer)
				free(ptr);
		}
	}
}

ndr_refid ndr_pointer_refid(const void* ptr)
{
	return (ndr_refid)((ULONG_PTR)ptr);
}

BOOL ndr_read_refpointer(NdrContext* context, wStream* s, ndr_refid* refId)
{
	return ndr_read_uint32(context, s, refId);
}

typedef struct {
	const void *needle;
	ndr_refid *presult;
} FindValueArgs;


BOOL findValueRefFn(const void *key, void *value, void *parg)
{
	FindValueArgs *args = (FindValueArgs *)parg;
	if (args->needle == value) {
		*args->presult =(ndr_refid)(UINT_PTR)key;
		return FALSE;
	}
	return TRUE;
}

BOOL ndr_context_allocatePtr(NdrContext* context, const void* ptr, ndr_refid *prefId, BOOL *pnewPtr)
{
	FindValueArgs findArgs = { ptr, prefId };
	if (!HashTable_Foreach(context->refPointers, findValueRefFn, &findArgs)) {
		*pnewPtr = FALSE;
		return TRUE;
	}

	*pnewPtr = TRUE;
	*prefId = context->refIdCounter + 4;
	if (!HashTable_Insert(context->refPointers, (void*)(UINT_PTR)(*prefId), ptr))
		return FALSE;

	context->refIdCounter += 4;
	return TRUE;
}


BOOL ndr_read_pointedMessageEx(NdrContext* context, wStream* s, ndr_refid ptrId, NdrMessageType descr, void *hints, void **target)
{
	WINPR_ASSERT(context);
	WINPR_ASSERT(s);
	WINPR_ASSERT(descr);
	WINPR_ASSERT(target);

	*target = NULL;
	if (!ptrId) {
		/*UINT32 v;
		return ndr_read_uint32(context, s, &v);
		return ndr_read_align(context, s, 4);*/
		return TRUE;
	}

	void* ret = HashTable_GetItemValue(context->refPointers, (void*)(UINT_PTR)ptrId);
	if (!ret)
	{
		size_t itemCount = ndr_hintsCount(descr, hints);
		ret = calloc(itemCount, descr->itemSize);
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

	if (!ndeferred)
		return TRUE;

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

BOOL ndr_treat_deferred_read(NdrContext* context, wStream* s)
{
	WINPR_ASSERT(context);
	WINPR_ASSERT(s);

	while (context->ndeferred)
	{
		NdrDeferredEntry current = context->deferred[context->ndeferred - 1];
		context->ndeferred--;

		WLog_DBG(TAG, "treating read deferred 0x%x for %s", current.ptrId, current.name);
		if (!ndr_read_pointedMessageEx(context, s, current.ptrId, current.msg, current.hints, current.target))
		{
			WLog_ERR(TAG, "error parsing deferred %s", current.name);
			return FALSE;
		}
	}

	return TRUE;
}

BOOL ndr_treat_deferred_write(NdrContext* context, wStream* s)
{
	WINPR_ASSERT(context);
	WINPR_ASSERT(s);

	while (context->ndeferred)
	{
		NdrDeferredEntry current = context->deferred[context->ndeferred - 1];
		context->ndeferred--;

		WLog_VRB(TAG, "treating write deferred for %s", current.name);
		if (!current.msg->writeFn(context, s, current.hints, current.target)) {
			WLog_ERR(TAG, "error writing deferred %s", current.name);
			return FALSE;
		}

	}

	return TRUE;
}

