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

#ifndef CHANNELS_RDPEAR_NDR_H_
#define CHANNELS_RDPEAR_NDR_H_

#include <winpr/stream.h>

typedef struct NdrContext_s NdrContext;

typedef UINT32 ndr_refid;

typedef BOOL (*NDR_READER_FN)(NdrContext* context, wStream* s, void *hints, void* target);
typedef BOOL (*NDR_WRITER_FN)(NdrContext* context, wStream* s, const void* obj);
typedef BOOL (*NDR_DESTROY_FN)(NdrContext* context, void* obj);

typedef struct {
	size_t itemSize;
	NDR_READER_FN readFn;
	NDR_WRITER_FN writeFn;
	NDR_DESTROY_FN destroyFn;
} NdrMessageDescr;

typedef const NdrMessageDescr *NdrMessageType;

/** @brief */
typedef struct {
	ndr_refid ptrId;
	const char *name;
	void *hints;
	void *target;
	NdrMessageType msg;
} NdrDeferredEntry;


NdrContext* ndr_context_new(BOOL bigEndianDrep, BYTE version);
void ndr_context_destroy(NdrContext** pcontext);

void ndr_context_reset(NdrContext* context);
NdrContext* ndr_context_copy(const NdrContext* src);

NdrContext* ndr_read_header(wStream* s);
BOOL ndr_write_header(NdrContext* context, wStream* s);

NdrMessageType ndr_uint8_descr();

BOOL ndr_read_uint16(NdrContext* context, wStream* s, UINT16* v);
BOOL ndr_write_uint16(NdrContext* context, wStream* s, UINT16 v);
NdrMessageType ndr_uint16_descr();

BOOL ndr_read_uint32(NdrContext* context, wStream* s, UINT32* v);
BOOL ndr_write_uint32(NdrContext* context, wStream* s, UINT32 v);
BOOL ndr_write_uint32_(NdrContext* context, wStream* s, const UINT32 *v);
NdrMessageType ndr_uint32_descr();

BOOL ndr_read_uint64(NdrContext* context, wStream* s, UINT64* v);
BOOL ndr_write_uint64(NdrContext* context, wStream* s, UINT64 v);
NdrMessageType ndr_uint64_descr();

NdrMessageType ndr_uint8Array_descr();
NdrMessageType ndr_uint16Array_descr();
NdrMessageType ndr_uint16VaryingArray_descr();

BOOL ndr_read_align(NdrContext* context, wStream* s);
BOOL ndr_write_align(NdrContext* context, wStream* s);

BOOL ndr_read_pickle(NdrContext* context, wStream* s);
BOOL ndr_write_pickle(NdrContext* context, wStream* s);

BOOL ndr_read_constructed(NdrContext* context, wStream* s, wStream* target);
BOOL ndr_write_constructed(NdrContext* context, wStream* s, wStream* payload);

BOOL ndr_start_constructed(NdrContext* context, wStream* s);
BOOL ndr_end_constructed(NdrContext* context, wStream* s);

BOOL ndr_read_wchar(NdrContext* context, wStream* s, WCHAR* ptr);


typedef struct
{
	UINT32 length;
	UINT32 maxLength;
} NdrVaryingArrayHints;



BOOL ndr_read_uconformant_varying_array(NdrContext* context, wStream* s, UINT32 lenHint,
                                        UINT32 maxHint, NdrMessageType itemType,
                                        void** target);


typedef struct
{
	UINT32 count;
} NdrArrayHints;

BOOL ndr_read_uconformant_array(NdrContext* context, wStream* s, UINT32 lenHint, NdrMessageType itemType, void** target);
BOOL ndr_write_uconformant_array(NdrContext* context, wStream* s, const BYTE* ptr, UINT32 len);


ndr_refid ndr_pointer_refid(const void* ptr);
BOOL ndr_read_refpointer(NdrContext* context, wStream* s, UINT32* refId);


BOOL ndr_read_pointedMessageEx(NdrContext* context, wStream* s, ndr_refid ptrId, NdrMessageType descr, void *hints, void **target);


BOOL ndr_push_deferreds(NdrContext* context, NdrDeferredEntry *deferreds, size_t ndeferred);
BOOL ndr_treat_deferred(NdrContext* context, wStream* s);

#endif /* CHANNELS_RDPEAR_NDR_H_ */
