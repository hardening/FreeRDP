#include <winpr/assert.h>
#include <winpr/error.h>
#include <winpr/library.h>
#include <winpr/interlocked.h>

#include <freerdp/msdvc.h>
#include <freerdp/dvc.h>

#ifndef _WIN32
#define STDMETHODCALLTYPE

#ifndef DECLSPEC_SELECTANY
#define DECLSPEC_SELECTANY /* __declspec(selectany) */
#endif

#ifndef EXTERN_C
#ifdef __cplusplus
#define EXTERN_C extern "C"
#else
#define EXTERN_C extern
#endif
#endif

#define INITGUID
#ifdef INITGUID
#ifdef __cplusplus
#define DEFINE_GUID(name,l,w1,w2,b1,b2,b3,b4,b5,b6,b7,b8) EXTERN_C const GUID DECLSPEC_SELECTANY name = { l, w1, w2, { b1, b2, b3, b4, b5, b6, b7, b8 } }
#else
#define DEFINE_GUID(name,l,w1,w2,b1,b2,b3,b4,b5,b6,b7,b8) const GUID DECLSPEC_SELECTANY name = { l, w1, w2, { b1, b2, b3, b4, b5, b6, b7, b8 } }
#endif
#else
/* __declspec(selectany) must be applied to initialized objects on GCC 5 hence must not be used here. */
#define DEFINE_GUID(name,l,w1,w2,b1,b2,b3,b4,b5,b6,b7,b8) EXTERN_C const GUID name
#endif


#endif

DEFINE_GUID(IID_IWTSPlugin, 0xa1230201, 0x1439, 0x4e62, 0xa4,0x14, 0x19,0x0d,0x0a,0xc3,0xd4,0x0e);

static HRESULT toHResult(UINT v)
{
	switch(v)
	{
	case CHANNEL_RC_OK:
		return S_OK;
	case CHANNEL_RC_NO_MEMORY:
		return E_OUTOFMEMORY;
	default:
		return E_FAIL;
	}
}

static UINT fromHResult(HRESULT v)
{
	switch (v)
	{
	case S_OK:
		return CHANNEL_RC_OK;
	case E_OUTOFMEMORY:
	default:
		return CHANNEL_RC_NO_MEMORY;
	}
}


/* ================================  CUnknown =============================== */

typedef struct {
	IUnknown base;
	volatile LONG refCount;
	void (*dtor)(void *This);
} CUnknown;

#if 0
static HRESULT STDMETHODCALLTYPE CUnknown_QueryInterface(IUnknown *This, REFIID riid, void **ppvObject)
{
	CUnknown *c = (CUnknown *)This;
	return S_OK;
}
#endif
static ULONG STDMETHODCALLTYPE CUnknown_AddRef(IUnknown *This)
{
	CUnknown *c = (CUnknown *)This;
	return InterlockedIncrement(&c->refCount);
}

static ULONG STDMETHODCALLTYPE CUnknown_Release(IUnknown *This)
{
	CUnknown *c = (CUnknown *)This;
	ULONG ret = InterlockedDecrement(&c->refCount);
	if (!ret && c->dtor)
		c->dtor(This);
	return ret;
}


typedef struct {
	union {
		CUnknown cunknown;
		IWTSVirtualChannel_ms base;
	};

	IWTSVirtualChannel *channel;
} CWTSVirtualChannel;


/* ===============================  CWTSListener =============================*/

typedef struct {
	union {
		CUnknown cunknown;
		IWTSListener_ms base;
	};
	IWTSListener *listener;
	IWTSListenerCallback_ms *callback_ms;
} CWTSListener;

static HRESULT STDMETHODCALLTYPE CWTSListener_QueryInterface(IUnknown *This, REFIID riid, void **ppvObject)
{
	//CWTSListener *listener = (CWTSListener *)This;
	return S_OK;
}

static HRESULT STDMETHODCALLTYPE CWTSListener_GetConfiguration(IWTSListener_ms *This, IPropertyBag **ppPropertyBag)
{
	CWTSListener *clistener = (CWTSListener *)This;
	void *p = NULL;
	HRESULT hres = toHResult(clistener->listener->GetConfiguration(clistener->listener, &p));
	*ppPropertyBag = (IPropertyBag *)p;
	return hres;
}

const IWTSListenerVtbl_ms CWTSListener_vtable = {
	{
		CWTSListener_QueryInterface,
		CUnknown_AddRef,
		CUnknown_Release
	},
	CWTSListener_GetConfiguration
};


CWTSListener *CWTSListener_new(IWTSListener *listener, IWTSListenerCallback_ms *callback) {
	CWTSListener *ret = calloc(1, sizeof(*ret));
	if (!ret)
		return NULL;
	ret->listener = listener;
	ret->callback_ms = callback;

	IWTSListener_ms *base = &ret->base;
	base->lpVtbl = &CWTSListener_vtable;
	return ret;
}

/* ============================ CWTSVirtualChannelCallback ==================== */
typedef struct {
	union {
		CUnknown cunknown;
		IWTSVirtualChannelCallback_ms base;
	};
	IWTSVirtualChannelCallback *freerdpCallback;
} CWTSVirtualChannelCallback;

static HRESULT STDMETHODCALLTYPE CWTSVirtualChannelCallback_QueryInterface(IUnknown *This, REFIID riid, void **ppvObject)
{
	*ppvObject = This;
	return S_OK;
}

static HRESULT STDMETHODCALLTYPE CWTSVirtualChannelCallback_OnDataReceived(IWTSVirtualChannelCallback_ms *This, ULONG cbSize, BYTE *pBuffer)
{
	CWTSVirtualChannelCallback *self = (CWTSVirtualChannelCallback *)This;
	wStream staticS;
	wStream *s = Stream_StaticInit(&staticS, pBuffer, cbSize);

	return fromHResult(self->freerdpCallback->OnDataReceived(self->freerdpCallback, s));
}

HRESULT STDMETHODCALLTYPE CWTSVirtualChannelCallbackOnClose(IWTSVirtualChannelCallback_ms *This)
{
	CWTSVirtualChannelCallback *self = (CWTSVirtualChannelCallback *)This;
	return fromHResult(self->freerdpCallback->OnClose(self->freerdpCallback));
}

const IWTSVirtualChannelCallbackVtbl_ms CWTSVirtualChannelCallback_vtable = {
	{
		CWTSVirtualChannelCallback_QueryInterface,
		CUnknown_AddRef,
		CUnknown_Release,
	},
	CWTSVirtualChannelCallback_OnDataReceived,
	CWTSVirtualChannelCallbackOnClose
};

CWTSVirtualChannelCallback *CWTSVirtualChannelCallback_new(IWTSVirtualChannelCallback *cb)
{
	CWTSVirtualChannelCallback *ret = calloc(1, sizeof(*ret));
	if (!ret)
		return NULL;

	ret->freerdpCallback = cb;

	IWTSVirtualChannelCallback_ms *base = &ret->base;
	base->lpVtbl = &CWTSVirtualChannelCallback_vtable;

	return ret;
}
/* ============================ CWTSVirtualChannelManager ==================== */

struct CWTSVirtualChannelManager {
	union {
		CUnknown cunknown;
		IWTSVirtualChannelManager_ms base;
	};

	IWTSVirtualChannelManager *manager;
};


static HRESULT STDMETHODCALLTYPE CWTSVirtualChannelManager_QueryInterface(IUnknown *This, REFIID riid, void **ppvObject)
{
	return S_OK;
}

UINT OnNewChannelConnection_cb(IWTSListenerCallback* pListenerCallback, IWTSVirtualChannel* pChannel, BYTE* Data,
		 BOOL* pbAccept, IWTSVirtualChannelCallback** ppCallback)
{
	CWTSListener *clistener = (CWTSListener *)pListenerCallback->pInterface;
	WINPR_ASSERT(clistener);

	CWTSVirtualChannel *cchannel = (CWTSVirtualChannel *)pChannel;
	IWTSVirtualChannelCallback_ms *callback_ms;

	IWTSListenerCallback_ms *cb = clistener->callback_ms;
	HRESULT hres = cb->lpVtbl->OnNewChannelConnection(cb, &cchannel->base, (BSTR)Data, pbAccept, &callback_ms);
	return fromHResult(hres);
}

HRESULT STDMETHODCALLTYPE CWTSVirtualChannelManager_CreateListener(IWTSVirtualChannelManager_ms *This, const char *pszChannelName, ULONG uFlags,
		IWTSListenerCallback_ms *pListenerCallback, IWTSListener_ms **ppListener)
{
	CWTSVirtualChannelManager *c = (CWTSVirtualChannelManager *)This;

	IWTSListenerCallback *cb = calloc(1, sizeof(*cb));
	cb->OnNewChannelConnection = OnNewChannelConnection_cb;
	cb->pInterface = NULL;

	IWTSListener *freerdpListener = NULL;
	ULONG ret = c->manager->CreateListener(c->manager, pszChannelName, uFlags, cb, &freerdpListener);
	if (ret != CHANNEL_RC_OK)
		return ret;

	CWTSListener *flistener = CWTSListener_new(freerdpListener, pListenerCallback);
	if (!flistener)
		return CHANNEL_RC_NO_MEMORY;

	cb->pInterface = flistener;
	*ppListener = &flistener->base;
	return S_OK;
}


static const IWTSVirtualChannelManagerVtbl_ms CWTSVirtualChannelManager_vtable = {
	{
		CWTSVirtualChannelManager_QueryInterface,
		CUnknown_AddRef,
		CUnknown_Release,
	},
	CWTSVirtualChannelManager_CreateListener
};

IWTSVirtualChannelManager_ms *CWTSVirtualChannelManager_new(IWTSVirtualChannelManager *manager) {
	CWTSVirtualChannelManager *ret = calloc(1, sizeof(*ret));
	if (!ret)
		return NULL;

	ret->manager = manager;

	IWTSVirtualChannelManager_ms *base = &ret->base;
	base->lpVtbl = &CWTSVirtualChannelManager_vtable;
	return base;
}

/* ============================ CWTSVirtualChannel ========================== */



static void CWTSVirtualChannel_Delete(void *arg)
{
	//CWTSVirtualChannel *channel = (CWTSVirtualChannel *)arg;
}

static HRESULT STDMETHODCALLTYPE CWTSVirtualChannel_QueryInterface(IUnknown *This, REFIID riid, void **ppvObject)
{
	*ppvObject = This;
	return S_OK;
}

HRESULT STDMETHODCALLTYPE CWTSVirtualChannel_Write(IWTSVirtualChannel_ms *This, ULONG cbSize, BYTE *pBuffer, IUnknown *pReserved)
{
	CWTSVirtualChannel *cvchannel = (CWTSVirtualChannel *)This;
	return toHResult( cvchannel->channel->Write(cvchannel->channel, cbSize, pBuffer, pReserved) );
}

HRESULT STDMETHODCALLTYPE CWTSVirtualChannel_Close(IWTSVirtualChannel_ms *This)
{
	CWTSVirtualChannel *cvchannel = (CWTSVirtualChannel *)This;
	return toHResult(cvchannel->channel->Close(cvchannel->channel));
}


static const IWTSVirtualChannelVtbl_ms CWTSVirtualChannel_vtable = {
	{
		CWTSVirtualChannel_QueryInterface,
		CUnknown_AddRef,
		CUnknown_Release,
	},
	CWTSVirtualChannel_Write,
	CWTSVirtualChannel_Close,
};

IWTSVirtualChannel_ms *CWTSVirtualChannel_new(IWTSVirtualChannel *channel) {
	CWTSVirtualChannel *ret = calloc(1, sizeof(*ret));
	if (!ret)
		return NULL;

	ret->channel = channel;
	ret->cunknown.dtor = CWTSVirtualChannel_Delete;

	IWTSVirtualChannel_ms *base = &ret->base;
	base->lpVtbl = &CWTSVirtualChannel_vtable;
	return base;
}

/* ===================== ============================ */

typedef HRESULT (VCAPITYPE *VirtualChannelGetInstanceFn)(const GUID *refiid, ULONG  *pNumObjs, VOID  **ppObjArray);

MstscPluginContext *mstscPluginLoad(const char *path, IWTSVirtualChannelManager *channelManager)
{
	WINPR_ASSERT(path);

	MstscPluginContext *pluginContext = calloc(1, sizeof(*pluginContext));
	if (!pluginContext)
		return NULL;

	pluginContext->hDll = LoadLibrary(path);
	if (!pluginContext->hDll)
		goto fail_dll;

	VirtualChannelGetInstanceFn fn = GetProcAddress(pluginContext->hDll, "VirtualChannelGetInstance");
	if (!fn)
		goto fail_getproc;

	ULONG nobjs = 1;
	void *obj = NULL;
	HRESULT hres = fn(&IID_IWTSPlugin, &nobjs, &obj);
	if (hres != S_OK || nobjs != 1)
		goto fail_VirtualChannelGetInstance;

	IWTSPlugin_ms *plugin = pluginContext->pluginObj = (IWTSPlugin_ms *)obj;
	pluginContext->vchannelManager = CWTSVirtualChannelManager_new(channelManager);
	if (!pluginContext->vchannelManager)
		goto fail_vchannelManager;

	hres = pluginContext->pluginObj->lpVtbl->Initialize(pluginContext->pluginObj, pluginContext->vchannelManager);
	if (hres != S_OK)
		goto fail_init;
	return pluginContext;

fail_init:
fail_vchannelManager:
	pluginContext->pluginObj->lpVtbl->iunknown.Release((IUnknown *)pluginContext->pluginObj);
fail_VirtualChannelGetInstance:
fail_getproc:
	FreeLibrary(pluginContext->hDll);
fail_dll:
	free(pluginContext);
	return NULL;
}
