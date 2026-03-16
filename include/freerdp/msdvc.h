#ifndef FREERDP_MSDVC_H
#define FREERDP_MSDVC_H

#include <winpr/wtypes.h>

#include <freerdp/api.h>
#include <freerdp/dvc.h>

#ifdef _WIN32
#include <unknwn.h>
#include <oaidl.h>
#else


typedef struct IUnknown IUnknown;
typedef struct IErrorLog IErrorLog;
typedef struct IPropertyBag IPropertyBag;

typedef char *LPCOLESTR;
#define STDMETHODCALLTYPE
#define __stdcall
typedef void *VARIANT;


typedef struct {
    /*** IUnknown methods ***/
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IUnknown *This, REFIID riid, void **ppvObject);
    ULONG (STDMETHODCALLTYPE *AddRef)(IUnknown *This);
    ULONG (STDMETHODCALLTYPE *Release)(IUnknown *This);
} IUnknownVtbl;

struct IUnknown {
    const IUnknownVtbl* lpVtbl;
};

typedef struct tagEXCEPINFO {
    WORD wCode;
    WORD wReserved;
    BSTR bstrSource;
    BSTR bstrDescription;
    BSTR bstrHelpFile;
    DWORD dwHelpContext;
    PVOID pvReserved;
    HRESULT (__stdcall *pfnDeferredFillIn)(struct tagEXCEPINFO *);
    SCODE scode;
  } EXCEPINFO, *LPEXCEPINFO;


typedef struct {
    /*** IUnknown methods ***/
	IUnknownVtbl iunknown;

    /*** IErrorLog methods ***/
    HRESULT (STDMETHODCALLTYPE *AddError)(IErrorLog *This, LPCOLESTR pszPropName, EXCEPINFO *pExcepInfo);
} IErrorLogVtbl;

struct IErrorLog {
    const IErrorLogVtbl* lpVtbl;
};


typedef struct {
    /*** IUnknown methods ***/
	IUnknownVtbl iunknown;

    /*** IPropertyBag methods ***/
    HRESULT (STDMETHODCALLTYPE *Read)(IPropertyBag *This, LPCOLESTR pszPropName, VARIANT *pVar, IErrorLog *pErrorLog);
    HRESULT (STDMETHODCALLTYPE *Write)(IPropertyBag *This, LPCOLESTR pszPropName, VARIANT *pVar);

} IPropertyBagVtbl;

struct IPropertyBag {
    const IPropertyBagVtbl* lpVtbl;
};

#endif /* -WIN32 */

typedef struct IWTSVirtualChannelManager_ms IWTSVirtualChannelManager_ms;
typedef struct IWTSPlugin_ms IWTSPlugin_ms;
typedef struct IWTSListener_ms IWTSListener_ms;
typedef struct IWTSListenerCallback_ms IWTSListenerCallback_ms;
typedef struct IWTSVirtualChannel_ms IWTSVirtualChannel_ms;
typedef struct IWTSVirtualChannelCallback_ms IWTSVirtualChannelCallback_ms;


typedef struct {
    /*** IUnknown methods ***/
	IUnknownVtbl iunknown;

    /*** IWTSVirtualChannelCallback methods ***/
    HRESULT (STDMETHODCALLTYPE *OnDataReceived)(IWTSVirtualChannelCallback_ms *This, ULONG cbSize, BYTE *pBuffer);
    HRESULT (STDMETHODCALLTYPE *OnClose)(IWTSVirtualChannelCallback_ms *This);
} IWTSVirtualChannelCallbackVtbl_ms;

struct IWTSVirtualChannelCallback_ms {
    const IWTSVirtualChannelCallbackVtbl_ms* lpVtbl;
};


typedef struct {
    /*** IUnknown methods ***/
	IUnknownVtbl iunknown;

	/*** IWTSVirtualChannel methods ***/
	HRESULT (STDMETHODCALLTYPE *Write)(IWTSVirtualChannel_ms *This, ULONG cbSize, BYTE *pBuffer, IUnknown *pReserved);
	HRESULT (STDMETHODCALLTYPE *Close)(IWTSVirtualChannel_ms *This);
} IWTSVirtualChannelVtbl_ms;

struct IWTSVirtualChannel_ms {
	const IWTSVirtualChannelVtbl_ms* lpVtbl;
};


typedef struct {
    /*** IUnknown methods ***/
	IUnknownVtbl iunknown;

    /*** IWTSListenerCallback methods ***/
    HRESULT (STDMETHODCALLTYPE *OnNewChannelConnection)(IWTSListenerCallback_ms *This, IWTSVirtualChannel_ms *pChannel, BSTR data,
        BOOL *pbAccept, IWTSVirtualChannelCallback_ms **ppCallback);
} IWTSListenerCallbackVtbl_ms;

struct IWTSListenerCallback_ms {
    const IWTSListenerCallbackVtbl_ms* lpVtbl;
};


typedef struct {
    /*** IUnknown methods ***/
	IUnknownVtbl iunknown;

    /*** IWTSListener methods ***/
    HRESULT (STDMETHODCALLTYPE *GetConfiguration)(IWTSListener_ms *This, IPropertyBag **ppPropertyBag);
} IWTSListenerVtbl_ms;

struct IWTSListener_ms {
    const IWTSListenerVtbl_ms* lpVtbl;
};


typedef struct {
	/*** IUnknown methods ***/
	IUnknownVtbl iunknown;

	/*** IWTSVirtualChannelManager methods ***/
	HRESULT (STDMETHODCALLTYPE *CreateListener)(IWTSVirtualChannelManager_ms *This, const char *pszChannelName, ULONG uFlags,
			IWTSListenerCallback_ms *pListenerCallback, IWTSListener_ms **ppListener);
} IWTSVirtualChannelManagerVtbl_ms;

struct IWTSVirtualChannelManager_ms {
	const IWTSVirtualChannelManagerVtbl_ms* lpVtbl;
};


typedef struct {
	/*** IUnknown methods ***/
	IUnknownVtbl iunknown;

	/*** IWTSPlugin methods ***/
	HRESULT (STDMETHODCALLTYPE *Initialize)(IWTSPlugin_ms *This, IWTSVirtualChannelManager_ms *pChannelMgr);
	HRESULT (STDMETHODCALLTYPE *Connected)(IWTSPlugin_ms *This);
	HRESULT (STDMETHODCALLTYPE *Disconnected)(IWTSPlugin_ms *This, DWORD dwDisconnectCode);
	HRESULT (STDMETHODCALLTYPE *Terminated)(IWTSPlugin_ms *This);
} IWTSPluginVtbl_ms;

struct IWTSPlugin_ms {
	const IWTSPluginVtbl_ms* lpVtbl;
};

typedef struct CWTSVirtualChannelManager CWTSVirtualChannelManager;
typedef struct {
	HMODULE hDll;
	IWTSPlugin_ms *pluginObj;
	IWTSVirtualChannelManager_ms *vchannelManager;
} MstscPluginContext;


FREERDP_API MstscPluginContext *mstscPluginLoad(const char *path, IWTSVirtualChannelManager *channelManager);

#endif /* FREERDP_MSDVC_H */
