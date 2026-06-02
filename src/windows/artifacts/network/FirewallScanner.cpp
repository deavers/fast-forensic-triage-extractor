#include "ff/core/IArtifactSubScanner.h"
#include "ff/models/ForensicArtifacts.h"
#include "windows/WinRegistry.h"
#include <windows.h>
#include <netfw.h>
#include <comdef.h>

namespace ff::windows
{
    class FirewallScanner : public core::IArtifactSubScanner
    {
    public:
        void scan(models::DigitalFootprint& footprint) const override
        {
            // COM open
            HRESULT hrInit = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

            INetFwPolicy2* pNetFwPolicy2 = nullptr;
            HRESULT hr = CoCreateInstance(__uuidof(NetFwPolicy2), nullptr, CLSCTX_INPROC_SERVER, __uuidof(INetFwPolicy2), (void**)&pNetFwPolicy2);
            
            if (SUCCEEDED(hr) && pNetFwPolicy2) 
            {
                INetFwRules* pFwRules = nullptr;

                if (SUCCEEDED(pNetFwPolicy2->get_Rules(&pFwRules))) 
                {
                    IUnknown* pEnumerator = nullptr;
                    pFwRules->get__NewEnum(&pEnumerator);
                    
                    if (pEnumerator) 
                    {
                        IEnumVARIANT* pVariant = nullptr;
                        pEnumerator->QueryInterface(__uuidof(IEnumVARIANT), (void**)&pVariant);
                        
                        if (pVariant) 
                        {
                            VARIANT var;
                            VariantInit(&var);
                            ULONG cFetched = 0;
                            
                            while (pVariant->Next(1, &var, &cFetched) == S_OK) 
                            {
                                INetFwRule* pFwRule = nullptr;

                                if (var.vt == VT_DISPATCH && SUCCEEDED(var.pdispVal->QueryInterface(__uuidof(INetFwRule), (void**)&pFwRule))) 
                                {
                                    models::FirewallRuleEntry rule;
                                    BSTR bstrName;
                                    BSTR bstrApp;
                                    
                                    if (SUCCEEDED(pFwRule->get_Name(&bstrName)) && bstrName) 
                                    {
                                        _bstr_t bstr(bstrName);
                                        rule.ruleName = (const char*)bstr;
                                        SysFreeString(bstrName);
                                    }
                                    
                                    if (SUCCEEDED(pFwRule->get_ApplicationName(&bstrApp)) && bstrApp) 
                                    {
                                        _bstr_t bstr(bstrApp);
                                        rule.ruleData = "App: " + std::string((const char*)bstr);
                                        SysFreeString(bstrApp);
                                    } 
                                    else 
                                    {
                                        if (SUCCEEDED(pFwRule->get_LocalPorts(&bstrApp)) && bstrApp) 
                                        {
                                            _bstr_t bstr(bstrApp);
                                            rule.ruleData = "Port: " + std::string((const char*)bstr);
                                            SysFreeString(bstrApp);
                                        }
                                    }
                                    
                                    if (!rule.ruleName.empty()) 
                                    {
                                        footprint.firewallRules.push_back(rule);
                                    }
                                    pFwRule->Release();
                                }
                                VariantClear(&var);
                            }
                            pVariant->Release();
                        }
                        pEnumerator->Release();
                    }
                    pFwRules->Release();
                }
                pNetFwPolicy2->Release();
            }

            // COM close
            if (SUCCEEDED(hrInit)) 
            {
                CoUninitialize();
            }
        }
    };

    REGISTER_WINDOWS_ARTIFACT(FirewallScanner)
}