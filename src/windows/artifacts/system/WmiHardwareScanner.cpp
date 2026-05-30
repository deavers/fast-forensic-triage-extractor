#include "ff/Platform.h"
#ifdef FF_PLATFORM_WINDOWS

#include "windows/WinRegistry.h"
#include <iostream>
#include <string>
#include <comdef.h>
#include <Wbemidl.h>

namespace ff::windows
{
    class WmiHardwareScanner : public core::IArtifactSubScanner
    {
    public:
        void scan(models::DigitalFootprint& footprint) const override
        {
            // Initialize COM and set up WMI connection
            HRESULT hr = CoInitializeEx(0, COINIT_MULTITHREADED);
            bool comInitialized = SUCCEEDED(hr);

            hr = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT,
                RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);

            IWbemLocator* pLoc = NULL;
            hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
            if (FAILED(hr)) 
            { 
                if (comInitialized) 
                    CoUninitialize(); 

                return; 
            }

            IWbemServices* pSvc = NULL;
            hr = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, NULL, 0, NULL, NULL, &pSvc);
            if (FAILED(hr)) 
            { 
                pLoc->Release(); 
                if (comInitialized) 
                    CoUninitialize(); 
                return; 
            }

            hr = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, 
                RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);

            // Function to query WMI and extract a specific property from the first result
            auto queryWMI = [&](const wchar_t* query, const wchar_t* propName) -> std::string 
            {
                IEnumWbemClassObject* pEnumerator = NULL;
                hr = pSvc->ExecQuery(_bstr_t("WQL"), _bstr_t(query),
                    WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
                
                if (FAILED(hr)) 
                    return "Unknown";

                IWbemClassObject* pclsObj = NULL;
                ULONG uReturn = 0;
                std::string result = "Unknown";

                while (pEnumerator) 
                {
                    HRESULT hrEnum = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

                    if (0 == uReturn) 
                        break;

                    VARIANT vtProp;
                    hrEnum = pclsObj->Get(propName, 0, &vtProp, 0, 0);

                    if (SUCCEEDED(hrEnum) && vtProp.vt == VT_BSTR) 
                    {
                        _bstr_t bstrPath(vtProp.bstrVal);
                        result = (const char*)bstrPath;
                    }

                    VariantClear(&vtProp);
                    pclsObj->Release();
                    break; // Only need the first result for hardware info
                }
                pEnumerator->Release();
                return result;
            };

            // Collecting digital footprint hardware information using WMI queries
            footprint.hw_info.cpuName = queryWMI(L"SELECT Name FROM Win32_Processor", L"Name");
            footprint.hw_info.gpuName = queryWMI(L"SELECT Name FROM Win32_VideoController", L"Name");
            footprint.hw_info.motherboardSerial = queryWMI(L"SELECT IdentifyingNumber FROM Win32_ComputerSystemProduct", L"IdentifyingNumber");

            // For RAM, we need to sum up all memory modules
            IEnumWbemClassObject* pMemEnum = NULL;
            if (SUCCEEDED(pSvc->ExecQuery(_bstr_t("WQL"), _bstr_t(L"SELECT Capacity FROM Win32_PhysicalMemory"),
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pMemEnum))) 
            {
                IWbemClassObject* pclsObj = NULL;
                ULONG uReturn = 0;
                unsigned long long totalRam = 0;

                while (pMemEnum) 
                {
                    if (FAILED(pMemEnum->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn)) || 0 == uReturn) 
                        break;

                    VARIANT vtProp;

                    if (SUCCEEDED(pclsObj->Get(L"Capacity", 0, &vtProp, 0, 0)) && vtProp.vt == VT_BSTR) 
                    {
                        totalRam += std::stoull(std::wstring(vtProp.bstrVal));
                    }

                    VariantClear(&vtProp);
                    pclsObj->Release();
                }
                pMemEnum->Release();
                footprint.hw_info.totalRamGB = std::to_string(totalRam / (1024ULL * 1024 * 1024)) + " GB";
            }

            // Free
            pSvc->Release();
            pLoc->Release();

            if (comInitialized) 
                CoUninitialize();
        }
    };

    REGISTER_WINDOWS_ARTIFACT(WmiHardwareScanner)
}
#endif