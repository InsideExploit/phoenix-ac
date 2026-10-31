#include "fivem.hpp"
#include <windows.h>
#include <tlhelp32.h>
#include <objbase.h>
#include <exdisp.h>
#include <servprov.h>
#include <shlobj.h>
#include <shobjidl.h>
#include <shldisp.h>
#include <stdio.h>
#include <wchar.h>
#include "../dbg.hpp"
#include "../sigcheck/sigcheck.hpp"
#include "pxstr.hpp"
#include "pxenc.hpp"
#include "lazy_importer.hpp"
#include "brkida.hpp"
#include "agent_stubs.hpp"

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

static
DWORD
FindShellPid()
{
    VIRTUALIZER_START
    BRKIDA;
    DWORD ourSession = 0;
    if (!LI_KERNEL(ProcessIdToSessionId)(LI_KERNEL(GetCurrentProcessId)(), &ourSession))
        return 0;

    HANDLE snap = LI_KERNEL(CreateToolhelp32Snapshot)(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return 0;

    PROCESSENTRY32W pe    = { sizeof(pe) };
    DWORD           found = 0;
    if (LI_KERNEL(Process32FirstW)(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, PX_W(L"explorer.exe")) != 0)
                continue;

            DWORD sess = 0;
            if (LI_KERNEL(ProcessIdToSessionId)(pe.th32ProcessID, &sess) && sess == ourSession) {
                found = pe.th32ProcessID;
                break;
            }
        } while (LI_KERNEL(Process32NextW)(snap, &pe));
    }

    LI_KERNEL(CloseHandle)(snap);
    VIRTUALIZER_END
    return found;
}

#define KG_FIVEM_BUILD   L"-b3258"
#define KG_FIVEM_PURE    L"-pure_1"

#define KG_FIVEM_INI_NAME    L"PhoenixAC.ini"
#define KG_FIVEM_INI_SECTION L"FiveM"
#define KG_FIVEM_INI_KEY     L"Path"

#define KG_FIVEM_CERT_SERIAL "043922e28e11d45f73ac1936ce97fc36"

static wchar_t g_FiveMRoot[MAX_PATH] = { 0 };
static LONG    g_FiveMResolved       = 0;

static
bool
RootHasExe(
    const wchar_t* Root
)
{
    if (!Root || !*Root)
        return false;

    wchar_t exe[MAX_PATH] = { 0 };
    if (_snwprintf_s(exe, _TRUNCATE, PX_W(L"%ls\\FiveM.exe"), Root) < 0)
        return false;

    return LI_KERNEL(GetFileAttributesW)(exe) != INVALID_FILE_ATTRIBUTES;
}

static
bool
ExeCertIsRockstar(
    const wchar_t* Exe
)
{
    return SigIsTrustedWithSerial(Exe, PX_A(KG_FIVEM_CERT_SERIAL));
}

static
void
ShowInvalidFiveMBox(
    const wchar_t* Exe
)
{
    wchar_t body[768] = { 0 };
    _snwprintf_s(body, _TRUNCATE,
        PX_W(L"This is not a valid FiveM file and cannot be launched.\n\n"
             L"%ls\n\n"
             L"Please reinstall FiveM from the official website and try again."),
        Exe);

    LI_KERNEL(LoadLibraryW)(pxenc(L"user32.dll"));
    LI_USER32(MessageBoxW)(NULL, body,
        PX_W(L"PhoenixAC: Invalid FiveM File"),
        MB_OK | MB_ICONERROR | MB_SETFOREGROUND | MB_TOPMOST);
}

static
bool
ConfigIniPath(
    wchar_t Out[MAX_PATH]
)
{
    wchar_t self[MAX_PATH] = { 0 };
    DWORD n = LI_KERNEL(GetModuleFileNameW)(NULL, self, MAX_PATH);
    if (n == 0 || n >= MAX_PATH)
        return false;

    wchar_t* slash = wcsrchr(self, L'\\');
    if (!slash)
        return false;
    *slash = 0;

    return _snwprintf_s(Out, MAX_PATH, _TRUNCATE, PX_W(L"%ls\\%ls"),
                        self, PX_W(KG_FIVEM_INI_NAME)) >= 0;
}

static
bool
ReadRootFromIni(
    wchar_t Out[MAX_PATH]
)
{
    Out[0] = 0;

    wchar_t ini[MAX_PATH] = { 0 };
    if (!ConfigIniPath(ini))
        return false;

    if (LI_KERNEL(GetFileAttributesW)(ini) == INVALID_FILE_ATTRIBUTES)
        return false;

    DWORD n = LI_KERNEL(GetPrivateProfileStringW)(
        PX_W(KG_FIVEM_INI_SECTION), PX_W(KG_FIVEM_INI_KEY), PX_W(L""),
        Out, MAX_PATH, ini);

    return n > 0 && Out[0] != 0;
}

static
bool
WriteRootToIni(
    const wchar_t* Root
)
{
    wchar_t ini[MAX_PATH] = { 0 };
    if (!ConfigIniPath(ini))
        return false;

    BOOL ok = LI_KERNEL(WritePrivateProfileStringW)(
        PX_W(KG_FIVEM_INI_SECTION), PX_W(KG_FIVEM_INI_KEY), Root, ini);

    LI_KERNEL(WritePrivateProfileStringW)(NULL, NULL, NULL, ini);
    return !!ok;
}

static
bool
PromptForFiveMExe(
    wchar_t Out[MAX_PATH]
)
{
    Out[0] = 0;

    HRESULT hrCo       = LI_OLE32(CoInitializeEx)(NULL, COINIT_APARTMENTTHREADED);
    bool    needUninit = (hrCo == S_OK) || (hrCo == S_FALSE);

    IFileOpenDialog* dlg = NULL;
    HRESULT hr = LI_OLE32(CoCreateInstance)(CLSID_FileOpenDialog, NULL, CLSCTX_INPROC_SERVER,
                                            IID_IFileOpenDialog, (void**)&dlg);
    if (FAILED(hr) || !dlg) {
        KGDBG(L"[fivem] CoCreateInstance(FileOpenDialog) hr=0x%08X\n", hr);
        if (needUninit) LI_OLE32(CoUninitialize)();
        return false;
    }

    COMDLG_FILTERSPEC filter[1];
    filter[0].pszName = PX_W(L"FiveM executable");
    filter[0].pszSpec = PX_W(L"FiveM.exe");
    dlg->SetFileTypes(1, filter);
    dlg->SetTitle(PX_W(L"PhoenixAC - locate your FiveM.exe"));
    dlg->SetFileName(PX_W(L"FiveM.exe"));
    dlg->SetOptions(FOS_FILEMUSTEXIST | FOS_PATHMUSTEXIST | FOS_FORCEFILESYSTEM | FOS_NOCHANGEDIR);

    bool got = false;
    if (SUCCEEDED(dlg->Show(NULL))) {
        IShellItem* item = NULL;
        if (SUCCEEDED(dlg->GetResult(&item)) && item) {
            PWSTR psz = NULL;
            if (SUCCEEDED(item->GetDisplayName(SIGDN_FILESYSPATH, &psz)) && psz) {
                if (wcslen(psz) < MAX_PATH) {
                    wcscpy_s(Out, MAX_PATH, psz);
                    got = true;
                }
                LI_OLE32(CoTaskMemFree)(psz);
            }
            item->Release();
        }
    }

    dlg->Release();
    if (needUninit) LI_OLE32(CoUninitialize)();
    return got;
}

bool
FiveMEnsureRoot()
{
    if (InterlockedCompareExchange(&g_FiveMResolved, 1, 0) != 0)
        return g_FiveMRoot[0] != 0;

    wchar_t cand[MAX_PATH] = { 0 };

    if (ReadRootFromIni(cand) && RootHasExe(cand)) {
        wcscpy_s(g_FiveMRoot, MAX_PATH, cand);
        KGDBG(L"[fivem] root from ini: %ls\n", g_FiveMRoot);
        return true;
    }

    wchar_t local[MAX_PATH] = { 0 };
    DWORD n = LI_KERNEL(GetEnvironmentVariableW)(PX_W(L"LOCALAPPDATA"), local, MAX_PATH);
    if (n > 0 && n < MAX_PATH &&
        _snwprintf_s(cand, _TRUNCATE, PX_W(L"%ls\\FiveM"), local) >= 0 &&
        RootHasExe(cand)) {
        wcscpy_s(g_FiveMRoot, MAX_PATH, cand);
        KGDBG(L"[fivem] root from default location: %ls\n", g_FiveMRoot);
        return true;
    }

    LI_KERNEL(LoadLibraryW)(pxenc(L"user32.dll"));
    LI_USER32(MessageBoxW)(NULL,
        PX_W(L"FiveM was not found in the default install location.\n\n"
             L"Press OK and select your FiveM.exe so PhoenixAC can launch it.\n"
             L"Your choice is remembered and you will not be asked again."),
        PX_W(L"PhoenixAC: FiveM Not Found"),
        MB_OK | MB_ICONINFORMATION | MB_SETFOREGROUND | MB_TOPMOST);

    wchar_t picked[MAX_PATH] = { 0 };
    if (!PromptForFiveMExe(picked)) {
        KGDBG(L"[fivem] location prompt cancelled\n");
        return false;
    }

    wcscpy_s(cand, MAX_PATH, picked);
    wchar_t* slash = wcsrchr(cand, L'\\');
    if (!slash)
        return false;
    *slash = 0;

    if (!RootHasExe(cand)) {
        LI_USER32(MessageBoxW)(NULL,
            PX_W(L"The selected folder does not contain FiveM.exe.\n\n"
                 L"Start PhoenixAC again and pick the FiveM.exe inside your FiveM folder."),
            PX_W(L"PhoenixAC: Invalid FiveM Path"),
            MB_OK | MB_ICONERROR | MB_SETFOREGROUND | MB_TOPMOST);
        KGDBG(L"[fivem] picked path has no FiveM.exe: %ls\n", cand);
        return false;
    }

    {
        wchar_t pickedExe[MAX_PATH] = { 0 };
        if (_snwprintf_s(pickedExe, _TRUNCATE, PX_W(L"%ls\\FiveM.exe"), cand) < 0)
            return false;

        if (!ExeCertIsRockstar(pickedExe)) {
            KGDBG(L"[fivem] rejected picked path, certificate check failed: %ls\n", pickedExe);
            ShowInvalidFiveMBox(pickedExe);
            return false;
        }
    }

    wcscpy_s(g_FiveMRoot, MAX_PATH, cand);
    if (WriteRootToIni(g_FiveMRoot))
        KGDBG(L"[fivem] root saved to ini: %ls\n", g_FiveMRoot);
    else
        KGDBG(L"[fivem] root resolved but ini write failed: %ls\n", g_FiveMRoot);

    return true;
}

bool
FiveMGetRoot(
    wchar_t Out[MAX_PATH]
)
{
    Out[0] = 0;
    if (!g_FiveMRoot[0])
        return false;

    wcscpy_s(Out, MAX_PATH, g_FiveMRoot);
    return true;
}

bool
FiveMGetAppDir(
    wchar_t Out[MAX_PATH]
)
{
    Out[0] = 0;

    wchar_t root[MAX_PATH] = { 0 };
    if (!FiveMGetRoot(root))
        return false;

    return _snwprintf_s(Out, MAX_PATH, _TRUNCATE, PX_W(L"%ls\\FiveM.app"), root) >= 0;
}

static
bool
PrepareFiveMConfig()
{
    VIRTUALIZER_START
    BRKIDA;
    VIRTUALIZER_END

    wchar_t app[MAX_PATH] = { 0 };
    if (!FiveMGetAppDir(app))
        return false;

    wchar_t ini[MAX_PATH] = { 0 };
    if (_snwprintf_s(ini, _TRUNCATE, PX_W(L"%ls\\CitizenFX.ini"), app) < 0)
        return false;

    if (LI_KERNEL(GetFileAttributesW)(ini) == INVALID_FILE_ATTRIBUTES)
        return false;

    LI_KERNEL(WritePrivateProfileStringW)(PX_W(L"Game"), PX_W(L"SavedBuildNumber"),
                                          PX_W(L"3258"), ini);
    //LI_KERNEL(WritePrivateProfileStringW)(PX_W(L"Game"), PX_W(L"PoolSizesIncrease"),
    //                                      PX_W(L"{\"AnimStore\":20480,\"TxdStore\":26000}"), ini);
    return true;
}

bool
LaunchFiveM()
{
    if (!FiveMEnsureRoot())
        return false;

    VIRTUALIZER_START
    BRKIDA;
    wchar_t dir[MAX_PATH] = { 0 };
    wchar_t exe[MAX_PATH] = { 0 };
    if (!FiveMGetRoot(dir))
        return false;

    if (_snwprintf_s(exe, _TRUNCATE, PX_W(L"%ls\\FiveM.exe"), dir) < 0)
        return false;

    if (LI_KERNEL(GetFileAttributesW)(exe) == INVALID_FILE_ATTRIBUTES)
        return false;

    VIRTUALIZER_END

    if (!ExeCertIsRockstar(exe)) {
        KGDBG(L"[fivem] refusing to launch, certificate check failed: %ls\n", exe);
        ShowInvalidFiveMBox(exe);
        return false;
    }
    KGDBG(L"[fivem] certificate verified (Rockstar Games, Inc.)\n");

    PrepareFiveMConfig();

    HRESULT hrCo = LI_OLE32(CoInitializeEx)(NULL, COINIT_APARTMENTTHREADED);
    bool    needUninit = (hrCo == S_OK) || (hrCo == S_FALSE);

    IShellWindows* pShellWindows = NULL;
    HRESULT hr = LI_OLE32(CoCreateInstance)(CLSID_ShellWindows, NULL, CLSCTX_ALL,
                                  IID_IShellWindows, (void**)&pShellWindows);
    if (FAILED(hr) || !pShellWindows) {
        KGDBG(L"[fivem] CoCreateInstance(ShellWindows) hr=0x%08X\n", hr);
        if (needUninit) LI_OLE32(CoUninitialize)();
        return false;
    }

    VARIANT vLoc, vEmpty;
    LI_OLEAUT32(VariantInit)(&vLoc);   vLoc.vt   = VT_I4; vLoc.lVal   = CSIDL_DESKTOP;
    LI_OLEAUT32(VariantInit)(&vEmpty); vEmpty.vt = VT_EMPTY;

    long          lHwnd     = 0;
    IDispatch*    pDispatch = NULL;
    hr = pShellWindows->FindWindowSW(&vLoc, &vEmpty, SWC_DESKTOP,
                                     &lHwnd, SWFO_NEEDDISPATCH, &pDispatch);
    pShellWindows->Release();
    LI_OLEAUT32(VariantClear)(&vLoc);
    LI_OLEAUT32(VariantClear)(&vEmpty);
    if (FAILED(hr) || !pDispatch) {
        KGDBG(L"[fivem] FindWindowSW(desktop) hr=0x%08X\n", hr);
        if (needUninit) LI_OLE32(CoUninitialize)();
        return false;
    }

    IServiceProvider* pSP = NULL;
    hr = pDispatch->QueryInterface(IID_IServiceProvider, (void**)&pSP);
    pDispatch->Release();
    if (FAILED(hr) || !pSP) {
        KGDBG(L"[fivem] QI IServiceProvider hr=0x%08X\n", hr);
        if (needUninit) LI_OLE32(CoUninitialize)();
        return false;
    }

    IShellBrowser* pBrowser = NULL;
    hr = pSP->QueryService(SID_STopLevelBrowser, IID_IShellBrowser, (void**)&pBrowser);
    pSP->Release();
    if (FAILED(hr) || !pBrowser) {
        KGDBG(L"[fivem] QueryService(STopLevelBrowser) hr=0x%08X\n", hr);
        if (needUninit) LI_OLE32(CoUninitialize)();
        return false;
    }

    IShellView* pView = NULL;
    hr = pBrowser->QueryActiveShellView(&pView);
    pBrowser->Release();
    if (FAILED(hr) || !pView) {
        KGDBG(L"[fivem] QueryActiveShellView hr=0x%08X\n", hr);
        if (needUninit) LI_OLE32(CoUninitialize)();
        return false;
    }

    IDispatch* pViewDisp = NULL;
    hr = pView->GetItemObject(SVGIO_BACKGROUND, IID_IDispatch, (void**)&pViewDisp);
    pView->Release();
    if (FAILED(hr) || !pViewDisp) {
        KGDBG(L"[fivem] GetItemObject(BACKGROUND) hr=0x%08X\n", hr);
        if (needUninit) LI_OLE32(CoUninitialize)();
        return false;
    }

    IShellFolderViewDual* pViewDual = NULL;
    hr = pViewDisp->QueryInterface(IID_IShellFolderViewDual, (void**)&pViewDual);
    pViewDisp->Release();
    if (FAILED(hr) || !pViewDual) {
        KGDBG(L"[fivem] QI IShellFolderViewDual hr=0x%08X\n", hr);
        if (needUninit) LI_OLE32(CoUninitialize)();
        return false;
    }

    IDispatch* pAppDisp = NULL;
    hr = pViewDual->get_Application(&pAppDisp);
    pViewDual->Release();
    if (FAILED(hr) || !pAppDisp) {
        KGDBG(L"[fivem] get_Application hr=0x%08X\n", hr);
        if (needUninit) LI_OLE32(CoUninitialize)();
        return false;
    }

    IShellDispatch2* pShellDisp = NULL;
    hr = pAppDisp->QueryInterface(IID_IShellDispatch2, (void**)&pShellDisp);
    pAppDisp->Release();
    if (FAILED(hr) || !pShellDisp) {
        KGDBG(L"[fivem] QI IShellDispatch2 hr=0x%08X\n", hr);
        if (needUninit) LI_OLE32(CoUninitialize)();
        return false;
    }

    wchar_t argsBuf[128];
    _snwprintf_s(argsBuf, _TRUNCATE, PX_W(L"%ls %ls"),
                 PX_W(KG_FIVEM_BUILD), PX_W(KG_FIVEM_PURE));

    VARIANT vFile, vArgs, vDir, vVerb, vShow;
    LI_OLEAUT32(VariantInit)(&vFile);  vFile.vt = VT_BSTR; vFile.bstrVal = LI_OLEAUT32(SysAllocString)(exe);
    LI_OLEAUT32(VariantInit)(&vArgs);  vArgs.vt = VT_BSTR; vArgs.bstrVal = LI_OLEAUT32(SysAllocString)(argsBuf);
    LI_OLEAUT32(VariantInit)(&vDir);   vDir.vt  = VT_BSTR; vDir.bstrVal  = LI_OLEAUT32(SysAllocString)(dir);
    LI_OLEAUT32(VariantInit)(&vVerb);  vVerb.vt = VT_BSTR; vVerb.bstrVal = LI_OLEAUT32(SysAllocString)(pxenc(L"open"));
    LI_OLEAUT32(VariantInit)(&vShow);  vShow.vt = VT_I4;   vShow.lVal    = SW_SHOWNORMAL;

    hr = pShellDisp->ShellExecute(vFile.bstrVal, vArgs, vDir, vVerb, vShow);
    KGDBG(L"[fivem] ShellExecute(FiveM.exe via explorer, args=%ls) hr=0x%08X\n", argsBuf, hr);

    LI_OLEAUT32(VariantClear)(&vFile);
    LI_OLEAUT32(VariantClear)(&vArgs);
    LI_OLEAUT32(VariantClear)(&vDir);
    LI_OLEAUT32(VariantClear)(&vVerb);
    LI_OLEAUT32(VariantClear)(&vShow);
    pShellDisp->Release();
    if (needUninit) LI_OLE32(CoUninitialize)();

    if (FAILED(hr))
        return false;

    KGDBG(L"[fivem] launched FiveM.exe via explorer (medium integrity, no args)\n");
    return true;
}
