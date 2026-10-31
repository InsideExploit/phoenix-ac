#include "capture.hpp"
#include <windows.h>
#include <wincodec.h>
#include <objbase.h>
#include <d3d11.h>
#include <dxgi.h>
#include <dxgi1_2.h>
#include <stdio.h>
#include <string.h>
#include "../dbg.hpp"
#include "pxenc.hpp"
#include "lazy_importer.hpp"
#include "brkida.hpp"
#include "agent_stubs.hpp"

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "windowscodecs.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")

typedef struct {
    UINT32 left, top, right, bottom;
} NVRECT;

#pragma pack(push, 1)
typedef struct {
    UINT32 version;
    UINT32 targetId;
    void*  hPhysicalGpu;
    NVRECT rect;
    UINT64 flags;
    UINT32 format;
    UINT32 _pad;
    void** ppData;
} NV_WKS_SCANOUT_PARAMS;
#pragma pack(pop)

typedef void* (*pfnNvQI)(UINT32);
typedef UINT32(*pfnNvInit)();
typedef UINT32(*pfnNvEnumGpus)(void* [64], UINT32*);
typedef UINT32(*pfnNvScanout)(ID3D11Device*, NV_WKS_SCANOUT_PARAMS*);

#define NV_ID_INIT      0x0150E828
#define NV_ID_ENUMGPUS  0xE5AC921F
#define NV_ID_SCANOUT   0xBCB1C536

static
bool
HasNvidiaGpu()
{
    BRKIDA;
    IDXGIFactory* factory = NULL;
    if (FAILED(LI_DXGI(CreateDXGIFactory)(__uuidof(IDXGIFactory), (void**)&factory)))
        return false;

    bool          found = false;
    IDXGIAdapter* ad    = NULL;
    for (UINT i = 0; factory->EnumAdapters(i, &ad) != DXGI_ERROR_NOT_FOUND; i++) {
        DXGI_ADAPTER_DESC d = { 0 };
        ad->GetDesc(&d);
        ad->Release();
        if (d.VendorId == 0x10DE) {
            found = true;
            break;
        }
    }

    factory->Release();
    return found;
}

typedef struct {
    UINT32 TargetId;
    INT32  X, Y;
    UINT32 W, H;
} KG_DISPLAY_INFO;

static
UINT
QueryActiveDisplays(
    KG_DISPLAY_INFO* out,
    UINT             outCap
)
{
    VIRTUALIZER_START
    BRKIDA;
    UINT32 pathCount = 0, modeCount = 0;
    if (LI_USER32(GetDisplayConfigBufferSizes)(QDC_ONLY_ACTIVE_PATHS, &pathCount, &modeCount) != ERROR_SUCCESS)
        return 0;

    if (pathCount == 0)
        return 0;

    DISPLAYCONFIG_PATH_INFO* paths = (DISPLAYCONFIG_PATH_INFO*)HeapAlloc(GetProcessHeap(), 0, pathCount * sizeof(DISPLAYCONFIG_PATH_INFO));
    DISPLAYCONFIG_MODE_INFO* modes = (DISPLAYCONFIG_MODE_INFO*)HeapAlloc(GetProcessHeap(), 0, modeCount * sizeof(DISPLAYCONFIG_MODE_INFO));
    UINT found = 0;
    if (paths && modes &&
        LI_USER32(QueryDisplayConfig)(QDC_ONLY_ACTIVE_PATHS, &pathCount, paths, &modeCount, modes, NULL) == ERROR_SUCCESS) {
        for (UINT32 i = 0; i < pathCount && found < outCap; i++) {
            UINT32 mi = paths[i].sourceInfo.modeInfoIdx;
            if (mi >= modeCount)
                continue;

            if (modes[mi].infoType != DISPLAYCONFIG_MODE_INFO_TYPE_SOURCE)
                continue;

            out[found].TargetId = paths[i].targetInfo.id;
            out[found].X        = modes[mi].sourceMode.position.x;
            out[found].Y        = modes[mi].sourceMode.position.y;
            out[found].W        = modes[mi].sourceMode.width;
            out[found].H        = modes[mi].sourceMode.height;
            found++;
        }
    }

    if (paths)
        HeapFree(GetProcessHeap(), 0, paths);

    if (modes)
        HeapFree(GetProcessHeap(), 0, modes);

    VIRTUALIZER_END
    return found;
}

static
BYTE*
GdiCaptureRegion(
    INT32 srcX,
    INT32 srcY,
    UINT  w,
    UINT  h
)
{
    VIRTUALIZER_START
    BRKIDA;
    if (w == 0 || h == 0)
        return NULL;

    HDC hScreen = LI_USER32(GetDC)(NULL);
    if (!hScreen)
        return NULL;

    HDC     hMem = LI_GDI32(CreateCompatibleDC)(hScreen);
    HBITMAP hBmp = LI_GDI32(CreateCompatibleBitmap)(hScreen, (int)w, (int)h);
    HGDIOBJ old  = LI_GDI32(SelectObject)(hMem, hBmp);

    LI_GDI32(BitBlt)(hMem, 0, 0, (int)w, (int)h, hScreen, srcX, srcY, SRCCOPY);

    BITMAPINFO bi = { 0 };
    bi.bmiHeader.biSize        = sizeof(BITMAPINFOHEADER);
    bi.bmiHeader.biWidth       = (LONG)w;
    bi.bmiHeader.biHeight      = -(LONG)h;
    bi.bmiHeader.biPlanes      = 1;
    bi.bmiHeader.biBitCount    = 32;
    bi.bmiHeader.biCompression = BI_RGB;

    UINT   stride = w * 4;
    SIZE_T total  = (SIZE_T)stride * h;
    BYTE*  buf    = (BYTE*)HeapAlloc(GetProcessHeap(), 0, total);
    bool   ok     = false;
    if (buf) {
        int lines = LI_GDI32(GetDIBits)(hMem, hBmp, 0, (UINT)h, buf, &bi, DIB_RGB_COLORS);
        ok = (lines == (int)h);
    }

    LI_GDI32(SelectObject)(hMem, old);
    LI_GDI32(DeleteObject)(hBmp);
    LI_GDI32(DeleteDC)(hMem);
    LI_USER32(ReleaseDC)(NULL, hScreen);

    if (!ok) {
        if (buf)
            HeapFree(GetProcessHeap(), 0, buf);

        return NULL;
    }
    VIRTUALIZER_END
    return buf;
}

static
HRESULT
EncodePng(
    const void* pixelsBgra,
    UINT        w,
    UINT        h,
    UINT        stride,
    BYTE**      outBytes,
    ULONG*      outLen
)
{
    BRKIDA;
    *outBytes = NULL;
    *outLen   = 0;

    HRESULT hr         = LI_OLE32(CoInitializeEx)(NULL, COINIT_APARTMENTTHREADED);
    bool    needUninit = SUCCEEDED(hr) || hr == S_FALSE;

    IWICImagingFactory* factory = NULL;
    hr = LI_OLE32(CoCreateInstance)(CLSID_WICImagingFactory, NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&factory));
    if (FAILED(hr)) {
        if (needUninit)
            LI_OLE32(CoUninitialize)();

        return hr;
    }

    IStream* stream = NULL;
    hr = LI_OLE32(CreateStreamOnHGlobal)(NULL, TRUE, &stream);
    if (FAILED(hr)) {
        factory->Release();
        if (needUninit)
            LI_OLE32(CoUninitialize)();

        return hr;
    }

    IWICBitmapEncoder* encoder = NULL;
    factory->CreateEncoder(GUID_ContainerFormatPng, NULL, &encoder);
    encoder->Initialize(stream, WICBitmapEncoderNoCache);

    VIRTUALIZER_START
    IWICBitmapFrameEncode* frame = NULL;
    encoder->CreateNewFrame(&frame, NULL);
    frame->Initialize(NULL);
    frame->SetSize(w, h);
    WICPixelFormatGUID px = GUID_WICPixelFormat32bppBGRA;
    frame->SetPixelFormat(&px);

    for (UINT y = 0; y < h; y++) {
        const BYTE* row = (const BYTE*)pixelsBgra + y * stride;
        hr = frame->WritePixels(1, w * 4, w * 4, (BYTE*)row);
        if (FAILED(hr))
            break;
    }
    VIRTUALIZER_END

    if (SUCCEEDED(hr))
        hr = frame->Commit();

    if (SUCCEEDED(hr))
        hr = encoder->Commit();

    frame->Release();
    encoder->Release();

    if (SUCCEEDED(hr)) {
        HGLOBAL hg = NULL;
        if (SUCCEEDED(LI_OLE32(GetHGlobalFromStream)(stream, &hg))) {
            SIZE_T sz  = GlobalSize(hg);
            void*  mem = GlobalLock(hg);
            if (mem && sz > 0) {
                *outBytes = (BYTE*)HeapAlloc(GetProcessHeap(), 0, sz);
                if (*outBytes) {
                    memcpy(*outBytes, mem, sz);
                    *outLen = (ULONG)sz;
                }
                GlobalUnlock(hg);
            }
        }
    }

    stream->Release();
    factory->Release();
    if (needUninit)
        LI_OLE32(CoUninitialize)();

    return (*outBytes) ? S_OK : (FAILED(hr) ? hr : E_FAIL);
}

static
bool
CaptureNvidiaScanout(
    BYTE** outBgra,
    UINT*  outW,
    UINT*  outH,
    UINT*  outStride
)
{
    VIRTUALIZER_START
    BRKIDA;
    ID3D11Device*     device = NULL;
    D3D_FEATURE_LEVEL lvl    = D3D_FEATURE_LEVEL_11_0;
    if (FAILED(LI_D3D11(D3D11CreateDevice)(NULL, D3D_DRIVER_TYPE_HARDWARE, NULL,
        D3D11_CREATE_DEVICE_BGRA_SUPPORT,
        &lvl, 1, D3D11_SDK_VERSION,
        &device, NULL, NULL)))
        return false;

    HMODULE nv = LI_KERNEL(LoadLibraryA)(pxenc("nvapi64.dll"));
    if (!nv) {
        device->Release();
        return false;
    }

    pfnNvQI qi = (pfnNvQI)LI_KERNEL(GetProcAddress)(nv, pxenc("nvapi_QueryInterface"));
    if (!qi) {
        device->Release();
        return false;
    }

    pfnNvInit init = (pfnNvInit)qi(NV_ID_INIT);
    if (!init || init() != 0) {
        device->Release();
        return false;
    }

    pfnNvEnumGpus enumGpus = (pfnNvEnumGpus)qi(NV_ID_ENUMGPUS);
    void*  gpus[64]  = { 0 };
    UINT32 gpuCount  = 0;
    if (!enumGpus || enumGpus(gpus, &gpuCount) != 0 || gpuCount == 0) {
        device->Release();
        return false;
    }

    pfnNvScanout scanout = (pfnNvScanout)qi(NV_ID_SCANOUT);
    if (!scanout) {
        device->Release();
        return false;
    }

    KG_DISPLAY_INFO displays[16];
    UINT displayCount = QueryActiveDisplays(displays, 16);
    if (displayCount == 0) {
        device->Release();
        return false;
    }

    struct CapturedPanel {
        BYTE*  bgra;
        UINT   stride;
        INT32  left, top, right, bottom;
    };
    CapturedPanel panels[16];
    UINT gotCount = 0;

    for (UINT d = 0; d < displayCount; d++) {
        for (UINT32 g = 0; g < gpuCount; g++) {
            void* captured = NULL;
            NV_WKS_SCANOUT_PARAMS p = { 0 };
            p.version      = (UINT32)(sizeof(NV_WKS_SCANOUT_PARAMS) | (1 << 16));
            p.targetId     = displays[d].TargetId;
            p.hPhysicalGpu = gpus[g];
            p.ppData       = &captured;

            UINT32 st = scanout(device, &p);
            if (st != 0 || !captured) {
                if (captured) VirtualFree(captured, 0, MEM_RELEASE);
                continue;
            }

            UINT w = p.rect.right - p.rect.left;
            UINT h = p.rect.bottom - p.rect.top;
            if (w == 0 || h == 0) {
                VirtualFree(captured, 0, MEM_RELEASE);
                break;
            }

            SIZE_T total = (SIZE_T)w * h * 4;
            BYTE*  copy  = (BYTE*)HeapAlloc(GetProcessHeap(), 0, total);
            if (!copy) {
                VirtualFree(captured, 0, MEM_RELEASE);
                break;
            }
            memcpy(copy, captured, total);
            VirtualFree(captured, 0, MEM_RELEASE);

            panels[gotCount].bgra   = copy;
            panels[gotCount].stride = w * 4;
            panels[gotCount].left   = (INT32)p.rect.left;
            panels[gotCount].top    = (INT32)p.rect.top;
            panels[gotCount].right  = (INT32)p.rect.right;
            panels[gotCount].bottom = (INT32)p.rect.bottom;
            gotCount++;
            KGDBG(L"[capture] nv panel target=%u gpu=%u %dx%d @ (%d,%d)\n",
                  displays[d].TargetId, g, (int)w, (int)h,
                  (int)p.rect.left, (int)p.rect.top);
            break;
        }
    }

    if (gotCount == 0) {
        device->Release();
        return false;
    }

    INT32 uLeft = INT32_MAX, uTop = INT32_MAX;
    INT32 uRight = INT32_MIN, uBottom = INT32_MIN;
    for (UINT i = 0; i < gotCount; i++) {
        if (panels[i].left   < uLeft)   uLeft   = panels[i].left;
        if (panels[i].top    < uTop)    uTop    = panels[i].top;
        if (panels[i].right  > uRight)  uRight  = panels[i].right;
        if (panels[i].bottom > uBottom) uBottom = panels[i].bottom;
    }

    UINT vw = (UINT)(uRight  - uLeft);
    UINT vh = (UINT)(uBottom - uTop);
    if (vw == 0 || vh == 0) {
        for (UINT i = 0; i < gotCount; i++) HeapFree(GetProcessHeap(), 0, panels[i].bgra);
        device->Release();
        return false;
    }

    SIZE_T totalOut = (SIZE_T)vw * vh * 4;
    BYTE*  out      = (BYTE*)HeapAlloc(GetProcessHeap(), 0, totalOut);
    if (!out) {
        for (UINT i = 0; i < gotCount; i++) HeapFree(GetProcessHeap(), 0, panels[i].bgra);
        device->Release();
        return false;
    }
    memset(out, 0, totalOut);
    UINT outStrideBytes = vw * 4;

    for (UINT i = 0; i < gotCount; i++) {
        INT32 offX = panels[i].left - uLeft;
        INT32 offY = panels[i].top  - uTop;
        UINT  pw   = (UINT)(panels[i].right  - panels[i].left);
        UINT  ph   = (UINT)(panels[i].bottom - panels[i].top);
        for (UINT y = 0; y < ph; y++) {
            const BYTE* srcRow = panels[i].bgra + (SIZE_T)y * panels[i].stride;
            BYTE*       dstRow = out + (SIZE_T)(offY + (INT32)y) * outStrideBytes + (SIZE_T)offX * 4;
            memcpy(dstRow, srcRow, (SIZE_T)pw * 4);
        }
        HeapFree(GetProcessHeap(), 0, panels[i].bgra);
    }

    device->Release();

    KGDBG(L"[capture] nv virtual %ux%u from %u panel(s)\n", vw, vh, gotCount);
    *outBgra   = out;
    *outW      = vw;
    *outH      = vh;
    *outStride = outStrideBytes;
    VIRTUALIZER_END
    return true;
}

static
bool
CaptureDxgiDup(
    BYTE** outBgra,
    UINT*  outW,
    UINT*  outH,
    UINT*  outStride
)
{
    VIRTUALIZER_START
    BRKIDA;

    ID3D11Device*        device = NULL;
    ID3D11DeviceContext* ctx    = NULL;
    D3D_FEATURE_LEVEL    lvl    = D3D_FEATURE_LEVEL_11_0;
    if (FAILED(LI_D3D11(D3D11CreateDevice)(NULL, D3D_DRIVER_TYPE_HARDWARE, NULL,
        D3D11_CREATE_DEVICE_BGRA_SUPPORT,
        &lvl, 1, D3D11_SDK_VERSION,
        &device, NULL, &ctx)))
        return false;

    IDXGIDevice* dxgiDev = NULL;
    if (FAILED(device->QueryInterface(__uuidof(IDXGIDevice), (void**)&dxgiDev))) {
        if (ctx) ctx->Release();
        device->Release();
        return false;
    }

    IDXGIAdapter* adapter = NULL;
    if (FAILED(dxgiDev->GetAdapter(&adapter))) {
        dxgiDev->Release();
        if (ctx) ctx->Release();
        device->Release();
        return false;
    }
    dxgiDev->Release();

    struct DupPanel {
        BYTE*  bgra;
        UINT   stride;
        INT32  left, top, right, bottom;
    };
    DupPanel panels[16];
    UINT     gotCount = 0;

    for (UINT o = 0; o < 16; ++o) {
        IDXGIOutput* output = NULL;
        if (adapter->EnumOutputs(o, &output) == DXGI_ERROR_NOT_FOUND) break;
        if (!output) continue;

        DXGI_OUTPUT_DESC odesc = { 0 };
        output->GetDesc(&odesc);
        if (!odesc.AttachedToDesktop) { output->Release(); continue; }

        IDXGIOutput1* output1 = NULL;
        if (FAILED(output->QueryInterface(__uuidof(IDXGIOutput1), (void**)&output1))) {
            output->Release();
            continue;
        }
        output->Release();

        IDXGIOutputDuplication* dup = NULL;
        HRESULT hrDup = output1->DuplicateOutput(device, &dup);
        output1->Release();
        if (FAILED(hrDup) || !dup) continue;

        IDXGIResource*      res         = NULL;
        DXGI_OUTDUPL_FRAME_INFO frameInfo = { 0 };
        for (int retry = 0; retry < 3; ++retry) {
            if (res) { res->Release(); res = NULL; }
            HRESULT hrA = dup->AcquireNextFrame(500, &frameInfo, &res);
            if (SUCCEEDED(hrA) && res) break;
            if (hrA == DXGI_ERROR_WAIT_TIMEOUT) continue;
            break;
        }
        if (!res) { dup->Release(); continue; }

        ID3D11Texture2D* srcTex = NULL;
        if (FAILED(res->QueryInterface(__uuidof(ID3D11Texture2D), (void**)&srcTex))) {
            res->Release();
            dup->ReleaseFrame();
            dup->Release();
            continue;
        }
        res->Release();

        D3D11_TEXTURE2D_DESC srcDesc = { 0 };
        srcTex->GetDesc(&srcDesc);

        D3D11_TEXTURE2D_DESC stagingDesc = srcDesc;
        stagingDesc.BindFlags      = 0;
        stagingDesc.MiscFlags      = 0;
        stagingDesc.Usage          = D3D11_USAGE_STAGING;
        stagingDesc.CPUAccessFlags = D3D11_CPU_ACCESS_READ;

        ID3D11Texture2D* stagingTex = NULL;
        if (FAILED(device->CreateTexture2D(&stagingDesc, NULL, &stagingTex))) {
            srcTex->Release();
            dup->ReleaseFrame();
            dup->Release();
            continue;
        }

        ctx->CopyResource(stagingTex, srcTex);
        srcTex->Release();

        D3D11_MAPPED_SUBRESOURCE mapped = { 0 };
        HRESULT hrMap = ctx->Map(stagingTex, 0, D3D11_MAP_READ, 0, &mapped);
        if (FAILED(hrMap) || !mapped.pData) {
            stagingTex->Release();
            dup->ReleaseFrame();
            dup->Release();
            continue;
        }

        UINT   w        = srcDesc.Width;
        UINT   h        = srcDesc.Height;
        UINT   rowBytes = w * 4;
        SIZE_T total    = (SIZE_T)rowBytes * h;
        BYTE*  copy     = (BYTE*)HeapAlloc(GetProcessHeap(), 0, total);
        if (copy) {
            const BYTE* src = (const BYTE*)mapped.pData;
            for (UINT y = 0; y < h; ++y) {
                memcpy(copy + (SIZE_T)y * rowBytes,
                       src  + (SIZE_T)y * mapped.RowPitch,
                       rowBytes);
            }

            if (gotCount < 16) {
                panels[gotCount].bgra   = copy;
                panels[gotCount].stride = rowBytes;
                panels[gotCount].left   = odesc.DesktopCoordinates.left;
                panels[gotCount].top    = odesc.DesktopCoordinates.top;
                panels[gotCount].right  = odesc.DesktopCoordinates.right;
                panels[gotCount].bottom = odesc.DesktopCoordinates.bottom;
                gotCount++;
                KGDBG(L"[capture] dxgi panel %u %ux%u @ (%d,%d)\n",
                      o, w, h,
                      (int)odesc.DesktopCoordinates.left,
                      (int)odesc.DesktopCoordinates.top);
            } else {
                HeapFree(GetProcessHeap(), 0, copy);
            }
        }

        ctx->Unmap(stagingTex, 0);
        stagingTex->Release();
        dup->ReleaseFrame();
        dup->Release();
    }

    adapter->Release();
    if (ctx) ctx->Release();
    device->Release();

    if (gotCount == 0) return false;

    INT32 uLeft = INT32_MAX, uTop = INT32_MAX;
    INT32 uRight = INT32_MIN, uBottom = INT32_MIN;
    for (UINT i = 0; i < gotCount; ++i) {
        if (panels[i].left   < uLeft)   uLeft   = panels[i].left;
        if (panels[i].top    < uTop)    uTop    = panels[i].top;
        if (panels[i].right  > uRight)  uRight  = panels[i].right;
        if (panels[i].bottom > uBottom) uBottom = panels[i].bottom;
    }
    UINT vw = (UINT)(uRight  - uLeft);
    UINT vh = (UINT)(uBottom - uTop);
    if (vw == 0 || vh == 0) {
        for (UINT i = 0; i < gotCount; ++i) HeapFree(GetProcessHeap(), 0, panels[i].bgra);
        return false;
    }

    SIZE_T totalOut = (SIZE_T)vw * vh * 4;
    BYTE*  out      = (BYTE*)HeapAlloc(GetProcessHeap(), 0, totalOut);
    if (!out) {
        for (UINT i = 0; i < gotCount; ++i) HeapFree(GetProcessHeap(), 0, panels[i].bgra);
        return false;
    }
    memset(out, 0, totalOut);
    UINT outStrideBytes = vw * 4;

    for (UINT i = 0; i < gotCount; ++i) {
        INT32 offX = panels[i].left - uLeft;
        INT32 offY = panels[i].top  - uTop;
        UINT  pw   = (UINT)(panels[i].right  - panels[i].left);
        UINT  ph   = (UINT)(panels[i].bottom - panels[i].top);
        for (UINT y = 0; y < ph; ++y) {
            const BYTE* srcRow = panels[i].bgra + (SIZE_T)y * panels[i].stride;
            BYTE*       dstRow = out + (SIZE_T)(offY + (INT32)y) * outStrideBytes + (SIZE_T)offX * 4;
            memcpy(dstRow, srcRow, (SIZE_T)pw * 4);
        }
        HeapFree(GetProcessHeap(), 0, panels[i].bgra);
    }

    SIZE_T px = totalOut / 4;
    for (SIZE_T i = 0; i < px; ++i) out[i * 4 + 3] = 0xFF;

    KGDBG(L"[capture] dxgi composed virtual %ux%u from %u panel(s)\n", vw, vh, gotCount);
    *outBgra   = out;
    *outW      = vw;
    *outH      = vh;
    *outStride = outStrideBytes;
    VIRTUALIZER_END
    return true;
}

typedef BOOL (WINAPI *pfnSetProcessDPIAware)(void);
typedef HRESULT (WINAPI *pfnSetProcessDpiAwareness)(int);
typedef BOOL (WINAPI *pfnSetProcessDpiAwarenessContext)(void*);

#define KG_DPI_CTX_PER_MONITOR_V2 ((void*)-4)

static
void
EnsureDpiAware(
)
{
    BRKIDA;
    static LONG done = 0;
    if (InterlockedCompareExchange(&done, 1, 0) != 0)
        return;

    HMODULE user32 = LI_KERNEL(GetModuleHandleW)(pxenc(L"user32.dll"));
    if (user32) {
        pfnSetProcessDpiAwarenessContext ctxFn =
            (pfnSetProcessDpiAwarenessContext)LI_KERNEL(GetProcAddress)(
                user32, pxenc("SetProcessDpiAwarenessContext"));
        if (ctxFn && ctxFn(KG_DPI_CTX_PER_MONITOR_V2))
            return;
    }

    HMODULE shcore = LI_KERNEL(LoadLibraryW)(pxenc(L"shcore.dll"));
    if (shcore) {
        pfnSetProcessDpiAwareness sFn =
            (pfnSetProcessDpiAwareness)LI_KERNEL(GetProcAddress)(
                shcore, pxenc("SetProcessDpiAwareness"));
        if (sFn && SUCCEEDED(sFn(2)))
            return;
    }

    if (user32) {
        pfnSetProcessDPIAware oldFn =
            (pfnSetProcessDPIAware)LI_KERNEL(GetProcAddress)(
                user32, pxenc("SetProcessDPIAware"));
        if (oldFn)
            oldFn();
    }
}

static
bool
CaptureGdi(
    BYTE** outBgra,
    UINT*  outW,
    UINT*  outH,
    UINT*  outStride
)
{
    BRKIDA;
    EnsureDpiAware();

    int vx = LI_USER32(GetSystemMetrics)(SM_XVIRTUALSCREEN);
    int vy = LI_USER32(GetSystemMetrics)(SM_YVIRTUALSCREEN);
    int vw = LI_USER32(GetSystemMetrics)(SM_CXVIRTUALSCREEN);
    int vh = LI_USER32(GetSystemMetrics)(SM_CYVIRTUALSCREEN);
    if (vw <= 0 || vh <= 0) {
        vx = 0;
        vy = 0;
        vw = LI_USER32(GetSystemMetrics)(SM_CXSCREEN);
        vh = LI_USER32(GetSystemMetrics)(SM_CYSCREEN);
    }
    if (vw <= 0 || vh <= 0 || vw > 32768 || vh > 32768)
        return false;

    KGDBG(L"[capture] virtual screen origin=%d,%d size=%dx%d\n", vx, vy, vw, vh);

    HDC hScreen = LI_USER32(GetDC)(NULL);
    if (!hScreen)
        return false;

    const int MAX_W = 2560;
    const int MAX_H = 1440;
    int dw = vw;
    int dh = vh;
    if (dw > MAX_W || dh > MAX_H) {
        double sx = (double)MAX_W / (double)vw;
        double sy = (double)MAX_H / (double)vh;
        double s  = (sx < sy) ? sx : sy;
        dw = (int)((double)vw * s);
        dh = (int)((double)vh * s);
        if (dw < 1) dw = 1;
        if (dh < 1) dh = 1;
        KGDBG(L"[capture] downscale %dx%d -> %dx%d (scale=%.3f)\n", vw, vh, dw, dh, s);
    }

    HDC     hMem = LI_GDI32(CreateCompatibleDC)(hScreen);
    HBITMAP hBmp = LI_GDI32(CreateCompatibleBitmap)(hScreen, dw, dh);
    HGDIOBJ old  = LI_GDI32(SelectObject)(hMem, hBmp);

    LI_GDI32(SetStretchBltMode)(hMem, HALFTONE);
    LI_GDI32(SetBrushOrgEx)(hMem, 0, 0, NULL);

    BOOL blitOk;
    if (dw == vw && dh == vh) {
        blitOk = LI_GDI32(BitBlt)(hMem, 0, 0, dw, dh, hScreen, vx, vy, SRCCOPY);
    } else {
        blitOk = LI_GDI32(StretchBlt)(hMem, 0, 0, dw, dh, hScreen, vx, vy, vw, vh, SRCCOPY);
    }

    BITMAPINFO bi = { 0 };
    bi.bmiHeader.biSize        = sizeof(BITMAPINFOHEADER);
    bi.bmiHeader.biWidth       = dw;
    bi.bmiHeader.biHeight      = -dh;
    bi.bmiHeader.biPlanes      = 1;
    bi.bmiHeader.biBitCount    = 32;
    bi.bmiHeader.biCompression = BI_RGB;

    UINT   stride = (UINT)dw * 4;
    SIZE_T total  = (SIZE_T)stride * dh;
    BYTE*  buf    = NULL;
    bool   ok     = false;
    if (blitOk && total > 0 && total < (SIZE_T)512 * 1024 * 1024) {
        buf = (BYTE*)HeapAlloc(GetProcessHeap(), 0, total);
        if (buf) {
            int lines = LI_GDI32(GetDIBits)(hMem, hBmp, 0, dh, buf, &bi, DIB_RGB_COLORS);
            ok = (lines == dh);
            if (ok) {
                SIZE_T px = total / 4;
                for (SIZE_T i = 0; i < px; i++)
                    buf[i * 4 + 3] = 0xFF;
            }
        }
    }

    LI_GDI32(SelectObject)(hMem, old);
    LI_GDI32(DeleteObject)(hBmp);
    LI_GDI32(DeleteDC)(hMem);
    LI_USER32(ReleaseDC)(NULL, hScreen);

    if (!ok) {
        if (buf)
            HeapFree(GetProcessHeap(), 0, buf);
        return false;
    }

    KGDBG(L"[capture] composed %dx%d\n", dw, dh);
    *outBgra   = buf;
    *outW      = (UINT)dw;
    *outH      = (UINT)dh;
    *outStride = stride;
    return true;
}

static SRWLOCK g_CaptureLock = SRWLOCK_INIT;

static
bool
CaptureNvidia(
    BYTE** outBgra,
    UINT*  outW,
    UINT*  outH,
    UINT*  outStride
)
{
    BRKIDA;
    if (!HasNvidiaGpu())
        return false;

    if (!CaptureNvidiaScanout(outBgra, outW, outH, outStride))
        return false;

    if (*outBgra && *outStride && *outH) {
        SIZE_T total = (SIZE_T)(*outStride) * (*outH);
        SIZE_T px    = total / 4;
        for (SIZE_T i = 0; i < px; i++)
            (*outBgra)[i * 4 + 3] = 0xFF;
    }
    return true;
}

static
bool
CaptureScreenshotBody(
    BYTE**  OutPng,
    ULONG*  OutPngLen,
    int     Method
)
{
    BYTE* bgra   = NULL;
    UINT  w      = 0, h = 0, stride = 0;

    bool got = false;

    if (Method == KG_CAPTURE_NVIDIA || Method == KG_CAPTURE_AUTO) {
        __try {
            got = CaptureNvidia(&bgra, &w, &h, &stride);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            KGDBG(L"[capture] SEH inside CaptureNvidia code=0x%08X\n", GetExceptionCode());
            got = false;
        }
        if (!got && Method == KG_CAPTURE_NVIDIA) {
            KGDBG(L"[capture] nvidia path failed (forced)\n");
            return false;
        }
        if (got) KGDBG(L"[capture] nvidia path ok\n");
    }

    if (!got && Method != KG_CAPTURE_GDI) {
        __try {
            got = CaptureDxgiDup(&bgra, &w, &h, &stride);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            KGDBG(L"[capture] SEH inside CaptureDxgiDup code=0x%08X\n", GetExceptionCode());
            got = false;
        }
        if (got) KGDBG(L"[capture] dxgi duplication path ok\n");
    }

    if (!got) {
        __try {
            got = CaptureGdi(&bgra, &w, &h, &stride);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            KGDBG(L"[capture] SEH inside CaptureGdi code=0x%08X\n", GetExceptionCode());
            got = false;
        }
    }

    if (!got) {
        KGDBG(L"[capture] all paths failed\n");
        return false;
    }

    if (w == 0 || h == 0 || w > 32768 || h > 32768 || stride < w * 4) {
        KGDBG(L"[capture] insane dims w=%u h=%u stride=%u\n", w, h, stride);
        if (bgra) HeapFree(GetProcessHeap(), 0, bgra);
        return false;
    }

    BYTE*   png    = NULL;
    ULONG   pngLen = 0;
    HRESULT hr     = E_FAIL;

    __try {
        hr = EncodePng(bgra, w, h, stride, &png, &pngLen);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        KGDBG(L"[capture] SEH inside EncodePng code=0x%08X\n", GetExceptionCode());
        hr     = E_FAIL;
        png    = NULL;
        pngLen = 0;
    }

    HeapFree(GetProcessHeap(), 0, bgra);

    if (FAILED(hr) || !png || pngLen == 0) {
        KGDBG(L"[capture] EncodePng failed hr=0x%08X\n", hr);
        if (png) HeapFree(GetProcessHeap(), 0, png);
        return false;
    }

    KGDBG(L"[capture] png ready %lu bytes\n", pngLen);
    *OutPng    = png;
    *OutPngLen = pngLen;
    return true;
}

bool
CaptureScreenshot(
    UINT64      SteamId64,
    const char* Reason,
    BYTE**      OutPng,
    ULONG*      OutPngLen,
    wchar_t*    OutPath,
    size_t      OutPathCap,
    int         Method
)
{
    BRKIDA;
    (void)SteamId64;
    (void)Reason;
    if (OutPath && OutPathCap)
        OutPath[0] = 0;

    if (!OutPng || !OutPngLen)
        return false;

    *OutPng    = NULL;
    *OutPngLen = 0;

    if (Method != KG_CAPTURE_NVIDIA && Method != KG_CAPTURE_GDI)
        Method = KG_CAPTURE_AUTO;

    if (!TryAcquireSRWLockExclusive(&g_CaptureLock)) {
        KGDBG(L"[capture] busy - another capture in flight, skipping\n");
        return false;
    }

    bool result = false;
    __try {
        result = CaptureScreenshotBody(OutPng, OutPngLen, Method);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        KGDBG(L"[capture] outer SEH code=0x%08X\n", GetExceptionCode());
        result = false;
        if (OutPng && *OutPng) {
            HeapFree(GetProcessHeap(), 0, *OutPng);
            *OutPng = NULL;
        }
        if (OutPngLen) *OutPngLen = 0;
    }

    ReleaseSRWLockExclusive(&g_CaptureLock);
    return result;
}

void
CaptureFree(
    BYTE* Png
)
{
    BRKIDA;
    if (Png)
        HeapFree(GetProcessHeap(), 0, Png);
}
