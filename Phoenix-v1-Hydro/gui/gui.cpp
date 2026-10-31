#include "gui.hpp"

#include "vendor/xor_string.hpp"

#include <Windows.h>
#include <d2d1.h>
#include <dwmapi.h>
#include <dwrite.h>
#include <objbase.h>

#include <atomic>
#include <cmath>
#include <string>

#pragma comment(lib, "d2d1.lib")
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "dwrite.lib")
#pragma comment(lib, "ole32.lib")

namespace gui
{
    namespace
    {
        const wchar_t* window_class_name() { return XSW(L"PhoenixACGui"); }

        constexpr int k_width  = 400;
        constexpr int k_height = 440;

        constexpr float k_accent_stripe_h = 1.5f;
        constexpr float k_logo_y          = 56.f;
        constexpr float k_sub_y           = 96.f;
        constexpr float k_top_div_y       = 126.f;
        constexpr float k_card_x          = 22.f;
        constexpr float k_card_y          = 146.f;
        constexpr float k_card_r          = 10.f;
        constexpr float k_status_cy       = 232.f;
        constexpr float k_detail_y        = 275.f;
        constexpr float k_footer_div_y    = 390.f;
        constexpr float k_footer_cy       = 412.f;
        constexpr float k_fw              = static_cast<float>(k_width);
        constexpr float k_fh              = static_cast<float>(k_height);

        constexpr D2D1_COLOR_F k_bg          = { 0.023f, 0.023f, 0.040f, 1.f };
        constexpr D2D1_COLOR_F k_accent      = { 1.000f, 0.376f, 0.055f, 1.f };
        constexpr D2D1_COLOR_F k_text_hi     = { 0.950f, 0.943f, 0.926f, 1.f };
        constexpr D2D1_COLOR_F k_text_mid    = { 0.950f, 0.943f, 0.926f, 0.44f };
        constexpr D2D1_COLOR_F k_text_lo     = { 0.950f, 0.943f, 0.926f, 0.20f };
        constexpr D2D1_COLOR_F k_divider     = { 0.950f, 0.943f, 0.926f, 0.055f };
        constexpr D2D1_COLOR_F k_danger      = { 0.929f, 0.247f, 0.247f, 1.f };
        constexpr D2D1_COLOR_F k_window_bd   = { 0.950f, 0.943f, 0.926f, 0.065f };
        constexpr D2D1_COLOR_F k_card_bg     = { 0.950f, 0.943f, 0.926f, 0.028f };
        constexpr D2D1_COLOR_F k_card_bd     = { 0.950f, 0.943f, 0.926f, 0.085f };

        constexpr int k_btn_top  = 10;
        constexpr int k_btn_bot  = 34;
        constexpr int k_close_l  = k_width - 44;
        constexpr int k_close_r  = k_width - 14;
        constexpr int k_min_l    = k_width - 84;
        constexpr int k_min_r    = k_width - 54;

        HWND      g_hwnd     = nullptr;
        HINSTANCE g_instance = nullptr;

        ID2D1Factory*          g_d2d = nullptr;
        ID2D1HwndRenderTarget* g_rt  = nullptr;
        IDWriteFactory*        g_dw  = nullptr;

        IDWriteTextFormat* g_fmt_logo   = nullptr;
        IDWriteTextFormat* g_fmt_sub    = nullptr;
        IDWriteTextFormat* g_fmt_status = nullptr;
        IDWriteTextFormat* g_fmt_detail = nullptr;
        IDWriteTextFormat* g_fmt_footer = nullptr;

        ID2D1SolidColorBrush*     g_br_accent    = nullptr;
        ID2D1SolidColorBrush*     g_br_bg        = nullptr;
        ID2D1SolidColorBrush*     g_br_text_hi   = nullptr;
        ID2D1SolidColorBrush*     g_br_text_mid  = nullptr;
        ID2D1SolidColorBrush*     g_br_text_lo   = nullptr;
        ID2D1SolidColorBrush*     g_br_danger    = nullptr;
        ID2D1SolidColorBrush*     g_br_divider   = nullptr;
        ID2D1SolidColorBrush*     g_br_window_bd = nullptr;
        ID2D1SolidColorBrush*     g_br_card_bg   = nullptr;
        ID2D1SolidColorBrush*     g_br_card_bd   = nullptr;
        ID2D1RadialGradientBrush* g_br_glow      = nullptr;

        std::atomic<state> g_state{ state::waiting_for_fivem };
        std::wstring       g_detail;
        UINT               g_tick         = 0;
        int                g_hover_button = 0;

        template <typename T>
        void release(T*& p) { if (p) { p->Release(); p = nullptr; } }

        void discard_device()
        {
            release(g_br_glow);
            release(g_br_card_bd);
            release(g_br_card_bg);
            release(g_br_window_bd);
            release(g_br_divider);
            release(g_br_danger);
            release(g_br_text_lo);
            release(g_br_text_mid);
            release(g_br_text_hi);
            release(g_br_accent);
            release(g_br_bg);
            release(g_rt);
        }

        HRESULT create_device()
        {
            if (g_rt)
                return S_OK;

            RECT rc{};
            GetClientRect(g_hwnd, &rc);
            const D2D1_SIZE_U sz = D2D1::SizeU(rc.right - rc.left, rc.bottom - rc.top);

            HRESULT hr = g_d2d->CreateHwndRenderTarget(
                D2D1::RenderTargetProperties(),
                D2D1::HwndRenderTargetProperties(g_hwnd, sz), &g_rt);
            if (FAILED(hr))
                return hr;

            g_rt->SetAntialiasMode(D2D1_ANTIALIAS_MODE_PER_PRIMITIVE);
            g_rt->SetTextAntialiasMode(D2D1_TEXT_ANTIALIAS_MODE_GRAYSCALE);

            g_rt->CreateSolidColorBrush(k_accent,    &g_br_accent);
            g_rt->CreateSolidColorBrush(k_bg,        &g_br_bg);
            g_rt->CreateSolidColorBrush(k_text_hi,   &g_br_text_hi);
            g_rt->CreateSolidColorBrush(k_text_mid,  &g_br_text_mid);
            g_rt->CreateSolidColorBrush(k_text_lo,   &g_br_text_lo);
            g_rt->CreateSolidColorBrush(k_danger,    &g_br_danger);
            g_rt->CreateSolidColorBrush(k_divider,   &g_br_divider);
            g_rt->CreateSolidColorBrush(k_window_bd, &g_br_window_bd);
            g_rt->CreateSolidColorBrush(k_card_bg,   &g_br_card_bg);
            g_rt->CreateSolidColorBrush(k_card_bd,   &g_br_card_bd);

            const D2D1_GRADIENT_STOP stops[2] = {
                { 0.f, { 1.000f, 0.376f, 0.055f, 0.090f } },
                { 1.f, { 0.023f, 0.023f, 0.040f, 0.000f } },
            };
            ID2D1GradientStopCollection* col = nullptr;
            if (SUCCEEDED(g_rt->CreateGradientStopCollection(stops, 2, &col)))
            {
                g_rt->CreateRadialGradientBrush(
                    D2D1::RadialGradientBrushProperties(
                        D2D1::Point2F(k_fw * 0.5f, 0.f),
                        D2D1::Point2F(0.f, 0.f),
                        k_fw * 0.60f, k_fw * 0.48f),
                    col, &g_br_glow);
                col->Release();
            }

            return S_OK;
        }

        void draw_spinner(float cx, float cy, float r)
        {
            g_rt->DrawEllipse(D2D1::Ellipse(D2D1::Point2F(cx, cy), r, r),
                              g_br_divider, 1.2f);

            const float a0    = static_cast<float>(g_tick) * 0.14f;
            const float sweep = 5.0f;
            const float a1    = a0 + sweep;
            const float sx    = cx + r * cosf(a0);
            const float sy    = cy + r * sinf(a0);
            const float ex    = cx + r * cosf(a1);
            const float ey    = cy + r * sinf(a1);

            ID2D1PathGeometry* path = nullptr;
            if (FAILED(g_d2d->CreatePathGeometry(&path)))
                return;
            ID2D1GeometrySink* sink = nullptr;
            if (FAILED(path->Open(&sink))) { path->Release(); return; }

            sink->BeginFigure(D2D1::Point2F(sx, sy), D2D1_FIGURE_BEGIN_HOLLOW);
            D2D1_ARC_SEGMENT arc{};
            arc.point          = D2D1::Point2F(ex, ey);
            arc.size           = D2D1::SizeF(r, r);
            arc.sweepDirection = D2D1_SWEEP_DIRECTION_CLOCKWISE;
            arc.arcSize        = D2D1_ARC_SIZE_LARGE;
            sink->AddArc(arc);
            sink->EndFigure(D2D1_FIGURE_END_OPEN);
            sink->Close();
            sink->Release();

            g_rt->DrawGeometry(path, g_br_accent, 2.4f);
            path->Release();
        }

        void draw_window_buttons()
        {
            const float btn_cy   = (k_btn_top + k_btn_bot) * 0.5f;
            const float min_cx   = (k_min_l + k_min_r) * 0.5f;
            const float close_cx = (k_close_l + k_close_r) * 0.5f;

            if (g_hover_button == 1)
            {
                g_rt->FillRoundedRectangle(
                    { { static_cast<float>(k_min_l), static_cast<float>(k_btn_top),
                        static_cast<float>(k_min_r),  static_cast<float>(k_btn_bot) }, 3.f, 3.f },
                    g_br_divider);
            }
            else if (g_hover_button == 2)
            {
                g_br_accent->SetOpacity(0.18f);
                g_rt->FillRoundedRectangle(
                    { { static_cast<float>(k_close_l), static_cast<float>(k_btn_top),
                        static_cast<float>(k_close_r),  static_cast<float>(k_btn_bot) }, 3.f, 3.f },
                    g_br_accent);
                g_br_accent->SetOpacity(1.f);
            }

            ID2D1Brush* close_brush = (g_hover_button == 2) ? g_br_text_hi : g_br_text_lo;

            g_rt->DrawLine(D2D1::Point2F(min_cx - 5.f, btn_cy + 4.f),
                           D2D1::Point2F(min_cx + 5.f, btn_cy + 4.f),
                           g_br_text_lo, 1.2f);
            g_rt->DrawLine(D2D1::Point2F(close_cx - 5.f, btn_cy - 5.f),
                           D2D1::Point2F(close_cx + 5.f, btn_cy + 5.f),
                           close_brush, 1.2f);
            g_rt->DrawLine(D2D1::Point2F(close_cx + 5.f, btn_cy - 5.f),
                           D2D1::Point2F(close_cx - 5.f, btn_cy + 5.f),
                           close_brush, 1.2f);
        }

        void draw_background()
        {
            g_rt->FillRectangle({ 0.f, 0.f, k_fw, k_fh }, g_br_bg);
            if (g_br_glow)
                g_rt->FillRectangle({ 0.f, 0.f, k_fw, k_fh * 0.55f }, g_br_glow);
            g_rt->FillRectangle({ 0.f, 0.f, k_fw, k_accent_stripe_h }, g_br_accent);
        }

        void draw_header()
        {
            IDWriteTextLayout* l_phoenix = nullptr;
            IDWriteTextLayout* l_ac      = nullptr;

            g_dw->CreateTextLayout(XSW(L"PHOENIX"), 7, g_fmt_logo, 400.f, 44.f, &l_phoenix);
            g_dw->CreateTextLayout(XSW(L" AC"),     3, g_fmt_logo, 200.f, 44.f, &l_ac);

            if (l_phoenix && l_ac)
            {
                DWRITE_TEXT_METRICS m1{}, m2{};
                l_phoenix->GetMetrics(&m1);
                l_ac->GetMetrics(&m2);

                const float total = m1.widthIncludingTrailingWhitespace + m2.width;
                const float x0    = (k_fw - total) * 0.5f;

                g_rt->DrawTextLayout(D2D1::Point2F(x0, k_logo_y), l_phoenix, g_br_text_hi);
                g_rt->DrawTextLayout(
                    D2D1::Point2F(x0 + m1.widthIncludingTrailingWhitespace, k_logo_y),
                    l_ac, g_br_accent);
            }

            release(l_phoenix);
            release(l_ac);

            g_rt->DrawText(XSW(L"A N T I - C H E A T   S Y S T E M"), 33, g_fmt_sub,
                           { 0.f, k_sub_y, k_fw, k_sub_y + 18.f }, g_br_text_mid);

            g_rt->DrawLine(D2D1::Point2F(36.f, k_top_div_y),
                           D2D1::Point2F(k_fw - 36.f, k_top_div_y),
                           g_br_divider, 1.f);
        }

        void draw_status()
        {
            const float card_right  = k_fw - k_card_x;
            const float card_bottom = k_fh - 56.f;
            g_rt->FillRoundedRectangle(
                { { k_card_x, k_card_y, card_right, card_bottom }, k_card_r, k_card_r },
                g_br_card_bg);
            g_rt->DrawRoundedRectangle(
                { { k_card_x + 0.5f, k_card_y + 0.5f,
                    card_right - 0.5f, card_bottom - 0.5f }, k_card_r, k_card_r },
                g_br_card_bd, 1.f);

            const state st         = g_state.load();
            const bool  is_waiting = (st == state::waiting_for_fivem);
            const bool  is_running = (st == state::running);
            const bool  is_closing = (st == state::closing);

            constexpr float spinner_r = 18.f;
            constexpr float gap       = 14.f;
            constexpr float text_half = 13.f;

            auto draw_fivem_spinner = [&](const wchar_t* prefix, int prefix_len,
                                          const wchar_t* suffix, int suffix_len)
            {
                IDWriteTextLayout* l1 = nullptr;
                IDWriteTextLayout* l2 = nullptr;
                IDWriteTextLayout* l3 = nullptr;

                g_dw->CreateTextLayout(prefix,          prefix_len, g_fmt_status, 500.f, 60.f, &l1);
                g_dw->CreateTextLayout(XSW(L"FiveM"),            5, g_fmt_status, 300.f, 60.f, &l2);
                g_dw->CreateTextLayout(suffix,          suffix_len, g_fmt_status,  60.f, 60.f, &l3);

                if (l1 && l2 && l3)
                {
                    DWRITE_TEXT_METRICS m1{}, m2{}, m3{};
                    l1->GetMetrics(&m1);
                    l2->GetMetrics(&m2);
                    l3->GetMetrics(&m3);

                    const float text_w = m1.widthIncludingTrailingWhitespace + m2.width + m3.width;
                    const float total  = spinner_r * 2.f + gap + text_w;
                    const float sx     = (k_fw - total) * 0.5f;
                    const float dot_x  = sx + spinner_r;
                    const float text_y = k_status_cy - text_half;
                    float       px     = sx + spinner_r * 2.f + gap;

                    draw_spinner(dot_x, k_status_cy, spinner_r);

                    g_rt->DrawTextLayout(D2D1::Point2F(px, text_y), l1, g_br_text_hi);
                    px += m1.widthIncludingTrailingWhitespace;
                    g_rt->DrawTextLayout(D2D1::Point2F(px, text_y), l2, g_br_accent);
                    px += m2.width;
                    g_rt->DrawTextLayout(D2D1::Point2F(px, text_y), l3, g_br_text_hi);
                }

                release(l1);
                release(l2);
                release(l3);
            };

            if (is_waiting)
            {
                draw_fivem_spinner(XSW(L"Waiting for "), 12, XSW(L"."), 1);
            }
            else if (is_closing)
            {
                draw_fivem_spinner(XSW(L"Searching for "), 14, XSW(L"..."), 3);
            }
            else if (is_running)
            {
                IDWriteTextLayout* layout = nullptr;
                g_dw->CreateTextLayout(XSW(L"Protection active"), 18, g_fmt_status,
                                       300.f, 60.f, &layout);
                if (layout)
                {
                    DWRITE_TEXT_METRICS m{};
                    layout->GetMetrics(&m);

                    const float text_w = m.widthIncludingTrailingWhitespace;
                    const float total  = spinner_r * 2.f + gap + text_w;
                    const float sx     = (k_fw - total) * 0.5f;
                    const float dot_x  = sx + spinner_r;
                    const float pulse  = 0.5f + 0.5f * sinf(static_cast<float>(g_tick) * 0.09f);

                    g_br_accent->SetOpacity(0.05f + pulse * 0.09f);
                    g_rt->FillEllipse(
                        D2D1::Ellipse(D2D1::Point2F(dot_x, k_status_cy),
                                      11.f + pulse * 7.f, 11.f + pulse * 7.f),
                        g_br_accent);
                    g_br_accent->SetOpacity(1.f);
                    g_rt->FillEllipse(
                        D2D1::Ellipse(D2D1::Point2F(dot_x, k_status_cy), 5.f, 5.f),
                        g_br_accent);

                    g_rt->DrawTextLayout(
                        D2D1::Point2F(sx + spinner_r * 2.f + gap, k_status_cy - text_half),
                        layout, g_br_accent);
                    layout->Release();
                }
            }
            else
            {
                IDWriteTextLayout* layout = nullptr;
                g_dw->CreateTextLayout(XSW(L"Error"), 5, g_fmt_status, k_fw, 60.f, &layout);
                if (layout)
                {
                    DWRITE_TEXT_METRICS m{};
                    layout->GetMetrics(&m);

                    const float total = spinner_r * 2.f + gap + m.width;
                    const float sx    = (k_fw - total) * 0.5f;
                    const float dot_x = sx + spinner_r;

                    g_rt->FillEllipse(
                        D2D1::Ellipse(D2D1::Point2F(dot_x, k_status_cy), 6.f, 6.f),
                        g_br_danger);
                    g_rt->DrawTextLayout(
                        D2D1::Point2F(sx + spinner_r * 2.f + gap, k_status_cy - text_half),
                        layout, g_br_danger);
                    layout->Release();
                }
            }

            if (!g_detail.empty() && !is_running && !is_closing)
            {
                g_rt->DrawText(g_detail.c_str(), static_cast<UINT32>(g_detail.size()),
                               g_fmt_detail,
                               { 36.f, k_detail_y, k_fw - 36.f, k_detail_y + 22.f },
                               g_br_text_lo);
            }
        }

        void draw_footer()
        {
            g_rt->DrawLine(D2D1::Point2F(36.f, k_footer_div_y),
                           D2D1::Point2F(k_fw - 36.f, k_footer_div_y),
                           g_br_divider, 1.f);

            g_rt->DrawText(XSW(L"PHOENIX AC  |  v1.0"), 19, g_fmt_footer,
                           { 0.f, k_footer_cy - 10.f, k_fw, k_footer_cy + 10.f },
                           g_br_text_lo);
        }

        void draw_window_border()
        {
            g_rt->DrawRoundedRectangle(
                { { 0.5f, 0.5f, k_fw - 0.5f, k_fh - 0.5f }, 8.f, 8.f },
                g_br_window_bd, 1.f);
        }

        void on_paint()
        {
            if (FAILED(create_device()))
                return;

            g_rt->BeginDraw();
            g_rt->Clear(k_bg);
            draw_background();
            draw_header();
            draw_status();
            draw_footer();
            draw_window_buttons();
            draw_window_border();

            if (g_rt->EndDraw() == D2DERR_RECREATE_TARGET)
                discard_device();
        }

        int hit_button(int x, int y)
        {
            if (y < k_btn_top || y >= k_btn_bot) return 0;
            if (x >= k_min_l   && x < k_min_r)  return 1;
            if (x >= k_close_l && x < k_close_r) return 2;
            return 0;
        }

        LRESULT CALLBACK wnd_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
        {
            switch (msg)
            {
            case WM_SIZE:
                if (g_rt)
                {
                    RECT rc{};
                    GetClientRect(hwnd, &rc);
                    g_rt->Resize(D2D1::SizeU(rc.right - rc.left, rc.bottom - rc.top));
                }
                return 0;

            case WM_PAINT:
            {
                PAINTSTRUCT ps{};
                BeginPaint(hwnd, &ps);
                on_paint();
                EndPaint(hwnd, &ps);
                return 0;
            }

            case WM_TIMER:
                ++g_tick;
                InvalidateRect(hwnd, nullptr, FALSE);
                return 0;

            case WM_NCHITTEST:
            {
                POINT pt{ static_cast<SHORT>(LOWORD(lp)), static_cast<SHORT>(HIWORD(lp)) };
                ScreenToClient(hwnd, &pt);
                if (hit_button(pt.x, pt.y))
                    return HTCLIENT;
                if (pt.y < k_height - 24)
                    return HTCAPTION;
                return HTCLIENT;
            }

            case WM_MOUSEMOVE:
            {
                const int btn = hit_button(LOWORD(lp), HIWORD(lp));
                if (btn != g_hover_button)
                {
                    g_hover_button = btn;
                    InvalidateRect(hwnd, nullptr, FALSE);
                    if (btn)
                    {
                        TRACKMOUSEEVENT tme{ sizeof(tme), TME_LEAVE, hwnd, 0 };
                        TrackMouseEvent(&tme);
                    }
                }
                return 0;
            }

            case WM_MOUSELEAVE:
                if (g_hover_button)
                {
                    g_hover_button = 0;
                    InvalidateRect(hwnd, nullptr, FALSE);
                }
                return 0;

            case WM_LBUTTONUP:
            {
                const int btn = hit_button(LOWORD(lp), HIWORD(lp));
                if (btn == 1)      ShowWindow(hwnd, SW_MINIMIZE);
                else if (btn == 2) PostMessageW(hwnd, WM_CLOSE, 0, 0);
                return 0;
            }

            case WM_DESTROY:
                KillTimer(hwnd, 1);
                PostQuitMessage(0);
                return 0;

            case WM_ERASEBKGND:
                return 1;
            }

            return DefWindowProcW(hwnd, msg, wp, lp);
        }

        void apply_chrome(HWND hwnd)
        {
            BOOL dark = TRUE;
            DwmSetWindowAttribute(hwnd, 20, &dark, sizeof(dark));
            int corner = 2;
            DwmSetWindowAttribute(hwnd, 33, &corner, sizeof(corner));
            COLORREF bd = RGB(8, 8, 16);
            DwmSetWindowAttribute(hwnd, 34, &bd, sizeof(bd));
        }

        void make_fmt(const wchar_t* family, float size, DWRITE_FONT_WEIGHT weight,
                      IDWriteTextFormat** out,
                      DWRITE_TEXT_ALIGNMENT h, DWRITE_PARAGRAPH_ALIGNMENT v)
        {
            g_dw->CreateTextFormat(family, nullptr, weight,
                                   DWRITE_FONT_STYLE_NORMAL, DWRITE_FONT_STRETCH_NORMAL,
                                   size, XSW(L"en-us"), out);
            if (*out)
            {
                (*out)->SetTextAlignment(h);
                (*out)->SetParagraphAlignment(v);
            }
        }
    }

    bool create(HINSTANCE instance)
    {
        g_instance = instance;
        CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);

        D2D1CreateFactory(D2D1_FACTORY_TYPE_SINGLE_THREADED, &g_d2d);
        if (!g_d2d) return false;

        DWriteCreateFactory(DWRITE_FACTORY_TYPE_SHARED, __uuidof(IDWriteFactory),
                            reinterpret_cast<IUnknown**>(&g_dw));
        if (!g_dw) return false;

        make_fmt(XSW(L"Bahnschrift"), 27.f, DWRITE_FONT_WEIGHT_SEMI_BOLD, &g_fmt_logo,
                 DWRITE_TEXT_ALIGNMENT_LEADING, DWRITE_PARAGRAPH_ALIGNMENT_NEAR);
        make_fmt(XSW(L"Segoe UI"), 8.5f, DWRITE_FONT_WEIGHT_NORMAL, &g_fmt_sub,
                 DWRITE_TEXT_ALIGNMENT_CENTER, DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
        make_fmt(XSW(L"Segoe UI"), 20.f, DWRITE_FONT_WEIGHT_SEMI_BOLD, &g_fmt_status,
                 DWRITE_TEXT_ALIGNMENT_LEADING, DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
        make_fmt(XSW(L"Segoe UI"), 10.5f, DWRITE_FONT_WEIGHT_NORMAL, &g_fmt_detail,
                 DWRITE_TEXT_ALIGNMENT_CENTER, DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
        make_fmt(XSW(L"Segoe UI"), 8.5f, DWRITE_FONT_WEIGHT_NORMAL, &g_fmt_footer,
                 DWRITE_TEXT_ALIGNMENT_CENTER, DWRITE_PARAGRAPH_ALIGNMENT_CENTER);

        WNDCLASSEXW wc{};
        wc.cbSize        = sizeof(wc);
        wc.style         = CS_HREDRAW | CS_VREDRAW;
        wc.lpfnWndProc   = wnd_proc;
        wc.hInstance     = instance;
        wc.hCursor       = LoadCursorW(nullptr, IDC_ARROW);
        wc.lpszClassName = window_class_name();
        RegisterClassExW(&wc);

        const int sw = GetSystemMetrics(SM_CXSCREEN);
        const int sh = GetSystemMetrics(SM_CYSCREEN);

        g_hwnd = CreateWindowExW(WS_EX_APPWINDOW, window_class_name(),
                                 XSW(L"Phoenix AC"),
                                 WS_POPUP | WS_MINIMIZEBOX | WS_SYSMENU,
                                 (sw - k_width) / 2, (sh - k_height) / 2,
                                 k_width, k_height,
                                 nullptr, nullptr, instance, nullptr);
        if (!g_hwnd) return false;

        apply_chrome(g_hwnd);
        ShowWindow(g_hwnd, SW_SHOW);
        UpdateWindow(g_hwnd);
        SetTimer(g_hwnd, 1, 50, nullptr);
        return true;
    }

    void set_status(state s)
    {
        g_state.store(s);
        if (g_hwnd) InvalidateRect(g_hwnd, nullptr, FALSE);
    }

    void set_detail(const wchar_t* text)
    {
        g_detail = text ? text : XSW(L"");
        if (g_hwnd) InvalidateRect(g_hwnd, nullptr, FALSE);
    }

    void set_security(security_flags) {}

    int run_loop()
    {
        MSG msg{};
        while (GetMessageW(&msg, nullptr, 0, 0) > 0)
        {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }

        discard_device();
        release(g_fmt_footer);
        release(g_fmt_detail);
        release(g_fmt_status);
        release(g_fmt_sub);
        release(g_fmt_logo);
        release(g_dw);
        release(g_d2d);

        CoUninitialize();
        return static_cast<int>(msg.wParam);
    }

    void request_close()
    {
        if (g_hwnd) PostMessageW(g_hwnd, WM_CLOSE, 0, 0);
    }
}
