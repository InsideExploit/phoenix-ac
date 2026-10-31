#include "overlay.hpp"
#include "vendor/lazy_importer.hpp"
#include "vendor/xor_string.hpp"
#include <TlHelp32.h>
#include <dwmapi.h>
#include <psapi.h>
#include <algorithm>
#include <cwchar>
#include <cwctype>
#include <string>
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "dwmapi.lib")
namespace detections::overlay
{
    namespace
    {
        std::wstring to_lower(std::wstring s)
        {
            std::transform(s.begin(), s.end(), s.begin(),
                           [](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); });
            return s;
        }

        bool contains_lower(const wchar_t* const* list, size_t count, const std::wstring& lower)
        {
            for (size_t i = 0; i < count; ++i)
            {
                if (list[i] && *list[i] && lower.find(list[i]) != std::wstring::npos)
                    return true;
            }
            return false;
        }

        LONG rect_area(const RECT& r)
        {
            const LONG w = (std::max)(0L, r.right - r.left);
            const LONG h = (std::max)(0L, r.bottom - r.top);
            return w * h;
        }

        LONG intersection_area(const RECT& a, const RECT& b)
        {
            const LONG left   = (std::max)(a.left, b.left);
            const LONG top    = (std::max)(a.top, b.top);
            const LONG right  = (std::min)(a.right, b.right);
            const LONG bottom = (std::min)(a.bottom, b.bottom);
            if (right <= left || bottom <= top)
                return 0;
            return (right - left) * (bottom - top);
        }

        DWORD find_pid_by_exe(const wchar_t* exe, std::wstring* out_name)
        {
            HANDLE snapshot = LI_KERNEL(CreateToolhelp32Snapshot)(TH32CS_SNAPPROCESS, 0);
            if (snapshot == INVALID_HANDLE_VALUE)
                return 0;

            PROCESSENTRY32W pe{};
            pe.dwSize = sizeof(pe);
            DWORD pid = 0;

            if (LI_KERNEL(Process32FirstW)(snapshot, &pe))
            {
                do
                {
                    if (_wcsicmp(pe.szExeFile, exe) == 0)
                    {
                        pid = pe.th32ProcessID;
                        if (out_name)
                            *out_name = pe.szExeFile;
                        break;
                    }
                } while (LI_KERNEL(Process32NextW)(snapshot, &pe));
            }

            LI_KERNEL(CloseHandle)(snapshot);
            return pid;
        }

        void get_process_name_by_pid(DWORD pid, wchar_t* out, size_t out_capacity)
        {
            if (!out || !out_capacity)
                return;
            out[0] = L'\0';

            HANDLE snapshot = LI_KERNEL(CreateToolhelp32Snapshot)(TH32CS_SNAPPROCESS, 0);
            if (snapshot == INVALID_HANDLE_VALUE)
                return;

            PROCESSENTRY32W pe{};
            pe.dwSize = sizeof(pe);

            if (LI_KERNEL(Process32FirstW)(snapshot, &pe))
            {
                do
                {
                    if (pe.th32ProcessID == pid)
                    {
                        wcsncpy_s(out, out_capacity, pe.szExeFile, _TRUNCATE);
                        break;
                    }
                } while (LI_KERNEL(Process32NextW)(snapshot, &pe));
            }

            LI_KERNEL(CloseHandle)(snapshot);
        }
    }

    DWORD find_fivem_gta_pid(std::wstring* out_exe_name)
    {
        static const wchar_t* const k_candidates[] = {
            XSW(L"FiveM_GTAProcess.exe"),
            XSW(L"FiveM_b2802_GTAProcess.exe"),
            XSW(L"FiveM_b2944_GTAProcess.exe"),
            XSW(L"FiveM_b3095_GTAProcess.exe"),
            XSW(L"FiveM_b3258_GTAProcess.exe"),
            XSW(L"FiveM_b3407_GTAProcess.exe"),
            XSW(L"FiveM_b3570_GTAProcess.exe"),
            XSW(L"FiveM.exe"),
            XSW(L"GTA5.exe"),
        };
        for (auto* candidate : k_candidates)
        {
            if (const DWORD pid = find_pid_by_exe(candidate, out_exe_name))
                return pid;
        }
        return 0;
    }

    HWND find_fivem_game_window(DWORD fivem_pid)
    {
        if (!fivem_pid)
            return nullptr;

        struct context { DWORD pid; HWND window; LONG area; };
        context ctx{ fivem_pid, nullptr, 0 };

        LI_USER32(EnumWindows)([](HWND hwnd, LPARAM lparam) -> BOOL {
            auto* ctx_ptr = reinterpret_cast<context*>(lparam);

            DWORD pid = 0;
            LI_USER32(GetWindowThreadProcessId)(hwnd, &pid);
            if (pid != ctx_ptr->pid)
                return TRUE;
            if (!LI_USER32(IsWindowVisible)(hwnd))
                return TRUE;

            RECT rect{};
            if (!GetWindowRect(hwnd, &rect))
                return TRUE;

            const LONG area = rect_area(rect);
            if (area > ctx_ptr->area)
            {
                ctx_ptr->area = area;
                ctx_ptr->window = hwnd;
            }
            return TRUE;
        }, reinterpret_cast<LPARAM>(&ctx));

        return ctx.window;
    }

    bool is_allowlisted_exe(const wchar_t* exe_file)
    {
        if (!exe_file || !*exe_file)
            return false;

        const std::wstring lower = to_lower(exe_file);

        static const wchar_t* const k_allowed[] = {
            XSW(L"fivem.exe"), XSW(L"fivem_gtaprocess.exe"),
            XSW(L"fivem_b2802_gtaprocess.exe"), XSW(L"fivem_b2944_gtaprocess.exe"),
            XSW(L"fivem_b3095_gtaprocess.exe"), XSW(L"fivem_b3258_gtaprocess.exe"),
            XSW(L"fivem_b3407_gtaprocess.exe"), XSW(L"fivem_b3570_gtaprocess.exe"),
            XSW(L"gta5.exe"),
            XSW(L"discord.exe"), XSW(L"discordcanary.exe"), XSW(L"discordptb.exe"),
            XSW(L"steam.exe"), XSW(L"steamwebhelper.exe"), XSW(L"gameoverlayui.exe"),
            XSW(L"nvcontainer.exe"), XSW(L"nvidia share.exe"),
            XSW(L"nvidia geforce experience.exe"), XSW(L"nvidia overlay.exe"),
            XSW(L"nvidia broadcast ui.exe"),
            XSW(L"rtss.exe"), XSW(L"rivatuner statistics server.exe"), XSW(L"msiafterburner.exe"),
            XSW(L"obs64.exe"), XSW(L"obs32.exe"), XSW(L"streamlabs obs.exe"),
            XSW(L"medal.exe"), XSW(L"overwolf.exe"),
            XSW(L"xboxappservices.exe"), XSW(L"gamebar.exe"), XSW(L"gamebarftserver.exe"),
            XSW(L"applicationframehost.exe"),
            XSW(L"corsair.service.exe"), XSW(L"icue.exe"), XSW(L"ghub.exe"), XSW(L"lghub.exe"),
            XSW(L"razer synapse.exe"), XSW(L"synapse3.exe"),
            XSW(L"textinputhost.exe"), XSW(L"ctfmon.exe"),
            XSW(L"searchhost.exe"), XSW(L"searchapp.exe"),
            XSW(L"startmenuexperiencehost.exe"), XSW(L"shellexperiencehost.exe"),
            XSW(L"dwm.exe"), XSW(L"explorer.exe"),
            XSW(L"wallpaper32.exe"), XSW(L"wallpaper64.exe"),
            XSW(L"powertoys.exe"), XSW(L"powertoys.peek.ui.exe"), XSW(L"powertoys.fancyzones.exe"),
            XSW(L"snippingtool.exe"), XSW(L"screenclippinghost.exe"),
            XSW(L"taskmgr.exe"),
            XSW(L"securityhealthsystray.exe"), XSW(L"runtimebroker.exe"),
        };

        return contains_lower(k_allowed, sizeof(k_allowed) / sizeof(k_allowed[0]), lower);
    }

    bool is_allowlisted_process(DWORD pid)
    {
        wchar_t name[260]{};
        get_process_name_by_pid(pid, name, 260);
        return is_allowlisted_exe(name);
    }

    std::vector<hit> scan(const config& cfg)
    {
        std::vector<hit> best;

        DWORD fivem_pid = cfg.fivem_pid;
        if (!fivem_pid)
            fivem_pid = find_fivem_gta_pid();
        if (!fivem_pid)
            return best;

        const HWND game_window = find_fivem_game_window(fivem_pid);
        RECT game_rect{};
        const bool have_game = game_window && GetWindowRect(game_window, &game_rect);

        struct enum_context
        {
            const config*   cfg;
            DWORD           fivem_pid;
            DWORD           self_pid;
            bool            have_game;
            RECT            game_rect;
            std::vector<hit>* results;
        };

        std::vector<hit> hits;
        enum_context ctx{ &cfg, fivem_pid, LI_KERNEL(GetCurrentProcessId)(), have_game, game_rect, &hits };

        LI_USER32(EnumWindows)([](HWND hwnd, LPARAM lparam) -> BOOL {
            auto* c = reinterpret_cast<enum_context*>(lparam);

            if (!LI_USER32(IsWindowVisible)(hwnd))
                return TRUE;

            DWORD pid = 0;
            LI_USER32(GetWindowThreadProcessId)(hwnd, &pid);
            if (pid == 0)                              return TRUE;
            if (pid == c->fivem_pid)                   return TRUE;
            if (pid == c->self_pid)                    return TRUE;
            if (c->cfg->ignore_pid && pid == c->cfg->ignore_pid)
                return TRUE;

            const LONG_PTR ex_style = GetWindowLongPtrW(hwnd, GWL_EXSTYLE);
            const bool layered     = (ex_style & WS_EX_LAYERED)     != 0;
            const bool transparent = (ex_style & WS_EX_TRANSPARENT) != 0;
            const bool topmost     = (ex_style & WS_EX_TOPMOST)     != 0;

            if (!layered && !topmost)
                return TRUE;

            RECT rect{};
            if (!GetWindowRect(hwnd, &rect))
                return TRUE;
            if (rect_area(rect) < 64 * 64)
                return TRUE;

            DWORD cloak_flag = 0;
            if (SUCCEEDED(DwmGetWindowAttribute(hwnd, DWMWA_CLOAKED, &cloak_flag, sizeof(cloak_flag))))
            {
                if (cloak_flag != 0)
                    return TRUE;
            }

            wchar_t title[256]{};
            GetWindowTextW(hwnd, title, 255);

            wchar_t class_name[128]{};
            LI_USER32(GetClassNameW)(hwnd, class_name, 127);
            const std::wstring class_lower = to_lower(class_name);

            static const wchar_t* const k_allow_class[] = {
                XSW(L"shell_traywnd"), XSW(L"shell_secondarytraywnd"),
                XSW(L"progman"), XSW(L"workerw"),
                XSW(L"tooltips_class32"), XSW(L"#32768"),
                XSW(L"ime"), XSW(L"msctfime ui"),
                XSW(L"dwmscreencapturewindow"),
            };
            if (contains_lower(k_allow_class,
                               sizeof(k_allow_class) / sizeof(k_allow_class[0]),
                               class_lower))
                return TRUE;

            wchar_t process_name[260]{};
            get_process_name_by_pid(pid, process_name, 260);
            if (is_allowlisted_exe(process_name))
                return TRUE;

            int score = 0;
            uint32_t flags = 0;
            if (layered)     { score += 25; flags |= flag_layered;     }
            if (transparent) { score += 25; flags |= flag_transparent; }
            if (topmost)     { score += 20; flags |= flag_topmost;     }

            float overlap = 0.f;
            if (c->have_game)
            {
                const LONG intersection = intersection_area(rect, c->game_rect);
                const LONG target_area  = rect_area(c->game_rect);
                if (target_area > 0)
                    overlap = static_cast<float>(intersection) / static_cast<float>(target_area);
                if (intersection * 2 >= target_area && target_area > 0)
                {
                    score += 15;
                    flags |= flag_aligned_game;
                }
            }

            if (title[0] == 0)
            {
                score += 10;
                flags |= flag_empty_title;
            }

            if (layered)
            {
                BYTE alpha = 255;
                COLORREF key = 0;
                DWORD lwa_flags = 0;
                if (GetLayeredWindowAttributes(hwnd, &key, &alpha, &lwa_flags))
                {
                    if ((lwa_flags & LWA_ALPHA) && alpha < 250)
                    {
                        score += 5;
                        flags |= flag_low_alpha;
                    }
                }
            }

            if (layered && transparent && topmost)
            {
                score += 10;
                flags |= flag_esp_combo;
            }

            if (score < c->cfg->min_score)
                return TRUE;
            if (score > 100)
                score = 100;

            hit h{};
            h.pid     = pid;
            h.window  = hwnd;
            h.score   = score;
            h.flags   = flags;
            h.overlap = overlap;
            wcsncpy_s(h.window_class, class_name, _TRUNCATE);
            wcsncpy_s(h.process_name, process_name, _TRUNCATE);
            c->results->push_back(h);
            return TRUE;
        }, reinterpret_cast<LPARAM>(&ctx));

        for (const hit& h : hits)
        {
            bool found = false;
            for (hit& b : best)
            {
                if (b.pid == h.pid)
                {
                    if (h.score > b.score)
                        b = h;
                    found = true;
                    break;
                }
            }
            if (!found)
                best.push_back(h);
        }

        std::sort(best.begin(), best.end(),
                  [](const hit& a, const hit& b) { return a.score > b.score; });
        return best;
    }

    std::vector<DWORD> detect_overlay_pids(DWORD fivem_pid, DWORD ignore_pid, int min_score)
    {
        config cfg{};
        cfg.fivem_pid  = fivem_pid;
        cfg.ignore_pid = ignore_pid;
        cfg.min_score  = min_score;

        auto hits = scan(cfg);

        std::vector<DWORD> pids;
        pids.reserve(hits.size());
        for (const hit& h : hits)
            pids.push_back(h.pid);
        return pids;
    }
}
