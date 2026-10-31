#include "anti_debug/anti_debug.hpp"
#include "auth/auth.hpp"
#include "common/common.hpp"
#include "detections/baseline/baseline.hpp"
#include "detections/handles/handles.hpp"
#include "detections/injection/injection.hpp"
#include "detections/internal/internal.hpp"
#include "detections/mapper/mapper.hpp"
#include "detections/modules/modules.hpp"
#include "detections/overlay/overlay.hpp"
#include "detections/rtss/rtss.hpp"
#include "detections/silent_aim/silent_aim.hpp"
#include "detections/streamproof/streamproof.hpp"
#include "gui/gui.hpp"
#include "offsets/offsets.hpp"
#include "poison_cfg/poison_cfg.hpp"
#include "response/anchor_sweep/anchor_sweep.hpp"
#include "response/syscall_hook/syscall_hook.hpp"
#include "response/viewport_scramble/viewport_scramble.hpp"
#include "security/security_core.hpp"
#include "security_check/security_check.hpp"
#include "timeguard/timeguard.hpp"
#include "update/update.hpp"
#include "vendor/lazy_importer.hpp"
#include "vendor/oreans/include/VirtualizerSDK.h"
#pragma auto_inline(off)
#include "vendor/xor_string.hpp"
#include "webhook/webhook.hpp"

#include <Windows.h>
#include <TlHelp32.h>
#include <d3d11.h>
#include <dxgi.h>

#include <chrono>
#include <cstdint>
#include <cstring>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")

namespace
{
    constexpr const wchar_t* k_version              = L"1.0.0";
    constexpr int            k_heartbeat_seconds    = 5;
    constexpr int            k_gate_delay_seconds   = 0;
    constexpr int            k_arm_delay_seconds    = 150;

    void presence_heartbeat_loop(std::string steam_hex, bool anticheat_required)
    {
        for (;;)
        {
            auth::result pulse{};
            if (auth::check_authorization(steam_hex, pulse) && pulse.ok)
            {
                if (anticheat_required && !pulse.anticheat_required)
                {
                    gui::set_status(gui::state::error);
                    gui::set_detail(XSW(L"Session revoked"));
                    LI_KERNEL(ExitProcess)(0);
                }

                if (!anticheat_required && pulse.anticheat_required)
                    LI_KERNEL(ExitProcess)(0);
            }

            std::this_thread::sleep_for(std::chrono::seconds(k_heartbeat_seconds));
        }
    }

    void pulse_presence(const std::string& steam_hex)
    {
        auth::result pulse{};
        auth::check_authorization(steam_hex, pulse);
    }

    uint64_t g_present_offset = 0;

    __declspec(noinline) void probe_dxgi_present_offset()
    {
        VIRTUALIZER_START;
        HWND hidden = LI_USER32(CreateWindowExW)(0, XSW(L"STATIC"), XSW(L""), WS_POPUP,
                                      0, 0, 1, 1, nullptr, nullptr, nullptr, nullptr);
        if (!hidden)
            return;

        DXGI_SWAP_CHAIN_DESC desc{};
        desc.BufferDesc.Width  = 1;
        desc.BufferDesc.Height = 1;
        desc.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
        desc.SampleDesc.Count  = 1;
        desc.BufferUsage       = DXGI_USAGE_RENDER_TARGET_OUTPUT;
        desc.BufferCount       = 1;
        desc.OutputWindow      = hidden;
        desc.Windowed          = TRUE;
        desc.SwapEffect        = DXGI_SWAP_EFFECT_DISCARD;

        IDXGISwapChain*   swap_chain     = nullptr;
        ID3D11Device*     device         = nullptr;
        D3D_FEATURE_LEVEL feature_level  = {};

        const HRESULT hr = D3D11CreateDeviceAndSwapChain(
            nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0,
            nullptr, 0, D3D11_SDK_VERSION, &desc,
            &swap_chain, &device, &feature_level, nullptr);

        DestroyWindow(hidden);

        if (FAILED(hr) || !swap_chain || !device)
        {
            if (swap_chain) swap_chain->Release();
            if (device)     device->Release();
            return;
        }

        void** vtable = *reinterpret_cast<void***>(swap_chain);
        const uint64_t present_address = reinterpret_cast<uint64_t>(vtable[8]);
        HMODULE dxgi = LI_KERNEL(GetModuleHandleA)(XS("dxgi.dll"));
        if (dxgi && present_address > reinterpret_cast<uint64_t>(dxgi))
            g_present_offset = present_address - reinterpret_cast<uint64_t>(dxgi);

        swap_chain->Release();
        device->Release();
        VIRTUALIZER_END;
    }

    __declspec(noinline) uint64_t remote_module_base(DWORD pid, const char* module_name)
    {
        VIRTUALIZER_START;
        HANDLE snapshot = LI_KERNEL(CreateToolhelp32Snapshot)(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (snapshot == INVALID_HANDLE_VALUE)
            return 0;

        MODULEENTRY32W me{};
        me.dwSize = sizeof(me);
        uint64_t base = 0;

        std::wstring wide_name(module_name, module_name + strlen(module_name));

        if (LI_KERNEL(Module32FirstW)(snapshot, &me))
        {
            do
            {
                if (_wcsicmp(me.szModule, wide_name.c_str()) == 0)
                {
                    base = reinterpret_cast<uint64_t>(me.modBaseAddr);
                    break;
                }
            } while (LI_KERNEL(Module32NextW)(snapshot, &me));
        }

        LI_KERNEL(CloseHandle)(snapshot);
        VIRTUALIZER_END;
        return base;
    }

    __declspec(noinline) int64_t process_uptime_seconds(DWORD pid)
    {
        VIRTUALIZER_START;
        HANDLE process = LI_KERNEL(OpenProcess)(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!process)
            return -1;

        FILETIME create{}, exit{}, kernel{}, user{};
        const BOOL ok = LI_KERNEL(GetProcessTimes)(process, &create, &exit, &kernel, &user);
        LI_KERNEL(CloseHandle)(process);
        if (!ok)
            return -1;

        FILETIME now{};
        LI_KERNEL(GetSystemTimeAsFileTime)(&now);

        ULARGE_INTEGER created{};
        ULARGE_INTEGER current{};
        created.LowPart  = create.dwLowDateTime;  created.HighPart = create.dwHighDateTime;
        current.LowPart  = now.dwLowDateTime;     current.HighPart = now.dwHighDateTime;

        if (current.QuadPart < created.QuadPart)
            return 0;

        const int64_t r = static_cast<int64_t>((current.QuadPart - created.QuadPart) / 10000000ULL);
        VIRTUALIZER_END;
        return r;
    }

    struct fivem_state
    {
        DWORD                     pid = 0;
        std::wstring              exe_name;
        uint64_t                  module_base = 0;
        uint64_t                  module_size = 0;
        int                       build = -1;
        offsets::pack             rvas{};
        uint64_t                  viewport_runtime = 0;
        uint64_t                  timeguard_addr   = 0;
        poison_cfg::payload_config cfg{};
    };

    bool refresh_fivem_state(fivem_state& state, const poison_cfg::syscall_numbers& ssn)
    {
        HANDLE process = LI_KERNEL(OpenProcess)(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, state.pid);
        if (!process)
        {
            return false;
        }

        bool ok = false;

        state.module_size = 0;
        state.module_base = common::remote_module_base(state.pid, state.exe_name, &state.module_size);
        if (state.module_base)
        {

            state.build = common::parse_build_number(state.exe_name);
            if (state.build < 0)
                state.build = detections::modules::highest_fivem_build();

            state.rvas = offsets::resolve(state.build);

            state.cfg.fivem_pid                        = state.pid;
            state.cfg.ssn_nt_read_virtual_memory       = ssn.nt_read_virtual_memory;
            state.cfg.ssn_nt_query_information_process = ssn.nt_query_information_process;
            state.cfg.viewport                         = state.module_base + state.rvas.viewport;
            state.cfg.viewport_end                     = state.cfg.viewport + 0x1000;
            state.cfg.cam_dir                          = state.module_base + state.rvas.cam;
            state.cfg.cam_end                          = state.cfg.cam_dir + 0x400;
            state.cfg.world                            = state.module_base + state.rvas.world;
            state.cfg.blip_list                        = state.module_base + state.rvas.blip;
            state.cfg.aim                              = state.rvas.aim ? state.module_base + state.rvas.aim : 0;

            state.cfg.ped_pool = offsets::find_ped_pool(process, state.module_base, state.module_size);

            state.viewport_runtime = offsets::find_viewport(process, state.module_base, state.module_size,
                                                            state.cfg.viewport);
            state.cfg.viewport_runtime = state.viewport_runtime;
            ok = state.viewport_runtime != 0;
        }

        LI_KERNEL(CloseHandle)(process);
        return ok;
    }

    void enrich_pid_name(DWORD pid, wchar_t* out, size_t out_size)
    {
        if (!out || out_size == 0)
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
                    wcsncpy_s(out, out_size, pe.szExeFile, _TRUNCATE);
                    break;
                }
            } while (LI_KERNEL(Process32NextW)(snapshot, &pe));
        }
        LI_KERNEL(CloseHandle)(snapshot);
    }

    void wait_for_grc_window(DWORD pid)
    {
        constexpr int k_poll_ms    = 500;
        constexpr int k_timeout_ms = 120000;
        int elapsed = 0;
        while (elapsed < k_timeout_ms)
        {
            HWND wnd = LI_USER32(FindWindowA)(XS("grcWindow"), nullptr);
            if (wnd)
            {
                DWORD wnd_pid = 0;
                LI_USER32(GetWindowThreadProcessId)(wnd, &wnd_pid);
                if (wnd_pid == pid && LI_USER32(IsWindowVisible)(wnd))
                    return;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(k_poll_ms));
            elapsed += k_poll_ms;
        }
    }

    void timeguard_init(DWORD pid, uint64_t module_base, uint64_t module_size,
                        uint64_t& out_addr, const std::string& steam_hex)
    {
        wait_for_grc_window(pid);
        std::this_thread::sleep_for(std::chrono::seconds(20));

        std::wstring dummy;
        if (!common::find_fivem_pid(dummy))
            return;

        HANDLE proc = LI_KERNEL(OpenProcess)(
            PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
            FALSE, pid);
        if (!proc)
            return;

        const uint64_t addr = timeguard::resolve_target(proc, module_base, module_size);
        if (addr)
        {
            out_addr = addr;
            timeguard::stamp(proc, addr, steam_hex);
        }

        LI_KERNEL(CloseHandle)(proc);
    }

    void run_main_loop(const std::string& steam_hex)
    {
        (void)common::enable_debug_privilege();
        probe_dxgi_present_offset();

        poison_cfg::syscall_numbers ssn = poison_cfg::resolve_syscall_numbers();
        if (!ssn.nt_read_virtual_memory || !ssn.nt_query_information_process)
        {
            gui::set_status(gui::state::error);
            gui::set_detail(XSW(L"Initialization error"));
            return;
        }

        fivem_state state{};

        gui::set_status(gui::state::waiting_for_fivem);
        gui::set_detail(XSW(L"Waiting for FiveM..."));

        while (!state.pid)
        {
            state.pid = common::find_fivem_pid(state.exe_name);
            if (!state.pid)
                std::this_thread::sleep_for(std::chrono::seconds(1));
        }

        gui::set_detail(XSW(L"FiveM detected, resolving offsets..."));

        int refresh_attempts = 0;
        while (!refresh_fivem_state(state, ssn))
        {
            ++refresh_attempts;
            if ((refresh_attempts % 20) == 0)
            {
                wchar_t message[160];
                swprintf_s(message, XSW(L"Resolving offsets (attempt %d)..."), refresh_attempts);
                gui::set_detail(message);
            }

            DWORD live = common::find_fivem_pid(state.exe_name);
            if (!live)
            {
                state.pid = 0;
                gui::set_detail(XSW(L"FiveM closed, waiting..."));
                while (!state.pid)
                {
                    state.pid = common::find_fivem_pid(state.exe_name);
                    if (!state.pid)
                        std::this_thread::sleep_for(std::chrono::seconds(1));
                }
                gui::set_detail(XSW(L"FiveM detected, resolving offsets..."));
                refresh_attempts = 0;
            }
            else if (live != state.pid)
            {
                state.pid = live;
                refresh_attempts = 0;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }

        gui::set_status(gui::state::running);
        gui::set_detail(XSW(L"Protection active"));

        pulse_presence(steam_hex);

        {
            const DWORD    tg_pid  = state.pid;
            const uint64_t tg_base = state.module_base;
            const uint64_t tg_size = state.module_size;
            std::thread([tg_pid, tg_base, tg_size, &state, steam_hex]() {
                timeguard_init(tg_pid, tg_base, tg_size, state.timeguard_addr, steam_hex);
            }).detach();
        }

        response::viewport_scramble::start();

        const DWORD self_pid = LI_KERNEL(GetCurrentProcessId)();
        std::unordered_set<DWORD> hooked_pids;
        std::unordered_map<DWORD, std::chrono::steady_clock::time_point> first_seen;
        constexpr auto k_wipe_delay = std::chrono::seconds(60);

        uint64_t tick = 0;
        auto last_resolve      = std::chrono::steady_clock::now();
        auto last_stamp        = std::chrono::steady_clock::time_point{};
        auto protection_start  = std::chrono::steady_clock::now();
        bool armed = false;

        for (;;)
        {
            ++tick;

        const DWORD live_pid = common::find_fivem_pid(state.exe_name);

        if (!live_pid && state.pid)
        {
            gui::set_status(gui::state::closing);
            response::viewport_scramble::g_pid.store(0);
            response::viewport_scramble::g_viewport.store(0);
            hooked_pids.clear();
            first_seen.clear();
            detections::silent_aim::reset();
            detections::baseline::reset();
            state.pid            = 0;
            state.module_base    = 0;
            state.module_size    = 0;
            state.timeguard_addr = 0;
            armed                = false;
        }

        if (live_pid && live_pid != state.pid)
        {
            state.pid = live_pid;
            response::viewport_scramble::g_pid.store(0);
            response::viewport_scramble::g_viewport.store(0);
            hooked_pids.clear();
            first_seen.clear();
            detections::silent_aim::reset();
            detections::baseline::reset();
            state.timeguard_addr = 0;
            gui::set_status(gui::state::waiting_for_fivem);
            gui::set_detail(XSW(L"FiveM detected, resolving..."));

            while (!refresh_fivem_state(state, ssn))
            {
                const DWORD check = common::find_fivem_pid(state.exe_name);
                if (!check)
                {
                    state.pid         = 0;
                    state.module_base = 0;
                    state.module_size = 0;
                    gui::set_status(gui::state::closing);
                    break;
                }
                if (check != state.pid)
                    state.pid = check;
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
            }

            if (state.pid)
            {
                {
                    const DWORD    tg_pid  = state.pid;
                    const uint64_t tg_base = state.module_base;
                    const uint64_t tg_size = state.module_size;
                    std::thread([tg_pid, tg_base, tg_size, &state, steam_hex]() {
                        timeguard_init(tg_pid, tg_base, tg_size, state.timeguard_addr, steam_hex);
                    }).detach();
                }

                gui::set_status(gui::state::running);
                gui::set_detail(XSW(L"Protection active"));
                protection_start = std::chrono::steady_clock::now();
                armed            = false;
                last_resolve     = protection_start;
            }
        }

        if (!state.pid)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }

        const auto now = std::chrono::steady_clock::now();

            if (state.timeguard_addr && now - last_stamp >= std::chrono::seconds(25))
            {
                HANDLE tg_proc = LI_KERNEL(OpenProcess)(
                    PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, state.pid);
                if (tg_proc)
                {
                    timeguard::stamp(tg_proc, state.timeguard_addr, steam_hex);
                    LI_KERNEL(CloseHandle)(tg_proc);
                }
                last_stamp = now;
            }

            if (armed && now - last_resolve > std::chrono::seconds(5))
            {
                const uint64_t previous_viewport = state.viewport_runtime;
                if (refresh_fivem_state(state, ssn))
                {
                    if (state.viewport_runtime != previous_viewport)
                        response::viewport_scramble::g_viewport.store(state.viewport_runtime);
                }
                last_resolve = now;
            }

            if (!armed && now - protection_start >= std::chrono::seconds(k_arm_delay_seconds))
            {
                armed = true;
                response::viewport_scramble::g_pid.store(state.pid);
                response::viewport_scramble::g_viewport.store(state.viewport_runtime);
            }

            {
                const bool full_nuke = (tick % 5) == 0;
                HANDLE fivem_handle = LI_KERNEL(OpenProcess)(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                                                  FALSE, state.pid);

                std::unordered_set<DWORD> candidates;
                for (DWORD p : detections::handles::scan(state.pid, self_pid))
                    candidates.insert(p);
                for (DWORD p : detections::modules::fingerprint_scan(self_pid, state.pid))
                    candidates.insert(p);
                for (DWORD p : hooked_pids)
                    candidates.insert(p);

                for (DWORD candidate_pid : candidates)
                {
                    if (candidate_pid == state.pid || candidate_pid == self_pid)
                        continue;
                    if (detections::modules::is_safe_pid(candidate_pid))
                        continue;

                    if (!hooked_pids.count(candidate_pid))
                    {
                        if (response::anchor_sweep::probe(candidate_pid, state.cfg, fivem_handle, 3) < 3)
                            continue;

                        const auto stamp = std::chrono::steady_clock::now();
                        auto seen_it = first_seen.find(candidate_pid);

                        if (seen_it == first_seen.end())
                        {
                            response::syscall_hook::hook_info info{};
                            if (response::syscall_hook::deploy(candidate_pid, state.cfg, &info))
                            {
                                wchar_t exe_name[260]{};
                                enrich_pid_name(candidate_pid, exe_name, 260);

                                webhook::report_detection(candidate_pid, std::wstring(exe_name),
                                                          L"handle+module",
                                                          info.nt_read_vm_address,
                                                          info.shellcode_address);
                                first_seen[candidate_pid] = stamp;
                            }
                            continue;
                        }

                        if (stamp - seen_it->second < k_wipe_delay)
                            continue;

                        response::anchor_sweep::wipe(candidate_pid, state.cfg, fivem_handle, true);
                        hooked_pids.insert(candidate_pid);
                        first_seen.erase(seen_it);
                    }
                    else
                    {
                        wchar_t exe_name[260]{};
                        enrich_pid_name(candidate_pid, exe_name, 260);

                        response::anchor_sweep::stats sweep_stats{};
                        response::anchor_sweep::wipe(candidate_pid, state.cfg, fivem_handle,
                                                    full_nuke, &sweep_stats);
                        if (sweep_stats.ok && (sweep_stats.anchor_hits > 0 || sweep_stats.range_hits > 0))
                        {
                            webhook::report_sweep(candidate_pid, std::wstring(exe_name),
                                                  sweep_stats.anchor_hits, sweep_stats.range_hits,
                                                  sweep_stats.needle_count, sweep_stats.full_nuke);
                        }
                    }
                }

                if (fivem_handle)
                    LI_KERNEL(CloseHandle)(fivem_handle);

                for (auto it = hooked_pids.begin(); it != hooked_pids.end();)
                {
                    HANDLE h = LI_KERNEL(OpenProcess)(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, *it);
                    if (!h) { it = hooked_pids.erase(it); continue; }
                    DWORD code = 0;
                    LI_KERNEL(GetExitCodeProcess)(h, &code);
                    LI_KERNEL(CloseHandle)(h);
                    if (code != STILL_ACTIVE)
                        it = hooked_pids.erase(it);
                    else
                        ++it;
                }

                for (auto it = first_seen.begin(); it != first_seen.end();)
                {
                    HANDLE h = LI_KERNEL(OpenProcess)(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, it->first);
                    if (!h) { it = first_seen.erase(it); continue; }
                    DWORD code = 0;
                    LI_KERNEL(GetExitCodeProcess)(h, &code);
                    LI_KERNEL(CloseHandle)(h);
                    if (code != STILL_ACTIVE)
                        it = first_seen.erase(it);
                    else
                        ++it;
                }
            }

            if ((tick % 15) == 0)
            {
                auto stream_hits = detections::streamproof::scan(state.pid, self_pid);
                for (const auto& h : stream_hits)
                {
                    webhook::report_streamproof(h.pid, std::wstring(h.process_name),
                                                reinterpret_cast<uint64_t>(h.window),
                                                h.affinity);
                }
            }

            if ((tick % 10) == 0)
            {
                if (!detections::silent_aim::is_ready() && !detections::silent_aim::was_tried())
                {
                    HANDLE fh = LI_KERNEL(OpenProcess)(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, state.pid);
                    if (fh)
                    {
                        detections::silent_aim::init(fh, state.module_base, static_cast<size_t>(state.module_size));
                        LI_KERNEL(CloseHandle)(fh);
                    }
                }

                if (detections::silent_aim::is_ready())
                {
                    HANDLE fh = LI_KERNEL(OpenProcess)(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, state.pid);
                    if (fh)
                    {
                        auto silent_hits = detections::silent_aim::scan(fh);
                        LI_KERNEL(CloseHandle)(fh);

                        static const wchar_t* const k_tags[] = {
                            L"None",
                            L"V1 JMP hook",
                            L"V1 MOV hook",
                            L"V1 indirect JMP",
                            L"V1 integrity",
                            L"V2 JMP hook",
                            L"V2 integrity",
                            L"V2 payload",
                            L"V2 payload (alt)",
                        };

                        for (const auto& sh : silent_hits)
                        {
                            const uint8_t kind = static_cast<uint8_t>(sh.kind);
                            const wchar_t* tag = (kind < sizeof(k_tags) / sizeof(k_tags[0]))
                                                 ? k_tags[kind] : L"Unknown";
                            webhook::report_silent_aim(kind, sh.address, tag);
                        }
                    }
                }
            }

            if ((tick % 300) == 0)
            {
                auto baseline_result = detections::baseline::scan(state.pid);
                if (baseline_result.level >= detections::baseline::severity::suspect)
                {
                    wchar_t detail[256];
                    swprintf_s(detail,
                               L"dMod=%+d dUnmappedReg=%+d dUnmappedSz=%+dKB "
                               L"dExec=%+d dSusThr=%+d privMB=%zu",
                               baseline_result.delta_modules,
                               baseline_result.delta_unmapped_regions,
                               baseline_result.delta_unmapped_size,
                               baseline_result.delta_exec_regions,
                               baseline_result.delta_suspicious_threads,
                               baseline_result.current.private_usage / (1024 * 1024));

                    webhook::report_baseline(baseline_result.flags,
                                             static_cast<uint8_t>(baseline_result.level),
                                             detail);
                }
            }

            if ((tick % 30) == 0)
            {
                detections::overlay::config oc{};
                oc.fivem_pid  = state.pid;
                oc.ignore_pid = self_pid;
                oc.min_score  = 60;

                auto overlay_hits = detections::overlay::scan(oc);
                for (const auto& h : overlay_hits)
                {
                    webhook::report_overlay(h.pid, std::wstring(h.process_name),
                                            std::wstring(h.window_class),
                                            h.score, h.flags, h.overlap);
                }
            }

            if ((tick % 20) == 0)
            {
                bool     swap_hook_restored = false;
                uint64_t swap_hook_address  = 0;

                HANDLE fivem_handle = LI_KERNEL(OpenProcess)(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION
                                                  | PROCESS_VM_OPERATION | PROCESS_VM_WRITE,
                                                  FALSE, state.pid);
                if (fivem_handle)
                {
                    auto internal_hits = detections::internal_scan::scan(state.pid, fivem_handle,
                                                                          state.module_base, state.build);
                    for (const auto& h : internal_hits)
                    {
                        if (h.type == detections::internal_scan::hit_type::injected_thread)
                        {
                            webhook::report_internal(h.tid, h.address,
                                                     XSW(L"InjectedThread (invoker)"));

                            if (HANDLE hthread = LI_KERNEL(OpenThread)(THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION,
                                                            FALSE, h.tid))
                            {
                                LI_KERNEL(SuspendThread)(hthread);
                                LI_KERNEL(CloseHandle)(hthread);
                            }

                            DWORD old = 0;
                            LI_KERNEL(VirtualProtectEx)(fivem_handle, reinterpret_cast<LPVOID>(h.address),
                                             0x1000, PAGE_NOACCESS, &old);
                        }
                        else
                        {
                            webhook::report_internal(0, h.address,
                                                     XSW(L"SwapchainHook (overlay)"));

                            if (h.vtable_slot_address && g_present_offset)
                            {
                                const uint64_t dxgi_base = remote_module_base(state.pid, XS("dxgi.dll"));
                                if (dxgi_base)
                                {
                                    const uint64_t real_present = dxgi_base + g_present_offset;

                                    DWORD old = 0;
                                    if (LI_KERNEL(VirtualProtectEx)(fivem_handle,
                                                         reinterpret_cast<LPVOID>(h.vtable_slot_address),
                                                         8, PAGE_EXECUTE_READWRITE, &old))
                                    {
                                        SIZE_T written = 0;
                                        LI_KERNEL(WriteProcessMemory)(fivem_handle,
                                                           reinterpret_cast<LPVOID>(h.vtable_slot_address),
                                                           &real_present, 8, &written);
                                        LI_KERNEL(VirtualProtectEx)(fivem_handle,
                                                         reinterpret_cast<LPVOID>(h.vtable_slot_address),
                                                         8, old, &old);
                                        swap_hook_restored = true;
                                        swap_hook_address  = h.address;
                                    }

                                    DWORD old2 = 0;
                                    LI_KERNEL(VirtualProtectEx)(fivem_handle, reinterpret_cast<LPVOID>(h.address),
                                                     0x1000, PAGE_NOACCESS, &old2);
                                }
                            }
                        }
                    }

                    static auto nt_query_information_thread =
                        reinterpret_cast<NTSTATUS (NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG)>(
                            GetProcAddress(LI_KERNEL(GetModuleHandleA)(XS("ntdll.dll")),
                                           XS("NtQueryInformationThread")));

                    auto injection_hits = detections::injection::scan(state.pid, fivem_handle);
                    for (const auto& ih : injection_hits)
                    {
                        webhook::report_injection(static_cast<uint8_t>(ih.type),
                                                  ih.address, ih.region_size, ih.detail);

                        int suspended_count = 0;
                        HANDLE thread_snapshot = LI_KERNEL(CreateToolhelp32Snapshot)(TH32CS_SNAPTHREAD, 0);
                        if (thread_snapshot != INVALID_HANDLE_VALUE)
                        {
                            THREADENTRY32 te{};
                            te.dwSize = sizeof(te);
                            if (LI_KERNEL(Thread32First)(thread_snapshot, &te))
                            {
                                do
                                {
                                    if (te.th32OwnerProcessID != state.pid)
                                        continue;

                                    HANDLE hthread = LI_KERNEL(OpenThread)(THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION,
                                                                FALSE, te.th32ThreadID);
                                    if (!hthread)
                                        continue;

                                    if (nt_query_information_thread)
                                    {
                                        PVOID start_address = nullptr;
                                        nt_query_information_thread(hthread, 9, &start_address,
                                                                    sizeof(start_address), nullptr);
                                        const uint64_t address = reinterpret_cast<uint64_t>(start_address);
                                        if (address >= ih.address && address < ih.address + ih.region_size)
                                        {
                                            LI_KERNEL(SuspendThread)(hthread);
                                            ++suspended_count;
                                        }
                                    }
                                    LI_KERNEL(CloseHandle)(hthread);
                                } while (LI_KERNEL(Thread32Next)(thread_snapshot, &te));
                            }
                            LI_KERNEL(CloseHandle)(thread_snapshot);
                        }

                        const bool hook_in_region = swap_hook_restored
                                                 && swap_hook_address >= ih.address
                                                 && swap_hook_address < ih.address + ih.region_size;

                        if (suspended_count > 0 || hook_in_region)
                        {
                            DWORD old = 0;
                            LI_KERNEL(VirtualProtectEx)(fivem_handle, reinterpret_cast<LPVOID>(ih.address),
                                             ih.region_size, PAGE_NOACCESS, &old);
                        }
                    }

                    LI_KERNEL(CloseHandle)(fivem_handle);
                }
            }

            if ((tick % 10) == 0)
            {
                bool game_hooked = false;
                detections::rtss::config rc{ state.pid, 2 };
                auto rtss_hits = detections::rtss::scan(rc, &game_hooked);

                for (const auto& h : rtss_hits)
                {
                    wchar_t owner_wide[256]{};
                    MultiByteToWideChar(CP_UTF8, 0, h.owner, -1, owner_wide, 256);

                    wchar_t tag[96];
                    swprintf_s(tag, XSW(L"[rtss:OSD score=%d flags=0x%X]"), h.score, h.flags);

                    webhook::report_overlay(state.pid, std::wstring(owner_wide), tag,
                                            h.score, h.flags, 0.f);
                }

                if (game_hooked)
                    webhook::report_internal(0, 0, XSW(L"RTSSHooks64 in FiveM (OSD inject)"));
            }

            if ((tick % 5) == 0)
            {
                struct overlay_ctx { DWORD fivem_pid; DWORD self_pid; };
                overlay_ctx ctx{ state.pid, LI_KERNEL(GetCurrentProcessId)() };

                LI_USER32(EnumWindows)([](HWND hwnd, LPARAM lparam) -> BOOL {
                    if (!LI_USER32(IsWindowVisible)(hwnd))
                        return TRUE;

                    wchar_t class_name[64]{};
                    LI_USER32(GetClassNameW)(hwnd, class_name, 64);
                    if (_wcsicmp(class_name, XSW(L"NativeDisplayHost")) != 0)
                        return TRUE;

                    DWORD pid = 0;
                    LI_USER32(GetWindowThreadProcessId)(hwnd, &pid);

                    auto* c = reinterpret_cast<overlay_ctx*>(lparam);
                    if (!pid || pid == c->fivem_pid || pid == c->self_pid)
                        return TRUE;

                    wchar_t exe_name[260]{};
                    HANDLE snapshot = LI_KERNEL(CreateToolhelp32Snapshot)(TH32CS_SNAPPROCESS, 0);
                    if (snapshot != INVALID_HANDLE_VALUE)
                    {
                        PROCESSENTRY32W pe{};
                        pe.dwSize = sizeof(pe);
                        if (LI_KERNEL(Process32FirstW)(snapshot, &pe))
                        {
                            do
                            {
                                if (pe.th32ProcessID == pid)
                                {
                                    wcsncpy_s(exe_name, pe.szExeFile, _TRUNCATE);
                                    break;
                                }
                            } while (LI_KERNEL(Process32NextW)(snapshot, &pe));
                        }
                        LI_KERNEL(CloseHandle)(snapshot);
                    }

                    webhook::report_overlay(pid, std::wstring(exe_name),
                                            XSW(L"NativeDisplayHost"), 100, 0u, 0.f);
                    return TRUE;
                }, reinterpret_cast<LPARAM>(&ctx));
            }

            if ((tick % 30) == 0)
            {
                static const wchar_t* const k_suspect_modules[] = {
                    XSW(L"d3d11.dll"),
                    XSW(L"dxgi.dll"),
                    XSW(L"d3dx9_43.dll"),
                    XSW(L"windowscodecs.dll"),
                    XSW(L"gdiplus.dll"),
                    XSW(L"shell32.dll"),
                    XSW(L"win32u.dll"),
                    XSW(L"ws2_32.dll"),
                    XSW(L"crypt32.dll"),
                    XSW(L"iphlpapi.dll"),
                    XSW(L"mpr.dll"),
                    XSW(L"nsi.dll"),
                    XSW(L"dnsapi.dll"),
                };
                constexpr int k_suspect_count = 13;
                constexpr int k_min_hits      = 4;

                const DWORD current_self_pid = LI_KERNEL(GetCurrentProcessId)();
                HANDLE process_snapshot = LI_KERNEL(CreateToolhelp32Snapshot)(TH32CS_SNAPPROCESS, 0);
                if (process_snapshot != INVALID_HANDLE_VALUE)
                {
                    PROCESSENTRY32W pe{};
                    pe.dwSize = sizeof(pe);
                    if (LI_KERNEL(Process32FirstW)(process_snapshot, &pe))
                    {
                        do
                        {
                            const DWORD scan_pid = pe.th32ProcessID;
                            if (scan_pid == 0 || scan_pid == 4 || scan_pid == current_self_pid || scan_pid == state.pid)
                                continue;

                            const wchar_t* exe = pe.szExeFile;
                            if (_wcsnicmp(exe, XSW(L"FiveM"), 5) == 0)                    continue;
                            if (_wcsicmp(exe, XSW(L"gameoverlayui64.exe")) == 0)          continue;
                            if (_wcsicmp(exe, XSW(L"steam.exe")) == 0)                    continue;
                            if (_wcsicmp(exe, XSW(L"steamwebhelper.exe")) == 0)           continue;

                            HANDLE module_snapshot = LI_KERNEL(CreateToolhelp32Snapshot)(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, scan_pid);
                            if (module_snapshot == INVALID_HANDLE_VALUE)
                                continue;

                            static const wchar_t* const k_d3d_gate[] = { XSW(L"d3dx9_43.dll") };

                            wchar_t hit_names[k_min_hits][64]{};
                            int hits = 0;
                            bool has_d3d = false;

                            MODULEENTRY32W me{};
                            me.dwSize = sizeof(me);
                            if (LI_KERNEL(Module32FirstW)(module_snapshot, &me))
                            {
                                do
                                {
                                    for (int i = 0; i < k_suspect_count; ++i)
                                    {
                                        if (_wcsicmp(me.szModule, k_suspect_modules[i]) == 0)
                                        {
                                            if (hits < k_min_hits)
                                                wcsncpy_s(hit_names[hits], me.szModule, 63);
                                            ++hits;
                                            break;
                                        }
                                    }
                                    if (!has_d3d)
                                    {
                                        for (const wchar_t* gate : k_d3d_gate)
                                        {
                                            if (_wcsicmp(me.szModule, gate) == 0)
                                            {
                                                has_d3d = true;
                                                break;
                                            }
                                        }
                                    }
                                } while (LI_KERNEL(Module32NextW)(module_snapshot, &me));
                            }
                            LI_KERNEL(CloseHandle)(module_snapshot);

                            if (hits >= k_min_hits && has_d3d)
                            {
                                wchar_t module_list[k_min_hits * 68]{};
                                int off = 0;
                                for (int i = 0; i < k_min_hits && i < hits; ++i)
                                {
                                    if (i > 0)
                                    {
                                        module_list[off++] = L',';
                                        module_list[off++] = L' ';
                                    }
                                    const int len = static_cast<int>(wcslen(hit_names[i]));
                                    wcsncpy_s(module_list + off, (k_min_hits * 68) - off, hit_names[i], len);
                                    off += len;
                                }

                                webhook::report_mod_fingerprint(scan_pid, std::wstring(pe.szExeFile),
                                                                hits, std::wstring(module_list));

                                if (!hooked_pids.count(scan_pid)
                                    && !detections::modules::is_safe_pid(scan_pid)
                                    && scan_pid != state.pid && scan_pid != current_self_pid)
                                {
                                    response::syscall_hook::hook_info info{};
                                    if (response::syscall_hook::deploy(scan_pid, state.cfg, &info))
                                    {
                                        HANDLE fh = LI_KERNEL(OpenProcess)(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                                                                FALSE, state.pid);
                                        if (fh)
                                        {
                                            response::anchor_sweep::wipe(scan_pid, state.cfg, fh, true);
                                            LI_KERNEL(CloseHandle)(fh);
                                        }

                                        hooked_pids.insert(scan_pid);
                                        webhook::report_detection(scan_pid, std::wstring(pe.szExeFile),
                                                                  L"modfingerprint",
                                                                  info.nt_read_vm_address,
                                                                  info.shellcode_address);
                                    }
                                }
                            }
                        } while (LI_KERNEL(Process32NextW)(process_snapshot, &pe));
                    }
                    LI_KERNEL(CloseHandle)(process_snapshot);
                }
            }

            if (tick == 1 || (tick % 30) == 0)
            {
                detections::modules::gta_cheat_hit gta_hit{};
                if (detections::modules::find_gta_internal_cheat(gta_hit))
                    webhook::report_internal_fivem(gta_hit.pid, gta_hit.exe_name, gta_hit.modules);
            }

            if (tick == 1 || (tick % 30) == 0)
            {
                detections::mapper::hit mapper_hits[32];
                int mapper_count = 0;
                detections::mapper::scan(mapper_hits, 32, &mapper_count);

                for (int i = 0; i < mapper_count; ++i)
                {
                    const auto& h = mapper_hits[i];
                    webhook::report_mapper(static_cast<uint8_t>(h.type),
                                           h.address, h.region_size, h.pid, h.detail);
                }
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }

    void run_presence_loop(const std::string&)
    {
        gui::set_status(gui::state::running);
        gui::set_detail(L"Session authorized (without AC)");

        for (;;)
            std::this_thread::sleep_for(std::chrono::hours(24));
    }

    void run_gateway(std::string steam_hex, auth::result auth_result)
    {
        gui::set_status(gui::state::waiting_for_fivem);
        gui::set_detail(L"Waiting for FiveM...");

        std::wstring exe_name;
        DWORD fivem_pid = 0;

        while (true)
        {
            fivem_pid = common::find_fivem_pid(exe_name);
            if (fivem_pid)
            {
                int64_t uptime = process_uptime_seconds(fivem_pid);
                if (uptime < 0)
                    uptime = 0;

                const int64_t remaining = static_cast<int64_t>(k_gate_delay_seconds) - uptime;
                if (remaining <= 0)
                    break;

                int waited = 0;
                bool died = false;

                while (waited < remaining)
                {
                    std::this_thread::sleep_for(std::chrono::seconds(1));
                    ++waited;

                    HANDLE check = LI_KERNEL(OpenProcess)(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, fivem_pid);
                    if (!check)
                    {
                        died = true;
                        break;
                    }
                    DWORD code = 0;
                    LI_KERNEL(GetExitCodeProcess)(check, &code);
                    LI_KERNEL(CloseHandle)(check);

                    if (code != STILL_ACTIVE)
                    {
                        died = true;
                        break;
                    }
                }

                if (died)
                {
                    fivem_pid = 0;
                    continue;
                }
                break;
            }
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }

        const int gate_flags = (auth_result.anticheat_required ? 0 : 1)
                             + (auth_result.ttl_seconds < 30 ? 4 : 0);

        if (gate_flags == 0)
        {
            webhook::start(steam_hex);
            run_main_loop(steam_hex);
        }
        else
        {
            run_presence_loop(steam_hex);
        }
    }
}

int wmain(int argc, wchar_t** argv)
{
    if (argc >= 3 && wcscmp(argv[1], XSW(L"--watchdog")) == 0)
        return anti_debug::run_watchdog(static_cast<DWORD>(_wtoi(argv[2])));


    if (update::check_and_apply(k_version))
    {
        return 0;
    }

    std::string steam_hex;
    auth::get_steam_id_hex(steam_hex);
    webhook::set_identity(steam_hex);

    anti_debug::start();

#ifndef _DEBUG
    security::core::init();
#endif

    security_check::status system_status = security_check::query();
    if (!system_status.all_ok())
    {
        if (!system_status.tpm20)
            webhook::report_security(XS("preflight"), XS("TPM 2.0 missing"),
                                     XS("System does not expose TPM 2.0."), 2);
        if (!system_status.secure_boot)
            webhook::report_security(XS("preflight"), XS("Secure Boot disabled"),
                                     XS("UEFI Secure Boot not enabled."), 2);
        if (!system_status.hvci)
            webhook::report_security(XS("preflight"), XS("HVCI / Memory Integrity off"),
                                     XS("Core Isolation / Memory Integrity disabled."), 2);
        if (!system_status.dma_guard)
            webhook::report_security(XS("preflight"), XS("Kernel DMA Protection off"),
                                     XS("Kernel DMA Protection disabled."), 2);
        if (!system_status.iommu)
            webhook::report_security(XS("preflight"), XS("IOMMU disabled"),
                                     XS("IOMMU (VT-d / AMD-Vi) not available in firmware."), 2);

        std::wstring message =
            std::wstring(XSW(L"Your system does not meet the minimum requirements for PhoenixAC.\n\n"))
            + XSW(L"Missing features:\n") + system_status.missing_list()
            + XSW(L"\n\nEnable these features in BIOS/UEFI and in "
                  L"Windows -> Device Security.");

        LI_USER32(MessageBoxW)(nullptr, message.c_str(),
                    XSW(L"PhoenixAC - Requirements not met"),
                    MB_ICONWARNING | MB_OK);
        webhook::flush(2000);
        return 1;
    }

    if (!auth::is_steam_running() || steam_hex.empty())
    {
        LI_USER32(MessageBoxW)(nullptr,
                    XSW(L"Open Steam before starting PhoenixAC."),
                    XSW(L"PhoenixAC - Steam not detected"),
                    MB_ICONINFORMATION | MB_OK);
        webhook::flush(2000);
        return 0;
    }

    {
        std::wstring tmp_exe;
        const DWORD fivem_running = common::find_fivem_pid(tmp_exe);
        if (fivem_running)
        {
            LI_USER32(MessageBoxW)(nullptr,
                        XSW(L"FiveM is already open. Close it, then restart PhoenixAC."),
                        XSW(L"PhoenixAC - FiveM already running"),
                        MB_ICONWARNING | MB_OK);
            webhook::flush(2000);
            return 0;
        }
    }

    auth::result authorization{};
    {
        constexpr int k_max_retries        = 5;
        constexpr int k_retry_delay_seconds = 2;

        bool got_response = false;
        for (int i = 0; i < k_max_retries && !got_response; ++i)
        {
            got_response = auth::check_authorization(steam_hex, authorization);
            if (!got_response && i + 1 < k_max_retries)
                std::this_thread::sleep_for(std::chrono::seconds(k_retry_delay_seconds));
        }

        if (!got_response || !authorization.ok)
        {
            LI_USER32(MessageBoxW)(nullptr,
                        XSW(L"PhoenixAC is not required."),
                        XSW(L"PhoenixAC"),
                        MB_ICONINFORMATION | MB_OK);
            webhook::flush(2000);
            return 0;
        }
    }

    std::thread([steam_hex, anticheat_required = authorization.anticheat_required]() {
        presence_heartbeat_loop(steam_hex, anticheat_required);
    }).detach();

    if (!gui::create(LI_KERNEL(GetModuleHandleW)(nullptr)))
    {
        return 1;
    }

    (void)common::enable_debug_privilege();
    std::thread([steam_hex, authorization]() {
        run_gateway(steam_hex, authorization);
    }).detach();

    return gui::run_loop();
}
