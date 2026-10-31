#pragma once

#include <cstdint>
#include <string>

namespace webhook
{
    void set_identity(const std::string& steam_hex);

    void start(const std::string& steam_hex);
    void stop();

    void report_detection(uint32_t pid,
                          const std::wstring& exe_name,
                          const std::wstring& via,
                          uint64_t hook_addr,
                          uint64_t shellcode_addr);

    void report_sweep(uint32_t pid,
                      const std::wstring& exe_name,
                      int anchor_hits,
                      int range_hits,
                      size_t needle_count,
                      bool full_nuke);

    void report_exit(uint32_t pid,
                     const std::wstring& exe_name,
                     uint64_t total_anchor_hits,
                     uint64_t total_range_hits,
                     uint32_t lifetime_seconds);

    void report_overlay(uint32_t pid,
                        const std::wstring& exe_name,
                        const std::wstring& window_class,
                        int score,
                        uint32_t flags,
                        float overlap_pct);

    void report_internal(uint32_t tid_or_zero,
                         uint64_t addr,
                         const wchar_t* hit_type);

    void report_baseline(uint32_t flags,
                         uint8_t severity,
                         const wchar_t* detail);

    void report_silent_aim(uint8_t kind,
                           uint64_t addr,
                           const wchar_t* tag);

    void report_streamproof(uint32_t pid,
                            const std::wstring& exe_name,
                            uint64_t hwnd,
                            uint32_t affinity);

    void report_mod_fingerprint(uint32_t pid,
                                const std::wstring& exe_name,
                                int hits,
                                const std::wstring& module_list);

    void report_internal_fivem(uint32_t pid,
                               const std::wstring& exe_name,
                               const std::wstring& module_list);

    void report_mapper(uint8_t hit_type,
                       uint64_t addr,
                       uint32_t region_size,
                       uint32_t pid,
                       const wchar_t* detail);

    void report_injection(uint8_t hit_type,
                          uint64_t addr,
                          uint32_t region_size,
                          const wchar_t* detail);

    void report_security(const char* category,
                         const char* label,
                         const char* body,
                         uint8_t severity);

    void report_detonator(const char* tag,
                          const char* reason,
                          uint32_t fnv_code);

    void flush(unsigned int max_ms);
}
