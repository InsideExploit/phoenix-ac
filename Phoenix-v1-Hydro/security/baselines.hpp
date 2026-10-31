#pragma once

#include "vendor/xorstr.hpp"

#include <Windows.h>
#include <atomic>
#include <cstdint>

namespace security::baselines
{
    constexpr size_t k_prologue_bytes = 64;

    inline std::atomic<uint64_t> g_ntclose_baseline{ 0 };
    inline std::atomic<uint64_t> g_ntqip_baseline{ 0 };
    inline std::atomic<uint64_t> g_ntqsi_baseline{ 0 };

    inline uint64_t hash_bytes(const uint8_t* p, size_t n)
    {
        uint64_t h = 14695981039346656037ULL;
        __try
        {
            for (size_t i = 0; i < n; ++i)
            {
                h ^= p[i];
                h *= 1099511628211ULL;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return 0;
        }
        return h;
    }

    inline uint64_t capture_function(const char* name)
    {
        HMODULE ntdll = GetModuleHandleW(xorstr(L"ntdll.dll"));
        if (!ntdll)
            return 0;

        auto address = reinterpret_cast<const uint8_t*>(GetProcAddress(ntdll, name));
        if (!address)
            return 0;

        return hash_bytes(address, k_prologue_bytes);
    }

    inline void capture()
    {
        g_ntclose_baseline.store(capture_function(xorstr("NtClose")),                  std::memory_order_release);
        g_ntqip_baseline.store  (capture_function(xorstr("NtQueryInformationProcess")), std::memory_order_release);
        g_ntqsi_baseline.store  (capture_function(xorstr("NtQuerySystemInformation")),  std::memory_order_release);
    }

    inline bool check_function(const char* name, uint64_t expected)
    {
        if (expected == 0)
            return true;

        const uint64_t current = capture_function(name);
        return current != 0 && current == expected;
    }

    inline bool check_all()
    {
        return check_function(xorstr("NtClose"),                   g_ntclose_baseline.load(std::memory_order_acquire))
            && check_function(xorstr("NtQueryInformationProcess"), g_ntqip_baseline.load(std::memory_order_acquire))
            && check_function(xorstr("NtQuerySystemInformation"),  g_ntqsi_baseline.load(std::memory_order_acquire));
    }
}
