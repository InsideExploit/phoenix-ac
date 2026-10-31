#include "timeguard.hpp"

#include "common/common.hpp"
#include "vendor/lazy_importer.hpp"
#include "vendor/oreans/include/VirtualizerSDK.h"
#pragma auto_inline(off)

#include <cstdint>
#include <cstring>
#include <vector>

namespace timeguard
{
    namespace
    {
        constexpr uint32_t k_xor = 0xB7E15163u;
        constexpr uint32_t k_window = 30u;

        static const uint8_t k_outer_sig[] = {
            0x8B, 0x41, 0x64,
            0xC1, 0xE8, 0x00,
            0xA8, 0x00,
            0x74, 0x00,
            0x8B, 0xC6
        };
        static const char k_outer_mask[] = "xxxxx?x?x?xx";

        static const uint8_t k_movss_prefix[] = { 0xF3, 0x0F, 0x10 };

        __declspec(noinline) uint32_t steam_low32(const std::string& steam_hex)
        {
            VIRTUALIZER_START;
            if (steam_hex.size() < 8)
                return 0;
            const char* tail = steam_hex.c_str() + steam_hex.size() - 8;
            const uint32_t r = static_cast<uint32_t>(strtoul(tail, nullptr, 16));
            VIRTUALIZER_END;
            return r;
        }

        __declspec(noinline) uint32_t make_token(const std::string& steam_hex)
        {
            VIRTUALIZER_START;
            FILETIME ft{};
            LI_KERNEL(GetSystemTimeAsFileTime)(&ft);
            ULARGE_INTEGER uli{};
            uli.LowPart  = ft.dwLowDateTime;
            uli.HighPart = ft.dwHighDateTime;
            const uint64_t unix_100ns = uli.QuadPart - 116444736000000000ULL;
            const uint32_t ts = static_cast<uint32_t>(unix_100ns / 10000000ULL);
            const uint32_t r = ts ^ k_xor ^ steam_low32(steam_hex);
            VIRTUALIZER_END;
            return r;
        }
    }

    __declspec(noinline) uint64_t resolve_target(HANDLE process, uint64_t module_base, uint64_t module_size)
    {
        VIRTUALIZER_START;
        const uint64_t hit = common::pattern_scan(process, module_base, module_size,
                                                  k_outer_sig, k_outer_mask);
        if (!hit)
            return 0;

        constexpr size_t k_max_backward = 128;
        const uint64_t scan_start = (hit > k_max_backward) ? hit - k_max_backward : module_base;
        const size_t   scan_len   = static_cast<size_t>(hit - scan_start);

        std::vector<uint8_t> buf(scan_len);
        SIZE_T got = 0;
        if (!LI_KERNEL(ReadProcessMemory)(process,
                reinterpret_cast<LPCVOID>(scan_start),
                buf.data(), scan_len, &got) || got != scan_len)
            return 0;
        VIRTUALIZER_END;

        for (size_t i = scan_len - 3; i != static_cast<size_t>(-1); --i)
        {
            if (buf[i]     == k_movss_prefix[0] &&
                buf[i + 1] == k_movss_prefix[1] &&
                buf[i + 2] == k_movss_prefix[2])
            {
                if (i + 8 > scan_len)
                    return 0;

                int32_t disp = 0;
                std::memcpy(&disp, &buf[i + 4], 4);

                const uint64_t insn_addr = scan_start + i;
                return static_cast<uint64_t>(
                    static_cast<int64_t>(insn_addr + 8) + disp);
            }
        }
        return 0;
    }

    __declspec(noinline) uint32_t make_token_public(const std::string& steam_hex)
    {
        VIRTUALIZER_START;
        const uint32_t r = make_token(steam_hex);
        VIRTUALIZER_END;
        return r;
    }

    __declspec(noinline) void stamp(HANDLE process, uint64_t target_addr, const std::string& steam_hex)
    {
        VIRTUALIZER_START;
        if (!process || !target_addr)
            return;

        MEMORY_BASIC_INFORMATION mbi{};
        if (!LI_KERNEL(VirtualQueryEx)(process, reinterpret_cast<LPCVOID>(target_addr),
                                       &mbi, sizeof(mbi)))
            return;

        if (mbi.State != MEM_COMMIT)
            return;

        constexpr DWORD k_writable = PAGE_READWRITE | PAGE_WRITECOPY |
                                     PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
        if (!(mbi.Protect & k_writable))
            return;

        const uint32_t token = make_token(steam_hex);
        SIZE_T written = 0;
        LI_KERNEL(WriteProcessMemory)(process,
                reinterpret_cast<LPVOID>(target_addr),
                &token, sizeof(token), &written);
        VIRTUALIZER_END;
    }
}
