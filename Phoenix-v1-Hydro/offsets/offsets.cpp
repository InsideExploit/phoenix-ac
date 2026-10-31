#include "offsets.hpp"

#include "common/common.hpp"
#include "vendor/lazy_importer.hpp"

namespace offsets
{
    pack resolve(int build)
    {
        switch (build)
        {
        case 3570: return { 0x25EC580, 0x2058BA0, 0x2059A48, 0x2061870, 0,          0          };
        case 3407: return { 0x25D7108, 0x20431C0, 0x20440C8, 0x2047D50, 0,          0x2051EE0  };
        case 3323: return { 0x25B14B0, 0x201DBA0, 0x201ED50, 0x2023400, 0,          0          };
        case 3258: return { 0x25B14B0, 0x201DBA0, 0x201ED50, 0x2023400, 0,          0x202C8D0  };
        case 3095: return { 0x2593320, 0x20019E0, 0x2002888, 0x2002FA0, 0,          0          };
        case 2944: return { 0x257BEA0, 0x1FEAAC0, 0x1FEB968, 0x1FF3130, 0,          0          };
        case 2802: return { 0x254D448, 0x1FBC100, 0x1FBCFA8, 0x1FBD6E0, 0,          0          };
        case 2699: return { 0x26684D8, 0x20D8C90, 0x20D9B38, 0x20E1420, 0,          0          };
        case 2612: return { 0x2567DB0, 0x1FD8570, 0x1FD9418, 0x1FDDD20, 0,          0          };
        case 2545: return { 0x25667E8, 0x1FD6F70, 0x1FD7E18, 0x1FDF560, 0,          0          };
        case 2372: return { 0x252DCD8, 0x1F9E9F0, 0x1F9F898, 0x1F9FFA0, 0,          0          };
        case 2189: return { 0x24E6D90, 0x1F888C0, 0x1F89768, 0x1F6EF80, 0,          0          };
        case 2060: return { 0x24C8858, 0x1F6A7E0, 0x1F6B940, 0x1F4F940, 0,          0          };
        case 1604: return { 0x247F840, 0x2087780, 0x20888E0, 0x206B4E0, 0,          0          };
        default:   return { 0x25B14B0, 0x201DBA0, 0x201ED50, 0x2023400, 0,          0x202C8D0  };
        }
    }

    uint64_t find_ped_pool(HANDLE process, uint64_t base, uint64_t size)
    {
        static const uint8_t sig_a[] = {
            0x48,0x8B,0x15,0,0,0,0,   0x41,0xB9,0,0,0,0,   0x41,0xB8,0,0,0,0,
            0x48,0x8B,0xD9,           0x44,0x89,0x4C,0x24,0x20,   0xE8,0,0,0,0,
            0x48,0x89,0xBB,0xC0,0x0B
        };
        static const char mask_a[] = "xxx????xx????xx????xxxxxxxxx????xxxxx";

        if (const uint64_t hit = common::pattern_scan(process, base, size, sig_a, mask_a))
        {
            int32_t displacement = 0;
            SIZE_T got = 0;
            LI_KERNEL(ReadProcessMemory)(process, reinterpret_cast<LPCVOID>(hit + 3), &displacement, sizeof(displacement), &got);
            return hit + 7 + displacement;
        }

        static const uint8_t sig_b[] = {
            0x48,0x8B,0x15,0,0,0,0,   0x48,0x85,0xD2,   0x74,0,   0x8B,0x42,0x08,   0x3B,0x42,0x14
        };
        static const char mask_b[] = "xxx????xxxx?xxxxxx";

        if (const uint64_t hit = common::pattern_scan(process, base, size, sig_b, mask_b))
        {
            int32_t displacement = 0;
            SIZE_T got = 0;
            LI_KERNEL(ReadProcessMemory)(process, reinterpret_cast<LPCVOID>(hit + 3), &displacement, sizeof(displacement), &got);
            return hit + 7 + displacement;
        }

        return 0;
    }

    uint64_t find_viewport(HANDLE process,
                           uint64_t module_base,
                           uint64_t module_size,
                           uint64_t fallback_global)
    {
        static const uint8_t sig[] = {
            0x48, 0x8B, 0x15, 0,0,0,0,
            0x48, 0x8D, 0x2D, 0,0,0,0,
            0x48, 0x8B, 0xCD
        };
        static const char mask[] = "xxx????xxx????xxx";

        constexpr uint64_t k_userland_ceiling = 0x00007FFFFFFFFFFFULL;
        constexpr uint64_t k_min_valid_ptr    = 0x10000ULL;

        if (const uint64_t hit = common::pattern_scan(process, module_base, module_size, sig, mask))
        {
            int32_t displacement = 0;
            SIZE_T got = 0;
            if (LI_KERNEL(ReadProcessMemory)(process, reinterpret_cast<LPCVOID>(hit + 10), &displacement, sizeof(displacement), &got) && got == 4)
            {
                const uint64_t global_ptr = hit + 14 + static_cast<int64_t>(displacement);
                uint64_t value = 0;
                if (LI_KERNEL(ReadProcessMemory)(process, reinterpret_cast<LPCVOID>(global_ptr), &value, sizeof(value), &got) && got == 8)
                {
                    if (value > k_min_valid_ptr && value < k_userland_ceiling)
                        return value;
                }
            }
        }

        if (fallback_global)
        {
            uint64_t value = 0;
            SIZE_T got = 0;
            if (LI_KERNEL(ReadProcessMemory)(process, reinterpret_cast<LPCVOID>(fallback_global), &value, sizeof(value), &got) && got == 8)
            {
                if (value > k_min_valid_ptr && value < k_userland_ceiling)
                    return value;
            }
        }

        return 0;
    }
}
