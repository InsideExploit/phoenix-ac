#include "lua_script.hpp"
#include "vendor/lazy_importer.hpp"
#include "vendor/xor_string.hpp"
#include <cstdint>
#include <cstring>
#include <vector>
namespace detections::lua_script
{
    namespace
    {
        bool contains(const uint8_t* buffer, size_t length, const char* needle)
        {
            const size_t needle_len = strlen(needle);
            if (needle_len == 0 || needle_len > length)
                return false;

            const uint8_t* end = buffer + length - needle_len;
            for (const uint8_t* p = buffer; p <= end; ++p)
            {
                if (std::memcmp(p, needle, needle_len) == 0)
                    return true;
            }
            return false;
        }

        bool is_read_only(DWORD protect)
        {
            const DWORD p = protect & 0xFF;
            if (protect & PAGE_GUARD)          return false;
            if (p == PAGE_EXECUTE)             return false;
            if (p == PAGE_EXECUTE_READ)        return false;
            if (p == PAGE_EXECUTE_READWRITE)   return false;
            if (p == PAGE_EXECUTE_WRITECOPY)   return false;
            if (p == PAGE_NOACCESS)            return false;
            return p == PAGE_READONLY || p == PAGE_READWRITE || p == PAGE_WRITECOPY;
        }

        struct pair_pattern
        {
            const char*    enum_str;
            const char*    draw_str;
            const wchar_t* label;
        };

        struct solo_pattern
        {
            const char*    str;
            const wchar_t* label;
        };
    }

    std::vector<hit> scan(HANDLE fivem_handle)
    {
        std::vector<hit> results;
        std::vector<uint8_t> buffer;

        const pair_pattern k_pair_patterns[] = {
            { XS("GetAllPeds"),  XS("DrawRect"),   XSW(L"ESP: GetAllPeds+DrawRect")    },
            { XS("GetAllPeds"),  XS("DrawText"),   XSW(L"ESP: GetAllPeds+DrawText")    },
            { XS("GetAllPeds"),  XS("DrawSprite"), XSW(L"ESP: GetAllPeds+DrawSprite")  },
            { XS("GetAllPeds"),  XS("DrawLine"),   XSW(L"ESP: GetAllPeds+DrawLine")    },
            { XS("GetGamePool"), XS("DrawRect"),   XSW(L"ESP: GetGamePool+DrawRect")   },
            { XS("GetGamePool"), XS("DrawText"),   XSW(L"ESP: GetGamePool+DrawText")   },
            { XS("GetGamePool"), XS("DrawSprite"), XSW(L"ESP: GetGamePool+DrawSprite") },
        };

        const solo_pattern k_solo_patterns[] = {
            { XS("GetAllObjects"), XSW(L"EntityESP: GetAllObjects")     },
            { XS("no_namer"),      XSW(L"Cheat: no_namer signature")    },
            { XS("eulen_"),        XSW(L"Cheat: Eulen signature")       },
            { XS("toxic_menu"),    XSW(L"Cheat: Toxic signature")       },
            { XS("lynx_esp"),      XSW(L"Cheat: Lynx ESP signature")    },
            { XS("impulse_cheat"), XSW(L"Cheat: Impulse signature")     },
            { XS("AimbotEnabled"), XSW(L"Cheat: aimbot state variable") },
            { XS("esp_enabled"),   XSW(L"Cheat: ESP state variable")    },
            { XS("noclip_speed"),  XSW(L"Cheat: noclip variable")       },
            { XS("triggerbot"),    XSW(L"Cheat: triggerbot module")     },
        };

        LPVOID address = nullptr;
        MEMORY_BASIC_INFORMATION mbi{};

        while (LI_KERNEL(VirtualQueryEx)(fivem_handle, address, &mbi, sizeof(mbi)) == sizeof(mbi))
        {
            uint8_t* next = static_cast<uint8_t*>(mbi.BaseAddress) + mbi.RegionSize;

            const bool region_ok = mbi.State == MEM_COMMIT
                                && mbi.Type == MEM_PRIVATE
                                && is_read_only(mbi.Protect)
                                && mbi.RegionSize >= 256
                                && mbi.RegionSize <= 64 * 1024 * 1024;

            if (region_ok)
            {
                if (buffer.size() < mbi.RegionSize)
                    buffer.resize(mbi.RegionSize);

                SIZE_T got = 0;
                if (LI_KERNEL(ReadProcessMemory)(fivem_handle, mbi.BaseAddress,
                                      buffer.data(), mbi.RegionSize, &got) && got >= 256)
                {
                    bool matched = false;

                    for (const auto& p : k_pair_patterns)
                    {
                        if (contains(buffer.data(), got, p.enum_str)
                            && contains(buffer.data(), got, p.draw_str))
                        {
                            hit h{};
                            h.address = reinterpret_cast<uint64_t>(mbi.BaseAddress);
                            h.size    = static_cast<uint32_t>(got);
                            wcsncpy_s(h.pattern, p.label, 63);
                            results.push_back(h);
                            matched = true;
                            break;
                        }
                    }

                    if (!matched)
                    {
                        for (const auto& s : k_solo_patterns)
                        {
                            if (contains(buffer.data(), got, s.str))
                            {
                                hit h{};
                                h.address = reinterpret_cast<uint64_t>(mbi.BaseAddress);
                                h.size    = static_cast<uint32_t>(got);
                                wcsncpy_s(h.pattern, s.label, 63);
                                results.push_back(h);
                                break;
                            }
                        }
                    }
                }
            }

            if (mbi.RegionSize == 0)
                break;
            address = next;
        }

        return results;
    }
}