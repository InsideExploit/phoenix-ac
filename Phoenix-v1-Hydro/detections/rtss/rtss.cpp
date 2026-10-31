#include "rtss.hpp"
#include "vendor/lazy_importer.hpp"
#include "vendor/xor_string.hpp"
#include <cstring>
namespace detections::rtss
{
    namespace
    {
        struct rtss_header
        {
            DWORD signature;
            DWORD version;
            DWORD app_entry_size;
            DWORD app_array_offset;
            DWORD app_array_size;
            DWORD osd_entry_size;
            DWORD osd_array_offset;
            DWORD osd_array_size;
        };

        constexpr DWORD k_osd_owner_offset = 256;
        constexpr DWORD k_osd_ex_offset    = 512;
        constexpr DWORD k_app_pid_offset   = 0;

        bool is_allowed_owner(const char* owner)
        {
            static const char* const k_allowed[] = {
                XS("MSI Afterburner"),
                XS("EVGA Precision X1"),
                XS("EVGA Precision XOC"),
                XS("EVGA Precision XOC1"),
                XS("HWiNFO64"),
                XS("GPU-Z"),
                XS("RTSS"),
                XS("RivaTuner Statistics Server"),
                XS("CPU-Z"),
                XS("CPUID HWMonitor"),
                XS("HWMonitor"),
                XS("Fraps"),
                XS("GeForce Experience"),
                XS("SteelSeries GG"),
                XS("Overwolf"),
                XS("Medal"),
                XS("Discord"),
            };
            for (const char* a : k_allowed)
            {
                if (_stricmp(owner, a) == 0)
                    return true;
            }
            return false;
        }

        bool contains_esp_tags(const char* text, size_t max_len)
        {
            for (size_t i = 0; i < max_len && text[i]; ++i)
            {
                if (text[i] == '<' && i + 2 < max_len)
                {
                    const char c = text[i + 1];
                    if ((c == 'P' || c == 'B') && text[i + 2] == '=')
                        return true;
                }
            }
            return false;
        }
    }

    bool is_running()
    {
        HANDLE mapping = OpenFileMappingA(FILE_MAP_READ, FALSE, XS("RTSSSharedMemoryV2"));
        if (!mapping)
            return false;
        LI_KERNEL(CloseHandle)(mapping);
        return true;
    }

    std::vector<hit> scan(const config& cfg, bool* out_game_hooked)
    {
        std::vector<hit> results;

        if (out_game_hooked)
            *out_game_hooked = false;

        HANDLE mapping = OpenFileMappingA(FILE_MAP_READ, FALSE, XS("RTSSSharedMemoryV2"));
        if (!mapping)
            return results;

        LPVOID view = LI_KERNEL(MapViewOfFile)(mapping, FILE_MAP_READ, 0, 0, 0);
        if (!view)
        {
            LI_KERNEL(CloseHandle)(mapping);
            return results;
        }

        auto* header = reinterpret_cast<rtss_header*>(view);
        if (header->signature != 'RTSS' || header->version < 0x00020000)
        {
            LI_KERNEL(UnmapViewOfFile)(view);
            LI_KERNEL(CloseHandle)(mapping);
            return results;
        }

        if (cfg.fivem_pid && out_game_hooked && header->app_entry_size >= 4)
        {
            for (DWORD i = 0; i < header->app_array_size && i < 256; ++i)
            {
                LPBYTE app_entry = static_cast<LPBYTE>(view) + header->app_array_offset + i * header->app_entry_size;
                const DWORD app_pid = *reinterpret_cast<const DWORD*>(app_entry + k_app_pid_offset);
                if (app_pid == cfg.fivem_pid)
                {
                    *out_game_hooked = true;
                    break;
                }
            }
        }

        for (DWORD i = 1; i < header->osd_array_size && i < 8; ++i)
        {
            if (header->osd_entry_size < (k_osd_owner_offset + 256))
                continue;

            LPBYTE entry = static_cast<LPBYTE>(view) + header->osd_array_offset + i * header->osd_entry_size;
            const char* owner = reinterpret_cast<const char*>(entry + k_osd_owner_offset);

            if (!owner[0])
                continue;

            hit h{};
            strncpy_s(h.owner, owner, sizeof(h.owner) - 1);

            if (_stricmp(owner, XS("RTSSSharedMemorySample")) == 0)
            {
                h.flags |= flag_sample_owner | flag_suspicious_owner;
                h.score += 6;
            }
            else if (!is_allowed_owner(owner))
            {
                h.flags |= flag_suspicious_owner;
                h.score += 3;
            }

            if (header->version >= 0x00020007
                && header->osd_entry_size >= (k_osd_ex_offset + 4096))
            {
                const char* osd_ex = reinterpret_cast<const char*>(entry + k_osd_ex_offset);
                if (contains_esp_tags(osd_ex, 4096))
                {
                    h.flags |= flag_esp_format_tags;
                    h.score += 4;
                }

                size_t preview_index = 0;
                for (const char* c = osd_ex; *c && preview_index < sizeof(h.osd_preview) - 1; ++c)
                {
                    const unsigned char uc = static_cast<unsigned char>(*c);
                    if (uc >= 0x20 && uc < 0x7F)
                        h.osd_preview[preview_index++] = *c;
                }
                h.osd_preview[preview_index] = '\0';
            }

            if (out_game_hooked && *out_game_hooked)
                h.flags |= flag_game_hooked;

            if (h.score >= cfg.min_score)
                results.push_back(h);
        }

        LI_KERNEL(UnmapViewOfFile)(view);
        LI_KERNEL(CloseHandle)(mapping);
        return results;
    }
}