#include "silent_aim.hpp"

#include "vendor/lazy_importer.hpp"

#include <cstring>
#include <vector>

namespace detections::silent_aim
{
    namespace
    {
        constexpr uint8_t k_sig_a[] = {
            0x48, 0x8D, 0x45, 0x00, 0xF3, 0x0F, 0x10, 0x00,
            0xF3, 0x0F, 0x10, 0x48, 0x00, 0xF3, 0x0F, 0x11, 0x45
        };
        constexpr size_t k_sig_a_length      = sizeof(k_sig_a);
        constexpr size_t k_sig_a_baseline_bytes = 38;

        constexpr uint8_t k_sig_b[] = {
            0xF3, 0x41, 0x0F, 0x10, 0x19,
            0xF3, 0x41, 0x0F, 0x10, 0x41, 0x04,
            0xF3, 0x41, 0x0F, 0x10, 0x51, 0x08
        };
        constexpr size_t k_sig_b_length      = sizeof(k_sig_b);
        constexpr size_t k_sig_b_baseline_bytes = 17;

        uint64_t g_module_base = 0;
        size_t   g_module_size = 0;

        uint64_t              g_addr_a = 0;
        std::vector<uint8_t>  g_baseline_a;

        uint64_t              g_addr_b = 0;
        std::vector<uint8_t>  g_baseline_b;

        bool g_ready  = false;
        bool g_tried  = false;

        bool read_memory(HANDLE process, uint64_t address, void* buffer, size_t size)
        {
            SIZE_T got = 0;
            return LI_KERNEL(ReadProcessMemory)(process, reinterpret_cast<LPCVOID>(address), buffer, size, &got)
                && got == size;
        }

        uint64_t find_signature(HANDLE process,
                                uint64_t base,
                                size_t size,
                                const uint8_t* signature,
                                size_t signature_length,
                                bool use_wildcard)
        {
            constexpr size_t block_size = 16 * 1024;
            std::vector<uint8_t> buffer(block_size + signature_length);

            for (uint64_t offset = 0; offset + signature_length <= size;)
            {
                const size_t to_read = (offset + block_size + signature_length <= size)
                                           ? (block_size + signature_length)
                                           : static_cast<size_t>(size - offset);
                SIZE_T got = 0;
                if (!LI_KERNEL(ReadProcessMemory)(process,
                                       reinterpret_cast<LPCVOID>(base + offset),
                                       buffer.data(), to_read, &got)
                    || got < signature_length)
                {
                    offset += block_size;
                    continue;
                }

                for (size_t i = 0; i + signature_length <= got; ++i)
                {
                    bool matched = true;
                    for (size_t j = 0; j < signature_length; ++j)
                    {
                        if (use_wildcard && signature[j] == 0x00)
                            continue;
                        if (buffer[i + j] != signature[j])
                        {
                            matched = false;
                            break;
                        }
                    }
                    if (matched)
                        return base + offset + i;
                }

                offset += block_size;
            }
            return 0;
        }
    }

    void reset()
    {
        g_module_base = 0;
        g_module_size = 0;
        g_addr_a = 0;
        g_addr_b = 0;
        g_baseline_a.clear();
        g_baseline_b.clear();
        g_ready = false;
        g_tried = false;
    }

    bool is_ready()  { return g_ready; }
    bool was_tried() { return g_tried; }

    bool init(HANDLE fivem_handle, uint64_t module_base, size_t module_size)
    {
        reset();
        if (!fivem_handle || !module_base || !module_size)
            return false;

        g_module_base = module_base;
        g_module_size = module_size;

        g_addr_a = find_signature(fivem_handle, module_base, module_size,
                                  k_sig_a, k_sig_a_length, true);
        if (g_addr_a)
        {
            g_baseline_a.resize(k_sig_a_baseline_bytes);
            if (!read_memory(fivem_handle, g_addr_a, g_baseline_a.data(), k_sig_a_baseline_bytes))
            {
                g_addr_a = 0;
                g_baseline_a.clear();
            }
        }

        g_addr_b = find_signature(fivem_handle, module_base, module_size,
                                  k_sig_b, k_sig_b_length, false);
        if (g_addr_b)
        {
            g_baseline_b.resize(k_sig_b_baseline_bytes);
            if (!read_memory(fivem_handle, g_addr_b, g_baseline_b.data(), k_sig_b_baseline_bytes))
            {
                g_addr_b = 0;
                g_baseline_b.clear();
            }
        }

        g_ready = (g_addr_a != 0) || (g_addr_b != 0);
        g_tried = true;
        return g_ready;
    }

    std::vector<hit> scan(HANDLE fivem_handle)
    {
        std::vector<hit> out;
        if (!g_ready || !fivem_handle)
            return out;

        if (g_addr_a)
        {
            uint8_t current[k_sig_a_baseline_bytes]{};
            if (read_memory(fivem_handle, g_addr_a, current, k_sig_a_baseline_bytes))
            {
                hit h{};
                h.address = g_addr_a;

                if      (current[0] == 0xE9)                              h.kind = hit_kind::v1_jmp_hook;
                else if (current[0] == 0xC7)                              h.kind = hit_kind::v1_mov_hook;
                else if (current[0] == 0xFF && current[1] == 0x25)        h.kind = hit_kind::v1_indirect;
                else if (std::memcmp(current, g_baseline_a.data(), k_sig_a_baseline_bytes) != 0)
                    h.kind = hit_kind::v1_integrity;

                if (h.kind != hit_kind::none)
                    out.push_back(h);
            }
        }

        if (g_addr_b)
        {
            uint8_t current[k_sig_b_baseline_bytes]{};
            if (read_memory(fivem_handle, g_addr_b, current, k_sig_b_baseline_bytes))
            {
                hit h{};
                h.address = g_addr_b;

                if (current[0] == 0xE9)
                    h.kind = hit_kind::v2_jmp_hook;
                else if (std::memcmp(current, g_baseline_b.data(), k_sig_b_baseline_bytes) != 0)
                    h.kind = hit_kind::v2_integrity;

                if (h.kind != hit_kind::none)
                {
                    out.push_back(h);
                }
                else
                {
                    uint8_t payload[33]{};
                    if (read_memory(fivem_handle, g_module_base + 0x34E, payload, sizeof(payload)))
                    {
                        hit ph{};
                        ph.address = g_module_base + 0x34E;

                        if (payload[0] == 0x41 && payload[1] == 0xC7 && payload[2] == 0x01)
                            ph.kind = hit_kind::v2_payload;
                        else if (payload[0] == 0x41 && payload[1] == 0xC7
                                 && payload[2] == 0x41 && payload[3] == 0x04)
                            ph.kind = hit_kind::v2_payload_alt;

                        if (ph.kind != hit_kind::none)
                            out.push_back(ph);
                    }
                }
            }
        }

        return out;
    }
}
