#include "syscall_hook.hpp"
#include "vendor/lazy_importer.hpp"
#include "vendor/xor_string.hpp"
#include <Windows.h>
#include <TlHelp32.h>
#include <cstdint>
#include <string>
#include <vector>
namespace response::syscall_hook
{
    namespace
    {
        class assembler
        {
        public:
            std::vector<uint8_t> bytes;

            void emit(uint8_t byte)
            {
                bytes.push_back(byte);
            }

            void emit(std::initializer_list<uint8_t> byte_list)
            {
                for (auto b : byte_list)
                    bytes.push_back(b);
            }

            void emit_u32(uint32_t value)
            {
                for (int i = 0; i < 4; ++i)
                    bytes.push_back(static_cast<uint8_t>((value >> (i * 8)) & 0xFF));
            }

            void emit_u64(uint64_t value)
            {
                for (int i = 0; i < 8; ++i)
                    bytes.push_back(static_cast<uint8_t>((value >> (i * 8)) & 0xFF));
            }

            size_t position() const
            {
                return bytes.size();
            }

            void patch_u32(size_t offset, uint32_t value)
            {
                for (int i = 0; i < 4; ++i)
                    bytes[offset + i] = static_cast<uint8_t>((value >> (i * 8)) & 0xFF);
            }
        };

        std::vector<uint8_t> build_shellcode(const poison_cfg::payload_config& c)
        {
            assembler a;

            struct fixup { size_t from; size_t* label_ptr; };

            size_t label_return_original  = SIZE_MAX;
            size_t label_return_success   = SIZE_MAX;
            size_t label_skip_viewport    = SIZE_MAX;
            size_t label_skip_cam         = SIZE_MAX;
            size_t label_anchor_hit       = SIZE_MAX;
            size_t label_return_zero      = SIZE_MAX;

            std::vector<fixup> fixups;

            auto jcc_rel32 = [&](uint8_t opcode2, size_t* label_addr) {
                a.emit({ 0x0F, opcode2 });
                const size_t patch_offset = a.position();
                a.emit_u32(0);
                fixups.push_back({ patch_offset, label_addr });
            };

            auto jmp_rel32 = [&](size_t* label_addr) {
                a.emit(0xE9);
                const size_t patch_offset = a.position();
                a.emit_u32(0);
                fixups.push_back({ patch_offset, label_addr });
            };

            a.emit(0x53);
            a.emit(0x56);
            a.emit(0x57);
            a.emit(0x55);
            a.emit({ 0x41, 0x54 });
            a.emit({ 0x41, 0x55 });
            a.emit({ 0x41, 0x56 });
            a.emit({ 0x41, 0x57 });
            a.emit({ 0x48, 0x83, 0xEC, 0x68 });

            a.emit({ 0x49, 0x89, 0xCC });
            a.emit({ 0x49, 0x89, 0xD5 });
            a.emit({ 0x4D, 0x89, 0xC6 });
            a.emit({ 0x4D, 0x89, 0xCF });
            a.emit({ 0x48, 0x8B, 0x9C, 0x24 });
            a.emit_u32(0xD0);

            a.emit({ 0x48, 0x89, 0x5C, 0x24, 0x28 });
            a.emit({ 0x4C, 0x8B, 0xD1 });
            a.emit({ 0xB8 });
            a.emit_u32(c.ssn_nt_read_virtual_memory);
            a.emit({ 0x0F, 0x05 });
            a.emit({ 0x85, 0xC0 });
            jcc_rel32(0x88, &label_return_original);

            a.emit({ 0x4C, 0x89, 0xE1 });
            a.emit({ 0x31, 0xD2 });
            a.emit({ 0x4C, 0x8D, 0x44, 0x24, 0x30 });
            a.emit({ 0x41, 0xB9 });
            a.emit_u32(0x30);
            a.emit({ 0x48, 0xC7, 0x44, 0x24, 0x28, 0x00, 0x00, 0x00, 0x00 });
            a.emit({ 0x4C, 0x8B, 0xD1 });
            a.emit({ 0xB8 });
            a.emit_u32(c.ssn_nt_query_information_process);
            a.emit({ 0x0F, 0x05 });
            a.emit({ 0x85, 0xC0 });
            jcc_rel32(0x88, &label_return_original);

            a.emit({ 0x8B, 0x44, 0x24, 0x50 });
            a.emit({ 0x3D });
            a.emit_u32(c.fivem_pid);
            jcc_rel32(0x85, &label_return_original);

            a.emit({ 0x48, 0xB8 });
            a.emit_u64(c.viewport);
            a.emit({ 0x49, 0x39, 0xC5 });
            jcc_rel32(0x82, &label_skip_viewport);

            a.emit({ 0x48, 0xB8 });
            a.emit_u64(c.viewport_end);
            a.emit({ 0x49, 0x39, 0xC5 });
            jcc_rel32(0x83, &label_skip_viewport);

            a.emit({ 0x4D, 0x85, 0xFF });
            jcc_rel32(0x84, &label_return_success);
            a.emit({ 0x4C, 0x89, 0xF7 });
            a.emit({ 0x4C, 0x89, 0xF9 });
            a.emit({ 0x31, 0xC0 });
            a.emit({ 0xF3, 0xAA });
            a.emit({ 0x49, 0x83, 0xFF, 0x40 });
            jcc_rel32(0x82, &label_return_success);
            a.emit({ 0x41, 0xC7, 0x06, 0x00, 0x00, 0x80, 0x3F });
            a.emit({ 0x41, 0xC7, 0x46, 0x14, 0x00, 0x00, 0x80, 0x3F });
            a.emit({ 0x41, 0xC7, 0x46, 0x28, 0x00, 0x00, 0x80, 0x3F });
            jmp_rel32(&label_return_success);

            label_skip_viewport = a.position();

            a.emit({ 0x48, 0xB8 });
            a.emit_u64(c.cam_dir);
            a.emit({ 0x49, 0x39, 0xC5 });
            jcc_rel32(0x82, &label_skip_cam);
            a.emit({ 0x48, 0xB8 });
            a.emit_u64(c.cam_end);
            a.emit({ 0x49, 0x39, 0xC5 });
            jcc_rel32(0x83, &label_skip_cam);
            a.emit({ 0x4D, 0x85, 0xFF });
            jcc_rel32(0x84, &label_return_success);
            a.emit({ 0x4C, 0x89, 0xF7 });
            a.emit({ 0x4C, 0x89, 0xF9 });
            a.emit({ 0x31, 0xC0 });
            a.emit({ 0xF3, 0xAA });
            jmp_rel32(&label_return_success);

            label_skip_cam = a.position();

            auto compare_anchor = [&](uint64_t value) {
                a.emit({ 0x48, 0xB8 });
                a.emit_u64(value);
                a.emit({ 0x49, 0x39, 0xC5 });
                jcc_rel32(0x84, &label_anchor_hit);
            };

            if (c.world)     compare_anchor(c.world);
            if (c.ped_pool)  compare_anchor(c.ped_pool);
            if (c.blip_list) compare_anchor(c.blip_list);
            if (c.aim)       compare_anchor(c.aim);
            jmp_rel32(&label_return_original);

            label_anchor_hit = a.position();
            a.emit({ 0x4D, 0x85, 0xFF });
            jcc_rel32(0x84, &label_return_success);
            a.emit({ 0x4C, 0x89, 0xF7 });
            a.emit({ 0x4C, 0x89, 0xF9 });
            a.emit({ 0x31, 0xC0 });
            a.emit({ 0xF3, 0xAA });

            label_return_success = a.position();
            a.emit({ 0x48, 0x85, 0xDB });
            jcc_rel32(0x84, &label_return_zero);
            a.emit({ 0x4C, 0x89, 0x3B });
            label_return_zero = a.position();
            a.emit({ 0x31, 0xC0 });

            label_return_original = a.position();
            a.emit({ 0x48, 0x83, 0xC4, 0x68 });
            a.emit({ 0x41, 0x5F });
            a.emit({ 0x41, 0x5E });
            a.emit({ 0x41, 0x5D });
            a.emit({ 0x41, 0x5C });
            a.emit(0x5D);
            a.emit(0x5F);
            a.emit(0x5E);
            a.emit(0x5B);
            a.emit(0xC3);

            for (auto& fx : fixups)
            {
                const size_t label_addr = *fx.label_ptr;
                const int32_t rel = static_cast<int32_t>(label_addr - (fx.from + 4));
                a.patch_u32(fx.from, static_cast<uint32_t>(rel));
            }

            return std::move(a.bytes);
        }

        bool patch_stub(HANDLE process, uint64_t target_remote, uint64_t hook_addr)
        {
            BYTE patch[14];
            patch[0] = 0xFF;
            patch[1] = 0x25;
            *reinterpret_cast<uint32_t*>(patch + 2) = 0;
            *reinterpret_cast<uint64_t*>(patch + 6) = hook_addr;

            DWORD old_protect = 0;
            if (!LI_KERNEL(VirtualProtectEx)(process, reinterpret_cast<LPVOID>(target_remote),
                                  sizeof(patch), PAGE_EXECUTE_READWRITE, &old_protect))
                return false;

            SIZE_T written = 0;
            const BOOL ok = LI_KERNEL(WriteProcessMemory)(process, reinterpret_cast<LPVOID>(target_remote),
                                               patch, sizeof(patch), &written);

            DWORD temp = 0;
            LI_KERNEL(VirtualProtectEx)(process, reinterpret_cast<LPVOID>(target_remote),
                             sizeof(patch), old_protect, &temp);
            FlushInstructionCache(process, reinterpret_cast<LPCVOID>(target_remote), sizeof(patch));

            return ok && written == sizeof(patch);
        }

        uint64_t remote_symbol(HANDLE process, DWORD pid, const char* module_name, const char* function_name)
        {
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

            if (!base)
                return 0;

            HMODULE local = LI_KERNEL(GetModuleHandleA)(module_name);
            if (!local)
                return 0;

            auto local_addr = reinterpret_cast<BYTE*>(LI_KERNEL(GetProcAddress)(local, function_name));
            if (!local_addr)
                return 0;

            const uint64_t offset = reinterpret_cast<uint64_t>(local_addr) - reinterpret_cast<uint64_t>(local);
            return base + offset;
        }
    }

    bool deploy(DWORD cheat_pid, const poison_cfg::payload_config& cfg, hook_info* out_info)
    {
        HANDLE process = LI_KERNEL(OpenProcess)(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                                     FALSE, cheat_pid);
        if (!process)
            return false;

        bool ok = false;

        const uint64_t nt_read_vm_remote = remote_symbol(process, cheat_pid,
                                                         XS("ntdll.dll"),
                                                         XS("NtReadVirtualMemory"));
        if (nt_read_vm_remote)
        {
            BYTE first_byte = 0;
            SIZE_T got = 0;
            LI_KERNEL(ReadProcessMemory)(process, reinterpret_cast<LPCVOID>(nt_read_vm_remote),
                              &first_byte, 1, &got);

            if (first_byte == 0xFF || first_byte == 0xE9)
            {
                if (out_info)
                {
                    out_info->nt_read_vm_address = nt_read_vm_remote;
                    out_info->shellcode_address  = 0;
                }
                ok = true;
            }
            else
            {
                const std::vector<uint8_t> shellcode = build_shellcode(cfg);
                LPVOID remote = LI_KERNEL(VirtualAllocEx)(process, nullptr, shellcode.size(),
                                               MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                if (remote)
                {
                    SIZE_T written = 0;
                    const bool wrote = LI_KERNEL(WriteProcessMemory)(process, remote,
                                                          shellcode.data(), shellcode.size(),
                                                          &written)
                                     && written == shellcode.size();
                    if (wrote)
                    {
                        FlushInstructionCache(process, remote, shellcode.size());
                        if (patch_stub(process, nt_read_vm_remote, reinterpret_cast<uint64_t>(remote)))
                        {
                            if (out_info)
                            {
                                out_info->nt_read_vm_address = nt_read_vm_remote;
                                out_info->shellcode_address  = reinterpret_cast<uint64_t>(remote);
                            }
                            ok = true;
                        }
                    }

                    if (!ok)
                        LI_KERNEL(VirtualFreeEx)(process, remote, 0, MEM_RELEASE);
                }
            }
        }

        LI_KERNEL(CloseHandle)(process);
        return ok;
    }
}