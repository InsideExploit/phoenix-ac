#include "handles.hpp"

#include "vendor/lazy_importer.hpp"

#include <winternl.h>

#include <cstdint>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#ifndef NT_SUCCESS
#define NT_SUCCESS(x) (((NTSTATUS)(x)) >= 0)
#endif

namespace detections::handles
{
    namespace
    {
        constexpr ULONG k_system_extended_handle_information = 0x40;
        constexpr NTSTATUS k_status_info_length_mismatch     = 0xC0000004;

        struct handle_table_entry
        {
            PVOID     object;
            ULONG_PTR unique_process_id;
            ULONG_PTR handle_value;
            ULONG     granted_access;
            USHORT    creator_back_trace_index;
            USHORT    object_type_index;
            ULONG     handle_attributes;
            ULONG     reserved;
        };

        struct handle_info_ex
        {
            ULONG_PTR          number_of_handles;
            ULONG_PTR          reserved;
            handle_table_entry handles[1];
        };
    }
}

extern "C" NTSTATUS NTAPI NtDuplicateObject(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG);

namespace detections::handles
{
    namespace
    {
        DWORD safe_get_process_id(HANDLE handle)
        {
            DWORD pid = 0;
            __try { pid = LI_KERNEL(GetProcessId)(handle); }
            __except (EXCEPTION_EXECUTE_HANDLER) { pid = 0; }
            return pid;
        }

        USHORT discover_process_type_index()
        {
            static USHORT cached = 0;
            if (cached != 0)
                return cached;

            ULONG size = 1 << 20;
            std::vector<uint8_t> buffer(size);
            NTSTATUS status = 0;

            for (;;)
            {
                ULONG returned = 0;
                status = LI_NTDLL(NtQuerySystemInformation)(
                    static_cast<SYSTEM_INFORMATION_CLASS>(k_system_extended_handle_information),
                    buffer.data(), size, &returned);
                if (status == k_status_info_length_mismatch)
                {
                    if (size >= (256u << 20))
                        return 0;
                    size *= 2;
                    buffer.resize(size);
                    continue;
                }
                break;
            }

            if (!NT_SUCCESS(status))
                return 0;

            auto* info = reinterpret_cast<handle_info_ex*>(buffer.data());
            const DWORD self_pid = LI_KERNEL(GetCurrentProcessId)();
            HANDLE self_handle = LI_KERNEL(GetCurrentProcess)();
            const ULONG_PTR self_handle_val = reinterpret_cast<ULONG_PTR>(self_handle);

            for (ULONG_PTR i = 0; i < info->number_of_handles; ++i)
            {
                auto& entry = info->handles[i];
                if (static_cast<DWORD>(entry.unique_process_id) == self_pid
                    && entry.handle_value == self_handle_val)
                {
                    cached = entry.object_type_index;
                    break;
                }
            }
            return cached;
        }
    }

    std::vector<DWORD> scan(DWORD target_pid, DWORD self_pid)
    {
        std::vector<DWORD> owners;

        const USHORT process_type_index = discover_process_type_index();

        ULONG size = 1 << 20;
        std::vector<uint8_t> buffer(size);
        NTSTATUS status = 0;
        bool size_abort = false;

        for (;;)
        {
            ULONG returned = 0;
            status = LI_NTDLL(NtQuerySystemInformation)(
                static_cast<SYSTEM_INFORMATION_CLASS>(k_system_extended_handle_information),
                buffer.data(), size, &returned);
            if (status == k_status_info_length_mismatch)
            {
                if (size >= (256u << 20))
                {
                    size_abort = true;
                    break;
                }
                size *= 2;
                buffer.resize(size);
                continue;
            }
            break;
        }

        if (size_abort || !NT_SUCCESS(status))
            return owners;

        auto* info = reinterpret_cast<handle_info_ex*>(buffer.data());
        HANDLE self = LI_KERNEL(GetCurrentProcess)();

        std::unordered_map<DWORD, HANDLE> owner_handles;
        std::unordered_set<DWORD> matched;

        for (ULONG_PTR i = 0; i < info->number_of_handles; ++i)
        {
            auto& entry = info->handles[i];

            if (process_type_index != 0 && entry.object_type_index != process_type_index)
                continue;
            if ((entry.granted_access & PROCESS_VM_READ) == 0)
                continue;

            const DWORD owner_pid = static_cast<DWORD>(entry.unique_process_id);
            if (owner_pid == self_pid || owner_pid == target_pid || owner_pid == 0 || owner_pid == 4)
                continue;
            if (matched.count(owner_pid))
                continue;

            HANDLE owner = nullptr;
            auto it = owner_handles.find(owner_pid);
            if (it != owner_handles.end())
            {
                owner = it->second;
            }
            else
            {
                owner = LI_KERNEL(OpenProcess)(PROCESS_DUP_HANDLE, FALSE, owner_pid);
                owner_handles[owner_pid] = owner;
            }
            if (!owner)
                continue;

            HANDLE duplicate = nullptr;
            const NTSTATUS dup_status = LI_NTDLL(NtDuplicateObject)(owner, reinterpret_cast<HANDLE>(entry.handle_value),
                                                          self, &duplicate, 0, 0, 0x2);
            if (!NT_SUCCESS(dup_status) || !duplicate)
                continue;

            const DWORD pid_of_handle = safe_get_process_id(duplicate);
            LI_KERNEL(CloseHandle)(duplicate);

            if (pid_of_handle == target_pid)
            {
                owners.push_back(owner_pid);
                matched.insert(owner_pid);
            }
        }

        for (auto& kv : owner_handles)
        {
            if (kv.second)
                LI_KERNEL(CloseHandle)(kv.second);
        }

        return owners;
    }
}
