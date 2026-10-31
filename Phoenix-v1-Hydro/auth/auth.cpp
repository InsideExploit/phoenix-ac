#include "auth.hpp"

#include "net/wire.hpp"
#include "vendor/lazy_importer.hpp"
#include "vendor/xor_string.hpp"
#include "vendor/oreans/include/VirtualizerSDK.h"
#pragma auto_inline(off)

#include <Windows.h>
#include <TlHelp32.h>
#include <bcrypt.h>

#include <cstdio>
#include <cwchar>
#include <string>
#include <vector>

namespace auth
{
    namespace
    {
        __declspec(noinline) bool read_dword_registry(HKEY root, const wchar_t* subkey, const wchar_t* value_name, DWORD& out)
        {
            VIRTUALIZER_START;
            HKEY key = nullptr;
            if (LI_ADVAPI(RegOpenKeyExW)(root, subkey, 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS)
                return false;

            DWORD type = 0;
            DWORD size = sizeof(DWORD);
            const LSTATUS status = LI_ADVAPI(RegQueryValueExW)(key, value_name, nullptr, &type,
                                                    reinterpret_cast<BYTE*>(&out), &size);
            LI_ADVAPI(RegCloseKey)(key);
            const bool r = status == ERROR_SUCCESS && type == REG_DWORD;
            VIRTUALIZER_END;
            return r;
        }

        __declspec(noinline) bool self_sha256_hex(std::string& out_hex)
        {
            VIRTUALIZER_START;
            wchar_t self_path[MAX_PATH]{};
            if (!LI_KERNEL(GetModuleFileNameW)(nullptr, self_path, MAX_PATH))
                return false;

            HANDLE file = LI_KERNEL(CreateFileW)(self_path, GENERIC_READ,
                                      FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                      OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (file == INVALID_HANDLE_VALUE)
                return false;

            BCRYPT_ALG_HANDLE alg = nullptr;
            if (LI_BCRYPT(BCryptOpenAlgorithmProvider)(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0)
            {
                LI_KERNEL(CloseHandle)(file);
                return false;
            }

            BCRYPT_HASH_HANDLE hash = nullptr;
            bool ok = false;

            if (LI_BCRYPT(BCryptCreateHash)(alg, &hash, nullptr, 0, nullptr, 0, 0) == 0)
            {
                BYTE buffer[4096];
                DWORD got = 0;
                bool read_ok = true;

                while (read_ok && LI_KERNEL(ReadFile)(file, buffer, sizeof(buffer), &got, nullptr) && got > 0)
                {
                    if (LI_BCRYPT(BCryptHashData)(hash, buffer, got, 0) != 0)
                    {
                        read_ok = false;
                        break;
                    }
                }

                BYTE digest[32];
                if (read_ok && LI_BCRYPT(BCryptFinishHash)(hash, digest, 32, 0) == 0)
                {
                    static const char* hex_chars = "0123456789abcdef";
                    out_hex.resize(64);
                    for (int i = 0; i < 32; ++i)
                    {
                        out_hex[i * 2]     = hex_chars[(digest[i] >> 4) & 0xF];
                        out_hex[i * 2 + 1] = hex_chars[digest[i]        & 0xF];
                    }
                    ok = true;
                }
                LI_BCRYPT(BCryptDestroyHash)(hash);
            }

            LI_BCRYPT(BCryptCloseAlgorithmProvider)(alg, 0);
            LI_KERNEL(CloseHandle)(file);
            VIRTUALIZER_END;
            return ok;
        }
    }

    __declspec(noinline) bool is_steam_running()
    {
        VIRTUALIZER_START;
        HANDLE snapshot = LI_KERNEL(CreateToolhelp32Snapshot)(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE)
            return false;

        bool found = false;
        PROCESSENTRY32W pe{};
        pe.dwSize = sizeof(pe);

        if (LI_KERNEL(Process32FirstW)(snapshot, &pe))
        {
            do
            {
                if (_wcsicmp(pe.szExeFile, XSW(L"steam.exe")) == 0)
                {
                    found = true;
                    break;
                }
            } while (LI_KERNEL(Process32NextW)(snapshot, &pe));
        }

        LI_KERNEL(CloseHandle)(snapshot);
        VIRTUALIZER_END;
        return found;
    }

    __declspec(noinline) bool get_steam_id_hex(std::string& out_hex)
    {
        VIRTUALIZER_START;
        DWORD active_user = 0;
        if (!read_dword_registry(HKEY_CURRENT_USER,
                                 XSW(L"Software\\Valve\\Steam\\ActiveProcess"),
                                 XSW(L"ActiveUser"), active_user))
            return false;

        if (active_user == 0)
            return false;

        const uint64_t steam_id = 0x0110000100000000ULL | static_cast<uint64_t>(active_user);
        char buffer[32];
        const int n = sprintf_s(buffer, XS("%llx"), static_cast<unsigned long long>(steam_id));
        if (n <= 0)
            return false;

        out_hex.assign(buffer, static_cast<size_t>(n));
        VIRTUALIZER_END;
        return true;
    }

    __declspec(noinline) bool get_disk_id(std::string& out_id)
    {
        VIRTUALIZER_START;
        DWORD serial = 0;
        if (!LI_KERNEL(GetVolumeInformationW)(XSW(L"C:\\"), nullptr, 0, &serial,
                                   nullptr, nullptr, nullptr, 0))
            return false;

        char buffer[16];
        const int n = sprintf_s(buffer, XS("%08lX"), static_cast<unsigned long>(serial));
        if (n <= 0)
            return false;

        out_id.assign(buffer, static_cast<size_t>(n));
        VIRTUALIZER_END;
        return true;
    }

    __declspec(noinline) bool check_authorization(const std::string& steam_hex, result& out_result)
    {
        VIRTUALIZER_START;
        out_result = {};

        std::string disk_id;
        get_disk_id(disk_id);

        std::string self_sha;
        self_sha256_hex(self_sha);

        const auto req = wire::pack_auth_check(steam_hex, disk_id, self_sha);

        std::vector<uint8_t> rsp_inner;
        uint32_t rsp_opcode = 0;
        if (!wire::transact(static_cast<uint16_t>(wire::opcode::auth_check_req),
                            req, rsp_inner, rsp_opcode))
            return false;

        if (rsp_opcode != static_cast<uint32_t>(wire::opcode::auth_check_rsp))
            return false;

        bool phoenix_ac = false;
        int ttl = 300;
        if (!wire::unpack_auth_check_rsp(rsp_inner, phoenix_ac, ttl))
            return false;

        out_result.ok                 = true;
        out_result.anticheat_required = phoenix_ac;
        out_result.ttl_seconds        = ttl;
        VIRTUALIZER_END;
        return true;
    }
}
