#include "update.hpp"

#include "../http_client/http_client.hpp"
#include "../file_writer/file_writer.hpp"
#include "../vendor/lazy_importer.hpp"
#include "../vendor/skCrypter.hpp"
#include "vendor/oreans/include/VirtualizerSDK.h"

#include <string>
#include <vector>

namespace
{
	__declspec(noinline) void resolve_install_paths(
		std::wstring& install_dir,
		std::wstring& exe_path,
		std::wstring& dll_path)
	{
		VIRTUALIZER_START;

		install_dir = skCrypt(L"C:\\Program Files\\PhoenixAC");
		exe_path = skCrypt(L"C:\\Program Files\\PhoenixAC\\PhoenixAC.exe");
		dll_path = skCrypt(L"C:\\Program Files\\PhoenixAC\\vxlib64.dll");

		VIRTUALIZER_END;
	}

	__declspec(noinline) void resolve_api_paths(
		std::wstring& runtime_path,
		std::wstring& download_path)
	{
		VIRTUALIZER_START;

		runtime_path = skCrypt(L"/api/launcher/runtime");
		download_path = skCrypt(L"/api/launcher/download");

		VIRTUALIZER_END;
	}

	__declspec(noinline) bool launch_process(
		const wchar_t* exe_path,
		const wchar_t* install_dir,
		STARTUPINFOW* startup_info,
		PROCESS_INFORMATION* process_info)
	{
		bool launched = false;

		VIRTUALIZER_START;

		launched = LI_KERNEL(CreateProcessW)(
			exe_path,
			nullptr,
			nullptr,
			nullptr,
			FALSE,
			0,
			nullptr,
			install_dir,
			startup_info,
			process_info) != FALSE;

		VIRTUALIZER_END;

		return launched;
	}
}

int update::run()
{
    return run_impl();
}

int update::run_impl()
{
    int result = 0;

    http_client http;
    file_writer writer;

    std::wstring install_dir;
    std::wstring exe_path;
    std::wstring dll_path;
    std::wstring runtime_path;
    std::wstring download_path;

    resolve_install_paths(install_dir, exe_path, dll_path);
    resolve_api_paths(runtime_path, download_path);

    do
    {
        LI_KERNEL(CreateDirectoryW)(install_dir.c_str(), nullptr);

        DWORD dll_attributes = LI_KERNEL(GetFileAttributesW)(dll_path.c_str());
        bool dll_exists = (dll_attributes != INVALID_FILE_ATTRIBUTES)
            && !(dll_attributes & FILE_ATTRIBUTE_DIRECTORY);

        if (!dll_exists)
        {
            DWORD dll_status = 0;
            std::vector<uint8_t> dll_bytes;

            if (!http.get(runtime_path.c_str(), &dll_status, &dll_bytes))
            {
                result = 5;
                break;
            }

            if (dll_status != 200)
            {
                result = 5;
                break;
            }

            if (dll_bytes.size() < 0x40)
            {
                result = 5;
                break;
            }

            if (!writer.write_all(dll_path.c_str(), dll_bytes.data(), dll_bytes.size()))
            {
                result = 6;
                break;
            }
        }

        DWORD status = 0;
        std::vector<uint8_t> exe_bytes;

        if (!http.get(download_path.c_str(), &status, &exe_bytes))
        {
            result = 2;
            break;
        }

        if (status != 200)
        {
            result = 2;
            break;
        }

        if (exe_bytes.size() < 0x200)
        {
            result = 2;
            break;
        }

        if (!writer.write_all(exe_path.c_str(), exe_bytes.data(), exe_bytes.size()))
        {
            result = 3;
            break;
        }

        STARTUPINFOW startup_info{};
        startup_info.cb = sizeof(startup_info);

        PROCESS_INFORMATION process_info{};

        if (!launch_process(exe_path.c_str(), install_dir.c_str(), &startup_info, &process_info))
        {
            result = 4;
            break;
        }

        LI_KERNEL(CloseHandle)(process_info.hProcess);
        LI_KERNEL(CloseHandle)(process_info.hThread);

        volatile unsigned char* buffer = exe_bytes.data();

        for (size_t index = 0; index < exe_bytes.size(); ++index)
        {
            buffer[index] = 0;
        }
    }
    while (0);

    return result;
}
