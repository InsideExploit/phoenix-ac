#include "ssl_pinning.hpp"

#include "../vendor/lazy_importer.hpp"
#include "../vendor/skCrypter.hpp"
#include "vendor/oreans/include/VirtualizerSDK.h"

#include <TlHelp32.h>
#include <cstdint>
#include <string>

namespace
{
	bool sha256_matches(const uint8_t* left, const uint8_t* right)
	{
		for (size_t index = 0; index < 32; ++index)
		{
			if (left[index] != right[index])
			{
				return false;
			}
		}

		return true;
	}

	bool iequals_wide(const wchar_t* left, const wchar_t* right)
	{
		while (*left && *right)
		{
			wchar_t a = *left++;
			wchar_t b = *right++;

			if (a >= L'A' && a <= L'Z')
			{
				a += L'a' - L'A';
			}

			if (b >= L'A' && b <= L'Z')
			{
				b += L'a' - L'A';
			}

			if (a != b)
			{
				return false;
			}
		}

		return *left == *right;
	}

	bool process_name_matches(const wchar_t* process_name, const wchar_t* target_name)
	{
		return iequals_wide(process_name, target_name);
	}

	bool sniffer_process_running(const std::wstring& ui_name, const std::wstring& app_name)
	{
		bool running = false;

		HANDLE snapshot = LI_KERNEL(CreateToolhelp32Snapshot)(TH32CS_SNAPPROCESS, 0);

		if (snapshot == INVALID_HANDLE_VALUE)
		{
			return false;
		}

		PROCESSENTRY32W entry{};
		entry.dwSize = sizeof(entry);

		if (LI_KERNEL(Process32FirstW)(snapshot, &entry))
		{
			do
			{
				if (process_name_matches(entry.szExeFile, ui_name.c_str())
					|| process_name_matches(entry.szExeFile, app_name.c_str()))
				{
					running = true;
					break;
				}
			}
			while (LI_KERNEL(Process32NextW)(snapshot, &entry));
		}

		LI_KERNEL(CloseHandle)(snapshot);

		return running;
	}

	bool sniffer_module_loaded(const std::wstring& debugger_sdk, const std::wstring& fiddler_core)
	{
		return LI_KERNEL(GetModuleHandleW)(debugger_sdk.c_str()) != nullptr
			|| LI_KERNEL(GetModuleHandleW)(fiddler_core.c_str()) != nullptr;
	}
}

__declspec(noinline) bool ssl_pinning::traffic_interception_detected()
{
	bool detected = false;

	VIRTUALIZER_START;

	std::wstring debugger_ui;
	std::wstring debugger_app;
	std::wstring debugger_sdk;
	std::wstring fiddler_core;

	debugger_ui = skCrypt(L"HTTPDebuggerUI.exe");
	debugger_app = skCrypt(L"HTTPDebugger.exe");
	debugger_sdk = skCrypt(L"HttpDebuggerSdk.dll");
	fiddler_core = skCrypt(L"FiddlerCore.dll");

	if (sniffer_process_running(debugger_ui, debugger_app))
	{
		detected = true;
	}

	if (!detected && sniffer_module_loaded(debugger_sdk, fiddler_core))
	{
		detected = true;
	}

	VIRTUALIZER_END;

	return detected;
}

__declspec(noinline) bool ssl_pinning::verify(HINTERNET request)
{
	bool ok = false;

	VIRTUALIZER_START;

	// Set to your TLS certificate SHA-256 before production use.
	static const uint8_t pinned_sha256[32] = {};

	PCCERT_CONTEXT certificate = nullptr;
	DWORD certificate_size = sizeof(certificate);

	if (LI_WINHTTP(WinHttpQueryOption)(
			request,
			WINHTTP_OPTION_SERVER_CERT_CONTEXT,
			&certificate,
			&certificate_size))
	{
		uint8_t digest[32] = {};
		DWORD digest_size = sizeof(digest);

		if (LI_CRYPT32(CertGetCertificateContextProperty)(
				certificate,
				CERT_SHA256_HASH_PROP_ID,
				digest,
				&digest_size))
		{
			ok = digest_size == sizeof(digest) && sha256_matches(digest, pinned_sha256);
		}

		LI_CRYPT32(CertFreeCertificateContext)(certificate);
	}

	VIRTUALIZER_END;

	return ok;
}
