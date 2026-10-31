#include "http_client.hpp"

#include "ssl_pinning.hpp"

#include "../vendor/lazy_importer.hpp"
#include "../vendor/skCrypter.hpp"
#include "vendor/oreans/include/VirtualizerSDK.h"

#include <string>

__declspec(noinline) static std::wstring build_api_header()
{
    std::wstring header;

    VIRTUALIZER_START;

    header = skCrypt(L"X-Api-Key: ");
    header += skCrypt(L"REDACTED");
    header += skCrypt(L"\r\n");

    VIRTUALIZER_END;

    return header;
}

bool http_client::get(const wchar_t* path, DWORD* out_status, std::vector<uint8_t>* out_body)
{
    return get_impl(path, out_status, out_body);
}

bool http_client::get_impl(const wchar_t* path, DWORD* out_status, std::vector<uint8_t>* out_body)
{
    bool result = false;

    HINTERNET session = nullptr;
    HINTERNET connection = nullptr;
    HINTERNET request = nullptr;

    do
    {
        if (ssl_pinning::traffic_interception_detected())
            break;

        session = LI_WINHTTP(WinHttpOpen)(
            skCrypt(L"Mozilla/5.0"),
            WINHTTP_ACCESS_TYPE_NO_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS,
            0);

        if (!session)
            break;

        DWORD timeout = 30000;

        LI_WINHTTP(WinHttpSetTimeouts)(session, timeout, timeout, timeout, timeout);

        DWORD secure_protocols =
            WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2
            | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;

        LI_WINHTTP(WinHttpSetOption)(
            session,
            WINHTTP_OPTION_SECURE_PROTOCOLS,
            &secure_protocols,
            sizeof(secure_protocols));

        connection = LI_WINHTTP(WinHttpConnect)(
            session,
            skCrypt(L"localhost"),
            port,
            0);

        if (!connection)
            break;

        request = LI_WINHTTP(WinHttpOpenRequest)(
            connection,
            skCrypt(L"GET"),
            path,
            nullptr,
            WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            0);

        if (!request)
            break;

        DWORD security_flags = 0;

        LI_WINHTTP(WinHttpSetOption)(
            request,
            WINHTTP_OPTION_SECURITY_FLAGS,
            &security_flags,
            sizeof(security_flags));

        std::wstring header = build_api_header();

        BOOL ok = LI_WINHTTP(WinHttpSendRequest)(
            request,
            header.c_str(),
            static_cast<DWORD>(header.size()),
            WINHTTP_NO_REQUEST_DATA,
            0,
            0,
            0);

        if (!ok)
            break;

        ok = LI_WINHTTP(WinHttpReceiveResponse)(request, nullptr);

        if (!ok)
            break;

        DWORD status = 0;
        DWORD status_size = sizeof(status);

        LI_WINHTTP(WinHttpQueryHeaders)(
            request,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX,
            &status,
            &status_size,
            WINHTTP_NO_HEADER_INDEX);

        std::vector<uint8_t> body;

        if (status == 200 && out_body)
        {
            body.reserve(4 * 1024 * 1024);

            for (;;)
            {
                DWORD available = 0;

                if (!LI_WINHTTP(WinHttpQueryDataAvailable)(request, &available) || !available)
                    break;

                size_t offset = body.size();
                body.resize(offset + available);

                DWORD received = 0;

                if (!LI_WINHTTP(WinHttpReadData)(request, body.data() + offset, available, &received) || !received)
                {
                    body.resize(offset);
                    break;
                }

                body.resize(offset + received);

                if (body.size() > 128 * 1024 * 1024)
                    break;
            }
        }

        *out_status = status;

        if (out_body)
            *out_body = std::move(body);

        result = true;
    }
    while (0);

    if (request)
        LI_WINHTTP(WinHttpCloseHandle)(request);

    if (connection)
        LI_WINHTTP(WinHttpCloseHandle)(connection);

    if (session)
        LI_WINHTTP(WinHttpCloseHandle)(session);

    return result;
}
