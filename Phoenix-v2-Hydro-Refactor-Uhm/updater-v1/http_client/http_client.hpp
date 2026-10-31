#pragma once

#include <Windows.h>
#include <winhttp.h>
#include <vector>
#include <cstdint>

class http_client
{
public:
    static constexpr INTERNET_PORT port = 3000;

    bool get(const wchar_t* path, DWORD* out_status, std::vector<uint8_t>* out_body);

private:
    __declspec(noinline) bool get_impl(const wchar_t* path, DWORD* out_status, std::vector<uint8_t>* out_body);
};