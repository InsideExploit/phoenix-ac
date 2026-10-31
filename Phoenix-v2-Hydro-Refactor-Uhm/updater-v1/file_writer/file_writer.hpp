#pragma once

#include <Windows.h>
#include <cstddef>

class file_writer
{
public:
    bool write_all(const wchar_t* path, const void* data, size_t size);

private:
    __declspec(noinline) bool write_all_impl(const wchar_t* path, const void* data, size_t size);
};