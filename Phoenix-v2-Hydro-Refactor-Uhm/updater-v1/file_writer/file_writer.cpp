#include "file_writer.hpp"

#include "../vendor/lazy_importer.hpp"

bool file_writer::write_all(const wchar_t* path, const void* data, size_t size)
{
    return write_all_impl(path, data, size);
}

bool file_writer::write_all_impl(const wchar_t* path, const void* data, size_t size)
{
    HANDLE file = LI_KERNEL(CreateFileW)(
        path,
        GENERIC_WRITE,
        0,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);

    if (file == INVALID_HANDLE_VALUE)
        return false;

    DWORD written = 0;

    BOOL ok = LI_KERNEL(WriteFile)(
        file,
        data,
        static_cast<DWORD>(size),
        &written,
        nullptr);

    LI_KERNEL(CloseHandle)(file);

    return ok && written == static_cast<DWORD>(size);
}