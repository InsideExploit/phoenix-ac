#pragma once

#include <Windows.h>

#include <cstdint>
#include <utility>

namespace li
{
    namespace detail
    {
        struct list_entry
        {
            list_entry* flink;
            list_entry* blink;
        };

        struct unicode_string
        {
            USHORT   length;
            USHORT   maximum_length;
            wchar_t* buffer;
        };

        struct ldr_entry
        {
            list_entry     in_load_order_links;
            list_entry     in_memory_order_links;
            list_entry     in_initialization_order_links;
            void*          dll_base;
            void*          entry_point;
            ULONG          size_of_image;
            unicode_string full_dll_name;
            unicode_string base_dll_name;
        };

        struct peb_ldr_data
        {
            ULONG      length;
            UCHAR      initialized;
            void*      ss_handle;
            list_entry in_load_order_module_list;
        };

        struct peb
        {
            UCHAR          reserved1[2];
            UCHAR          being_debugged;
            UCHAR          reserved2[1];
            void*          reserved3[2];
            peb_ldr_data*  ldr;
        };

        constexpr uint32_t fnv1a(const char* value)
        {
            uint32_t h = 2166136261u;
            while (*value) { h ^= static_cast<uint8_t>(*value++); h *= 16777619u; }
            return h;
        }

        constexpr uint32_t fnv1a_wide(const wchar_t* value)
        {
            uint32_t h = 2166136261u;
            while (*value)
            {
                wchar_t ch = *value++;
                if (ch >= L'A' && ch <= L'Z') ch += L'a' - L'A';
                h ^= static_cast<uint8_t>(ch & 0xFF);  h *= 16777619u;
                h ^= static_cast<uint8_t>((ch >> 8) & 0xFF); h *= 16777619u;
            }
            return h;
        }

        inline peb* current_peb()
        {
#if defined(_M_X64)
            return reinterpret_cast<peb*>(__readgsqword(0x60));
#elif defined(_M_IX86)
            return reinterpret_cast<peb*>(__readfsdword(0x30));
#else
#error unsupported platform
#endif
        }

        inline void* module_base(uint32_t module_hash)
        {
            auto* loader = current_peb()->ldr;
            auto* head   = &loader->in_load_order_module_list;
            auto* link   = head->flink;

            while (link != head)
            {
                auto* entry = reinterpret_cast<ldr_entry*>(link);
                if (entry->base_dll_name.buffer &&
                    fnv1a_wide(entry->base_dll_name.buffer) == module_hash)
                    return entry->dll_base;
                link = link->flink;
            }
            return nullptr;
        }

        inline void* export_address(void* base, uint32_t export_hash)
        {
            if (!base) return nullptr;

            auto* dos  = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
            auto* nt   = reinterpret_cast<IMAGE_NT_HEADERS*>(
                reinterpret_cast<uint8_t*>(base) + dos->e_lfanew);
            auto& dir  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
            if (!dir.VirtualAddress) return nullptr;

            auto* exp  = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(
                reinterpret_cast<uint8_t*>(base) + dir.VirtualAddress);
            auto* names = reinterpret_cast<DWORD*>(
                reinterpret_cast<uint8_t*>(base) + exp->AddressOfNames);
            auto* ords  = reinterpret_cast<WORD*>(
                reinterpret_cast<uint8_t*>(base) + exp->AddressOfNameOrdinals);
            auto* funcs = reinterpret_cast<DWORD*>(
                reinterpret_cast<uint8_t*>(base) + exp->AddressOfFunctions);

            for (DWORD i = 0; i < exp->NumberOfNames; ++i)
            {
                const char* name = reinterpret_cast<const char*>(
                    reinterpret_cast<uint8_t*>(base) + names[i]);
                if (fnv1a(name) == export_hash)
                    return reinterpret_cast<void*>(
                        reinterpret_cast<uint8_t*>(base) + funcs[ords[i]]);
            }
            return nullptr;
        }

        inline void* ensure_module(uint32_t module_hash, const wchar_t* dll_path)
        {
            void* base = module_base(module_hash);
            if (base) return base;

            using load_library_fn = HMODULE(WINAPI*)(LPCWSTR);
            static load_library_fn load_library = nullptr;
            if (!load_library)
            {
                void* k32 = module_base(fnv1a_wide(L"kernel32.dll"));
                load_library = reinterpret_cast<load_library_fn>(
                    export_address(k32, fnv1a("LoadLibraryW")));
            }
            if (!load_library) return nullptr;
            return load_library(dll_path);
        }

        template<uint32_t ModuleHash, uint32_t ExportHash, typename Signature>
        class cached_function
        {
        public:
            static Signature get()
            {
                static Signature ptr = nullptr;
                if (!ptr)
                {
                    void* mod = module_base(ModuleHash);
                    ptr = reinterpret_cast<Signature>(export_address(mod, ExportHash));
                }
                return ptr;
            }

            template<typename... Args>
            static auto call(Args&&... args)
            {
                return get()(std::forward<Args>(args)...);
            }
        };

#define LI_MAKE_LOADABLE_TEMPLATE(classname, dllhash, dllpath)                         \
        template<uint32_t ExportHash, typename Signature>                              \
        class classname                                                                 \
        {                                                                               \
        public:                                                                         \
            static Signature get()                                                      \
            {                                                                           \
                static Signature ptr = nullptr;                                         \
                if (!ptr)                                                               \
                {                                                                       \
                    void* mod = ensure_module(dllhash, dllpath);                       \
                    ptr = reinterpret_cast<Signature>(export_address(mod, ExportHash)); \
                }                                                                       \
                return ptr;                                                             \
            }                                                                           \
            template<typename... Args>                                                  \
            static auto call(Args&&... args)                                            \
            {                                                                           \
                return get()(std::forward<Args>(args)...);                              \
            }                                                                           \
        }

        LI_MAKE_LOADABLE_TEMPLATE(cached_bcrypt_fn,   fnv1a_wide(L"bcrypt.dll"),   L"bcrypt.dll");
        LI_MAKE_LOADABLE_TEMPLATE(cached_ws2_fn,      fnv1a_wide(L"ws2_32.dll"),  L"ws2_32.dll");
        LI_MAKE_LOADABLE_TEMPLATE(cached_psapi_fn,    fnv1a_wide(L"psapi.dll"),   L"psapi.dll");
        LI_MAKE_LOADABLE_TEMPLATE(cached_iphlpapi_fn, fnv1a_wide(L"iphlpapi.dll"),L"iphlpapi.dll");
        LI_MAKE_LOADABLE_TEMPLATE(cached_dwmapi_fn,   fnv1a_wide(L"dwmapi.dll"),  L"dwmapi.dll");
        LI_MAKE_LOADABLE_TEMPLATE(cached_ole32_fn,    fnv1a_wide(L"ole32.dll"),   L"ole32.dll");

#undef LI_MAKE_LOADABLE_TEMPLATE
    }

    namespace modules
    {
        inline constexpr uint32_t kernel32 = detail::fnv1a_wide(L"kernel32.dll");
        inline constexpr uint32_t ntdll    = detail::fnv1a_wide(L"ntdll.dll");
        inline constexpr uint32_t user32   = detail::fnv1a_wide(L"user32.dll");
        inline constexpr uint32_t advapi32 = detail::fnv1a_wide(L"advapi32.dll");
    }

    template<uint32_t ExportHash, typename Signature>
    using kernel32_fn = detail::cached_function<modules::kernel32, ExportHash, Signature>;

    template<uint32_t ExportHash, typename Signature>
    using ntdll_fn    = detail::cached_function<modules::ntdll,    ExportHash, Signature>;

    template<uint32_t ExportHash, typename Signature>
    using user32_fn   = detail::cached_function<modules::user32,   ExportHash, Signature>;

    template<uint32_t ExportHash, typename Signature>
    using advapi32_fn = detail::cached_function<modules::advapi32, ExportHash, Signature>;

    template<uint32_t ExportHash, typename Signature>
    using bcrypt_fn   = detail::cached_bcrypt_fn<ExportHash, Signature>;

    template<uint32_t ExportHash, typename Signature>
    using ws2_fn      = detail::cached_ws2_fn<ExportHash, Signature>;

    template<uint32_t ExportHash, typename Signature>
    using psapi_fn    = detail::cached_psapi_fn<ExportHash, Signature>;

    template<uint32_t ExportHash, typename Signature>
    using iphlpapi_fn = detail::cached_iphlpapi_fn<ExportHash, Signature>;

    template<uint32_t ExportHash, typename Signature>
    using dwmapi_fn   = detail::cached_dwmapi_fn<ExportHash, Signature>;

    template<uint32_t ExportHash, typename Signature>
    using ole32_fn    = detail::cached_ole32_fn<ExportHash, Signature>;
}

#define LI_HASH(name)     ::li::detail::fnv1a(name)
#define LI_KERNEL(name)   ::li::kernel32_fn<LI_HASH(#name), decltype(&name)>::get()
#define LI_NTDLL(name)    ::li::ntdll_fn   <LI_HASH(#name), decltype(&name)>::get()
#define LI_USER32(name)   ::li::user32_fn  <LI_HASH(#name), decltype(&name)>::get()
#define LI_ADVAPI(name)   ::li::advapi32_fn<LI_HASH(#name), decltype(&name)>::get()
#define LI_BCRYPT(name)   ::li::bcrypt_fn  <LI_HASH(#name), decltype(&name)>::get()
#define LI_WS2(name)      ::li::ws2_fn     <LI_HASH(#name), decltype(&name)>::get()
#define LI_IPHLPAPI(name) ::li::iphlpapi_fn<LI_HASH(#name), decltype(&name)>::get()
