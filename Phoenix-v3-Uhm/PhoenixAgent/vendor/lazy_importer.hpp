#pragma once

#include <Windows.h>
#include <iostream>
#include <cstdint>
#include <utility>

#include "config.hpp"
#include "pxenc.hpp"

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

        constexpr uint32_t fnv1a_wide_from_ascii(const char* value)
        {
            uint32_t h = 2166136261u;
            while (*value)
            {
                char c = *value++;
                if (c >= 'A' && c <= 'Z') c = (char)(c + ('a' - 'A'));
                h ^= static_cast<uint8_t>(c);  h *= 16777619u;
                h ^= 0u; h *= 16777619u;
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

        inline void* resolve_forwarder(const char* fwd);

        inline void* export_address_raw(void* base, uint32_t export_hash)
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
                {
                    DWORD rva = funcs[ords[i]];
                    if (rva >= dir.VirtualAddress && rva < dir.VirtualAddress + dir.Size)
                    {
                        const char* fwd = reinterpret_cast<const char*>(
                            reinterpret_cast<uint8_t*>(base) + rva);
                        return resolve_forwarder(fwd);
                    }
                    return reinterpret_cast<void*>(
                        reinterpret_cast<uint8_t*>(base) + rva);
                }
            }
            return nullptr;
        }

        inline void* export_address(void* base, uint32_t export_hash)
        {
            return export_address_raw(base, export_hash);
        }

        inline void* resolve_forwarder(const char* fwd)
        {
            const char* dot = fwd;
            while (*dot && *dot != '.') ++dot;
            if (*dot != '.') return nullptr;

            wchar_t dll_name[128];
            size_t  dll_len = (size_t)(dot - fwd);
            if (dll_len >= 120) return nullptr;
            for (size_t i = 0; i < dll_len; ++i)
            {
                char c = fwd[i];
                if (c >= 'A' && c <= 'Z') c = (char)(c + ('a' - 'A'));
                dll_name[i] = (wchar_t)(unsigned char)c;
            }
            dll_name[dll_len++] = L'.';
            dll_name[dll_len++] = L'd';
            dll_name[dll_len++] = L'l';
            dll_name[dll_len++] = L'l';
            dll_name[dll_len]   = 0;

            uint32_t dll_hash = fnv1a_wide(dll_name);
            void*    target   = module_base(dll_hash);
            if (!target)
            {
                using load_library_fn = HMODULE(WINAPI*)(LPCWSTR);
                constexpr uint32_t _k32_h = fnv1a_wide_from_ascii("kernel32.dll");
                constexpr uint32_t _ll_h  = fnv1a("LoadLibraryW");
                void* k32 = module_base(_k32_h);
                auto  ll  = reinterpret_cast<load_library_fn>(export_address_raw(k32, _ll_h));
                if (ll) target = ll(dll_name);
                if (!target) return nullptr;
            }

            const char* export_name = dot + 1;
            if (*export_name == '#')
            {
                uint32_t ord = 0;
                for (const char* p = export_name + 1; *p >= '0' && *p <= '9'; ++p)
                    ord = ord * 10 + (uint32_t)(*p - '0');

                auto* dos  = reinterpret_cast<IMAGE_DOS_HEADER*>(target);
                auto* nt   = reinterpret_cast<IMAGE_NT_HEADERS*>(
                    reinterpret_cast<uint8_t*>(target) + dos->e_lfanew);
                auto& dir2 = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
                if (!dir2.VirtualAddress) return nullptr;
                auto* exp = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(
                    reinterpret_cast<uint8_t*>(target) + dir2.VirtualAddress);
                if (ord < exp->Base || ord >= exp->Base + exp->NumberOfFunctions) return nullptr;
                auto* funcs = reinterpret_cast<DWORD*>(
                    reinterpret_cast<uint8_t*>(target) + exp->AddressOfFunctions);
                DWORD rva = funcs[ord - exp->Base];
                if (rva >= dir2.VirtualAddress && rva < dir2.VirtualAddress + dir2.Size)
                    return resolve_forwarder(reinterpret_cast<const char*>(
                        reinterpret_cast<uint8_t*>(target) + rva));
                return reinterpret_cast<void*>(
                    reinterpret_cast<uint8_t*>(target) + rva);
            }

            return export_address_raw(target, fnv1a(export_name));
        }

        inline void* ensure_module(uint32_t module_hash, const wchar_t* dll_path)
        {
            void* base = module_base(module_hash);
            if (base) return base;

            using load_library_fn = HMODULE(WINAPI*)(LPCWSTR);
            static load_library_fn load_library = nullptr;
            if (!load_library)
            {
                constexpr uint32_t _k32_hash = fnv1a_wide_from_ascii("kernel32.dll");
                constexpr uint32_t _ll_hash  = fnv1a("LoadLibraryW");
                void* k32 = module_base(_k32_hash);
                load_library = reinterpret_cast<load_library_fn>(
                    export_address(k32, _ll_hash));
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
                    constexpr uint32_t _li_h = dllhash;                                 \
                    void* mod = ensure_module(_li_h, dllpath);                          \
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

#ifdef PHOENIX_UPDATER
#define LI_DLL_STR(narrow) \
    ([]() -> const wchar_t* { \
        static const char _lin[] = narrow; \
        static wchar_t _liw[sizeof(_lin)]; \
        for (size_t _lii = 0; _lii < sizeof(_lin); ++_lii) \
            _liw[_lii] = (wchar_t)(unsigned char)_lin[_lii]; \
        return _liw; \
    }())
#define LI_DLL_HASH(narrow) fnv1a_wide_from_ascii(narrow)
#else
#define LI_DLL_STR(narrow)  pxenc(L##narrow)
#define LI_DLL_HASH(narrow) fnv1a_wide(L##narrow)
#endif

        LI_MAKE_LOADABLE_TEMPLATE(cached_bcrypt_fn,   LI_DLL_HASH("bcrypt.dll"),   LI_DLL_STR("bcrypt.dll"));
        LI_MAKE_LOADABLE_TEMPLATE(cached_ws2_fn,      LI_DLL_HASH("ws2_32.dll"),   LI_DLL_STR("ws2_32.dll"));
        LI_MAKE_LOADABLE_TEMPLATE(cached_psapi_fn,    LI_DLL_HASH("psapi.dll"),    LI_DLL_STR("psapi.dll"));
        LI_MAKE_LOADABLE_TEMPLATE(cached_iphlpapi_fn, LI_DLL_HASH("iphlpapi.dll"), LI_DLL_STR("iphlpapi.dll"));
        LI_MAKE_LOADABLE_TEMPLATE(cached_dwmapi_fn,   LI_DLL_HASH("dwmapi.dll"),   LI_DLL_STR("dwmapi.dll"));
        LI_MAKE_LOADABLE_TEMPLATE(cached_ole32_fn,    LI_DLL_HASH("ole32.dll"),    LI_DLL_STR("ole32.dll"));
        LI_MAKE_LOADABLE_TEMPLATE(cached_tbs_fn,      LI_DLL_HASH("tbs.dll"),      LI_DLL_STR("tbs.dll"));
        LI_MAKE_LOADABLE_TEMPLATE(cached_gdi32_fn,    LI_DLL_HASH("gdi32.dll"),    LI_DLL_STR("gdi32.dll"));
        LI_MAKE_LOADABLE_TEMPLATE(cached_version_fn,  LI_DLL_HASH("version.dll"),  LI_DLL_STR("version.dll"));
        LI_MAKE_LOADABLE_TEMPLATE(cached_setupapi_fn, LI_DLL_HASH("setupapi.dll"), LI_DLL_STR("setupapi.dll"));
        LI_MAKE_LOADABLE_TEMPLATE(cached_cfgmgr32_fn, LI_DLL_HASH("cfgmgr32.dll"), LI_DLL_STR("cfgmgr32.dll"));
        LI_MAKE_LOADABLE_TEMPLATE(cached_shell32_fn,  LI_DLL_HASH("shell32.dll"),  LI_DLL_STR("shell32.dll"));
        LI_MAKE_LOADABLE_TEMPLATE(cached_winhttp_fn,  LI_DLL_HASH("winhttp.dll"),  LI_DLL_STR("winhttp.dll"));
        LI_MAKE_LOADABLE_TEMPLATE(cached_dbghelp_fn,  LI_DLL_HASH("dbghelp.dll"),  LI_DLL_STR("dbghelp.dll"));
        LI_MAKE_LOADABLE_TEMPLATE(cached_d3d11_fn,    LI_DLL_HASH("d3d11.dll"),    LI_DLL_STR("d3d11.dll"));
        LI_MAKE_LOADABLE_TEMPLATE(cached_dxgi_fn,     LI_DLL_HASH("dxgi.dll"),     LI_DLL_STR("dxgi.dll"));
        LI_MAKE_LOADABLE_TEMPLATE(cached_tdh_fn,      LI_DLL_HASH("tdh.dll"),      LI_DLL_STR("tdh.dll"));
        LI_MAKE_LOADABLE_TEMPLATE(cached_oleaut32_fn, LI_DLL_HASH("oleaut32.dll"), LI_DLL_STR("oleaut32.dll"));
        LI_MAKE_LOADABLE_TEMPLATE(cached_shlwapi_fn,  LI_DLL_HASH("shlwapi.dll"),  LI_DLL_STR("shlwapi.dll"));
        LI_MAKE_LOADABLE_TEMPLATE(cached_wv2_fn,      LI_DLL_HASH("WebView2Loader.dll"), LI_DLL_STR("WebView2Loader.dll"));
        LI_MAKE_LOADABLE_TEMPLATE(cached_wintrust_fn, LI_DLL_HASH("wintrust.dll"), LI_DLL_STR("wintrust.dll"));
        LI_MAKE_LOADABLE_TEMPLATE(cached_crypt32_fn,  LI_DLL_HASH("crypt32.dll"),  LI_DLL_STR("crypt32.dll"));

#undef LI_MAKE_LOADABLE_TEMPLATE
    }

    namespace modules
    {
        inline constexpr uint32_t kernel32 = detail::fnv1a_wide_from_ascii("kernel32.dll");
        inline constexpr uint32_t ntdll    = detail::fnv1a_wide_from_ascii("ntdll.dll");
        inline constexpr uint32_t user32   = detail::fnv1a_wide_from_ascii("user32.dll");
        inline constexpr uint32_t advapi32 = detail::fnv1a_wide_from_ascii("advapi32.dll");
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

    template<uint32_t ExportHash, typename Signature>
    using tbs_fn      = detail::cached_tbs_fn<ExportHash, Signature>;

    template<uint32_t ExportHash, typename Signature>
    using gdi32_fn    = detail::cached_gdi32_fn<ExportHash, Signature>;

    template<uint32_t ExportHash, typename Signature>
    using version_fn  = detail::cached_version_fn<ExportHash, Signature>;

    template<uint32_t ExportHash, typename Signature>
    using setupapi_fn = detail::cached_setupapi_fn<ExportHash, Signature>;

    template<uint32_t ExportHash, typename Signature>
    using cfgmgr32_fn = detail::cached_cfgmgr32_fn<ExportHash, Signature>;

    template<uint32_t ExportHash, typename Signature>
    using shell32_fn  = detail::cached_shell32_fn<ExportHash, Signature>;

    template<uint32_t ExportHash, typename Signature>
    using winhttp_fn  = detail::cached_winhttp_fn<ExportHash, Signature>;

    template<uint32_t ExportHash, typename Signature>
    using dbghelp_fn  = detail::cached_dbghelp_fn<ExportHash, Signature>;

    template<uint32_t ExportHash, typename Signature>
    using d3d11_fn    = detail::cached_d3d11_fn<ExportHash, Signature>;

    template<uint32_t ExportHash, typename Signature>
    using dxgi_fn     = detail::cached_dxgi_fn<ExportHash, Signature>;

    template<uint32_t ExportHash, typename Signature>
    using tdh_fn      = detail::cached_tdh_fn<ExportHash, Signature>;

    template<uint32_t ExportHash, typename Signature>
    using oleaut32_fn = detail::cached_oleaut32_fn<ExportHash, Signature>;

    template<uint32_t ExportHash, typename Signature>
    using shlwapi_fn  = detail::cached_shlwapi_fn<ExportHash, Signature>;

    template<uint32_t ExportHash, typename Signature>
    using wv2_fn      = detail::cached_wv2_fn<ExportHash, Signature>;

    template<uint32_t ExportHash, typename Signature>
    using wintrust_fn = detail::cached_wintrust_fn<ExportHash, Signature>;

    template<uint32_t ExportHash, typename Signature>
    using crypt32_fn  = detail::cached_crypt32_fn<ExportHash, Signature>;
}

#define LI_HASH(name)     ::li::detail::fnv1a(name)
#define LI_KERNEL(name)   ::li::kernel32_fn<LI_HASH(#name), decltype(&name)>::get()
#define LI_NTDLL(name)    ::li::ntdll_fn   <LI_HASH(#name), decltype(&name)>::get()
#define LI_USER32(name)   ::li::user32_fn  <LI_HASH(#name), decltype(&name)>::get()
#define LI_ADVAPI(name)   ::li::advapi32_fn<LI_HASH(#name), decltype(&name)>::get()
#define LI_BCRYPT(name)   ::li::bcrypt_fn  <LI_HASH(#name), decltype(&name)>::get()
#define LI_WS2(name)      ::li::ws2_fn     <LI_HASH(#name), decltype(&name)>::get()
#define LI_IPHLPAPI(name) ::li::iphlpapi_fn<LI_HASH(#name), decltype(&name)>::get()
#define LI_TBS(name)      ::li::tbs_fn     <LI_HASH(#name), decltype(&name)>::get()
#define LI_GDI32(name)    ::li::gdi32_fn   <LI_HASH(#name), decltype(&name)>::get()
#define LI_VERSION(name)  ::li::version_fn <LI_HASH(#name), decltype(&name)>::get()
#define LI_SETUPAPI(name) ::li::setupapi_fn<LI_HASH(#name), decltype(&name)>::get()
#define LI_CFGMGR32(name) ::li::cfgmgr32_fn<LI_HASH(#name), decltype(&name)>::get()
#define LI_OLE32(name)    ::li::ole32_fn   <LI_HASH(#name), decltype(&name)>::get()
#define LI_DWMAPI(name)   ::li::dwmapi_fn  <LI_HASH(#name), decltype(&name)>::get()
#define LI_PSAPI(name)    ::li::psapi_fn   <LI_HASH(#name), decltype(&name)>::get()
#define LI_SHELL32(name)  ::li::shell32_fn <LI_HASH(#name), decltype(&name)>::get()
#define LI_WINHTTP(name)  ::li::winhttp_fn <LI_HASH(#name), decltype(&name)>::get()
#define LI_DBGHELP(name)  ::li::dbghelp_fn <LI_HASH(#name), decltype(&name)>::get()
#define LI_D3D11(name)    ::li::d3d11_fn   <LI_HASH(#name), decltype(&name)>::get()
#define LI_DXGI(name)     ::li::dxgi_fn    <LI_HASH(#name), decltype(&name)>::get()
#define LI_TDH(name)      ::li::tdh_fn     <LI_HASH(#name), decltype(&name)>::get()
#define LI_OLEAUT32(name) ::li::oleaut32_fn<LI_HASH(#name), decltype(&name)>::get()
#define LI_SHLWAPI(name)  ::li::shlwapi_fn <LI_HASH(#name), decltype(&name)>::get()
#define LI_WV2(name)      ::li::wv2_fn     <LI_HASH(#name), decltype(&name)>::get()
#define LI_WINTRUST(name) ::li::wintrust_fn<LI_HASH(#name), decltype(&name)>::get()
#define LI_CRYPT32(name)  ::li::crypt32_fn <LI_HASH(#name), decltype(&name)>::get()
