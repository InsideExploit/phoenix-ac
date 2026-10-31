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
			USHORT length;
			USHORT maximum_length;
			wchar_t* buffer;
		};

		struct ldr_entry
		{
			list_entry in_load_order_links;
			list_entry in_memory_order_links;
			list_entry in_initialization_order_links;
			void* dll_base;
			void* entry_point;
			ULONG size_of_image;
			unicode_string full_dll_name;
			unicode_string base_dll_name;
		};

		struct peb_ldr_data
		{
			ULONG length;
			UCHAR initialized;
			void* ss_handle;
			list_entry in_load_order_module_list;
		};

		struct peb
		{
			UCHAR reserved1[2];
			UCHAR being_debugged;
			UCHAR reserved2[1];
			void* reserved3[2];
			peb_ldr_data* ldr;
		};

		constexpr uint32_t fnv1a(const char* value)
		{
			uint32_t hash = 2166136261u;

			while (*value)
			{
				hash ^= static_cast<uint8_t>(*value++);
				hash *= 16777619u;
			}

			return hash;
		}

		constexpr uint32_t fnv1a_wide(const wchar_t* value)
		{
			uint32_t hash = 2166136261u;

			while (*value)
			{
				wchar_t ch = *value++;

				if (ch >= L'A' && ch <= L'Z')
				{
					ch += L'a' - L'A';
				}

				hash ^= static_cast<uint8_t>(ch & 0xFF);
				hash *= 16777619u;

				hash ^= static_cast<uint8_t>((ch >> 8) & 0xFF);
				hash *= 16777619u;
			}

			return hash;
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
			auto* head = &loader->in_load_order_module_list;
			auto* link = head->flink;

			while (link != head)
			{
				auto* entry = reinterpret_cast<ldr_entry*>(link);

				if (entry->base_dll_name.buffer)
				{
					if (fnv1a_wide(entry->base_dll_name.buffer) == module_hash)
					{
						return entry->dll_base;
					}
				}

				link = link->flink;
			}

			return nullptr;
		}

		inline void* export_address(void* module_base_ptr, uint32_t export_hash)
		{
			auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(module_base_ptr);
			auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(reinterpret_cast<uint8_t*>(module_base_ptr) + dos->e_lfanew);
			auto& export_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

			if (export_dir.VirtualAddress == 0)
			{
				return nullptr;
			}

			auto* exports = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(
				reinterpret_cast<uint8_t*>(module_base_ptr) + export_dir.VirtualAddress);

			auto* names = reinterpret_cast<DWORD*>(reinterpret_cast<uint8_t*>(module_base_ptr) + exports->AddressOfNames);
			auto* ordinals = reinterpret_cast<WORD*>(reinterpret_cast<uint8_t*>(module_base_ptr) + exports->AddressOfNameOrdinals);
			auto* functions = reinterpret_cast<DWORD*>(reinterpret_cast<uint8_t*>(module_base_ptr) + exports->AddressOfFunctions);

			for (DWORD index = 0; index < exports->NumberOfNames; ++index)
			{
				auto* name = reinterpret_cast<const char*>(reinterpret_cast<uint8_t*>(module_base_ptr) + names[index]);

				if (fnv1a(name) != export_hash)
				{
					continue;
				}

				return reinterpret_cast<void*>(
					reinterpret_cast<uint8_t*>(module_base_ptr) + functions[ordinals[index]]);
			}

			return nullptr;
		}

		inline void* ensure_module(uint32_t module_hash, const wchar_t* module_path)
		{
			void* base = module_base(module_hash);

			if (base)
			{
				return base;
			}

			using load_library_fn = HMODULE(WINAPI*)(LPCWSTR);

			static load_library_fn load_library = nullptr;

			if (!load_library)
			{
				void* kernel = module_base(fnv1a_wide(L"kernel32.dll"));

				load_library = reinterpret_cast<load_library_fn>(
					export_address(kernel, fnv1a("LoadLibraryW")));
			}

			if (!load_library)
			{
				return nullptr;
			}

			return load_library(module_path);
		}

		template<uint32_t ModuleHash, uint32_t ExportHash, typename Signature>
		class cached_function
		{
		public:
			static Signature get()
			{
				static Signature pointer = nullptr;

				if (!pointer)
				{
					void* module = module_base(ModuleHash);

					pointer = reinterpret_cast<Signature>(
						export_address(module, ExportHash));
				}

				return pointer;
			}

			template<typename... Args>
			static auto call(Args&&... args)
			{
				return get()(std::forward<Args>(args)...);
			}
		};

		template<uint32_t ExportHash, typename Signature>
		class cached_winhttp_function
		{
		public:
			static Signature get()
			{
				static Signature pointer = nullptr;

				if (!pointer)
				{
					void* module = ensure_module(fnv1a_wide(L"winhttp.dll"), L"winhttp.dll");

					pointer = reinterpret_cast<Signature>(
						export_address(module, ExportHash));
				}

				return pointer;
			}

			template<typename... Args>
			static auto call(Args&&... args)
			{
				return get()(std::forward<Args>(args)...);
			}
		};

		template<uint32_t ExportHash, typename Signature>
		class cached_crypt32_function
		{
		public:
			static Signature get()
			{
				static Signature pointer = nullptr;

				if (!pointer)
				{
					void* module = ensure_module(fnv1a_wide(L"crypt32.dll"), L"crypt32.dll");

					pointer = reinterpret_cast<Signature>(
						export_address(module, ExportHash));
				}

				return pointer;
			}

			template<typename... Args>
			static auto call(Args&&... args)
			{
				return get()(std::forward<Args>(args)...);
			}
		};
	}

	namespace modules
	{
		inline constexpr uint32_t kernel32 = detail::fnv1a_wide(L"kernel32.dll");
	}

	template<uint32_t ExportHash, typename Signature>
	using kernel32_fn = detail::cached_function<modules::kernel32, ExportHash, Signature>;

	template<uint32_t ExportHash, typename Signature>
	using winhttp_fn = detail::cached_winhttp_function<ExportHash, Signature>;

	template<uint32_t ExportHash, typename Signature>
	using crypt32_fn = detail::cached_crypt32_function<ExportHash, Signature>;
}

#define LI_HASH(name) ::li::detail::fnv1a(name)
#define LI_KERNEL(name) ::li::kernel32_fn<LI_HASH(#name), decltype(&name)>::get()
#define LI_WINHTTP(name) ::li::winhttp_fn<LI_HASH(#name), decltype(&name)>::get()
#define LI_CRYPT32(name) ::li::crypt32_fn<LI_HASH(#name), decltype(&name)>::get()