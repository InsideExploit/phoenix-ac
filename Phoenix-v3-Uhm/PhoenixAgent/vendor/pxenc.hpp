#pragma once

#include <type_traits>
#include "pxstr.hpp"

namespace pxenc {

using u32 = unsigned int;
using u16 = unsigned short;
using u8  = unsigned char;

__forceinline constexpr u32 mix32(u32 x) {
    x ^= x >> 15;
    x *= 0x85ebca6bu;
    x ^= x >> 13;
    x *= 0xc2b2ae35u;
    x ^= x >> 16;
    return x;
}

template<u32 Seed>
struct scheme {
    static constexpr u32 K1 = mix32(Seed ^ 0xF00DCAFEu);
    static constexpr u32 K2 = mix32(Seed ^ 0x517CC1B7u);
    static constexpr u32 K3 = mix32(Seed ^ 0x3D51D3C2u);
    static constexpr u32 K4 = mix32(Seed + 0xB16B00B5u);
    static constexpr u32 K5 = mix32(Seed * 0x9E370001u + 0x0BADF00Du);

    static constexpr u32 R1 = (mix32(Seed * 7u  + 131u) & 0x1Fu) | 1u;
    static constexpr u32 R2 = (mix32(Seed * 11u + 149u) & 0x1Fu) | 1u;
    static constexpr u32 R3 = (mix32(Seed * 13u + 167u) & 0x1Fu) | 1u;

    static constexpr u32 M1 = mix32(Seed * 17u + 181u) | 1u;
    static constexpr u32 M2 = mix32(Seed * 19u + 199u) | 1u;
    static constexpr u32 M3 = mix32(Seed * 23u + 211u) | 1u;

    static constexpr u32 V  = mix32(Seed * 29u + 233u) % 8u;

    static __forceinline constexpr u32 step(unsigned long long i) {
        u32 k = (u32)i;
        if constexpr (V == 0u) {
            k = mix32(k * K1 + K2);
            k = (k << R1) | (k >> (32u - R1));
            k ^= (u32)i * M1;
            k = mix32(k ^ K3);
            k = ((k << R2) | (k >> (32u - R2))) + K4;
            return (k * M2) ^ K5;
        } else if constexpr (V == 1u) {
            k ^= K1;
            k = (k >> R2) | (k << (32u - R2));
            k *= M2;
            k = mix32(k + K3 * (u32)i);
            k = ((k << R3) | (k >> (32u - R3))) + K4;
            k ^= (u32)i * M3;
            return mix32(k) ^ K5;
        } else if constexpr (V == 2u) {
            k = k * M1 + (u32)i * K2;
            k ^= k >> R1;
            k = mix32(k) + K3;
            k = (k << R2) | (k >> (32u - R2));
            k ^= (u32)i * K4;
            k *= M3;
            return mix32(k ^ K5);
        } else if constexpr (V == 3u) {
            k += K1;
            k = ((k << R1) | (k >> (32u - R1))) * M1;
            k ^= mix32((u32)i * M2 + K2);
            k = ((k >> R3) | (k << (32u - R3))) ^ K3;
            k = k * M3 + K4;
            return mix32(k) ^ K5;
        } else if constexpr (V == 4u) {
            k ^= (u32)i * K1;
            k = mix32(k) * M2;
            k = (k << R2) | (k >> (32u - R2));
            k += K3 ^ ((u32)i * M1);
            k = (k >> R1) | (k << (32u - R1));
            k *= M3;
            k ^= (u32)i * K4;
            return mix32(k) ^ K5;
        } else if constexpr (V == 5u) {
            k = mix32((k * M1) ^ K1);
            k = (k << R3) | (k >> (32u - R3));
            k += (u32)i * K2;
            k = mix32(k) ^ K3;
            k = ((k >> R2) | (k << (32u - R2))) * M2;
            k ^= (u32)i * M3;
            return k ^ K4 ^ K5;
        } else if constexpr (V == 6u) {
            k += (u32)i * M1;
            k ^= K1;
            k = mix32(k);
            k = (k >> R1) | (k << (32u - R1));
            k *= M2;
            k += K2 ^ (u32)i;
            k = mix32(k ^ K3);
            k = ((k << R2) | (k >> (32u - R2))) + K4;
            return (k * M3) ^ K5;
        } else {
            k ^= mix32(K1 + (u32)i);
            k = (k << R2) | (k >> (32u - R2));
            k = k * M1 + K2;
            k = mix32(k) ^ (K3 * (u32)i);
            k = ((k >> R3) | (k << (32u - R3))) ^ M2;
            k += K4;
            k = mix32(k * M3);
            return k ^ K5;
        }
    }
};

template<typename T> struct traits;
template<> struct traits<char>    { using U = u8;  };
template<> struct traits<wchar_t> { using U = u16; };

template<u32 Seed, typename T>
__forceinline constexpr typename traits<T>::U key_at(unsigned long long i) {
    u32 k = scheme<Seed>::step(i);
    if constexpr (sizeof(T) == 1)
        return (u8)(k ^ (k >> 8) ^ (k >> 16) ^ (k >> 24));
    else
        return (u16)(k ^ (k >> 16));
}

template<typename T, unsigned long long N, u32 Seed>
struct enc_box {
    T data[N];
    constexpr enc_box(const T (&s)[N]) : data{} {
        for (unsigned long long i = 0; i < N; i++)
            data[i] = (T)((typename traits<T>::U)s[i] ^ key_at<Seed, T>(i));
    }
};

template<u32 Seed, typename T, unsigned long long N>
__declspec(noinline)
void
decode_into(const T (&src)[N], T (&dst)[N])
{
    using U = typename traits<T>::U;
    for (unsigned long long i = 0; i < N; ++i) {
        U cipher = *(const volatile U*)&src[i];
        dst[i]   = (T)(cipher ^ key_at<Seed, T>(i));
    }
    if (N > 0) (void)*(volatile T*)&dst[0];
}

template<u32 Seed, typename T, unsigned long long N>
struct box {
    T buf[N];
    __declspec(noinline) box(const T (&src)[N]) {
        decode_into<Seed, T, N>(src, buf);
    }
    __declspec(noinline) ~box() {
        using U = typename traits<T>::U;
        for (unsigned long long i = 0; i < N; ++i)
            *(volatile U*)&buf[i] = 0;
    }
    __forceinline const T* get() const { return buf; }
};

}

#define PXENC_SEED_INNER(a, b) \
    (::pxenc::mix32((::pxenc::u32)(a) * 0x517CC1B7u ^ (::pxenc::u32)(b) * 0x9E370001u ^ 0x0BADF00Du))

#define pxenc_raw(str) \
    ([]() { \
        using _pxT = std::remove_cv_t<std::remove_extent_t<std::remove_reference_t<decltype(str)>>>; \
        constexpr auto _pxN = sizeof(str) / sizeof(_pxT); \
        constexpr ::pxenc::u32 _pxS = PXENC_SEED_INNER(__LINE__, __COUNTER__); \
        static constexpr ::pxenc::enc_box<_pxT, _pxN, _pxS> _pxE(str); \
        return ::pxenc::box<_pxS, _pxT, _pxN>{_pxE.data}; \
    }())

#define pxenc(str) pxenc_raw(str).get()
