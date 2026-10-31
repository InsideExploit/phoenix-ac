#pragma once

#include <intrin.h>

namespace pxstr {

using u32 = unsigned int;
using u16 = unsigned short;
using u8  = unsigned char;

__forceinline constexpr
u32
mix32(
    u32 x
)
{
    x ^= x >> 15;
    x *= 0x85ebca6bu;
    x ^= x >> 13;
    x *= 0xc2b2ae35u;
    x ^= x >> 16;
    return x;
}

template<u32 Seed>
struct scheme {
    static constexpr u32 K1 = mix32(Seed ^ 0xA5A5A5A5u);
    static constexpr u32 K2 = mix32(Seed ^ 0x9E3779B1u);
    static constexpr u32 K3 = mix32(Seed ^ 0xC2B2AE3Du);
    static constexpr u32 K4 = mix32(Seed + 0x50414331u);
    static constexpr u32 K5 = mix32(Seed * 0x27D4EB2Fu + 0xDEADBEEFu);

    static constexpr u32 R1 = (mix32(Seed + 11u) & 0x1Fu) | 1u;
    static constexpr u32 R2 = (mix32(Seed + 22u) & 0x1Fu) | 1u;
    static constexpr u32 R3 = (mix32(Seed + 33u) & 0x1Fu) | 1u;

    static constexpr u32 M1 = mix32(Seed + 44u) | 1u;
    static constexpr u32 M2 = mix32(Seed + 55u) | 1u;
    static constexpr u32 M3 = mix32(Seed + 66u) | 1u;

    static constexpr u32 V  = mix32(Seed + 77u) % 8u;

    static __forceinline constexpr
    u32
    step(
        unsigned long long i
    )
    {
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
__forceinline constexpr
typename traits<T>::U
key_at(
    unsigned long long i
)
{
    u32 k = scheme<Seed>::step(i);

    if constexpr (sizeof(T) == 1)
        return (u8)(k ^ (k >> 8) ^ (k >> 16) ^ (k >> 24));
    else
        return (u16)(k ^ (k >> 16));
}

template<typename T, unsigned long long N, u32 Seed>
struct enc_box {
    T data[N];

    constexpr enc_box(const T (&s)[N]) : data{}
    {
        for (unsigned long long i = 0; i < N; i++)
            data[i] = (T)((typename traits<T>::U)s[i] ^ key_at<Seed, T>(i));
    }
};

template<typename T, unsigned long long N, u32 Seed>
__declspec(noinline)
void
decode(
    const T (&src)[N],
    T       (&dst)[N]
)
{
    using U = typename traits<T>::U;
    for (unsigned long long i = 0; i < N; i++) {
        U cipher = *(const volatile U*)&src[i];
        dst[i]   = (T)(cipher ^ key_at<Seed, T>(i));
    }
    if (N > 0) (void)*(volatile T*)&dst[0];
}

template<typename T, unsigned long long N, u32 Seed>
class scoped {
    T buf_[N];

public:
    __forceinline scoped(const T (&enc)[N])
    {
        using U = typename traits<T>::U;
        for (unsigned long long i = 0; i < N; ++i) {
            U cipher = *(const volatile U*)&enc[i];
            buf_[i]  = (T)(cipher ^ key_at<Seed, T>(i));
        }
        _ReadWriteBarrier();
    }

    __forceinline ~scoped()
    {
        using U = typename traits<T>::U;
        for (unsigned long long i = 0; i < N; ++i)
            *(volatile U*)&buf_[i] = 0;
        _ReadWriteBarrier();
    }

    __forceinline operator const T*() const { return buf_; }
    __forceinline const T* get()     const { return buf_; }

    scoped(const scoped&)            = delete;
    scoped& operator=(const scoped&) = delete;
    scoped(scoped&&)                 = delete;
    scoped& operator=(scoped&&)      = delete;
};

}

#define PX_SEED_INNER(a, b) \
    (::pxstr::mix32((::pxstr::u32)(a) * 0x9E3779B1u ^ (::pxstr::u32)(b) * 0xC2B2AE3Du ^ 0x50414331u))

#define PX_A(str) ([]() -> const char* { \
        constexpr ::pxstr::u32 _pxsd = PX_SEED_INNER(__LINE__, __COUNTER__); \
        static constexpr ::pxstr::enc_box<char, sizeof(str), _pxsd> _pxb(str); \
        static char _pxbuf[sizeof(str)]; \
        ::pxstr::decode<char, sizeof(str), _pxsd>(_pxb.data, _pxbuf); \
        return _pxbuf; \
    }())

#define PX_W(str) ([]() -> const wchar_t* { \
        constexpr ::pxstr::u32 _pxsd = PX_SEED_INNER(__LINE__, __COUNTER__); \
        static constexpr ::pxstr::enc_box<wchar_t, sizeof(str) / sizeof(wchar_t), _pxsd> _pxb(str); \
        static wchar_t _pxbuf[sizeof(str) / sizeof(wchar_t)]; \
        ::pxstr::decode<wchar_t, sizeof(str) / sizeof(wchar_t), _pxsd>(_pxb.data, _pxbuf); \
        return _pxbuf; \
    }())

#define PX_AS(str) \
    ([]() { \
        constexpr ::pxstr::u32 _pxsds = PX_SEED_INNER(__LINE__, __COUNTER__); \
        static constexpr ::pxstr::enc_box<char, sizeof(str), _pxsds> _pxbs(str); \
        return ::pxstr::scoped<char, sizeof(str), _pxsds>(_pxbs.data); \
    }())

#define PX_WS(str) \
    ([]() { \
        constexpr ::pxstr::u32 _pxsds = PX_SEED_INNER(__LINE__, __COUNTER__); \
        static constexpr ::pxstr::enc_box<wchar_t, sizeof(str) / sizeof(wchar_t), _pxsds> _pxbs(str); \
        return ::pxstr::scoped<wchar_t, sizeof(str) / sizeof(wchar_t), _pxsds>(_pxbs.data); \
    }())
