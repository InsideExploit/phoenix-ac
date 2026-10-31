#pragma once

#include <cstddef>
#include <cstdint>

namespace xor_string
{
    constexpr uint64_t rotl64(uint64_t v, unsigned r)
    {
        r &= 63;
        if (!r)
            return v;
        return (v << r) | (v >> (64 - r));
    }

    constexpr uint64_t rotr64(uint64_t v, unsigned r)
    {
        r &= 63;
        if (!r)
            return v;
        return (v >> r) | (v << (64 - r));
    }

    constexpr uint8_t rotl8(uint8_t v, unsigned r)
    {
        r &= 7;
        if (!r)
            return v;
        return static_cast<uint8_t>((v << r) | (v >> (8 - r)));
    }

    constexpr uint8_t rotr8(uint8_t v, unsigned r)
    {
        r &= 7;
        if (!r)
            return v;
        return static_cast<uint8_t>((v >> r) | (v << (8 - r)));
    }

    constexpr uint64_t avalanche64(uint64_t x)
    {
        x ^= x >> 33;
        x *= 0xff51afd7ed558ccdULL;
        x ^= x >> 33;
        x *= 0xc4ceb9fe1a85ec53ULL;
        x ^= x >> 33;
        return x;
    }

    constexpr uint64_t derive_seed(uint64_t k, size_t line, size_t counter)
    {
        uint64_t s = k ^ rotl64(line * 0xd6e8feb86659fd93ULL, static_cast<unsigned>(counter & 31));
        s ^= (counter + 1) * 0x9e3779b97f4a7c15ULL;
        s ^= rotr64(k, static_cast<unsigned>((line ^ counter) & 63));
        return avalanche64(s);
    }

    constexpr void materialize_keys(size_t i, uint64_t seed, uint8_t& k0, uint8_t& k1, uint8_t& k2, uint8_t& k3, unsigned& rot)
    {
        uint64_t lane = seed ^ (i * 0xbf58476d1ce4e5b9ULL);
        lane = avalanche64(lane ^ rotl64(seed, static_cast<unsigned>((i + 3) & 63)));
        lane = avalanche64(lane + i * 0x94d049bb133111ebULL);

        k0 = static_cast<uint8_t>(lane);
        k1 = static_cast<uint8_t>(lane >> 8);
        k2 = static_cast<uint8_t>(lane >> 16);
        k3 = static_cast<uint8_t>(lane >> 24);
        rot = static_cast<unsigned>((k2 ^ k3 ^ static_cast<uint8_t>(i)) & 7) + 1;
    }

    constexpr uint8_t transform_fwd(uint8_t b, size_t i, uint64_t seed)
    {
        uint8_t k0, k1, k2, k3;
        unsigned rot;
        materialize_keys(i, seed, k0, k1, k2, k3, rot);

        switch ((i + static_cast<size_t>(seed >> 17)) & 3)
        {
        case 0:
            b = static_cast<uint8_t>((b + k0) ^ k1);
            b = static_cast<uint8_t>(rotl8(b, rot) ^ k3);
            break;
        case 1:
            b = static_cast<uint8_t>(~(b ^ k0) + k1);
            b = static_cast<uint8_t>(rotr8(b, rot) ^ k3);
            break;
        case 2:
            b = static_cast<uint8_t>(((b ^ k0) + k1) ^ rotl8(k2, rot & 7));
            b = static_cast<uint8_t>(rotr8(b, rot) + k3);
            break;
        default:
            b = static_cast<uint8_t>(rotl8(b ^ k0, rot) + k1);
            b = static_cast<uint8_t>((b ^ k2) - k3);
            break;
        }

        return static_cast<uint8_t>(b ^ static_cast<uint8_t>(seed >> ((i & 7) * 8)));
    }

    __declspec(noinline) static uint8_t inverse_lane0(uint8_t b, uint8_t k0, uint8_t k1, uint8_t k3, unsigned rot)
    {
        b = static_cast<uint8_t>(b ^ k3);
        b = rotr8(b, rot);
        b = static_cast<uint8_t>(b ^ k1);
        return static_cast<uint8_t>(b - k0);
    }

    __declspec(noinline) static uint8_t inverse_lane1(uint8_t b, uint8_t k0, uint8_t k1, uint8_t k3, unsigned rot)
    {
        b = static_cast<uint8_t>(b ^ k3);
        b = rotl8(b, rot);
        b = static_cast<uint8_t>(~static_cast<uint8_t>(b - k1));
        return static_cast<uint8_t>(b ^ k0);
    }

    __declspec(noinline) static uint8_t inverse_lane2(uint8_t b, uint8_t k0, uint8_t k1, uint8_t k2, uint8_t k3, unsigned rot)
    {
        b = static_cast<uint8_t>(b - k3);
        b = rotl8(b, rot);
        b = static_cast<uint8_t>(b ^ rotl8(k2, rot & 7));
        b = static_cast<uint8_t>(b - k1);
        return static_cast<uint8_t>(b ^ k0);
    }

    __declspec(noinline) static uint8_t inverse_lane3(uint8_t b, uint8_t k0, uint8_t k1, uint8_t k2, uint8_t k3, unsigned rot)
    {
        b = static_cast<uint8_t>(b + k3);
        b = static_cast<uint8_t>(b ^ k2);
        b = static_cast<uint8_t>(b - k1);
        return static_cast<uint8_t>(rotr8(b, rot) ^ k0);
    }

    inline uint8_t transform_inv(uint8_t b, size_t i, uint64_t seed)
    {
        b = static_cast<uint8_t>(b ^ static_cast<uint8_t>(seed >> ((i & 7) * 8)));

        uint8_t k0, k1, k2, k3;
        unsigned rot;
        materialize_keys(i, seed, k0, k1, k2, k3, rot);

        switch ((i + static_cast<size_t>(seed >> 17)) & 3)
        {
        case 0:  return inverse_lane0(b, k0, k1, k3, rot);
        case 1:  return inverse_lane1(b, k0, k1, k3, rot);
        case 2:  return inverse_lane2(b, k0, k1, k2, k3, rot);
        default: return inverse_lane3(b, k0, k1, k2, k3, rot);
        }
    }

    constexpr uint16_t transform_fwd16(uint16_t v, size_t i, uint64_t seed)
    {
        uint8_t lo = transform_fwd(static_cast<uint8_t>(v), i * 2, seed ^ 0x243f6a8885a308d3ULL);
        uint8_t hi = transform_fwd(static_cast<uint8_t>(v >> 8), i * 2 + 1, seed ^ 0x13198a2e03707344ULL);
        return static_cast<uint16_t>(lo | (static_cast<uint16_t>(hi) << 8));
    }

    inline uint16_t transform_inv16(uint16_t v, size_t i, uint64_t seed)
    {
        uint8_t lo = transform_inv(static_cast<uint8_t>(v), i * 2, seed ^ 0x243f6a8885a308d3ULL);
        uint8_t hi = transform_inv(static_cast<uint8_t>(v >> 8), i * 2 + 1, seed ^ 0x13198a2e03707344ULL);
        return static_cast<uint16_t>(lo | (static_cast<uint16_t>(hi) << 8));
    }

    inline uint64_t recover_seed(uint64_t a, uint64_t b, unsigned twist)
    {
        return a ^ rotl64(b, twist);
    }

    template <size_t N>
    struct encoded_ansi
    {
        char data[N];
        uint64_t seed_a;
        uint64_t seed_b;
        uint32_t tag;

        constexpr encoded_ansi(const char* s, uint64_t k, size_t line, size_t counter)
            : data{}, seed_a(0), seed_b(0), tag(0)
        {
            const uint64_t seed = derive_seed(k, line, counter);
            const uint64_t veil = avalanche64(k ^ (line * 0x5851f42d4c957f2dULL) ^ counter);
            seed_a = seed ^ rotl64(veil, 11);
            seed_b = veil;
            tag = static_cast<uint32_t>(avalanche64(seed ^ veil) ^ static_cast<uint32_t>(line + counter));

            uint8_t chain = static_cast<uint8_t>(tag ^ static_cast<uint8_t>(seed));
            for (size_t i = 0; i < N; ++i)
            {
                const uint8_t plain = static_cast<uint8_t>(s[i]);
                const uint8_t mixed = static_cast<uint8_t>(plain ^ chain);
                const uint8_t enc = transform_fwd(mixed, i, seed);
                data[i] = static_cast<char>(enc);
                chain = static_cast<uint8_t>(enc + static_cast<uint8_t>(i * 17) + static_cast<uint8_t>(seed >> ((i & 3) * 8)));
            }
        }

        const char* decode(char* out) const
        {
            const uint64_t seed = recover_seed(seed_a, seed_b, 11);
            uint8_t chain = static_cast<uint8_t>(tag ^ static_cast<uint8_t>(seed));

            for (size_t i = 0; i < N; ++i)
            {
                const uint8_t enc = static_cast<uint8_t>(data[i]);
                const uint8_t mixed = transform_inv(enc, i, seed);
                out[i] = static_cast<char>(mixed ^ chain);
                chain = static_cast<uint8_t>(enc + static_cast<uint8_t>(i * 17) + static_cast<uint8_t>(seed >> ((i & 3) * 8)));
            }

            return out;
        }
    };

    template <size_t N>
    struct encoded_wide
    {
        wchar_t data[N];
        uint64_t seed_a;
        uint64_t seed_b;
        uint32_t tag;

        constexpr encoded_wide(const wchar_t* s, uint64_t k, size_t line, size_t counter)
            : data{}, seed_a(0), seed_b(0), tag(0)
        {
            const uint64_t seed = derive_seed(k, line, counter);
            const uint64_t veil = avalanche64(k ^ rotl64(line + counter, 13));
            seed_a = seed ^ rotl64(veil, 29);
            seed_b = veil;
            tag = static_cast<uint32_t>(avalanche64(seed ^ rotl64(veil, 7)) ^ static_cast<uint32_t>(line * counter));

            uint16_t chain = static_cast<uint16_t>(tag ^ static_cast<uint16_t>(seed));
            for (size_t i = 0; i < N; ++i)
            {
                const uint16_t plain = static_cast<uint16_t>(s[i]);
                const uint16_t mixed = static_cast<uint16_t>(plain ^ chain);
                const uint16_t enc = transform_fwd16(mixed, i, seed);
                data[i] = static_cast<wchar_t>(enc);
                chain = static_cast<uint16_t>(enc + static_cast<uint16_t>(i * 23) + static_cast<uint16_t>(seed >> ((i & 3) * 8)));
            }
        }

        const wchar_t* decode(wchar_t* out) const
        {
            const uint64_t seed = recover_seed(seed_a, seed_b, 29);
            uint16_t chain = static_cast<uint16_t>(tag ^ static_cast<uint16_t>(seed));

            for (size_t i = 0; i < N; ++i)
            {
                const uint16_t enc = static_cast<uint16_t>(data[i]);
                const uint16_t mixed = transform_inv16(enc, i, seed);
                out[i] = static_cast<wchar_t>(mixed ^ chain);
                chain = static_cast<uint16_t>(enc + static_cast<uint16_t>(i * 23) + static_cast<uint16_t>(seed >> ((i & 3) * 8)));
            }

            return out;
        }
    };
}

#define XS(literal) ([]() -> const char* {                                        \
        constexpr size_t _n = sizeof(literal);                                    \
        constexpr size_t _ctr = (size_t)__COUNTER__;                                \
        static constexpr ::xor_string::encoded_ansi<_n> _e(                       \
            literal,                                                              \
            ((uint64_t)(_ctr + 1) * 0x9e3779b97f4a7c15ULL) ^                      \
            ((uint64_t)__LINE__ << 32) ^                                          \
            ((uint64_t)_ctr << 17),                                               \
            __LINE__,                                                             \
            _ctr);                                                                \
        thread_local char _b[_n];                                                 \
        return _e.decode(_b);                                                     \
    }())

#define XSW(literal) ([]() -> const wchar_t* {                                    \
        constexpr size_t _n = sizeof(literal) / sizeof(wchar_t);                  \
        constexpr size_t _ctr = (size_t)__COUNTER__;                              \
        static constexpr ::xor_string::encoded_wide<_n> _e(                       \
            literal,                                                              \
            ((uint64_t)(_ctr + 1) * 0x9e3779b97f4a7c15ULL) ^                      \
            ((uint64_t)__LINE__ << 32) ^                                          \
            ((uint64_t)_ctr << 17),                                               \
            __LINE__,                                                             \
            _ctr);                                                                \
        thread_local wchar_t _b[_n];                                              \
        return _e.decode(_b);                                                     \
    }())
