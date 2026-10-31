#pragma once

#ifdef _KERNEL_MODE
namespace std
{
template <class _Ty>
struct remove_reference {
    using type = _Ty;
};

template <class _Ty>
struct remove_reference<_Ty&> {
    using type = _Ty;
};

template <class _Ty>
struct remove_reference<_Ty&&> {
    using type = _Ty;
};

template <class _Ty>
using remove_reference_t = typename remove_reference<_Ty>::type;

template <class _Ty>
struct remove_const {
    using type = _Ty;
};

template <class _Ty>
struct remove_const<const _Ty> {
    using type = _Ty;
};

template <class _Ty>
using remove_const_t = typename remove_const<_Ty>::type;
}
#else
#include <type_traits>
#endif

namespace skc
{
template<class _Ty>
using clean_type = typename std::remove_const_t<std::remove_reference_t<_Ty>>;

namespace detail
{
constexpr uint64_t mix64(uint64_t h, uint64_t k)
{
    k *= 0xFF51AFD7ED558CCDULL;
    k ^= k >> 33;
    k *= 0xC4CEB9FE1A85EC53ULL;
    k ^= k >> 33;
    return h ^ k;
}

constexpr uint64_t make_seed(char key1, char key2, char key3, unsigned line, unsigned counter)
{
    uint64_t seed = 0x84222325CBF29CE4ULL;
    seed = mix64(seed, static_cast<uint64_t>(static_cast<unsigned char>(key1)));
    seed = mix64(seed, static_cast<uint64_t>(static_cast<unsigned char>(key2)));
    seed = mix64(seed, static_cast<uint64_t>(static_cast<unsigned char>(key3)));
    seed = mix64(seed, static_cast<uint64_t>(line) * 0x9E3779B97F4A7C15ULL);
    seed = mix64(seed, static_cast<uint64_t>(counter) * 0xBF58476D1CE4E5B9ULL);
    seed = mix64(seed, seed << 17);
    return seed;
}

template<typename T>
using unsigned_t = typename std::make_unsigned<T>::type;

template<typename T, uint64_t Seed>
struct cipher
{
    static constexpr unsigned bit_width = static_cast<unsigned>(sizeof(T) * 8);

    static constexpr unsigned_t<T> rotl(unsigned_t<T> value, unsigned shift)
    {
        shift %= bit_width;
        if (shift == 0)
            return value;

        return static_cast<unsigned_t<T>>((value << shift) | (value >> (bit_width - shift)));
    }

    static constexpr unsigned_t<T> rotr(unsigned_t<T> value, unsigned shift)
    {
        shift %= bit_width;
        if (shift == 0)
            return value;

        return static_cast<unsigned_t<T>>((value >> shift) | (value << (bit_width - shift)));
    }

    static constexpr uint64_t subkey(int index)
    {
        return mix64(Seed, static_cast<uint64_t>(index) * 0x5851F42D4C957F2DULL);
    }

    static constexpr unsigned round_shift(uint64_t key, int index, unsigned round)
    {
        return static_cast<unsigned>(((key >> (round * 5)) ^ (key >> 11) ^ index) % (bit_width - 1)) + 1;
    }

    static constexpr unsigned_t<T> round_key(uint64_t key, int index, unsigned round)
    {
        return static_cast<unsigned_t<T>>((key >> ((round + index) & 7)) ^ (key >> ((round * 3) & 15)));
    }

    static constexpr T encode(T value, int index)
    {
        unsigned_t<T> current = static_cast<unsigned_t<T>>(value);
        uint64_t key = subkey(index);

        for (unsigned round = 0; round < 4; ++round)
        {
            current ^= round_key(key, index, round);
            current = rotl(current, round_shift(key, index, round));
            current += static_cast<unsigned_t<T>>(round_key(key, index, round + 4) + index + round);
            current ^= static_cast<unsigned_t<T>>(mix64(key, static_cast<uint64_t>(round) ^ 0xA5A5A5A5A5A5A5A5ULL));
        }

        return static_cast<T>(current);
    }

    static constexpr T decode(T value, int index)
    {
        unsigned_t<T> current = static_cast<unsigned_t<T>>(value);
        uint64_t key = subkey(index);

        for (unsigned round = 4; round-- > 0;)
        {
            current ^= static_cast<unsigned_t<T>>(mix64(key, static_cast<uint64_t>(round) ^ 0xA5A5A5A5A5A5A5A5ULL));
            current -= static_cast<unsigned_t<T>>(round_key(key, index, round + 4) + index + round);
            current = rotr(current, round_shift(key, index, round));
            current ^= round_key(key, index, round);
        }

        return static_cast<T>(current);
    }
};
}

template <int _size, uint64_t _seed, typename T>
class skCrypter
{
public:
    __forceinline constexpr skCrypter(T* data)
    {
        for (int i = 0; i < _size; ++i)
            _storage[i] = detail::cipher<T, _seed>::encode(data[i], i);
    }

    __forceinline T* get()
    {
        return _storage;
    }

    __forceinline int size()
    {
        return _size;
    }

    __forceinline T* encrypt()
    {
        if (!_open)
            return _storage;

        for (int i = 0; i < _size; ++i)
            _storage[i] = detail::cipher<T, _seed>::encode(_storage[i], i);

        _open = false;
        return _storage;
    }

    __declspec(noinline) T* decrypt()
    {
        if (_open)
            return _storage;

        volatile unsigned noise = static_cast<unsigned>(_seed);
        for (int i = 0; i < _size; ++i)
        {
            noise = (noise * 16777619u) ^ static_cast<unsigned>(i);
            _storage[i] = detail::cipher<T, _seed>::decode(_storage[i], i);
        }

        _open = true;
        return _storage;
    }

    __forceinline bool isEncrypted()
    {
        return !_open;
    }

    __forceinline void clear()
    {
        for (int i = 0; i < _size; ++i)
            _storage[i] = T{};

        _open = false;
    }

    __declspec(noinline) operator T* ()
    {
        return decrypt();
    }

private:
    T _storage[_size]{};
    mutable bool _open = false;
};

}

#define skCrypt(str) skCrypt_key(str, __TIME__[4], __TIME__[7], __DATE__[2], __LINE__, __COUNTER__)
#define skCrypt_key(str, key1, key2, key3, line, counter) []() { \
    constexpr static auto crypted = skc::skCrypter \
        <sizeof(str) / sizeof(str[0]), \
        skc::detail::make_seed(key1, key2, key3, line, counter), \
        skc::clean_type<decltype(str[0])>>((skc::clean_type<decltype(str[0])>*)str); \
    return crypted; }()