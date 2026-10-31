/*
 * MIT License https://github.com/Android1337/brkida/blob/main/LICENSE
 * Copyright (c) 2024 Android1337
 *
 * Corrupts IDA's decompiler by embedding a bogus code stub and a call to 0x0
 * inside the function; guarded by an always-false predicate so nothing ever runs.
 */

#ifndef BRKIDA_HPP
#define BRKIDA_HPP

#if defined(_MSC_VER) && defined(_WIN64)
#include <intrin.h>

inline constexpr unsigned long long brkida_const_hash(const char* input) {
    return *input
        ? static_cast<unsigned long long>(*input) + 33 * brkida_const_hash(input + 1)
        : 5381;
}

#define BRKIDA \
{ \
    constexpr unsigned __int8 _brkida_stub[] = { \
        0xEB, 0x08, \
        0x48, 0x89, 0x8C, 0x24, \
        static_cast<unsigned __int8>((brkida_const_hash(__DATE__ __TIME__) + __COUNTER__ * __COUNTER__) % 0xFF), \
        static_cast<unsigned __int8>((brkida_const_hash(__DATE__ __TIME__) + __COUNTER__ * __COUNTER__) % 0xFF), \
        static_cast<unsigned __int8>((brkida_const_hash(__DATE__ __TIME__) + __COUNTER__ * __COUNTER__) % 0xFF), \
        static_cast<unsigned __int8>((brkida_const_hash(__DATE__ __TIME__) + __COUNTER__ * __COUNTER__) % 0xFF), \
        0xC3 \
    }; \
    if (!_AddressOfReturnAddress()) { \
        ((void(*)())reinterpret_cast<uintptr_t>(_brkida_stub))(); \
        ((void(*)())static_cast<uintptr_t>(0x0))(); \
    } \
}

#else
#define BRKIDA
#endif

#endif
