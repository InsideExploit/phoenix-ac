#include "crypto.hpp"

#include "vendor/lazy_importer.hpp"
#include "vendor/xor_string.hpp"
#include "vendor/oreans/include/VirtualizerSDK.h"
#pragma auto_inline(off)

#include <Windows.h>
#include <bcrypt.h>
#include <ntstatus.h>
#include <cstring>
#include <vector>

namespace crypto
{
    namespace
    {
        constexpr size_t k_key_bytes   = 32;
        constexpr size_t k_nonce_bytes = 12;
        constexpr size_t k_tag_bytes   = 16;

        __declspec(noinline) const char* master_key_hex()
        {
            VIRTUALIZER_START;
            const char* k = XS("REDACTED");
            VIRTUALIZER_END;
            return k;
        }

        __declspec(noinline) bool hex_nibble(char c, uint8_t& out)
        {
            VIRTUALIZER_START;
            if (c >= '0' && c <= '9') { out = static_cast<uint8_t>(c - '0');      return true; }
            if (c >= 'a' && c <= 'f') { out = static_cast<uint8_t>(c - 'a' + 10); return true; }
            if (c >= 'A' && c <= 'F') { out = static_cast<uint8_t>(c - 'A' + 10); return true; }
            VIRTUALIZER_END;
            return false;
        }

        __declspec(noinline) bool hex_to_bytes(const char* hex, uint8_t* out, size_t out_len)
        {
            VIRTUALIZER_START;
            for (size_t i = 0; i < out_len; ++i)
            {
                uint8_t hi = 0, lo = 0;
                if (!hex_nibble(hex[i * 2], hi))     return false;
                if (!hex_nibble(hex[i * 2 + 1], lo)) return false;
                out[i] = static_cast<uint8_t>((hi << 4) | lo);
            }
            VIRTUALIZER_END;
            return true;
        }

        constexpr char k_base64_alphabet[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        __declspec(noinline) std::string base64_encode(const uint8_t* data, size_t len)
        {
            VIRTUALIZER_START;
            std::string out;
            out.reserve(((len + 2) / 3) * 4);

            size_t i = 0;
            while (i + 3 <= len)
            {
                const uint32_t v = (static_cast<uint32_t>(data[i]) << 16)
                                 | (static_cast<uint32_t>(data[i + 1]) << 8)
                                 |  static_cast<uint32_t>(data[i + 2]);
                out += k_base64_alphabet[(v >> 18) & 0x3F];
                out += k_base64_alphabet[(v >> 12) & 0x3F];
                out += k_base64_alphabet[(v >>  6) & 0x3F];
                out += k_base64_alphabet[ v        & 0x3F];
                i += 3;
            }

            if (i < len)
            {
                uint32_t v = static_cast<uint32_t>(data[i]) << 16;
                const size_t rem = len - i;
                if (rem == 2)
                    v |= static_cast<uint32_t>(data[i + 1]) << 8;

                out += k_base64_alphabet[(v >> 18) & 0x3F];
                out += k_base64_alphabet[(v >> 12) & 0x3F];
                out += (rem == 2) ? k_base64_alphabet[(v >> 6) & 0x3F] : '=';
                out += '=';
            }
            VIRTUALIZER_END;
            return out;
        }

        __declspec(noinline) int base64_index(char c)
        {
            VIRTUALIZER_START;
            int r = -1;
            if (c >= 'A' && c <= 'Z') r = c - 'A';
            else if (c >= 'a' && c <= 'z') r = c - 'a' + 26;
            else if (c >= '0' && c <= '9') r = c - '0' + 52;
            else if (c == '+') r = 62;
            else if (c == '/') r = 63;
            VIRTUALIZER_END;
            return r;
        }

        __declspec(noinline) bool base64_decode(const std::string& s, std::vector<uint8_t>& out)
        {
            VIRTUALIZER_START;
            out.clear();
            size_t len = s.size();
            while (len > 0 && (s[len - 1] == '=' || s[len - 1] == '\r' || s[len - 1] == '\n'))
                --len;

            out.reserve((len * 3) / 4);

            uint32_t buffer = 0;
            int bits = 0;

            for (size_t i = 0; i < len; ++i)
            {
                const char c = s[i];
                if (c == '\r' || c == '\n' || c == ' ')
                    continue;

                const int v = base64_index(c);
                if (v < 0)
                    return false;

                buffer = (buffer << 6) | static_cast<uint32_t>(v);
                bits += 6;

                if (bits >= 8)
                {
                    bits -= 8;
                    out.push_back(static_cast<uint8_t>((buffer >> bits) & 0xFF));
                }
            }
            VIRTUALIZER_END;
            return true;
        }

        __declspec(noinline) bool load_key(uint8_t key[k_key_bytes])
        {
            VIRTUALIZER_START;
            const char* hex = master_key_hex();
            if (!hex)
                return false;
            volatile bool r = hex_to_bytes(hex, key, k_key_bytes);
            VIRTUALIZER_END;
            return r;
        }

        __declspec(noinline) bool gen_random(uint8_t* out, size_t len)
        {
            VIRTUALIZER_START;
            volatile bool r = LI_BCRYPT(BCryptGenRandom)(nullptr, out, static_cast<ULONG>(len),
                                                         BCRYPT_USE_SYSTEM_PREFERRED_RNG) == STATUS_SUCCESS;
            VIRTUALIZER_END;
            return r;
        }

        __declspec(noinline) bool aes_gcm_encrypt(const uint8_t* key,
                             const uint8_t* nonce,
                             const uint8_t* plaintext,
                             size_t pt_len,
                             uint8_t* ciphertext,
                             uint8_t* tag)
        {
            VIRTUALIZER_START;
            BCRYPT_ALG_HANDLE alg = nullptr;
            BCRYPT_KEY_HANDLE key_handle = nullptr;
            bool ok = false;

            do
            {
                if (LI_BCRYPT(BCryptOpenAlgorithmProvider)(&alg, BCRYPT_AES_ALGORITHM, nullptr, 0) != STATUS_SUCCESS)
                    break;
                if (LI_BCRYPT(BCryptSetProperty)(alg, BCRYPT_CHAINING_MODE,
                                      (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                                      sizeof(BCRYPT_CHAIN_MODE_GCM), 0) != STATUS_SUCCESS)
                    break;
                if (LI_BCRYPT(BCryptGenerateSymmetricKey)(alg, &key_handle, nullptr, 0,
                                               const_cast<PUCHAR>(key), static_cast<ULONG>(k_key_bytes), 0) != STATUS_SUCCESS)
                    break;

                BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
                BCRYPT_INIT_AUTH_MODE_INFO(info);
                info.pbNonce = const_cast<PUCHAR>(nonce);
                info.cbNonce = static_cast<ULONG>(k_nonce_bytes);
                info.pbTag   = tag;
                info.cbTag   = static_cast<ULONG>(k_tag_bytes);

                ULONG produced = 0;
                if (LI_BCRYPT(BCryptEncrypt)(key_handle, const_cast<PUCHAR>(plaintext), static_cast<ULONG>(pt_len), &info,
                                  nullptr, 0, ciphertext, static_cast<ULONG>(pt_len), &produced, 0) != STATUS_SUCCESS)
                    break;
                if (produced != static_cast<ULONG>(pt_len))
                    break;
                ok = true;
            } while (false);

            if (key_handle) LI_BCRYPT(BCryptDestroyKey)(key_handle);
            if (alg)        LI_BCRYPT(BCryptCloseAlgorithmProvider)(alg, 0);
            VIRTUALIZER_END;
            return ok;
        }

        __declspec(noinline) bool aes_gcm_decrypt(const uint8_t* key,
                             const uint8_t* nonce,
                             const uint8_t* ciphertext,
                             size_t ct_len,
                             const uint8_t* tag,
                             uint8_t* plaintext)
        {
            VIRTUALIZER_START;
            BCRYPT_ALG_HANDLE alg = nullptr;
            BCRYPT_KEY_HANDLE key_handle = nullptr;
            bool ok = false;

            do
            {
                if (LI_BCRYPT(BCryptOpenAlgorithmProvider)(&alg, BCRYPT_AES_ALGORITHM, nullptr, 0) != STATUS_SUCCESS)
                    break;
                if (LI_BCRYPT(BCryptSetProperty)(alg, BCRYPT_CHAINING_MODE,
                                      (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                                      sizeof(BCRYPT_CHAIN_MODE_GCM), 0) != STATUS_SUCCESS)
                    break;
                if (LI_BCRYPT(BCryptGenerateSymmetricKey)(alg, &key_handle, nullptr, 0,
                                               const_cast<PUCHAR>(key), static_cast<ULONG>(k_key_bytes), 0) != STATUS_SUCCESS)
                    break;

                BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
                BCRYPT_INIT_AUTH_MODE_INFO(info);
                info.pbNonce = const_cast<PUCHAR>(nonce);
                info.cbNonce = static_cast<ULONG>(k_nonce_bytes);
                info.pbTag   = const_cast<PUCHAR>(tag);
                info.cbTag   = static_cast<ULONG>(k_tag_bytes);

                ULONG produced = 0;
                const NTSTATUS s = LI_BCRYPT(BCryptDecrypt)(key_handle, const_cast<PUCHAR>(ciphertext), static_cast<ULONG>(ct_len), &info,
                                                 nullptr, 0, plaintext, static_cast<ULONG>(ct_len), &produced, 0);
                if (s != STATUS_SUCCESS)
                    break;
                if (produced != static_cast<ULONG>(ct_len))
                    break;
                ok = true;
            } while (false);

            if (key_handle) LI_BCRYPT(BCryptDestroyKey)(key_handle);
            if (alg)        LI_BCRYPT(BCryptCloseAlgorithmProvider)(alg, 0);
            VIRTUALIZER_END;
            return ok;
        }

        __declspec(noinline) uint64_t avalanche64(uint64_t x)
        {
            VIRTUALIZER_START;
            x ^= x >> 33;
            x *= 0xff51afd7ed558ccdULL;
            x ^= x >> 33;
            x *= 0xc4ceb9fe1a85ec53ULL;
            x ^= x >> 33;
            VIRTUALIZER_END;
            return x;
        }

        uint8_t rotl8(uint8_t v, unsigned r)
        {
            r &= 7;
            if (!r)
                return v;
            return static_cast<uint8_t>((v << r) | (v >> (8 - r)));
        }

        uint64_t rotl64(uint64_t v, unsigned r)
        {
            r &= 63;
            if (!r)
                return v;
            return (v << r) | (v >> (64 - r));
        }
    }

    __declspec(noinline) bool encrypt(const std::string& plaintext, std::string& out_base64)
    {
        VIRTUALIZER_START;
        uint8_t key[k_key_bytes];
        if (!load_key(key))
            return false;

        uint8_t nonce[k_nonce_bytes];
        if (!gen_random(nonce, k_nonce_bytes))
            return false;

        const size_t pt_len = plaintext.size();

        std::vector<uint8_t> envelope(k_nonce_bytes + pt_len + k_tag_bytes);
        std::memcpy(envelope.data(), nonce, k_nonce_bytes);

        uint8_t* ct_buffer  = envelope.data() + k_nonce_bytes;
        uint8_t* tag_buffer = envelope.data() + k_nonce_bytes + pt_len;

        if (!aes_gcm_encrypt(key, nonce,
                             reinterpret_cast<const uint8_t*>(plaintext.data()), pt_len,
                             ct_buffer, tag_buffer))
            return false;

        out_base64 = base64_encode(envelope.data(), envelope.size());
        VIRTUALIZER_END;
        return true;
    }

    __declspec(noinline) bool decrypt(const std::string& base64_envelope, std::string& out_plaintext)
    {
        VIRTUALIZER_START;
        std::vector<uint8_t> envelope;
        if (!base64_decode(base64_envelope, envelope))
            return false;
        if (envelope.size() < k_nonce_bytes + k_tag_bytes)
            return false;

        uint8_t key[k_key_bytes];
        if (!load_key(key))
            return false;

        const size_t ct_len = envelope.size() - k_nonce_bytes - k_tag_bytes;
        const uint8_t* nonce      = envelope.data();
        const uint8_t* ct_buffer  = envelope.data() + k_nonce_bytes;
        const uint8_t* tag_buffer = envelope.data() + k_nonce_bytes + ct_len;

        std::vector<uint8_t> pt(ct_len);
        if (!aes_gcm_decrypt(key, nonce, ct_buffer, ct_len, tag_buffer, pt.data()))
            return false;

        out_plaintext.assign(reinterpret_cast<const char*>(pt.data()), pt.size());
        VIRTUALIZER_END;
        return true;
    }

    __declspec(noinline) bool hmac_sha256(const uint8_t* key, size_t key_len,
                     const uint8_t* msg, size_t msg_len,
                     uint8_t out[32])
    {
        VIRTUALIZER_START;
        BCRYPT_ALG_HANDLE alg = nullptr;
        if (LI_BCRYPT(BCryptOpenAlgorithmProvider)(&alg, BCRYPT_SHA256_ALGORITHM, nullptr,
                                        BCRYPT_ALG_HANDLE_HMAC_FLAG) != STATUS_SUCCESS)
            return false;

        bool ok = false;
        BCRYPT_HASH_HANDLE hash = nullptr;
        if (LI_BCRYPT(BCryptCreateHash)(alg, &hash, nullptr, 0,
                             const_cast<PUCHAR>(key), static_cast<ULONG>(key_len), 0) == 0)
        {
            if (LI_BCRYPT(BCryptHashData)(hash, const_cast<PUCHAR>(msg), static_cast<ULONG>(msg_len), 0) == 0 &&
                LI_BCRYPT(BCryptFinishHash)(hash, out, 32, 0) == 0)
            {
                ok = true;
            }
            LI_BCRYPT(BCryptDestroyHash)(hash);
        }
        LI_BCRYPT(BCryptCloseAlgorithmProvider)(alg, 0);
        VIRTUALIZER_END;
        return ok;
    }

    __declspec(noinline) bool random_bytes(uint8_t* out, size_t len)
    {
        VIRTUALIZER_START;
        volatile bool r = LI_BCRYPT(BCryptGenRandom)(nullptr, out, static_cast<ULONG>(len),
                                                     BCRYPT_USE_SYSTEM_PREFERRED_RNG) == STATUS_SUCCESS;
        VIRTUALIZER_END;
        return r;
    }

    __declspec(noinline) uint64_t wire_mix(uint32_t seq, uint16_t opcode)
    {
        VIRTUALIZER_START;
        static uint64_t session = 0;
        if (!session)
        {
            const char* api = XS("REDACTED");
            const char* label = XS("module-wire-v1");
            uint8_t mac[32]{};
            if (hmac_sha256(reinterpret_cast<const uint8_t*>(api), strlen(api),
                            reinterpret_cast<const uint8_t*>(label), strlen(label), mac))
            {
                session = (static_cast<uint64_t>(mac[0]) << 56)
                        | (static_cast<uint64_t>(mac[1]) << 48)
                        | (static_cast<uint64_t>(mac[2]) << 40)
                        | (static_cast<uint64_t>(mac[3]) << 32)
                        | (static_cast<uint64_t>(mac[4]) << 24)
                        | (static_cast<uint64_t>(mac[5]) << 16)
                        | (static_cast<uint64_t>(mac[6]) << 8)
                        |  static_cast<uint64_t>(mac[7]);
            }
            session = avalanche64(session ^ 0xc2b2ae3d27d4eb4fULL);
        }
        const uint64_t r = avalanche64(session ^ (static_cast<uint64_t>(opcode) << 32) ^ seq);
        VIRTUALIZER_END;
        return r;
    }

    __declspec(noinline) void veil_apply(uint8_t* data, size_t len, uint64_t mix)
    {
        VIRTUALIZER_START;
        uint64_t s0 = avalanche64(mix ^ 0x243f6a8885a308d3ULL);
        uint64_t s1 = avalanche64(mix ^ 0x13198a2e03707344ULL);
        for (size_t i = 0; i < len; ++i)
        {
            const uint8_t kb = static_cast<uint8_t>(
                (s0 >> ((i & 7) * 8))
                ^ (s1 >> (((i + 3) & 7) * 8))
                ^ static_cast<uint8_t>(i * 29 + 0x5A));
            data[i] ^= kb;
            s0 = avalanche64(s0 ^ kb ^ static_cast<uint64_t>(i));
            s1 = rotl64(s1 ^ static_cast<uint64_t>(kb), static_cast<unsigned>(((i & 31) + 1)));
        }
        VIRTUALIZER_END;
    }

    __declspec(noinline) bool encrypt_bytes(const uint8_t* data, size_t len, std::vector<uint8_t>& out)
    {
        VIRTUALIZER_START;
        uint8_t key[32];
        if (!load_key(key))
            return false;

        uint8_t nonce[12];
        if (!random_bytes(nonce, 12))
            return false;

        out.resize(12 + len + 16);
        std::memcpy(out.data(), nonce, 12);
        const bool r = aes_gcm_encrypt(key, nonce, data, len, out.data() + 12, out.data() + 12 + len);
        VIRTUALIZER_END;
        return r;
    }

    __declspec(noinline) bool decrypt_bytes(const uint8_t* data, size_t len, std::vector<uint8_t>& out)
    {
        VIRTUALIZER_START;
        if (len < 12 + 16)
            return false;

        uint8_t key[32];
        if (!load_key(key))
            return false;

        const size_t ct_len = len - 12 - 16;
        out.resize(ct_len);
        const bool r = aes_gcm_decrypt(key, data, data + 12, ct_len, data + 12 + ct_len, out.data());
        VIRTUALIZER_END;
        return r;
    }
}
