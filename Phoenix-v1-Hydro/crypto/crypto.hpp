#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace crypto
{
    bool encrypt(const std::string& plaintext, std::string& out_base64);
    bool decrypt(const std::string& base64_envelope, std::string& out_plaintext);

    bool encrypt_bytes(const uint8_t* data, size_t len, std::vector<uint8_t>& out);
    bool decrypt_bytes(const uint8_t* data, size_t len, std::vector<uint8_t>& out);

    void veil_apply(uint8_t* data, size_t len, uint64_t mix);
    uint64_t wire_mix(uint32_t seq, uint16_t opcode);

    bool hmac_sha256(const uint8_t* key, size_t key_len,
                     const uint8_t* msg, size_t msg_len,
                     uint8_t out[32]);

    bool random_bytes(uint8_t* out, size_t len);
}
