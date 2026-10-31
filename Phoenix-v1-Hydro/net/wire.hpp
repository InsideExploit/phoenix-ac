#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace wire
{
    constexpr uint32_t k_magic   = 0x31584850u;
    constexpr uint16_t k_version = 1;

    enum class opcode : uint16_t
    {
        auth_check_req  = 0x0101,
        auth_check_rsp  = 0x0102,
        event_req       = 0x0201,
        event_rsp       = 0x0202,
        update_check_req = 0x0301,
        update_check_rsp = 0x0302,
        update_dl_req   = 0x0303,
        update_dl_rsp   = 0x0304,
    };

    enum class event_kind : uint8_t
    {
        detection      = 1,
        sweep          = 2,
        exit_kind      = 3,
        overlay        = 4,
        internal_kind  = 5,
        mapper         = 6,
        injection      = 7,
        modfingerprint = 8,
        security       = 9,
        internal_fivem = 10,
    };

#pragma pack(push, 1)
    struct frame_header
    {
        uint32_t magic;
        uint16_t version;
        uint16_t opcode;
        uint32_t seq;
        uint32_t flags;
        uint32_t body_len;
    };

    struct auth_check_rsp
    {
        uint8_t status;
        uint8_t phoenix_ac;
        uint16_t ttl;
    };

    struct update_check_rsp
    {
        uint8_t status;
        uint8_t update_available;
        char version[16];
    };

    struct update_dl_rsp
    {
        uint8_t status;
        uint8_t reserved[3];
        uint64_t size;
    };

    struct event_rsp
    {
        uint8_t status;
    };
#pragma pack(pop)

    bool transact(uint16_t opcode,
                  const std::vector<uint8_t>& inner,
                  std::vector<uint8_t>& out_inner,
                  uint32_t& out_opcode);

    bool transact_raw(uint16_t opcode,
                      const std::vector<uint8_t>& inner,
                      std::vector<uint8_t>& out_body,
                      uint32_t& out_opcode);

    bool download_file(std::vector<uint8_t>& out_bytes);

    std::vector<uint8_t> pack_auth_check(const std::string& steam_hex,
                                         const std::string& disk_id,
                                         const std::string& sha256);

    bool unpack_auth_check_rsp(const std::vector<uint8_t>& inner,
                               bool& phoenix_ac,
                               int& ttl);

    std::vector<uint8_t> pack_update_check(const char* version);

    bool unpack_update_check_rsp(const std::vector<uint8_t>& inner,
                                 bool& update_available,
                                 std::string& version);

    std::vector<uint8_t> pack_event(event_kind kind,
                                    uint32_t pid,
                                    const std::string& steam_hex,
                                    const std::string& exe_utf8,
                                    const std::string& host_utf8,
                                    const std::vector<uint8_t>& payload);

    void append_u16(std::vector<uint8_t>& out, uint16_t v);
    void append_u32(std::vector<uint8_t>& out, uint32_t v);
    void append_u64(std::vector<uint8_t>& out, uint64_t v);
    void append_bytes(std::vector<uint8_t>& out, const void* data, size_t len);
    void append_string(std::vector<uint8_t>& out, const std::string& s);

    bool read_u16(const uint8_t*& p, const uint8_t* end, uint16_t& v);
    bool read_u32(const uint8_t*& p, const uint8_t* end, uint32_t& v);
    bool read_u64(const uint8_t*& p, const uint8_t* end, uint64_t& v);
    bool read_bytes(const uint8_t*& p, const uint8_t* end, size_t len, std::vector<uint8_t>& out);
    bool read_string(const uint8_t*& p, const uint8_t* end, std::string& out);
}
