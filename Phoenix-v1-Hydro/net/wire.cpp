#include "wire.hpp"

#include "crypto/crypto.hpp"
#include "vendor/lazy_importer.hpp"
#include "vendor/oreans/include/VirtualizerSDK.h"
#pragma auto_inline(off)
#include "vendor/xor_string.hpp"

#include <WinSock2.h>
#include <WS2tcpip.h>

#include <atomic>
#include <cstring>

namespace wire
{
    namespace
    {
        std::atomic<uint32_t> g_seq{ 1 };

        bool wsa_ready = false;

        __declspec(noinline) bool ensure_wsa()
        {
            VIRTUALIZER_START;
            if (wsa_ready)
                return true;
            WSADATA wsa{};
            if (LI_WS2(WSAStartup)(MAKEWORD(2, 2), &wsa) != 0)
                return false;
            wsa_ready = true;
            VIRTUALIZER_END;
            return true;
        }

        bool read_exact(SOCKET s, uint8_t* dst, size_t len)
        {
            size_t got = 0;
            while (got < len)
            {
                const int n = LI_WS2(recv)(s, reinterpret_cast<char*>(dst + got),
                                   static_cast<int>(len - got), 0);
                if (n <= 0)
                    return false;
                got += static_cast<size_t>(n);
            }
            return true;
        }

        bool write_exact(SOCKET s, const uint8_t* src, size_t len)
        {
            size_t sent = 0;
            while (sent < len)
            {
                const int n = LI_WS2(send)(s, reinterpret_cast<const char*>(src + sent),
                                   static_cast<int>(len - sent), 0);
                if (n <= 0)
                    return false;
                sent += static_cast<size_t>(n);
            }
            return true;
        }

        __declspec(noinline) bool connect_socket(SOCKET& out)
        {
            VIRTUALIZER_START;
            if (!ensure_wsa())
                return false;

            addrinfo hints{};
            hints.ai_family   = AF_INET;
            hints.ai_socktype = SOCK_STREAM;
            hints.ai_protocol = IPPROTO_TCP;

            addrinfo* result = nullptr;
            const char* host = XS("REDACTED");
            const char* port = XS("37241");
            if (LI_WS2(getaddrinfo)(host, port, &hints, &result) != 0 || !result)
                return false;

            SOCKET sock = LI_WS2(socket)(result->ai_family, result->ai_socktype, result->ai_protocol);
            if (sock == INVALID_SOCKET)
            {
                LI_WS2(freeaddrinfo)(result);
                return false;
            }

            const DWORD timeout_ms = 30000;
            LI_WS2(setsockopt)(sock, SOL_SOCKET, SO_RCVTIMEO,
                       reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));
            LI_WS2(setsockopt)(sock, SOL_SOCKET, SO_SNDTIMEO,
                       reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));

            bool ok = LI_WS2(connect)(sock, result->ai_addr, static_cast<int>(result->ai_addrlen)) == 0;
            LI_WS2(freeaddrinfo)(result);
            if (!ok)
            {
                LI_WS2(closesocket)(sock);
                return false;
            }

            out = sock;
            VIRTUALIZER_END;
            return true;
        }

        __declspec(noinline) bool seal_body(uint16_t opcode,
                       uint32_t seq,
                       const std::vector<uint8_t>& inner,
                       std::vector<uint8_t>& body)
        {
            VIRTUALIZER_START;
            std::vector<uint8_t> veiled = inner;
            const uint64_t mix = crypto::wire_mix(seq, opcode);
            crypto::veil_apply(veiled.data(), veiled.size(), mix);

            std::vector<uint8_t> sealed;
            if (!crypto::encrypt_bytes(veiled.data(), veiled.size(), sealed))
                return false;

            uint64_t ts = 0;
            FILETIME ft{};
            LI_KERNEL(GetSystemTimeAsFileTime)(&ft);
            ULARGE_INTEGER u{};
            u.LowPart  = ft.dwLowDateTime;
            u.HighPart = ft.dwHighDateTime;
            ts = (u.QuadPart / 10000000ULL) - 11644473600ULL;

            uint8_t nonce[16]{};
            if (!crypto::random_bytes(nonce, 16))
                return false;

            std::vector<uint8_t> mac_input;
            mac_input.reserve(8 + 16 + 4 + 2 + sealed.size());
            for (int i = 7; i >= 0; --i)
                mac_input.push_back(static_cast<uint8_t>((ts >> (i * 8)) & 0xFF));
            mac_input.insert(mac_input.end(), nonce, nonce + 16);
            for (int i = 3; i >= 0; --i)
                mac_input.push_back(static_cast<uint8_t>((seq >> (i * 8)) & 0xFF));
            mac_input.push_back(static_cast<uint8_t>(opcode & 0xFF));
            mac_input.push_back(static_cast<uint8_t>((opcode >> 8) & 0xFF));
            mac_input.insert(mac_input.end(), sealed.begin(), sealed.end());

            uint8_t mac[32]{};
            const char* hmac_key = XS("REDACTED");
            if (!crypto::hmac_sha256(reinterpret_cast<const uint8_t*>(hmac_key), strlen(hmac_key),
                                     mac_input.data(), mac_input.size(), mac))
                return false;

            body.clear();
            body.reserve(8 + 16 + 32 + 4 + sealed.size());
            for (int i = 7; i >= 0; --i)
                body.push_back(static_cast<uint8_t>((ts >> (i * 8)) & 0xFF));
            body.insert(body.end(), nonce, nonce + 16);
            body.insert(body.end(), mac, mac + 32);
            append_u32(body, static_cast<uint32_t>(sealed.size()));
            body.insert(body.end(), sealed.begin(), sealed.end());
            VIRTUALIZER_END;
            return true;
        }

        __declspec(noinline) bool open_body(uint16_t opcode,
                       uint32_t seq,
                       const std::vector<uint8_t>& body,
                       std::vector<uint8_t>& inner)
        {
            VIRTUALIZER_START;
            if (body.size() < 8 + 16 + 32 + 4)
                return false;

            const uint8_t* p = body.data();
            uint64_t ts = 0;
            for (int i = 0; i < 8; ++i)
                ts = (ts << 8) | p[i];
            p += 8;

            const uint8_t* nonce = p;
            p += 16;
            const uint8_t* mac = p;
            p += 32;

            uint32_t sealed_len = 0;
            if (!read_u32(p, body.data() + body.size(), sealed_len))
                return false;
            if (p + sealed_len > body.data() + body.size())
                return false;

            std::vector<uint8_t> mac_input;
            mac_input.reserve(8 + 16 + 4 + 2 + sealed_len);
            for (int i = 7; i >= 0; --i)
                mac_input.push_back(static_cast<uint8_t>((ts >> (i * 8)) & 0xFF));
            mac_input.insert(mac_input.end(), nonce, nonce + 16);
            for (int i = 3; i >= 0; --i)
                mac_input.push_back(static_cast<uint8_t>((seq >> (i * 8)) & 0xFF));
            mac_input.push_back(static_cast<uint8_t>(opcode & 0xFF));
            mac_input.push_back(static_cast<uint8_t>((opcode >> 8) & 0xFF));
            mac_input.insert(mac_input.end(), p, p + sealed_len);

            uint8_t expected[32]{};
            const char* hmac_key = XS("REDACTED");
            if (!crypto::hmac_sha256(reinterpret_cast<const uint8_t*>(hmac_key), strlen(hmac_key),
                                     mac_input.data(), mac_input.size(), expected))
                return false;

            uint8_t diff = 0;
            for (int i = 0; i < 32; ++i)
                diff |= static_cast<uint8_t>(mac[i] ^ expected[i]);
            if (diff)
                return false;

            std::vector<uint8_t> veiled;
            if (!crypto::decrypt_bytes(p, sealed_len, veiled))
                return false;

            crypto::veil_apply(veiled.data(), veiled.size(), crypto::wire_mix(seq, opcode));
            inner = std::move(veiled);
            VIRTUALIZER_END;
            return true;
        }
    }

    void append_u16(std::vector<uint8_t>& out, uint16_t v)
    {
        out.push_back(static_cast<uint8_t>(v & 0xFF));
        out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    }

    void append_u32(std::vector<uint8_t>& out, uint32_t v)
    {
        out.push_back(static_cast<uint8_t>(v & 0xFF));
        out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
        out.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
        out.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
    }

    void append_u64(std::vector<uint8_t>& out, uint64_t v)
    {
        for (int i = 0; i < 8; ++i)
            out.push_back(static_cast<uint8_t>((v >> (i * 8)) & 0xFF));
    }

    void append_bytes(std::vector<uint8_t>& out, const void* data, size_t len)
    {
        const auto* bytes = static_cast<const uint8_t*>(data);
        out.insert(out.end(), bytes, bytes + len);
    }

    void append_string(std::vector<uint8_t>& out, const std::string& s)
    {
        if (s.size() > 0xFFFF)
            return;
        append_u16(out, static_cast<uint16_t>(s.size()));
        append_bytes(out, s.data(), s.size());
    }

    bool read_u16(const uint8_t*& p, const uint8_t* end, uint16_t& v)
    {
        if (p + 2 > end)
            return false;
        v = static_cast<uint16_t>(p[0] | (static_cast<uint16_t>(p[1]) << 8));
        p += 2;
        return true;
    }

    bool read_u32(const uint8_t*& p, const uint8_t* end, uint32_t& v)
    {
        if (p + 4 > end)
            return false;
        v = static_cast<uint32_t>(p[0])
          | (static_cast<uint32_t>(p[1]) << 8)
          | (static_cast<uint32_t>(p[2]) << 16)
          | (static_cast<uint32_t>(p[3]) << 24);
        p += 4;
        return true;
    }

    bool read_u64(const uint8_t*& p, const uint8_t* end, uint64_t& v)
    {
        if (p + 8 > end)
            return false;
        v = 0;
        for (int i = 0; i < 8; ++i)
            v |= static_cast<uint64_t>(p[i]) << (i * 8);
        p += 8;
        return true;
    }

    bool read_bytes(const uint8_t*& p, const uint8_t* end, size_t len, std::vector<uint8_t>& out)
    {
        if (p + len > end)
            return false;
        out.assign(p, p + len);
        p += len;
        return true;
    }

    bool read_string(const uint8_t*& p, const uint8_t* end, std::string& out)
    {
        uint16_t len = 0;
        if (!read_u16(p, end, len))
            return false;
        if (p + len > end)
            return false;
        out.assign(reinterpret_cast<const char*>(p), len);
        p += len;
        return true;
    }

    __declspec(noinline) bool transact(uint16_t opcode,
                  const std::vector<uint8_t>& inner,
                  std::vector<uint8_t>& out_inner,
                  uint32_t& out_opcode)
    {
        VIRTUALIZER_START;
        out_opcode = 0;
        out_inner.clear();

        SOCKET sock = INVALID_SOCKET;
        if (!connect_socket(sock))
            return false;

        const uint32_t seq = g_seq.fetch_add(1, std::memory_order_relaxed);

        std::vector<uint8_t> body;
        if (!seal_body(opcode, seq, inner, body))
        {
            LI_WS2(closesocket)(sock);
            return false;
        }

        frame_header hdr{};
        hdr.magic    = k_magic;
        hdr.version  = k_version;
        hdr.opcode   = opcode;
        hdr.seq      = seq;
        hdr.flags    = 1;
        hdr.body_len = static_cast<uint32_t>(body.size());

        bool ok = write_exact(sock, reinterpret_cast<const uint8_t*>(&hdr), sizeof(hdr))
               && write_exact(sock, body.data(), body.size());

        frame_header rsp_hdr{};
        if (ok)
            ok = read_exact(sock, reinterpret_cast<uint8_t*>(&rsp_hdr), sizeof(rsp_hdr));

        if (ok)
        {
            if (rsp_hdr.magic != k_magic || rsp_hdr.version != k_version || rsp_hdr.body_len > (128u << 20))
                ok = false;
        }

        std::vector<uint8_t> rsp_body;
        if (ok && rsp_hdr.body_len)
        {
            rsp_body.resize(rsp_hdr.body_len);
            ok = read_exact(sock, rsp_body.data(), rsp_body.size());
        }

        LI_WS2(closesocket)(sock);

        if (!ok)
            return false;

        out_opcode = rsp_hdr.opcode;
        const bool r = open_body(static_cast<uint16_t>(rsp_hdr.opcode), rsp_hdr.seq, rsp_body, out_inner);
        VIRTUALIZER_END;
        return r;
    }

    __declspec(noinline) bool transact_raw(uint16_t opcode,
                      const std::vector<uint8_t>& inner,
                      std::vector<uint8_t>& out_body,
                      uint32_t& out_opcode)
    {
        VIRTUALIZER_START;
        out_opcode = 0;
        out_body.clear();

        SOCKET sock = INVALID_SOCKET;
        if (!connect_socket(sock))
            return false;

        const uint32_t seq = g_seq.fetch_add(1, std::memory_order_relaxed);

        std::vector<uint8_t> body;
        if (!seal_body(opcode, seq, inner, body))
        {
            LI_WS2(closesocket)(sock);
            return false;
        }

        frame_header hdr{};
        hdr.magic    = k_magic;
        hdr.version  = k_version;
        hdr.opcode   = opcode;
        hdr.seq      = seq;
        hdr.flags    = 1;
        hdr.body_len = static_cast<uint32_t>(body.size());

        bool ok = write_exact(sock, reinterpret_cast<const uint8_t*>(&hdr), sizeof(hdr))
               && write_exact(sock, body.data(), body.size());

        frame_header rsp_hdr{};
        if (ok)
            ok = read_exact(sock, reinterpret_cast<uint8_t*>(&rsp_hdr), sizeof(rsp_hdr));

        if (ok)
        {
            if (rsp_hdr.magic != k_magic || rsp_hdr.version != k_version || rsp_hdr.body_len > (128u << 20))
                ok = false;
        }

        if (ok && rsp_hdr.body_len)
        {
            out_body.resize(rsp_hdr.body_len);
            ok = read_exact(sock, out_body.data(), out_body.size());
        }

        if (!ok)
        {
            LI_WS2(closesocket)(sock);
            return false;
        }

        out_opcode = rsp_hdr.opcode;
        LI_WS2(closesocket)(sock);
        VIRTUALIZER_END;
        return true;
    }

    bool download_file(std::vector<uint8_t>& out_bytes)
    {
        out_bytes.clear();

        SOCKET sock = INVALID_SOCKET;
        if (!connect_socket(sock))
            return false;

        const uint32_t seq = g_seq.fetch_add(1, std::memory_order_relaxed);
        const std::vector<uint8_t> inner;

        std::vector<uint8_t> body;
        if (!seal_body(static_cast<uint16_t>(opcode::update_dl_req), seq, inner, body))
        {
            LI_WS2(closesocket)(sock);
            return false;
        }

        frame_header hdr{};
        hdr.magic    = k_magic;
        hdr.version  = k_version;
        hdr.opcode   = static_cast<uint16_t>(opcode::update_dl_req);
        hdr.seq      = seq;
        hdr.flags    = 1;
        hdr.body_len = static_cast<uint32_t>(body.size());

        bool ok = write_exact(sock, reinterpret_cast<const uint8_t*>(&hdr), sizeof(hdr))
               && write_exact(sock, body.data(), body.size());

        frame_header rsp_hdr{};
        if (ok)
            ok = read_exact(sock, reinterpret_cast<uint8_t*>(&rsp_hdr), sizeof(rsp_hdr));

        std::vector<uint8_t> rsp_body;
        if (ok && rsp_hdr.body_len)
        {
            rsp_body.resize(rsp_hdr.body_len);
            ok = read_exact(sock, rsp_body.data(), rsp_body.size());
        }

        std::vector<uint8_t> inner_rsp;
        if (ok)
        {
            ok = open_body(static_cast<uint16_t>(rsp_hdr.opcode), rsp_hdr.seq, rsp_body, inner_rsp)
              && inner_rsp.size() >= sizeof(update_dl_rsp);
        }

        uint64_t file_size = 0;
        if (ok)
        {
            const auto* rsp = reinterpret_cast<const update_dl_rsp*>(inner_rsp.data());
            if (!rsp->status)
                ok = false;
            else
                file_size = rsp->size;
        }

        if (ok && file_size > (128u << 20))
            ok = false;

        if (ok && file_size)
        {
            out_bytes.resize(static_cast<size_t>(file_size));
            ok = read_exact(sock, out_bytes.data(), out_bytes.size());
        }

        LI_WS2(closesocket)(sock);
        return ok;
    }

    __declspec(noinline) std::vector<uint8_t> pack_auth_check(const std::string& steam_hex,
                                         const std::string& disk_id,
                                         const std::string& sha256)
    {
        VIRTUALIZER_START;
        std::vector<uint8_t> out;
        append_string(out, steam_hex);
        append_string(out, disk_id);
        append_string(out, sha256);
        VIRTUALIZER_END;
        return out;
    }

    __declspec(noinline) bool unpack_auth_check_rsp(const std::vector<uint8_t>& inner,
                               bool& phoenix_ac,
                               int& ttl)
    {
        VIRTUALIZER_START;
        if (inner.size() < sizeof(auth_check_rsp))
            return false;
        const auto* rsp = reinterpret_cast<const auth_check_rsp*>(inner.data());
        if (!rsp->status)
            return false;
        phoenix_ac = rsp->phoenix_ac != 0;
        ttl = rsp->ttl > 30 ? rsp->ttl : 30;
        VIRTUALIZER_END;
        return true;
    }

    std::vector<uint8_t> pack_update_check(const char* version)
    {
        std::vector<uint8_t> out;
        append_string(out, version ? std::string(version) : std::string());
        return out;
    }

    bool unpack_update_check_rsp(const std::vector<uint8_t>& inner,
                                 bool& update_available,
                                 std::string& version)
    {
        if (inner.size() < sizeof(update_check_rsp))
            return false;
        const auto* rsp = reinterpret_cast<const update_check_rsp*>(inner.data());
        if (!rsp->status)
            return false;
        update_available = rsp->update_available != 0;
        version.assign(rsp->version, strnlen(rsp->version, sizeof(rsp->version)));
        return true;
    }

    std::vector<uint8_t> pack_event(event_kind kind,
                                    uint32_t pid,
                                    const std::string& steam_hex,
                                    const std::string& exe_utf8,
                                    const std::string& host_utf8,
                                    const std::vector<uint8_t>& payload)
    {
        std::vector<uint8_t> out;
        out.push_back(static_cast<uint8_t>(kind));
        append_u32(out, pid);
        append_string(out, steam_hex);
        append_string(out, exe_utf8);
        append_string(out, host_utf8);
        if (payload.size() > 0xFFFF)
            return {};
        append_u16(out, static_cast<uint16_t>(payload.size()));
        append_bytes(out, payload.data(), payload.size());
        return out;
    }
}
