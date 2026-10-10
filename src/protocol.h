// AC Relay protocol v1 wire format (see docs/PROTOCOL.md).
// All integers are big-endian. Every control datagram starts with
// "ACRL" | u8 version | u8 type.
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

namespace acr {

inline constexpr uint8_t kMagic[4] = {'A', 'C', 'R', 'L'};
inline constexpr uint8_t kVersion = 1;
inline constexpr size_t kHeaderSize = 6;
inline constexpr size_t kMaxDatagram = 1500;
inline constexpr size_t kWrapOverhead = kHeaderSize + 4 + 2;  // SEND/RECV: 12 bytes

enum class Type : uint8_t {
    Allocate = 0x01,
    Allocated = 0x02,
    Denied = 0x03,
    Keepalive = 0x04,
    KeepaliveAck = 0x05,
    Send = 0x06,
    Recv = 0x07,
    Release = 0x08,
};

enum class DenyReason : uint8_t {
    BadPassword = 1,
    PoolExhausted = 2,
    BadVersion = 3,
    RateLimited = 4,
};

// Builds one outgoing control datagram, header included.
class Writer {
public:
    explicit Writer(Type t) {
        buf_.reserve(64);
        buf_.insert(buf_.end(), kMagic, kMagic + 4);
        buf_.push_back(kVersion);
        buf_.push_back(static_cast<uint8_t>(t));
    }
    Writer& u8(uint8_t v) { buf_.push_back(v); return *this; }
    Writer& u16(uint16_t v) { return u8(uint8_t(v >> 8)).u8(uint8_t(v)); }
    Writer& u32(uint32_t v) { return u16(uint16_t(v >> 16)).u16(uint16_t(v)); }
    Writer& bytes(const uint8_t* p, size_t n) { buf_.insert(buf_.end(), p, p + n); return *this; }
    const uint8_t* data() const { return buf_.data(); }
    size_t size() const { return buf_.size(); }

private:
    std::vector<uint8_t> buf_;
};

// Reads the payload after the header. Any short read sets ok() to false
// and returns zeros, so callers check ok() once after reading all fields.
class Reader {
public:
    Reader(const uint8_t* p, size_t n) : p_(p), n_(n) {}
    uint8_t u8() { return need(1) ? p_[off_++] : 0; }
    uint16_t u16() { uint16_t hi = u8(); return uint16_t(hi << 8 | u8()); }
    uint32_t u32() { uint32_t hi = u16(); return hi << 16 | u16(); }
    const uint8_t* bytes(size_t n) {
        if (!need(n)) return nullptr;
        const uint8_t* r = p_ + off_;
        off_ += n;
        return r;
    }
    const uint8_t* rest() const { return p_ + off_; }
    size_t remaining() const { return n_ - off_; }
    bool ok() const { return ok_; }

private:
    bool need(size_t k) {
        if (ok_ && n_ - off_ >= k) return true;
        ok_ = false;
        return false;
    }
    const uint8_t* p_;
    size_t n_;
    size_t off_ = 0;
    bool ok_ = true;
};

inline bool has_magic(const uint8_t* p, size_t n) {
    return n >= kHeaderSize && std::memcmp(p, kMagic, 4) == 0;
}

}  // namespace acr
