#include "relay.h"

#include "protocol.h"

#include <algorithm>
#include <cstdarg>
#include <cstdio>
#include <ctime>
#include <utility>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
using socklen_t = int;
namespace {
constexpr acr::sock_t kInvalid = INVALID_SOCKET;
int sys_poll(pollfd* f, size_t n, int ms) { return WSAPoll(f, ULONG(n), ms); }
void close_sock(acr::sock_t s) { closesocket(s); }
int last_err() { return WSAGetLastError(); }
bool is_would_block(int e) { return e == WSAEWOULDBLOCK; }
bool is_intr(int e) { return e == WSAEINTR; }
bool set_nonblocking(acr::sock_t s) {
    u_long on = 1;
    if (ioctlsocket(s, FIONBIO, &on) != 0) return false;
    // Don't let ICMP port-unreachable surface as WSAECONNRESET on recvfrom.
    BOOL off = FALSE;
    DWORD ret = 0;
    WSAIoctl(s, SIO_UDP_CONNRESET, &off, sizeof off, nullptr, 0, &ret, nullptr, nullptr);
    return true;
}
}  // namespace
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <cerrno>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
namespace {
constexpr acr::sock_t kInvalid = -1;
int sys_poll(pollfd* f, size_t n, int ms) { return ::poll(f, nfds_t(n), ms); }
void close_sock(acr::sock_t s) { ::close(s); }
int last_err() { return errno; }
bool is_would_block(int e) { return e == EAGAIN || e == EWOULDBLOCK; }
bool is_intr(int e) { return e == EINTR; }
bool set_nonblocking(acr::sock_t s) {
    int fl = fcntl(s, F_GETFL, 0);
    return fl >= 0 && fcntl(s, F_SETFL, fl | O_NONBLOCK) == 0;
}
}  // namespace
#endif

namespace acr {
namespace {

constexpr int kDrainBudget = 64;  // datagrams per socket per poll round
constexpr auto kStatsInterval = std::chrono::seconds(60);
constexpr auto kNackInterval = std::chrono::seconds(1);

uint64_t addr_key(uint32_t ip, uint16_t port) { return uint64_t(ip) << 16 | port; }

std::string fmt_ip(uint32_t ip) {
    char b[16];
    std::snprintf(b, sizeof b, "%u.%u.%u.%u", ip >> 24, (ip >> 16) & 255, (ip >> 8) & 255,
                  ip & 255);
    return b;
}

std::string fmt_addr(uint32_t ip, uint16_t port) { return fmt_ip(ip) + ":" + std::to_string(port); }

void logf(const char* fmt, ...) {
    char ts[32];
    std::time_t now = std::time(nullptr);
    std::strftime(ts, sizeof ts, "%Y-%m-%dT%H:%M:%SZ", std::gmtime(&now));
    std::printf("%s ", ts);
    va_list ap;
    va_start(ap, fmt);
    std::vprintf(fmt, ap);
    va_end(ap);
    std::printf("\n");
    std::fflush(stdout);
}

sockaddr_in make_sa(uint32_t ip, uint16_t port) {
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(ip);
    sa.sin_port = htons(port);
    return sa;
}

sock_t open_udp(uint32_t ip, uint16_t port) {
    sock_t s = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == kInvalid) return kInvalid;
    sockaddr_in sa = make_sa(ip, port);
    if (::bind(s, reinterpret_cast<sockaddr*>(&sa), sizeof sa) != 0 || !set_nonblocking(s)) {
        close_sock(s);
        return kInvalid;
    }
    return s;
}

// Returns bytes read, 0 when the socket is drained, -1 on a transient error.
int recv_from(sock_t s, uint8_t* buf, size_t cap, uint32_t& ip, uint16_t& port) {
    sockaddr_in sa{};
    socklen_t len = sizeof sa;
    auto n = ::recvfrom(s, reinterpret_cast<char*>(buf), int(cap), 0,
                        reinterpret_cast<sockaddr*>(&sa), &len);
    if (n < 0) return is_would_block(last_err()) ? 0 : -1;
    ip = ntohl(sa.sin_addr.s_addr);
    port = ntohs(sa.sin_port);
    return n == 0 ? -2 : int(n);  // -2: valid empty datagram
}

void send_to(sock_t s, const uint8_t* p, size_t n, uint32_t ip, uint16_t port) {
    sockaddr_in sa = make_sa(ip, port);
    ::sendto(s, reinterpret_cast<const char*>(p), int(n), 0, reinterpret_cast<sockaddr*>(&sa),
             sizeof sa);
}

}  // namespace

bool parse_ipv4(const std::string& s, uint32_t& out) {
    in_addr a{};
    if (inet_pton(AF_INET, s.c_str(), &a) != 1) return false;
    out = ntohl(a.s_addr);
    return true;
}

bool resolve_ipv4(const std::string& host, uint32_t& out) {
    if (parse_ipv4(host, out)) return true;
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0 || !res) return false;
    out = ntohl(reinterpret_cast<sockaddr_in*>(res->ai_addr)->sin_addr.s_addr);
    freeaddrinfo(res);
    return true;
}

Relay::Relay(Config cfg) : cfg_(std::move(cfg)), ctrl_(kInvalid) {
    for (uint32_t p = cfg_.port_lo; p <= cfg_.port_hi; ++p) free_ports_.push_back(uint16_t(p));
    if (cfg_.max_allocations == 0 || cfg_.max_allocations > free_ports_.size())
        cfg_.max_allocations = free_ports_.size();
}

Relay::~Relay() {
    for (auto& [k, a] : allocs_) close_sock(a.sock);
    if (ctrl_ != kInvalid) close_sock(ctrl_);
#ifdef _WIN32
    if (net_init_) WSACleanup();
#endif
}

bool Relay::start() {
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return false;
#endif
    net_init_ = true;
    if (!resolve_ipv4(cfg_.public_host, cfg_.public_ip) || cfg_.public_ip == 0) {
        logf("error: cannot resolve public address '%s' to an IPv4", cfg_.public_host.c_str());
        return false;
    }
    if (!parse_ipv4(cfg_.public_host, cfg_.public_ip))
        logf("public address %s resolved to %s (re-resolved only on restart)",
             cfg_.public_host.c_str(), fmt_ip(cfg_.public_ip).c_str());
    if (!parse_ipv4(cfg_.bind, bind_ip_)) {
        logf("error: bad bind address '%s'", cfg_.bind.c_str());
        return false;
    }
    ctrl_ = open_udp(bind_ip_, cfg_.control_port);
    if (ctrl_ == kInvalid) {
        logf("error: cannot bind control socket %s (err %d)",
             fmt_addr(bind_ip_, cfg_.control_port).c_str(), last_err());
        return false;
    }
    logf("ac-relay listening on %s, public ip %s, ports %u-%u, max %zu allocations "
         "(%zu per ip), lease %us, password %s",
         fmt_addr(bind_ip_, cfg_.control_port).c_str(),
         fmt_ip(cfg_.public_ip).c_str(), cfg_.port_lo, cfg_.port_hi, cfg_.max_allocations,
         cfg_.max_per_ip, cfg_.lease, cfg_.password.empty() ? "off" : "on");
    return true;
}

void Relay::send_ctrl(const uint8_t* p, size_t n, uint32_t ip, uint16_t port) {
    send_to(ctrl_, p, n, ip, port);
}

void Relay::deny(uint32_t nonce, uint8_t reason, uint32_t ip, uint16_t port) {
    ++stats_.denied;
    Writer w(Type::Denied);
    w.u32(nonce).u8(reason);
    send_ctrl(w.data(), w.size(), ip, port);
    logf("denied %s reason %u", fmt_addr(ip, port).c_str(), reason);
}

void Relay::send_ack(uint32_t nonce, uint16_t lease, uint32_t ip, uint16_t port) {
    Writer w(Type::KeepaliveAck);
    w.u32(nonce).u16(lease);
    send_ctrl(w.data(), w.size(), ip, port);
}

// Replies to unknown or bad senders are capped at one per second per address.
bool Relay::nack_allowed(uint32_t ip, uint16_t port) {
    auto now = Clock::now();
    auto [it, fresh] = last_nack_.try_emplace(addr_key(ip, port), now);
    if (fresh) return true;
    if (now - it->second < kNackInterval) return false;
    it->second = now;
    return true;
}

bool Relay::take_token(uint32_t ip) {
    auto now = Clock::now();
    auto [it, fresh] = buckets_.try_emplace(ip, Bucket{cfg_.alloc_burst, now});
    Bucket& b = it->second;
    double dt = std::chrono::duration<double>(now - b.last).count();
    b.tokens = std::min(cfg_.alloc_burst, b.tokens + dt * cfg_.alloc_rate);
    b.last = now;
    if (b.tokens < 1.0) return false;
    b.tokens -= 1.0;
    return true;
}

void Relay::handle_control(const uint8_t* buf, size_t n, uint32_t ip, uint16_t port) {
    if (!has_magic(buf, n)) {
        ++stats_.drop_malformed;
        return;
    }
    const uint8_t version = buf[4];
    const uint8_t type = buf[5];
    const uint8_t* p = buf + kHeaderSize;
    const size_t len = n - kHeaderSize;

    if (version != kVersion) {
        // Echo the nonce if the datagram is long enough to carry one.
        uint32_t nonce = len >= 4 ? Reader(p, len).u32() : 0;
        if (nack_allowed(ip, port)) deny(nonce, uint8_t(DenyReason::BadVersion), ip, port);
        return;
    }

    const uint64_t key = addr_key(ip, port);
    auto it = allocs_.find(key);
    const auto lease_end = Clock::now() + std::chrono::seconds(cfg_.lease);

    switch (Type(type)) {
    case Type::Allocate:
        handle_allocate(p, len, ip, port);
        return;

    case Type::Keepalive: {
        Reader r(p, len);
        uint32_t nonce = r.u32();
        if (!r.ok()) break;
        if (it != allocs_.end()) {
            it->second.expires = lease_end;
            send_ack(nonce, cfg_.lease, ip, port);
        } else if (nack_allowed(ip, port)) {
            send_ack(nonce, 0, ip, port);
        }
        if (cfg_.verbose) logf("keepalive from %s", fmt_addr(ip, port).c_str());
        return;
    }

    case Type::Send: {
        Reader r(p, len);
        uint32_t peer_ip = r.u32();
        uint16_t peer_port = r.u16();
        if (!r.ok() || peer_ip == 0 || peer_port == 0) break;
        if (it == allocs_.end()) {
            ++stats_.drop_unknown_owner;
            if (nack_allowed(ip, port)) send_ack(0, 0, ip, port);
            return;
        }
        it->second.expires = lease_end;
        send_to(it->second.sock, r.rest(), r.remaining(), peer_ip, peer_port);
        ++stats_.pkts_out;
        stats_.bytes_out += r.remaining();
        if (cfg_.verbose)
            logf("SEND %s -> %s via :%u, %zu bytes", fmt_addr(ip, port).c_str(),
                 fmt_addr(peer_ip, peer_port).c_str(), it->second.port, r.remaining());
        return;
    }

    case Type::Release:
        if (it != allocs_.end()) {
            free_allocation(key, "released");
            ++stats_.allocs_released;
        }
        return;

    default:  // unknown type, or a relay->owner type sent to us
        break;
    }
    ++stats_.drop_malformed;
}

void Relay::handle_allocate(const uint8_t* p, size_t n, uint32_t ip, uint16_t port) {
    Reader r(p, n);
    uint32_t nonce = r.u32();
    uint8_t pwlen = r.u8();
    const uint8_t* pw = r.bytes(pwlen);
    if (!r.ok()) {
        ++stats_.drop_malformed;
        return;
    }

    const uint64_t key = addr_key(ip, port);
    auto it = allocs_.find(key);
    const bool fresh = it == allocs_.end();

    // New allocations (including password guesses) cost a token; refreshes are free.
    if (fresh && !take_token(ip)) {
        if (nack_allowed(ip, port)) deny(nonce, uint8_t(DenyReason::RateLimited), ip, port);
        return;
    }
    // With no relay password configured, any password is accepted.
    if (!cfg_.password.empty() &&
        std::string(reinterpret_cast<const char*>(pw), pwlen) != cfg_.password) {
        deny(nonce, uint8_t(DenyReason::BadPassword), ip, port);
        return;
    }

    if (fresh) {
        if (per_ip_[ip] >= cfg_.max_per_ip) {
            deny(nonce, uint8_t(DenyReason::RateLimited), ip, port);
            return;
        }
        sock_t s = kInvalid;
        uint16_t aport = 0;
        while (allocs_.size() < cfg_.max_allocations && !free_ports_.empty()) {
            aport = free_ports_.front();
            free_ports_.pop_front();
            s = open_udp(bind_ip_, aport);
            if (s != kInvalid) break;
            logf("warning: cannot bind port %u (err %d), removed from pool", aport,
                 last_err());
        }
        if (s == kInvalid) {
            deny(nonce, uint8_t(DenyReason::PoolExhausted), ip, port);
            return;
        }
        it = allocs_.emplace(key, Allocation{s, aport, ip, port, {}}).first;
        ++per_ip_[ip];
        ++stats_.allocs_created;
    }

    Allocation& a = it->second;
    a.expires = Clock::now() + std::chrono::seconds(cfg_.lease);
    Writer w(Type::Allocated);
    w.u32(nonce).u32(cfg_.public_ip).u16(a.port).u32(ip).u16(port).u16(cfg_.lease);
    send_ctrl(w.data(), w.size(), ip, port);
    logf("allocation %s: owner %s port %u (%zu active)", fresh ? "created" : "refreshed",
         fmt_addr(ip, port).c_str(), a.port, allocs_.size());
}

void Relay::handle_peer(Allocation& a, const uint8_t* buf, size_t n, uint32_t ip,
                        uint16_t port) {
    if (n + kWrapOverhead > kMaxDatagram) {
        ++stats_.drop_oversize;
        if (cfg_.verbose)
            logf("drop oversize %zu bytes from %s on :%u", n, fmt_addr(ip, port).c_str(), a.port);
        return;
    }
    Writer w(Type::Recv);
    w.u32(ip).u16(port).bytes(buf, n);
    send_ctrl(w.data(), w.size(), a.owner_ip, a.owner_port);
    ++stats_.pkts_in;
    stats_.bytes_in += n;
    if (cfg_.verbose)
        logf("RECV %s -> owner %s via :%u, %zu bytes", fmt_addr(ip, port).c_str(),
             fmt_addr(a.owner_ip, a.owner_port).c_str(), a.port, n);
}

void Relay::free_allocation(uint64_t key, const char* why) {
    auto it = allocs_.find(key);
    if (it == allocs_.end()) return;
    Allocation& a = it->second;
    close_sock(a.sock);
    free_ports_.push_back(a.port);
    if (--per_ip_[a.owner_ip] == 0) per_ip_.erase(a.owner_ip);
    logf("allocation %s: owner %s port %u (%zu active)", why,
         fmt_addr(a.owner_ip, a.owner_port).c_str(), a.port, allocs_.size() - 1);
    allocs_.erase(it);
}

void Relay::sweep() {
    auto now = Clock::now();
    std::vector<uint64_t> expired;
    for (auto& [k, a] : allocs_)
        if (a.expires <= now) expired.push_back(k);
    for (uint64_t k : expired) {
        free_allocation(k, "expired");
        ++stats_.allocs_expired;
    }
    std::erase_if(last_nack_, [&](auto& kv) { return now - kv.second > kNackInterval; });
    std::erase_if(buckets_, [&](auto& kv) {
        double dt = std::chrono::duration<double>(now - kv.second.last).count();
        return kv.second.tokens + dt * cfg_.alloc_rate >= cfg_.alloc_burst;
    });
}

void Relay::log_stats() {
    const Stats& s = stats_;
    logf("stats: allocations %zu/%zu (created %llu, released %llu, expired %llu, denied %llu) "
         "in %llu pkts/%llu B, out %llu pkts/%llu B, drops oversize %llu unknown-owner %llu "
         "malformed %llu",
         allocs_.size(), cfg_.max_allocations, (unsigned long long)s.allocs_created,
         (unsigned long long)s.allocs_released, (unsigned long long)s.allocs_expired,
         (unsigned long long)s.denied, (unsigned long long)s.pkts_in,
         (unsigned long long)s.bytes_in, (unsigned long long)s.pkts_out,
         (unsigned long long)s.bytes_out, (unsigned long long)s.drop_oversize,
         (unsigned long long)s.drop_unknown_owner, (unsigned long long)s.drop_malformed);
}

void Relay::run(const volatile std::sig_atomic_t& stop) {
    std::vector<pollfd> fds;
    std::vector<uint64_t> owners;  // owners[i] belongs to fds[i + 1]
    std::vector<uint8_t> buf(65536);
    auto next_stats = Clock::now() + kStatsInterval;
    auto next_sweep = Clock::now();

    while (!stop) {
        fds.clear();
        owners.clear();
        fds.push_back({ctrl_, POLLIN, 0});
        for (auto& [k, a] : allocs_) {
            fds.push_back({a.sock, POLLIN, 0});
            owners.push_back(k);
        }

        if (sys_poll(fds.data(), fds.size(), 250) < 0) {
            if (is_intr(last_err())) continue;
            logf("error: poll failed (err %d)", last_err());
            break;
        }

        uint32_t ip;
        uint16_t port;
        if (fds[0].revents & (POLLIN | POLLERR)) {
            for (int i = 0; i < kDrainBudget; ++i) {
                int n = recv_from(ctrl_, buf.data(), buf.size(), ip, port);
                if (n == 0) break;
                if (n > 0) handle_control(buf.data(), size_t(n), ip, port);
            }
        }
        for (size_t i = 1; i < fds.size(); ++i) {
            if (!(fds[i].revents & (POLLIN | POLLERR))) continue;
            // The control pass above may have released or replaced this allocation.
            auto it = allocs_.find(owners[i - 1]);
            if (it == allocs_.end() || it->second.sock != fds[i].fd) continue;
            for (int k = 0; k < kDrainBudget; ++k) {
                int n = recv_from(it->second.sock, buf.data(), buf.size(), ip, port);
                if (n == 0) break;
                if (n == -2) handle_peer(it->second, buf.data(), 0, ip, port);
                else if (n > 0) handle_peer(it->second, buf.data(), size_t(n), ip, port);
            }
        }

        auto now = Clock::now();
        if (now >= next_sweep) {
            sweep();
            next_sweep = now + std::chrono::milliseconds(250);
        }
        if (now >= next_stats) {
            log_stats();
            next_stats = now + kStatsInterval;
        }
    }
    logf("shutting down");
    log_stats();
}

}  // namespace acr
