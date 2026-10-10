#pragma once

#include <chrono>
#include <csignal>
#include <cstdint>
#include <deque>
#include <string>
#include <unordered_map>

namespace acr {

#ifdef _WIN32
using sock_t = uintptr_t;  // SOCKET
#else
using sock_t = int;
#endif

struct Config {
    std::string bind = "0.0.0.0";
    uint32_t public_ip = 0;  // host byte order
    uint16_t control_port = 21100;
    uint16_t port_lo = 40200;
    uint16_t port_hi = 40999;
    std::string password;
    uint16_t lease = 60;              // seconds
    size_t max_allocations = 0;       // 0 = pool size
    size_t max_per_ip = 4;            // allocations per source IP
    double alloc_rate = 2.0;          // new allocations per second per source IP
    double alloc_burst = 5.0;         // token bucket size
    bool verbose = false;
};

// Parses dotted-quad IPv4 into host byte order.
bool parse_ipv4(const std::string& s, uint32_t& out);

class Relay {
public:
    explicit Relay(Config cfg);
    ~Relay();
    bool start();
    void run(const volatile std::sig_atomic_t& stop);

private:
    using Clock = std::chrono::steady_clock;

    struct Allocation {
        sock_t sock;
        uint16_t port;
        uint32_t owner_ip;
        uint16_t owner_port;
        Clock::time_point expires;
    };
    struct Bucket {
        double tokens;
        Clock::time_point last;
    };
    struct Stats {
        uint64_t allocs_created = 0, allocs_expired = 0, allocs_released = 0, denied = 0;
        uint64_t pkts_in = 0, bytes_in = 0;    // raw datagrams from peers (RECV)
        uint64_t pkts_out = 0, bytes_out = 0;  // raw datagrams to peers (SEND)
        uint64_t drop_oversize = 0, drop_unknown_owner = 0, drop_malformed = 0;
    };

    void handle_control(const uint8_t* buf, size_t n, uint32_t ip, uint16_t port);
    void handle_allocate(const uint8_t* p, size_t n, uint32_t ip, uint16_t port);
    void handle_peer(Allocation& a, const uint8_t* buf, size_t n, uint32_t ip, uint16_t port);
    void deny(uint32_t nonce, uint8_t reason, uint32_t ip, uint16_t port);
    void send_ack(uint32_t nonce, uint16_t lease, uint32_t ip, uint16_t port);
    bool nack_allowed(uint32_t ip, uint16_t port);
    bool take_token(uint32_t ip);
    void free_allocation(uint64_t key, const char* why);
    void sweep();
    void log_stats();
    void send_ctrl(const uint8_t* p, size_t n, uint32_t ip, uint16_t port);

    Config cfg_;
    uint32_t bind_ip_ = 0;
    sock_t ctrl_;
    std::unordered_map<uint64_t, Allocation> allocs_;  // key = owner ip:port
    std::unordered_map<uint32_t, size_t> per_ip_;
    std::unordered_map<uint32_t, Bucket> buckets_;
    std::unordered_map<uint64_t, Clock::time_point> last_nack_;
    std::deque<uint16_t> free_ports_;
    Stats stats_;
    bool net_init_ = false;
};

}  // namespace acr
