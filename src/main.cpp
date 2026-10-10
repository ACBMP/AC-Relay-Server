// ac-relay: TURN-style UDP relay for AC Relay (Quazal PRUDP peer-to-peer traffic).
#include "relay.h"

#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>
#include <vector>

namespace {

volatile std::sig_atomic_t g_stop = 0;
void on_signal(int) { g_stop = 1; }

void usage(const char* argv0) {
    std::fprintf(stderr,
        "usage: %s --public-ip <ipv4|host> [options]\n"
        "  --public-ip <ipv4|host>   public address sent to owners (required);\n"
        "                            a hostname is resolved (IPv4) once at startup\n"
        "  --bind <ipv4>             local address to bind (default 0.0.0.0)\n"
        "  --control-port <port>     control port (default 21100)\n"
        "  --port-range <lo-hi>      allocation port pool (default 40200-40999)\n"
        "  --password <str>          require this password in ALLOCATE\n"
        "  --lease <seconds>         allocation lease (default 60)\n"
        "  --max-allocations <n>     total allocation cap (default: pool size)\n"
        "  --max-per-ip <n>          allocations per source IP (default 4)\n"
        "  --alloc-rate <n/s>        new allocations per second per IP (default 2)\n"
        "  --alloc-burst <n>         allocation burst per IP (default 5)\n"
        "  --config <file>           read key=value lines (keys = option names)\n"
        "  --verbose                 log every packet\n",
        argv0);
}

bool parse_uint(const std::string& s, unsigned long max, unsigned long& out) {
    if (s.empty() || s.find_first_not_of("0123456789") != std::string::npos) return false;
    out = std::strtoul(s.c_str(), nullptr, 10);
    return s.size() <= 10 && out <= max;
}

bool parse_double(const std::string& s, double& out) {
    char* end = nullptr;
    out = std::strtod(s.c_str(), &end);
    return !s.empty() && *end == '\0' && out > 0;
}

// Applies one option; returns false (after printing why) on a bad name or value.
bool apply(acr::Config& c, const std::string& key, const std::string& val);

bool load_config(acr::Config& c, const std::string& path) {
    std::ifstream f(path);
    if (!f) {
        std::fprintf(stderr, "cannot read config file %s\n", path.c_str());
        return false;
    }
    std::string line;
    while (std::getline(f, line)) {
        auto trim = [](std::string s) {
            size_t a = s.find_first_not_of(" \t\r"), b = s.find_last_not_of(" \t\r");
            return a == std::string::npos ? std::string() : s.substr(a, b - a + 1);
        };
        line = trim(line);
        if (line.empty() || line[0] == '#' || line[0] == ';') continue;
        size_t eq = line.find('=');
        std::string key = trim(line.substr(0, eq));
        std::string val = eq == std::string::npos ? "true" : trim(line.substr(eq + 1));
        if (!apply(c, key, val)) return false;
    }
    return true;
}

bool apply(acr::Config& c, const std::string& key, const std::string& val) {
    unsigned long n = 0;
    bool ok = true;
    if (key == "bind") {
        uint32_t ip;
        ok = acr::parse_ipv4(val, ip);
        c.bind = val;
    } else if (key == "public-ip") {
        c.public_host = val;  // IPv4 or hostname, resolved at startup
        ok = !val.empty();
    } else if (key == "control-port") {
        ok = parse_uint(val, 65535, n) && n > 0;
        c.control_port = uint16_t(n);
    } else if (key == "port-range") {
        size_t dash = val.find('-');
        unsigned long lo = 0, hi = 0;
        ok = dash != std::string::npos && parse_uint(val.substr(0, dash), 65535, lo) &&
             parse_uint(val.substr(dash + 1), 65535, hi) && lo > 0 && lo <= hi;
        c.port_lo = uint16_t(lo);
        c.port_hi = uint16_t(hi);
    } else if (key == "password") {
        ok = val.size() <= 255;
        c.password = val;
    } else if (key == "lease") {
        ok = parse_uint(val, 65535, n) && n > 0;
        c.lease = uint16_t(n);
    } else if (key == "max-allocations") {
        ok = parse_uint(val, 65535, n);
        c.max_allocations = n;
    } else if (key == "max-per-ip") {
        ok = parse_uint(val, 65535, n) && n > 0;
        c.max_per_ip = n;
    } else if (key == "alloc-rate") {
        ok = parse_double(val, c.alloc_rate);
    } else if (key == "alloc-burst") {
        ok = parse_double(val, c.alloc_burst) && c.alloc_burst >= 1;
    } else if (key == "verbose") {
        c.verbose = val == "1" || val == "true" || val == "yes";
    } else if (key == "config") {
        return load_config(c, val);
    } else {
        std::fprintf(stderr, "unknown option '%s'\n", key.c_str());
        return false;
    }
    if (!ok) std::fprintf(stderr, "bad value for %s: '%s'\n", key.c_str(), val.c_str());
    return ok;
}

}  // namespace

int main(int argc, char** argv) {
    acr::Config cfg;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            usage(argv[0]);
            return 0;
        }
        if (arg.rfind("--", 0) != 0) {
            std::fprintf(stderr, "unexpected argument '%s'\n", arg.c_str());
            usage(argv[0]);
            return 2;
        }
        std::string key = arg.substr(2), val;
        if (size_t eq = key.find('='); eq != std::string::npos) {
            val = key.substr(eq + 1);
            key.resize(eq);
        } else if (key == "verbose") {
            val = "true";
        } else if (i + 1 < argc) {
            val = argv[++i];
        } else {
            std::fprintf(stderr, "missing value for --%s\n", key.c_str());
            usage(argv[0]);
            return 2;
        }
        if (!apply(cfg, key, val)) {
            usage(argv[0]);
            return 2;
        }
    }
    if (cfg.public_host.empty()) {
        std::fprintf(stderr, "--public-ip is required\n");
        usage(argv[0]);
        return 2;
    }
    if (cfg.control_port >= cfg.port_lo && cfg.control_port <= cfg.port_hi) {
        std::fprintf(stderr, "--control-port must be outside --port-range\n");
        return 2;
    }

    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    acr::Relay relay(cfg);
    if (!relay.start()) return 1;
    relay.run(g_stop);
    return 0;
}
