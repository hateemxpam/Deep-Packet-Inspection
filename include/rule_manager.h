#pragma once
#include "types.h"
#include <string>
#include <unordered_set>
#include <vector>
#include <mutex>

class RuleManager {
public:
    // Load rules from file — thread safe, can be called at any time
    bool loadFromFile(const std::string& filename);

    // Add rules programmatically
    void blockIP(const std::string& ip);
    void blockApp(AppType app);
    void blockDomain(const std::string& domain);

    // Check if packet should be blocked — thread safe
    bool isBlocked(uint32_t           src_ip,
                   AppType            app,
                   const std::string& sni) const;

private:
    mutable std::mutex           mutex_;
    std::unordered_set<uint32_t> blocked_ips_;
    std::unordered_set<int>      blocked_apps_;
    std::vector<std::string>     blocked_domains_;
};