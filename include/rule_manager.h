#pragma once
#include "types.h"
#include <string>
#include <unordered_set>
#include <vector>

class RuleManager {
public:
    // Load rules from file (one rule per line)
    bool loadFromFile(const std::string& filename);

    // Add rules directly
    void blockIP(const std::string& ip);
    void blockApp(AppType app);
    void blockDomain(const std::string& domain);

    // Returns true if this packet should be dropped
    bool isBlocked(uint32_t src_ip,
                   AppType  app,
                   const std::string& sni) const;

private:
    std::unordered_set<uint32_t>    blocked_ips_;
    std::unordered_set<int>         blocked_apps_;
    std::vector<std::string>        blocked_domains_;
};