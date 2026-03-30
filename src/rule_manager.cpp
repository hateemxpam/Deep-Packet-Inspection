#include "rule_manager.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>

// ─────────────────────────────────────────────
// Rule file format (rules/rules.txt):
//
//   # Lines starting with # are comments
//   BLOCK_IP     192.168.1.50
//   BLOCK_APP    YouTube
//   BLOCK_DOMAIN tiktok
//   BLOCK_DOMAIN facebook
//
// ─────────────────────────────────────────────

// Convert "x.x.x.x" string to uint32 (network byte order)
static uint32_t parseIPString(const std::string& ip) {
    uint32_t result = 0;
    int shift = 24;
    std::istringstream ss(ip);
    std::string octet;
    while (std::getline(ss, octet, '.') && shift >= 0) {
        try {
            uint32_t val = std::stoul(octet);
            if (val > 255) return 0;
            result |= (val << shift);
            shift -= 8;
        } catch (...) {
            return 0;
        }
    }
    return result;
}

// Case-insensitive string comparison
static std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c){ return std::tolower(c); });
    return s;
}

// Map app name string to AppType enum
static AppType appNameToType(const std::string& name) {
    std::string lower = toLower(name);
    if (lower == "youtube")  return AppType::YOUTUBE;
    if (lower == "facebook") return AppType::FACEBOOK;
    if (lower == "twitter")  return AppType::TWITTER;
    if (lower == "github")   return AppType::GITHUB;
    if (lower == "netflix")  return AppType::NETFLIX;
    if (lower == "tiktok")   return AppType::TIKTOK;
    if (lower == "google")   return AppType::GOOGLE;
    if (lower == "http")     return AppType::HTTP;
    if (lower == "https")    return AppType::HTTPS;
    if (lower == "dns")      return AppType::DNS;
    return AppType::UNKNOWN;
}

bool RuleManager::loadFromFile(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        // Not an error — rules file is optional
        std::cout << "[RuleManager] No rules file found at: "
                  << filename << " (using defaults)\n";
        return true;
    }

    std::string line;
    int rules_loaded = 0;

    while (std::getline(file, line)) {
        // Skip comments and empty lines
        if (line.empty() || line[0] == '#') continue;

        std::istringstream ss(line);
        std::string command, value;
        ss >> command >> value;

        if (command == "BLOCK_IP") {
            blockIP(value);
            ++rules_loaded;
        } else if (command == "BLOCK_APP") {
            AppType app = appNameToType(value);
            if (app != AppType::UNKNOWN) {
                blockApp(app);
                ++rules_loaded;
            } else {
                std::cerr << "[RuleManager] Unknown app: " << value << "\n";
            }
        } else if (command == "BLOCK_DOMAIN") {
            blockDomain(value);
            ++rules_loaded;
        } else {
            std::cerr << "[RuleManager] Unknown rule command: "
                      << command << "\n";
        }
    }

    std::cout << "[RuleManager] Loaded " << rules_loaded
              << " rules from: " << filename << "\n";
    return true;
}

void RuleManager::blockIP(const std::string& ip) {
    uint32_t parsed = parseIPString(ip);
    if (parsed != 0) {
        blocked_ips_.insert(parsed);
        std::cout << "[RuleManager] Blocking IP: " << ip << "\n";
    } else {
        std::cerr << "[RuleManager] Invalid IP address: " << ip << "\n";
    }
}

void RuleManager::blockApp(AppType app) {
    blocked_apps_.insert(static_cast<int>(app));
    std::cout << "[RuleManager] Blocking app: "
              << appTypeToString(app) << "\n";
}

void RuleManager::blockDomain(const std::string& domain) {
    blocked_domains_.push_back(toLower(domain));
    std::cout << "[RuleManager] Blocking domain containing: "
              << domain << "\n";
}

bool RuleManager::isBlocked(uint32_t           src_ip,
                             AppType            app,
                             const std::string& sni) const
{
    // Check 1: Is source IP blocked?
    if (blocked_ips_.count(src_ip)) {
        return true;
    }

    // Check 2: Is app type blocked?
    if (app != AppType::UNKNOWN &&
        blocked_apps_.count(static_cast<int>(app))) {
        return true;
    }

    // Check 3: Does SNI contain a blocked domain substring?
    if (!sni.empty()) {
        std::string lower_sni = toLower(sni);
        for (const auto& dom : blocked_domains_) {
            if (lower_sni.find(dom) != std::string::npos) {
                return true;
            }
        }
    }

    return false;
}
