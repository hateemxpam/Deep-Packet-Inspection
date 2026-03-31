#include "rule_manager.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <cctype>

static uint32_t parseIPString(const std::string& ip) {
    uint32_t result = 0;
    int      shift  = 24;
    std::istringstream ss(ip);
    std::string octet;
    while (std::getline(ss, octet, '.') && shift >= 0) {
        try {
            uint32_t val = std::stoul(octet);
            if (val > 255) return 0;
            result |= (val << shift);
            shift -= 8;
        } catch (...) { return 0; }
    }
    return result;
}

static std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
        [](unsigned char c){ return std::tolower(c); });
    return s;
}

static AppType appNameToType(const std::string& name) {
    std::string l = toLower(name);
    if (l == "youtube")  return AppType::YOUTUBE;
    if (l == "facebook") return AppType::FACEBOOK;
    if (l == "twitter")  return AppType::TWITTER;
    if (l == "github")   return AppType::GITHUB;
    if (l == "netflix")  return AppType::NETFLIX;
    if (l == "tiktok")   return AppType::TIKTOK;
    if (l == "google")   return AppType::GOOGLE;
    if (l == "http")     return AppType::HTTP;
    if (l == "https")    return AppType::HTTPS;
    if (l == "dns")      return AppType::DNS;
    return AppType::UNKNOWN;
}

bool RuleManager::loadFromFile(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cout << "[RuleManager] No rules file at: "
                  << filename << " (running with no rules)\n";
        return true;
    }

    // Build new rule sets then swap atomically under lock
    std::unordered_set<uint32_t> new_ips;
    std::unordered_set<int>      new_apps;
    std::vector<std::string>     new_domains;

    std::string line;
    int         count = 0;

    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') continue;

        std::istringstream ss(line);
        std::string        cmd, val;
        ss >> cmd >> val;

        if (cmd == "BLOCK_IP") {
            uint32_t ip = parseIPString(val);
            if (ip != 0) {
                new_ips.insert(ip);
                std::cout << "[RuleManager] Block IP: " << val << "\n";
                ++count;
            }
        } else if (cmd == "BLOCK_APP") {
            AppType app = appNameToType(val);
            if (app != AppType::UNKNOWN) {
                new_apps.insert(static_cast<int>(app));
                std::cout << "[RuleManager] Block App: "
                          << appTypeToString(app) << "\n";
                ++count;
            }
        } else if (cmd == "BLOCK_DOMAIN") {
            new_domains.push_back(toLower(val));
            std::cout << "[RuleManager] Block Domain: " << val << "\n";
            ++count;
        }
    }

    // Swap under lock so workers always see a consistent rule set
    {
        std::lock_guard<std::mutex> lock(mutex_);
        blocked_ips_     = std::move(new_ips);
        blocked_apps_    = std::move(new_apps);
        blocked_domains_ = std::move(new_domains);
    }

    std::cout << "[RuleManager] Loaded " << count << " rules.\n";
    return true;
}

void RuleManager::blockIP(const std::string& ip) {
    uint32_t parsed = parseIPString(ip);
    if (parsed == 0) return;
    std::lock_guard<std::mutex> lock(mutex_);
    blocked_ips_.insert(parsed);
}

void RuleManager::blockApp(AppType app) {
    std::lock_guard<std::mutex> lock(mutex_);
    blocked_apps_.insert(static_cast<int>(app));
}

void RuleManager::blockDomain(const std::string& domain) {
    std::lock_guard<std::mutex> lock(mutex_);
    blocked_domains_.push_back(toLower(domain));
}

bool RuleManager::isBlocked(uint32_t           src_ip,
                              AppType            app,
                              const std::string& sni) const
{
    std::lock_guard<std::mutex> lock(mutex_);

    if (blocked_ips_.count(src_ip)) return true;

    if (app != AppType::UNKNOWN &&
        blocked_apps_.count(static_cast<int>(app))) return true;

    if (!sni.empty()) {
        std::string lower = toLower(sni);
        for (const auto& dom : blocked_domains_) {
            if (lower.find(dom) != std::string::npos) return true;
        }
    }

    return false;
}