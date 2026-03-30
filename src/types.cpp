#include "types.h"
#include <sstream>
#include <functional>
#include <vector>
#include <algorithm>

// FiveTuple equality
bool FiveTuple::operator==(const FiveTuple& other) const {
    return src_ip   == other.src_ip   &&
           dst_ip   == other.dst_ip   &&
           src_port == other.src_port &&
           dst_port == other.dst_port &&
           protocol == other.protocol;
}

// FiveTuple hash — combines all 5 fields
size_t FiveTupleHash::operator()(const FiveTuple& t) const {
    size_t seed = 0;
    auto combine = [&](size_t val) {
        seed ^= val + 0x9e3779b9 + (seed << 6) + (seed >> 2);
    };
    combine(std::hash<uint32_t>{}(t.src_ip));
    combine(std::hash<uint32_t>{}(t.dst_ip));
    combine(std::hash<uint16_t>{}(t.src_port));
    combine(std::hash<uint16_t>{}(t.dst_port));
    combine(std::hash<uint8_t>{}(static_cast<uint8_t>(t.protocol)));
    return seed;
}

// Convert raw IP integer to dotted string
std::string ipToString(uint32_t ip) {
    std::ostringstream oss;
    oss << ((ip >> 24) & 0xFF) << '.'
        << ((ip >> 16) & 0xFF) << '.'
        << ((ip >>  8) & 0xFF) << '.'
        << ( ip        & 0xFF);
    return oss.str();
}

// Map SNI hostname to application type
AppType sniToAppType(const std::string& sni) {
    if (sni.find("youtube")   != std::string::npos) return AppType::YOUTUBE;
    if (sni.find("facebook")  != std::string::npos) return AppType::FACEBOOK;
    if (sni.find("twitter")   != std::string::npos) return AppType::TWITTER;
    if (sni.find("github")    != std::string::npos) return AppType::GITHUB;
    if (sni.find("netflix")   != std::string::npos) return AppType::NETFLIX;
    if (sni.find("tiktok")    != std::string::npos) return AppType::TIKTOK;
    if (sni.find("google")    != std::string::npos) return AppType::GOOGLE;
    return AppType::UNKNOWN;
}

// Human-readable app name
std::string appTypeToString(AppType app) {
    switch (app) {
        case AppType::UNKNOWN:  return "Unknown";
        case AppType::HTTP:     return "HTTP";
        case AppType::HTTPS:    return "HTTPS";
        case AppType::DNS:      return "DNS";
        case AppType::GOOGLE:   return "Google";
        case AppType::YOUTUBE:  return "YouTube";
        case AppType::FACEBOOK: return "Facebook";
        case AppType::TWITTER:  return "Twitter";
        case AppType::GITHUB:   return "GitHub";
        case AppType::NETFLIX:  return "Netflix";
        case AppType::TIKTOK:   return "TikTok";
        default:                return "Unknown";
    }
}

static std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) {
                       return static_cast<char>(std::tolower(c));
                   });
    return s;
}

static std::vector<std::string> splitByDot(const std::string& s) {
    std::vector<std::string> out;
    std::string current;
    for (char c : s) {
        if (c == '.') {
            if (!current.empty()) {
                out.push_back(current);
                current.clear();
            }
        } else {
            current.push_back(c);
        }
    }
    if (!current.empty()) out.push_back(current);
    return out;
}

static std::string normalizedBaseDomain(const std::string& sni) {
    if (sni.empty()) return sni;

    std::string host = toLower(sni);
    if (!host.empty() && host.back() == '.') {
        host.pop_back();
    }

    auto parts = splitByDot(host);
    if (parts.size() <= 2) {
        return host;
    }

    const std::string& tld = parts.back();
    const std::string& sld = parts[parts.size() - 2];
    const bool cc_tld = (tld.size() == 2);
    const bool common_second_level =
        (sld == "co" || sld == "com" || sld == "org" || sld == "net" ||
         sld == "gov" || sld == "edu" || sld == "ac");

    // Heuristic for domains like example.co.uk
    if (parts.size() >= 3 && cc_tld && common_second_level) {
        return parts[parts.size() - 3] + "." + sld + "." + tld;
    }

    // Default: last two labels
    return sld + "." + tld;
}

std::string sniDisplayLabel(const std::string& sni, AppType app) {
    if (app != AppType::UNKNOWN) {
        return appTypeToString(app);
    }
    return normalizedBaseDomain(sni);
}