#pragma once
#include <cstdint>
#include <optional>
#include <string>

class SNIExtractor {
public:
    // Returns SNI hostname if found in TLS Client Hello, else nullopt
    static std::optional<std::string> extract(
        const uint8_t* payload,
        uint16_t length
    );
};