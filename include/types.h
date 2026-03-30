#pragma once
#include <cstdint>
#include <string>
#include <vector>

// Supported transport protocols
enum class Protocol : uint8_t {
    TCP = 6,
    UDP = 17,
    OTHER = 0
};

// Identified application types
enum class AppType {
    UNKNOWN,
    HTTP,
    HTTPS,
    DNS,
    GOOGLE,
    YOUTUBE,
    FACEBOOK,
    TWITTER,
    GITHUB,
    NETFLIX,
    TIKTOK
};

// Uniquely identifies one network connection
struct FiveTuple {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    Protocol protocol;

    bool operator==(const FiveTuple& other) const;
};

// Hash function so FiveTuple can be used as unordered_map key
struct FiveTupleHash {
    size_t operator()(const FiveTuple& t) const;
};

// All state we track for one connection
struct Flow {
    FiveTuple   tuple;
    std::string sni;           // Extracted domain name
    AppType     app  = AppType::UNKNOWN;
    bool        blocked = false;
    uint32_t    packet_count = 0;
    uint64_t    byte_count   = 0;

    // Buffers early TLS bytes so SNI can still be extracted when
    // ClientHello is split across multiple TCP packets.
    std::vector<uint8_t> tls_client_hello_buffer;
    bool tls_handshake_done = false;
};

// Raw packet as read from pcap file
struct RawPacket {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
    const uint8_t* data = nullptr;
};

// Parsed fields after protocol unwrapping
struct ParsedPacket {
    // Ethernet
    uint8_t  src_mac[6]  = {};
    uint8_t  dst_mac[6]  = {};
    uint16_t ether_type  = 0;

    // IP
    uint32_t src_ip      = 0;
    uint32_t dst_ip      = 0;
    Protocol protocol    = Protocol::OTHER;
    uint8_t  ttl         = 0;

    // TCP/UDP
    uint16_t src_port    = 0;
    uint16_t dst_port    = 0;

    // TCP specific
    uint32_t seq_num     = 0;
    uint32_t ack_num     = 0;
    uint8_t  tcp_flags   = 0;

    // Payload
    const uint8_t* payload     = nullptr;
    uint16_t       payload_len = 0;

    bool has_ip  = false;
    bool has_tcp = false;
    bool has_udp = false;
};

// Helper: convert uint32 IP to "x.x.x.x" string
std::string ipToString(uint32_t ip);

// Helper: map SNI string to AppType
AppType sniToAppType(const std::string& sni);

// Helper: AppType to readable string
std::string appTypeToString(AppType app);

// Helper: label to print next to SNI.
// Known apps print app name, unknown apps print normalized base domain.
std::string sniDisplayLabel(const std::string& sni, AppType app);