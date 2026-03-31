#include "packet_parser.h"
#include <cstring>
#include <iostream>

// ─────────────────────────────────────────────
// Network byte order helpers
// Network protocols store multi-byte values in big-endian order.
// x86 CPUs use little-endian. These functions convert correctly
// without relying on platform-specific ntohl/ntohs.
// ─────────────────────────────────────────────

static uint16_t readU16BE(const uint8_t* p) {
    return static_cast<uint16_t>(
        (static_cast<uint16_t>(p[0]) << 8) |
         static_cast<uint16_t>(p[1])
    );
}

static uint32_t readU32BE(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) <<  8) |
            static_cast<uint32_t>(p[3]);
}

// ─────────────────────────────────────────────
// Ethernet Header (always 14 bytes for standard Ethernet II)
//
// Byte layout:
//  [0-5]   Destination MAC
//  [6-11]  Source MAC
//  [12-13] EtherType
//           0x0800 = IPv4
//           0x0806 = ARP
//           0x86DD = IPv6
// ─────────────────────────────────────────────

static bool parseEthernet(const uint8_t* data,
                           uint32_t       len,
                           ParsedPacket&  out,
                           uint32_t&      offset)
{
    constexpr uint32_t ETH_HEADER_LEN = 14;

    if (len < ETH_HEADER_LEN) {
        return false; // Too short to be Ethernet
    }

    std::memcpy(out.dst_mac, data + 0, 6);
    std::memcpy(out.src_mac, data + 6, 6);
    out.ether_type = readU16BE(data + 12);

    offset = ETH_HEADER_LEN;
    return true;
}

// ─────────────────────────────────────────────
// IPv4 Header (minimum 20 bytes)
//
// Byte layout:
//  [0]     Version (4 bits, upper) + IHL (4 bits, lower)
//          IHL = header length in 32-bit words
//          Actual byte length = IHL * 4
//  [1]     DSCP + ECN (we ignore these)
//  [2-3]   Total length (header + data)
//  [4-5]   Identification
//  [6-7]   Flags + Fragment offset
//  [8]     TTL
//  [9]     Protocol (6=TCP, 17=UDP, 1=ICMP)
//  [10-11] Header checksum (we don't verify)
//  [12-15] Source IP
//  [16-19] Destination IP
//  [20+]   Options (if IHL > 5)
// ─────────────────────────────────────────────

static bool parseIPv4(const uint8_t* data,
                       uint32_t       len,
                       uint32_t       offset,
                       ParsedPacket&  out,
                       uint32_t&      next_offset)
{
    constexpr uint32_t IP_MIN_LEN = 20;

    if (len < offset + IP_MIN_LEN) {
        return false; // Not enough bytes for IP header
    }

    const uint8_t* ip = data + offset;

    // Extract IHL from lower 4 bits of first byte
    uint8_t  ihl        = (ip[0] & 0x0F);
    uint8_t  version    = (ip[0] >> 4);
    uint32_t ip_hdr_len = ihl * 4;

    // Validate IPv4 version and minimum header size
    if (version != 4 || ihl < 5 || len < offset + ip_hdr_len) {
        return false;
    }

    out.ttl      = ip[8];
    out.src_ip   = readU32BE(ip + 12);
    out.dst_ip   = readU32BE(ip + 16);

    // Map protocol byte to our enum
    switch (ip[9]) {
        case 6:  out.protocol = Protocol::TCP; break;
        case 17: out.protocol = Protocol::UDP; break;
        default: out.protocol = Protocol::OTHER; break;
    }

    out.has_ip  = true;
    next_offset = offset + ip_hdr_len;
    return true;
}

// ─────────────────────────────────────────────
// TCP Header (minimum 20 bytes)
//
// Byte layout:
//  [0-1]   Source port
//  [2-3]   Destination port
//  [4-7]   Sequence number
//  [8-11]  Acknowledgment number
//  [12]    Data offset (upper 4 bits) — header length in 32-bit words
//  [13]    Flags: CWR|ECE|URG|ACK|PSH|RST|SYN|FIN
//  [14-15] Window size
//  [16-17] Checksum
//  [18-19] Urgent pointer
//  [20+]   Options (if data offset > 5)
// ─────────────────────────────────────────────

static bool parseTCP(const uint8_t* data,
                      uint32_t       len,
                      uint32_t       offset,
                      ParsedPacket&  out,
                      uint32_t&      next_offset)
{
    constexpr uint32_t TCP_MIN_LEN = 20;

    if (len < offset + TCP_MIN_LEN) {
        return false;
    }

    const uint8_t* tcp = data + offset;

    out.src_port = readU16BE(tcp + 0);
    out.dst_port = readU16BE(tcp + 2);
    out.seq_num  = readU32BE(tcp + 4);
    out.ack_num  = readU32BE(tcp + 8);
    out.tcp_flags = tcp[13];

    // Data offset: upper 4 bits of byte 12, in 32-bit words
    uint8_t  data_offset  = (tcp[12] >> 4);
    uint32_t tcp_hdr_len  = data_offset * 4;

    // Validate — TCP header must be at least 20 bytes
    if (data_offset < 5 || len < offset + tcp_hdr_len) {
        return false;
    }

    // Payload starts after TCP header
    uint32_t payload_start = offset + tcp_hdr_len;
    if (payload_start < len) {
        out.payload     = data + payload_start;
        out.payload_len = static_cast<uint16_t>(len - payload_start);
    } else {
        out.payload     = nullptr;
        out.payload_len = 0;
    }

    out.has_tcp  = true;
    next_offset  = payload_start;
    return true;
}

// ─────────────────────────────────────────────
// UDP Header (always exactly 8 bytes)
//
// Byte layout:
//  [0-1]  Source port
//  [2-3]  Destination port
//  [4-5]  Length (header + data)
//  [6-7]  Checksum
// ─────────────────────────────────────────────

static bool parseUDP(const uint8_t* data,
                      uint32_t       len,
                      uint32_t       offset,
                      ParsedPacket&  out,
                      uint32_t&      next_offset)
{
    constexpr uint32_t UDP_HEADER_LEN = 8;

    if (len < offset + UDP_HEADER_LEN) {
        return false;
    }

    const uint8_t* udp = data + offset;

    out.src_port = readU16BE(udp + 0);
    out.dst_port = readU16BE(udp + 2);

    // Payload starts right after 8-byte UDP header
    uint32_t payload_start = offset + UDP_HEADER_LEN;
    if (payload_start < len) {
        out.payload     = data + payload_start;
        out.payload_len = static_cast<uint16_t>(len - payload_start);
    } else {
        out.payload     = nullptr;
        out.payload_len = 0;
    }

    out.has_udp  = true;
    next_offset  = payload_start;
    return true;
}

// ─────────────────────────────────────────────
// Main parse entry point
// Chains all parsers together
// ─────────────────────────────────────────────

bool PacketParser::parse(const RawPacket& raw, ParsedPacket& out) {
    // Reset output
    out = ParsedPacket{};

    if (raw.data.empty() || raw.incl_len < 14) {
        return false; // Too short for even Ethernet header
    }

    const uint8_t* data = raw.data.data();
    const uint32_t len  = raw.incl_len;
    uint32_t offset     = 0;

    // Layer 2: Ethernet
    if (!parseEthernet(data, len, out, offset)) {
        return false;
    }

    // We only handle IPv4 (EtherType 0x0800)
    if (out.ether_type != 0x0800) {
        return false; // ARP, IPv6, etc — skip
    }

    // Layer 3: IPv4
    uint32_t transport_offset = 0;
    if (!parseIPv4(data, len, offset, out, transport_offset)) {
        return false;
    }

    // Layer 4: TCP or UDP
    uint32_t payload_offset = 0;
    if (out.protocol == Protocol::TCP) {
        parseTCP(data, len, transport_offset, out, payload_offset);
    } else if (out.protocol == Protocol::UDP) {
        parseUDP(data, len, transport_offset, out, payload_offset);
    }

    return out.has_ip; // Success if we at least parsed IP
}