#include "pcap_reader.h"
#include <iostream>
#include <cstring>

// PCAP file global header structure (24 bytes at start of every .pcap file)
struct PcapGlobalHeader {
    uint32_t magic_number;   // 0xa1b2c3d4 for standard pcap
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;       // GMT offset (usually 0)
    uint32_t sigfigs;        // Accuracy of timestamps (usually 0)
    uint32_t snaplen;        // Max length of captured packets
    uint32_t network;        // Data link type (1 = Ethernet)
};

// Per-packet header (16 bytes before every packet)
struct PcapPacketHeader {
    uint32_t ts_sec;         // Timestamp seconds
    uint32_t ts_usec;        // Timestamp microseconds
    uint32_t incl_len;       // Bytes actually saved in file
    uint32_t orig_len;       // Original packet length on wire
};

bool PcapReader::open(const std::string& filename) {
    // Open in binary mode — critical for pcap files
    file_.open(filename, std::ios::binary);
    if (!file_.is_open()) {
        std::cerr << "[PcapReader] Error: Cannot open file: " << filename << "\n";
        return false;
    }

    // Read and validate global header
    PcapGlobalHeader gh{};
    file_.read(reinterpret_cast<char*>(&gh), sizeof(gh));
    if (!file_) {
        std::cerr << "[PcapReader] Error: File too small to be a valid PCAP.\n";
        return false;
    }

    // Validate magic number — identifies this as a pcap file
    // 0xa1b2c3d4 = standard pcap (microsecond timestamps)
    // 0xa1b23c4d = pcap with nanosecond timestamps (also acceptable)
    if (gh.magic_number != 0xa1b2c3d4 && gh.magic_number != 0xa1b23c4d) {
        std::cerr << "[PcapReader] Error: Not a valid PCAP file. "
                  << "Magic number: 0x" << std::hex << gh.magic_number << "\n";
        return false;
    }

    // We only support Ethernet (link type 1)
    if (gh.network != 1) {
        std::cerr << "[PcapReader] Error: Unsupported link type: "
                  << gh.network << " (only Ethernet/1 supported)\n";
        return false;
    }

    valid_ = true;
    std::cout << "[PcapReader] Opened: " << filename
              << " (snaplen=" << std::dec << gh.snaplen << ")\n";
    return true;
}

bool PcapReader::readNextPacket(RawPacket& out) {
    if (!valid_) return false;

    // Read per-packet header
    PcapPacketHeader ph{};
    file_.read(reinterpret_cast<char*>(&ph), sizeof(ph));

    // If we couldn't read a full header, we've reached end of file
    if (!file_ || file_.gcount() < static_cast<std::streamsize>(sizeof(ph))) {
        return false;
    }

    // Safety check — incl_len should never exceed 65535 bytes
    if (ph.incl_len == 0 || ph.incl_len > 65535) {
        std::cerr << "[PcapReader] Warning: Suspicious packet length: "
                  << ph.incl_len << ", skipping.\n";
        return false;
    }

    // Resize buffer and read packet bytes
    buffer_.resize(ph.incl_len);
    file_.read(reinterpret_cast<char*>(buffer_.data()), ph.incl_len);

    if (file_.gcount() < static_cast<std::streamsize>(ph.incl_len)) {
        std::cerr << "[PcapReader] Warning: Truncated packet, skipping.\n";
        return false;
    }

    // Fill output struct
    out.ts_sec   = ph.ts_sec;
    out.ts_usec  = ph.ts_usec;
    out.incl_len = ph.incl_len;
    out.orig_len = ph.orig_len;
    out.data     = buffer_.data();

    return true;
}

void PcapReader::close() {
    if (file_.is_open()) {
        file_.close();
    }
    valid_ = false;
}

PcapReader::~PcapReader() {
    close();
}