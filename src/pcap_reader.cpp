#include "pcap_reader.h"
#include <iostream>
#include <cstring>

struct PcapGlobalHeader {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
};

struct PcapPacketHeader {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
};

bool PcapReader::open(const std::string& filename) {
    file_.open(filename, std::ios::binary);
    if (!file_.is_open()) {
        std::cerr << "[PcapReader] Cannot open: " << filename << "\n";
        return false;
    }

    PcapGlobalHeader gh{};
    file_.read(reinterpret_cast<char*>(&gh), sizeof(gh));
    if (!file_) {
        std::cerr << "[PcapReader] File too small.\n";
        return false;
    }

    if (gh.magic_number != 0xa1b2c3d4 &&
        gh.magic_number != 0xa1b23c4d) {
        std::cerr << "[PcapReader] Invalid magic number.\n";
        return false;
    }

    if (gh.network != 1) {
        std::cerr << "[PcapReader] Only Ethernet supported.\n";
        return false;
    }

    valid_ = true;
    std::cout << "[PcapReader] Opened: " << filename << "\n";
    return true;
}

bool PcapReader::readNextPacket(RawPacket& out) {
    if (!valid_) return false;

    PcapPacketHeader ph{};
    file_.read(reinterpret_cast<char*>(&ph), sizeof(ph));
    if (!file_ ||
        file_.gcount() < static_cast<std::streamsize>(sizeof(ph))) {
        return false;
    }

    if (ph.incl_len == 0 || ph.incl_len > 65535) {
        return false;
    }

    // Resize and read directly into the vector
    out.data.resize(ph.incl_len);
    file_.read(reinterpret_cast<char*>(out.data.data()), ph.incl_len);
    if (file_.gcount() < static_cast<std::streamsize>(ph.incl_len)) {
        return false;
    }

    out.ts_sec   = ph.ts_sec;
    out.ts_usec  = ph.ts_usec;
    out.incl_len = ph.incl_len;
    out.orig_len = ph.orig_len;

    return true;
}

void PcapReader::close() {
    if (file_.is_open()) file_.close();
    valid_ = false;
}

PcapReader::~PcapReader() { close(); }