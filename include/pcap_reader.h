#pragma once
#include "types.h"
#include <string>
#include <fstream>
#include <vector>

class PcapReader {
public:
    bool open(const std::string& filename);
    bool readNextPacket(RawPacket& out);
    void close();
    ~PcapReader();

private:
    std::ifstream   file_;
    std::vector<uint8_t> buffer_;
    bool            valid_ = false;
};