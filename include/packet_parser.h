#pragma once
#include "types.h"

class PacketParser {
public:
    // Returns true if packet was successfully parsed
    static bool parse(const RawPacket& raw, ParsedPacket& out);
};