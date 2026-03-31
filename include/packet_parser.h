#pragma once

#include "types.h"

class PacketParser {
public:
    // Parse one raw packet into ParsedPacket fields.
    // Returns true when Ethernet+IPv4 were parsed successfully.
    static bool parse(const RawPacket& raw, ParsedPacket& out);
};
