#pragma once
#include "types.h"
#include "flow_tracker.h"
#include <cstdint>

struct Stats {
    uint64_t total_packets   = 0;
    uint64_t total_bytes     = 0;
    uint64_t tcp_packets     = 0;
    uint64_t udp_packets     = 0;
    uint64_t forwarded       = 0;
    uint64_t dropped         = 0;
};

class Reporter {
public:
    void printReport(const Stats& stats, const FlowTracker& tracker) const;
};