#pragma once
#include "types.h"
#include "rule_manager.h"
#include "thread_safe_queue.h"
#include "worker.h"
#include <string>
#include <vector>
#include <memory>
#include <atomic>
#include <chrono>

// Multithreaded engine stats
struct MTStats {
    uint64_t total_packets   = 0;
    uint64_t total_bytes     = 0;
    uint64_t tcp_packets     = 0;
    uint64_t udp_packets     = 0;
    uint64_t forwarded       = 0;
    uint64_t dropped         = 0;

    // Timing
    double duration_seconds  = 0.0;
    double throughput_pps    = 0.0;  // packets per second
    double throughput_mbps   = 0.0;  // megabits per second
};

// MTEngine orchestrates the full multithreaded pipeline:
//
//   Reader -> [Input Queues] -> Workers -> [Output Queue] -> Writer
//
// Flow affinity: hash(5-tuple) % num_workers
// Guarantees all packets of one connection go to same worker.
// This means each worker's flow table is consistent with no locking.

class MTEngine {
public:
    MTEngine(int                num_workers,
             const std::string& input_file,
             const std::string& output_file,
             const RuleManager& rules);

    // Run the full pipeline — blocks until complete
    bool run();

    // Get aggregated stats after run() completes
    MTStats stats() const { return stats_; }

    // Get per-worker stats for reporting
    const std::vector<std::unique_ptr<Worker>>& workers() const {
        return workers_;
    }

private:
    void writerThread();

    int                              num_workers_;
    std::string                      input_file_;
    std::string                      output_file_;
    const RuleManager&               rules_;
    MTStats                          stats_;

    // One input queue per worker
    std::vector<std::unique_ptr<ThreadSafeQueue<RawPacket>>> input_queues_;

    // Single shared output queue
    ThreadSafeQueue<RawPacket>       output_queue_;

    std::vector<std::unique_ptr<Worker>> workers_;
};