#pragma once
#include "types.h"
#include "thread_safe_queue.h"
#include "rule_manager.h"
#include <thread>
#include <atomic>
#include <unordered_map>
#include <string>

// Per-worker statistics
struct WorkerStats {
    std::atomic<uint64_t> packets_processed{0};
    std::atomic<uint64_t> packets_forwarded{0};
    std::atomic<uint64_t> packets_dropped{0};
    std::atomic<uint64_t> snis_found{0};
};

// One Worker thread:
//  - Pops packets from its input queue
//  - Maintains its own flow table (no sharing, no locks needed)
//  - Extracts SNI, classifies app, applies rules
//  - Pushes allowed packets to the shared output queue
class Worker {
public:
    Worker(int                              id,
           ThreadSafeQueue<RawPacket>&      input_queue,
           ThreadSafeQueue<RawPacket>&      output_queue,
           const RuleManager&               rules);

    // Start the worker thread
    void start();

    // Wait for worker thread to finish
    void join();

    // Get this worker's stats
    const WorkerStats& stats() const { return stats_; }
    int id() const { return id_; }

private:
    void run();

    // Process one packet — returns true if forwarded
    bool processPacket(RawPacket& pkt);

    // SNI + HTTP + DNS classification
    void classifyFlow(const ParsedPacket& parsed,
                      RawPacket&          raw,
                      Flow&               flow);

    int                              id_;
    ThreadSafeQueue<RawPacket>&      input_queue_;
    ThreadSafeQueue<RawPacket>&      output_queue_;
    const RuleManager&               rules_;
    WorkerStats                      stats_;
    std::thread                      thread_;

    // Each worker has its own flow table — no mutex needed
    std::unordered_map<FiveTuple, Flow, FiveTupleHash> flows_;
};