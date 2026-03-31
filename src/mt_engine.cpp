#include "mt_engine.h"
#include "pcap_reader.h"
#include "packet_parser.h"
#include <iostream>
#include <fstream>
#include <thread>
#include <chrono>

// ─────────────────────────────────────────────
// PCAP write helpers
// ─────────────────────────────────────────────

static void writePcapGlobalHeader(std::ofstream& f) {
    uint32_t magic   = 0xa1b2c3d4;
    uint16_t vmaj    = 2;
    uint16_t vmin    = 4;
    int32_t  zone    = 0;
    uint32_t sigfigs = 0;
    uint32_t snaplen = 65535;
    uint32_t network = 1;
    f.write(reinterpret_cast<char*>(&magic),   4);
    f.write(reinterpret_cast<char*>(&vmaj),    2);
    f.write(reinterpret_cast<char*>(&vmin),    2);
    f.write(reinterpret_cast<char*>(&zone),    4);
    f.write(reinterpret_cast<char*>(&sigfigs), 4);
    f.write(reinterpret_cast<char*>(&snaplen), 4);
    f.write(reinterpret_cast<char*>(&network), 4);
}

static void writePcapPacket(std::ofstream& f, const RawPacket& pkt) {
    f.write(reinterpret_cast<const char*>(&pkt.ts_sec),   4);
    f.write(reinterpret_cast<const char*>(&pkt.ts_usec),  4);
    f.write(reinterpret_cast<const char*>(&pkt.incl_len), 4);
    f.write(reinterpret_cast<const char*>(&pkt.orig_len), 4);
    f.write(reinterpret_cast<const char*>(pkt.data.data()),
            pkt.incl_len);
}

// ─────────────────────────────────────────────
// Flow affinity hash
// Bidirectional — both directions of a flow go to same worker
// ─────────────────────────────────────────────

static size_t affinityHash(const ParsedPacket& parsed,
                             int                 num_workers)
{
    uint32_t a = parsed.src_ip   ^ parsed.dst_ip;
    uint32_t b = parsed.src_port ^ parsed.dst_port;
    size_t   h = static_cast<size_t>(a) * 2654435761ULL ^
                 static_cast<size_t>(b) * 40503ULL;
    return h % static_cast<size_t>(num_workers);
}

// ─────────────────────────────────────────────
// Constructor
// ─────────────────────────────────────────────

MTEngine::MTEngine(int                num_workers,
                   const std::string& input_file,
                   const std::string& output_file,
                   const RuleManager& rules)
    : num_workers_(num_workers)
    , input_file_(input_file)
    , output_file_(output_file)
    , rules_(rules)
    , output_queue_(4096)
{
    for (int i = 0; i < num_workers_; ++i) {
        input_queues_.push_back(
            std::make_unique<ThreadSafeQueue<RawPacket>>(512)
        );
    }
    for (int i = 0; i < num_workers_; ++i) {
        workers_.push_back(
            std::make_unique<Worker>(
                i,
                *input_queues_[i],
                output_queue_,
                rules_
            )
        );
    }
}

// ─────────────────────────────────────────────
// Writer thread
// ─────────────────────────────────────────────

void MTEngine::writerThread() {
    std::ofstream out_file;
    bool          has_output = !output_file_.empty();

    if (has_output) {
        out_file.open(output_file_, std::ios::binary);
        if (!out_file.is_open()) {
            std::cerr << "[Writer] Cannot open: " << output_file_ << "\n";
            has_output = false;
        } else {
            writePcapGlobalHeader(out_file);
        }
    }

    while (true) {
        auto item = output_queue_.pop();
        if (!item.has_value()) break;
        ++stats_.forwarded;
        if (has_output) writePcapPacket(out_file, item.value());
    }

    if (out_file.is_open()) out_file.close();
}

// ─────────────────────────────────────────────
// Main run
// ─────────────────────────────────────────────

bool MTEngine::run() {
    // ── Start writer thread ───────────────────────────────────
    std::thread writer(&MTEngine::writerThread, this);

    // ── Start workers ─────────────────────────────────────────
    for (auto& w : workers_) w->start();

    // ── Open input file ───────────────────────────────────────
    PcapReader reader;
    if (!reader.open(input_file_)) {
        for (auto& q : input_queues_) q->shutdown();
        output_queue_.shutdown();
        for (auto& w : workers_) w->join();
        writer.join();
        return false;
    }

    // ── Start timing exactly when we begin processing ─────────
    auto t_start = std::chrono::steady_clock::now();

    RawPacket    raw{};
    ParsedPacket parsed{};

    std::cout << "[Engine] Starting " << num_workers_
              << " worker thread(s)...\n";

    while (reader.readNextPacket(raw)) {
        ++stats_.total_packets;
        stats_.total_bytes += raw.incl_len;

        size_t worker_idx = 0;
        if (PacketParser::parse(raw, parsed)) {
            if (parsed.has_tcp) ++stats_.tcp_packets;
            if (parsed.has_udp) ++stats_.udp_packets;
            worker_idx = affinityHash(parsed, num_workers_);
        }

        input_queues_[worker_idx]->push(raw);
    }

    std::cout << "[Engine] Reader done. Waiting for workers...\n";

    // ── Drain and shut down ───────────────────────────────────
    for (auto& q : input_queues_) q->shutdown();
    for (auto& w : workers_)      w->join();
    output_queue_.shutdown();
    writer.join();

    // ── Stop timing after everything is fully processed ───────
    auto t_end = std::chrono::steady_clock::now();
    stats_.duration_seconds =
        std::chrono::duration<double>(t_end - t_start).count();

    // ── Calculate throughput ──────────────────────────────────
    if (stats_.duration_seconds > 0.0) {
        stats_.throughput_pps =
            static_cast<double>(stats_.total_packets) /
            stats_.duration_seconds;

        // bytes -> bits -> megabits
        stats_.throughput_mbps =
            (static_cast<double>(stats_.total_bytes) * 8.0) /
            (stats_.duration_seconds * 1'000'000.0);
    }

    // ── Aggregate dropped count from workers ──────────────────
    stats_.dropped = 0;
    for (const auto& w : workers_) {
        stats_.dropped += w->stats().packets_dropped;
    }

    return true;
}