#include <iostream>
#include <iomanip>
#include <string>
#include <chrono>
#include "types.h"
#include "rule_manager.h"
#include "mt_engine.h"
#include "hot_reload.h"

// ─────────────────────────────────────────────
// Usage
// ─────────────────────────────────────────────

static void printUsage(const char* prog) {
    std::cerr
        << "Usage: " << prog
        << " <input.pcap> [output.pcap]"
        << " [--rules <path>]"
        << " [--workers N]\n\n"
        << "Options:\n"
        << "  --rules    Rules file path (default: rules/rules.txt)\n"
        << "  --workers  Worker thread count (default: 2, max: 16)\n\n"
        << "Examples:\n"
        << "  " << prog << " capture.pcap\n"
        << "  " << prog << " capture.pcap out.pcap\n"
        << "  " << prog
        << " capture.pcap out.pcap --rules rules/rules.txt"
        << " --workers 4\n";
}

// ─────────────────────────────────────────────
// Benchmark display helper
// ─────────────────────────────────────────────

static void printBenchmark(const MTStats& s) {
    std::cout
        << "\n============================================================\n"
        << "  BENCHMARK RESULTS\n"
        << "============================================================\n"
        << std::fixed << std::setprecision(3)
        << "  Processing Time  : " << s.duration_seconds << " seconds\n"
        << std::setprecision(0)
        << "  Throughput       : " << s.throughput_pps
        << " packets/sec\n"
        << std::setprecision(2)
        << "  Throughput       : " << s.throughput_mbps << " Mbps\n"
        << "  Total Packets    : " << s.total_packets   << "\n"
        << "  Total Bytes      : " << s.total_bytes     << "\n"
        << "------------------------------------------------------------\n";
}

// ─────────────────────────────────────────────
// Main report display
// ─────────────────────────────────────────────

static void printReport(const MTStats&                          s,
                         const std::vector<std::unique_ptr<Worker>>& workers)
{
    std::cout
        << "\n============================================================\n"
        << "  PROCESSING REPORT\n"
        << "============================================================\n"
        << "  Total Packets  : " << s.total_packets << "\n"
        << "  Total Bytes    : " << s.total_bytes   << "\n"
        << "  TCP Packets    : " << s.tcp_packets   << "\n"
        << "  UDP Packets    : " << s.udp_packets   << "\n"
        << "------------------------------------------------------------\n"
        << "  Forwarded      : " << s.forwarded     << "\n"
        << "  Dropped        : " << s.dropped       << "\n";

    double drop_rate = s.total_packets > 0
        ? (100.0 * s.dropped / s.total_packets) : 0.0;
    std::cout
        << "  Drop Rate      : "
        << std::fixed << std::setprecision(1) << drop_rate << "%\n"
        << "------------------------------------------------------------\n"
        << "  WORKER THREAD BREAKDOWN\n"
        << "------------------------------------------------------------\n";

    for (const auto& w : workers) {
        const auto& ws = w->stats();
        double worker_drop_rate = ws.packets_processed > 0
            ? (100.0 * ws.packets_dropped / ws.packets_processed)
            : 0.0;

        std::cout
            << "  Worker #" << w->id() << "\n"
            << "    Processed : " << ws.packets_processed << "\n"
            << "    Forwarded : " << ws.packets_forwarded << "\n"
            << "    Dropped   : " << ws.packets_dropped   << "\n"
            << "    SNIs Found: " << ws.snis_found        << "\n"
            << "    Drop Rate : "
            << std::fixed << std::setprecision(1)
            << worker_drop_rate << "%\n";
    }

    std::cout
        << "============================================================\n\n";
}

// ─────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printUsage(argv[0]);
        return 1;
    }

    // ── Parse arguments ───────────────────────────────────────
    std::string input_file  = argv[1];
    std::string output_file = "";
    std::string rules_file  = "rules/rules.txt";
    int         num_workers = 2;

    if (argc >= 3 && argv[2][0] != '-') {
        output_file = argv[2];
    }

    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--rules" && i + 1 < argc) {
            rules_file = argv[++i];
        } else if (arg == "--workers" && i + 1 < argc) {
            num_workers = std::stoi(argv[++i]);
            if (num_workers < 1)  num_workers = 1;
            if (num_workers > 16) num_workers = 16;
        }
    }

    // ── Banner ────────────────────────────────────────────────
    std::cout
        << "============================================================\n"
        << "  DPI ENGINE v2.0 - Multithreaded\n"
        << "============================================================\n"
        << "  Input   : " << input_file  << "\n"
        << "  Output  : "
        << (output_file.empty() ? "(none — monitor only)" : output_file)
        << "\n"
        << "  Rules   : " << rules_file  << "\n"
        << "  Workers : " << num_workers << " thread(s)\n"
        << "============================================================\n\n";

    // ── Load initial rules ────────────────────────────────────
    RuleManager rules;
    rules.loadFromFile(rules_file);

    // ── Hot-reload watcher ────────────────────────────────────
    // Checks rules file every 2 seconds for changes
    HotReloader reloader(
        rules_file,
        2000,
        [&rules, &rules_file]() {
            rules.loadFromFile(rules_file);
        }
    );
    reloader.start();

    // ── Run engine ────────────────────────────────────────────
    MTEngine engine(num_workers, input_file, output_file, rules);

    if (!engine.run()) {
        std::cerr << "[Error] Engine failed to run.\n";
        reloader.stop();
        return 1;
    }

    reloader.stop();

    // ── Display results ───────────────────────────────────────
    MTStats stats = engine.stats();
    printBenchmark(stats);
    printReport(stats, engine.workers());

    return 0;
}