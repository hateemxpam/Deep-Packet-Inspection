#include "reporter.h"
#include "types.h"
#include <iostream>
#include <iomanip>
#include <map>
#include <vector>
#include <algorithm>
#include <string>

// Print a horizontal divider line
static void divider() {
    std::cout << "------------------------------------------------------------\n";
}

// Print a bar of # characters proportional to percentage
static std::string makeBar(double pct, int max_width = 20) {
    int filled = static_cast<int>(pct / 100.0 * max_width);
    filled = std::max(0, std::min(filled, max_width));
    return std::string(filled, '#');
}

void Reporter::printReport(const Stats&       stats,
                            const FlowTracker& tracker) const
{
    const auto& flows = tracker.flows();

    // ── Count packets per AppType ─────────────────────────────
    std::map<AppType, uint64_t> app_counts;
    std::map<AppType, bool>     app_blocked;
    std::vector<std::pair<std::string, AppType>> detected_snis;

    for (const auto& [tuple, flow] : flows) {
        app_counts[flow.app] += flow.packet_count;
        if (flow.blocked) {
            app_blocked[flow.app] = true;
        }
        if (!flow.sni.empty()) {
            detected_snis.push_back({ flow.sni, flow.app });
        }
    }

    // Remove duplicate SNIs
    std::sort(detected_snis.begin(), detected_snis.end());
    detected_snis.erase(
        std::unique(detected_snis.begin(), detected_snis.end()),
        detected_snis.end()
    );

    // ── Print Header ──────────────────────────────────────────
    std::cout << "\n";
    std::cout << "================ DPI ENGINE PROCESSING REPORT ================\n";
    divider();

    // ── Traffic Summary ───────────────────────────────────────
    std::cout << "Total Packets  : " << stats.total_packets << "\n";
    std::cout << "Total Bytes    : " << stats.total_bytes << "\n";
    std::cout << "TCP Packets    : " << stats.tcp_packets << "\n";
    std::cout << "UDP Packets    : " << stats.udp_packets << "\n";
    std::cout << "Unique Flows   : " << flows.size() << "\n";
    divider();

    // ── Forwarded / Dropped ───────────────────────────────────
    std::cout << "Forwarded      : " << stats.forwarded << "\n";
    std::cout << "Dropped        : " << stats.dropped << "\n";

    double drop_rate = stats.total_packets > 0
        ? (100.0 * stats.dropped / stats.total_packets)
        : 0.0;
    std::cout << "Drop Rate      : "
              << std::fixed << std::setprecision(1) << drop_rate << "%\n";
    divider();

    // ── Application Breakdown ─────────────────────────────────
    std::cout << "APPLICATION BREAKDOWN\n";
    divider();

    // Sort apps by packet count descending
    std::vector<std::pair<uint64_t, AppType>> sorted_apps;
    for (const auto& [app, count] : app_counts) {
        sorted_apps.push_back({ count, app });
    }
    std::sort(sorted_apps.rbegin(), sorted_apps.rend());

    for (const auto& [count, app] : sorted_apps) {
        double pct = stats.total_packets > 0
            ? (100.0 * count / stats.total_packets)
            : 0.0;

        std::string name    = appTypeToString(app);
        std::string bar     = makeBar(pct);
        bool        blocked = app_blocked.count(app) &&
                              app_blocked.at(app);

        std::cout << "  " << std::left << std::setw(12) << name
                  << std::right << std::setw(6) << count
                  << "  " << std::setw(5) << std::fixed
                  << std::setprecision(1) << pct << "%"
                  << "  " << std::left << std::setw(20) << bar
              << (blocked ? " [BLOCKED]" : "")
              << "\n";
    }

    divider();

    // ── Detected SNIs ─────────────────────────────────────────
    std::cout << "DETECTED DOMAINS / SNIs\n";
    divider();

    if (detected_snis.empty()) {
        std::cout << "(none detected - no HTTPS Client Hello seen)\n";
    } else {
        for (const auto& [sni, app] : detected_snis) {
            std::cout << "  " << std::left << std::setw(40) << sni;
            const std::string app_name = sniDisplayLabel(sni, app);
            std::cout << " -> " << std::setw(12) << app_name;
            std::cout << "\n";
        }
    }

    std::cout << "============================================================\n\n";
}