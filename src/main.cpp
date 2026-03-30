#include <iostream>
#include <fstream>
#include <iomanip>
#include <cstring>
#include <algorithm>
#include <cctype>
#include "types.h"
#include "pcap_reader.h"
#include "packet_parser.h"
#include "sni_extractor.h"
#include "flow_tracker.h"
#include "rule_manager.h"
#include "reporter.h"

// ─────────────────────────────────────────────
// PCAP output writer
// Writes a valid .pcap file containing only forwarded packets
// ─────────────────────────────────────────────

class PcapWriter {
public:
    bool open(const std::string& filename) {
        file_.open(filename, std::ios::binary);
        if (!file_.is_open()) {
            std::cerr << "[PcapWriter] Cannot open output: "
                      << filename << "\n";
            return false;
        }
        writeGlobalHeader();
        return true;
    }

    void writePacket(const RawPacket& pkt) {
        if (!file_.is_open()) return;
        file_.write(reinterpret_cast<const char*>(&pkt.ts_sec),   4);
        file_.write(reinterpret_cast<const char*>(&pkt.ts_usec),  4);
        file_.write(reinterpret_cast<const char*>(&pkt.incl_len), 4);
        file_.write(reinterpret_cast<const char*>(&pkt.orig_len), 4);
        file_.write(reinterpret_cast<const char*>(pkt.data),
                    pkt.incl_len);
    }

    void close() {
        if (file_.is_open()) file_.close();
    }

    ~PcapWriter() { close(); }

private:
    std::ofstream file_;

    void writeGlobalHeader() {
        uint32_t magic   = 0xa1b2c3d4;
        uint16_t vmaj    = 2;
        uint16_t vmin    = 4;
        int32_t  zone    = 0;
        uint32_t sigfigs = 0;
        uint32_t snaplen = 65535;
        uint32_t network = 1;

        file_.write(reinterpret_cast<char*>(&magic),   4);
        file_.write(reinterpret_cast<char*>(&vmaj),    2);
        file_.write(reinterpret_cast<char*>(&vmin),    2);
        file_.write(reinterpret_cast<char*>(&zone),    4);
        file_.write(reinterpret_cast<char*>(&sigfigs), 4);
        file_.write(reinterpret_cast<char*>(&snaplen), 4);
        file_.write(reinterpret_cast<char*>(&network), 4);
    }
};

// ─────────────────────────────────────────────
// Print usage instructions
// ─────────────────────────────────────────────

static void printUsage(const char* prog) {
    std::cerr << "Usage: " << prog
              << " <input.pcap> [output.pcap] [--rules <rules.txt>]\n\n"
              << "Examples:\n"
              << "  " << prog << " capture.pcap\n"
              << "  " << prog << " capture.pcap filtered.pcap\n"
              << "  " << prog
              << " capture.pcap filtered.pcap --rules rules/rules.txt\n";
}

// ─────────────────────────────────────────────
// Main entry point
// ─────────────────────────────────────────────

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printUsage(argv[0]);
        return 1;
    }

    // ── Parse arguments ───────────────────────────────────────
    std::string input_file  = argv[1];
    std::string output_file = (argc >= 3 && argv[2][0] != '-')
                              ? argv[2] : "";
    std::string rules_file  = "rules/rules.txt";

    for (int i = 2; i < argc; ++i) {
        if (std::string(argv[i]) == "--rules" && i + 1 < argc) {
            rules_file = argv[i + 1];
        }
    }

    // ── Print banner ──────────────────────────────────────────
    std::cout << "============================================================\n";
    std::cout << "DPI ENGINE v1.0\n";
    std::cout << "============================================================\n";
    std::cout << "[Config] Input  : " << input_file  << "\n";
    std::cout << "[Config] Output : "
              << (output_file.empty() ? "(none)" : output_file) << "\n";
    std::cout << "[Config] Rules  : " << rules_file  << "\n\n";

    // ── Load rules ────────────────────────────────────────────
    RuleManager rules;
    rules.loadFromFile(rules_file);

    // ── Open input file ───────────────────────────────────────
    PcapReader reader;
    if (!reader.open(input_file)) {
        return 1;
    }

    // ── Open output file (optional) ───────────────────────────
    PcapWriter writer;
    bool write_output = !output_file.empty();
    if (write_output) {
        if (!writer.open(output_file)) {
            return 1;
        }
    }

    // ── Processing state ──────────────────────────────────────
    FlowTracker  tracker;
    Stats        stats{};
    RawPacket    raw{};
    ParsedPacket parsed{};
    uint64_t     packet_num = 0;

    std::cout << "[Engine] Processing packets...\n\n";

    // ── Main processing loop ──────────────────────────────────
    while (reader.readNextPacket(raw)) {
        ++packet_num;
        ++stats.total_packets;
        stats.total_bytes += raw.incl_len;

        // ── Parse protocol headers ────────────────────────────
        if (!PacketParser::parse(raw, parsed)) {
            // Non-IPv4 or malformed — forward as-is
            if (write_output) writer.writePacket(raw);
            ++stats.forwarded;
            continue;
        }

        // Count by protocol
        if (parsed.has_tcp) ++stats.tcp_packets;
        if (parsed.has_udp) ++stats.udp_packets;

        // ── Build five-tuple ──────────────────────────────────
        FiveTuple tuple{};
        tuple.src_ip   = parsed.src_ip;
        tuple.dst_ip   = parsed.dst_ip;
        tuple.src_port = parsed.src_port;
        tuple.dst_port = parsed.dst_port;
        tuple.protocol = parsed.protocol;

        // ── Get or create flow ────────────────────────────────
        Flow& flow = tracker.getOrCreate(tuple);
        ++flow.packet_count;
        flow.byte_count += raw.incl_len;

        // ── SNI Extraction (TCP port 443 only) ────────────────
        // We buffer early TLS bytes because ClientHello may be
        // split across multiple TCP packets in real captures.
        if (parsed.has_tcp         &&
            parsed.dst_port == 443 &&
            parsed.payload_len > 0 &&
            flow.sni.empty()       &&
            !flow.tls_handshake_done)
        {
            constexpr size_t kMaxTlsHelloBuffer = 8192;

            // We only begin buffering when a TLS Handshake record starts.
            // 0x16 = TLS Handshake, and byte 5 = 0x01 means ClientHello.
            const bool starts_tls_handshake =
                parsed.payload_len >= 6 &&
                parsed.payload[0] == 0x16 &&
                parsed.payload[5] == 0x01;

            if (starts_tls_handshake || !flow.tls_client_hello_buffer.empty()) {
                if (starts_tls_handshake) {
                    std::cout << "[SNI-Debug] Pkt #" << packet_num
                              << " len=" << parsed.payload_len
                              << " first_byte=0x" << std::hex
                              << static_cast<int>(parsed.payload[0])
                              << std::dec << "\n";
                }

                const size_t current_size = flow.tls_client_hello_buffer.size();
                const size_t incoming = parsed.payload_len;
                const size_t remaining =
                    (current_size < kMaxTlsHelloBuffer)
                        ? (kMaxTlsHelloBuffer - current_size)
                        : 0;

                if (remaining > 0) {
                    const size_t to_copy = std::min(incoming, remaining);
                    flow.tls_client_hello_buffer.insert(
                        flow.tls_client_hello_buffer.end(),
                        parsed.payload,
                        parsed.payload + to_copy
                    );
                }

                auto sni = SNIExtractor::extract(
                    flow.tls_client_hello_buffer.data(),
                    static_cast<uint16_t>(flow.tls_client_hello_buffer.size())
                );

                if (sni.has_value()) {
                    // Basic hostname sanity check to avoid noisy false positives.
                    const bool sane = !sni->empty() &&
                                      sni->find('.') != std::string::npos &&
                                      std::all_of(
                                          sni->begin(),
                                          sni->end(),
                                          [](unsigned char c) {
                                              return std::isalnum(c) ||
                                                     c == '.' || c == '-' || c == '_';
                                          }
                                      );

                    if (sane) {
                        flow.sni = *sni;
                        flow.app = sniToAppType(flow.sni);
                        std::cout << "[SNI] Found: " << flow.sni
                              << " -> " << sniDisplayLabel(flow.sni, flow.app)
                                  << "\n";
                    }

                    flow.tls_handshake_done = true;
                    flow.tls_client_hello_buffer.clear();
                } else if (flow.tls_client_hello_buffer.size() >= kMaxTlsHelloBuffer) {
                    // Give up on oversized/irregular handshakes to cap memory.
                    flow.tls_handshake_done = true;
                    flow.tls_client_hello_buffer.clear();
                }
            }
        }

        // ── HTTP Host extraction (port 80) ────────────────────
        if (parsed.has_tcp          &&
            parsed.dst_port == 80   &&
            parsed.payload_len > 10 &&
            flow.sni.empty())
        {
            const char* host_hdr    = "Host: ";
            const char* payload_str = reinterpret_cast<const char*>(
                parsed.payload);
            const char* host_pos = std::search(
                payload_str,
                payload_str + parsed.payload_len,
                host_hdr,
                host_hdr + 6
            );

            if (host_pos != payload_str + parsed.payload_len) {
                const char* start = host_pos + 6;
                const char* end   = start;
                const char* limit = payload_str + parsed.payload_len;
                while (end < limit && *end != '\r' && *end != '\n') {
                    ++end;
                }
                if (end > start) {
                    flow.sni = std::string(start, end);
                    flow.app = AppType::HTTP;
                    std::cout << "[HTTP] Host: " << flow.sni << "\n";
                }
            }
        }

        // ── DNS detection (port 53) ───────────────────────────
        if (parsed.dst_port == 53 || parsed.src_port == 53) {
            flow.app = AppType::DNS;
        }

        // ── Apply blocking rules ──────────────────────────────
        if (!flow.blocked) {
            flow.blocked = rules.isBlocked(
                tuple.src_ip,
                flow.app,
                flow.sni
            );
        }

        // ── Forward or drop ───────────────────────────────────
        if (flow.blocked) {
            ++stats.dropped;
        } else {
            if (write_output) writer.writePacket(raw);
            ++stats.forwarded;
        }
    }

    std::cout << "\n[Engine] Done. Total packets: "
              << packet_num << "\n";

    // ── Print final report ────────────────────────────────────
    Reporter reporter;
    reporter.printReport(stats, tracker);

    return 0;
}