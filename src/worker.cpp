#include "worker.h"
#include "packet_parser.h"
#include "sni_extractor.h"
#include <iostream>
#include <algorithm>
#include <cctype>

Worker::Worker(int                         id,
               ThreadSafeQueue<RawPacket>& input_queue,
               ThreadSafeQueue<RawPacket>& output_queue,
               const RuleManager&          rules)
    : id_(id)
    , input_queue_(input_queue)
    , output_queue_(output_queue)
    , rules_(rules)
{}

void Worker::start() {
    thread_ = std::thread(&Worker::run, this);
}

void Worker::join() {
    if (thread_.joinable()) thread_.join();
}

void Worker::run() {
    while (true) {
        auto item = input_queue_.pop();
        if (!item.has_value()) break; // Queue shut down and empty

        RawPacket pkt = std::move(item.value());
        bool forwarded = processPacket(pkt);

        ++stats_.packets_processed;
        if (forwarded) {
            ++stats_.packets_forwarded;
            output_queue_.push(std::move(pkt));
        } else {
            ++stats_.packets_dropped;
        }
    }
}

void Worker::classifyFlow(const ParsedPacket& parsed,
                           RawPacket&          raw,
                           Flow&               flow)
{
    // ── SNI Extraction (TCP port 443) ─────────────────────────
    if (parsed.has_tcp         &&
        parsed.dst_port == 443 &&
        parsed.payload_len > 0 &&
        flow.sni.empty()       &&
        !flow.tls_handshake_done)
    {
        constexpr size_t kMaxBuffer = 8192;

        const bool starts_hello =
            parsed.payload_len >= 6     &&
            parsed.payload[0] == 0x16   &&
            parsed.payload[5] == 0x01;

        if (starts_hello || !flow.tls_client_hello_buffer.empty()) {
            // Append to buffer up to max
            const size_t space =
                kMaxBuffer - flow.tls_client_hello_buffer.size();
            const size_t to_copy =
                std::min(static_cast<size_t>(parsed.payload_len), space);

            flow.tls_client_hello_buffer.insert(
                flow.tls_client_hello_buffer.end(),
                parsed.payload,
                parsed.payload + to_copy
            );

            auto sni = SNIExtractor::extract(
                flow.tls_client_hello_buffer.data(),
                static_cast<uint16_t>(
                    flow.tls_client_hello_buffer.size())
            );

            if (sni.has_value()) {
                // Sanity check hostname
                const bool sane =
                    !sni->empty() &&
                    sni->find('.') != std::string::npos &&
                    std::all_of(sni->begin(), sni->end(),
                        [](unsigned char c){
                            return std::isalnum(c) ||
                                   c == '.' ||
                                   c == '-' ||
                                   c == '_';
                        });

                if (sane) {
                    flow.sni = *sni;
                    flow.app = sniToAppType(flow.sni);
                    ++stats_.snis_found;
                }
                flow.tls_handshake_done = true;
                flow.tls_client_hello_buffer.clear();
            } else if (flow.tls_client_hello_buffer.size() >= kMaxBuffer) {
                flow.tls_handshake_done = true;
                flow.tls_client_hello_buffer.clear();
            }
        }
    }

    // ── HTTP Host extraction (port 80) ────────────────────────
    if (parsed.has_tcp          &&
        parsed.dst_port == 80   &&
        parsed.payload_len > 10 &&
        flow.sni.empty())
    {
        const char* host_hdr    = "Host: ";
        const char* payload_str =
            reinterpret_cast<const char*>(parsed.payload);
        const char* host_pos = std::search(
            payload_str,
            payload_str + parsed.payload_len,
            host_hdr, host_hdr + 6
        );

        if (host_pos != payload_str + parsed.payload_len) {
            const char* start = host_pos + 6;
            const char* end   = start;
            const char* limit = payload_str + parsed.payload_len;
            while (end < limit && *end != '\r' && *end != '\n') ++end;
            if (end > start) {
                flow.sni = std::string(start, end);
                flow.app = AppType::HTTP;
            }
        }
    }

    // ── DNS detection (port 53) ───────────────────────────────
    if (parsed.dst_port == 53 || parsed.src_port == 53) {
        flow.app = AppType::DNS;
    }
}

bool Worker::processPacket(RawPacket& pkt) {
    ParsedPacket parsed{};

    // Non-IPv4 or malformed — forward as-is
    if (!PacketParser::parse(pkt, parsed)) {
        return true;
    }

    // Build five-tuple
    FiveTuple tuple{};
    tuple.src_ip   = parsed.src_ip;
    tuple.dst_ip   = parsed.dst_ip;
    tuple.src_port = parsed.src_port;
    tuple.dst_port = parsed.dst_port;
    tuple.protocol = parsed.protocol;

    // Get or create flow in this worker's private table
    Flow& flow = flows_[tuple];
    flow.tuple  = tuple;
    ++flow.packet_count;
    flow.byte_count += pkt.incl_len;

    // Classify
    classifyFlow(parsed, pkt, flow);

    // Apply blocking rules
    if (!flow.blocked) {
        flow.blocked = rules_.isBlocked(
            tuple.src_ip,
            flow.app,
            flow.sni
        );
    }

    return !flow.blocked;
}