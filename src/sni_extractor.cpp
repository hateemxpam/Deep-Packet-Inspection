#include "sni_extractor.h"
#include <iostream>

// ─────────────────────────────────────────────
// TLS Record and Handshake constants
// ─────────────────────────────────────────────

static constexpr uint8_t  TLS_CONTENT_HANDSHAKE   = 0x16;
static constexpr uint8_t  TLS_HANDSHAKE_CLIENT_HELLO = 0x01;
static constexpr uint16_t TLS_EXTENSION_SNI        = 0x0000;
static constexpr uint8_t  SNI_TYPE_HOST_NAME       = 0x00;

// ─────────────────────────────────────────────
// Safe big-endian readers with bounds checking
// These return false if reading would go out of bounds
// ─────────────────────────────────────────────

static bool readU8(const uint8_t* data, uint16_t len,
                   uint16_t offset, uint8_t& out)
{
    if (offset >= len) return false;
    out = data[offset];
    return true;
}

static bool readU16BE(const uint8_t* data, uint16_t len,
                      uint16_t offset, uint16_t& out)
{
    if (offset + 1 >= len) return false;
    out = static_cast<uint16_t>(
        (static_cast<uint16_t>(data[offset])     << 8) |
         static_cast<uint16_t>(data[offset + 1])
    );
    return true;
}

// ─────────────────────────────────────────────
// TLS Client Hello memory layout
//
// [0]      Content Type     (1 byte)  must be 0x16
// [1-2]    TLS Version      (2 bytes) 0x0301 or 0x0303
// [3-4]    Record Length    (2 bytes)
// --- Handshake Layer (starts at byte 5) ---
// [5]      Handshake Type   (1 byte)  must be 0x01 (ClientHello)
// [6-8]    Handshake Length (3 bytes) big-endian
// --- ClientHello Body (starts at byte 9) ---
// [9-10]   Client Version   (2 bytes)
// [11-42]  Random           (32 bytes)
// [43]     Session ID Len   (1 byte)
// [44+N]   Session ID       (N bytes)
// [44+N to 44+N+2]  Cipher Suites Length (2 bytes)
// [...]    Cipher Suites
// [...]    Compression Methods Length (1 byte)
// [...]    Compression Methods
// [...]    Extensions Length (2 bytes)
// [...]    Extensions (repeated):
//            Extension Type   (2 bytes)
//            Extension Length (2 bytes)
//            Extension Data
// ─────────────────────────────────────────────

std::optional<std::string> SNIExtractor::extract(
    const uint8_t* payload,
    uint16_t       length)
{
    // Minimum meaningful TLS Client Hello is ~50 bytes
    if (payload == nullptr || length < 50) {
        return std::nullopt;
    }

    // ── Step 1: Verify TLS Record Header ──────────────────────
    // Byte 0 must be 0x16 (Handshake content type)
    if (payload[0] != TLS_CONTENT_HANDSHAKE) {
        return std::nullopt;
    }

    // Bytes 1-2: TLS version. Must be 0x0301 (TLS 1.0) or higher
    // We accept 0x0301, 0x0302, 0x0303 (TLS 1.0/1.1/1.2/1.3)
    if (payload[1] != 0x03) {
        return std::nullopt;
    }

    // ── Step 2: Verify Handshake Type ─────────────────────────
    // Byte 5 is the handshake message type
    // 0x01 = ClientHello (the only one that contains SNI)
    if (payload[5] != TLS_HANDSHAKE_CLIENT_HELLO) {
        return std::nullopt;
    }

    // ── Step 3: Navigate to ClientHello Body ──────────────────
    // Skip: content type(1) + version(2) + record len(2)
    //      + handshake type(1) + handshake len(3)
    // = 9 bytes total to reach ClientHello version field
    uint16_t offset = 9;

    // Skip ClientHello version (2 bytes)
    offset += 2;

    // Skip Random (always exactly 32 bytes)
    offset += 32;

    // ── Step 4: Skip Session ID ───────────────────────────────
    uint8_t session_id_len = 0;
    if (!readU8(payload, length, offset, session_id_len)) {
        return std::nullopt;
    }
    offset += 1 + session_id_len;

    // ── Step 5: Skip Cipher Suites ────────────────────────────
    uint16_t cipher_suites_len = 0;
    if (!readU16BE(payload, length, offset, cipher_suites_len)) {
        return std::nullopt;
    }
    offset += 2 + cipher_suites_len;

    // ── Step 6: Skip Compression Methods ─────────────────────
    uint8_t comp_methods_len = 0;
    if (!readU8(payload, length, offset, comp_methods_len)) {
        return std::nullopt;
    }
    offset += 1 + comp_methods_len;

    // ── Step 7: Read Extensions ───────────────────────────────
    uint16_t extensions_total_len = 0;
    if (!readU16BE(payload, length, offset, extensions_total_len)) {
        return std::nullopt;
    }
    offset += 2;

    // Bounds check — extensions must fit within payload
    if (offset + extensions_total_len > length) {
        return std::nullopt;
    }

    uint16_t ext_end = offset + extensions_total_len;

    // ── Step 8: Iterate Extensions to Find SNI ────────────────
    while (offset + 4 <= ext_end) {
        uint16_t ext_type = 0;
        uint16_t ext_len  = 0;

        if (!readU16BE(payload, length, offset,     ext_type)) break;
        if (!readU16BE(payload, length, offset + 2, ext_len))  break;
        offset += 4;

        if (ext_type == TLS_EXTENSION_SNI) {
            // ── Found SNI Extension ───────────────────────────
            // SNI extension layout:
            //   [0-1]  Server Name List Length  (2 bytes)
            //   [2]    Server Name Type         (1 byte, 0x00 = hostname)
            //   [3-4]  Server Name Length       (2 bytes)
            //   [5+]   Server Name              (ASCII string)

            if (offset + 5 > length) return std::nullopt;

            // Skip server name list length (2 bytes)
            // Skip server name type (1 byte) — should be 0x00
            uint8_t name_type = 0;
            if (!readU8(payload, length, offset + 2, name_type)) {
                return std::nullopt;
            }
            if (name_type != SNI_TYPE_HOST_NAME) {
                return std::nullopt;
            }

            // Read server name length
            uint16_t name_len = 0;
            if (!readU16BE(payload, length, offset + 3, name_len)) {
                return std::nullopt;
            }

            // Validate name fits in buffer
            if (offset + 5 + name_len > length) {
                return std::nullopt;
            }

            // name_len of 0 is invalid
            if (name_len == 0) {
                return std::nullopt;
            }

            // Extract hostname string
            std::string sni(
                reinterpret_cast<const char*>(payload + offset + 5),
                name_len
            );

            return sni;
        }

        // Not SNI — skip this extension's data
        offset += ext_len;
    }

    // No SNI extension found in this Client Hello
    return std::nullopt;
}