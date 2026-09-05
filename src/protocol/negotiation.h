#pragma once
// TCP handshake driver: connect → auth → ClientInit/ServerInit → (SessionSelect) → plaintext
// prelude → enc1103 record layer → encrypted 0x1c media offer/answer. Port of negotiation.py.
#include "common/bytes.h"
#include "crypto/srtp.h"
#include "net/tcp.h"
#include "protocol/offers.h"
#include "protocol/record_layer.h"

#include <array>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace scshr::negotiation {

struct AdvertiseDims { int width = 1920, height = 1080; double hidpi_scale = 2.0; };

struct Keys {
    Bytes audio_key_v, audio_key_s, video_key_v, video_key_s;  // 46-byte blobs
};
Keys random_keys();

// 0x1c MediaStreamConfiguration (matches AVConference _buildOfferMessage byte-for-byte).
Bytes build_0x1c(ByteView audio_offer, ByteView video_offer, const Keys& keys, bool alt_session, bool legacy_cursor = false);

struct Params {
    std::string host;      // IPv4 literal (resolved by caller)
    uint16_t port = 5900;
    std::string username, password;
    bool srp_first = true;
    AdvertiseDims advertise;
    bool hdr = false;
    bool curtain = true;
    bool share_console = false, alt_session = false;
    std::function<std::string(const std::string& console_user)> on_session_choice;  // "share_console"|"alt_session"
    Bytes audio_offer, video_offer;
    bool legacy_cursor = false;
    // Polled during every blocking wait of the handshake; true aborts it with an exception. The
    // handshake can otherwise sit in a single wait for a minute (the Mac's "Allow" popup).
    std::function<bool()> cancelled;
};

struct Result {
    net::TcpSocket sock;
    std::unique_ptr<RecordLayer> cipher;
    Keys keys;
    std::array<uint8_t, 16> wrap_key{};
    uint16_t server_width = 0, server_height = 0;
    uint32_t canvas_width = 0, canvas_height = 0, canvas_tiles = 0;
    std::unique_ptr<SrtpDecryptor> video_decryptor;
    std::vector<Bytes> leftover_msgs;  // decrypted non-answer msgs seen during the answer window
};

Result connect_and_negotiate(const Params& p);
void warmup_tcp(const std::string& host, uint16_t port, double dwell_s = 1.4, const std::function<bool()>& cancelled = {});

}  // namespace scshr::negotiation
