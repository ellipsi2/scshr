// scshr_inputprobe — connects a real session and injects synthetic pointer/keyboard events so the
// host side can be observed (log stream on the Mac) without a window. Diagnostic tool only.
//
//   scshr_inputprobe --host 10.77.77.1 -u USER --password-stdin [--share-console] [--seconds N] [--plain-pointer]
#include "common/log.h"
#include "session/session.h"

#include <chrono>
#include <cstdio>
#include <iostream>
#include <string>
#include <thread>

using namespace scshr;

int main(int argc, char** argv) {
    std::string host, user, password;
    bool share_console = false, plain_pointer = false;
    int seconds = 12;
    for (int i = 1; i < argc; ++i) {
        const std::string k = argv[i];
        auto need = [&] { return std::string(argv[++i]); };
        if (k == "--host") host = need(); else if (k == "-u") user = need();
        else if (k == "--password-stdin") std::getline(std::cin, password);
        else if (k == "--share-console") share_console = true; else if (k == "--plain-pointer") plain_pointer = true;
        else if (k == "--seconds") seconds = atoi(need().c_str());
        else { std::fprintf(stderr, "unknown arg %s\n", k.c_str()); return 2; }
    }
    while (!password.empty() && (password.back() == '\r' || password.back() == '\n')) password.pop_back();
    if (host.empty() || user.empty()) { std::fprintf(stderr, "need --host and -u\n"); return 2; }
    log_set_level(LogLevel::Debug);

    SessionConfig sc;
    sc.host = host; sc.username = user; sc.password = password;
    sc.alt_session = !share_console; sc.share_console = share_console;
    sc.audio = false; sc.clipboard = false; sc.prefer_hw = false; sc.decoder_override = "sw";
    sc.codec = VideoCodec::Avc; sc.offer_codec = offers::Codec::Avc; sc.tiles_per_frame = offers::default_tiles_per_frame(offers::Codec::Avc);
    sc.advertise.width = 1280; sc.advertise.height = 800; sc.advertise.hidpi_scale = 1.0;
    Session s(sc);
    try { s.connect(); } catch (const std::exception& e) { std::fprintf(stderr, "connect failed: %s\n", e.what()); return 1; }
    auto [cw, ch] = s.canvas_dims();
    std::printf("connected: canvas %dx%d tiles=%d\n", cw, ch, s.num_tiles());
    std::this_thread::sleep_for(std::chrono::seconds(3));

    const auto t0 = std::chrono::steady_clock::now();
    int step = 0;
    while (std::chrono::steady_clock::now() - t0 < std::chrono::seconds(seconds) && s.is_connected()) {
        const int x = 100 + (step * 37) % std::max(1, cw - 200), y = 100 + (step * 23) % std::max(1, ch - 200);
        s.pointer_event(0, x, y);
        if (step % 20 == 10) { s.pointer_event(1, x, y); std::this_thread::sleep_for(std::chrono::milliseconds(60)); s.pointer_event(0, x, y); std::printf("click at %d,%d\n", x, y); }
        if (step % 20 == 15) { s.key_event(true, 'a'); std::this_thread::sleep_for(std::chrono::milliseconds(40)); s.key_event(false, 'a'); std::printf("key a\n"); }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        ++step;
    }
    std::printf("sent %d pointer moves; connected=%d\n", step, int(s.is_connected()));
    std::printf("%s\n", s.telemetry_line().c_str());
    s.close();
    return 0;
}
