// scshr_sender: replay a .scshr recording over real UDP with the recorded timing (or --fps re-pacing) and
// optional emulated WAN impairment (one-way delay, jitter, loss). Pairs with `scshr --replay ...`.
//
//   scshr_sender --in clean.scshr --to 127.0.0.1 --video-port 5901 [--ctrl-port 5900] [--delay-ms 50] [--jitter-ms 5]
//                [--loss P] [--loop N] [--speed 1.0]
// Emulation runs entirely inside this process (a per-packet delay queue), so the results are labelled EMULATED.
#include "common/clock.h"
#include "net/udp.h"
#include "tools/pktfile.h"

#include <algorithm>
#include <cstdio>
#include <queue>
#include <random>
#include <thread>
#include <windows.h>
#include <timeapi.h>

using namespace scshr;

int main(int argc, char** argv) {
    std::string in, to = "127.0.0.1"; uint16_t vport = 5901, cport = 5900; double delay = 0, jitter = 0, loss = 0, speed = 1.0; int loop = 1; unsigned seed = 7;
    for (int i = 1; i < argc; ++i) {
        std::string k = argv[i]; auto v = [&] { return std::string(argv[++i]); };
        if (k == "--in") in = v(); else if (k == "--to") to = v(); else if (k == "--video-port") vport = uint16_t(atoi(v().c_str())); else if (k == "--ctrl-port") cport = uint16_t(atoi(v().c_str()));
        else if (k == "--delay-ms") delay = atof(v().c_str()); else if (k == "--jitter-ms") jitter = atof(v().c_str()); else if (k == "--loss") loss = atof(v().c_str());
        else if (k == "--loop") loop = atoi(v().c_str()); else if (k == "--speed") speed = atof(v().c_str()); else if (k == "--seed") seed = unsigned(atoi(v().c_str()));
        else { std::fprintf(stderr, "unknown arg %s\n", argv[i]); return 2; }
    }
    pkt::Header h; std::vector<pkt::Record> recs;
    if (in.empty() || !pkt::read_file(in, h, recs) || recs.empty()) { std::fprintf(stderr, "usage: scshr_sender --in file.scshr --to IP [--video-port 5901] [--delay-ms D --jitter-ms J --loss P]\n"); return 2; }
    net::UdpSocket sock; sock.bind("", 0);
    timeBeginPeriod(1);
    // Precise pacing: sleep until ~1.5 ms before the deadline, then spin (a 60 fps source must not be jittered by the sender).
    auto wait_until = [](int64_t at) { for (;;) { const int64_t d = at - now_ns(); if (d <= 0) return; if (d > 1'500'000) std::this_thread::sleep_for(std::chrono::nanoseconds(d - 1'500'000)); else std::this_thread::yield(); } };
    std::mt19937 rng(seed); std::normal_distribution<double> jit(0.0, jitter); std::uniform_real_distribution<double> uni(0, 100);
    std::fprintf(stderr, "sending %zu records to %s:%u/%u  delay=%.1fms jitter=%.1fms loss=%.2f%% speed=%.2fx loop=%d  (EMULATED impairment)\n", recs.size(), to.c_str(), vport, cport, delay, jitter, loss, speed, loop);
    uint64_t sent = 0, dropped = 0;
    const int64_t t0 = now_ns();
    int64_t base = recs.front().t_ns, offset = 0;
    struct Due { int64_t at; size_t idx; bool operator>(const Due& o) const { return at != o.at ? at > o.at : idx > o.idx; } };   // stable: equal times keep recording order
    std::priority_queue<Due, std::vector<Due>, std::greater<Due>> q;
    for (int l = 0; l < loop; ++l) {
        for (size_t i = 0; i < recs.size(); ++i) {
            const int64_t rel = int64_t(double(recs[i].t_ns - base) / speed) + offset;
            int64_t at = t0 + rel + int64_t(delay * 1e6);
            if (jitter > 0) at += int64_t(std::max(-delay, jit(rng)) * 1e6);
            if (uni(rng) < loss) { ++dropped; continue; }
            q.push({at, i});
            // Flush everything due before this packet's nominal send time (keeps the queue small and ordered by delivery time).
            while (!q.empty() && q.top().at <= t0 + rel) {
                Due d = q.top(); q.pop();
                wait_until(d.at);
                sock.send_to(view(recs[d.idx].data), to, recs[d.idx].kind == 0 ? vport : cport); ++sent;
            }
        }
        offset += int64_t(double(recs.back().t_ns - base) / speed) + 20'000'000;
    }
    while (!q.empty()) { Due d = q.top(); q.pop(); wait_until(d.at); sock.send_to(view(recs[d.idx].data), to, recs[d.idx].kind == 0 ? vport : cport); ++sent; }
    timeEndPeriod(1);
    std::fprintf(stderr, "done: sent=%llu dropped(emulated loss)=%llu in %.2fs\n", (unsigned long long)sent, (unsigned long long)dropped, double(now_ns() - t0) / 1e9);
    return 0;
}
