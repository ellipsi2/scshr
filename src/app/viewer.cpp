// The viewer: window + renderer + session + input + audio.
//
//   Winsock IOCP → SRTP → RTP/NAL → FFmpeg D3D11VA → decoder texture slice → D3D11 pixel shader → DXGI flip-model Present
//
// Render loop (calling thread): wait for the swapchain's frame-latency waitable object, THEN take the newest
// decoded frame of every tile (older ones were already replaced in the decoder) and present. No frame queue.
//
// Nothing here shows a dialog: failures come back in ViewerResult so the CLI can print them and the GUI
// launcher can phrase them its own way.
#include "app/viewer.h"

#include "app/app.h"
#include "app/audio.h"
#include "app/tunnel_cli.h"
#include "common/clock.h"
#include "common/log.h"
#include "gfx/d3d11_renderer.h"
#include "session/session.h"

#include <psapi.h>
#include <timeapi.h>

#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstdio>
#include <iostream>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace scshr::app {
namespace {

std::wstring widen(const std::string& s) {
    if (s.empty()) return {};
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), int(s.size()), nullptr, 0);
    std::wstring w(size_t(n > 0 ? n : 0), L'\0');
    if (n > 0) MultiByteToWideChar(CP_UTF8, 0, s.c_str(), int(s.size()), w.data(), n);
    return w;
}

std::string read_password(const ViewerOptions& o) {
    if (!o.password_stdin) {
        std::fprintf(stderr, "password: ");
        HANDLE h = GetStdHandle(STD_INPUT_HANDLE); DWORD mode = 0; GetConsoleMode(h, &mode); SetConsoleMode(h, mode & ~ENABLE_ECHO_INPUT);
        std::string p; std::getline(std::cin, p);
        SetConsoleMode(h, mode); std::fprintf(stderr, "\n");
        return p;
    }
    std::string line; std::getline(std::cin, line);
    while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
    return line;
}

int even(int n) { return n - (n & 1); }
constexpr int MIN_ADV_W = 640, MIN_ADV_H = 480, HOST_MAX_BACKING_W = 3840, HOST_MAX_BACKING_H = 2160;

// (hidpi mode, window logical size, client display scale) → request (w, h, scale); mirrors app.py _resolve_hidpi_request.
void resolve_hidpi(const std::string& mode, int win_w, int win_h, float client_scale, int& rw, int& rh, double& scale) {
    win_w = std::max(1, win_w); win_h = std::max(1, win_h);
    if (mode == "off") scale = 1.0; else if (mode == "on") scale = 2.0;
    else if (mode != "auto" && !mode.empty()) { scale = std::clamp(atof(mode.c_str()), 1.0, 4.0); if (scale == 0) scale = client_scale >= 2 ? 2.0 : 1.0; }
    else scale = client_scale >= 2.0f ? 2.0 : 1.0;
    const double max_w = HOST_MAX_BACKING_W / scale, max_h = HOST_MAX_BACKING_H / scale;
    const double fit = std::min({max_w / win_w, max_h / win_h, 1.0});
    rw = std::max(MIN_ADV_W, even(int(win_w * fit))); rh = std::max(MIN_ADV_H, even(int(win_h * fit)));
}

double process_cpu_percent(int64_t& last_wall_ns, uint64_t& last_cpu_100ns) {
    FILETIME c, e, k, u; GetProcessTimes(GetCurrentProcess(), &c, &e, &k, &u);
    const uint64_t cpu = (uint64_t(k.dwHighDateTime) << 32 | k.dwLowDateTime) + (uint64_t(u.dwHighDateTime) << 32 | u.dwLowDateTime);
    const int64_t now = now_ns();
    double pct = 0;
    if (last_wall_ns) { const double wall = double(now - last_wall_ns); const double c100 = double(cpu - last_cpu_100ns) * 100.0; SYSTEM_INFO si; GetSystemInfo(&si); pct = wall > 0 ? c100 / wall * 100.0 / double(si.dwNumberOfProcessors) : 0; }
    last_wall_ns = now; last_cpu_100ns = cpu;
    return pct;
}
size_t working_set_mb() { PROCESS_MEMORY_COUNTERS pmc{}; pmc.cb = sizeof pmc; GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof pmc); return pmc.WorkingSetSize >> 20; }

}  // namespace

void usage() {
    std::puts("scshr — native client for Apple Screen Sharing High Performance mode\n"
              "  scshr                                  (no arguments) opens the setup / connect window\n"
              "  scshr setup --mac HOST[:PORT] --mac-user USER   pairs this PC with the Mac (the wizard, from the CLI)\n"
              "  scshr check   scshr unpair   scshr init [--server-code SCST1:...]   scshr status\n"
              "  scshr tunnel uninstall [--reset-identity]        (add -h to any subcommand for its own options)\n"
              "  -u USER  [--password-stdin]  [--port 5900]  [--auth srp|nonsrp]\n"
              "    sessions run over the paired scshr WireGuard tunnel; --direct --host H bypasses it (development only)\n"
              "  --advertise WxH[@SCALE]|auto   --hidpi auto|on|off|N   --dynamic / --no-dynamic   --hdr\n"
              "  --codec auto|hevc|avc   --decoder auto|sw   --tiles N   --no-ltrp\n"
              "  --curtain / --no-curtain   --alt-session (default: own virtual session) / --share-console   --audio / --no-audio\n"
              "  --present vsync|lowlat   --adapter N   --list-adapters   --display N|all|combined\n"
              "  --record FILE.scshr   --auto-quit-secs N   --stats-interval S   --no-clipboard   --no-grab\n"
              "  --drop-pct P (synthetic loss)   --headless   -v   -q   --log-file PATH");
}

bool parse_viewer_args(int argc, char** argv, ViewerOptions& a) {
    bool bad = false;
    auto need = [&](int& i) -> std::string { if (i + 1 >= argc) { std::fprintf(stderr, "missing value for %s\n", argv[i]); bad = true; return {}; } return argv[++i]; };
    for (int i = 1; i < argc && !bad; ++i) {
        std::string k = argv[i];
        if (k == "--host") a.host = need(i); else if (k == "-u" || k == "--user") a.user = need(i);
        else if (k == "--password-stdin") a.password_stdin = true; else if (k == "--port") a.port = uint16_t(atoi(need(i).c_str()));
        else if (k == "--auth") a.srp = need(i) != "nonsrp"; else if (k == "--advertise") a.advertise = need(i);
        else if (k == "--hidpi") a.hidpi = need(i); else if (k == "--dynamic") a.dynamic = true; else if (k == "--no-dynamic") a.dynamic = false;
        else if (k == "--hdr") a.hdr = true; else if (k == "--codec") a.codec = need(i); else if (k == "--decoder") a.decoder = need(i);
        else if (k == "--tiles") a.tiles = atoi(need(i).c_str()); else if (k == "--no-ltrp") a.ltrp = false;
        else if (k == "--curtain") a.curtain = true; else if (k == "--no-curtain") a.curtain = false;
        else if (k == "--share-console") { a.share_console = true; a.alt_session = false; } else if (k == "--alt-session") { a.alt_session = true; a.share_console = false; }
        else if (k == "--audio") a.audio = true; else if (k == "--no-audio") a.audio = false;
        else if (k == "--present") a.present = need(i); else if (k == "--adapter") a.adapter = atoi(need(i).c_str()); else if (k == "--list-adapters") a.list_adapters = true;
        else if (k == "--display") a.display = need(i); else if (k == "--record") a.record = need(i);
        else if (k == "--auto-quit-secs") a.auto_quit = atoi(need(i).c_str()); else if (k == "--stats-interval") a.stats_interval = atoi(need(i).c_str());
        else if (k == "--no-clipboard") a.clipboard = false; else if (k == "--no-grab") a.grab = false; else if (k == "--legacy-cursor") a.legacy_cursor = true;
        else if (k == "--direct") a.direct = true; else if (k == "--replay-key") a.replay_key = need(i); else if (k == "--drop-pct") a.drop_pct = atof(need(i).c_str()); else if (k == "--headless") a.headless = true;
        else if (k == "-v" || k == "--verbose") a.verbose = true; else if (k == "-q" || k == "--quiet") a.quiet = true; else if (k == "--log-file") a.log_file = need(i);
        else if (k == "-h" || k == "--help") { usage(); exit(0); }
        else { std::fprintf(stderr, "unknown argument %s\n", argv[i]); usage(); return false; }
    }
    return !bad;
}

ViewerResult run_viewer(ViewerOptions& a) {
    log_set_level(a.verbose ? LogLevel::Debug : a.quiet ? LogLevel::Warn : LogLevel::Info);
    if (!a.log_file.empty()) log_set_file(a.log_file);
    if (a.list_adapters) {
        for (auto& ad : D3D11Renderer::enumerate_adapters()) { std::string d; for (wchar_t c : ad.description) d.push_back(c < 128 ? char(c) : '?'); std::printf("%d: %s vendor=0x%04x luid=%08x:%08x outputs=%zu%s\n", ad.index, d.c_str(), ad.vendor_id, (unsigned)ad.luid.HighPart, (unsigned)ad.luid.LowPart, ad.outputs.size(), ad.software ? " [software]" : ""); }
        return {};
    }
    const bool replay = !a.replay_key.empty();
    if (!replay && a.user.empty()) return {ViewerExit::Error, "no user name given", 2};
    if (a.direct && !replay && a.host.empty()) return {ViewerExit::Error, "--direct requires --host", 2};
    // Fail closed: production sessions only ever talk to the paired tunnel address.
    try { a.host = resolve_session_host(a.host, a.direct || replay); }
    catch (const std::exception& e) { return {ViewerExit::ConnectFailed, e.what(), 1}; }
    if (!replay && a.password.empty()) a.password = read_password(a);
    const std::string label = a.title_label.empty() ? a.host : a.title_label;
    timeBeginPeriod(1);
    struct TimeScope { ~TimeScope() { timeEndPeriod(1); } } time_scope;

    // ── window + GPU first: adapter selection follows the window's monitor ──
    std::atomic<bool> closed{false};
    int win_w = 1280, win_h = 800;
    std::optional<std::pair<int, int>> fixed_adv; double fixed_scale = 0;
    if (a.advertise != "auto") {
        int w = 0, h = 0; double sc = 2.0; char at = 0;
        if (sscanf(a.advertise.c_str(), "%dx%d%c%lf", &w, &h, &at, &sc) >= 2 && w > 0 && h > 0) { fixed_adv = {w, h}; fixed_scale = at == '@' ? sc : (a.hidpi == "on" ? 2.0 : (a.hidpi == "off" || a.hidpi == "auto") ? 1.0 : atof(a.hidpi.c_str())); }
        else return {ViewerExit::Error, "bad --advertise " + a.advertise, 2};
        win_w = fixed_adv->first; win_h = fixed_adv->second;
    } else {
        RECT wa; SystemParametersInfoW(SPI_GETWORKAREA, 0, &wa, 0);
        win_w = std::clamp(even(int((wa.right - wa.left) * 0.85)), MIN_ADV_W, 1920); win_h = std::clamp(even(int((wa.bottom - wa.top) * 0.85)), MIN_ADV_H, 1080);
    }
    const bool dynamic = a.dynamic.value_or(!fixed_adv);

    // Input state shared with the window callbacks. One View per window (primary + one per extra host monitor).
    std::unique_ptr<Session> session;
    D3D11Renderer renderer;
    std::atomic<int> canvas_w{0}, canvas_h{0};
    std::atomic<bool> cursor_dirty{false};
    std::mutex cursor_mu; std::shared_ptr<const CursorShape> pending_cursor; bool have_pending_cursor = false; std::shared_ptr<const CursorShape> last_cursor;
    std::unique_ptr<KeyboardHook> hook;
    struct View {
        std::unique_ptr<Window> window;
        int id = 0;                                        // renderer window id
        uint8_t button_mask = 0;
        std::optional<std::pair<int, int>> cursor;         // pointer in canvas texels
        bool pointer_in = true;
        double wheel_accum = 0; int64_t wheel_last_ns = 0;
        std::optional<std::pair<int, int>> last_drawn_cursor;
    };
    std::vector<std::unique_ptr<View>> views;
    auto to_canvas = [&](View& v, int wx, int wy) -> std::optional<std::pair<int, int>> {
        auto [ww, wh] = v.window->client_size();
        if (ww <= 0 || wh <= 0 || canvas_w <= 0) return std::nullopt;
        CropRect r = renderer.effective_crop(v.id);
        if (r.w <= 0 || r.h <= 0) return std::nullopt;
        const double u = std::clamp(double(wx) / ww, 0.0, 1.0), vv = std::clamp(double(wy) / wh, 0.0, 1.0);
        const int sx = r.x + std::min(r.w - 1, int(u * r.w)), sy = r.y + std::min(r.h - 1, int(vv * r.h));
        return std::pair<int, int>{std::clamp(sx, 0, canvas_w - 1), std::clamp(sy, 0, canvas_h - 1)};
    };
    // A drag that leaves its window keeps delivering to the press-origin window; remap through whichever view contains the global point.
    auto global_to_canvas = [&](int gx, int gy) -> std::optional<std::pair<int, int>> {
        for (auto& vp : views) {
            RECT rc; POINT o{0, 0}; GetClientRect(vp->window->hwnd(), &rc); ClientToScreen(vp->window->hwnd(), &o);
            if (gx >= o.x && gx < o.x + rc.right && gy >= o.y && gy < o.y + rc.bottom) return to_canvas(*vp, gx - o.x, gy - o.y);
        }
        return std::nullopt;
    };
    auto make_events = [&](View* v) {
        WindowEvents ev;
        ev.on_close = [&, v] { if (v == views.front().get()) closed = true; };   // secondaries: Window::closed() is reaped by the render loop
        ev.on_resize = [&, v](int, int) { renderer.resize(v->id); };
        ev.on_mouse_move = [&, v](int x, int y) {
            std::optional<std::pair<int, int>> c;
            if (views.size() > 1 && v->button_mask) { POINT p{x, y}; ClientToScreen(v->window->hwnd(), &p); c = global_to_canvas(p.x, p.y); }
            if (!c) c = to_canvas(*v, x, y);
            v->cursor = c;
            if (v->cursor && session) session->pointer_event(v->button_mask, v->cursor->first, v->cursor->second);
            cursor_dirty = true;
        };
        ev.on_mouse_button = [&, v](int bit, bool down, int x, int y) { if (down) v->button_mask |= uint8_t(bit); else v->button_mask &= uint8_t(~bit); auto c = to_canvas(*v, x, y); if (c) v->cursor = c; if (v->cursor && session) session->pointer_event(v->button_mask, v->cursor->first, v->cursor->second); };
        ev.on_wheel = [&, v](int, int, double notches) {
            if (!v->cursor || !session || notches == 0) return;
            const int64_t now = now_ns(); const double dt = v->wheel_last_ns ? double(now - v->wheel_last_ns) / 1e6 : 1000; v->wheel_last_ns = now;
            const double accel = dt < 25 ? 10.0 : dt < 50 ? 6.0 : dt < 100 ? 3.5 : dt < 200 ? 2.0 : dt < 350 ? 1.4 : 1.0;
            v->wheel_accum += -notches * 12.0 * accel;   // 12 ticks/notch: the host scrolls exactly 1 px per tick
            v->wheel_accum = std::clamp(v->wheel_accum, -200.0, 200.0);
            const int ticks = int(v->wheel_accum); if (ticks == 0) return;
            const int emit = std::clamp(ticks, -50, 50); v->wheel_accum -= emit;
            session->scroll_event(v->cursor->first, v->cursor->second, emit);
        };
        ev.on_key = [&](bool down, uint32_t ks, bool) { if (session && ks) session->key_event(down, ks); };   // printable keys arrive via WM_CHAR; modifier combos via the LL hook
        ev.on_char = [&](uint32_t cp) { if (session) { session->key_event(true, cp); session->key_event(false, cp); } };
        ev.on_mouse_enter = [&, v](bool in) { v->pointer_in = in; cursor_dirty = true; };
        ev.on_focus = [&, v](bool f) { if (hook) { hook->set_window(v->window->hwnd()); if (f) hook->enable(); else hook->disable(); } };
        return ev;
    };
    views.push_back(std::make_unique<View>());
    View& primary = *views.front();
    primary.window = std::make_unique<Window>(L"scshr — connecting to " + widen(label) + L"…", win_w, win_h, make_events(&primary));
    Window* window = primary.window.get();
    int primary_id = 0;

    RendererConfig rc; rc.adapter_override = a.adapter; rc.present_mode = a.present;
    try { renderer.init(window->hwnd(), rc); } catch (const std::exception& e) { LOG_ERROR("app", "renderer init failed: %s", e.what()); return {ViewerExit::Error, std::string("The graphics device could not be prepared: ") + e.what(), 1}; }
    primary_id = 0; primary.id = 0;
    GpuDevice gpu = renderer.gpu();

    // ── codec selection (mirrors registry.resolve_codec: HEVC only with a hardware 4:4:4 decoder) ──
    SessionConfig sc;
    if (a.codec == "hevc") sc.codec = VideoCodec::Hevc;
    else if (a.codec == "avc") sc.codec = VideoCodec::Avc;
    else { const bool hevc444 = a.decoder != "sw" && probe_hevc444_hw(gpu); sc.codec = hevc444 ? VideoCodec::Hevc : VideoCodec::Avc; LOG_INFO("app", "codec=auto: %s", hevc444 ? "HEVC 4:4:4 hardware decoder available -> hevc" : "no HEVC 4:4:4 hardware decoder -> avc (H.264 4:2:0)"); }
    sc.offer_codec = sc.codec == VideoCodec::Hevc ? offers::Codec::Both : offers::Codec::Avc;
    sc.tiles_per_frame = a.tiles > 0 ? a.tiles : offers::default_tiles_per_frame(sc.codec == VideoCodec::Hevc ? offers::Codec::Hevc : offers::Codec::Avc);
    sc.host = a.host; sc.port = a.port; sc.username = a.user; sc.password = a.password; sc.srp_first = a.srp;
    sc.hdr = a.hdr; sc.audio = a.audio; sc.curtain = a.curtain; sc.share_console = a.share_console; sc.alt_session = a.alt_session; sc.hidpi = a.hidpi;
    sc.dynamic_resolution = dynamic; sc.ltrp = a.ltrp; sc.prefer_hw = a.decoder != "sw"; sc.decoder_override = a.decoder == "sw" ? "sw" : "";
    sc.clipboard = a.clipboard; sc.legacy_cursor = a.legacy_cursor; sc.record_packets = a.record; sc.drop_pct = a.drop_pct; sc.gpu = gpu;
    if (replay) { sc.replay_mode = true; sc.replay_video_key = unhex(a.replay_key); sc.warmup_tcp = false; sc.clipboard = false; sc.audio = false; if (a.codec == "auto") { sc.codec = VideoCodec::Avc; sc.tiles_per_frame = a.tiles > 0 ? a.tiles : 1; } }
    {
        int rw, rh; double scale;
        const float client_scale = window->dpi_scale();
        if (fixed_adv) { rw = fixed_adv->first; rh = fixed_adv->second; scale = fixed_scale; }
        else resolve_hidpi(a.hidpi, win_w, win_h, client_scale, rw, rh, scale);
        sc.advertise.width = rw; sc.advertise.height = rh; sc.advertise.hidpi_scale = scale;
        LOG_INFO("app", "advertise %dx%d @%gx (hidpi=%s dynamic=%d client_scale=%.2f)", rw, rh, scale, a.hidpi.c_str(), int(dynamic), client_scale);
    }
    session = std::make_unique<Session>(sc);
    session->on_cursor = [&](std::shared_ptr<const CursorShape> img) { std::lock_guard<std::mutex> lk(cursor_mu); pending_cursor = img; have_pending_cursor = true; };
    session->read_local_clipboard = [] { return clipboard_read_text(); };
    session->write_local_clipboard = [](const std::string& s) { clipboard_write_text(s); };
    std::unique_ptr<AudioSink> sink;
    if (a.audio && !replay) { std::string why; sink = AudioSink::create(&why); if (!sink) LOG_WARN("audio", "%s", why.c_str()); else session->on_audio = [&](const float* pcm, size_t frames) { sink->feed(pcm, frames); }; }

    // Connect on a helper thread so the window stays responsive.
    std::atomic<int> conn_state{0}; std::string conn_error;
    std::thread conn([&] { try { session->connect(); conn_state = 1; } catch (const std::exception& e) { conn_error = e.what(); conn_state = 2; } });
    while (conn_state == 0 && !closed) { window->pump(); std::this_thread::sleep_for(std::chrono::milliseconds(10)); }
    conn.join();
    if (closed) { session->close(); return {}; }
    if (conn_state == 2) { LOG_ERROR("app", "connect failed: %s", conn_error.c_str()); session->close(); return {ViewerExit::ConnectFailed, conn_error, 1}; }

    auto [cw0, ch0] = session->canvas_dims(); canvas_w = cw0; canvas_h = ch0;
    if (cw0 == 0 || ch0 == 0) {
        // Replay mode has no 0x1c answer: size the canvas from the first decoded frame.
        for (int i = 0; i < 500 && (cw0 == 0 || ch0 == 0); ++i) {
            window->pump(); session->decoder()->wait_for_frame(20);
            auto f = session->decoder()->take_latest(0);
            if (f) { cw0 = f->frame_width(); ch0 = f->frame_height() * session->num_tiles(); canvas_w = cw0; canvas_h = ch0; }
        }
        if (cw0 == 0 || ch0 == 0) { LOG_ERROR("app", "no decoded frame within 10 s"); session->close(); return {ViewerExit::Error, "No picture arrived from the Mac within 10 seconds.", 1}; }
    }
    auto [sw0, sh0] = session->scaled_dims();
    const int ntiles = session->num_tiles();
    LOG_INFO("app", "session ready: canvas=%dx%d scaled=%dx%d server=%dx%d tiles=%d decoder=%s pixfmt=%s", cw0, ch0, sw0, sh0, session->server_dims().first, session->server_dims().second, ntiles, session->decoder_name().c_str(), session->decoder()->pix_fmt_name().c_str());
    renderer.set_canvas(cw0, ch0, ntiles);
    window->set_title(L"scshr — " + widen(label));
    if (!dynamic) window->lock_aspect(sc.advertise.width, sc.advertise.height);
    if (a.grab) { hook = std::make_unique<KeyboardHook>(window->hwnd(), [&](bool d, uint32_t ks) { session->key_event(d, ks); }); if (window->focused()) hook->enable(); }
    renderer.set_cursor_scale(float(sc.advertise.hidpi_scale));
    // --display N crop / auto per-monitor
    int display_idx = -1; bool display_all = true;
    if (a.display == "combined") display_all = false; else if (a.display != "all") { display_idx = atoi(a.display.c_str()); display_all = false; }
    bool crop_applied = display_idx < 0, secondaries_done = !display_all;

    // ── render loop ──
    bool connection_lost = false;
    const int64_t t_start = now_ns();
    const int64_t deadline = a.auto_quit > 0 ? t_start + int64_t(a.auto_quit) * 1000000000LL : INT64_MAX;
    int64_t last_stats = t_start, cpu_wall = 0; uint64_t cpu_time = 0;
    int cur_adv_w = win_w, cur_adv_h = win_h; std::optional<std::pair<int, int>> pending_size; int64_t pending_since = 0, last_resize = 0;
    bool os_cursor_hidden = false;
    bool dynamic_active = dynamic;
    std::vector<std::unique_ptr<DecodedFrame>> fresh;
    bool any_frame_ever = false;
    while (!closed && now_ns() < deadline) {
        window->pump();
        if (closed) break;
        // Reap secondary windows the user closed.
        for (size_t i = 1; i < views.size();) { if (views[i]->window->closed()) { renderer.remove_window(views[i]->id); views.erase(views.begin() + ptrdiff_t(i)); } else ++i; }
        if (!session->is_connected()) { LOG_ERROR("app", "connection lost — closing viewer"); connection_lost = true; break; }
        if (renderer.device_lost()) break;
        // Cursor shape from the session thread → GPU texture on this thread.
        { std::lock_guard<std::mutex> lk(cursor_mu); if (have_pending_cursor) { have_pending_cursor = false; if (pending_cursor) { renderer.set_cursor_image(CursorImage{pending_cursor->w, pending_cursor->h, pending_cursor->hx, pending_cursor->hy, pending_cursor->rgba}); last_cursor = pending_cursor; cursor_dirty = true; } } }
        if (!os_cursor_hidden && last_cursor && primary.cursor) { for (auto& v : views) v->window->show_cursor(false); os_cursor_hidden = true; }
        // Canvas change (0x451 after a dynamic resize / SSRC adoption with new geometry).
        auto [ncw, nch] = session->canvas_dims();
        if (replay) { ncw = canvas_w; nch = canvas_h; }
        if ((ncw != canvas_w || nch != canvas_h) && ncw && nch) {
            canvas_w = ncw; canvas_h = nch;
            renderer.set_canvas(ncw, nch, session->num_tiles());
            auto [ww, wh] = window->client_size(); cur_adv_w = even(ww); cur_adv_h = even(wh);
            if (auto gap = session->display_content_rect()) renderer.set_crop(primary_id, CropRect{gap->x, gap->y, gap->w, gap->h});
            LOG_INFO("app", "dynamic resize: canvas=%dx%d tiles=%d decoder=%s", ncw, nch, session->num_tiles(), session->decoder_name().c_str());
        }
        // --display crop once the layout lands.
        if (!crop_applied) {
            auto rects = session->display_rects();
            if (int(rects.size()) > display_idx) { auto& r = rects[size_t(display_idx)]; renderer.set_crop(primary_id, CropRect{r.x, r.y, r.w, r.h}); crop_applied = true; LOG_INFO("app", "--display %d: cropping to host monitor #%u @%d,%d %dx%d", display_idx, r.display_id, r.x, r.y, r.w, r.h); }
            else if (!rects.empty()) { LOG_WARN("app", "--display %d out of range (host has %zu monitor(s))", display_idx, rects.size()); crop_applied = true; }
        }
        if (!secondaries_done) {
            auto rects = session->display_rects();
            if (!rects.empty()) {
                if (rects.size() > 1) {
                    // One window per host monitor, all fed by the single decode; the primary shows monitor 1 and dynamic
                    // resolution is pinned (re-advertising the whole canvas to one window would distort the others).
                    dynamic_active = false;
                    renderer.set_crop(primary_id, CropRect{rects[0].x, rects[0].y, rects[0].w, rects[0].h});
                    window->set_title(std::wstring(L"scshr — monitor 1"));
                    for (size_t i = 1; i < rects.size(); ++i) {
                        auto& r = rects[i];
                        auto v = std::make_unique<View>();
                        const int base = std::min(r.w, 1280);
                        v->window = std::make_unique<Window>(L"scshr — monitor " + std::to_wstring(i + 1), base, std::max(1, base * r.h / std::max(1, r.w)), make_events(v.get()));
                        v->window->lock_aspect(r.w, r.h);
                        v->id = renderer.add_window(v->window->hwnd());
                        renderer.set_crop(v->id, CropRect{r.x, r.y, r.w, r.h});
                        views.push_back(std::move(v));
                    }
                    LOG_INFO("app", "multi-window: opened %zu window(s) for %zu host monitor(s)", views.size(), rects.size());
                } else if (auto gap = session->display_content_rect()) { renderer.set_crop(primary_id, CropRect{gap->x, gap->y, gap->w, gap->h}); LOG_WARN("app", "single-monitor layout covers less than canvas — auto-cropping to @%d,%d %dx%d", gap->x, gap->y, gap->w, gap->h); }
                secondaries_done = true;
            }
        }
        // Dynamic resolution: debounce window resizes into 0x1d requests.
        if (dynamic_active) {
            auto [ww, wh] = window->client_size();
            const int tw = even(ww), th = even(wh);
            const int64_t now = now_ns();
            if (ww > 0 && wh > 0 && (std::abs(tw - cur_adv_w) >= 32 || std::abs(th - cur_adv_h) >= 32)) { if (!pending_size || *pending_size != std::pair{tw, th}) { pending_size = {tw, th}; pending_since = now; } }
            else pending_size.reset();
            if (pending_size && now - pending_since >= 500'000'000 && now - last_resize >= 2'500'000'000) {
                int rw, rh; double scale; resolve_hidpi(a.hidpi, pending_size->first, pending_size->second, window->dpi_scale(), rw, rh, scale);
                cur_adv_w = tw; cur_adv_h = th; pending_size.reset(); last_resize = now;
                LOG_INFO("app", "resize -> requesting %dx%d @%gx", rw, rh, scale);
                try { session->send_dynamic_resolution(rw, rh, scale); renderer.set_cursor_scale(float(scale)); } catch (const std::exception& e) { LOG_ERROR("app", "send_dynamic_resolution failed: %s", e.what()); }
            }
        }
        // Wait for a decoded frame (≤ 4 ms), then gate on the swapchain, then grab the NEWEST frame per tile.
        const bool got = session->decoder()->wait_for_frame(4);
        bool cursor_moved = cursor_dirty.exchange(false);
        for (auto& v : views) if (v->cursor != v->last_drawn_cursor) cursor_moved = true;
        if (!got && !cursor_moved) continue;
        if (!renderer.wait_can_present(primary_id, 50)) continue;   // swapchain still owns the previous frame: never queue
        bool any_fresh = false;
        for (int ti = 0; ti < session->decoder()->num_tiles(); ++ti) { auto f = session->decoder()->take_latest(ti); if (f) { renderer.submit_frame(std::move(f)); any_fresh = true; any_frame_ever = true; } }
        if ((any_fresh || cursor_moved) && any_frame_ever) {
            bool lost = false;
            for (auto& v : views) {
                if (v.get() != &primary && !renderer.wait_can_present(v->id, 0)) continue;   // secondaries never block the primary
                renderer.set_cursor_pos(v->id, v->pointer_in ? v->cursor : std::nullopt);
                if (!renderer.draw(v->id, now_ns())) { lost = true; break; }
                v->last_drawn_cursor = v->cursor;
            }
            if (lost) break;
        }
        // Periodic compact statistics.
        if (a.stats_interval > 0 && now_ns() - last_stats >= int64_t(a.stats_interval) * 1000000000LL) {
            last_stats = now_ns();
            auto& rt = renderer.telemetry();
            auto pi = rt.present_interval_ms.summary(), rp = rt.ready_to_present_ms.summary(), ap = rt.au_to_present_ms.summary(), dc = rt.draw_cpu_ms.summary();
            LOG_INFO("stats", "present: %s n=%llu interval p50/p95/p99/max=%.1f/%.1f/%.1f/%.1f ms | decoded→present p50/p95=%.2f/%.2f ms | AU→present p50/p95/p99=%.2f/%.2f/%.2f ms | draw cpu p50=%.2f ms | zero-copy=%llu gpu-copy=%llu cpu-upload=%llu | cpu %.1f%% ws %zu MB",
                     renderer.present_mode().c_str(), (unsigned long long)rt.presents.load(), pi.median, pi.p95, pi.p99, pi.max, rp.median, rp.p95, ap.median, ap.p95, ap.p99, dc.median,
                     (unsigned long long)rt.frames_zero_copy.load(), (unsigned long long)rt.frames_gpu_copy.load(), (unsigned long long)rt.frames_uploaded_cpu.load(), process_cpu_percent(cpu_wall, cpu_time), working_set_mb());
            LOG_INFO("stats", "%s", session->telemetry_line().c_str());
        }
    }
    LOG_INFO("app", "viewer closing");
    if (hook) hook->disable();
    if (sink) sink->stop();
    session->close();
    if (connection_lost) return {ViewerExit::ConnectionLost, "The connection to " + label + " was lost.", 0};
    return {};
}

}  // namespace scshr::app
