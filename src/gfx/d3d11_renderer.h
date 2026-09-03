#pragma once
// D3D11 presentation: one device (shared with FFmpeg D3D11VA), one flip-model waitable swapchain per
// window, pixel-shader YUV→RGB directly from the decoder's texture-array slice (no copy), cursor overlay.
//
// Zero-copy contract: a hardware DecodedFrame carries ID3D11Texture2D* + array slice. We create a
// shader-resource view on that slice (luma R8 / chroma R8G8 for NV12; RGBA8 view for AYUV/VUYX) and
// sample it. The texture is never mapped, never read back, never copied — unless the decoder pool could
// not be created with D3D11_BIND_SHADER_RESOURCE, in which case a single GPU→GPU CopySubresourceRegion
// into an SRV-capable texture is the (counted, logged) fallback. Software frames are uploaded through
// a dynamic texture and counted separately (`frames_uploaded_cpu`) so they can never masquerade as the
// hardware path.
#include "common/bytes.h"
#include "common/stats.h"
#include "media/decoder.h"

#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <windows.h>

namespace scshr {

struct AdapterInfo {
    int index = 0;
    std::wstring description;
    uint32_t vendor_id = 0, device_id = 0;
    LUID luid{};
    bool software = false;
    size_t dedicated_vram = 0;
    std::vector<std::wstring> outputs;   // monitor device names attached to this adapter
    std::vector<HMONITOR> monitors;
};

struct RendererConfig {
    int adapter_override = -1;          // -1 = pick the adapter driving the window's monitor
    std::string present_mode = "vsync"; // "vsync" (tear-free, latency 1) | "lowlat" (SyncInterval 0 + tearing when supported)
    bool debug_layer = false;
};

struct RenderTelemetry {
    RollingStats present_interval_ms{600};
    RollingStats ready_to_present_ms{600};     // decoder output → Present() call
    RollingStats au_to_present_ms{600};        // AU reconstructable → Present() call
    RollingStats draw_cpu_ms{600};
    std::atomic<uint64_t> presents{0}, frames_zero_copy{0}, frames_gpu_copy{0}, frames_uploaded_cpu{0}, stale_frames_dropped{0};
};

struct CursorImage { int w = 0, h = 0, hx = 0, hy = 0; Bytes rgba; };
struct CropRect { int x = 0, y = 0, w = 0, h = 0; };

class D3D11Renderer {
public:
    D3D11Renderer();
    ~D3D11Renderer();
    static std::vector<AdapterInfo> enumerate_adapters();

    // Creates the device on the adapter that drives `hwnd`'s monitor (or the override). Logs the choice.
    void init(HWND hwnd, const RendererConfig& cfg);
    GpuDevice gpu();
    const AdapterInfo& adapter() const { return adapter_; }
    std::string describe() const;      // one-line diagnostics: adapter, feature level, decode profiles, present mode

    // Windows (viewports). Window 0 is created by init(); more for multi-monitor views.
    int add_window(HWND hwnd);
    void remove_window(int id);
    void resize(int id);                 // call on WM_SIZE (ResizeBuffers)
    // Blocks until the swapchain can accept another frame (frame-latency waitable object). false on timeout.
    bool wait_can_present(int id, int timeout_ms);

    void set_canvas(int canvas_w, int canvas_h, int tiles);
    // Newest frame for its tile; replaces the previous one (which is released).
    void submit_frame(std::unique_ptr<DecodedFrame> f);
    bool has_any_frame() const;
    std::pair<int, int> content_dims() const;    // decoded extent grown from tiles (≤ canvas)
    void set_crop(int id, std::optional<CropRect> crop);   // presented sub-rect (per window)
    CropRect effective_crop(int id) const;

    void set_cursor_image(const CursorImage& img);
    void clear_cursor();
    void set_cursor_pos(int id, std::optional<std::pair<int, int>> canvas_xy);
    void set_cursor_scale(float s) { cursor_scale_ = s; }
    bool cursor_visible() const { return cursor_tex_ != nullptr; }

    // Draw + Present for one window. Returns false if the device was lost.
    bool draw(int id, int64_t now_ns);
    RenderTelemetry& telemetry() { return tel_; }
    const std::string& present_mode() const { return present_mode_; }
    bool tearing_supported() const { return tearing_supported_; }
    bool device_lost() const { return device_lost_; }

private:
    struct Impl;
    std::unique_ptr<Impl> p_;
    AdapterInfo adapter_;
    RenderTelemetry tel_;
    std::string present_mode_;
    bool tearing_supported_ = false;
    bool device_lost_ = false;
    float cursor_scale_ = 1.0f;
    void* cursor_tex_ = nullptr;
};

}  // namespace scshr
