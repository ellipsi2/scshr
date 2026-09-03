#include "gfx/d3d11_renderer.h"
#include "common/clock.h"
#include "common/log.h"

#include <d3d11.h>
#include <d3d11_1.h>
#include <d3d11_4.h>
#include <d3dcompiler.h>
#include <dxgi1_6.h>
#include <wrl/client.h>

extern "C" {
#include <libavutil/frame.h>
#include <libavutil/hwcontext.h>
#include <libavutil/pixdesc.h>
#include <libavutil/pixfmt.h>
}

#include <algorithm>
#include <map>
#include <stdexcept>

using Microsoft::WRL::ComPtr;

namespace scshr {

namespace {

const char* HLSL = R"(
cbuffer Frame : register(b0) {
    float4 dst;        // NDC rect: x0, y0(top), x1, y1(bottom)
    float4 src;        // uv rect: u0, v0, u1, v1
    float4 luma_xf;    // x: luma scale, y: luma offset, z: chroma offset, w: unused
    float4 m0;         // rows of the YUV->RGB matrix (r)
    float4 m1;         // (g)
    float4 m2;         // (b)
};
struct VSOut { float4 pos : SV_Position; float2 uv : TEXCOORD0; };
VSOut vs(uint id : SV_VertexID) {
    float2 c = float2(id & 1, (id >> 1) & 1);          // 0,0 / 1,0 / 0,1 / 1,1 (strip)
    VSOut o;
    o.pos = float4(lerp(dst.x, dst.z, c.x), lerp(dst.y, dst.w, c.y), 0.0, 1.0);
    o.uv = float2(lerp(src.x, src.z, c.x), lerp(src.y, src.w, c.y));
    return o;
}
SamplerState samp : register(s0);
Texture2DArray<float>  t_luma   : register(t0);
Texture2DArray<float2> t_chroma : register(t1);
Texture2DArray<float>  t_u      : register(t1);
Texture2DArray<float>  t_v      : register(t2);
Texture2DArray<float4> t_packed : register(t0);
Texture2D<float4>      t_cursor : register(t0);
float3 convert(float y, float cb, float cr) {
    float yy = (y - luma_xf.y) * luma_xf.x;
    float u = cb - luma_xf.z, v = cr - luma_xf.z;
    float3 yuv = float3(yy, u, v);
    return saturate(float3(dot(m0.xyz, yuv), dot(m1.xyz, yuv), dot(m2.xyz, yuv)));
}
float4 ps_nv12(VSOut i) : SV_Target {
    float y = t_luma.Sample(samp, float3(i.uv, 0));
    float2 c = t_chroma.Sample(samp, float3(i.uv, 0));
    return float4(convert(y, c.x, c.y), 1.0);
}
float4 ps_planar(VSOut i) : SV_Target {
    float y = t_luma.Sample(samp, float3(i.uv, 0));
    float u = t_u.Sample(samp, float3(i.uv, 0));
    float v = t_v.Sample(samp, float3(i.uv, 0));
    return float4(convert(y, u, v), 1.0);
}
float4 ps_vuyx(VSOut i) : SV_Target {
    float4 p = t_packed.Sample(samp, float3(i.uv, 0));   // AYUV as RGBA8 view: R=V, G=U, B=Y
    return float4(convert(p.b, p.g, p.r), 1.0);
}
float4 ps_cursor(VSOut i) : SV_Target { return t_cursor.Sample(samp, i.uv); }
)";

struct FrameCB { float dst[4]; float src[4]; float luma_xf[4]; float m0[4]; float m1[4]; float m2[4]; };

ComPtr<ID3DBlob> compile(const char* entry, const char* target) {
    ComPtr<ID3DBlob> code, err;
    const HRESULT hr = D3DCompile(HLSL, std::strlen(HLSL), "scshr.hlsl", nullptr, nullptr, entry, target, D3DCOMPILE_OPTIMIZATION_LEVEL3, 0, &code, &err);
    if (FAILED(hr)) throw std::runtime_error(std::string("shader compile failed: ") + (err ? static_cast<const char*>(err->GetBufferPointer()) : ""));
    return code;
}

std::string narrow(const std::wstring& w) { std::string s; for (wchar_t c : w) s.push_back(c < 128 ? char(c) : '?'); return s; }

enum class Layout { None, Nv12, Planar, Vuyx };

struct TileView {
    std::unique_ptr<DecodedFrame> frame;
    ComPtr<ID3D11ShaderResourceView> srv0, srv1, srv2;
    ComPtr<ID3D11Texture2D> owned;    // GPU-copy / CPU-upload destination (fallback paths)
    Layout layout = Layout::None;
    int w = 0, h = 0;
    bool full_range = true, bt709 = true;
};

struct Window {
    HWND hwnd = nullptr;
    ComPtr<IDXGISwapChain2> swap;
    ComPtr<ID3D11RenderTargetView> rtv;
    HANDLE waitable = nullptr;
    int width = 0, height = 0;
    std::optional<CropRect> crop;
    std::optional<std::pair<int, int>> cursor;
    int64_t last_present_ns = 0;
    bool waited = false;
};

}  // namespace

struct D3D11Renderer::Impl {
    ComPtr<ID3D11Device> dev;
    ComPtr<ID3D11DeviceContext> ctx;
    ComPtr<IDXGIFactory2> factory;
    ComPtr<IDXGIAdapter1> adapter;
    std::recursive_mutex lock;
    D3D_FEATURE_LEVEL feature_level = D3D_FEATURE_LEVEL_11_0;
    ComPtr<ID3D11VertexShader> vs;
    ComPtr<ID3D11PixelShader> ps_nv12, ps_planar, ps_vuyx, ps_cursor;
    ComPtr<ID3D11Buffer> cb;
    ComPtr<ID3D11SamplerState> sampler;
    ComPtr<ID3D11BlendState> blend;
    ComPtr<ID3D11RasterizerState> raster;
    std::vector<std::unique_ptr<Window>> windows;
    std::vector<TileView> tiles;
    int canvas_w = 0, canvas_h = 0, ntiles = 0, slot_h = 0;
    int content_w = 0, content_h = 0;
    ComPtr<ID3D11Texture2D> cursor_tex;
    ComPtr<ID3D11ShaderResourceView> cursor_srv;
    int cur_w = 0, cur_h = 0, cur_hx = 0, cur_hy = 0;
    bool decode_h264 = false, decode_hevc = false;
    // SRV cache keyed by (texture, slice): the decoder pool reuses a small set of surfaces.
    std::map<std::pair<ID3D11Texture2D*, UINT>, std::array<ComPtr<ID3D11ShaderResourceView>, 2>> srv_cache;
    bool srv_cache_warned = false;
};

D3D11Renderer::D3D11Renderer() : p_(std::make_unique<Impl>()) {}
D3D11Renderer::~D3D11Renderer() {
    for (auto& w : p_->windows) if (w && w->waitable) CloseHandle(w->waitable);
    p_->tiles.clear();
}

std::vector<AdapterInfo> D3D11Renderer::enumerate_adapters() {
    std::vector<AdapterInfo> out;
    ComPtr<IDXGIFactory1> f;
    if (FAILED(CreateDXGIFactory1(IID_PPV_ARGS(&f)))) return out;
    ComPtr<IDXGIAdapter1> a;
    for (UINT i = 0; f->EnumAdapters1(i, &a) != DXGI_ERROR_NOT_FOUND; ++i) {
        DXGI_ADAPTER_DESC1 d; a->GetDesc1(&d);
        AdapterInfo ai; ai.index = int(i); ai.description = d.Description; ai.vendor_id = d.VendorId; ai.device_id = d.DeviceId; ai.luid = d.AdapterLuid;
        ai.software = (d.Flags & DXGI_ADAPTER_FLAG_SOFTWARE) != 0; ai.dedicated_vram = d.DedicatedVideoMemory;
        ComPtr<IDXGIOutput> o;
        for (UINT j = 0; a->EnumOutputs(j, &o) != DXGI_ERROR_NOT_FOUND; ++j) { DXGI_OUTPUT_DESC od; o->GetDesc(&od); ai.outputs.push_back(od.DeviceName); ai.monitors.push_back(od.Monitor); o.Reset(); }
        out.push_back(std::move(ai));
        a.Reset();
    }
    return out;
}

void D3D11Renderer::init(HWND hwnd, const RendererConfig& cfg) {
    auto adapters = enumerate_adapters();
    if (adapters.empty()) throw std::runtime_error("no DXGI adapters");
    const HMONITOR mon = MonitorFromWindow(hwnd, MONITOR_DEFAULTTOPRIMARY);
    int chosen = -1;
    if (cfg.adapter_override >= 0 && cfg.adapter_override < int(adapters.size())) chosen = cfg.adapter_override;
    else {
        for (auto& a : adapters) if (!a.software) for (HMONITOR m : a.monitors) if (m == mon) { chosen = a.index; break; }
        if (chosen < 0) for (auto& a : adapters) if (!a.software && !a.monitors.empty()) { chosen = a.index; break; }
        if (chosen < 0) chosen = 0;
    }
    adapter_ = adapters[size_t(chosen)];
    for (auto& a : adapters) {
        LOG_INFO("gfx", "adapter %d: %s vendor=0x%04x device=0x%04x luid=%08x:%08x vram=%zuMB outputs=%zu%s%s", a.index, narrow(a.description).c_str(), a.vendor_id, a.device_id,
                 (unsigned)a.luid.HighPart, (unsigned)a.luid.LowPart, a.dedicated_vram >> 20, a.outputs.size(), a.software ? " [software]" : "", a.index == chosen ? "  <== selected" : "");
    }
    MONITORINFOEXW mi{}; mi.cbSize = sizeof mi; GetMonitorInfoW(mon, &mi);
    bool monitor_on_selected = false; for (HMONITOR m : adapter_.monitors) if (m == mon) monitor_on_selected = true;
    LOG_INFO("gfx", "window monitor: %s (%s the selected adapter%s)", narrow(mi.szDevice).c_str(), monitor_on_selected ? "attached to" : "NOT attached to",
             monitor_on_selected ? "; no cross-adapter presentation" : " — DWM will copy each frame across adapters (Optimus-style); use --adapter to change");

    ComPtr<IDXGIFactory1> f1;
    if (FAILED(CreateDXGIFactory1(IID_PPV_ARGS(&f1)))) throw std::runtime_error("CreateDXGIFactory1 failed");
    f1.As(&p_->factory);
    f1->EnumAdapters1(UINT(chosen), &p_->adapter);
    UINT flags = D3D11_CREATE_DEVICE_BGRA_SUPPORT | D3D11_CREATE_DEVICE_VIDEO_SUPPORT;
    if (cfg.debug_layer) flags |= D3D11_CREATE_DEVICE_DEBUG;
    const D3D_FEATURE_LEVEL levels[] = {D3D_FEATURE_LEVEL_11_1, D3D_FEATURE_LEVEL_11_0};
    HRESULT hr = D3D11CreateDevice(p_->adapter.Get(), D3D_DRIVER_TYPE_UNKNOWN, nullptr, flags, levels, 2, D3D11_SDK_VERSION, &p_->dev, &p_->feature_level, &p_->ctx);
    if (FAILED(hr) && cfg.debug_layer) hr = D3D11CreateDevice(p_->adapter.Get(), D3D_DRIVER_TYPE_UNKNOWN, nullptr, flags & ~D3D11_CREATE_DEVICE_DEBUG, levels, 2, D3D11_SDK_VERSION, &p_->dev, &p_->feature_level, &p_->ctx);
    if (FAILED(hr)) throw std::runtime_error("D3D11CreateDevice failed");
    // FFmpeg's D3D11VA path and our render thread share the immediate context; protect it.
    ComPtr<ID3D11Multithread> mt;
    if (SUCCEEDED(p_->ctx.As(&mt))) mt->SetMultithreadProtected(TRUE);

    // Decoder capability report.
    ComPtr<ID3D11VideoDevice> vd;
    if (SUCCEEDED(p_->dev.As(&vd))) {
        BOOL ok = FALSE;
        vd->CheckVideoDecoderFormat(&D3D11_DECODER_PROFILE_H264_VLD_NOFGT, DXGI_FORMAT_NV12, &ok); p_->decode_h264 = ok != 0;
        ok = FALSE;
        vd->CheckVideoDecoderFormat(&D3D11_DECODER_PROFILE_HEVC_VLD_MAIN, DXGI_FORMAT_NV12, &ok); p_->decode_hevc = ok != 0;
    }
    BOOL tearing = FALSE;
    ComPtr<IDXGIFactory5> f5;
    if (SUCCEEDED(f1.As(&f5))) f5->CheckFeatureSupport(DXGI_FEATURE_PRESENT_ALLOW_TEARING, &tearing, sizeof tearing);
    tearing_supported_ = tearing != 0;
    present_mode_ = cfg.present_mode == "lowlat" ? "lowlat" : "vsync";

    // Shaders + state.
    auto vsb = compile("vs", "vs_5_0");
    p_->dev->CreateVertexShader(vsb->GetBufferPointer(), vsb->GetBufferSize(), nullptr, &p_->vs);
    auto mk = [&](const char* e, ComPtr<ID3D11PixelShader>& out) { auto b = compile(e, "ps_5_0"); p_->dev->CreatePixelShader(b->GetBufferPointer(), b->GetBufferSize(), nullptr, &out); };
    mk("ps_nv12", p_->ps_nv12); mk("ps_planar", p_->ps_planar); mk("ps_vuyx", p_->ps_vuyx); mk("ps_cursor", p_->ps_cursor);
    D3D11_BUFFER_DESC bd{}; bd.ByteWidth = sizeof(FrameCB); bd.Usage = D3D11_USAGE_DYNAMIC; bd.BindFlags = D3D11_BIND_CONSTANT_BUFFER; bd.CPUAccessFlags = D3D11_CPU_ACCESS_WRITE;
    p_->dev->CreateBuffer(&bd, nullptr, &p_->cb);
    D3D11_SAMPLER_DESC sd{}; sd.Filter = D3D11_FILTER_MIN_MAG_MIP_LINEAR; sd.AddressU = sd.AddressV = sd.AddressW = D3D11_TEXTURE_ADDRESS_CLAMP; sd.MaxLOD = D3D11_FLOAT32_MAX;
    p_->dev->CreateSamplerState(&sd, &p_->sampler);
    D3D11_BLEND_DESC bl{}; bl.RenderTarget[0].BlendEnable = TRUE; bl.RenderTarget[0].SrcBlend = D3D11_BLEND_SRC_ALPHA; bl.RenderTarget[0].DestBlend = D3D11_BLEND_INV_SRC_ALPHA; bl.RenderTarget[0].BlendOp = D3D11_BLEND_OP_ADD;
    bl.RenderTarget[0].SrcBlendAlpha = D3D11_BLEND_ONE; bl.RenderTarget[0].DestBlendAlpha = D3D11_BLEND_INV_SRC_ALPHA; bl.RenderTarget[0].BlendOpAlpha = D3D11_BLEND_OP_ADD; bl.RenderTarget[0].RenderTargetWriteMask = D3D11_COLOR_WRITE_ENABLE_ALL;
    p_->dev->CreateBlendState(&bl, &p_->blend);
    D3D11_RASTERIZER_DESC rd{}; rd.FillMode = D3D11_FILL_SOLID; rd.CullMode = D3D11_CULL_NONE; rd.DepthClipEnable = TRUE;
    p_->dev->CreateRasterizerState(&rd, &p_->raster);

    add_window(hwnd);
    LOG_INFO("gfx", "%s", describe().c_str());
}

std::string D3D11Renderer::describe() const {
    char buf[512];
    snprintf(buf, sizeof buf, "D3D11 device: %s (vendor 0x%04x) FL=%s decode: h264=%s hevc_main=%s hevc_444=n/a(D3D11VA) present=%s tearing_supported=%s swap=FLIP_DISCARD latency=1 waitable",
             narrow(adapter_.description).c_str(), adapter_.vendor_id, p_->feature_level >= D3D_FEATURE_LEVEL_11_1 ? "11.1" : "11.0", p_->decode_h264 ? "yes" : "no", p_->decode_hevc ? "yes" : "no",
             present_mode_.c_str(), tearing_supported_ ? "yes" : "no");
    return buf;
}

GpuDevice D3D11Renderer::gpu() { return GpuDevice{p_->dev.Get(), p_->ctx.Get(), &p_->lock}; }

int D3D11Renderer::add_window(HWND hwnd) {
    auto w = std::make_unique<Window>();
    w->hwnd = hwnd;
    RECT rc; GetClientRect(hwnd, &rc);
    w->width = std::max<int>(1, rc.right - rc.left); w->height = std::max<int>(1, rc.bottom - rc.top);
    DXGI_SWAP_CHAIN_DESC1 sc{};
    sc.Width = UINT(w->width); sc.Height = UINT(w->height);
    sc.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
    sc.SampleDesc.Count = 1;
    sc.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sc.BufferCount = 2;
    sc.SwapEffect = DXGI_SWAP_EFFECT_FLIP_DISCARD;
    sc.Scaling = DXGI_SCALING_STRETCH;
    sc.AlphaMode = DXGI_ALPHA_MODE_IGNORE;
    sc.Flags = DXGI_SWAP_CHAIN_FLAG_FRAME_LATENCY_WAITABLE_OBJECT | (tearing_supported_ ? DXGI_SWAP_CHAIN_FLAG_ALLOW_TEARING : 0);
    ComPtr<IDXGISwapChain1> sc1;
    HRESULT hr = p_->factory->CreateSwapChainForHwnd(p_->dev.Get(), hwnd, &sc, nullptr, nullptr, &sc1);
    if (FAILED(hr) && (sc.Flags & DXGI_SWAP_CHAIN_FLAG_ALLOW_TEARING)) {
        LOG_WARN("gfx", "CreateSwapChainForHwnd 0x%08lx with ALLOW_TEARING; retrying without", hr);
        sc.Flags &= ~UINT(DXGI_SWAP_CHAIN_FLAG_ALLOW_TEARING); tearing_supported_ = false;
        hr = p_->factory->CreateSwapChainForHwnd(p_->dev.Get(), hwnd, &sc, nullptr, nullptr, &sc1);
    }
    if (FAILED(hr)) { char b[96]; snprintf(b, sizeof b, "CreateSwapChainForHwnd failed (0x%08lx) %dx%d", hr, w->width, w->height); throw std::runtime_error(b); }
    sc1.As(&w->swap);
    p_->factory->MakeWindowAssociation(hwnd, DXGI_MWA_NO_ALT_ENTER);
    w->swap->SetMaximumFrameLatency(1);
    w->waitable = w->swap->GetFrameLatencyWaitableObject();
    ComPtr<ID3D11Texture2D> bb; w->swap->GetBuffer(0, IID_PPV_ARGS(&bb));
    p_->dev->CreateRenderTargetView(bb.Get(), nullptr, &w->rtv);
    p_->windows.push_back(std::move(w));
    return int(p_->windows.size()) - 1;
}

void D3D11Renderer::remove_window(int id) {
    if (id < 0 || id >= int(p_->windows.size()) || !p_->windows[size_t(id)]) return;
    std::lock_guard<std::recursive_mutex> lk(p_->lock);
    auto& w = p_->windows[size_t(id)];
    if (w->waitable) CloseHandle(w->waitable);
    w.reset();
}

void D3D11Renderer::resize(int id) {
    if (id < 0 || id >= int(p_->windows.size()) || !p_->windows[size_t(id)]) return;
    auto& w = *p_->windows[size_t(id)];
    RECT rc; GetClientRect(w.hwnd, &rc);
    const int nw = std::max<int>(1, rc.right - rc.left), nh = std::max<int>(1, rc.bottom - rc.top);
    if (nw == w.width && nh == w.height) return;
    std::lock_guard<std::recursive_mutex> lk(p_->lock);
    w.rtv.Reset();
    p_->ctx->OMSetRenderTargets(0, nullptr, nullptr);
    const HRESULT hr = w.swap->ResizeBuffers(0, UINT(nw), UINT(nh), DXGI_FORMAT_UNKNOWN, DXGI_SWAP_CHAIN_FLAG_FRAME_LATENCY_WAITABLE_OBJECT | (tearing_supported_ ? DXGI_SWAP_CHAIN_FLAG_ALLOW_TEARING : 0));
    if (FAILED(hr)) { LOG_WARN("gfx", "ResizeBuffers failed 0x%08lx", hr); device_lost_ = hr == DXGI_ERROR_DEVICE_REMOVED || hr == DXGI_ERROR_DEVICE_RESET; return; }
    ComPtr<ID3D11Texture2D> bb; w.swap->GetBuffer(0, IID_PPV_ARGS(&bb));
    p_->dev->CreateRenderTargetView(bb.Get(), nullptr, &w.rtv);
    w.width = nw; w.height = nh;
}

bool D3D11Renderer::wait_can_present(int id, int timeout_ms) {
    if (id < 0 || id >= int(p_->windows.size()) || !p_->windows[size_t(id)]) return false;
    auto& w = *p_->windows[size_t(id)];
    if (w.waited) return true;
    const DWORD r = WaitForSingleObjectEx(w.waitable, DWORD(timeout_ms), TRUE);
    if (r == WAIT_OBJECT_0) { w.waited = true; return true; }
    return false;
}

void D3D11Renderer::set_canvas(int cw, int ch, int tiles) {
    std::lock_guard<std::recursive_mutex> lk(p_->lock);
    p_->canvas_w = cw; p_->canvas_h = ch; p_->ntiles = std::max(1, tiles);
    p_->slot_h = ch / p_->ntiles;
    p_->content_w = p_->content_h = 0;
    p_->tiles.clear(); p_->tiles.resize(size_t(p_->ntiles));
    p_->srv_cache.clear();
    LOG_INFO("gfx", "canvas %dx%d tiles=%d slot_h=%d", cw, ch, p_->ntiles, p_->slot_h);
}

bool D3D11Renderer::has_any_frame() const { for (auto& t : p_->tiles) if (t.frame) return true; return false; }
std::pair<int, int> D3D11Renderer::content_dims() const {
    const int cw = p_->content_w ? p_->content_w : p_->canvas_w, ch = p_->content_h ? p_->content_h : p_->canvas_h;
    return {std::min(cw, p_->canvas_w), std::min(ch, p_->canvas_h)};
}

void D3D11Renderer::submit_frame(std::unique_ptr<DecodedFrame> f) {
    if (!f || !f->frame) return;
    std::lock_guard<std::recursive_mutex> lk(p_->lock);
    if (f->tile < 0 || f->tile >= int(p_->tiles.size())) return;
    TileView& tv = p_->tiles[size_t(f->tile)];
    AVFrame* av = f->frame;
    tv.w = av->width; tv.h = av->height;
    tv.full_range = av->color_range != AVCOL_RANGE_MPEG;   // Apple's screen streams are full-range; only an explicit MPEG tag means limited
    tv.bt709 = !(av->colorspace == AVCOL_SPC_BT470BG || av->colorspace == AVCOL_SPC_SMPTE170M);
    tv.srv0.Reset(); tv.srv1.Reset(); tv.srv2.Reset();
    // Refine the tile slot height from the encoder's real (CTU-padded) picture height on the first tile.
    if (f->tile == 0 && av->height > 0 && p_->slot_h != av->height && p_->ntiles > 1) { p_->slot_h = av->height; LOG_INFO("gfx", "slot_h refined to %d from tile 0", av->height); }
    if (p_->ntiles == 1) p_->slot_h = av->height;
    const int origin_y = f->tile * p_->slot_h;
    const int rows = std::min(av->height, std::max(0, p_->canvas_h - origin_y));
    if (av->width > p_->content_w) p_->content_w = av->width;
    if (origin_y + rows > p_->content_h) p_->content_h = origin_y + rows;

    if (av->format == AV_PIX_FMT_D3D11) {
        auto* tex = reinterpret_cast<ID3D11Texture2D*>(av->data[0]);
        const UINT slice = UINT(reinterpret_cast<intptr_t>(av->data[1]));
        D3D11_TEXTURE2D_DESC td; tex->GetDesc(&td);
        const bool can_srv = (td.BindFlags & D3D11_BIND_SHADER_RESOURCE) != 0;
        ID3D11Texture2D* src = tex; UINT src_slice = slice;
        if (!can_srv) {
            // Fallback: one GPU→GPU copy into an SRV-capable texture (never a CPU readback).
            if (!tv.owned) {
                D3D11_TEXTURE2D_DESC od = td; od.ArraySize = 1; od.BindFlags = D3D11_BIND_SHADER_RESOURCE; od.MiscFlags = 0; od.Usage = D3D11_USAGE_DEFAULT; od.CPUAccessFlags = 0;
                p_->dev->CreateTexture2D(&od, nullptr, &tv.owned);
            }
            p_->ctx->CopySubresourceRegion(tv.owned.Get(), 0, 0, 0, 0, tex, slice, nullptr);
            src = tv.owned.Get(); src_slice = 0;
            ++tel_.frames_gpu_copy;
        } else {
            ++tel_.frames_zero_copy;
        }
        auto key = std::make_pair(src, src_slice);
        auto it = p_->srv_cache.find(key);
        if (it == p_->srv_cache.end() || !can_srv) {
            std::array<ComPtr<ID3D11ShaderResourceView>, 2> v;
            D3D11_SHADER_RESOURCE_VIEW_DESC sv{};
            sv.ViewDimension = D3D11_SRV_DIMENSION_TEXTURE2DARRAY;
            sv.Texture2DArray.MostDetailedMip = 0; sv.Texture2DArray.MipLevels = 1; sv.Texture2DArray.FirstArraySlice = src_slice; sv.Texture2DArray.ArraySize = 1;
            if (td.Format == DXGI_FORMAT_NV12) {
                sv.Format = DXGI_FORMAT_R8_UNORM; p_->dev->CreateShaderResourceView(src, &sv, &v[0]);
                sv.Format = DXGI_FORMAT_R8G8_UNORM; p_->dev->CreateShaderResourceView(src, &sv, &v[1]);
                tv.layout = Layout::Nv12;
            } else if (td.Format == DXGI_FORMAT_AYUV) {
                sv.Format = DXGI_FORMAT_R8G8B8A8_UNORM; p_->dev->CreateShaderResourceView(src, &sv, &v[0]);
                tv.layout = Layout::Vuyx;
            } else {
                if (!p_->srv_cache_warned) { p_->srv_cache_warned = true; LOG_ERROR("gfx", "unsupported hardware surface format %d", int(td.Format)); }
                tv.layout = Layout::None;
            }
            if (can_srv) { if (p_->srv_cache.size() > 64) p_->srv_cache.clear(); it = p_->srv_cache.emplace(key, v).first; }
            tv.srv0 = v[0]; tv.srv1 = v[1];
        } else {
            tv.layout = td.Format == DXGI_FORMAT_NV12 ? Layout::Nv12 : Layout::Vuyx;
            tv.srv0 = it->second[0]; tv.srv1 = it->second[1];
        }
    } else {
        // SOFTWARE frame: CPU upload through a dynamic texture. Counted; never the performance path.
        ++tel_.frames_uploaded_cpu;
        const AVPixFmtDescriptor* desc = av_pix_fmt_desc_get(AVPixelFormat(av->format));
        const bool nv12 = av->format == AV_PIX_FMT_NV12;
        const bool planar = desc && desc->nb_components == 3 && !(desc->flags & AV_PIX_FMT_FLAG_RGB) && desc->comp[0].depth == 8;
        if (!nv12 && !planar) { static bool warned = false; if (!warned) { warned = true; LOG_ERROR("gfx", "unsupported software pixel format %s", desc ? desc->name : "?"); } tv.layout = Layout::None; tv.frame = std::move(f); return; }
        struct Plane { int w, h; DXGI_FORMAT fmt; };
        Plane planes[3];
        const int cw = nv12 ? (av->width + 1) / 2 : -((-av->width) >> desc->log2_chroma_w), chh = nv12 ? (av->height + 1) / 2 : -((-av->height) >> desc->log2_chroma_h);
        int np;
        if (nv12) { planes[0] = {av->width, av->height, DXGI_FORMAT_R8_UNORM}; planes[1] = {cw, chh, DXGI_FORMAT_R8G8_UNORM}; np = 2; tv.layout = Layout::Nv12; }
        else { planes[0] = {av->width, av->height, DXGI_FORMAT_R8_UNORM}; planes[1] = {cw, chh, DXGI_FORMAT_R8_UNORM}; planes[2] = {cw, chh, DXGI_FORMAT_R8_UNORM}; np = 3; tv.layout = Layout::Planar; }
        static ComPtr<ID3D11Texture2D> sw_tex[8][3];
        static ComPtr<ID3D11ShaderResourceView> sw_srv[8][3];
        static int sw_dims[8][3][2];
        const int ti = f->tile & 7;
        for (int i = 0; i < np; ++i) {
            if (!sw_tex[ti][i] || sw_dims[ti][i][0] != planes[i].w || sw_dims[ti][i][1] != planes[i].h) {
                D3D11_TEXTURE2D_DESC d{}; d.Width = UINT(planes[i].w); d.Height = UINT(planes[i].h); d.MipLevels = 1; d.ArraySize = 1; d.Format = planes[i].fmt; d.SampleDesc.Count = 1;
                d.Usage = D3D11_USAGE_DYNAMIC; d.BindFlags = D3D11_BIND_SHADER_RESOURCE; d.CPUAccessFlags = D3D11_CPU_ACCESS_WRITE;
                sw_tex[ti][i].Reset(); sw_srv[ti][i].Reset();
                p_->dev->CreateTexture2D(&d, nullptr, &sw_tex[ti][i]);
                D3D11_SHADER_RESOURCE_VIEW_DESC sv{}; sv.Format = planes[i].fmt; sv.ViewDimension = D3D11_SRV_DIMENSION_TEXTURE2DARRAY; sv.Texture2DArray.MipLevels = 1; sv.Texture2DArray.ArraySize = 1;
                p_->dev->CreateShaderResourceView(sw_tex[ti][i].Get(), &sv, &sw_srv[ti][i]);
                sw_dims[ti][i][0] = planes[i].w; sw_dims[ti][i][1] = planes[i].h;
            }
            D3D11_MAPPED_SUBRESOURCE m;
            if (SUCCEEDED(p_->ctx->Map(sw_tex[ti][i].Get(), 0, D3D11_MAP_WRITE_DISCARD, 0, &m))) {
                const int bpp = planes[i].fmt == DXGI_FORMAT_R8G8_UNORM ? 2 : 1;
                const size_t row = size_t(planes[i].w) * size_t(bpp);
                for (int y = 0; y < planes[i].h; ++y) std::memcpy(static_cast<uint8_t*>(m.pData) + size_t(y) * m.RowPitch, av->data[i] + ptrdiff_t(y) * av->linesize[i], row);
                p_->ctx->Unmap(sw_tex[ti][i].Get(), 0);
            }
        }
        tv.srv0 = sw_srv[ti][0]; tv.srv1 = sw_srv[ti][1]; tv.srv2 = np == 3 ? sw_srv[ti][2] : nullptr;
    }
    tv.frame = std::move(f);   // releases the previous frame's surface back to the decoder pool
}

void D3D11Renderer::set_crop(int id, std::optional<CropRect> crop) { if (id >= 0 && id < int(p_->windows.size()) && p_->windows[size_t(id)]) p_->windows[size_t(id)]->crop = crop; }

CropRect D3D11Renderer::effective_crop(int id) const {
    auto [cw, ch] = content_dims();
    CropRect r{0, 0, cw, ch};
    if (id >= 0 && id < int(p_->windows.size()) && p_->windows[size_t(id)] && p_->windows[size_t(id)]->crop) {
        const CropRect& c = *p_->windows[size_t(id)]->crop;
        r.x = std::clamp(c.x, 0, cw); r.y = std::clamp(c.y, 0, ch);
        r.w = std::max(1, std::min(c.w, cw - r.x)); r.h = std::max(1, std::min(c.h, ch - r.y));
    }
    return r;
}

void D3D11Renderer::set_cursor_image(const CursorImage& img) {
    if (img.w <= 0 || img.h <= 0 || img.rgba.size() < size_t(img.w) * size_t(img.h) * 4) return;
    std::lock_guard<std::recursive_mutex> lk(p_->lock);
    D3D11_TEXTURE2D_DESC d{}; d.Width = UINT(img.w); d.Height = UINT(img.h); d.MipLevels = 1; d.ArraySize = 1; d.Format = DXGI_FORMAT_R8G8B8A8_UNORM; d.SampleDesc.Count = 1;
    d.Usage = D3D11_USAGE_IMMUTABLE; d.BindFlags = D3D11_BIND_SHADER_RESOURCE;
    D3D11_SUBRESOURCE_DATA sd{img.rgba.data(), UINT(img.w * 4), 0};
    ComPtr<ID3D11Texture2D> t;
    if (FAILED(p_->dev->CreateTexture2D(&d, &sd, &t))) return;
    p_->cursor_srv.Reset();
    p_->dev->CreateShaderResourceView(t.Get(), nullptr, &p_->cursor_srv);
    p_->cursor_tex = t;
    p_->cur_w = img.w; p_->cur_h = img.h; p_->cur_hx = img.hx; p_->cur_hy = img.hy;
    cursor_tex_ = p_->cursor_tex.Get();
}

void D3D11Renderer::clear_cursor() { std::lock_guard<std::recursive_mutex> lk(p_->lock); p_->cursor_tex.Reset(); p_->cursor_srv.Reset(); cursor_tex_ = nullptr; }
void D3D11Renderer::set_cursor_pos(int id, std::optional<std::pair<int, int>> xy) { if (id >= 0 && id < int(p_->windows.size()) && p_->windows[size_t(id)]) p_->windows[size_t(id)]->cursor = xy; }

bool D3D11Renderer::draw(int id, int64_t now) {
    if (device_lost_) return false;
    if (id < 0 || id >= int(p_->windows.size()) || !p_->windows[size_t(id)]) return false;
    Window& w = *p_->windows[size_t(id)];
    const int64_t t0 = now_ns();
    std::lock_guard<std::recursive_mutex> lk(p_->lock);   // serialise with FFmpeg's D3D11VA submits
    ID3D11DeviceContext* c = p_->ctx.Get();
    const float clear[4] = {0, 0, 0, 1};
    c->ClearRenderTargetView(w.rtv.Get(), clear);
    ID3D11RenderTargetView* rtvs[] = {w.rtv.Get()};
    c->OMSetRenderTargets(1, rtvs, nullptr);
    D3D11_VIEWPORT vp{0, 0, float(w.width), float(w.height), 0, 1};
    c->RSSetViewports(1, &vp);
    c->RSSetState(p_->raster.Get());
    c->IASetPrimitiveTopology(D3D11_PRIMITIVE_TOPOLOGY_TRIANGLESTRIP);
    c->IASetInputLayout(nullptr);
    c->VSSetShader(p_->vs.Get(), nullptr, 0);
    ID3D11Buffer* cbs[] = {p_->cb.Get()};
    c->VSSetConstantBuffers(0, 1, cbs); c->PSSetConstantBuffers(0, 1, cbs);
    ID3D11SamplerState* ss[] = {p_->sampler.Get()};
    c->PSSetSamplers(0, 1, ss);
    c->OMSetBlendState(nullptr, nullptr, 0xffffffff);

    const CropRect crop = effective_crop(id);
    int64_t newest_out = 0, newest_au = 0;
    for (int ti = 0; ti < int(p_->tiles.size()); ++ti) {
        TileView& tv = p_->tiles[size_t(ti)];
        if (!tv.frame || tv.layout == Layout::None || !tv.srv0) continue;
        // Rows of this tile in canvas space, intersected with the crop.
        const int ty0 = ti * p_->slot_h, ty1 = std::min(ty0 + tv.h, p_->canvas_h);
        const int y0 = std::max(ty0, crop.y), y1 = std::min(ty1, crop.y + crop.h);
        if (y1 <= y0) continue;
        const int x0 = crop.x, x1 = std::min(crop.x + crop.w, tv.w);
        if (x1 <= x0) continue;
        FrameCB cb{};
        // Destination in NDC (crop fills the window per-axis, like the reference renderer).
        const float fx0 = float(x0 - crop.x) / float(crop.w), fx1 = float(x1 - crop.x) / float(crop.w);
        const float fy0 = float(y0 - crop.y) / float(crop.h), fy1 = float(y1 - crop.y) / float(crop.h);
        cb.dst[0] = fx0 * 2 - 1; cb.dst[2] = fx1 * 2 - 1; cb.dst[1] = 1 - fy0 * 2; cb.dst[3] = 1 - fy1 * 2;
        cb.src[0] = float(x0) / float(tv.w); cb.src[2] = float(x1) / float(tv.w);
        cb.src[1] = float(y0 - ty0) / float(tv.h); cb.src[3] = float(y1 - ty0) / float(tv.h);
        // Range + matrix (BT.709 / BT.601, full or limited), matching the reference's full-range default.
        const float kr = tv.bt709 ? 0.2126f : 0.299f, kb = tv.bt709 ? 0.0722f : 0.114f, kg = 1.0f - kr - kb;
        const float yscale = tv.full_range ? 1.0f : 255.0f / 219.0f, cscale = tv.full_range ? 1.0f : 255.0f / 224.0f;
        cb.luma_xf[0] = yscale; cb.luma_xf[1] = tv.full_range ? 0.0f : 16.0f / 255.0f; cb.luma_xf[2] = 128.0f / 255.0f;
        cb.m0[0] = 1; cb.m0[1] = 0; cb.m0[2] = 2 * (1 - kr) * cscale;
        cb.m1[0] = 1; cb.m1[1] = -2 * (1 - kb) * kb / kg * cscale; cb.m1[2] = -2 * (1 - kr) * kr / kg * cscale;
        cb.m2[0] = 1; cb.m2[1] = 2 * (1 - kb) * cscale; cb.m2[2] = 0;
        D3D11_MAPPED_SUBRESOURCE m;
        if (SUCCEEDED(c->Map(p_->cb.Get(), 0, D3D11_MAP_WRITE_DISCARD, 0, &m))) { std::memcpy(m.pData, &cb, sizeof cb); c->Unmap(p_->cb.Get(), 0); }
        ID3D11ShaderResourceView* srvs[3] = {tv.srv0.Get(), tv.srv1.Get(), tv.srv2.Get()};
        c->PSSetShaderResources(0, tv.layout == Layout::Planar ? 3 : 2, srvs);
        c->PSSetShader(tv.layout == Layout::Nv12 ? p_->ps_nv12.Get() : tv.layout == Layout::Planar ? p_->ps_planar.Get() : p_->ps_vuyx.Get(), nullptr, 0);
        c->Draw(4, 0);
        newest_out = std::max(newest_out, tv.frame->t_output_ns);
        newest_au = std::max(newest_au, tv.frame->t_au_complete_ns);
    }
    // Cursor overlay at the pointer position (canvas texels → window), scaled with the video.
    if (p_->cursor_srv && w.cursor) {
        const float sclx = float(w.width) / float(crop.w), scly = float(w.height) / float(crop.h);
        const float d = std::min(sclx, scly) * cursor_scale_;
        const float px = float(w.cursor->first - crop.x) * sclx, py = float(w.cursor->second - crop.y) * scly;
        const float sx = px - float(p_->cur_hx) * d, sy = py - float(p_->cur_hy) * d;
        const float sw = float(p_->cur_w) * d, sh = float(p_->cur_h) * d;
        FrameCB cb{};
        cb.dst[0] = sx / float(w.width) * 2 - 1; cb.dst[2] = (sx + sw) / float(w.width) * 2 - 1;
        cb.dst[1] = 1 - sy / float(w.height) * 2; cb.dst[3] = 1 - (sy + sh) / float(w.height) * 2;
        cb.src[0] = 0; cb.src[1] = 0; cb.src[2] = 1; cb.src[3] = 1;
        D3D11_MAPPED_SUBRESOURCE m;
        if (SUCCEEDED(c->Map(p_->cb.Get(), 0, D3D11_MAP_WRITE_DISCARD, 0, &m))) { std::memcpy(m.pData, &cb, sizeof cb); c->Unmap(p_->cb.Get(), 0); }
        ID3D11ShaderResourceView* srvs[1] = {p_->cursor_srv.Get()};
        c->PSSetShaderResources(0, 1, srvs);
        c->PSSetShader(p_->ps_cursor.Get(), nullptr, 0);
        c->OMSetBlendState(p_->blend.Get(), nullptr, 0xffffffff);
        c->Draw(4, 0);
        c->OMSetBlendState(nullptr, nullptr, 0xffffffff);
    }
    ID3D11ShaderResourceView* nulls[3] = {nullptr, nullptr, nullptr};
    c->PSSetShaderResources(0, 3, nulls);

    const bool lowlat = present_mode_ == "lowlat";
    const UINT flags = lowlat && tearing_supported_ ? DXGI_PRESENT_ALLOW_TEARING : 0;
    const int64_t t_present = now_ns();
    const HRESULT hr = w.swap->Present(lowlat ? 0 : 1, flags);
    w.waited = false;
    tel_.draw_cpu_ms.add(double(t_present - t0) / 1e6);
    if (newest_out) tel_.ready_to_present_ms.add(double(t_present - newest_out) / 1e6);
    if (newest_au) tel_.au_to_present_ms.add(double(t_present - newest_au) / 1e6);
    if (w.last_present_ns) tel_.present_interval_ms.add(double(t_present - w.last_present_ns) / 1e6);
    w.last_present_ns = t_present;
    ++tel_.presents;
    (void)now;
    if (hr == DXGI_ERROR_DEVICE_REMOVED || hr == DXGI_ERROR_DEVICE_RESET) { device_lost_ = true; LOG_ERROR("gfx", "GPU device lost (0x%08lx) — closing viewer", hr); return false; }
    return true;
}

}  // namespace scshr
