cmake_minimum_required(VERSION 3.25)
project(scshr LANGUAGES CXX C)

# Native Windows iShareScreen client. Reproducible build:
#   * FFmpeg: pinned BtbN autobuild (see third_party/README.md) under third_party/ffmpeg
#   * OpenSSL 3.x: Shining Light install (C:/Program Files/OpenSSL-Win64) or -DOPENSSL_ROOT
#   * miniz 3.0.2 vendored (third_party/miniz)
#   * Windows SDK: D3D11 / DXGI / Winsock / WASAPI

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

if(NOT WIN32)
  message(FATAL_ERROR "scshr targets Windows (D3D11VA / DXGI / Winsock).")
endif()

set(FFMPEG_ROOT "${CMAKE_SOURCE_DIR}/third_party/ffmpeg" CACHE PATH "FFmpeg shared dev tree")
set(OPENSSL_ROOT "C:/Program Files/OpenSSL-Win64" CACHE PATH "OpenSSL 3 install root")

foreach(lib avcodec avutil swscale)
  if(NOT EXISTS "${FFMPEG_ROOT}/lib/${lib}.lib")
    message(FATAL_ERROR "FFmpeg import lib missing: ${FFMPEG_ROOT}/lib/${lib}.lib (run tools/fetch_deps.ps1)")
  endif()
endforeach()
if(NOT EXISTS "${OPENSSL_ROOT}/lib/VC/x64/MD/libcrypto.lib")
  message(FATAL_ERROR "OpenSSL libcrypto.lib not found under ${OPENSSL_ROOT}/lib/VC/x64/MD")
endif()

add_library(ffmpeg::avcodec SHARED IMPORTED)
set_target_properties(ffmpeg::avcodec PROPERTIES
  IMPORTED_IMPLIB "${FFMPEG_ROOT}/lib/avcodec.lib"
  IMPORTED_LOCATION "${FFMPEG_ROOT}/bin/avcodec-63.dll"
  INTERFACE_INCLUDE_DIRECTORIES "${FFMPEG_ROOT}/include")
add_library(ffmpeg::avutil SHARED IMPORTED)
set_target_properties(ffmpeg::avutil PROPERTIES
  IMPORTED_IMPLIB "${FFMPEG_ROOT}/lib/avutil.lib"
  IMPORTED_LOCATION "${FFMPEG_ROOT}/bin/avutil-61.dll"
  INTERFACE_INCLUDE_DIRECTORIES "${FFMPEG_ROOT}/include")
add_library(ffmpeg::swscale SHARED IMPORTED)
set_target_properties(ffmpeg::swscale PROPERTIES
  IMPORTED_IMPLIB "${FFMPEG_ROOT}/lib/swscale.lib"
  IMPORTED_LOCATION "${FFMPEG_ROOT}/bin/swscale-10.dll"
  INTERFACE_INCLUDE_DIRECTORIES "${FFMPEG_ROOT}/include")

add_library(openssl::crypto SHARED IMPORTED)
set_target_properties(openssl::crypto PROPERTIES
  IMPORTED_IMPLIB "${OPENSSL_ROOT}/lib/VC/x64/MD/libcrypto.lib"
  IMPORTED_LOCATION "${OPENSSL_ROOT}/bin/libcrypto-3-x64.dll"
  INTERFACE_INCLUDE_DIRECTORIES "${OPENSSL_ROOT}/include")

add_library(miniz STATIC third_party/miniz/miniz.c)
target_include_directories(miniz PUBLIC third_party/miniz)
target_compile_definitions(miniz PUBLIC MINIZ_NO_ARCHIVE_APIS MINIZ_NO_STDIO MINIZ_NO_TIME)

add_compile_definitions(WIN32_LEAN_AND_MEAN NOMINMAX _CRT_SECURE_NO_WARNINGS _WIN32_WINNT=0x0A00 UNICODE _UNICODE)
add_compile_options(/W4 /permissive- /Zc:__cplusplus /utf-8 /EHsc /Zi /MP)
add_compile_options("$<$<CONFIG:Release>:/O2>" "$<$<CONFIG:Release>:/Oi>" "$<$<CONFIG:Release>:/GL>")
add_link_options("$<$<CONFIG:Release>:/LTCG>" "$<$<CONFIG:Release>:/DEBUG>" "$<$<CONFIG:Release>:/OPT:REF>")

# ── core: protocol + packet path (no FFmpeg / D3D dependency) ─────────────
add_library(scshr_core STATIC
  src/common/log.cpp
  src/common/clock.cpp
  src/crypto/crypto.cpp
  src/crypto/srtp.cpp
  src/protocol/record_layer.cpp
  src/protocol/rfb.cpp
  src/protocol/auth.cpp
  src/protocol/bplist.cpp
  src/protocol/offers.cpp
  src/protocol/rtcp.cpp
  src/protocol/clipboard.cpp
  src/protocol/negotiation.cpp
  src/media/nalu.cpp
  src/media/hevc_rps.cpp
  src/media/avc_util.cpp
  src/media/rtp_assembler.cpp
  src/media/quality_gate.cpp
  src/media/burst.cpp
  src/net/udp.cpp
  src/net/tcp.cpp
  src/tunnel/pairing.cpp
  src/tunnel/wgconfig.cpp
)
target_include_directories(scshr_core PUBLIC src ${CMAKE_SOURCE_DIR})
target_link_libraries(scshr_core PUBLIC openssl::crypto miniz ws2_32)

# ── media: FFmpeg decode + D3D11 presentation ────────────────────────────
add_library(scshr_media STATIC
  src/media/decoder.cpp
  src/gfx/d3d11_renderer.cpp
  src/session/session.cpp
  src/app/audio.cpp
)
target_link_libraries(scshr_media PUBLIC scshr_core ffmpeg::avcodec ffmpeg::avutil ffmpeg::swscale d3d11 dxgi dxguid d3dcompiler user32 gdi32 ole32 avrt)

add_executable(scshr src/app/main.cpp src/app/window.cpp src/app/input.cpp src/app/keyboard_hook.cpp src/app/local_clipboard.cpp
               src/app/tunnel_cli.cpp src/tunnel/win_tunnel.cpp)
target_link_libraries(scshr PRIVATE scshr_media shell32 shcore winmm iphlpapi crypt32 advapi32)
# WireGuardNT's adapter API header: status is read from the driver, not a userspace-API pipe.
target_include_directories(scshr PRIVATE "${CMAKE_SOURCE_DIR}/third_party/wireguard")

# Bundled WireGuard components (pinned; see third_party/README.md). Copied next to scshr.exe so the
# tunnel service can load them from the executable directory.
set(WIREGUARD_DIR "${CMAKE_SOURCE_DIR}/third_party/wireguard")
if(EXISTS "${WIREGUARD_DIR}/tunnel.dll" AND EXISTS "${WIREGUARD_DIR}/wireguard.dll")
  add_custom_command(TARGET scshr POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
      "${WIREGUARD_DIR}/tunnel.dll" "${WIREGUARD_DIR}/wireguard.dll" $<TARGET_FILE_DIR:scshr>)
else()
  message(WARNING "WireGuard components missing under ${WIREGUARD_DIR}: `scshr init` will refuse to run until tools/fetch_deps.ps1 has produced tunnel.dll + wireguard.dll")
endif()

# ── tools ─────────────────────────────────────────────────────────────────
add_executable(scshr_replay tools/replay.cpp)
target_link_libraries(scshr_replay PRIVATE scshr_media)
add_executable(scshr_synth tools/synth.cpp)
target_link_libraries(scshr_synth PRIVATE scshr_core)
add_executable(scshr_sender tools/sender.cpp)
target_link_libraries(scshr_sender PRIVATE scshr_core winmm)
add_executable(scshr_bench tools/bench.cpp)
target_link_libraries(scshr_bench PRIVATE scshr_core)
add_executable(scshr_vectors tools/vectors.cpp)
target_link_libraries(scshr_vectors PRIVATE scshr_core)

# ── tests ─────────────────────────────────────────────────────────────────
add_executable(scshr_tests tests/test_main.cpp tests/test_crypto.cpp tests/test_protocol.cpp tests/test_media.cpp tests/test_tunnel.cpp)
target_link_libraries(scshr_tests PRIVATE scshr_core)
enable_testing()
add_test(NAME unit COMMAND scshr_tests)

# Copy runtime DLLs next to every executable.
foreach(tgt scshr scshr_replay scshr_tests scshr_synth scshr_sender scshr_bench scshr_vectors)
  add_custom_command(TARGET ${tgt} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
      "${FFMPEG_ROOT}/bin/avcodec-63.dll" "${FFMPEG_ROOT}/bin/avutil-61.dll" "${FFMPEG_ROOT}/bin/swscale-10.dll"
      "${FFMPEG_ROOT}/bin/swresample-7.dll"
      "${OPENSSL_ROOT}/bin/libcrypto-3-x64.dll"
      $<TARGET_FILE_DIR:${tgt}>)
endforeach()
