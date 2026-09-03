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

# libssh2 (static, OpenSSL backend) — pairing wizard only. Built by tools/fetch_deps.ps1.
set(LIBSSH2_ROOT "${CMAKE_SOURCE_DIR}/third_party/libssh2" CACHE PATH "libssh2 static install (include/ + lib/libssh2.lib)")
if(NOT EXISTS "${LIBSSH2_ROOT}/lib/libssh2.lib")
  message(WARNING "libssh2 missing: ${LIBSSH2_ROOT}/lib/libssh2.lib (run tools/fetch_deps.ps1); scshr.exe will not link")
endif()
add_library(libssh2::libssh2 STATIC IMPORTED)
set_target_properties(libssh2::libssh2 PROPERTIES
  IMPORTED_LOCATION "${LIBSSH2_ROOT}/lib/libssh2.lib"
  INTERFACE_INCLUDE_DIRECTORIES "${LIBSSH2_ROOT}/include")

# fdk-aac (shared DLL, built from source with MSVC by tools/fetch_deps.ps1) — AAC-ELD audio.
set(FDKAAC_DLL "${CMAKE_SOURCE_DIR}/third_party/fdk-aac/bin/fdk-aac.dll" CACHE FILEPATH "fdk-aac.dll to bundle")

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

# ── application pieces shared by scshr.exe and the tests (everything but main/gui/viewer) ──
add_library(scshr_app STATIC
  src/app/tunnel_cli.cpp
  src/app/settings.cpp
  src/app/ssh_client.cpp
  src/app/setup.cpp
  src/tunnel/win_tunnel.cpp
)
target_link_libraries(scshr_app PUBLIC scshr_core libssh2::libssh2 shell32 shcore iphlpapi crypt32 advapi32 ole32)
# WireGuardNT's adapter API header: status is read from the driver, not a userspace-API pipe.
target_include_directories(scshr_app PUBLIC "${CMAKE_SOURCE_DIR}/third_party/wireguard")

# GUI subsystem (no console flashes for double-click launches); CLI use re-attaches to the parent
# console (see src/app/main.cpp). comctl32 v6 + per-monitor DPI + requireAdministrator come from
# the manifest embedded through scshr.rc.
add_executable(scshr WIN32
  src/app/main.cpp src/app/viewer.cpp src/app/gui.cpp
  src/app/window.cpp src/app/input.cpp src/app/keyboard_hook.cpp src/app/local_clipboard.cpp
  src/app/scshr.rc)
target_link_libraries(scshr PRIVATE scshr_media scshr_app comctl32 winmm)
# The process manifest is embedded by scshr.rc (RT_MANIFEST 1); stop the linker from adding a second one.
target_link_options(scshr PRIVATE /ENTRY:mainCRTStartup /MANIFEST:NO)

# macOS helper bundle (script + Go tunnel daemon for arm64/amd64), uploaded to the Mac by the wizard.
set(MAC_HELPER_DIR "${CMAKE_SOURCE_DIR}/third_party/mac")
set(MAC_HELPER_FILES
  "${CMAKE_SOURCE_DIR}/tools/scshr-macos-tunnel.sh"
  "${MAC_HELPER_DIR}/scshr-tunnel-darwin-arm64"
  "${MAC_HELPER_DIR}/scshr-tunnel-darwin-amd64")
if(EXISTS "${MAC_HELPER_DIR}/scshr-tunnel-darwin-arm64" AND EXISTS "${MAC_HELPER_DIR}/scshr-tunnel-darwin-amd64")
  # A real dependency (not POST_BUILD): an edited script or a rebuilt helper must be restaged even
  # when scshr.exe itself does not relink.
  set(MAC_STAGE_DIR "${CMAKE_BINARY_DIR}/mac")
  set(MAC_STAGED_FILES)
  foreach(f ${MAC_HELPER_FILES})
    get_filename_component(name "${f}" NAME)
    add_custom_command(OUTPUT "${MAC_STAGE_DIR}/${name}"
      COMMAND ${CMAKE_COMMAND} -E make_directory "${MAC_STAGE_DIR}"
      COMMAND ${CMAKE_COMMAND} -E copy_if_different "${f}" "${MAC_STAGE_DIR}/${name}"
      DEPENDS "${f}" COMMENT "staging mac/${name}")
    list(APPEND MAC_STAGED_FILES "${MAC_STAGE_DIR}/${name}")
  endforeach()
  add_custom_target(scshr_mac_bundle ALL DEPENDS ${MAC_STAGED_FILES})
  add_dependencies(scshr scshr_mac_bundle)
else()
  message(WARNING "macOS tunnel helper missing under ${MAC_HELPER_DIR}: run tools/fetch_deps.ps1 (cross-compiles tools/mac-tunnel with Go); the mac/ bundle will not be staged")
endif()
if(EXISTS "${FDKAAC_DLL}")
  add_custom_command(TARGET scshr POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different "${FDKAAC_DLL}" $<TARGET_FILE_DIR:scshr>)
else()
  message(WARNING "fdk-aac.dll missing (${FDKAAC_DLL}): audio will be disabled at runtime until tools/fetch_deps.ps1 has built it")
endif()

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
add_executable(scshr_inputprobe tools/inputprobe.cpp)
target_link_libraries(scshr_inputprobe PRIVATE scshr_media)
target_link_options(scshr_inputprobe PRIVATE /DEBUG:NONE)   # diagnostic tool; LTCG PDB limit (LNK1140)
add_executable(scshr_bench tools/bench.cpp)
target_link_libraries(scshr_bench PRIVATE scshr_core)
add_executable(scshr_vectors tools/vectors.cpp)
target_link_libraries(scshr_vectors PRIVATE scshr_core)

# ── tests ─────────────────────────────────────────────────────────────────
add_executable(scshr_tests tests/test_main.cpp tests/test_crypto.cpp tests/test_protocol.cpp tests/test_media.cpp tests/test_tunnel.cpp tests/test_setup.cpp)
target_link_libraries(scshr_tests PRIVATE scshr_app)
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
