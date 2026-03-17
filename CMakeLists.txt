cmake_minimum_required(VERSION 3.13)

# ── Pico SDK ──────────────────────────────────────────────────────────────────
include(pico_sdk_import.cmake)

project(ward3n C CXX ASM)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

# Tell mbedTLS where our config file lives (must be before pico_sdk_init)
set(PICO_MBEDTLS_CONFIG_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mbedtls_config.h")

pico_sdk_init()

# ── PIO for WS2812 NeoPixel ───────────────────────────────────────────────────
add_library(ws2812_pio INTERFACE)
pico_generate_pio_header(ws2812_pio ${CMAKE_CURRENT_SOURCE_DIR}/ws2812.pio
    OUTPUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/generated)

# ── Main firmware target ───────────────────────────────────────────────────────
add_executable(ward3n
    src/main.c
    src/usb_descriptors.c
    src/ccid.c
    src/piv.c
    src/apdu.c
    src/crypto_backend_soft.c
    src/button.c
    src/neopixel.c
    src/device_state.c
)

target_include_directories(ward3n PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}           # tusb_config.h, mbedtls_config.h
    ${CMAKE_CURRENT_BINARY_DIR}/generated # ws2812.pio.h
)

target_link_libraries(ward3n
    pico_stdlib
    pico_unique_id
    hardware_flash
    hardware_sync
    hardware_pio
    hardware_clocks
    tinyusb_device
    tinyusb_board
    pico_mbedtls
    ws2812_pio
)

# Stack lives in SCRATCH_Y (hard 4 KB limit on RP2040).
# mbedTLS allocates its workspace from the heap, not the stack.
# Heap is in main SRAM; 48 KB gives mbedTLS x509write plenty of room.
target_compile_definitions(ward3n PRIVATE
    PICO_STACK_SIZE=4096
    PICO_HEAP_SIZE=49152
)

# USB device pull-up fix for RP2040 A2 silicon
target_compile_definitions(ward3n PRIVATE
    PICO_RP2040_USB_DEVICE_ENUMERATION_FIX=1
)

pico_add_extra_outputs(ward3n)

# Optionally send stdio over USB-CDC for debug (disable for production)
# pico_enable_stdio_usb(ward3n 1)
pico_enable_stdio_uart(ward3n 0)
