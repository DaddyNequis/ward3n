# ward3n

A real, compilable PIV security key firmware for the **RP2040 Zero** built with C, Pico SDK 2.x, TinyUSB, and mbedTLS 3.x. It enumerates as a USB CCID smart card reader/card combo and implements a functional subset of NIST SP 800-73-4 (PIV) sufficient for macOS smart card authentication.

---

## Design constraints

| Constraint | Decision |
|---|---|
| No HID keyboard | USB class is CCID only (0x0B) |
| No password injection | No HID at all |
| No Arduino / PlatformIO | Pure C + CMake + Pico SDK |
| No Touch ID emulation | Works alongside macOS's native biometrics |
| Physical user-presence button | GPIO 23, active-low with pull-up |
| Onboard NeoPixel feedback | GPIO 16, PIO-driven WS2812 |
| No secure element (yet) | Temporary P-256 private key in software (mbedTLS) |
| Swappable crypto backend | `crypto_backend.h` abstract interface — drop in SE050 or ATECC608 later |

---

## 1 — System architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                       RP2040 (USB FS, 125 MHz)                   │
│                                                                  │
│  ┌──────────┐    ┌──────────┐    ┌────────────────────────────┐ │
│  │  Button   │    │NeoPixel  │    │      Flash Storage          │ │
│  │ GPIO 23   │    │ GPIO 16  │    │  P-256 key pair + cert DER  │ │
│  │ PullUp    │    │  PIO SM  │    │  (last 4 KB flash sector)   │ │
│  └────┬──────┘    └────┬─────┘    └──────────────┬─────────────┘ │
│       │                │                          │               │
│  ┌────▼────────────────▼──────────────────────────▼────────────┐ │
│  │                    device_state.c                             │ │
│  │    IDLE → WAITING_BUTTON → AUTHORIZED → PROCESSING           │ │
│  └────────────────────────────┬──────────────────────────────── ┘ │
│                                │                                  │
│  ┌─────────────────────────────▼──────────────────────────────┐  │
│  │                TinyUSB (bare-metal, polled)                  │  │
│  │  ┌─────────────────────────────────────────────────────┐   │  │
│  │  │            CCID Custom Class Driver                   │   │  │
│  │  │  EP1 OUT Bulk  ← PC_to_RDR_XfrBlock / PowerOn / …   │   │  │
│  │  │  EP1 IN  Bulk  → RDR_to_PC_DataBlock / SlotStatus    │   │  │
│  │  │  EP2 IN  Intr  → RDR_to_PC_NotifySlotChange (stub)   │   │  │
│  │  └────────────────────────┬────────────────────────────┘   │  │
│  └──────────────────────────  │  ──────────────────────────────┘  │
│                  APDU bytes   │                                    │
│  ┌────────────────────────────▼──────────────────────────────┐   │
│  │                   piv.c  (PIV applet)                       │   │
│  │   SELECT / VERIFY / GET DATA / GENERAL AUTH / GET RESPONSE  │   │
│  └────────────────────────────┬──────────────────────────────┘   │
│                                │                                   │
│  ┌─────────────────────────────▼──────────────────────────────┐  │
│  │              crypto_backend.h  (abstract interface)          │  │
│  │  ┌──────────────────────────────────────────────────────┐  │  │
│  │  │  crypto_backend_soft.c  — mbedTLS 3.x, ECDSA-P256    │  │  │
│  │  │  (swap for crypto_backend_se.c to use SE050/ATECC608) │  │  │
│  │  └──────────────────────────────────────────────────────┘  │  │
│  └────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
```

**Layer boundaries** — each layer communicates only through its defined interface:

| Layer | File | Responsibility |
|---|---|---|
| Main loop | `src/main.c` | Init sequence, `tud_task` / `ccid_task` / button / NeoPixel poll |
| USB transport | `src/usb_descriptors.c` | Device + config descriptors, string callbacks |
| CCID class driver | `src/ccid.c` | CCID message framing, endpoint management |
| APDU utilities | `src/apdu.c` | ISO 7816-4 parse + response builder |
| PIV applet | `src/piv.c` | NIST SP 800-73-4 APDU routing, chaining, state |
| Crypto backend | `src/crypto_backend_soft.c` | Key generation, cert generation, ECDSA sign |
| Device state | `src/device_state.c` | Authorization FSM + timeouts |
| Button | `src/button.c` | GPIO edge ISR + 30 ms debounce |
| NeoPixel | `src/neopixel.c` | PIO WS2812 driver + state-driven animation |

---

## 2 — Device state machine

```
                      ┌──────────────┐
          boot /       │              │
          USB mount    │     IDLE     │  ← dim blue NeoPixel
          ─────────►  │              │
                       └──────┬───────┘
                              │  GENERAL AUTHENTICATE received,
                              │  PIN verified, button not yet pressed
                              ▼
                       ┌──────────────────────┐
                       │   WAITING_BUTTON      │  ← yellow fast blink
                       │   30 s timeout        │
                       └──────┬───────────────┘
                              │  button pressed (debounced)
                              ▼
                       ┌──────────────────────┐
                       │    AUTHORIZED         │  ← green solid
                       │    10 s one-shot      │
                       └──────┬───────────────┘
                              │  crypto op arrives within window
                              ▼
                       ┌──────────────────────┐
                       │    PROCESSING         │  ← green fast blink
                       └──────┬───────────────┘
                              │  signing complete → consume one-shot
                              ▼
                       ┌──────────────┐
                       │     IDLE     │
                       └──────────────┘

  Timeouts:
    WAITING_BUTTON  → IDLE  after 30 s  (red flash, then blue)
    AUTHORIZED      → IDLE  after 10 s  (red flash, then blue)
```

**Rules enforced by the FSM:**
- Only one crypto operation is allowed per button press (one-shot flag)
- The authorization window is exactly 10 seconds
- A GENERAL AUTHENTICATE that arrives when not authorized returns `SW_CONDITIONS_NOT_SATISFIED` (0x6985) — the host must retry after the user presses the button
- PIN must be verified before any GENERAL AUTHENTICATE is accepted

### NeoPixel colour map

| State | Colour | Pattern |
|---|---|---|
| IDLE | Dim blue `#00001E` | Static |
| WAITING_BUTTON | Warm yellow `#504000` | 200 ms blink |
| AUTHORIZED | Green `#003C00` | Solid |
| PROCESSING | Green `#005000` | 100 ms blink |
| Fatal init error | Red `#FF0000` | Solid, hang |

---

## 3 — Minimum CCID messages required

Reference: USB Smart Card Device Class (CCID) Specification v1.1.

| Direction | Message | Cmd byte | Handled by | Purpose |
|---|---|---|---|---|
| PC → RDR | `PC_to_RDR_IccPowerOn` | `0x62` | `ccid.c` | Power on virtual ICC → return ATR |
| PC → RDR | `PC_to_RDR_IccPowerOff` | `0x63` | `ccid.c` | Power off virtual ICC |
| PC → RDR | `PC_to_RDR_GetSlotStatus` | `0x65` | `ccid.c` | Query slot state |
| PC → RDR | `PC_to_RDR_XfrBlock` | `0x6F` | `ccid.c` → `piv.c` | Send APDU, receive response |
| PC → RDR | `PC_to_RDR_Abort` | `0x72` | `ccid.c` | Acknowledge abort (no-op) |
| RDR → PC | `RDR_to_PC_DataBlock` | `0x80` | `ccid.c` | Return APDU response or ATR |
| RDR → PC | `RDR_to_PC_SlotStatus` | `0x81` | `ccid.c` | Return slot state |

**ATR returned on IccPowerOn:** `3B 00` — direct convention, no historical bytes. Minimal valid ATR; CCID short-APDU exchange makes the ATR content non-critical. _(Pending validation — see §8)_

**dwFeatures** in the CCID descriptor: `0x000204B0` — matches YubiKey 5 and is known-good with the macOS CCID driver:
- `0x00000010` AUTO_CLOCK_FREQ
- `0x00000020` AUTO_BAUD_RATE
- `0x00000080` AUTO_PPS
- `0x00000400` AUTO_IFSD (T=1)
- `0x00020000` SHORT_APDU_EXCHANGE

---

## 4 — Minimum PIV APDUs required

Reference: NIST SP 800-73-4, Part 1 and Part 2.

| CLA | INS | P1 | P2 | Command | Handler | Notes |
|---|---|---|---|---|---|---|
| `00` | `A4` | `04` | `00` | SELECT | `_handle_select` | Selects PIV AID `A0 00 00 03 08 00 00 10 00 01 00`; returns minimal FCI |
| `00` | `CB` | `3F` | `FF` | GET DATA | `_handle_get_data` | Tag `5FC107`=CCC, `5FC102`=CHUID, `5FC105`=cert 9A, `7E`=Discovery |
| `00` | `20` | `00` | `80` | VERIFY | `_handle_verify` | PIN ref `80` = application PIN; 8-byte padded with `0xFF` |
| `00` | `87` | `11` | `9A` | GENERAL AUTHENTICATE | `_handle_general_authenticate` | Alg `0x11`=ECDSA-P256; key ref `9A`=PIV Auth; requires PIN + button |
| `00` | `C0` | `00` | `00` | GET RESPONSE | `_handle_get_response` | ISO 7816 chaining; used when response > Le (typically for certificate) |

### GENERAL AUTHENTICATE data format

```
Command data (BER-TLV):
  7C [len]
    82 00           ← RESPONSE tag, empty = "please sign"
    81 [hash_len]   ← CHALLENGE: SHA-256 digest (32 bytes) from host

Response body:
  7C [len]
    82 [sig_len]    ← RESPONSE: DER-encoded ECDSA-P256 signature (≤72 bytes)
```

### PIV data objects served

| Tag | Object | Content |
|---|---|---|
| `5FC107` | Card Capability Container (CCC) | Minimal PIV-II CCC; signals card type and capabilities |
| `5FC102` | CHUID | FASC-N (25 bytes zeros) + GUID (16 bytes, stable) + expiry 2099-12-31 |
| `5FC105` | X.509 Certificate, slot 9A | DER cert generated at first boot; self-signed, ECDSA-P256, Client Auth EKU |
| `7E` | Discovery Object | Minimal stub; reports application PIN policy |

---

## 5 — Project directory structure

```
ward3n/
├── build.sh                    ← one-shot build script
├── CMakeLists.txt
├── mbedtls_config.h            ← mbedTLS 3.x config (ECDSA-P256, SHA-256, X.509 write)
├── pico_sdk_import.cmake       ← standard Pico SDK import helper
├── tusb_config.h               ← TinyUSB config (CCID via custom class, all std classes off)
├── ws2812.pio                  ← PIO program for WS2812 NeoPixel (800 kHz, GRB)
│
├── include/
│   ├── config.h                ← pin defs, flash layout, timing constants, USB VID/PID
│   ├── device_state.h          ← FSM API
│   ├── crypto_backend.h        ← abstract crypto interface (swap for SE backend here)
│   ├── apdu.h                  ← ISO 7816-4 types, SW constants, parse/build API
│   ├── piv.h                   ← PIV applet API + data object tags
│   ├── ccid.h                  ← CCID class driver API + message type constants
│   ├── button.h                ← button API
│   └── neopixel.h              ← NeoPixel API
│
├── src/
│   ├── main.c                  ← init sequence + main loop
│   ├── usb_descriptors.c       ← USB device/config/string descriptors + usbd_app_driver_get_cb
│   ├── ccid.c                  ← TinyUSB custom class driver (IccPowerOn/Off, XfrBlock…)
│   ├── apdu.c                  ← ISO 7816-4 APDU parser + response builder
│   ├── piv.c                   ← PIV applet (SELECT, VERIFY, GET DATA, GENERAL AUTH, GET RESPONSE)
│   ├── crypto_backend_soft.c   ← mbedTLS 3.x: key gen + self-signed cert + ECDSA sign
│   ├── button.c                ← GPIO edge ISR + 30 ms debounce
│   ├── neopixel.c              ← PIO WS2812 driver + state-driven animation tick
│   └── device_state.c          ← FSM: IDLE / WAITING_BUTTON / AUTHORIZED / PROCESSING
│
└── tools/
    └── generate_keys.py        ← Python: generate P-256 key pair + self-signed cert → C arrays
```

---

## 6 — Hardware

| Item | Detail |
|---|---|
| Board | RP2040 Zero (Waveshare) |
| NeoPixel | Onboard WS2812, GPIO 16 |
| Button | External tactile switch: one leg to GPIO 23, other leg to GND |
| USB | Onboard USB connector (native RP2040 USB FS) |

**Button wiring:** GPIO 23 is configured with the internal pull-up. Press connects it to GND (active-low). No external resistor needed.

---

## 7 — Build instructions

### 7.1 Prerequisites

```bash
# 1. Homebrew cmake
brew install cmake

# 2. Official ARM GNU Toolchain 14.2 (includes newlib + nosys.specs)
#    The Homebrew arm-none-eabi-gcc formula is built --without-headers
#    and lacks nosys.specs — do NOT use it for Pico SDK projects.
curl -L -o /tmp/arm-toolchain.tar.xz \
  "https://developer.arm.com/-/media/Files/downloads/gnu/14.2.rel1/binrel/arm-gnu-toolchain-14.2.rel1-darwin-arm64-arm-none-eabi.tar.xz"
mkdir -p ~/arm-toolchain
tar -xf /tmp/arm-toolchain.tar.xz -C ~/arm-toolchain --strip-components=1

# 3. Pico SDK 2.x with submodules
git clone https://github.com/raspberrypi/pico-sdk.git \
    --branch 2.2.0 --recurse-submodules ~/pico-sdk
```

### 7.2 Build

```bash
cd ward3n
./build.sh          # configure + build
./build.sh clean    # clean rebuild
```

Output: `build/ward3n.uf2` (≈177 KB)

### 7.3 Flash

1. Hold the **BOOT** button on the RP2040 Zero while plugging it into USB.
2. It mounts as a mass-storage device named **RPI-RP2**.
3. Drag `build/ward3n.uf2` onto that volume.
4. The board reboots automatically. On first boot it generates the P-256 key pair and self-signed certificate — this takes 2–5 seconds. The NeoPixel glows **red** during init, then **blue** when ready.

### 7.4 Build environment — compiled sizes

```
   text     data      bss      dec   filename
 143856        0    34400   178256   ward3n.elf

Flash used : 140 KB / 2048 KB
SRAM  used : 34 KB BSS + 48 KB heap + 4 KB stack ≈ 86 KB / 264 KB
```

---

## 8 — Testing plan for macOS

### Prerequisites

```bash
brew install opensc pcsc-lite

# Ensure pcscd is running
sudo launchctl load /System/Library/LaunchDaemons/com.apple.pcscd.plist
```

---

### Step 1 — USB enumeration

```bash
system_profiler SPUSBDataType | grep -A 12 "PIV Security Key"
```

Expected output:
```
PIV Security Key:
  Product ID: 0x0001
  Vendor ID:  0x1209  (pid.codes)
  Version:    1.00
  Serial:     00000001
  Speed:      Up to 12 Mb/s
  Manufacturer: ward3n
  Location ID: 0x…
  Current Available (mA): 500
  Current Required (mA):  100
  Extra Operating Current (mA): 0
```

**Pass criterion:** Device appears with class `0x0b` (Smart Card) in `ioreg -p IOUSB -l`.

---

### Step 2 — CCID / PC/SC detection

```bash
opensc-tool --list-readers
# or
pcsctest
```

Expected:
```
0: ward3n PIV Security Key [Slot 0]
```

**Pass criterion:** Reader listed, card present (`atr=3B00` or similar).

---

### Step 3 — Raw APDU smoke test (no crypto required)

```bash
# Select PIV AID
opensc-tool --send-apdu 00A404000BA000000308000010000100
# Expected: 61 13 ... 90 00  (FCI returned, SW=9000)

# GET DATA: Card Capability Container
opensc-tool --send-apdu 00CB3FFF055C035FC107
# Expected: 53 33 ... 90 00

# GET DATA: CHUID
opensc-tool --send-apdu 00CB3FFF055C035FC102
# Expected: 53 3B ... 90 00  (contains GUID at offset ~28)

# VERIFY PIN "123456" padded to 8 bytes with 0xFF
opensc-tool --send-apdu 0020008008313233343536FFFF
# Expected: 90 00

# Retry counter (no data sent)
opensc-tool --send-apdu 002000800000
# Expected: 63 C3  (3 retries remaining)
```

---

### Step 4 — Certificate retrieval

```bash
# GET DATA: PIV Auth certificate (slot 9A)
opensc-tool --send-apdu 00CB3FFF055C035FC105
# If cert > Le bytes: SW=61xx → issue GET RESPONSE
opensc-tool --send-apdu 00C0000000
# Repeat GET RESPONSE until SW=9000

# Parse the DER certificate bytes manually, or use piv-tool:
piv-tool --reader 0 --read-certificate 9a > /tmp/cert_9a.der 2>/dev/null
openssl x509 -inform DER -in /tmp/cert_9a.der -text -noout
```

Expected cert fields:
```
Subject: C=US, O=ward3n, CN=ward3n PIV Key
Issuer:  C=US, O=ward3n, CN=ward3n PIV Key   (self-signed)
Key:     id-ecPublicKey (P-256)
KeyUsage: Digital Signature
ExtKeyUsage: TLS Web Client Authentication
```

---

### Step 5 — GENERAL AUTHENTICATE (ECDSA sign — requires button press)

```bash
# First call: PIN must already be verified (Step 3 above)
# Send GENERAL AUTHENTICATE with a 32-byte fake SHA-256 hash:
opensc-tool --send-apdu 00871190257C238200812031323334353637383930313233343536373839303132
#                                                  ^^^^ 32 bytes of "12345..."

# Expected on first call (button not pressed): 69 85
# NeoPixel turns YELLOW — press the button within 30 s
# Re-send the same APDU:
opensc-tool --send-apdu 00871190257C238200812031323334353637383930313233343536373839303132

# Expected: 7C [len] 82 [sig_len] [DER ECDSA signature] 90 00
# NeoPixel blinks GREEN during signing, returns to BLUE after
```

Verify the signature offline:
```bash
# Extract public key from cert
openssl x509 -inform DER -in /tmp/cert_9a.der -pubkey -noout > /tmp/pubkey.pem

# The "hash" we sent was ASCII bytes of "12345678901234567890123456789012"
echo -n "12345678901234567890123456789012" > /tmp/hash.bin

# Extract the DER signature bytes from the APDU response, save as sig.der
# Then verify:
openssl dgst -sha256 -verify /tmp/pubkey.pem -signature /tmp/sig.der /tmp/hash.bin
# Expected: Verified OK
```

---

### Step 6 — macOS smart card pairing

```bash
# List available smart cards
sc_auth list

# Open the pairing UI (macOS Ventura+)
sc_auth pairing_ui

# Or pair manually via certificate hash:
HASH=$(openssl x509 -inform DER -in /tmp/cert_9a.der -fingerprint -sha1 -noout \
       | sed 's/SHA1 Fingerprint=//' | tr -d ':')
sc_auth pair -d -u "$USER" -h "$HASH"

# Verify pairing
sc_auth list -u "$USER"
```

---

### Step 7 — Full macOS authentication flow

1. Lock the screen (`Ctrl+Cmd+Q`).
2. At the login window, select **Smart Card** (or wait — macOS detects it automatically if paired).
3. Enter PIN: `123456`
4. macOS sends GENERAL AUTHENTICATE to the card. The NeoPixel turns **yellow**.
5. Press the button within 30 seconds. The NeoPixel turns **green**.
6. Signing completes. The NeoPixel blinks **green** briefly, then returns to **blue**.
7. macOS verifies the signature and unlocks.

---

### Step 8 — OpenSC PIV tool (comprehensive test)

```bash
# Full PIV card dump (reads all data objects and certificates)
piv-tool --reader 0 -P 313233343536FFFF --list-keys

# Or use OpenSC's pkcs11 tool:
pkcs11-tool --module /usr/local/lib/opensc-pkcs11.so --list-objects
pkcs11-tool --module /usr/local/lib/opensc-pkcs11.so \
    --sign --mechanism ECDSA --input-file /tmp/hash.bin \
    --output-file /tmp/sig.bin
```

---

## 9 — Key notes and pending validations

| # | Item | Status | Detail |
|---|---|---|---|
| 1 | USB VID/PID `1209:0001` | **PENDING** | `0x1209` is the pid.codes open-source VID; `0x0001` is unassigned. [Register a PID](https://pid.codes) before production. |
| 2 | ATR `3B 00` | **PENDING** | Minimal valid ATR. If macOS CCID driver rejects it, replace with: `3B DA 18 FF 81 B1 FE 75 1F 03 00 31 C5 73 C0 01 40 00 90 00` (a real PIV card ATR). |
| 3 | `dwFeatures = 0x000204B0` | VALIDATED | Matches YubiKey 5; known-good with macOS CCID driver. |
| 4 | GENERAL AUTHENTICATE retry on SW=6985 | **PENDING** | macOS CryptoTokenKit is expected to retry when the user dismisses/retries the PIN prompt. If it does not, implement CCID time extensions (CCID spec §5.3) — the card holds the USB response until the button is pressed, similar to YubiKey behaviour. |
| 5 | mbedTLS X.509 cert in flash | VALIDATED | Generated at first boot; survives power cycles. Flash erase happens before `tusb_init()` — no USB conflict. |
| 6 | Heap usage during first boot | **PENDING** | mbedTLS x509write is heap-intensive. `PICO_HEAP_SIZE=49152` (48 KB) is provisioned. Validate with heap watermark instrumentation if crashes occur on first boot. |
| 7 | PIN management | **PENDING** | PIN is hardcoded as `"123456"` in `config.h`. A production implementation must store a PIN hash (PBKDF2-HMAC-SHA256) in flash and implement retry count / lockout. |
| 8 | Private key in flash | **PENDING** | The P-256 private key scalar is stored in flash as plaintext. This is acceptable for a prototype without a secure element. Replace `crypto_backend_soft.c` with `crypto_backend_se.c` targeting SE050 / ATECC608B for production. |
| 9 | Button GPIO 23 | **USER CONFIG** | Change `BUTTON_PIN` in `include/config.h` to match your wiring. Any RP2040 GPIO works. |
| 10 | Self-signed cert macOS trust | **PENDING** | macOS will not trust the self-signed cert for login without either (a) it being in the System keychain, or (b) the user account being paired via `sc_auth`. For testing, pairing via `sc_auth pair` is sufficient. |
| 11 | PIV PIN reference 80 only | **PENDING** | Only application PIN (ref `0x80`) is implemented. Global PIN (ref `0x00`) and PUK are not implemented. Some macOS versions may probe for PUK; return `SW_REFERENCED_DATA_NOT_FOUND` (0x6A88). |
| 12 | Homebrew `arm-none-eabi-gcc` | NOT SUPPORTED | Built `--without-headers`; missing `nosys.specs` / newlib. Use the [official ARM GNU Toolchain](https://developer.arm.com/downloads/-/arm-gnu-toolchain-downloads) extracted to `~/arm-toolchain`. |

---

## 10 — How to replace the crypto backend

The file `include/crypto_backend.h` is the only interface the PIV layer uses for cryptography. To swap in a secure element:

1. Create `src/crypto_backend_se.c` implementing all functions in `crypto_backend.h`.
2. In `CMakeLists.txt`, replace `src/crypto_backend_soft.c` with `src/crypto_backend_se.c`.
3. Add the SE's I2C/SPI library to `target_link_libraries`.
4. Remove `pico_mbedtls` from `target_link_libraries` if mbedTLS is no longer needed.
5. Remove `mbedtls_config.h` and the `PICO_MBEDTLS_CONFIG_FILE` cmake line.

The PIV layer (`piv.c`) does not need any changes.

---

## 11 — Key file reference

| File | Critical constants |
|---|---|
| `include/config.h` | `BUTTON_PIN`, `NEOPIXEL_PIN`, `AUTH_WINDOW_MS`, `WAIT_BUTTON_TIMEOUT_MS`, `PIV_DEFAULT_PIN`, `USB_VID`, `USB_PID`, `KEY_STORAGE_OFFSET` |
| `include/crypto_backend.h` | `KEY_REF_9A`, `ALG_ECDSA_P256` |
| `include/piv.h` | `PIV_AID`, `PIV_AID_LEN`, `PIV_TAG_*`, `PIV_DAT_*` |
| `include/ccid.h` | `CCID_PC_to_RDR_*`, `CCID_RDR_to_PC_*`, `CCID_CMD_*`, `CCID_ICC_*` |
| `include/apdu.h` | `SW_OK`, `SW_MORE_DATA`, `SW_SECURITY_NOT_SATISFIED`, all other SWs |

---

## 12 — Tools

### `tools/generate_keys.py`

Generates a fresh P-256 key pair and a self-signed X.509 certificate, then prints them as C arrays. Use this to inspect the card's key material or pre-provision a known key pair.

```bash
pip install cryptography
python3 tools/generate_keys.py
# Writes tools/private_key.pem and tools/cert.pem
# Prints C arrays for hardcoding into firmware (optional — firmware self-generates)
```

---

## License

Prototype / research firmware. No warranty. Do not use in production without replacing the software crypto backend with a secure element and implementing proper PIN management and key protection.
