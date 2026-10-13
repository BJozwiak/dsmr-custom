# Modified dsmr-custom from nikopaulanne/dsmr-custom:main - Enhanced DSMR P1 Component for ESPHome

**Forked version:** 1.0.2 (upstream) - **this branch:** 1.2.1-stoen

**Modification:** Work with Polish STOEN DSMR P1 protocol

**ESPHome Compatibility:** 2025.5.x or newer (including 2026.1+)

**Targets:** ESP8266 and ESP32 on Arduino, ESP32 family on ESP-IDF

## What this fork changes

On top of `nikopaulanne/dsmr-custom:main` this branch adds support for the
Polish STOEN dialect and fixes what that support originally broke.

**Added**

* `method:` selects how a telegram is read and decoded - `plain`, `encrypted`
  or `poland_stoen` (alias `bajo`). The STOEN path drains the UART into one
  buffer and parses it once the line goes quiet, instead of reading byte by
  byte, because the meter pushes a whole telegram every second. Parsing takes
  about 5 ms on an ESP32.
* AES-GCM decryption of the STOEN body, with the frame layout derived from the
  DLMS wrapper rather than hardcoded: both an explicit 8 byte system title
  (`0xDB`) and an empty one (`0x00`) are handled, and the ciphertext length
  comes from `LEN_INFO` minus the security byte, the frame counter and the tag.
* `authentication_key:` - optional, see *Keys* below.
* `debug_udp_target: "<ip>:<port>"` - mirror every raw and decrypted telegram
  to a host over UDP, for reverse engineering a dialect the ESPHome logger
  cannot show. ESP32 only; on ESP8266 no socket code is compiled at all.
* `scripts/analyze-stoen-telegram.py` - takes a captured telegram apart
  offline: DLMS fields, decrypted contents, and which additional
  authenticated data reproduces the meter's AES-GCM tag.
* Compile tests for the STOEN path on ESP8266/Arduino, ESP32/Arduino and
  ESP32/ESP-IDF, in the CI matrix.

**Fixed**

* Builds on ESPHome 2026.1 and newer. `CORE.using_esp_idf` was removed from
  ESPHome's core, so code generation aborted before compiling anything.
* Standard DSMR sensors publish again. The vendored P1 parser had been
  commented out wholesale, which left *every* user of the component with
  `custom_obis_sensors` only. It is skipped just for `method: poland_stoen`,
  whose footer CRC covers the encrypted frame and can never match.
* The STOEN path no longer parses frames it failed to decrypt. Malformed
  frames, a truncated body, a `LEN_INFO` smaller than its own overhead, a
  misplaced length marker and oversized plaintext each discard the telegram
  and raise the component's warning status, instead of being logged and then
  parsed anyway.
* AES-GCM frame arithmetic. The tag length was hardcoded to 0, which put the
  tag pointer one byte past the end of the body - a 12 byte out-of-bounds
  read - and made the tag check verify nothing. On ESP-IDF that same zero
  length made MbedTLS reject every frame, so the STOEN path never decrypted
  there at all.
* No more buffer overruns in the STOEN path: the receive buffer was a fixed
  2000 bytes written without a bounds check and is now sized from
  `max_telegram_length`; the telegram scanner read up to six bytes past the
  received data and consumed eight bytes for a seven byte false footer,
  dropping a body byte; the identification line was `strcpy`-ed into a 21 byte
  buffer; and reassembling the telegram could write past
  `max_telegram_length`.
* A failing debug socket no longer calls `vTaskDelete(NULL)`, which killed the
  ESPHome main task. The two hardcoded LAN addresses are gone with it.
* `method: encrypted` is no longer silently ignored - the YAML spelling did not
  match the lookup table on the C++ side, so it fell back to `plain`.
* The quiet time that ends a telegram follows the existing `receive_timeout`
  option instead of a hardcoded 200 ms.

### Verified on

| Target | Framework | Configuration | Status |
|---|---|---|---|
| ESP32 | ESP-IDF | STOEN, real meter | **running on an ELGAMA G350 / typ G35**, uninterrupted since 2026-10-12 |
| ESP32 | Arduino | STOEN, real meter | earlier revision of this branch ran here for months; this revision is build-tested only |
| ESP8266 `d1_mini` | Arduino | `test-stoen-arduino-esp8266.yaml` | builds and links; not yet run on a meter, and tight on RAM (see below) |
| ESP32 | Arduino | `test-stoen-arduino-esp32.yaml` | builds and links |
| ESP32 | ESP-IDF | `test-stoen-espidf-esp32.yaml` | builds and links |
| ESP8266 `d1_mini` | Arduino | `test-arduino-esp8266.yaml` (plain DSMR) | builds and links |
| ESP32 | ESP-IDF | `test-espidf-esp32.yaml` (plain DSMR) | builds and links |
| ESP32-C6 | ESP-IDF | `test-espidf-esp32c6.yaml` (plain DSMR) | builds and links |

Everything above is built with ESPHome 2026.9.1.

### RAM on ESP8266

The STOEN path builds and links on ESP8266, but the chip has 80 kB of RAM in
total and no PSRAM, so a firmware that fits can still misbehave on the meter.
At `max_telegram_length: 1700` this component allocates about 7 kB of heap in
`setup()` - receive buffer, encrypted body, decrypted body and the telegram
itself - on top of the 31 kB of static RAM the firmware already uses, and a
`uart` with `rx_buffer_size: 1700` adds another 1.7 kB. What is left has to
carry the WiFi stack, the API connection and every other component on the
device. Two failure modes follow from that, and neither of them is a
decryption problem:

* **Not enough heap.** The buffers are allocated once, at startup. If that
  fails the component logs `Failed to allocate STOEN telegram buffers` and
  marks itself failed instead of crashing, so the cause is in the log. A
  shortage later is less polite: WiFi and the API allocate as they go, and as
  free heap approaches 10 kB the device starts dropping its connection and
  rebooting.
* **Not enough stack.** The Arduino sketch runs on a ~4 kB stack on ESP8266,
  shared by every component in the loop. A reboot with `Fatal exception` or
  `Stack smashing protect failure!` in the boot log, always while a telegram
  is being handled, is that and not the crypto.

If the device reboots or goes unavailable, in this order:

1. Lower `max_telegram_length` to just above the longest telegram your meter
   actually sends, and set the uart `rx_buffer_size` to the same value. Every
   100 bytes taken off gives back about 400 bytes of heap, because four
   buffers are sized from it.
2. Drop what the device does not need - `web_server` and `captive_portal` are
   the expensive ones - and keep the logger at `INFO` or `DEBUG`. At
   `VERY_VERBOSE` the component prints whole telegrams through the log
   formatter, which is a reliable way to run out of stack here.
3. Watch the free heap for a day before trusting it:

   ```yaml
   debug:

   sensor:
     - platform: debug
       free:
         name: "Free heap"
   ```

If it still reboots, the component is simply at the edge of what an ESP8266
can host - an ESP32 has roughly four times the RAM and is the target this
branch is verified on.

### Keys

STOEN hands out two keys, but only the decryption key takes part in reading
the telegram: the frame as the meter sends it carries no field that would make
the second one necessary. That is why an authenticated frame (security byte
`0x30`) decrypts correctly while its AES-GCM tag cannot be reproduced - DLMS
computes that tag over `security byte || authentication key`. The component
probes the layouts it knows on the first five telegrams and then says, once,
that telegrams are decrypted but not authenticated. Setting
`authentication_key` makes it try `security byte || authentication key` as
well, and if that reproduces the tag the component authenticates every
telegram from then on.

## Polish STOEN meters (ELGAMA G350 / typ G35)

STOEN programs these meters to push a complete telegram every second, with an
AES-GCM encrypted body wrapped in a plain header and a plain `!CRC` footer.
That does not fit the byte-by-byte receive loop of the upstream component, so
this fork adds a `method` option that switches to a buffered receive path:
everything the UART has is drained into one buffer and parsed once the line
has been quiet for `receive_timeout`, which takes about 5 ms on an ESP32.

```yaml
external_components:
  - source:
      type: git
      url: https://github.com/BJozwiak/dsmr-custom
      ref: BAJO_STOEN
    components: [ dsmr_custom ]

dsmr_custom:
  id: dsmr_hub
  uart_id: uart_0
  method: poland_stoen          # the STOEN receive + decrypt path
  decryption_key: !secret meter_key
  max_telegram_length: 1700
  crc_check: false              # the footer CRC covers the encrypted frame
  custom_obis_sensors:
    - code: "1-0:1.8.0"
      name: "Total Energy Import"
      type: sensor
      unit_of_measurement: "kWh"
      accuracy_decimals: 3
      device_class: energy
      state_class: total_increasing
```

`ref: BAJO_STOEN` follows this branch as it moves. To stay on a fixed
revision use the tag instead - `ref: v1.2.1-stoen` is the state verified on
the meter and described under [Verified on](#verified-on).

With `method: poland_stoen` the values come from `custom_obis_sensors` only:
the reassembled telegram carries a CRC over the *encrypted* frame, so the
vendored P1 parser is skipped for this dialect and the standard DSMR sensors
stay unpublished. Every other `method` keeps the upstream behaviour, standard
sensors included.

The meter needs a `uart:` with an inverted, pulled-up RX pin and an
`rx_buffer_size` of at least the telegram length; see
`test-configs/p1-dongle_Polish_STOEN_ELGAMA350_G35.yaml` for a complete,
working device configuration including a display.

### Troubleshooting the STOEN path

* **`telegrams are decrypted but NOT authenticated`** - expected on a STOEN
  meter, see *Keys* above. The AES-GCM tag covers the ciphertext plus
  additional authenticated data, which DLMS defines as
  `security byte || authentication key`; the telegram itself is read with the
  decryption key alone, so the tag stays unverifiable. The component probes the
  layouts it knows on the first five telegrams and, once none of them matches,
  keeps decrypting and says so once. Setting `authentication_key` adds
  `security byte || authentication key` to the candidates.
* **`GCM tag verifies with additional data = ...`** - the layout was recognised;
  from that point on a telegram with a bad tag is rejected.
* **`Security byte 0x.. has no authentication tag`** - the meter uses a DLMS
  security suite this path does not implement; open an issue with the logged
  byte.
* **`RX buffer full`** - the device cannot keep up with the meter. Raise
  `max_telegram_length` (the receive buffer is sized from it) or take load off
  the main loop.
* **Nothing at all** - set `logger: level: VERY_VERBOSE` for the
  `BAJO dsmr_custom` tag, or dump the raw telegram to a PC with
  `debug_udp_target` (see below), catch it with `nc -ul 37008 > telegram.bin`
  and take it apart offline:

  ```
  python3 scripts/analyze-stoen-telegram.py telegram.bin --key-file key.txt
  ```

  The script mirrors the frame arithmetic of the component, so it prints the
  DLMS wrapper fields, the decrypted telegram and which additional
  authenticated data (if any) reproduces the meter's AES-GCM tag.

## Framework Support

This component supports both Arduino and ESP-IDF frameworks with different feature sets:

### Supported Frameworks

- ✅ **Arduino Framework**: ESP8266, ESP32, ESP32-S2/S3/C3
  - **Full support** including encrypted telegram decryption
  - Tested and stable
- ✅ **ESP-IDF Framework**: ESP32, ESP32-C6, ESP32-H2
  - **Full support** including encrypted telegram decryption
  - Uses hardware acceleration on supported chips (e.g. ESP32-C6)
  - *Note: Encryption support is currently experimental and needs field testing*

### Which Framework Should I Use?

| **Your Situation** | **Recommended Framework** |
|-------------------|--------------------------|
| My meter sends **encrypted** telegrams | ✅ Arduino (Stable) or ESP-IDF (Experimental) |
| My meter sends **unencrypted** telegrams | ✅ Arduino or ESP-IDF |
| I have ESP32-C6 or ESP32-H2 | ✅ ESP-IDF |
| I have ESP8266 or classic ESP32 | ✅ Arduino (fully tested) |

> **Note:** Most Dutch smart meters send unencrypted telegrams. Check your meter's specifications if unsure.

### Configuration Examples

**Arduino (ESP8266 - Recommended)**
```yaml
esp8266:
  board: d1_mini

dsmr_custom:
  decryption_key: "AABBCCDDEEFF00112233445566778899"  # ✅ Supported
```

**ESP-IDF (ESP32-C6)**
```yaml
esp32:
  board: esp32-c6-devkitc-1
  framework:
    type: esp-idf

dsmr_custom:
  decryption_key: "AABBCCDDEEFF00112233445566778899"  # ✅ Supported (Experimental)
```

**Author:** Niko Paulanne

**Parser Base:** `glmnet/Dsmr` (v0.8), vendored and modified. Original by Matthijs Kooijman.

`dsmr-custom` is an advanced custom component for ESPHome designed to read and parse data from the P1 port of smart meters. It offers significant improvements in flexibility and compatibility, especially for meters that do not fully adhere to standards (such as meters following the SESKO standard common in Finland).

---

## Quick Start: Find Your Meter's OBIS Codes via Logs

This guide will get you running in minutes and show you the most stable way to discover all the data your specific meter provides by reading the device logs directly in Home Assistant.

### Step 1: Add the Component to your Configuration

Instead of copying files manually, you can add this component directly to your device's `.yaml` file. This will make ESPHome automatically download the correct version from GitHub.

Add the following `external_components` block to your YAML:
```yaml
external_components:
  - source:
      type: git
      url: https://github.com/nikopaulanne/dsmr-custom
      ref: v1.0.2
    components: [ dsmr_custom ]
```

### Step 2: Initial Test & Logging Configuration

Use this minimal configuration first. Its only purpose is to safely view the raw data from your meter in the ESPHome logs without crashing the device.

```yaml
# In your secrets.yaml file, you should have:
# wifi_ssid: "YourNetwork"
# wifi_password: "YourPassword"
# esphome_api_encryption_key: "GENERATE_A_KEY_HERE"

esphome:
  name: dsmr-diagnostics

esp8266:
  board: d1_mini # Change to match your board

wifi:
  ssid: !secret wifi_ssid
  password: !secret wifi_password

api:
  encryption:
    key: !secret esphome_api_encryption_key

ota:

# The logger is essential for viewing the telegram data
logger:
  level: INFO # INFO level is sufficient for this purpose

uart:
  id: uart_bus
  baud_rate: 115200
  rx_pin: D7 # Check the pinout for your hardware
  rx_buffer_size: 1700

external_components:
  - source:
      type: git
      url: https://github.com/nikopaulanne/dsmr-custom
      ref: 1.0.2
    components: [ dsmr_custom ]

# --- DSMR Hub ---
dsmr_custom:
  id: dsmr_hub
  uart_id: uart_bus

# --- Sensors for Logging & Diagnostics Only ---
text_sensor:
  - platform: dsmr_custom
    dsmr_custom_hub_id: dsmr_hub
    
    # This sensor helps confirm a connection to the meter
    identification:
      name: "P1 Telegram Header"
      
    # This captures the full telegram but does NOT send it to a Home Assistant state.
    # Instead, a lightweight on_value trigger prints the data to the logs.
    telegram:
      internal: true # This prevents the state from being sent to Home Assistant
      on_value:
        - logger.log:
            level: INFO
            tag: "telegram_dump" # Makes the message easy to find in logs
            format: "--- FULL TELEGRAM RECEIVED ---\n%s\n-----------------------------"
            args: [x.c_str()]
```

### Step 3: View Logs and Collect OBIS Codes

1.  Install the minimal configuration above to your device.
2.  In Home Assistant, navigate to **Settings > Add-ons > ESPHome**.
3.  Select your device (`dsmr-diagnostics`) from the dashboard and click the **LOGS** button.
4.  Wait for the device to connect and receive a data packet from your meter.
5.  You will see a clearly marked block of text appear in the logs, starting with `--- FULL TELEGRAM RECEIVED ---`. This is the complete, raw data packet from your meter.
6.  **Copy this entire block of text** (from the start line to the end line) to your clipboard. You now have a complete list of all OBIS codes your meter provides.

### Step 4: Configure Your Final Sensors

Now that you have your list of OBIS codes, you can create your final, permanent configuration. Modify your YAML file, remove the diagnostic `on_value` trigger, and add the sensors you want using the `custom_obis_sensors` list.

See the `slimmelezer-example.yaml` file for a detailed example.

```yaml
dsmr_custom:
  id: dsmr_hub
  uart_id: uart_bus
  # ... other hub settings ...
  
  custom_obis_sensors:
    # Add sensors here using the codes you found in the logs
    - code: "1-0:1.8.0" 
      name: "Total Energy Import"
      type: sensor
      # ...
```

---

## Full Documentation

### Key Features

* **User-Defined OBIS Sensors:** Define sensors for *any* OBIS code directly in your ESPHome YAML configuration, including full control over name, unit, device class, state class, icon, and other ESPHome sensor properties.
* **Enhanced Vendored Parser:** Based on `glmnet/Dsmr`, this component includes critical fixes:
    * **Lenient P1 Header Parsing:** Correctly parses P1 telegrams with non-standard identification lines (e.g., `/ADN9...` used in Finland).
    * **`DEFINE_FIELD` Macro Fix:** Resolves a C++ compilation error found in some versions of the underlying parser.
    * **Configurable M-Bus Channel IDs:** Allows M-Bus channel IDs for gas/water meters to be configured via YAML.
* **Standard DSMR Sensor Support:** Option to define common sensors (energy, power, etc.) via standard `sensor:` and `text_sensor:` platforms.
* **Sensor Override Mechanism:** A custom OBIS sensor will always take precedence over a standard sensor if they target the same OBIS code, preventing duplicate entities.
* **Encrypted Telegram Support (Experimental):** Decrypts AES-128 GCM encrypted P1 telegrams (e.g., for Luxembourg meters). **Note: This feature is considered experimental and has not been tested on physical hardware.**
* **`request_pin` Support:** Allows active data requests by controlling the P1 port's Data Request (RTS) pin.

### Detailed Configuration

#### Hub Configuration (`dsmr_custom:`)

This block configures the main P1 port interface. All parameters from the example below can be added to your `dsmr_custom:` block.

```yaml
dsmr_custom:
  id: dsmr_hub # Required. This ID is used to link sensors to this hub.
  uart_id: uart_bus # Required. The ID of the UART bus connected to the P1 port.
  max_telegram_length: 1700 # Optional, default: 1500. Max bytes for a telegram.
  receive_timeout: "600ms"  # Optional, default: "200ms". Timeout for receiving data.
  crc_check: true           # Optional, default: true. Perform CRC check on telegrams.
  decryption_key: "YOUR_32_CHAR_HEX_DECRYPTION_KEY" # Optional. For encrypted telegrams.
  # Note: See docs/aes-gcm-implementation-notes.md for technical details on ESP-IDF encryption support
  request_pin: D5           # Optional. GPIO pin for Data Request (RTS). E.g., D5.
  request_interval: "10s"   # Optional, default: "0s". Interval for active data requests.
  gas_mbus_id: 1            # Optional, default: 1. M-Bus channel ID for standard gas meter.
  water_mbus_id: 2          # Optional, default: 2. M-Bus channel ID for standard water meter.
  method: plain             # Optional, default: "plain". One of "plain", "encrypted"
                            # or "poland_stoen" (alias: "bajo"). See the STOEN section above.
  authentication_key: "YOUR_32_CHAR_HEX_AUTH_KEY" # Optional. DLMS authentication key,
                            # if your operator issued one on top of the decryption key.
                            # Without it an authenticated frame is decrypted but its
                            # AES-GCM tag cannot be verified.
  debug_udp_target: "192.168.1.5:37008" # Optional, ESP32 only. Mirror every raw and
                            # decrypted telegram to this host as UDP, for reverse
                            # engineering a dialect the logger cannot show.
```

#### User-Defined OBIS Sensors (`custom_obis_sensors:`)

This is the most powerful feature. Add this list under your `dsmr_custom:` hub configuration.

```yaml
dsmr_custom:
  id: dsmr_hub
  # ... other hub settings ...
  custom_obis_sensors:
    - code: "1-0:1.8.0"  # The OBIS code string from your meter's telegram
      name: "My Custom Total Energy Import"
      type: sensor      # "sensor" for numeric, "text_sensor" for text
      # All standard ESPHome sensor parameters are supported:
      unit_of_measurement: "kWh"
      accuracy_decimals: 3
      device_class: energy
      state_class: total_increasing
      icon: "mdi:home-import-outline"
```

### Vendored Parser & Modifications

This component includes a **vendored (locally embedded) copy of the `glmnet/Dsmr` parser library** to apply critical fixes not available upstream. This ensures wider meter compatibility and build stability.

* **Lenient P1 Header Parsing:** The parser was modified to accept non-standard identification lines, like those from Finnish meters.
* **`DEFINE_FIELD` Macro Fix:** A C++ compilation error related to PROGMEM was resolved, making the component compatible with modern compilers.
* **Consistent Naming:** Parser-internal struct members were standardized to fix compilation errors.

### Notes for ESPHome Developers (Potential Upstreaming)

This component demonstrates features that could benefit the native ESPHome DSMR component:
1.  **User-Defined OBIS Sensors:** A native YAML-based system for defining arbitrary OBIS sensors would greatly improve flexibility.
2.  **Lenient P1 Header Parsing:** A more tolerant parsing strategy would improve out-of-the-box compatibility with a wider range of meters.
3.  **Exposing Raw P1 Identification/Telegram:** Built-in text sensors for the P1 header and the full telegram are invaluable for debugging.

## License

This component is licensed under the **GNU General Public License v3.0**. A copy of the license is included in the `LICENSE` file in this repository.

This project incorporates and modifies code from the `glmnet/Dsmr` library (which is based on `matthijskooijman/arduino-dsmr`). That original work is licensed under the MIT License. In compliance with the licensing terms, the original copyright notices and permissions are preserved in the headers of the respective source files (`parser.h`, `fields.h`, `util.h`, etc.).

