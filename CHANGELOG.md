# Changelog

All notable changes to this project will be documented in this file.

## [1.2.1-stoen] - 2026-10-12

Ships as one change set: STOEN support that builds and runs on the current
ESPHome, on ESP8266 as well as ESP32, without leaving the rest of the
component broken.

### Added
- **ESP8266 support for the STOEN path.** The debug UDP dump was unconditional
  and pulled in `<sys/socket.h>`, `<netdb.h>` and FreeRTOS, none of which exist
  on ESP8266. It is now the optional `debug_udp_target: "<ip>:<port>"`, compiled
  only on ESP32, so `method: poland_stoen` builds and runs on ESP8266 too.
  ESP8266 is tight on RAM for this: the buffers are now allocated once with
  the result checked, so the component marks itself failed with a log line
  instead of crashing when they do not fit, and the README says what to trim
  and which reboot looks like heap and which looks like stack exhaustion.
- `authentication_key` option. STOEN issues two keys but only the decryption
  key takes part in reading the telegram, so an authenticated frame (security
  byte `0x30`) decrypts while its AES-GCM tag stays unverifiable. The component
  probes the additional-data layouts it knows on the first five telegrams; with
  an authentication key configured it also tries
  `security byte || authentication key`, and whichever layout reproduces the tag
  is then enforced on every telegram.
- `scripts/analyze-stoen-telegram.py`: takes a telegram captured with
  `debug_udp_target` apart offline - DLMS wrapper fields, decrypted contents,
  and which additional authenticated data reproduces the meter's tag.
- CI compile tests for the STOEN path on ESP8266/Arduino, ESP32/Arduino and
  ESP32/ESP-IDF; the previous configurations only ever compiled the file.
- README sections on what this fork changes, where it is verified, the key
  situation, the STOEN dialect, its options and its log messages.

### Fixed
- **Build on ESPHome 2026.1+:** `CORE.using_esp_idf` was removed from ESPHome's
  core, so code generation failed with `AttributeError` before anything was
  compiled. The framework check now asks `CORE.target_framework` instead.
- **Standard DSMR sensors work again:** the vendored P1 parser was commented
  out wholesale, which left every user of the component with custom OBIS
  sensors only. It is restored, and skipped just for `method: poland_stoen`,
  whose footer CRC covers the encrypted frame and can never match.
- **AES-GCM frame arithmetic:** the tag length was hardcoded to 0, which put
  the tag pointer one byte past the end of the body - a 12 byte out-of-bounds
  read - and made the tag check verify nothing. On ESP-IDF that same zero
  length made MbedTLS reject every frame with `MBEDTLS_ERR_GCM_BAD_INPUT`, so
  the STOEN path never decrypted there at all. The 12 byte tag is now part of
  the frame arithmetic, and decryption goes through a call that returns the
  computed tag rather than discarding the plaintext on mismatch.
- **Frame validation aborts instead of continuing:** malformed frames, a
  truncated body, a `LEN_INFO` smaller than its own overhead, a misplaced
  length marker and oversized plaintext used to be logged and then parsed
  anyway, because every reset/return after the log line was commented out. They
  now discard the telegram and raise the component's warning status.
- **No more buffer overruns in the STOEN path:** the receive buffer was a fixed
  2000 bytes written without a bounds check and is now sized from
  `max_telegram_length`; the telegram scanner read up to six bytes past the
  received data and consumed eight bytes for a seven byte false footer,
  dropping a body byte; the identification line was `strcpy`-ed into a 21 byte
  buffer; and reassembling the telegram could write past
  `max_telegram_length`.
- **`method: encrypted` is no longer silently ignored:** the YAML value did not
  match any name the C++ side knew, so it fell back to `plain`.
- Removed a `vTaskDelete(NULL)` that killed the ESPHome main task when the
  debug socket could not be created.

### Changed
- The hardcoded debug destination addresses (`192.168.22.233`,
  `192.168.22.27`) and the hardcoded 200 ms quiet time are gone; the quiet time
  now follows the existing `receive_timeout` option.
- `Methods` enum replaced by `enum class Method` with distinct values
  (`poland_stoen` and `BAJO` shared the value 5); the YAML spelling `bajo` is
  kept as an alias for `poland_stoen`.
- Stopped tracking `__pycache__/*.pyc` and `.vscode/settings.json`, and
  extended `.gitignore` so they do not come back.

### Verified on
- ESP32 / ESP-IDF, `method: poland_stoen`, running on an ELGAMA G350 typ G35.
- ESP8266 `d1_mini` / Arduino, ESP32 / Arduino, ESP32 / ESP-IDF and
  ESP32-C6 / ESP-IDF: built and linked with ESPHome 2026.9.1, with and without
  the STOEN path.

## [1.2.0 modified] - 2025-12-11
### Added
- **Polish STOEN protocol:** Added decyrption for polish STOEN protocol in ELGAMA 350 Typ G35. 
  - works with both platform: Arduino and ESP-IDF.
  - added 'method' option to force proceed methods.
    - default id 'plain'
    - method: Polish_STOEN -> force to proceed method 'Polish_STOEN'.
    In this method also reading data from uart was changed to aster method.
    Polish meters is programmed by STOEN to send telegram every second.
    I read all received bytes and store in buffer.
    After 200ms from last receives I start proceed telegram.
    This method gives proceed time in range of 5ms on esp32.


## [1.2.0] - 2025-12-03

### Added
- **ESP-IDF Encryption Support:** Added experimental support for AES-GCM decryption on ESP-IDF platforms (e.g., ESP32-C6).
  - Uses system MbedTLS library with hardware acceleration where available.
  - Implemented via PlatformIO `extra_scripts` to handle library linking.

## [1.1.0] - 2025-12-02

### Added
- ESP-IDF framework support for ESP32-C6, ESP32-H2, and future chips
- Framework-agnostic string handling using conditional compilation
- AUTO_LOAD directive for sensor/text_sensor components (fixes #7)
- Comprehensive testing configuration files
- GitHub Actions CI/CD for compile testing

### Changed
- Replaced hardcoded Arduino.h dependency with conditional compilation
- Migrated Arduino String operations to framework-agnostic implementation
- Updated util.h to support both Arduino String and std::string

### Fixed
- Issue #6: Arduino.h missing file error when using ESP-IDF framework
- Issue #7: sensor.h missing when no sensor platform defined in YAML configuration

### Breaking Changes
None - fully backward compatible with existing configurations.

## [1.0.2] - Previous Release
- Initial stable release with custom OBIS sensor support
