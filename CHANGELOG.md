# Changelog

All notable changes to this project will be documented in this file.

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
