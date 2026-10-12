/*
 * This file is part of the dsmr_custom ESPHome component.
 *
 * Support for the Polish STOEN P1 dialect as sent by the ELGAMA G350
 * (typ G35) meter: the whole telegram arrives as one burst every second,
 * with an AES-GCM encrypted body wrapped in a plain header and footer.
 *
 * Copyright (c) 2025 Bartosz Jozwiak.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

#ifndef DSMR_CUSTOM_BAJO_H // Unique include guard for the STOEN extension
#define DSMR_CUSTOM_BAJO_H

    #include "esphome/core/defines.h"  // For USE_ARDUINO / USE_ESP_IDF / USE_ESP32

    #if defined(USE_ARDUINO) || defined(USE_ESP_IDF) // Guard for supported platforms

    #include "esphome/core/hal.h"      // For millis()
    #include "esphome/core/log.h"      // For ESP_LOGx logging macros

    #include <cstddef>
    #include <cstdint>
    #include <string>
    #include <vector>

    // The UDP telegram dump is a debugging aid for reverse engineering an
    // unknown P1 dialect: it mirrors the raw and the decrypted telegram to a
    // host PC, which the ESPHome logger cannot do for 1.5 kB of binary data.
    // It needs BSD sockets, which only the ESP32 family offers (both Arduino
    // and ESP-IDF sit on lwIP's socket API there). ESP8266 therefore builds
    // without any socket code at all.
    #if defined(USE_ESP32)
    #define DSMR_CUSTOM_HAS_DEBUG_UDP 1
    #include <lwip/sockets.h>
    #include <lwip/inet.h>
    #endif

    namespace esphome {
    namespace dsmr_custom {

        /// How a telegram is read from the P1 port and decoded.
        enum class Method : uint8_t {
            /// Upstream behaviour: plain telegram, or encrypted when decryption_key is set.
            PLAIN = 0,
            /// Encrypted DSMR telegram; same code path as PLAIN plus decryption_key.
            ENCRYPTED = 1,
            /// Polish STOEN dialect (ELGAMA G350 / typ G35), handled by the Bajo code below.
            POLAND_STOEN = 2,
        };

        // Forward declaration of the Dsmr hub; Bajo is only ever used as its
        // base class and downcasts `this` to reach the hub's buffers.
        class Dsmr;

        class Bajo {
            public:
                virtual ~Bajo() = default;

                /// Select the receive/decode path. Accepts the YAML spellings
                /// (`plain`, `encrypted`, `poland_stoen`, and the legacy alias `bajo`).
                void set_method(const std::string &value);

                /// Mirror raw and decrypted telegrams to host:port over UDP (ESP32 only).
                void set_debug_udp_target(const std::string &host, uint16_t port) {
                    this->debug_udp_host_ = host;
                    this->debug_udp_port_ = port;
                }

                /// Optional DLMS authentication key (32 hex characters). Only needed
                /// if the meter authenticates over one; without it the GCM tag of an
                /// authenticated frame cannot be verified.
                void set_authentication_key(const std::string &key_hex);

                Method get_method() const { return this->method_; }

            protected:
                /// Which additional authenticated data this meter's GCM tag covers.
                /// DLMS specifies "security control byte || authentication key", but
                /// meters that ship a single key leave it unverifiable, so the layout
                /// is probed on the first telegrams instead of assumed.
                enum class AadMode : uint8_t {
                    UNKNOWN,          ///< not probed yet
                    NONE,             ///< tag covers the ciphertext only
                    SECURITY_BYTE,    ///< tag covers the security control byte
                    SECURITY_AND_KEY, ///< tag covers security control byte || auth key
                    UNVERIFIABLE,     ///< no candidate matched; decrypt without verifying
                };

                void BAJO_setup();
                void BAJO_reset_telegram();
                /// Decrypt body_ into decrypted_body_. Returns false when the frame
                /// is malformed or the GCM tag does not verify.
                bool BAJO_decrypt_telegram();
                void BAJO_receive_telegram();
                void BAJO_process_telegram();
                void BAJO_send_udp_telegram(const void *data, size_t len);
                void BAJO_setup_debug_udp_();
                /// Decrypt into decrypted_body_ and report the tag the ciphertext
                /// authenticates to under @p aad. False means a crypto error.
                bool BAJO_decrypt_body_(const uint8_t *ciphertext, size_t ciphertext_len, const uint8_t *iv,
                                        const uint8_t *aad, size_t aad_len, uint8_t *tag_out, size_t tag_len);
                /// Build the additional authenticated data for @p mode.
                size_t BAJO_build_aad_(AadMode mode, uint8_t security_byte, uint8_t *buffer, size_t buffer_size);
                const char *BAJO_aad_mode_str_(AadMode mode);

                Method method_{Method::PLAIN};

                AadMode aad_mode_{AadMode::UNKNOWN};
                uint8_t aad_probes_left_{5};
                std::vector<uint8_t> authentication_key_{};

                uint32_t last_receive_time_{0};
                uint32_t start_milis_{0};
                bool header_completed_{false};
                bool empty_line_completed_{false};
                bool footer_completed_{false};
                char *header_{nullptr};
                uint8_t *body_{nullptr};
                size_t body_bytes_{0};
                uint16_t bodyPos_{0};
                char *decrypted_body_{nullptr};
                size_t decrypted_body_bytes_{0};
                char *footer_{nullptr};
                uint16_t crcPos_{0};
                uint8_t *rx_buffer_{nullptr};
                size_t rx_buffer_len_{0};
                size_t rx_buffer_size_{0};

                std::string debug_udp_host_{};
                uint16_t debug_udp_port_{0};
                #ifdef DSMR_CUSTOM_HAS_DEBUG_UDP
                int debug_udp_sock_{-1};
                struct sockaddr_in debug_udp_addr_{};
                #endif
        };

    }  // namespace dsmr_custom
    }  // namespace esphome

    #endif // USE_ARDUINO || USE_ESP_IDF
#endif // DSMR_CUSTOM_BAJO_H
