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

                /// Reject telegrams whose AES-GCM tag does not verify (Arduino only;
                /// the ESP-IDF backend always verifies while decrypting).
                void set_gcm_tag_check(bool check) { this->gcm_tag_check_ = check; }

                Method get_method() const { return this->method_; }

            protected:
                void BAJO_setup();
                void BAJO_reset_telegram();
                /// Decrypt body_ into decrypted_body_. Returns false when the frame
                /// is malformed or the GCM tag does not verify.
                bool BAJO_decrypt_telegram();
                void BAJO_receive_telegram();
                void BAJO_process_telegram();
                void BAJO_send_udp_telegram(const void *data, size_t len);
                void BAJO_setup_debug_udp_();

                Method method_{Method::PLAIN};
                bool gcm_tag_check_{true};

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
