/*
 * This file is part of the dsmr_custom ESPHome component.
 *
 * Polish STOEN P1 dialect (ELGAMA G350 / typ G35).
 *
 * The meter is programmed by STOEN to push a complete telegram every second,
 * so instead of reading the UART byte by byte we drain everything that is
 * available into rx_buffer_ and start parsing once the line has been quiet
 * for receive_timeout_ milliseconds. Parsing the whole buffer in one go takes
 * about 5 ms on an ESP32.
 *
 * The telegram is a plain header line, an empty line, an AES-GCM encrypted
 * DLMS "general-glo-ciphering" body, and a plain "!CRC" footer:
 *
 *   /ELG5\253769430_A<CR><LF><CR><LF>
 *   DB 08 <system title x8> 82 <len hi> <len lo> <SC> <frame counter x4>
 *      <ciphertext ...> <GCM tag x12>
 *   !<crc x4><CR><LF>
 *
 * The 2 byte length field counts everything that follows it: the security
 * control byte, the 4 byte frame counter, the ciphertext and the GCM tag.
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

#include "bajo.h"

#if defined(USE_ARDUINO) || defined(USE_ESP_IDF)

#include "dsmr.h"

#include <cstring>
#include <cstdlib>

#ifdef USE_ARDUINO
#include <AES.h>
#include <GCM.h>
#else
#include "dsmr_crypto.h"
#endif

#ifdef DSMR_CUSTOM_HAS_DEBUG_UDP
#include <cerrno>
#endif

namespace esphome {
namespace dsmr_custom {

// Logging tag for the STOEN extension
static const char *const TAG = "BAJO dsmr_custom";

// DLMS general-glo-ciphering wrapper constants.
static const size_t GCM_TAG_LENGTH = 12;      // Authentication tag at the end of the body
static const size_t SC_AND_FC_LENGTH = 5;     // Security control byte + 4 byte frame counter
static const uint8_t SC_AUTHENTICATED = 0x10; // Security control bit: authentication applied
static const uint8_t SC_ENCRYPTED = 0x20;     // Security control bit: encryption applied

// Worst case number of bytes a single iteration of BAJO_process_telegram()
// appends to telegram_ / body_. Used as the headroom for the capacity checks.
static const size_t MAX_BYTES_PER_STEP = 8;

// Headroom on top of max_telegram_length for the plain header, the footer and
// the encryption overhead of the raw frame.
static const size_t RX_BUFFER_HEADROOM = 256;

void Bajo::set_method(const std::string &value) {
  if (value == "poland_stoen" || value == "bajo") {
    this->method_ = Method::POLAND_STOEN;
  } else if (value == "encrypted") {
    this->method_ = Method::ENCRYPTED;
  } else if (value == "plain") {
    this->method_ = Method::PLAIN;
  } else {
    ESP_LOGW(TAG, "Unknown method '%s', falling back to 'plain'.", value.c_str());
    this->method_ = Method::PLAIN;
  }
}

void Bajo::BAJO_setup() {
  // Bajo is only ever used as a base class of Dsmr, so this downcast is safe.
  Dsmr *d = static_cast<Dsmr *>(this);
  ESP_LOGCONFIG(TAG, "Setting up Polish STOEN support...");

  this->rx_buffer_size_ = d->max_telegram_len_ + RX_BUFFER_HEADROOM;

  this->decrypted_body_ = new char[d->max_telegram_len_ + 1];
  this->header_ = new char[20 + 1];
  this->body_ = new uint8_t[d->max_telegram_len_ + 1];
  this->footer_ = new char[20 + 1];
  this->rx_buffer_ = new uint8_t[this->rx_buffer_size_];

  if (this->decrypted_body_ == nullptr || this->header_ == nullptr || this->body_ == nullptr ||
      this->footer_ == nullptr || this->rx_buffer_ == nullptr) {
    ESP_LOGE(TAG, "Failed to allocate STOEN telegram buffers (%zu bytes needed)!",
             3 * (d->max_telegram_len_ + 1) + this->rx_buffer_size_ + 42);
    d->mark_failed();
    return;
  }

  this->BAJO_setup_debug_udp_();
}

void Bajo::BAJO_setup_debug_udp_() {
  if (this->debug_udp_port_ == 0) {
    return;
  }
#ifdef DSMR_CUSTOM_HAS_DEBUG_UDP
  memset(&this->debug_udp_addr_, 0, sizeof(this->debug_udp_addr_));
  this->debug_udp_addr_.sin_family = AF_INET;
  this->debug_udp_addr_.sin_port = htons(this->debug_udp_port_);
  if (inet_pton(AF_INET, this->debug_udp_host_.c_str(), &this->debug_udp_addr_.sin_addr) != 1) {
    ESP_LOGE(TAG, "debug_udp_target: '%s' is not a valid IPv4 address, telegram dump disabled.",
             this->debug_udp_host_.c_str());
    this->debug_udp_port_ = 0;
    return;
  }
  this->debug_udp_sock_ = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (this->debug_udp_sock_ < 0) {
    // A failing debug aid must not take the component down.
    ESP_LOGE(TAG, "debug_udp_target: cannot create UDP socket (errno %d), telegram dump disabled.", errno);
    this->debug_udp_port_ = 0;
    return;
  }
  ESP_LOGCONFIG(TAG, "  Telegram dump: UDP to %s:%u", this->debug_udp_host_.c_str(), this->debug_udp_port_);
#else
  ESP_LOGW(TAG, "debug_udp_target is only supported on ESP32 targets, telegram dump disabled.");
  this->debug_udp_port_ = 0;
#endif
}

void Bajo::BAJO_send_udp_telegram(const void *data, size_t len) {
#ifdef DSMR_CUSTOM_HAS_DEBUG_UDP
  if (this->debug_udp_sock_ < 0 || len == 0) {
    return;
  }
  if (::sendto(this->debug_udp_sock_, data, len, 0, reinterpret_cast<struct sockaddr *>(&this->debug_udp_addr_),
               sizeof(this->debug_udp_addr_)) < 0) {
    ESP_LOGW(TAG, "Telegram dump: UDP send failed (errno %d).", errno);
  }
#else
  (void) data;
  (void) len;
#endif
}

void Bajo::BAJO_reset_telegram() {
  this->start_milis_ = 0;
  this->header_completed_ = false;
  this->empty_line_completed_ = false;
  this->footer_completed_ = false;
  this->body_bytes_ = 0;
  this->bodyPos_ = 0;
  this->crcPos_ = 0;
  this->decrypted_body_bytes_ = 0;
  if (this->header_ != nullptr) {
    this->header_[0] = '\0';
  }
  if (this->footer_ != nullptr) {
    this->footer_[0] = '\0';
  }
  if (this->body_ != nullptr) {
    this->body_[0] = 0;
  }
  if (this->decrypted_body_ != nullptr) {
    this->decrypted_body_[0] = '\0';
  }
  // header_found_/footer_found_/bytes_read_ and the telegram_ buffer itself
  // belong to Dsmr and are cleared by Dsmr::reset_telegram_(), which is the
  // only caller of this method.
}

void Bajo::BAJO_receive_telegram() {
  Dsmr *d = static_cast<Dsmr *>(this);

  int available = d->available();
  if (available > 0) {
    // Take everything the UART has in one go; that is much faster than
    // reading byte by byte and checking for the end of the data.
    size_t space = this->rx_buffer_size_ - this->rx_buffer_len_;
    if (static_cast<size_t>(available) > space) {
      ESP_LOGW(TAG,
               "RX buffer full (%zu of %zu bytes used, %d more waiting). Discarding and "
               "resynchronising on the next telegram.",
               this->rx_buffer_len_, this->rx_buffer_size_, available);
      this->rx_buffer_len_ = 0;
      space = this->rx_buffer_size_;
      if (static_cast<size_t>(available) > space) {
        available = static_cast<int>(space);
      }
    }
    if (!d->read_array(this->rx_buffer_ + this->rx_buffer_len_, available)) {
      ESP_LOGW(TAG, "UART read of %d bytes failed.", available);
      return;
    }
    this->rx_buffer_len_ += available;
    this->last_receive_time_ = millis();
  }

  if (this->last_receive_time_ != 0 && millis() - this->last_receive_time_ > d->receive_timeout_) {
    // The line has been quiet long enough, the telegram should be complete.
    this->BAJO_send_udp_telegram(this->rx_buffer_, this->rx_buffer_len_);
    ESP_LOGV(TAG, "Got %zu bytes from the P1 port.", this->rx_buffer_len_);

    d->reset_telegram_();
    this->BAJO_process_telegram();
    this->last_receive_time_ = 0;
    this->rx_buffer_len_ = 0;
  }
}

void Bajo::BAJO_process_telegram() {
  Dsmr *d = static_cast<Dsmr *>(this);
  size_t x = 0;

  // Reads past the end of the received data return '\0', which never matches
  // CR/LF/'!', so a truncated telegram simply never completes and is dropped.
  auto peek = [&](size_t offset) -> char {
    size_t i = x + offset;
    return i < this->rx_buffer_len_ ? static_cast<char>(this->rx_buffer_[i]) : '\0';
  };

  while (x < this->rx_buffer_len_) {
    const char c = static_cast<char>(this->rx_buffer_[x]);

    // Every branch below appends at most MAX_BYTES_PER_STEP bytes.
    if (d->bytes_read_ + MAX_BYTES_PER_STEP > d->max_telegram_len_ ||
        this->body_bytes_ + MAX_BYTES_PER_STEP > d->max_telegram_len_) {
      ESP_LOGE(TAG, "Telegram larger than max_telegram_length (%zu bytes). Discarding.", d->max_telegram_len_);
      d->status_set_warning();
      d->reset_telegram_();
      d->stop_requesting_data_();
      return;
    }

    if (!d->header_found_) {
      if (c == '/') {
        d->reset_telegram_();
        d->header_found_ = true;
        d->last_read_time_ = millis();
        this->start_milis_ = millis();
      } else {
        x++;
        continue;
      }
    }

    if (d->header_found_ && !this->header_completed_) {
      if (c == '\r') {
        const char e = peek(1);
        if (e == '\n') {
          this->header_completed_ = true;
          d->telegram_[d->bytes_read_] = '\0';
          strncpy(this->header_, d->telegram_, 20);
          this->header_[20] = '\0';
        }
        d->telegram_[d->bytes_read_++] = c;
        d->telegram_[d->bytes_read_++] = e;
        x += 2;
      } else {
        d->telegram_[d->bytes_read_++] = c;
        x++;
      }
      continue;
    }

    if (this->header_completed_ && !this->empty_line_completed_) {
      if (c == '\r') {
        const char e = peek(1);
        d->telegram_[d->bytes_read_++] = c;
        d->telegram_[d->bytes_read_++] = e;
        x += 2;
        if (e == '\n') {
          this->empty_line_completed_ = true;
          this->bodyPos_ = d->bytes_read_;
        }
      } else {
        d->telegram_[d->bytes_read_++] = c;
        x++;
      }
      continue;
    }

    if (this->empty_line_completed_ && !d->footer_found_) {
      if (c == '!') {
        // Potential footer start: '!' can also occur inside the encrypted
        // body, so only "! xx xx xx xx CR LF" really ends the telegram.
        this->footer_[0] = peek(1);
        this->footer_[1] = peek(2);
        this->footer_[2] = peek(3);
        this->footer_[3] = peek(4);
        this->footer_[4] = '\0';
        const char e = peek(5);
        if (e == '\r') {
          const char f = peek(6);
          d->telegram_[d->bytes_read_++] = '!';
          x++;

          if (f == '\n') {
            d->footer_found_ = true;
            this->footer_completed_ = true;
            this->crcPos_ = d->bytes_read_;
          } else {
            // False alarm, the '!' was part of the body after all.
            this->body_[this->body_bytes_++] = '!';
            this->body_[this->body_bytes_++] = this->footer_[0];
            this->body_[this->body_bytes_++] = this->footer_[1];
            this->body_[this->body_bytes_++] = this->footer_[2];
            this->body_[this->body_bytes_++] = this->footer_[3];
            this->body_[this->body_bytes_++] = e;
            this->body_[this->body_bytes_++] = f;
          }
          d->telegram_[d->bytes_read_++] = this->footer_[0];
          d->telegram_[d->bytes_read_++] = this->footer_[1];
          d->telegram_[d->bytes_read_++] = this->footer_[2];
          d->telegram_[d->bytes_read_++] = this->footer_[3];
          d->telegram_[d->bytes_read_++] = e;
          d->telegram_[d->bytes_read_++] = f;
          x += 6;
          if (!this->footer_completed_) {
            // False alarm: the seven bytes above are consumed, so skip the
            // x++ at the end of the loop that the real footer relies on.
            continue;
          }
        } else {
          // False alarm, the '!' was part of the body after all.
          this->body_[this->body_bytes_++] = '!';
          d->telegram_[d->bytes_read_++] = '!';
          this->body_[this->body_bytes_++] = this->footer_[0];
          d->telegram_[d->bytes_read_++] = this->footer_[0];
          this->body_[this->body_bytes_++] = this->footer_[1];
          d->telegram_[d->bytes_read_++] = this->footer_[1];
          this->body_[this->body_bytes_++] = this->footer_[2];
          d->telegram_[d->bytes_read_++] = this->footer_[2];
          this->body_[this->body_bytes_++] = this->footer_[3];
          d->telegram_[d->bytes_read_++] = this->footer_[3];
          this->body_[this->body_bytes_++] = e;
          d->telegram_[d->bytes_read_++] = e;
          x += 5;
          this->footer_[0] = '\0';
        }
      } else {
        d->telegram_[d->bytes_read_++] = c;
        this->body_[this->body_bytes_++] = c;
        x++;
        continue;
      }
    }

    if (this->footer_completed_) {
      // Full telegram received: decrypt the body and splice the plaintext
      // back in between the plain header and the plain footer, so that the
      // rest of the component sees an ordinary P1 telegram.
      this->body_[this->body_bytes_] = 0;
      d->telegram_[d->bytes_read_] = '\0';

      if (!this->BAJO_decrypt_telegram()) {
        d->status_set_warning();
        d->reset_telegram_();
        d->stop_requesting_data_();
        return;
      }

      const size_t footer_len = strlen(this->footer_);
      // header + CRLF + empty line, plaintext, '!', CRC, CRLF and the NUL.
      const size_t total_len = this->bodyPos_ + this->decrypted_body_bytes_ + 1 + footer_len + 2;
      if (total_len > d->max_telegram_len_) {
        ESP_LOGE(TAG,
                 "Reassembled telegram (%zu bytes) does not fit into max_telegram_length (%zu). Discarding.",
                 total_len, d->max_telegram_len_);
        d->status_set_warning();
        d->reset_telegram_();
        d->stop_requesting_data_();
        return;
      }

      memcpy(d->telegram_ + this->bodyPos_, this->decrypted_body_, this->decrypted_body_bytes_);
      this->crcPos_ = this->bodyPos_ + this->decrypted_body_bytes_;
      d->telegram_[this->crcPos_] = '!';
      memcpy(d->telegram_ + this->crcPos_ + 1, this->footer_, footer_len);
      d->bytes_read_ = this->crcPos_ + 1 + footer_len;
      d->telegram_[d->bytes_read_++] = '\r';
      d->telegram_[d->bytes_read_++] = '\n';
      d->telegram_[d->bytes_read_] = '\0';

      this->BAJO_send_udp_telegram(d->telegram_, d->bytes_read_);
      ESP_LOGD(TAG, "Telegram total bytes %zu, process time %u ms", d->bytes_read_, millis() - this->start_milis_);

      d->status_clear_warning();
      d->parse_telegram();
      d->reset_telegram_();
      return;
    }

    x++;
  }
}

bool Bajo::BAJO_decrypt_telegram() {
  Dsmr *d = static_cast<Dsmr *>(this);

  if (d->decryption_key_.empty()) {
    ESP_LOGE(TAG, "Method poland_stoen needs a decryption_key.");
    return false;
  }

  if (this->body_bytes_ < 2) {
    ESP_LOGE(TAG, "Encrypted body holds only %zu bytes.", this->body_bytes_);
    return false;
  }

  size_t system_title_length = 0;
  if (this->body_[0] == 0x00) {
    // 0x00 means an empty system title
    system_title_length = 1;
  } else if (this->body_[0] == 0xDB) {
    // 0xDB means a system title follows, with its length in the next byte
    system_title_length = this->body_[1] + 2;
  } else {
    ESP_LOGE(TAG, "Decryptor: unknown start byte 0x%02X.", this->body_[0]);
    return false;
  }

  // The length field and everything it describes must be inside the body.
  if (this->body_bytes_ < system_title_length + 8) {
    ESP_LOGE(TAG, "Encrypted body too short (%zu bytes) for a %zu byte system title.", this->body_bytes_,
             system_title_length);
    return false;
  }

  // The two byte length that the arithmetic below relies on is introduced by
  // 0x82; any other encoding would put the length somewhere else.
  if (this->body_[system_title_length] != 0x82) {
    ESP_LOGE(TAG, "Expected a 0x82 length marker after the system title, got 0x%02X.",
             this->body_[system_title_length]);
    return false;
  }

  const size_t len_info_from_frame = (static_cast<size_t>(this->body_[system_title_length + 1]) << 8) |
                                     static_cast<size_t>(this->body_[system_title_length + 2]);
  const uint8_t security_byte = this->body_[system_title_length + 3];
  const size_t gcm_tag_length = GCM_TAG_LENGTH;
  const size_t ciphertext_offset = system_title_length + 8;

  ESP_LOGV(TAG, "Frame: system title %zu B, LEN_INFO %zu, security byte 0x%02X", system_title_length,
           len_info_from_frame, security_byte);

  // These meters send encrypted + authenticated frames (security byte 0x30).
  // The frame layout below counts a 12 byte tag, so a frame without the
  // authentication bit would be delimited differently.
  if ((security_byte & SC_ENCRYPTED) == 0) {
    ESP_LOGE(TAG, "Security byte 0x%02X says the body is not encrypted; method poland_stoen cannot handle that.",
             security_byte);
    return false;
  }
  if ((security_byte & SC_AUTHENTICATED) == 0) {
    ESP_LOGE(TAG, "Security byte 0x%02X has no authentication tag; method poland_stoen cannot handle that yet.",
             security_byte);
    return false;
  }

  // LEN_INFO counts the security byte, the frame counter, the ciphertext and
  // the GCM tag, so anything at or below that overhead is malformed.
  if (len_info_from_frame <= SC_AND_FC_LENGTH + gcm_tag_length) {
    ESP_LOGE(TAG, "LEN_INFO %zu is too small for a %zu byte tag.", len_info_from_frame, gcm_tag_length);
    return false;
  }

  const size_t ciphertext_len = len_info_from_frame - SC_AND_FC_LENGTH - gcm_tag_length;

  if (ciphertext_offset + ciphertext_len + gcm_tag_length > this->body_bytes_) {
    ESP_LOGE(TAG, "Encrypted frame is truncated: LEN_INFO wants %zu bytes, body holds %zu.",
             ciphertext_offset + ciphertext_len + gcm_tag_length, this->body_bytes_);
    return false;
  }
  if (ciphertext_offset + ciphertext_len + gcm_tag_length != this->body_bytes_) {
    ESP_LOGW(TAG, "Encrypted frame has %zu trailing bytes; ignoring them.",
             this->body_bytes_ - (ciphertext_offset + ciphertext_len + gcm_tag_length));
  }
  if (ciphertext_len > d->max_telegram_len_) {
    ESP_LOGE(TAG, "Decrypted data (%zu bytes) would not fit into max_telegram_length (%zu).", ciphertext_len,
             d->max_telegram_len_);
    return false;
  }

  // IV = 8 byte system title || 4 byte frame counter.
  uint8_t iv[12] = {0};
  if (system_title_length > 8) {
    memcpy(iv, &this->body_[2], 8);
  }
  memcpy(iv + 8, &this->body_[system_title_length + 4], 4);

  uint8_t *ciphertext_ptr = &this->body_[ciphertext_offset];
  uint8_t *tag_ptr = &this->body_[ciphertext_offset + ciphertext_len];

  // The tag covers the ciphertext plus some additional authenticated data.
  // DLMS says that is "security control byte || authentication key", but these
  // meters are handed out with a single key, so the layout is probed on the
  // first few telegrams: whichever candidate reproduces the tag in the frame is
  // used from then on, and if none does the telegram is decrypted but not
  // authenticated. The plaintext is the same either way - the additional data
  // only feeds the tag, never the keystream.
  uint8_t aad_buffer[1 + 16];
  uint8_t computed_tag[GCM_TAG_LENGTH];

  if (this->aad_mode_ == AadMode::UNKNOWN) {
    static const AadMode CANDIDATES[] = {AadMode::SECURITY_AND_KEY, AadMode::SECURITY_BYTE, AadMode::NONE};
    for (AadMode candidate : CANDIDATES) {
      const size_t aad_len = this->BAJO_build_aad_(candidate, security_byte, aad_buffer, sizeof(aad_buffer));
      if (aad_len == 0 && candidate != AadMode::NONE) {
        continue;  // candidate needs an authentication key we do not have
      }
      if (!this->BAJO_decrypt_body_(ciphertext_ptr, ciphertext_len, iv, aad_buffer, aad_len, computed_tag,
                                    gcm_tag_length)) {
        return false;
      }
      if (memcmp(computed_tag, tag_ptr, gcm_tag_length) == 0) {
        this->aad_mode_ = candidate;
        ESP_LOGI(TAG, "GCM tag verifies with additional data = %s; authenticating every telegram from now on.",
                 this->BAJO_aad_mode_str_(candidate));
        break;
      }
    }
    if (this->aad_mode_ == AadMode::UNKNOWN) {
      if (--this->aad_probes_left_ == 0) {
        this->aad_mode_ = AadMode::UNVERIFIABLE;
        ESP_LOGW(TAG,
                 "GCM tag does not match any known layout of the additional data (security byte 0x%02X); "
                 "telegrams are decrypted but NOT authenticated.",
                 security_byte);
        ESP_LOGW(TAG, "This is expected for a meter handed out with a decryption key only. If the operator also "
                      "gave you an authentication key, set 'authentication_key' to verify the tag.");
      } else {
        // Keep the plaintext of this telegram and probe again on the next one.
        ESP_LOGD(TAG, "GCM tag did not match any candidate, %u probe(s) left.", this->aad_probes_left_);
      }
    }
  } else {
    const AadMode mode = this->aad_mode_ == AadMode::UNVERIFIABLE ? AadMode::NONE : this->aad_mode_;
    const size_t aad_len = this->BAJO_build_aad_(mode, security_byte, aad_buffer, sizeof(aad_buffer));
    if (!this->BAJO_decrypt_body_(ciphertext_ptr, ciphertext_len, iv, aad_buffer, aad_len, computed_tag,
                                  gcm_tag_length)) {
      return false;
    }
    if (this->aad_mode_ != AadMode::UNVERIFIABLE && memcmp(computed_tag, tag_ptr, gcm_tag_length) != 0) {
      ESP_LOGW(TAG, "Decryption failed: GCM tag mismatch (tag %02X %02X %02X %02X ..., expected %02X %02X %02X %02X ...).",
               tag_ptr[0], tag_ptr[1], tag_ptr[2], tag_ptr[3], computed_tag[0], computed_tag[1], computed_tag[2],
               computed_tag[3]);
      return false;
    }
  }

  this->decrypted_body_[ciphertext_len] = '\0';
  this->decrypted_body_bytes_ = ciphertext_len;
  ESP_LOGV(TAG, "Decryption successful, %zu bytes of plaintext.", this->decrypted_body_bytes_);
  return true;
}

size_t Bajo::BAJO_build_aad_(AadMode mode, uint8_t security_byte, uint8_t *buffer, size_t buffer_size) {
  switch (mode) {
  case AadMode::SECURITY_AND_KEY:
    if (this->authentication_key_.empty() || buffer_size < 1 + this->authentication_key_.size()) {
      return 0;
    }
    buffer[0] = security_byte;
    memcpy(buffer + 1, this->authentication_key_.data(), this->authentication_key_.size());
    return 1 + this->authentication_key_.size();
  case AadMode::SECURITY_BYTE:
    if (buffer_size < 1) {
      return 0;
    }
    buffer[0] = security_byte;
    return 1;
  default:
    return 0;
  }
}

const char *Bajo::BAJO_aad_mode_str_(AadMode mode) {
  switch (mode) {
  case AadMode::NONE:
    return "none";
  case AadMode::SECURITY_BYTE:
    return "security byte";
  case AadMode::SECURITY_AND_KEY:
    return "security byte || authentication key";
  case AadMode::UNVERIFIABLE:
    return "unverifiable";
  default:
    return "unknown";
  }
}

bool Bajo::BAJO_decrypt_body_(const uint8_t *ciphertext, size_t ciphertext_len, const uint8_t *iv,
                              const uint8_t *aad, size_t aad_len, uint8_t *tag_out, size_t tag_len) {
  Dsmr *d = static_cast<Dsmr *>(this);

#ifdef USE_ARDUINO
  // Arduino: rweather/Crypto decrypts and computes the tag in separate steps.
  GCM<AES128> gcmaes128;
  if (!gcmaes128.setKey(d->decryption_key_.data(), gcmaes128.keySize())) {
    ESP_LOGE(TAG, "Could not set the AES-128 decryption key.");
    return false;
  }
  if (!gcmaes128.setIV(iv, 12)) {
    ESP_LOGE(TAG, "Could not set the AES-GCM initialisation vector.");
    return false;
  }
  if (aad_len != 0) {
    gcmaes128.addAuthData(aad, aad_len);
  }
  gcmaes128.decrypt(reinterpret_cast<uint8_t *>(this->decrypted_body_), ciphertext, ciphertext_len);
  gcmaes128.computeTag(tag_out, tag_len);
  return true;
#else
  // ESP-IDF: the MbedTLS wrapper returns the computed tag rather than wiping
  // the plaintext, so an unverifiable tag does not cost us the telegram.
  const int result = dsmr_aes_gcm_decrypt_with_tag(d->decryption_key_.data(), d->decryption_key_.size(), iv, 12,
                                                   aad_len != 0 ? aad : nullptr, aad_len, ciphertext,
                                                   ciphertext_len, reinterpret_cast<unsigned char *>(this->decrypted_body_),
                                                   tag_out, tag_len);
  if (result != 0) {
    ESP_LOGW(TAG, "AES-GCM decryption failed: error code %d.", result);
    return false;
  }
  return true;
#endif
}

void Bajo::set_authentication_key(const std::string &key_hex) {
  this->authentication_key_.clear();
  this->aad_mode_ = AadMode::UNKNOWN;
  if (key_hex.empty()) {
    return;
  }
  if (key_hex.length() != 32) {
    ESP_LOGE(TAG, "Authentication key must be 32 hexadecimal characters long (is %zu), ignoring it.",
             key_hex.length());
    return;
  }
  this->authentication_key_.assign(16, 0);
  for (size_t i = 0; i < 16; i++) {
    const char pair[3] = {key_hex[i * 2], key_hex[i * 2 + 1], '\0'};
    this->authentication_key_[i] = static_cast<uint8_t>(strtoul(pair, nullptr, 16));
  }
  ESP_LOGI(TAG, "Authentication key is set.");
}

}  // namespace dsmr_custom
}  // namespace esphome

#endif  // USE_ARDUINO || USE_ESP_IDF
